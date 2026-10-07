package license

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

// Default limits for non-production fair-use evaluation.
const (
	DefaultMaxNonProdBatchRecords     int64 = 10_000
	DefaultMaxNonProdContainerRecords int64 = 25_000
)

// FairUseWarningInterval specifies the minimum duration between rate-limited fair-use warning banners (60 minutes).
const FairUseWarningInterval = 60 * time.Minute

// FairUseWarningBanner defines the structured warning message emitted when fair-use throughput allocation is breached.
const FairUseWarningBanner = "[WARN_FAIR_USE_THROUGHPUT_EXCEEDED] Monthly log volume has exceeded the licensed fair-use allocation (Allocated: %d GB). Telemetry processing continues uninterrupted without data loss. Please contact licensing@divmora.com to adjust your commitment tier."

// QuotaTracker maintains in-container execution metrics and evaluates fair-use rate ceilings.
type QuotaTracker struct {
	containerRecords    atomic.Int64
	bytesProcessed      atomic.Int64
	compressedBytes     atomic.Int64
	maxBatchRecords     int64
	maxContainerRecords int64
	lastWarningTime     atomic.Int64 // Unix timestamp in seconds
	throughputExceeded  atomic.Bool  // Manual or external overage signal
}

// NewQuotaTracker initializes a QuotaTracker with limits loaded from environment or defaults.
// To prevent licensing bypass loopholes, environment variables can only tighten (lower) limits for testing,
// but can never exceed the hardcoded DefaultMaxNonProdBatchRecords (10,000) or DefaultMaxNonProdContainerRecords (25,000) ceilings.
func NewQuotaTracker() *QuotaTracker {
	batchLimit := getEnvInt64("DIVMORA_NON_PROD_MAX_BATCH", DefaultMaxNonProdBatchRecords)
	if batchLimit > DefaultMaxNonProdBatchRecords {
		batchLimit = DefaultMaxNonProdBatchRecords
	}
	containerLimit := getEnvInt64("DIVMORA_NON_PROD_MAX_CONTAINER", DefaultMaxNonProdContainerRecords)
	if containerLimit > DefaultMaxNonProdContainerRecords {
		containerLimit = DefaultMaxNonProdContainerRecords
	}

	return &QuotaTracker{
		maxBatchRecords:     batchLimit,
		maxContainerRecords: containerLimit,
	}
}

// SetLimitsForTest overrides limits for testing purposes.
func (q *QuotaTracker) SetLimitsForTest(batchLimit, containerLimit int64) {
	if q != nil {
		q.maxBatchRecords = batchLimit
		q.maxContainerRecords = containerLimit
	}
}

// RecordBytes atomically increments bytes processed by this Lambda container.
func (q *QuotaTracker) RecordBytes(n int64) int64 {
	if n <= 0 {
		return q.bytesProcessed.Load()
	}
	return q.bytesProcessed.Add(n)
}

// TotalBytesProcessed returns the cumulative bytes processed by this container.
func (q *QuotaTracker) TotalBytesProcessed() int64 {
	return q.bytesProcessed.Load()
}

// RecordCompressedBytes atomically increments compressed bytes processed by this container.
func (q *QuotaTracker) RecordCompressedBytes(n int64) int64 {
	if n <= 0 {
		return q.compressedBytes.Load()
	}
	return q.compressedBytes.Add(n)
}

// TotalCompressedBytes returns the cumulative compressed bytes processed by this container.
func (q *QuotaTracker) TotalCompressedBytes() int64 {
	return q.compressedBytes.Load()
}

// SetThroughputExceeded manually or dynamically sets the throughput overage state.
func (q *QuotaTracker) SetThroughputExceeded(exceeded bool) {
	if q != nil {
		q.throughputExceeded.Store(exceeded)
	}
}

// IsThroughputExceeded returns whether throughput overage has been flagged.
func (q *QuotaTracker) IsThroughputExceeded() bool {
	if q == nil {
		return false
	}
	return q.throughputExceeded.Load()
}

// CheckThroughputQuota checks whether the cumulative volume or external signals indicate that
// the fair-use monthly throughput ceiling has been breached.
func (q *QuotaTracker) CheckThroughputQuota(maxMonthlyGB int) bool {
	if q == nil || maxMonthlyGB <= 0 {
		return false
	}
	if q.throughputExceeded.Load() {
		return true
	}
	if os.Getenv("DIVMORA_THROUGHPUT_EXCEEDED") == "true" || os.Getenv("DIVMORA_FAIR_USE_EXCEEDED") == "true" {
		return true
	}
	if usageStr := os.Getenv("DIVMORA_MONTHLY_USAGE_GB"); usageStr != "" {
		if usageGB, err := strconv.Atoi(usageStr); err == nil && usageGB > maxMonthlyGB {
			return true
		}
	}
	if usageBytesStr := os.Getenv("DIVMORA_MONTHLY_USAGE_BYTES"); usageBytesStr != "" {
		if usageBytes, err := strconv.ParseInt(usageBytesStr, 10, 64); err == nil && usageBytes > int64(maxMonthlyGB)*1_000_000_000 {
			return true
		}
	}
	if maxContainerBytes := getEnvInt64("DIVMORA_MAX_CONTAINER_BYTES", 0); maxContainerBytes > 0 && q.TotalBytesProcessed() > maxContainerBytes {
		return true
	}
	if q.TotalBytesProcessed() > int64(maxMonthlyGB)*1_000_000_000 {
		return true
	}
	return false
}

// ShouldEmitFairUseWarningAt reports whether enough time has elapsed since the last warning
// (at most once every 60 minutes per Lambda container) at reference time now.
// If true, it atomically updates the last warning timestamp.
func (q *QuotaTracker) ShouldEmitFairUseWarningAt(now time.Time) bool {
	if q == nil {
		return false
	}
	last := q.lastWarningTime.Load()
	nowSec := now.Unix()
	if last == 0 || (nowSec-last) >= int64(FairUseWarningInterval.Seconds()) {
		if q.lastWarningTime.CompareAndSwap(last, nowSec) {
			return true
		}
	}
	return false
}

// ShouldEmitFairUseWarning reports whether enough time has elapsed since the last warning at current UTC time.
func (q *QuotaTracker) ShouldEmitFairUseWarning() bool {
	return q.ShouldEmitFairUseWarningAt(time.Now().UTC())
}

// LogFairUseWarningAt emits the rate-limited soft fair-use warning banner at reference time now.
// Returns true if the warning was emitted, or false if it was suppressed by rate limiting.
func (q *QuotaTracker) LogFairUseWarningAt(allocatedGB int, now time.Time) bool {
	if q == nil || !q.ShouldEmitFairUseWarningAt(now) {
		return false
	}
	msg := fmt.Sprintf(FairUseWarningBanner, allocatedGB)
	slog.Warn(msg,
		"allocated_gb", allocatedGB,
		"total_bytes_processed", q.TotalBytesProcessed(),
		"contact", "licensing@divmora.com",
	)
	return true
}

// LogFairUseWarning emits the rate-limited soft fair-use warning banner at current UTC time.
// Returns true if the warning was emitted, or false if it was suppressed by rate limiting.
func (q *QuotaTracker) LogFairUseWarning(allocatedGB int) bool {
	return q.LogFairUseWarningAt(allocatedGB, time.Now().UTC())
}

// ResetWarningTime resets the last warning timestamp (primarily for testing).
func (q *QuotaTracker) ResetWarningTime() {
	if q != nil {
		q.lastWarningTime.Store(0)
	}
}

// CheckBatchDensity evaluates whether a single log batch exceeds the non-production density threshold.
func (q *QuotaTracker) CheckBatchDensity(batchCount int) (exceeded bool, reason string) {
	count := int64(batchCount)
	if count > q.maxBatchRecords {
		return true, fmt.Sprintf("batch record count (%d) exceeds non-production density ceiling (%d)", count, q.maxBatchRecords)
	}
	return false, ""
}

// RecordAndCheckContainerQuota atomically increments cumulative container records
// and checks if the container lifecycle ceiling has been breached.
func (q *QuotaTracker) RecordAndCheckContainerQuota(batchCount int) (exceeded bool, totalRecords int64, reason string) {
	newTotal := q.containerRecords.Add(int64(batchCount))
	if newTotal > q.maxContainerRecords {
		return true, newTotal, fmt.Sprintf("cumulative container records (%d) exceeds non-production fair-use ceiling (%d)", newTotal, q.maxContainerRecords)
	}
	return false, newTotal, ""
}

// TotalRecordsProcessed returns the current cumulative records processed by this container.
func (q *QuotaTracker) TotalRecordsProcessed() int64 {
	return q.containerRecords.Load()
}

func getEnvInt64(key string, fallback int64) int64 {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}
