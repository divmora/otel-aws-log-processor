package license

import (
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
)

// Default limits for non-production fair-use evaluation.
const (
	DefaultMaxNonProdBatchRecords     int64 = 10_000
	DefaultMaxNonProdContainerRecords int64 = 25_000
)

// QuotaTracker maintains in-container execution metrics and evaluates fair-use rate ceilings.
type QuotaTracker struct {
	containerRecords    atomic.Int64
	maxBatchRecords     int64
	maxContainerRecords int64
}

// NewQuotaTracker initializes a QuotaTracker with limits loaded from environment or defaults.
func NewQuotaTracker() *QuotaTracker {
	batchLimit := getEnvInt64("DIVMORA_NON_PROD_MAX_BATCH", DefaultMaxNonProdBatchRecords)
	containerLimit := getEnvInt64("DIVMORA_NON_PROD_MAX_CONTAINER", DefaultMaxNonProdContainerRecords)

	return &QuotaTracker{
		maxBatchRecords:     batchLimit,
		maxContainerRecords: containerLimit,
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
