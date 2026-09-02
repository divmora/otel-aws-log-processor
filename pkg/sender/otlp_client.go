package sender

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/divmora/otel-aws-log-processor/pkg/model"
	"github.com/divmora/otel-aws-log-processor/pkg/processor"
)

var Version = "dev"

// OTLPClient handles sending logs to an OTLP endpoint.
type OTLPClient struct {
	Endpoint      string
	BasicAuthUser string
	BasicAuthPass string
	MaxRetries    int
	MaxBatchSize  int
	MaxConcurrent int
	RetryBaseSec  float64
	Logger        *slog.Logger
}

type resourceGroup struct {
	ResourceAttrs []model.OTelAttribute
	LogRecords    []model.OTelLogRecord
}

// NewOTLPClient creates a new OTLP client.
func NewOTLPClient(endpoint, user, pass string, maxRetries, maxBatchSize, maxConcurrent int, logger *slog.Logger) *OTLPClient {
	return &OTLPClient{
		Endpoint:      endpoint,
		BasicAuthUser: user,
		BasicAuthPass: pass,
		MaxRetries:    maxRetries,
		MaxBatchSize:  maxBatchSize,
		MaxConcurrent: maxConcurrent,
		RetryBaseSec:  1.0,
		Logger:        logger,
	}
}

// SendLogs converts adapters to OTLP log records and sends them in batches.
func (c *OTLPClient) SendLogs(entries []processor.LogAdapter) error {
	// Group by resource
	grouped := make(map[string]*resourceGroup)

	for _, entry := range entries {
		resKey := entry.GetResourceKey()

		if _, exists := grouped[resKey]; !exists {
			grouped[resKey] = &resourceGroup{
				ResourceAttrs: entry.GetResourceAttributes(),
				LogRecords:    []model.OTelLogRecord{},
			}
		}

		logRecord := entry.ToOTel()
		grouped[resKey].LogRecords = append(grouped[resKey].LogRecords, logRecord)
	}

	c.Logger.Info("Grouped logs", "resource_group_count", len(grouped))

	// Concurrency control
	sem := make(chan struct{}, c.MaxConcurrent)
	var wg sync.WaitGroup
	errChan := make(chan error, 1)

	totalSent := 0
	var sentLock sync.Mutex

	// Send each group in batches
	for resKey, group := range grouped {
		groupLog := c.Logger.With("resource_key", resKey, "total_logs", len(group.LogRecords))
		groupLog.Info("Processing resource group")

		// Split into batches
		batchCount := 0
		for i := 0; i < len(group.LogRecords); i += c.MaxBatchSize {
			// Check for previous errors
			select {
			case err := <-errChan:
				return err
			default:
			}

			end := i + c.MaxBatchSize
			if end > len(group.LogRecords) {
				end = len(group.LogRecords)
			}

			batch := group.LogRecords[i:end]
			payload := c.buildPayload(group.ResourceAttrs, batch)
			currentBatchCount := batchCount + 1
			currentBatchSize := len(batch)

			wg.Add(1)
			go func(p model.OTLPPayload, bID int, bSize int, log *slog.Logger) {
				defer wg.Done()

				// Acquire semaphore
				sem <- struct{}{}
				defer func() { <-sem }()

				log.Info("Sending batch", "batch_id", bID, "batch_size", bSize)

				if err := c.sendWithRetry(p); err != nil {
					log.Error("Failed to send batch", "batch_id", bID, "error", err)
					// Try to report error (non-blocking)
					select {
					case errChan <- fmt.Errorf("failed to send batch %d: %w", bID, err):
					default:
					}
					return
				}

				sentLock.Lock()
				totalSent += bSize
				sentLock.Unlock()
			}(payload, currentBatchCount, currentBatchSize, groupLog)

			batchCount++
		}
	}

	// Wait for all batches to complete
	wg.Wait()

	// Check for any errors that occurred
	select {
	case err := <-errChan:
		return err
	default:
	}

	c.Logger.Info("Successfully sent all logs", "total_sent", totalSent, "resource_groups", len(grouped))
	return nil
}

func (c *OTLPClient) buildPayload(resourceAttrs []model.OTelAttribute, logRecords []model.OTelLogRecord) model.OTLPPayload {
	return model.OTLPPayload{
		ResourceLogs: []model.ResourceLog{
			{
				Resource: model.ResourceAttributes{
					Attributes: resourceAttrs,
				},
				ScopeLogs: []model.ScopeLog{
					{
						Scope: model.Scope{
							Name:    "otel-aws-log-processor",
							Version: Version,
						},
						LogRecords: logRecords,
					},
				},
			},
		},
	}
}

func (c *OTLPClient) sendWithRetry(payload model.OTLPPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= c.MaxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			multiplier := 1 << uint(attempt-1)
			sleep := time.Duration(c.RetryBaseSec*float64(multiplier)) * time.Second
			time.Sleep(sleep)
		}

		req, err := http.NewRequest("POST", c.Endpoint, bytes.NewBuffer(body))
		if err != nil {
			lastErr = err
			continue
		}

		req.Header.Set("Content-Type", "application/json")

		if c.BasicAuthUser != "" && c.BasicAuthPass != "" {
			req.SetBasicAuth(c.BasicAuthUser, c.BasicAuthPass)
		}

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			c.Logger.Warn("Batch send attempt failed", "attempt", attempt+1, "error", err)
			lastErr = err
			continue
		}

		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			c.Logger.Info("Batch sent successfully", "attempt", attempt+1, "status", resp.StatusCode)
			return nil
		}

		respBody, _ := io.ReadAll(resp.Body)
		c.Logger.Warn("Batch send attempt failed", "attempt", attempt+1, "status", resp.StatusCode, "response", string(respBody))
		lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return fmt.Errorf("failed after %d attempts: %w", c.MaxRetries+1, lastErr)
}
