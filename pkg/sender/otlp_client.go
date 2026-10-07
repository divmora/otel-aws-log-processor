package sender

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/divmora/otel-aws-log-processor/pkg/license"
	"github.com/divmora/otel-aws-log-processor/pkg/model"
	"github.com/divmora/otel-aws-log-processor/pkg/processor"
	"github.com/divmora/otel-aws-log-processor/pkg/version"
)

var Version = version.Get().Version

// OTLPClient handles sending logs to an OTLP endpoint with connection pooling and retry capabilities.
type OTLPClient struct {
	Endpoint      string
	BasicAuthUser string
	BasicAuthPass string
	Headers       map[string]string
	MaxRetries    int
	MaxBatchSize  int
	MaxConcurrent int
	RetryBaseSec  float64
	Logger        *slog.Logger
	LicenseStatus *license.ValidationStatus
	Environment   string
	CallerAccount string
	HTTPClient    *http.Client
}

type resourceGroup struct {
	ResourceAttrs []model.OTelAttribute
	LogRecords    []model.OTelLogRecord
}

// NewOTLPClient creates a new OTLP client configured with reusable HTTP connection pooling.
func NewOTLPClient(endpoint, user, pass string, maxRetries, maxBatchSize, maxConcurrent int, logger *slog.Logger) *OTLPClient {
	maxIdleConnsPerHost := maxConcurrent * 2
	if maxIdleConnsPerHost < 10 {
		maxIdleConnsPerHost = 10
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &OTLPClient{
		Endpoint:      endpoint,
		BasicAuthUser: user,
		BasicAuthPass: pass,
		Headers:       make(map[string]string),
		MaxRetries:    maxRetries,
		MaxBatchSize:  maxBatchSize,
		MaxConcurrent: maxConcurrent,
		RetryBaseSec:  1.0,
		Logger:        logger,
		HTTPClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}
}

// SetHeaders sets custom HTTP headers to be sent with every OTLP export request.
func (c *OTLPClient) SetHeaders(headers map[string]string) {
	if c.Headers == nil {
		c.Headers = make(map[string]string)
	}
	for k, v := range headers {
		c.Headers[k] = v
	}
}

// SetHeader sets a single custom HTTP header.
func (c *OTLPClient) SetHeader(key, value string) {
	if c.Headers == nil {
		c.Headers = make(map[string]string)
	}
	c.Headers[key] = value
}

// SetHTTPClient overrides the underlying HTTP client (primarily for testing and custom transports).
func (c *OTLPClient) SetHTTPClient(client *http.Client) {
	if client != nil {
		c.HTTPClient = client
	}
}

// SetLicenseContext configures licensing metadata to be attached to OTLP resource attributes.
func (c *OTLPClient) SetLicenseContext(status *license.ValidationStatus, env, callerAccount string) {
	c.LicenseStatus = status
	c.Environment = env
	c.CallerAccount = callerAccount
}

// SendLogs converts adapters to OTLP log records and sends them in batches across concurrent goroutines.
func (c *OTLPClient) SendLogs(ctx context.Context, entries []processor.LogAdapter) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// Group by resource
	grouped := make(map[string]*resourceGroup)

	for _, entry := range entries {
		resKey := entry.GetResourceKey()

		if _, exists := grouped[resKey]; !exists {
			attrs := entry.GetResourceAttributes()
			if c.LicenseStatus != nil {
				attrs = license.AppendLicenseAttributes(attrs, c.LicenseStatus, c.Environment, c.CallerAccount)
			}
			grouped[resKey] = &resourceGroup{
				ResourceAttrs: attrs,
				LogRecords:    []model.OTelLogRecord{},
			}
		}

		logRecord := entry.ToOTel()
		grouped[resKey].LogRecords = append(grouped[resKey].LogRecords, logRecord)
	}

	c.Logger.Info("Grouped logs", "resource_group_count", len(grouped))

	sendCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Concurrency control
	sem := make(chan struct{}, c.MaxConcurrent)
	var wg sync.WaitGroup
	errChan := make(chan error, 1)

	totalSent := 0
	var sentLock sync.Mutex

dispatchLoop:
	// Send each group in batches
	for resKey, group := range grouped {
		groupLog := c.Logger.With("resource_key", resKey, "total_logs", len(group.LogRecords))
		groupLog.Info("Processing resource group")

		// Split into batches
		batchCount := 0
		for i := 0; i < len(group.LogRecords); i += c.MaxBatchSize {
			// Check for context cancellation or previous batch errors before spawning more workers
			select {
			case <-sendCtx.Done():
				break dispatchLoop
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

				// Acquire semaphore or abort on context cancellation
				select {
				case <-sendCtx.Done():
					return
				case sem <- struct{}{}:
					defer func() { <-sem }()
				}

				log.Info("Sending batch", "batch_id", bID, "batch_size", bSize)

				if err := c.sendWithRetry(sendCtx, p); err != nil {
					log.Error("Failed to send batch", "batch_id", bID, "error", err)
					select {
					case errChan <- fmt.Errorf("failed to send batch %d: %w", bID, err):
					default:
					}
					cancel()
					return
				}

				sentLock.Lock()
				totalSent += bSize
				sentLock.Unlock()
			}(payload, currentBatchCount, currentBatchSize, groupLog)

			batchCount++
		}
	}

	// Wait for all launched batches to complete or abort
	wg.Wait()

	// Check for any errors that occurred
	select {
	case err := <-errChan:
		return err
	default:
	}

	if err := ctx.Err(); err != nil {
		return err
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

// isRetryableStatus determines whether an HTTP status code represents a transient error that can be retried.
func isRetryableStatus(statusCode int) bool {
	// 429 Too Many Requests (rate limited) and 408 Request Timeout are retryable
	if statusCode == http.StatusTooManyRequests || statusCode == http.StatusRequestTimeout {
		return true
	}
	// 5xx Server Errors (500, 502, 503, 504) are transient and retryable
	if statusCode >= 500 && statusCode < 600 {
		return true
	}
	// 4xx client errors (400, 401, 403, 404, etc.) are deterministic and non-retryable
	return false
}

func (c *OTLPClient) sendWithRetry(ctx context.Context, payload model.OTLPPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	var lastErr error
	var nextSleep time.Duration

	for attempt := 0; attempt <= c.MaxRetries; attempt++ {
		if attempt > 0 {
			sleep := nextSleep
			if sleep <= 0 {
				multiplier := 1 << uint(attempt-1)
				sleep = time.Duration(c.RetryBaseSec*float64(multiplier)) * time.Second
			}
			nextSleep = 0

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(sleep):
			}
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("failed to create HTTP request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "otel-aws-log-processor/"+Version)

		for k, v := range c.Headers {
			req.Header.Set(k, v)
		}

		if c.BasicAuthUser != "" && c.BasicAuthPass != "" && req.Header.Get("Authorization") == "" {
			req.SetBasicAuth(c.BasicAuthUser, c.BasicAuthPass)
		}

		resp, err := client.Do(req)
		if err != nil {
			c.Logger.Warn("Batch send attempt failed with network error", "attempt", attempt+1, "error", err)
			lastErr = err
			continue
		}

		// Read response body fully and close immediately on each attempt to avoid socket/body leaks
		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			c.Logger.Info("Batch sent successfully", "attempt", attempt+1, "status", resp.StatusCode)
			return nil
		}

		// Check if error is non-retryable (e.g. 400 Bad Request, 401 Unauthorized, 403 Forbidden)
		if !isRetryableStatus(resp.StatusCode) {
			c.Logger.Error("Non-retryable HTTP client error received from OTLP endpoint",
				"attempt", attempt+1,
				"status", resp.StatusCode,
				"response", string(respBody),
			)
			return fmt.Errorf("non-retryable HTTP error %d: %s", resp.StatusCode, string(respBody))
		}

		// Parse Retry-After header if present on 429/503
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, parseErr := strconv.Atoi(strings.TrimSpace(ra)); parseErr == nil && secs > 0 {
				if secs > 30 {
					secs = 30
				}
				nextSleep = time.Duration(secs) * time.Second
			}
		}

		c.Logger.Warn("Batch send attempt failed with retryable status",
			"attempt", attempt+1,
			"status", resp.StatusCode,
			"response", string(respBody),
		)
		lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return fmt.Errorf("failed after %d attempts: %w", c.MaxRetries+1, lastErr)
}
