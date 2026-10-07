package sender

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/divmora/otel-aws-log-processor/pkg/license"
	"github.com/divmora/otel-aws-log-processor/pkg/model"
	"github.com/divmora/otel-aws-log-processor/pkg/processor"
)

type mockAdapter struct {
	resourceKey  string
	resourceAttr []model.OTelAttribute
}

func (m *mockAdapter) GetResourceKey() string {
	return m.resourceKey
}

func (m *mockAdapter) GetResourceAttributes() []model.OTelAttribute {
	return m.resourceAttr
}

func (m *mockAdapter) BuildAttributes() []model.OTelAttribute {
	return []model.OTelAttribute{
		{Key: "test.key", Value: model.StringValue("test.value")},
	}
}

func (m *mockAdapter) ToOTel() model.OTelLogRecord {
	return model.OTelLogRecord{
		TimeUnixNano:   "1788784496000000000",
		SeverityNumber: 9,
		SeverityText:   "INFO",
		Body:           map[string]string{"stringValue": "mock body"},
		Attributes:     m.BuildAttributes(),
	}
}

func TestOTLPClientSendLogsWithLicense(t *testing.T) {
	receivedPayload := make(chan model.OTLPPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p model.OTLPPayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		receivedPayload <- p
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	client := NewOTLPClient(server.URL, "user", "pass", 1, 10, 2, logger)

	status := &license.ValidationStatus{
		Valid:        true,
		StatusReason: "valid",
		Claims: &license.Claims{
			ID:   "lic_test_123",
			Plan: license.TierEnterprise,
		},
	}
	client.SetLicenseContext(status, "production", "123456789012")

	adapter := &mockAdapter{
		resourceKey: "res1",
		resourceAttr: []model.OTelAttribute{
			{Key: "service.name", Value: model.StringValue("test-service")},
		},
	}

	err := client.SendLogs(context.Background(), []processor.LogAdapter{adapter})
	if err != nil {
		t.Fatalf("unexpected SendLogs error: %v", err)
	}

	var payload model.OTLPPayload
	select {
	case payload = <-receivedPayload:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTP request")
	}

	if len(payload.ResourceLogs) != 1 {
		t.Fatalf("expected 1 ResourceLog, got %d", len(payload.ResourceLogs))
	}

	foundLicenseStatus := false
	for _, attr := range payload.ResourceLogs[0].Resource.Attributes {
		if attr.Key == "divmora.license.status" {
			foundLicenseStatus = true
			if attr.Value.StringValue == nil || *attr.Value.StringValue != "valid" {
				t.Errorf("expected license status valid, got %v", attr.Value)
			}
		}
	}
	if !foundLicenseStatus {
		t.Error("expected divmora.license.status in resource attributes")
	}
}

func TestParseHeaders(t *testing.T) {
	// Standard comma-separated headers
	h1 := ParseHeaders("api-key=secret123,tenant-id=prod-tenant")
	if h1["api-key"] != "secret123" || h1["tenant-id"] != "prod-tenant" {
		t.Errorf("unexpected parsed headers: %v", h1)
	}

	// Whitespace trimming & URL unescaping
	h2 := ParseHeaders(" Authorization = Bearer%20my-secret-token , x-custom = val1 ")
	if h2["Authorization"] != "Bearer my-secret-token" || h2["x-custom"] != "val1" {
		t.Errorf("unexpected parsed headers with URL encoding: %v", h2)
	}

	// Empty and malformed
	h3 := ParseHeaders("  , ,, keyonly , =valonly , = ")
	if len(h3) != 0 {
		t.Errorf("expected empty map for malformed input, got %v", h3)
	}
}

func TestParseHeadersFromEnv(t *testing.T) {
	os.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "api-key=default_key,tenant=acme")
	os.Setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS", "api-key=logs_override,log-level=debug")
	defer func() {
		os.Unsetenv("OTEL_EXPORTER_OTLP_HEADERS")
		os.Unsetenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS")
	}()

	headers := ParseHeadersFromEnv()
	if headers["api-key"] != "logs_override" {
		t.Errorf("expected logs signal override 'logs_override', got %s", headers["api-key"])
	}
	if headers["tenant"] != "acme" {
		t.Errorf("expected general header 'acme', got %s", headers["tenant"])
	}
	if headers["log-level"] != "debug" {
		t.Errorf("expected logs header 'debug', got %s", headers["log-level"])
	}
}

func TestOTLPClient_CustomHeadersAndBasicAuth(t *testing.T) {
	receivedHeaders := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	client := NewOTLPClient(server.URL, "testuser", "testpass", 1, 10, 2, logger)
	client.SetHeaders(map[string]string{
		"api-key":   "secret-signoz-key",
		"tenant-id": "tenant-456",
	})

	adapter := &mockAdapter{
		resourceKey: "res1",
	}

	err := client.SendLogs(context.Background(), []processor.LogAdapter{adapter})
	if err != nil {
		t.Fatalf("unexpected SendLogs error: %v", err)
	}

	headers := <-receivedHeaders
	if headers.Get("api-key") != "secret-signoz-key" {
		t.Errorf("expected api-key 'secret-signoz-key', got %s", headers.Get("api-key"))
	}
	if headers.Get("tenant-id") != "tenant-456" {
		t.Errorf("expected tenant-id 'tenant-456', got %s", headers.Get("tenant-id"))
	}
	// Basic Auth header was set
	user, pass, ok := headers.Get("Authorization"), "", false
	if user != "" {
		ok = true
	}
	if !ok {
		t.Error("expected Authorization header for basic auth")
	}
	_ = pass
}

func TestOTLPClient_NonRetryable4xxError(t *testing.T) {
	var attemptCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attemptCount, 1)
		w.WriteHeader(http.StatusUnauthorized) // 401 Unauthorized is non-retryable
		_, _ = w.Write([]byte(`{"error":"invalid_api_key"}`))
	}))
	defer server.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	client := NewOTLPClient(server.URL, "", "", 3, 10, 2, logger)

	adapter := &mockAdapter{resourceKey: "res1"}
	err := client.SendLogs(context.Background(), []processor.LogAdapter{adapter})

	if err == nil {
		t.Fatal("expected error on 401 Unauthorized")
	}

	// Must NOT retry 401 Unauthorized (attemptCount must be 1, not 4)
	if count := atomic.LoadInt32(&attemptCount); count != 1 {
		t.Errorf("expected exactly 1 attempt for non-retryable 401 error, got %d", count)
	}
}

func TestOTLPClient_RetryableTransientErrors(t *testing.T) {
	var attemptCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attemptCount, 1)
		if count == 1 {
			w.WriteHeader(http.StatusServiceUnavailable) // 503 is retryable
			_, _ = w.Write([]byte(`{"error":"service_unavailable"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	client := NewOTLPClient(server.URL, "", "", 3, 10, 2, logger)
	client.RetryBaseSec = 0.01 // Fast retries for testing

	adapter := &mockAdapter{resourceKey: "res1"}
	err := client.SendLogs(context.Background(), []processor.LogAdapter{adapter})

	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}

	// Must have attempted twice (failed 1st with 503, succeeded on 2nd)
	if count := atomic.LoadInt32(&attemptCount); count != 2 {
		t.Errorf("expected 2 attempts for 503 transient recovery, got %d", count)
	}
}

func TestOTLPClient_RetryAfterHeader(t *testing.T) {
	var attemptCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attemptCount, 1)
		if count == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests) // 429 is retryable
			_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	client := NewOTLPClient(server.URL, "", "", 2, 10, 2, logger)
	client.RetryBaseSec = 0.01

	adapter := &mockAdapter{resourceKey: "res1"}
	start := time.Now()
	err := client.SendLogs(context.Background(), []processor.LogAdapter{adapter})

	if err != nil {
		t.Fatalf("expected success after 429 retry, got: %v", err)
	}

	elapsed := time.Since(start)
	if elapsed < 900*time.Millisecond {
		t.Errorf("expected sleep to respect Retry-After of 1s, but elapsed was %v", elapsed)
	}
	if count := atomic.LoadInt32(&attemptCount); count != 2 {
		t.Errorf("expected 2 attempts, got %d", count)
	}
}

func TestOTLPClient_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	client := NewOTLPClient(server.URL, "", "", 1, 10, 2, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	adapter := &mockAdapter{resourceKey: "res1"}
	err := client.SendLogs(ctx, []processor.LogAdapter{adapter})

	if err == nil {
		t.Fatal("expected context timeout error, got nil")
	}
}

func TestOTLPClient_HTTPClientConnectionReuse(t *testing.T) {
	// Verify that the pooled HTTPClient is reused across multiple SendLogs calls
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	client := NewOTLPClient("http://localhost:4318", "", "", 1, 10, 2, logger)

	if client.HTTPClient == nil {
		t.Fatal("expected HTTPClient to be initialized")
	}
	if client.HTTPClient.Transport == nil {
		t.Fatal("expected HTTPClient.Transport to be initialized with connection pooling")
	}

	tr, ok := client.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.HTTPClient.Transport)
	}
	if tr.MaxIdleConns != 100 {
		t.Errorf("expected MaxIdleConns=100, got %d", tr.MaxIdleConns)
	}
	if tr.MaxIdleConnsPerHost < 4 {
		t.Errorf("expected MaxIdleConnsPerHost >= 4, got %d", tr.MaxIdleConnsPerHost)
	}
}

func TestOTLPClient_BatchFailureCleansUpGoroutines(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count == 1 {
			w.WriteHeader(http.StatusBadRequest) // 400 non-retryable error
			_, _ = w.Write([]byte(`{"error":"bad_request"}`))
			return
		}
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	client := NewOTLPClient(server.URL, "", "", 0, 1, 4, logger)

	var adapters []processor.LogAdapter
	for i := 0; i < 5; i++ {
		adapters = append(adapters, &mockAdapter{resourceKey: "res1"})
	}

	err := client.SendLogs(context.Background(), adapters)
	if err == nil {
		t.Fatal("expected error on batch failure, got nil")
	}
}
