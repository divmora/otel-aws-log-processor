package sender

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
			Tier: license.TierEnterprise,
		},
	}
	client.SetLicenseContext(status, "production", "123456789012")

	adapter := &mockAdapter{
		resourceKey: "res1",
		resourceAttr: []model.OTelAttribute{
			{Key: "service.name", Value: model.StringValue("test-service")},
		},
	}

	err := client.SendLogs([]processor.LogAdapter{adapter})
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
