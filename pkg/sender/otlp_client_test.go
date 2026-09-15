package sender

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/divmora/otel-aws-log-processor/pkg/license"
	"github.com/divmora/otel-aws-log-processor/pkg/model"
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
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

	adapters := []mockAdapter{
		{
			resourceKey: "res1",
			resourceAttr: []model.OTelAttribute{
				{Key: "service.name", Value: model.StringValue("test-service")},
			},
		},
	}

	var logAdapters []mockAdapter
	logAdapters = append(logAdapters, adapters...)

	// Convert to []processor.LogAdapter
	var ifaceAdapters []any
	for _, a := range logAdapters {
		ifaceAdapters = append(ifaceAdapters, &a)
	}

	payload := client.buildPayload(adapters[0].GetResourceAttributes(), []model.OTelLogRecord{adapters[0].ToOTel()})
	if len(payload.ResourceLogs) != 1 {
		t.Fatalf("expected 1 ResourceLog, got %d", len(payload.ResourceLogs))
	}
}
