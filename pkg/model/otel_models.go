package model

import "fmt"

// OTelLogRecord represents an OpenTelemetry log record
type OTelLogRecord struct {
	TimeUnixNano   string            `json:"timeUnixNano"`
	SeverityNumber int               `json:"severityNumber"`
	SeverityText   string            `json:"severityText"`
	Body           map[string]string `json:"body"`
	Attributes     []OTelAttribute   `json:"attributes"`
	TraceID        string            `json:"traceId"`
	SpanID         string            `json:"spanId"`
}

// OTelAttribute represents a key-value attribute
type OTelAttribute struct {
	Key   string       `json:"key"`
	Value OTelAnyValue `json:"value"`
}

// OTelAnyValue represents a typed value
type OTelAnyValue struct {
	StringValue *string  `json:"stringValue,omitempty"`
	IntValue    *string  `json:"intValue,omitempty"`
	DoubleValue *float64 `json:"doubleValue,omitempty"`
	BoolValue   *bool    `json:"boolValue,omitempty"`
}

// ResourceAttributes represents resource-level attributes
type ResourceAttributes struct {
	Attributes []OTelAttribute `json:"attributes"`
}

// ScopeLog represents a scope with log records
type ScopeLog struct {
	Scope      Scope           `json:"scope"`
	LogRecords []OTelLogRecord `json:"logRecords"`
}

// Scope represents instrumentation scope
type Scope struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ResourceLog represents a resource with scope logs
type ResourceLog struct {
	Resource  ResourceAttributes `json:"resource"`
	ScopeLogs []ScopeLog         `json:"scopeLogs"`
}

// OTLPPayload represents the complete OTLP payload
type OTLPPayload struct {
	ResourceLogs []ResourceLog `json:"resourceLogs"`
}

// Helper functions for value creation

func StringValue(s string) OTelAnyValue {
	return OTelAnyValue{StringValue: &s}
}

func IntValue(i int) OTelAnyValue {
	s := fmt.Sprintf("%d", i)
	return OTelAnyValue{IntValue: &s}
}

func FloatValue(f float64) OTelAnyValue {
	return OTelAnyValue{DoubleValue: &f}
}

func AddAttr(attrs *[]OTelAttribute, key, value string) {
	if value != "" && value != "-" {
		*attrs = append(*attrs, OTelAttribute{
			Key:   key,
			Value: StringValue(value),
		})
	}
}

// EnsureRegionAccountAttributes ensures cloud.region and cloud.account.id are present
func EnsureRegionAccountAttributes(attrs []OTelAttribute, region, accountID string) []OTelAttribute {
	hasAccount := false
	hasRegion := false

	for _, attr := range attrs {
		if attr.Key == "cloud.account.id" {
			hasAccount = true
		}
		if attr.Key == "cloud.region" {
			hasRegion = true
		}
	}

	if !hasAccount && accountID != "" {
		attrs = append(attrs, OTelAttribute{Key: "cloud.account.id", Value: StringValue(accountID)})
	}
	if !hasRegion && region != "" {
		attrs = append(attrs, OTelAttribute{Key: "cloud.region", Value: StringValue(region)})
	}

	return attrs
}

func AddIntAttr(attrs *[]OTelAttribute, key string, value int) {
	if value != 0 {
		*attrs = append(*attrs, OTelAttribute{
			Key:   key,
			Value: IntValue(value),
		})
	}
}

func AddInt64Attr(attrs *[]OTelAttribute, key string, value int64) {
	if value != 0 {
		s := fmt.Sprintf("%d", value)
		*attrs = append(*attrs, OTelAttribute{
			Key:   key,
			Value: OTelAnyValue{IntValue: &s},
		})
	}
}

func AddFloatAttr(attrs *[]OTelAttribute, key string, value float64) {
	if value != 0 {
		*attrs = append(*attrs, OTelAttribute{
			Key:   key,
			Value: FloatValue(value),
		})
	}
}
