package processor

import (
	"testing"

	"github.com/divmora/otel-aws-log-parser/pkg/parser"
)

func TestALBAdapterToOTel(t *testing.T) {
	entry := &parser.ALBLogEntry{
		Type:                   "h2",
		Time:                   "2025-12-04T00:55:01.294082Z",
		ELB:                    "app/test/12345",
		ClientIP:               "192.168.1.1",
		ClientPort:             12345,
		TargetIP:               "10.0.0.1",
		TargetPort:             80,
		RequestProcessingTime:  0.001,
		TargetProcessingTime:   0.010,
		ResponseProcessingTime: 0.001,
		ELBStatusCode:          200,
		TargetStatusCode:       "200",
		ReceivedBytes:          100,
		SentBytes:              500,
		RequestVerb:            "GET",
		RequestURL:             "https://example.com:443/api/test",
		RequestProto:           "HTTP/2.0",
		UserAgent:              "TestAgent/1.0",
		SSLCipher:              "ECDHE-RSA-AES128-GCM-SHA256",
		SSLProtocol:            "TLSv1.2",
		TargetGroupARN:         "arn:aws:elasticloadbalancing:us-east-1:123456:targetgroup/test/abc",
		TraceID:                "Root=1-58337262-36d228ad5d99923122bbe354",
		DomainName:             "example.com",
	}

	adapter := ALBAdapter{ALBLogEntry: entry}
	record := adapter.ToOTel()

	// Verify basic fields
	if record.SeverityText != "INFO" {
		t.Errorf("SeverityText = %q, want INFO", record.SeverityText)
	}

	if record.SeverityNumber != 9 {
		t.Errorf("SeverityNumber = %d, want 9", record.SeverityNumber)
	}

	if record.TraceID != "5833726236d228ad5d99923122bbe354" {
		t.Errorf("TraceID = %q, want 5833726236d228ad5d99923122bbe354", record.TraceID)
	}

	// Verify some attributes exist
	foundMethod := false
	for _, attr := range record.Attributes {
		if attr.Key == "http.request.method" && attr.Value.StringValue != nil && *attr.Value.StringValue == "GET" {
			foundMethod = true
			break
		}
	}

	if !foundMethod {
		t.Error("http.request.method attribute not found or incorrect")
	}

	// Verify aws.alb.response_processing_time
	foundRespTime := false
	for _, attr := range record.Attributes {
		if attr.Key == "aws.alb.response_processing_time" && attr.Value.DoubleValue != nil && *attr.Value.DoubleValue == 0.001 {
			foundRespTime = true
			break
		}
	}
	if !foundRespTime {
		t.Error("aws.alb.response_processing_time attribute not found or incorrect")
	}

	// Verify aws.lb.name is NOT present (moved to Resource)
	for _, attr := range record.Attributes {
		if attr.Key == "aws.lb.name" {
			t.Error("Found unexpected attribute in Log Record: aws.lb.name")
		}
		// Verify aws.alb.target_group_arn is NOT present (moved to Resource)
		if attr.Key == "aws.alb.target_group_arn" {
			t.Error("Found unexpected attribute in Log Record: aws.alb.target_group_arn")
		}
	}
}

func TestALBAdapterExtractResourceAttributes(t *testing.T) {
	entry := &parser.ALBLogEntry{
		TargetGroupARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test/abc",
		ELB:            "my-load-balancer",
	}

	adapter := ALBAdapter{ALBLogEntry: entry}
	attrs := adapter.GetResourceAttributes()

	// Verify we have at least base attributes + lb name + cloud attributes
	// Provider, Platform, Service, LBName, Region, Account = 6
	if len(attrs) < 6 {
		t.Errorf("Expected at least 6 resource attributes, got %d", len(attrs))
	}

	// Verify cloud.provider exists
	foundProvider := false
	foundLBName := false
	foundCloudService := false
	foundTargetGroupARN := false
	for _, attr := range attrs {
		if attr.Key == "cloud.provider" && attr.Value.StringValue != nil && *attr.Value.StringValue == "aws" {
			foundProvider = true
		}
		if attr.Key == "aws.lb.name" && attr.Value.StringValue != nil && *attr.Value.StringValue == "my-load-balancer" {
			foundLBName = true
		}
		if attr.Key == "cloud.service" && attr.Value.StringValue != nil && *attr.Value.StringValue == "elasticloadbalancing" {
			foundCloudService = true
		}
		if attr.Key == "aws.alb.target_group_arn" && attr.Value.StringValue != nil && *attr.Value.StringValue == "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test/abc" {
			foundTargetGroupARN = true
		}
	}

	if !foundProvider {
		t.Error("cloud.provider attribute not found")
	}
	if !foundLBName {
		t.Error("aws.lb.name attribute not found in Resource Attributes")
	}
	if !foundCloudService {
		t.Error("cloud.service attribute not found in Resource Attributes")
	}
	if !foundTargetGroupARN {
		t.Error("aws.alb.target_group_arn attribute not found in Resource Attributes")
	}
}
