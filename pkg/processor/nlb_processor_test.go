package processor

import (
	"testing"

	"github.com/divmora/otel-aws-log-processor/pkg/model"
	"github.com/divmora/otel-aws-log-processor/pkg/parser"
)

func TestNLBAdapterToOTel(t *testing.T) {
	entry := &parser.NLBLogEntry{
		Type:                      "tls",
		Version:                   "2.0",
		Time:                      "2023-10-27T10:00:00.123456Z",
		ELB:                       "app/my-load-balancer/50dc6c495c0c9188",
		ListenerID:                "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/net/my-load-balancer/50dc6c495c0c9188/0467ef8c84b359db",
		ClientIP:                  "192.168.1.100",
		ClientPort:                54321,
		TargetIP:                  "10.0.0.1",
		TargetPort:                8080,
		ConnectionTime:            5.5,
		TLSHandshakeTime:          1.2,
		ReceivedBytes:             1024,
		SentBytes:                 2048,
		IncomingTLSAlert:          "-",
		ChosenCertARN:             "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
		ChosenCertSerial:          "12345",
		TLSCipher:                 "ECDHE-RSA-AES128-GCM-SHA256",
		TLSProtocolVersion:        "TLSv1.2",
		TLSNamedGroup:             "-",
		DomainName:                "example.com",
		ALPNFrontEndProtocol:      "-",
		ALPNBackEndProtocol:       "-",
		ALPNClientPreferenceList:  "-",
		TLSConnectionCreationTime: "2023-10-27T10:00:00.123000Z",
	}

	adapter := NLBAdapter{NLBLogEntry: entry}
	record := adapter.ToOTel()

	// Verify basic fields
	if record.SeverityText != "INFO" {
		t.Errorf("SeverityText = %q, want INFO", record.SeverityText)
	}

	if record.SeverityNumber != 9 {
		t.Errorf("SeverityNumber = %d, want 9", record.SeverityNumber)
	}

	if record.TraceID == "" {
		t.Error("TraceID should be generated")
	}

	if record.SpanID == "" {
		t.Error("SpanID should be generated")
	}

	// Verify body
	expectedBody := "tls log for app/my-load-balancer/50dc6c495c0c9188"
	if record.Body["stringValue"] != expectedBody {
		t.Errorf("Body = %q, want %q", record.Body["stringValue"], expectedBody)
	}

	// Verify some attributes exist
	foundCipher := false
	foundBytes := false
	foundTransport := false

	for _, attr := range record.Attributes {
		if attr.Key == "tls.cipher_suite" && attr.Value.StringValue != nil && *attr.Value.StringValue == "ECDHE-RSA-AES128-GCM-SHA256" {
			foundCipher = true
		}
		if attr.Key == "aws.nlb.received_bytes" && attr.Value.IntValue != nil && *attr.Value.IntValue == "1024" {
			foundBytes = true
		}
		if attr.Key == "network.transport" && attr.Value.StringValue != nil && *attr.Value.StringValue == "tcp" {
			foundTransport = true
		}

		// Verify excluded resource attributes
		if attr.Key == "aws.lb.name" {
			t.Error("Found unexpected attribute in Log Record: aws.lb.name")
		}
	}

	if !foundCipher {
		t.Error("tls.cipher_suite attribute not found or incorrect")
	}
	if !foundBytes {
		t.Error("aws.nlb.received_bytes attribute not found or incorrect")
	}
	if !foundTransport {
		t.Error("network.transport attribute not found or incorrect")
	}
}

func TestNLBAdapterToOTel_TCP(t *testing.T) {
	entry := &parser.NLBLogEntry{
		Type:           "tcp",
		Version:        "2.0",
		Time:           "2023-10-27T10:00:00.123456Z",
		ELB:            "net/my-load-balancer/50dc6c495c0c9188",
		ListenerID:     "listener/net/my-load-balancer/50dc6c495c0c9188/0467ef8c84b359db",
		ClientIP:       "192.168.1.100",
		ClientPort:     54321,
		TargetIP:       "", // unrouted target
		TargetPort:     0,
		ConnectionTime: 1.5,
		ReceivedBytes:  512,
		SentBytes:      1024,
	}

	adapter := NLBAdapter{NLBLogEntry: entry}
	record := adapter.ToOTel()

	expectedBody := "tcp log for net/my-load-balancer/50dc6c495c0c9188"
	if record.Body["stringValue"] != expectedBody {
		t.Errorf("Body = %q, want %q", record.Body["stringValue"], expectedBody)
	}

	attrMap := make(map[string]model.OTelAttribute)
	for _, attr := range record.Attributes {
		attrMap[attr.Key] = attr
	}

	// Verify TCP specific attributes
	if attr, ok := attrMap["network.transport"]; !ok || attr.Value.StringValue == nil || *attr.Value.StringValue != "tcp" {
		t.Errorf("expected network.transport = tcp, got %+v", attr)
	}
	if attr, ok := attrMap["network.protocol.name"]; !ok || attr.Value.StringValue == nil || *attr.Value.StringValue != "tcp" {
		t.Errorf("expected network.protocol.name = tcp, got %+v", attr)
	}
	if attr, ok := attrMap["aws.nlb.type"]; !ok || attr.Value.StringValue == nil || *attr.Value.StringValue != "tcp" {
		t.Errorf("expected aws.nlb.type = tcp, got %+v", attr)
	}
	if attr, ok := attrMap["aws.nlb.received_bytes"]; !ok || attr.Value.IntValue == nil || *attr.Value.IntValue != "512" {
		t.Errorf("expected aws.nlb.received_bytes = 512, got %+v", attr)
	}
	if attr, ok := attrMap["aws.nlb.sent_bytes"]; !ok || attr.Value.IntValue == nil || *attr.Value.IntValue != "1024" {
		t.Errorf("expected aws.nlb.sent_bytes = 1024, got %+v", attr)
	}

	// Verify unrouted target does NOT add server attributes
	if _, ok := attrMap["server.address"]; ok {
		t.Error("server.address should be omitted when TargetIP is empty")
	}
	if _, ok := attrMap["server.port"]; ok {
		t.Error("server.port should be omitted when TargetPort is 0")
	}

	// Verify TLS attributes are NOT present in TCP log
	for _, tlsKey := range []string{"tls.cipher_suite", "tls.protocol.version", "tls.server.name", "aws.nlb.tls_handshake_time"} {
		if _, ok := attrMap[tlsKey]; ok {
			t.Errorf("unexpected TLS attribute %s in TCP log", tlsKey)
		}
	}
}

func TestNLBAdapterExtractResourceAttributes(t *testing.T) {
	// Case 1: With ChosenCertARN (contains region/account)
	entry1 := &parser.NLBLogEntry{
		ChosenCertARN: "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
		ELB:           "app/my-load-balancer/50dc6c495c0c9188",
	}

	adapter1 := NLBAdapter{NLBLogEntry: entry1}
	attrs1 := adapter1.GetResourceAttributes()

	// Verify attributes
	expectedAttrs := map[string]string{
		"cloud.provider":   "aws",
		"cloud.platform":   "aws_elastic_load_balancing",
		"service.name":     "nlb-log-parser",
		"aws.lb.name":      "app/my-load-balancer/50dc6c495c0c9188",
		"cloud.region":     "us-east-1",
		"cloud.account.id": "123456789012",
	}

	verifyAttributes(t, attrs1, expectedAttrs)

	// Case 2: Without ChosenCertARN (empty) - Should default to base attributes
	// Note: The code doesn't fall back to ListenerID for region/account extraction inside GetResourceAttributes
	// It only checks ChosenCertARN for region/account extraction.
	entry2 := &parser.NLBLogEntry{
		ChosenCertARN: "-",
		ELB:           "app/my-load-balancer/50dc6c495c0c9188",
	}

	adapter2 := NLBAdapter{NLBLogEntry: entry2}
	attrs2 := adapter2.GetResourceAttributes()

	expectedAttrs2 := map[string]string{
		"cloud.provider": "aws",
		"cloud.platform": "aws_elastic_load_balancing",
		"service.name":   "nlb-log-parser",
		"aws.lb.name":    "app/my-load-balancer/50dc6c495c0c9188",
	}

	verifyAttributes(t, attrs2, expectedAttrs2)

	// Verify region/account are NOT present for Case 2
	for _, attr := range attrs2 {
		if attr.Key == "cloud.region" || attr.Key == "cloud.account.id" {
			t.Errorf("Unexpected attribute %s found when ARN is missing", attr.Key)
		}
	}

	// Case 3: Without ChosenCertARN ("-"), but with AccountID and Region populated from S3 key context
	entry3 := &parser.NLBLogEntry{
		ChosenCertARN: "-",
		ELB:           "net/my-load-balancer/50dc6c495c0c9188",
	}
	adapter3 := NLBAdapter{
		NLBLogEntry: entry3,
		AccountID:   "999988887777",
		Region:      "eu-west-1",
	}
	attrs3 := adapter3.GetResourceAttributes()
	expectedAttrs3 := map[string]string{
		"cloud.provider":   "aws",
		"cloud.platform":   "aws_elastic_load_balancing",
		"service.name":     "nlb-log-parser",
		"aws.lb.name":      "net/my-load-balancer/50dc6c495c0c9188",
		"cloud.region":     "eu-west-1",
		"cloud.account.id": "999988887777",
	}
	verifyAttributes(t, attrs3, expectedAttrs3)
}

func TestNLBAdapter_GetResourceKey(t *testing.T) {
	// 1. ChosenCertARN present
	a1 := NLBAdapter{
		NLBLogEntry: &parser.NLBLogEntry{
			ChosenCertARN: "arn:aws:acm:us-east-1:123456789012:certificate/abc",
			ListenerID:    "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/net/my-nlb/123/456",
			ELB:           "net/my-nlb/123",
		},
	}
	if key := a1.GetResourceKey(); key != "arn:aws:acm:us-east-1:123456789012:certificate/abc" {
		t.Errorf("got %q, want cert ARN", key)
	}

	// 2. ChosenCertARN empty, ListenerID present
	a2 := NLBAdapter{
		NLBLogEntry: &parser.NLBLogEntry{
			ChosenCertARN: "-",
			ListenerID:    "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/net/my-nlb/123/456",
			ELB:           "net/my-nlb/123",
		},
	}
	if key := a2.GetResourceKey(); key != "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/net/my-nlb/123/456" {
		t.Errorf("got %q, want listener ARN", key)
	}

	// 3. Both cert and listener empty/dash -> fallback to ELB
	a3 := NLBAdapter{
		NLBLogEntry: &parser.NLBLogEntry{
			ChosenCertARN: "-",
			ListenerID:    "-",
			ELB:           "net/my-nlb/123",
		},
	}
	if key := a3.GetResourceKey(); key != "net/my-nlb/123" {
		t.Errorf("got %q, want ELB name", key)
	}
}

func verifyAttributes(t *testing.T, attrs []model.OTelAttribute, expected map[string]string) {
	// Create a map from actual attributes for easy lookup
	actualMap := make(map[string]string)
	for _, attr := range attrs {
		if attr.Value.StringValue != nil {
			actualMap[attr.Key] = *attr.Value.StringValue
		}
	}

	for k, v := range expected {
		if val, ok := actualMap[k]; !ok {
			t.Errorf("Attribute %s missing", k)
		} else if val != v {
			t.Errorf("Attribute %s = %q, want %q", k, val, v)
		}
	}
}
