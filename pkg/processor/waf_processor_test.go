package processor

import (
	"encoding/json"
	"testing"

	"github.com/divmora/otel-aws-log-processor/pkg/model"
	"github.com/divmora/otel-aws-log-processor/pkg/parser"
)

func TestWAFAdapterToOTel_ProcessedRules(t *testing.T) {
	entry := &parser.WAFLogEntry{
		Timestamp:         1609459200000,
		Action:            "BLOCK",
		TerminatingRuleID: "TerminatingRule",
		NonTerminatingMatchingRules: []parser.NonTerminatingRule{
			{RuleID: "NonTerminatingRule1", Action: "COUNT"},
		},
		RuleGroupList: []parser.RuleGroup{
			{
				TerminatingRule: &parser.RuleGroupRule{RuleID: "GroupTerminatingRule", Action: "BLOCK"},
				NonTerminatingRules: []parser.RuleGroupRule{
					{RuleID: "GroupNonTerminatingRule", Action: "COUNT"},
				},
			},
		},
		HTTPRequest: parser.HTTPRequest{
			HTTPMethod: "GET",
			URI:        "/",
			RequestID:  "1-58337262-36d228ad5d99923122bbe354",
			Country:    "IN",
			Headers: []parser.Header{
				{Name: "Host", Value: "example.com"},
			},
		},
		Labels:                   []parser.Label{{Name: "awswaf:clientip:geo:country:IN"}},
		RequestBodySize:          21,
		RequestBodySizeInspected: 21,
		JA3Fingerprint:           "f79b6bad2ad0641e1921aef10262856b",
		JA4Fingerprint:           "t13d1513h2_8daaf6152771_eca864cca44a",
	}

	adapter := WAFAdapter{WAFLogEntry: entry}
	record := adapter.ToOTel()

	// Verify TraceID is extracted correctly from RequestID
	if record.TraceID != "5833726236d228ad5d99923122bbe354" {
		t.Errorf("TraceID = %q, want 5833726236d228ad5d99923122bbe354", record.TraceID)
	}

	// Verify new attributes
	expectedAttrs := map[string]string{
		"client.geo.country_iso_code": "IN",
		"aws.waf.labels":              `["awswaf:clientip:geo:country:IN"]`,
		"tls.client.ja3":              "f79b6bad2ad0641e1921aef10262856b",
		"tls.client.ja4":              "t13d1513h2_8daaf6152771_eca864cca44a",
	}

	for k, v := range expectedAttrs {
		found := false
		for _, attr := range record.Attributes {
			if attr.Key == k && attr.Value.StringValue != nil && *attr.Value.StringValue == v {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Attribute %q = %q not found", k, v)
		}
	}

	var processedRulesAttr *model.OTelAttribute
	for _, attr := range record.Attributes {
		if attr.Key == "aws.waf.processed_rules" {
			// Taking address of loop variable is risky in older Go but okay in 1.22+
			// but to be safe:
			val := attr
			processedRulesAttr = &val
			break
		}
	}

	if processedRulesAttr == nil {
		t.Fatal("aws.waf.processed_rules attribute not found")
	}

	if processedRulesAttr.Value.StringValue == nil {
		t.Fatal("aws.waf.processed_rules value is nil")
	}

	jsonValue := *processedRulesAttr.Value.StringValue
	var rules []ProcessedRule
	if err := json.Unmarshal([]byte(jsonValue), &rules); err != nil {
		t.Fatalf("Failed to unmarshal processed rules JSON: %v", err)
	}

	// Expect 4 rules: 1 Terminating + 1 NonTerminating + 1 GroupTerminating + 1 GroupNonTerminating
	if len(rules) != 4 {
		t.Errorf("Expected 4 processed rules, got %d", len(rules))
	}

	// Verify specific rule presence
	ruleMap := make(map[string]ProcessedRule)
	for _, r := range rules {
		ruleMap[r.RuleID] = r
	}

	if r, ok := ruleMap["TerminatingRule"]; !ok || r.Type != "TERMINATING" {
		t.Error("TerminatingRule missing or incorrect type")
	}
	if r, ok := ruleMap["NonTerminatingRule1"]; !ok || r.Type != "NON_TERMINATING" {
		t.Error("NonTerminatingRule1 missing or incorrect type")
	}
	if r, ok := ruleMap["GroupTerminatingRule"]; !ok || r.Type != "GROUP_TERMINATING" {
		t.Error("GroupTerminatingRule missing or incorrect type")
	}
	if r, ok := ruleMap["GroupNonTerminatingRule"]; !ok || r.Type != "GROUP_NON_TERMINATING" {
		t.Error("GroupNonTerminatingRule missing or incorrect type")
	}

	// Verify that cloud.* attributes are NOT present (should be in Resource, not Log Record)
	for _, attr := range record.Attributes {
		if attr.Key == "cloud.provider" || attr.Key == "cloud.platform" || attr.Key == "service.name" {
			t.Errorf("Found unexpected attribute in Log Record: %s", attr.Key)
		}
		// Verify aws.waf.web_acl_id is NOT present (moved to Resource)
		if attr.Key == "aws.waf.web_acl_id" {
			t.Errorf("Found unexpected attribute in Log Record: %s", attr.Key)
		}
	}
}
