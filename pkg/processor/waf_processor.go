package processor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/divmora/otel-aws-log-parser/pkg/model"
	"github.com/divmora/otel-aws-log-parser/pkg/parser"
	"github.com/divmora/otel-aws-log-parser/pkg/utils"
)

type WAFProcessor struct {
	MaxBatchSize  int
	MaxConcurrent int
	Parser        parser.LogParser[parser.WAFLogEntry]
}

func (p *WAFProcessor) Name() string {
	return "WAF"
}

func (p *WAFProcessor) Matches(bucket, key string) bool {
	return strings.HasPrefix(bucket, "aws-waf-logs-") && strings.Contains(key, "/WAFLogs/") && strings.Contains(key, "_waflogs_")
}

func (p *WAFProcessor) Process(ctx context.Context, logger *slog.Logger, s3Client *s3.S3, bucket, key string) ([]LogAdapter, error) {
	// Extract common attributes from S3 key
	accountID, region := utils.ParseRegionAccountFromS3Key(key)

	return ReadAndParseJSONFromS3(logger, s3Client, bucket, key, p.MaxBatchSize, p.MaxConcurrent, func(data []byte) (LogAdapter, error) {
		// Use the existing parser mechanism or unmarshal directly
		// Since Parser.ParseLogLine takes a string, we can convert []byte to string
		// Or better, just unmarshal here since we have the bytes
		var entry parser.WAFLogEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, err
		}

		return &WAFAdapter{
			WAFLogEntry: &entry,
			AccountID:   accountID,
			Region:      region,
		}, nil
	})
}

// WAFAdapter implementation
type WAFAdapter struct {
	*parser.WAFLogEntry
	AccountID string
	Region    string
}

func (a *WAFAdapter) GetResourceKey() string {
	return a.WAFLogEntry.WebACLID
}

func (a *WAFAdapter) GetResourceAttributes() []model.OTelAttribute {
	attrs := []model.OTelAttribute{
		{Key: "cloud.provider", Value: model.StringValue("aws")},
		{Key: "cloud.platform", Value: model.StringValue("aws_waf")},
		{Key: "cloud.service", Value: model.StringValue("waf")},
		{Key: "service.name", Value: model.StringValue("waf-log-parser")},
		{Key: "aws.waf.web_acl_id", Value: model.StringValue(a.WAFLogEntry.WebACLID)},
	}

	// Try extracting from WebACLID
	extractedAccount := ""
	extractedRegion := ""

	if a.WAFLogEntry.WebACLID != "" {
		r, acc := utils.ParseRegionAccountFromARN(a.WAFLogEntry.WebACLID)
		if r == "" {
			extractedRegion = "global"
		} else {
			extractedRegion = r
		}
		extractedAccount = acc
	}

	// Use extracted values, fallback to S3 context
	finalAccount := extractedAccount
	if finalAccount == "" {
		finalAccount = a.AccountID
	}

	finalRegion := extractedRegion
	if finalRegion == "" {
		finalRegion = a.Region
	}

	attrs = model.EnsureRegionAccountAttributes(attrs, finalRegion, finalAccount)

	return attrs
}

func (a *WAFAdapter) ToOTel() model.OTelLogRecord {
	// WAF timestamp is already int64 (milliseconds)
	timeUnixNano := a.WAFLogEntry.Timestamp * 1000000

	attributes := a.BuildAttributes()

	severityText := "INFO"
	severityNumber := 9
	if a.WAFLogEntry.Action == "BLOCK" {
		severityText = "WARN"
		severityNumber = 13
	}

	bodyContent := fmt.Sprintf("%s %s %s", a.WAFLogEntry.HTTPRequest.HTTPMethod, a.WAFLogEntry.HTTPRequest.URI, a.WAFLogEntry.Action)

	traceID := ""
	// Try to extract Trace ID from headers
	for _, h := range a.WAFLogEntry.HTTPRequest.Headers {
		if strings.EqualFold(h.Name, "X-Amzn-Trace-Id") {
			traceID = utils.ParseAWSTraceID(h.Value)
			break
		}
	}

	// Fallback to RequestID if it matches Trace ID format
	if traceID == "" && a.WAFLogEntry.HTTPRequest.RequestID != "" {
		traceID = utils.ParseAWSTraceID(a.WAFLogEntry.HTTPRequest.RequestID)
	}

	if traceID == "" {
		traceID = utils.GenerateTraceID()
	}

	spanID := utils.GenerateSpanID()

	return model.OTelLogRecord{
		TimeUnixNano:   fmt.Sprintf("%d", timeUnixNano),
		SeverityNumber: severityNumber,
		SeverityText:   severityText,
		Body:           map[string]string{"stringValue": bodyContent},
		Attributes:     attributes,
		TraceID:        traceID,
		SpanID:         spanID,
	}
}

func (a *WAFAdapter) BuildAttributes() []model.OTelAttribute {
	attrs := []model.OTelAttribute{}
	entry := a.WAFLogEntry

	// WAF Attributes
	model.AddAttr(&attrs, "aws.waf.terminating_rule_id", entry.TerminatingRuleID)
	model.AddAttr(&attrs, "aws.waf.terminating_rule_type", entry.TerminatingRuleType)
	model.AddAttr(&attrs, "aws.waf.action", entry.Action)
	model.AddAttr(&attrs, "aws.waf.http_source_name", entry.HTTPSourceName)
	model.AddAttr(&attrs, "aws.waf.http_source_id", entry.HTTPSourceID)

	// HTTP Attributes
	req := entry.HTTPRequest
	model.AddAttr(&attrs, "http.request.method", req.HTTPMethod)
	model.AddAttr(&attrs, "url.path", req.URI)
	model.AddAttr(&attrs, "url.query", req.Args)
	model.AddAttr(&attrs, "network.protocol.version", req.HTTPVersion)
	model.AddAttr(&attrs, "client.address", req.ClientIP)

	// User Agent from headers
	for _, h := range req.Headers {
		if strings.EqualFold(h.Name, "User-Agent") {
			model.AddAttr(&attrs, "user_agent.original", h.Value)
		}
		if strings.EqualFold(h.Name, "Host") {
			model.AddAttr(&attrs, "server.address", h.Value)
		}
	}

	// Additional Details
	model.AddAttr(&attrs, "client.geo.country_iso_code", req.Country)
	model.AddInt64Attr(&attrs, "http.request.body.size", entry.RequestBodySize)
	model.AddInt64Attr(&attrs, "aws.waf.request_body_size_inspected", entry.RequestBodySizeInspected)
	model.AddAttr(&attrs, "tls.client.ja3", entry.JA3Fingerprint)
	model.AddAttr(&attrs, "tls.client.ja4", entry.JA4Fingerprint)

	if len(entry.Labels) > 0 {
		var labels []string
		for _, l := range entry.Labels {
			labels = append(labels, l.Name)
		}
		lblBytes, _ := json.Marshal(labels)
		model.AddAttr(&attrs, "aws.waf.labels", string(lblBytes))
	}

	// Collect all processed rules
	processedRules := collectProcessedRules(entry)
	if len(processedRules) > 0 {
		jsonBytes, err := json.Marshal(processedRules)
		if err == nil {
			model.AddAttr(&attrs, "aws.waf.processed_rules", string(jsonBytes))
		}
	}

	return attrs
}

type ProcessedRule struct {
	RuleID string `json:"ruleId"`
	Action string `json:"action"`
	Type   string `json:"type,omitempty"` // TERMINATING, NON_TERMINATING, GROUP
}

func collectProcessedRules(entry *parser.WAFLogEntry) []ProcessedRule {
	var rules []ProcessedRule

	// 1. Terminating Rule
	if entry.TerminatingRuleID != "" {
		rules = append(rules, ProcessedRule{
			RuleID: entry.TerminatingRuleID,
			Action: entry.Action,
			Type:   "TERMINATING",
		})
	}

	// 2. Non-Terminating Rules
	for _, rule := range entry.NonTerminatingMatchingRules {
		rules = append(rules, ProcessedRule{
			RuleID: rule.RuleID,
			Action: rule.Action,
			Type:   "NON_TERMINATING",
		})
	}

	// 3. Rule Groups
	for _, group := range entry.RuleGroupList {
		// If the group itself has specific actions or inner rules
		if group.TerminatingRule != nil {
			rules = append(rules, ProcessedRule{
				RuleID: group.TerminatingRule.RuleID,
				Action: group.TerminatingRule.Action,
				Type:   "GROUP_TERMINATING",
			})
		}
		for _, rule := range group.NonTerminatingRules {
			rules = append(rules, ProcessedRule{
				RuleID: rule.RuleID,
				Action: rule.Action,
				Type:   "GROUP_NON_TERMINATING",
			})
		}
	}

	return rules
}
