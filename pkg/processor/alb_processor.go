package processor

import (
	"context"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/divmora/otel-aws-log-parser/pkg/model"
	"github.com/divmora/otel-aws-log-parser/pkg/parser"
	"fmt"

	"github.com/divmora/otel-aws-log-parser/pkg/utils"
)

type ALBProcessor struct {
	MaxBatchSize  int
	MaxConcurrent int
	Parser        parser.LogParser[parser.ALBLogEntry]
}

func (p *ALBProcessor) Name() string {
	return "ALB"
}

func (p *ALBProcessor) Matches(bucket, key string) bool {
	return strings.Contains(key, "/elasticloadbalancing/") && strings.Contains(key, "_app.")
}

func (p *ALBProcessor) Process(ctx context.Context, logger *slog.Logger, s3Client *s3.S3, bucket, key string) ([]LogAdapter, error) {
	// Extract common attributes from S3 key
	accountID, region := utils.ParseRegionAccountFromS3Key(key)

	return ReadAndParseFromS3(logger, s3Client, bucket, key, p.MaxBatchSize, p.MaxConcurrent, func(line string) (LogAdapter, error) {
		entry, err := p.Parser.ParseLogLine(line)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			return nil, nil
		}
		return ALBAdapter{
			ALBLogEntry: entry,
			AccountID:   accountID,
			Region:      region,
		}, nil
	})
}

// ALBAdapter implementation
type ALBAdapter struct {
	*parser.ALBLogEntry
	AccountID string
	Region    string
}

func (a ALBAdapter) GetResourceKey() string {
	arn := a.ALBLogEntry.TargetGroupARN
	if arn == "" || arn == "-" {
		arn = a.ALBLogEntry.ELB
	}
	return arn
}

func (a ALBAdapter) GetResourceAttributes() []model.OTelAttribute {
	entry := a.ALBLogEntry
	attrs := []model.OTelAttribute{
		{Key: "cloud.provider", Value: model.StringValue("aws")},
		{Key: "cloud.platform", Value: model.StringValue("aws_elastic_load_balancing")},
		{Key: "cloud.service", Value: model.StringValue("elasticloadbalancing")},
		{Key: "service.name", Value: model.StringValue("alb-log-parser")},
		{Key: "aws.lb.name", Value: model.StringValue(entry.ELB)},
	}

	// Extract region and account from ARN
	arn := entry.TargetGroupARN

	if arn != "" && arn != "-" {
		// Add TargetGroupARN to resource attributes if available
		if entry.TargetGroupARN != "" && entry.TargetGroupARN != "-" {
			attrs = append(attrs, model.OTelAttribute{Key: "aws.alb.target_group_arn", Value: model.StringValue(entry.TargetGroupARN)})
		}

		region, accountID := utils.ParseRegionAccountFromARN(arn)
		if region != "" {
			attrs = append(attrs, model.OTelAttribute{Key: "cloud.region", Value: model.StringValue(region)})
		}
		if accountID != "" {
			attrs = append(attrs, model.OTelAttribute{Key: "cloud.account.id", Value: model.StringValue(accountID)})
		}
	}

	// Check if cloud attributes are missing and fill from S3 key context
	attrs = model.EnsureRegionAccountAttributes(attrs, a.Region, a.AccountID)

	return attrs
}

func (a ALBAdapter) ToOTel() model.OTelLogRecord {
	// Convert timestamp
	timeUnixNano := utils.ConvertTimestamp(a.ALBLogEntry.Time)

	// Build attributes
	attributes := a.BuildAttributes()

	// Determine severity
	severityText := "INFO"
	severityNumber := 9

	if a.ALBLogEntry.ELBStatusCode >= 500 {
		severityText = "ERROR"
		severityNumber = 17
	} else if a.ALBLogEntry.ELBStatusCode >= 400 {
		severityText = "WARN"
		severityNumber = 13
	}

	// Build body
	bodyContent := strings.Join([]string{a.ALBLogEntry.RequestVerb, a.ALBLogEntry.RequestURL, a.ALBLogEntry.RequestProto}, " ")

	// Parse trace ID
	traceID := utils.ParseAWSTraceID(a.ALBLogEntry.TraceID)

	// Generate a random Span ID (16 hex chars)
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

func (a ALBAdapter) BuildAttributes() []model.OTelAttribute {
	attrs := []model.OTelAttribute{}
	entry := a.ALBLogEntry

	// HTTP attributes
	model.AddAttr(&attrs, "http.request.method", entry.RequestVerb)
	model.AddIntAttr(&attrs, "http.response.status_code", entry.ELBStatusCode)
	model.AddInt64Attr(&attrs, "http.request.body.size", entry.ReceivedBytes)
	model.AddInt64Attr(&attrs, "http.response.body.size", entry.SentBytes)
	model.AddAttr(&attrs, "url.full", entry.RequestURL)

	// Parse URL for additional attributes
	urlAttrs := utils.ParseRequestURL(entry.RequestURL)
	for k, v := range urlAttrs {
		model.AddAttr(&attrs, k, v)
	}

	// Network attributes
	model.AddAttr(&attrs, "network.protocol.name", "http")
	model.AddAttr(&attrs, "network.protocol.version", entry.RequestProto)

	// Client attributes
	model.AddAttr(&attrs, "client.address", entry.ClientIP)
	model.AddIntAttr(&attrs, "client.port", entry.ClientPort)

	// Server attributes
	model.AddAttr(&attrs, "server.address", entry.DomainName)
	model.AddAttr(&attrs, "server.socket.address", entry.TargetIP)
	model.AddIntAttr(&attrs, "server.socket.port", entry.TargetPort)

	// User agent
	model.AddAttr(&attrs, "user_agent.original", entry.UserAgent)

	// TLS attributes
	model.AddAttr(&attrs, "tls.cipher_suite", entry.SSLCipher)
	model.AddAttr(&attrs, "tls.protocol.version", entry.SSLProtocol)

	// AWS-specific attributes
	model.AddAttr(&attrs, "aws.alb.type", entry.Type)
	model.AddFloatAttr(&attrs, "aws.alb.request_processing_time", entry.RequestProcessingTime)
	model.AddFloatAttr(&attrs, "aws.alb.target_processing_time", entry.TargetProcessingTime)
	model.AddFloatAttr(&attrs, "aws.alb.response_processing_time", entry.ResponseProcessingTime)
	model.AddAttr(&attrs, "aws.alb.target_status_code", entry.TargetStatusCode)
	model.AddAttr(&attrs, "aws.alb.trace_id", entry.TraceID)
	model.AddAttr(&attrs, "aws.alb.chosen_cert_arn", entry.ChosenCertARN)
	model.AddAttr(&attrs, "aws.alb.matched_rule_priority", entry.MatchedRulePriority)
	model.AddAttr(&attrs, "aws.alb.request_creation_time", entry.RequestCreationTime)
	model.AddAttr(&attrs, "aws.alb.actions_executed", entry.ActionsExecuted)
	model.AddAttr(&attrs, "aws.alb.redirect_url", entry.RedirectURL)
	model.AddAttr(&attrs, "aws.alb.lambda_error_reason", entry.LambdaErrorReason)
	model.AddAttr(&attrs, "aws.alb.target_port_list", entry.TargetPortList)
	model.AddAttr(&attrs, "aws.alb.target_status_code_list", entry.TargetStatusCodeList)
	model.AddAttr(&attrs, "aws.alb.classification", entry.Classification)
	model.AddAttr(&attrs, "aws.alb.classification_reason", entry.ClassificationReason)
	model.AddAttr(&attrs, "aws.alb.conn_trace_id", entry.ConnTraceID)

	return attrs
}
