package processor

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/divmora/otel-aws-log-processor/pkg/model"
	"github.com/divmora/otel-aws-log-processor/pkg/parser"
	"github.com/divmora/otel-aws-log-processor/pkg/utils"
)

type NLBProcessor struct {
	MaxBatchSize  int
	MaxConcurrent int
	Parser        parser.LogParser[parser.NLBLogEntry]
}

func (p *NLBProcessor) Name() string {
	return "NLB"
}

func (p *NLBProcessor) Matches(bucket, key string) bool {
	return strings.Contains(key, "/elasticloadbalancing/") && strings.Contains(key, "_net.")
}

func (p *NLBProcessor) Process(ctx context.Context, logger *slog.Logger, s3Client *s3.Client, bucket, key string) ([]LogAdapter, error) {
	return ReadAndParseFromS3(ctx, logger, s3Client, bucket, key, p.MaxBatchSize, p.MaxConcurrent, func(line string) (LogAdapter, error) {
		entry, err := p.Parser.ParseLogLine(line)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			return nil, nil
		}
		return NLBAdapter{entry}, nil
	})
}

// NLBAdapter implementation
type NLBAdapter struct {
	*parser.NLBLogEntry
}

func (a NLBAdapter) GetResourceKey() string {
	arn := a.NLBLogEntry.ChosenCertARN
	if arn == "" || arn == "-" {
		// Fallback to ListenerID or ELB name
		arn = a.NLBLogEntry.ListenerID // often contains ARN
	}
	return arn
}

func (a NLBAdapter) GetResourceAttributes() []model.OTelAttribute {
	entry := a.NLBLogEntry
	attrs := []model.OTelAttribute{
		{Key: "cloud.provider", Value: model.StringValue("aws")},
		{Key: "cloud.platform", Value: model.StringValue("aws_elastic_load_balancing")},
		{Key: "cloud.service", Value: model.StringValue("elasticloadbalancing")},
		{Key: "service.name", Value: model.StringValue("nlb-log-parser")},
		{Key: "aws.lb.name", Value: model.StringValue(entry.ELB)},
	}

	// Extract region and account from ARN (ListenerID usually contains full ARN)
	arn := entry.ChosenCertARN

	if arn != "" && arn != "-" {
		region, accountID := utils.ParseRegionAccountFromARN(arn)
		if region != "" {
			attrs = append(attrs, model.OTelAttribute{Key: "cloud.region", Value: model.StringValue(region)})
		}
		if accountID != "" {
			attrs = append(attrs, model.OTelAttribute{Key: "cloud.account.id", Value: model.StringValue(accountID)})
		}
	}

	return attrs
}

func (a NLBAdapter) ToOTel() model.OTelLogRecord {
	// Convert timestamp
	timeUnixNano := utils.ConvertTimestamp(a.NLBLogEntry.Time)

	// Build attributes
	attributes := a.BuildAttributes()

	// Default to INFO
	severityText := "INFO"
	severityNumber := 9

	// Build body
	bodyContent := fmt.Sprintf("%s log for %s", a.NLBLogEntry.Type, a.NLBLogEntry.ELB)

	// Generate trace and span IDs
	traceID := utils.GenerateTraceID()
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

func (a NLBAdapter) BuildAttributes() []model.OTelAttribute {
	attrs := []model.OTelAttribute{}
	entry := a.NLBLogEntry

	// Transport attributes
	model.AddAttr(&attrs, "network.transport", "tcp") // Mostly TCP for NLB
	model.AddAttr(&attrs, "network.protocol.name", entry.Type)
	model.AddAttr(&attrs, "network.protocol.version", entry.Version)

	// Client attributes
	model.AddAttr(&attrs, "client.address", entry.ClientIP)
	model.AddIntAttr(&attrs, "client.port", entry.ClientPort)

	// Server attributes
	model.AddAttr(&attrs, "server.address", entry.TargetIP)
	model.AddIntAttr(&attrs, "server.port", entry.TargetPort)

	// TLS attributes
	model.AddAttr(&attrs, "tls.cipher_suite", entry.TLSCipher)
	model.AddAttr(&attrs, "tls.protocol.version", entry.TLSProtocolVersion)
	model.AddAttr(&attrs, "tls.server.name", entry.DomainName)

	// AWS-specific attributes
	model.AddAttr(&attrs, "aws.nlb.type", entry.Type)
	model.AddAttr(&attrs, "aws.nlb.listener_id", entry.ListenerID)
	model.AddFloatAttr(&attrs, "aws.nlb.connection_time", entry.ConnectionTime)
	model.AddFloatAttr(&attrs, "aws.nlb.tls_handshake_time", entry.TLSHandshakeTime)
	model.AddInt64Attr(&attrs, "aws.nlb.received_bytes", entry.ReceivedBytes)
	model.AddInt64Attr(&attrs, "aws.nlb.sent_bytes", entry.SentBytes)
	model.AddAttr(&attrs, "aws.nlb.incoming_tls_alert", entry.IncomingTLSAlert)
	model.AddAttr(&attrs, "aws.nlb.chosen_cert_arn", entry.ChosenCertARN)
	model.AddAttr(&attrs, "aws.nlb.chosen_cert_serial", entry.ChosenCertSerial)
	model.AddAttr(&attrs, "aws.nlb.tls_named_group", entry.TLSNamedGroup)
	model.AddAttr(&attrs, "aws.nlb.alpn_frontend_protocol", entry.ALPNFrontEndProtocol)
	model.AddAttr(&attrs, "aws.nlb.alpn_backend_protocol", entry.ALPNBackEndProtocol)
	model.AddAttr(&attrs, "aws.nlb.alpn_client_preference_list", entry.ALPNClientPreferenceList)
	model.AddAttr(&attrs, "aws.nlb.tls_connection_creation_time", entry.TLSConnectionCreationTime)

	return attrs
}
