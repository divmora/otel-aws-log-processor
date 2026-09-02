package processor

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/divmora/otel-aws-log-processor/pkg/model"
	"github.com/divmora/otel-aws-log-processor/pkg/parser"
	"github.com/divmora/otel-aws-log-processor/pkg/utils"
)

// Regex for CloudFront log filename
// Format: {DistributionID}.{YYYY}-{MM}-{DD}-{HH}.{UniqueID}.gz or .parquet
// Example: E2K55636F2K7.2019-12-04-21.d111111abcdef8.gz
// We'll use a relatively loose pattern to capture the structure.
// Distribution ID is usually alphanumeric.
var cloudFrontLogPattern = regexp.MustCompile(`[A-Z0-9]+\.\d{4}-\d{2}-\d{2}-\d{2}\.[a-zA-Z0-9]+\.(gz|parquet)$`)

type CloudFrontProcessor struct {
	MaxBatchSize  int
	MaxConcurrent int
	Parser        parser.LogParser[parser.CloudFrontLogEntry]
}

func (p *CloudFrontProcessor) Name() string {
	return "CloudFront"
}

func (p *CloudFrontProcessor) Matches(bucket, key string) bool {
	// Only match standard logging (v2) with default prefix structure:
	// AWSLogs/{account-id}/CloudFront/{distribution-id}/{yyyy}/{mm}/{dd}/{hh}/{distribution-id}.{date}.{unique-id}.[gz|parquet]
	// We strictly require "AWSLogs/" prefix and "/CloudFront/" segment to avoid
	// processing legacy logs or custom prefixes.
	return strings.HasPrefix(key, "AWSLogs/") &&
		strings.Contains(key, "/CloudFront/") &&
		(strings.HasSuffix(key, ".gz") || strings.HasSuffix(key, ".parquet")) &&
		cloudFrontLogPattern.MatchString(key)
}

func (p *CloudFrontProcessor) Process(ctx context.Context, logger *slog.Logger, s3Client *s3.S3, bucket, key string) ([]LogAdapter, error) {
	// Attempt to parse account/region if they happen to be in the path
	accountID, _ := utils.ParseRegionAccountFromS3Key(key)
	// CloudFront is global, the default S3 regex might extract DistributionID as Region, so we override it
	region := "global"

	if strings.HasSuffix(key, ".parquet") {
		return ReadAndParseParquetFromS3(logger, s3Client, bucket, key, p.MaxBatchSize, p.MaxConcurrent, func(row *parser.CloudFrontParquetLogEntry) (LogAdapter, error) {
			if row == nil {
				return nil, nil
			}
			entry := row.ToLogEntry()
			return CloudFrontAdapter{
				CloudFrontLogEntry: entry,
				AccountID:          accountID,
				Region:             region,
			}, nil
		})
	}

	return ReadAndParseFromS3(logger, s3Client, bucket, key, p.MaxBatchSize, p.MaxConcurrent, func(line string) (LogAdapter, error) {
		entry, err := p.Parser.ParseLogLine(line)
		if err != nil {
			return nil, err
		}
		// If entry is nil (comment line), ReadAndParseFromS3 handles it if we return nil, nil?
		// Looking at ALBProcessor: parser.ParseLogLine returns nil, nil for comments.
		// CloudFront parser behaves similarly.
		if entry == nil {
			return nil, nil
		}

		return CloudFrontAdapter{
			CloudFrontLogEntry: entry,
			AccountID:          accountID,
			Region:             region,
		}, nil
	})
}

// CloudFrontAdapter implementation
type CloudFrontAdapter struct {
	*parser.CloudFrontLogEntry
	AccountID string
	Region    string
}

func (a CloudFrontAdapter) GetResourceKey() string {
	// Use distribution domain as key resource identifier
	return a.CloudFrontLogEntry.CSHost
}

func (a CloudFrontAdapter) GetResourceAttributes() []model.OTelAttribute {
	entry := a.CloudFrontLogEntry
	attrs := []model.OTelAttribute{
		{Key: "cloud.provider", Value: model.StringValue("aws")},
		{Key: "cloud.platform", Value: model.StringValue("aws_cloudfront")},
		{Key: "cloud.service", Value: model.StringValue("cloudfront")},
		{Key: "service.name", Value: model.StringValue("cloudfront-log-parser")},
	}

	if entry.CSHost != "" && strings.HasSuffix(entry.CSHost, ".cloudfront.net") {
		distID := strings.TrimSuffix(entry.CSHost, ".cloudfront.net")
		attrs = append(attrs, model.OTelAttribute{Key: "aws.cloudfront.distribution_id", Value: model.StringValue(distID)})
	}

	// If we managed to extract account/region from path (rare), add them
	attrs = model.EnsureRegionAccountAttributes(attrs, a.Region, a.AccountID)

	return attrs
}

func (a CloudFrontAdapter) ToOTel() model.OTelLogRecord {
	// Convert timestamp
	// Date: 2019-12-04, Time: 21:02:31
	timeStr := fmt.Sprintf("%sT%sZ", a.CloudFrontLogEntry.Date, a.CloudFrontLogEntry.Time)
	t, err := time.Parse(time.RFC3339, timeStr)
	var timeUnixNano int64
	if err != nil {
		timeUnixNano = time.Now().UnixNano()
	} else {
		timeUnixNano = t.UnixNano()
	}

	attributes := a.BuildAttributes()

	severityText := "INFO"
	severityNumber := 9
	if a.CloudFrontLogEntry.SCStatus >= 500 {
		severityText = "ERROR"
		severityNumber = 17
	} else if a.CloudFrontLogEntry.SCStatus >= 400 {
		severityText = "WARN"
		severityNumber = 13
	}

	bodyContent := fmt.Sprintf("%s %s %d", a.CloudFrontLogEntry.CSMethod, a.CloudFrontLogEntry.CSURIStem, a.CloudFrontLogEntry.SCStatus)

	traceID := ""
	// Use x-edge-request-id as trace ID if it fits format, but it's base64 usually.
	// CloudFront Request IDs are long base64 strings, not valid W3C Trace IDs.
	// So we generate a random Trace ID.
	traceID = utils.GenerateTraceID()
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

func (a CloudFrontAdapter) BuildAttributes() []model.OTelAttribute {
	attrs := []model.OTelAttribute{}
	entry := a.CloudFrontLogEntry

	// HTTP Attributes
	model.AddAttr(&attrs, "http.request.method", entry.CSMethod)
	model.AddIntAttr(&attrs, "http.response.status_code", entry.SCStatus)
	model.AddAttr(&attrs, "url.path", entry.CSURIStem)
	model.AddAttr(&attrs, "url.query", entry.CSURIQuery)
	model.AddAttr(&attrs, "network.protocol.version", entry.CSProtocolVersion) // e.g. HTTP/2.0
	model.AddAttr(&attrs, "network.protocol.name", entry.CSProtocol)           // http/https

	// User Agent
	decodedUA, err := url.QueryUnescape(entry.CSUserAgent)
	if err == nil {
		model.AddAttr(&attrs, "user_agent.original", decodedUA)
	} else {
		model.AddAttr(&attrs, "user_agent.original", entry.CSUserAgent)
	}

	// Client
	model.AddAttr(&attrs, "client.address", entry.CIP)
	model.AddIntAttr(&attrs, "client.port", entry.CPort)

	// Server
	model.AddAttr(&attrs, "server.address", entry.CSHost) // Distribution domain or CNAME

	// AWS CloudFront Specific
	model.AddAttr(&attrs, "aws.cloudfront.edge_location", entry.XEdgeLocation)
	model.AddInt64Attr(&attrs, "aws.cloudfront.sc_bytes", entry.SCBytes)
	model.AddInt64Attr(&attrs, "aws.cloudfront.cs_bytes", entry.CSBytes)
	model.AddAttr(&attrs, "aws.cloudfront.result_type", entry.XEdgeResultType)
	model.AddAttr(&attrs, "aws.cloudfront.request_id", entry.XEdgeRequestID)
	model.AddAttr(&attrs, "aws.cloudfront.host_header", entry.XHostHeader)
	model.AddFloatAttr(&attrs, "aws.cloudfront.time_taken", entry.TimeTaken)
	model.AddAttr(&attrs, "aws.cloudfront.x_forwarded_for", entry.XForwardedFor)
	model.AddAttr(&attrs, "aws.cloudfront.ssl_protocol", entry.SSLProtocol)
	model.AddAttr(&attrs, "aws.cloudfront.ssl_cipher", entry.SSLCipher)
	model.AddAttr(&attrs, "aws.cloudfront.response_result_type", entry.XEdgeResponseResultType)
	model.AddAttr(&attrs, "aws.cloudfront.fle_status", entry.FLEStatus)
	model.AddIntAttr(&attrs, "aws.cloudfront.fle_encrypted_fields", entry.FLEEncryptedFields)
	model.AddFloatAttr(&attrs, "aws.cloudfront.time_to_first_byte", entry.TimeToFirstByte)
	model.AddAttr(&attrs, "aws.cloudfront.detailed_result_type", entry.XEdgeDetailedResultType)
	model.AddAttr(&attrs, "aws.cloudfront.sc_content_type", entry.SCContentType)
	model.AddInt64Attr(&attrs, "aws.cloudfront.sc_content_len", entry.SCContentLen)
	model.AddAttr(&attrs, "aws.cloudfront.sc_range_start", entry.SCRangeStart)
	model.AddAttr(&attrs, "aws.cloudfront.sc_range_end", entry.SCRangeEnd)

	return attrs
}
