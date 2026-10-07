package processor

import (
	"testing"

	"github.com/divmora/otel-aws-log-processor/pkg/parser"
)

func TestCloudFrontProcessor_Matches(t *testing.T) {
	proc := &CloudFrontProcessor{Parser: &parser.CloudFrontParser{}}

	tests := []struct {
		key  string
		want bool
	}{
		// Valid case: Standard Logging v2 with default prefix
		{"AWSLogs/123456789012/CloudFront/E2K55636F2K7.2019-12-04-21.d111111abcdef8.gz", true},
		// Invalid cases: Legacy or Custom prefixes (we enforce AWSLogs/.../CloudFront/)
		{"E2K55636F2K7.2019-12-04-21.d111111abcdef8.gz", false},
		{"prefix/E2K55636F2K7.2019-12-04-21.d111111abcdef8.gz", false},
		{"my/custom/path/E2K55636F2K7.2019-12-04-21.d111111abcdef8.gz", false},
		// Valid cases: Parquet format
		{"AWSLogs/123456789012/CloudFront/E2K55636F2K7.2019-12-04-21.d111111abcdef8.parquet", true},
		{"AWSLogs/178751861697/CloudFront/E2RM8BAWEBGMEV/2026/07/31/17/E2RM8BAWEBGMEV.2026-07-31-17.92cee41b.parquet", true},
		{"prefix/E2K55636F2K7.2019-12-04-21.d111111abcdef8.parquet", false},
		// Invalid cases: Other types
		{"not-cloudfront.log", false},
		{"AWSLogs/123456789012/CloudFront/E2K55636F2K7.2019-12-04-21.d111111abcdef8.txt", false}, // Must be .gz or .parquet
		{"invalid-format.gz", false}, // Does not match pattern
		{"AWSLogs/123456789012/elasticloadbalancing/us-east-1/2023/01/01/123456789012_elasticloadbalancing_us-east-1_app.my-load-balancer.1234567890.gz", false}, // ALB log
	}

	for _, tt := range tests {
		got := proc.Matches("bucket", tt.key)
		if got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

// Mocking S3 read functionality for Process test is complex without a full mock S3 client
// or abstracting the reader.
// However, we can trust ReadAndParseFromS3 is tested elsewhere or trust integration tests.
// We should check if converter logic works via unit tests on CloudFrontAdapter or similar.

func TestExtractDistributionID(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"AWSLogs/123456789012/CloudFront/E2K55636F2K7.2019-12-04-21.d111111abcdef8.gz", "E2K55636F2K7"},
		{"AWSLogs/178751861697/CloudFront/E2RM8BAWEBGMEV/2026/07/31/17/E2RM8BAWEBGMEV.2026-07-31-17.92cee41b.parquet", "E2RM8BAWEBGMEV"},
		{"AWSLogs/123456789012/CloudFront/EDFDVBD632BHDS5/2026/01/01/00/EDFDVBD632BHDS5.2026-01-01-00.abc123.gz", "EDFDVBD632BHDS5"},
	}

	for _, tt := range tests {
		got := ExtractDistributionID(tt.key)
		if got != tt.want {
			t.Errorf("ExtractDistributionID(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestCloudFrontAdapter_GetResourceKey(t *testing.T) {
	// Case 1: DistributionID set directly from S3 key
	adapter1 := CloudFrontAdapter{
		CloudFrontLogEntry: &parser.CloudFrontLogEntry{
			CSHost: "d111111abcdef8.cloudfront.net",
		},
		DistributionID: "E2K55636F2K7",
		AccountID:      "123456789012",
		Region:         "global",
	}
	if got := adapter1.GetResourceKey(); got != "E2K55636F2K7" {
		t.Errorf("GetResourceKey() = %q, want E2K55636F2K7", got)
	}

	attrs1 := adapter1.GetResourceAttributes()
	foundDistID := false
	for _, attr := range attrs1 {
		if attr.Key == "aws.cloudfront.distribution_id" && attr.Value.StringValue != nil && *attr.Value.StringValue == "E2K55636F2K7" {
			foundDistID = true
			break
		}
	}
	if !foundDistID {
		t.Error("aws.cloudfront.distribution_id attribute not set or incorrect")
	}

	// Case 2: Fallback when DistributionID is empty
	adapter2 := CloudFrontAdapter{
		CloudFrontLogEntry: &parser.CloudFrontLogEntry{
			CSHost: "api.customdomain.com",
		},
	}
	if got := adapter2.GetResourceKey(); got != "api.customdomain.com" {
		t.Errorf("GetResourceKey() fallback = %q, want api.customdomain.com", got)
	}
}
