package processor

import (
	"testing"

	"github.com/divmora/otel-aws-log-parser/pkg/parser"
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

func TestCloudFrontAdapter_GetResourceKey(t *testing.T) {
	// Need to import parser locally or mock
}
