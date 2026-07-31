package processor

import (
	"testing"

	"github.com/divmora/otel-aws-log-parser/pkg/parser"
)

func TestALBAdapterGetResourceKey(t *testing.T) {
	tests := []struct {
		name     string
		entry    *parser.ALBLogEntry
		expected string
	}{
		{
			name: "TargetGroupARN present",
			entry: &parser.ALBLogEntry{
				TargetGroupARN: "arn:aws:elasticloadbalancing:us-east-1:123456:targetgroup/test/abc",
				ELB:            "app/my-load-balancer/123",
			},
			expected: "arn:aws:elasticloadbalancing:us-east-1:123456:targetgroup/test/abc",
		},
		{
			name: "TargetGroupARN missing, use ELB",
			entry: &parser.ALBLogEntry{
				TargetGroupARN: "-",
				ELB:            "app/my-load-balancer/123",
				ChosenCertARN:  "arn:aws:acm:us-east-1:123456:certificate/abc",
			},
			expected: "app/my-load-balancer/123",
		},
		{
			name: "TargetGroupARN empty, use ELB",
			entry: &parser.ALBLogEntry{
				TargetGroupARN: "",
				ELB:            "app/my-load-balancer/123",
				ChosenCertARN:  "arn:aws:acm:us-east-1:123456:certificate/abc",
			},
			expected: "app/my-load-balancer/123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := ALBAdapter{ALBLogEntry: tt.entry}
			got := adapter.GetResourceKey()
			if got != tt.expected {
				t.Errorf("GetResourceKey() = %v, want %v", got, tt.expected)
			}
		})
	}
}
