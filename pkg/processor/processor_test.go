package processor_test

import (
	"bytes"
	"io"
	"sync/atomic"
	"testing"

	"github.com/divmora/otel-aws-log-processor/pkg/processor"
)

func TestProcessorMatching(t *testing.T) {
	albProc := &processor.ALBProcessor{}
	nlbProc := &processor.NLBProcessor{}

	tests := []struct {
		name    string
		key     string
		wantALB bool
		wantNLB bool
	}{
		{
			name:    "User provided NLB format",
			key:     "bucket/prefix/AWSLogs/123/elasticloadbalancing/us-east-1/2023/01/01/123_elasticloadbalancing_us-east-1_net.my-lb.123_20230101T0000Z_123.log.gz",
			wantALB: false,
			wantNLB: true,
		},
		{
			name:    "User provided ALB format",
			key:     "bucket/prefix/AWSLogs/123/elasticloadbalancing/us-east-1/2023/01/01/123_elasticloadbalancing_us-east-1_app.my-lb.123_20230101T0000Z_1.2.3.4_123.log.gz",
			wantALB: true,
			wantNLB: false,
		},
		{
			name:    "Standard NLB without prefix",
			key:     "AWSLogs/123/elasticloadbalancing/us-east-1/2023/01/01/123_elasticloadbalancing_us-east-1_net.my-lb.123_20230101T0000Z_hash.log.gz",
			wantALB: false,
			wantNLB: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := albProc.Matches("bucket", tt.key); got != tt.wantALB {
				t.Errorf("ALBProcessor.Matches() = %v, want %v", got, tt.wantALB)
			}
			if got := nlbProc.Matches("bucket", tt.key); got != tt.wantNLB {
				t.Errorf("NLBProcessor.Matches() = %v, want %v", got, tt.wantNLB)
			}
		})
	}
}

type testByteTracker struct {
	bytes atomic.Int64
}

func (m *testByteTracker) RecordBytes(n int64) int64 {
	return m.bytes.Add(n)
}

func TestCountingReader_AccurateMetering(t *testing.T) {
	tracker := &testByteTracker{}
	sampleData := []byte("hello world, this is a test log line with exact length tracking")
	reader := processor.NewCountingReader(bytes.NewReader(sampleData), tracker)

	buf := make([]byte, 16)
	totalRead := 0
	for {
		n, err := reader.Read(buf)
		totalRead += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected read error: %v", err)
		}
	}

	if totalRead != len(sampleData) {
		t.Errorf("got totalRead %d, want %d", totalRead, len(sampleData))
	}
	if recorded := tracker.bytes.Load(); recorded != int64(len(sampleData)) {
		t.Errorf("got recorded bytes %d, want %d", recorded, len(sampleData))
	}
}

func TestRegistry_SetByteTracker(t *testing.T) {
	reg := processor.NewRegistry()
	tracker := &testByteTracker{}
	reg.SetByteTracker(tracker)

	alb := &processor.ALBProcessor{}
	reg.Register(alb)

	if alb.ByteTracker != tracker {
		t.Fatal("expected ALBProcessor.ByteTracker to be set by registry")
	}

	nlb := &processor.NLBProcessor{}
	cf := &processor.CloudFrontProcessor{}
	waf := &processor.WAFProcessor{}
	reg.Register(nlb)
	reg.Register(cf)
	reg.Register(waf)

	if nlb.ByteTracker != tracker {
		t.Fatal("expected NLBProcessor.ByteTracker to be set by registry")
	}
	if cf.ByteTracker != tracker {
		t.Fatal("expected CloudFrontProcessor.ByteTracker to be set by registry")
	}
	if waf.ByteTracker != tracker {
		t.Fatal("expected WAFProcessor.ByteTracker to be set by registry")
	}
}

func BenchmarkCountingReader_ZeroAllocations(b *testing.B) {
	tracker := &testByteTracker{}
	data := bytes.Repeat([]byte("A"), 4096)
	reader := processor.NewCountingReader(bytes.NewReader(data), tracker)
	buf := make([]byte, 256)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = reader.Read(buf)
	}
}
