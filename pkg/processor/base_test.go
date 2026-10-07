package processor

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/divmora/otel-aws-log-processor/pkg/model"
)

type dummyLogAdapter struct {
	content string
}

func (d dummyLogAdapter) GetResourceKey() string {
	return "test-resource"
}

func (d dummyLogAdapter) GetResourceAttributes() []model.OTelAttribute {
	return []model.OTelAttribute{
		{Key: "service.name", Value: model.StringValue("dummy")},
	}
}

func (d dummyLogAdapter) BuildAttributes() []model.OTelAttribute {
	return []model.OTelAttribute{
		{Key: "log.content", Value: model.StringValue(d.content)},
	}
}

func (d dummyLogAdapter) ToOTel() model.OTelLogRecord {
	return model.OTelLogRecord{
		Body: map[string]string{"stringValue": d.content},
	}
}

func createMockS3Client(t *testing.T, handler http.HandlerFunc) *s3.Client {
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("mockKey", "mockSecret", "")),
	)
	if err != nil {
		t.Fatalf("failed to load default aws config: %v", err)
	}

	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(ts.URL)
		o.UsePathStyle = true
	})
}

func TestReadAndParseFromS3_Success(t *testing.T) {
	client := createMockS3Client(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("line 1\nline 2\nline 3\n"))
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	entries, err := ReadAndParseFromS3(context.Background(), logger, client, "test-bucket", "logs.txt", 10, 2, func(line string) (LogAdapter, error) {
		return dummyLogAdapter{content: line}, nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got: %d", len(entries))
	}
}

func TestReadAndParseFromS3_GzipSuccess(t *testing.T) {
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write([]byte("line 1\nline 2\n"))
	_ = gw.Close()

	client := createMockS3Client(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzBuf.Bytes())
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	entries, err := ReadAndParseFromS3(context.Background(), logger, client, "test-bucket", "logs.log.gz", 10, 2, func(line string) (LogAdapter, error) {
		return dummyLogAdapter{content: line}, nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got: %d", len(entries))
	}
}

func TestReadAndParseFromS3_ScannerError_LineTooLong(t *testing.T) {
	// A line > 1MB triggers bufio.ErrTooLong in bufio.Scanner
	oversizedLine := strings.Repeat("A", 1024*1024+100) + "\n"

	client := createMockS3Client(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(oversizedLine))
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := ReadAndParseFromS3(context.Background(), logger, client, "test-bucket", "oversized.txt", 10, 2, func(line string) (LogAdapter, error) {
		return dummyLogAdapter{content: line}, nil
	})
	if err == nil {
		t.Fatal("expected error on oversized line, got nil")
	}
	if !strings.Contains(err.Error(), "error reading S3 stream") {
		t.Errorf("expected error message to contain 'error reading S3 stream', got: %v", err)
	}
}

func TestReadAndParseJSONFromS3_DecodeError(t *testing.T) {
	// Corrupted JSON stream
	malformedJSON := `{"valid": "object"}` + "\n" + `{"incomplete": `

	client := createMockS3Client(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(malformedJSON))
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := ReadAndParseJSONFromS3(context.Background(), logger, client, "test-bucket", "logs.json", 10, 2, func(data []byte) (LogAdapter, error) {
		return dummyLogAdapter{content: string(data)}, nil
	})
	if err == nil {
		t.Fatal("expected error on malformed JSON stream, got nil")
	}
	if !strings.Contains(err.Error(), "error reading JSON stream from S3") {
		t.Errorf("expected error message to contain 'error reading JSON stream from S3', got: %v", err)
	}
}
