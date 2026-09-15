package events

import (
	"io"
	"log/slog"
	"testing"
)

func TestParseBodyAsS3(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	// 1. EventBridge S3 Event
	ebPayload := []byte(`{
		"version": "0",
		"id": "12345-abcd",
		"detail-type": "Object Created",
		"source": "aws.s3",
		"region": "us-east-1",
		"detail": {
			"bucket": {
				"name": "my-alb-logs-bucket"
			},
			"object": {
				"key": "AWSLogs/123456789012/elasticloadbalancing/us-east-1/2026/09/15/app.log.gz"
			}
		}
	}`)

	records, err := ParseBodyAsS3(logger, ebPayload)
	if err != nil {
		t.Fatalf("unexpected error parsing EventBridge event: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].S3.Bucket.Name != "my-alb-logs-bucket" {
		t.Errorf("expected bucket 'my-alb-logs-bucket', got '%s'", records[0].S3.Bucket.Name)
	}
	if records[0].S3.Object.Key != "AWSLogs/123456789012/elasticloadbalancing/us-east-1/2026/09/15/app.log.gz" {
		t.Errorf("expected key to match, got '%s'", records[0].S3.Object.Key)
	}

	// 2. Direct S3 Notification Event
	directS3Payload := []byte(`{
		"Records": [
			{
				"eventVersion": "2.1",
				"eventSource": "aws:s3",
				"awsRegion": "us-east-1",
				"eventName": "ObjectCreated:Put",
				"s3": {
					"bucket": {
						"name": "direct-s3-logs-bucket"
					},
					"object": {
						"key": "WAFLogs/waf+test%20file.json.gz"
					}
				}
			}
		]
	}`)

	records, err = ParseBodyAsS3(logger, directS3Payload)
	if err != nil {
		t.Fatalf("unexpected error parsing direct S3 event: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].S3.Bucket.Name != "direct-s3-logs-bucket" {
		t.Errorf("expected bucket 'direct-s3-logs-bucket', got '%s'", records[0].S3.Bucket.Name)
	}
	if records[0].S3.Object.Key != "WAFLogs/waf test file.json.gz" {
		t.Errorf("expected key 'WAFLogs/waf test file.json.gz', got '%s'", records[0].S3.Object.Key)
	}

	// 3. SNS-wrapped S3 Event
	snsWrappedPayload := []byte(`{
		"Type": "Notification",
		"MessageId": "msg-12345",
		"TopicArn": "arn:aws:sns:us-east-1:123456789012:s3-log-topic",
		"Message": "{\"Records\":[{\"s3\":{\"bucket\":{\"name\":\"sns-s3-bucket\"},\"object\":{\"key\":\"cf/access.parquet\"}}}]}"
	}`)

	records, err = ParseBodyAsS3(logger, snsWrappedPayload)
	if err != nil {
		t.Fatalf("unexpected error parsing SNS wrapped S3 event: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].S3.Bucket.Name != "sns-s3-bucket" {
		t.Errorf("expected bucket 'sns-s3-bucket', got '%s'", records[0].S3.Bucket.Name)
	}
	if records[0].S3.Object.Key != "cf/access.parquet" {
		t.Errorf("expected key 'cf/access.parquet', got '%s'", records[0].S3.Object.Key)
	}

	// 4. Invalid Payload
	invalidPayload := []byte(`{"invalid": "data"}`)
	_, err = ParseBodyAsS3(logger, invalidPayload)
	if err == nil {
		t.Error("expected error parsing invalid payload")
	}
}
