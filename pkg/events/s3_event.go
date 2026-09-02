package events

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/aws/aws-lambda-go/events"
)

// EventBridgeS3Event structure for S3 events via EventBridge
type EventBridgeS3Event struct {
	Source     string `json:"source"`
	DetailType string `json:"detail-type"`
	Region     string `json:"region"`
	Detail     struct {
		Bucket struct {
			Name string `json:"name"`
		} `json:"bucket"`
		Object struct {
			Key string `json:"key"`
		} `json:"object"`
	} `json:"detail"`
}

// ParseBodyAsS3 parses the SQS body to extract S3 event records.
// It supports EventBridge S3 events.
func ParseBodyAsS3(logger *slog.Logger, body []byte) ([]events.S3EventRecord, error) {
	// Try EventBridge S3 Event (common in SQS)
	var ebEvent EventBridgeS3Event
	if err := json.Unmarshal(body, &ebEvent); err == nil {
		if ebEvent.Source == "aws.s3" && ebEvent.Detail.Bucket.Name != "" {
			return []events.S3EventRecord{{
				S3: events.S3Entity{
					Bucket: events.S3Bucket{Name: ebEvent.Detail.Bucket.Name},
					Object: events.S3Object{Key: ebEvent.Detail.Object.Key},
				},
				AWSRegion: ebEvent.Region,
			}}, nil
		}
	}

	return nil, fmt.Errorf("body does not match EventBridge S3 format")
}
