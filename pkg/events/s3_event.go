package events

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"

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
// It supports EventBridge S3 events, direct S3 bucket notifications, and SNS-wrapped S3 events.
func ParseBodyAsS3(logger *slog.Logger, body []byte) ([]events.S3EventRecord, error) {
	// 1. Try EventBridge S3 Event (common modern pattern: S3 -> EventBridge -> SQS)
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

	// 2. Try Standard Direct S3 Event Notification (traditional pattern: S3 -> SQS)
	var s3Event events.S3Event
	if err := json.Unmarshal(body, &s3Event); err == nil && len(s3Event.Records) > 0 {
		if s3Event.Records[0].S3.Bucket.Name != "" {
			for i := range s3Event.Records {
				if unescaped, err := url.QueryUnescape(s3Event.Records[i].S3.Object.Key); err == nil {
					s3Event.Records[i].S3.Object.Key = unescaped
				}
			}
			return s3Event.Records, nil
		}
	}

	// 3. Try SNS-wrapped S3 Event (pattern: S3 -> SNS Topic -> SQS)
	var snsMessage struct {
		Type    string `json:"Type"`
		Message string `json:"Message"`
	}
	if err := json.Unmarshal(body, &snsMessage); err == nil && snsMessage.Type == "Notification" && snsMessage.Message != "" {
		return ParseBodyAsS3(logger, []byte(snsMessage.Message))
	}

	return nil, fmt.Errorf("body does not match EventBridge, direct S3, or SNS-wrapped S3 event format")
}
