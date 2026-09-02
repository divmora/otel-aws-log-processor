package main

import (
	"context"
	"log/slog"
	"os"
	"sync"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"

	eventsPkg "github.com/divmora/otel-aws-log-processor/pkg/events"
	"github.com/divmora/otel-aws-log-processor/pkg/parser"
	"github.com/divmora/otel-aws-log-processor/pkg/processor"
	"github.com/divmora/otel-aws-log-processor/pkg/sender"
	"github.com/divmora/otel-aws-log-processor/pkg/utils"
)

var (
	s3Client      *s3.S3
	logger        *slog.Logger
	maxConcurrent int
	registry      *processor.Registry
	otlpClient    *sender.OTLPClient
)

func init() {
	// Initialize structured logger (JSON format)
	logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Initialize AWS session
	sess := session.Must(session.NewSession())
	s3Client = s3.New(sess)

	// Load configuration from environment
	otlpEndpoint := utils.GetEnv("OTLP_HTTP_LOGS_ENDPOINT", "http://localhost:4318/v1/logs")
	basicAuthUser := utils.GetEnv("BASIC_AUTH_USERNAME", "")
	basicAuthPass := utils.GetEnv("BASIC_AUTH_PASSWORD", "")
	maxBatchSize := utils.GetEnvInt("MAX_BATCH_SIZE", 500)
	maxRetries := utils.GetEnvInt("MAX_RETRIES", 3)
	maxConcurrent = utils.GetEnvInt("MAX_CONCURRENT", 10)

	// Initialize OTLP Client
	otlpClient = sender.NewOTLPClient(otlpEndpoint, basicAuthUser, basicAuthPass, maxRetries, maxBatchSize, maxConcurrent, logger)

	// Initialize Registry
	registry = processor.NewRegistry()
	registry.Register(&processor.ALBProcessor{
		MaxBatchSize:  maxBatchSize,
		MaxConcurrent: maxConcurrent,
		Parser:        &parser.ALBParser{},
	})
	registry.Register(&processor.NLBProcessor{
		MaxBatchSize:  maxBatchSize,
		MaxConcurrent: maxConcurrent,
		Parser:        &parser.NLBParser{},
	})
	registry.Register(&processor.CloudFrontProcessor{
		MaxBatchSize:  maxBatchSize,
		MaxConcurrent: maxConcurrent,
		Parser:        &parser.CloudFrontParser{},
	})
	registry.Register(&processor.WAFProcessor{
		MaxBatchSize:  maxBatchSize,
		MaxConcurrent: maxConcurrent,
		Parser:        &parser.WAFParser{},
	})
}

func handler(ctx context.Context, sqsEvent events.SQSEvent) (events.SQSEventResponse, error) {
	response := events.SQSEventResponse{
		BatchItemFailures: []events.SQSBatchItemFailure{},
	}

	var allEntries []processor.LogAdapter

	logger.Info("Lambda triggered", "sqs_record_count", len(sqsEvent.Records))

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, maxConcurrent)

	for _, record := range sqsEvent.Records {
		wg.Add(1)
		go func(record events.SQSMessage) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			// Parse Body as S3 Event
			s3Records, err := eventsPkg.ParseBodyAsS3(logger, []byte(record.Body))
			if err != nil {
				logger.Warn("Failed to parse SQS body, skipping message", "message_id", record.MessageId, "error", err)
				return
			}

			// Usually one SQS message contains one S3 event (EventBridge wrapper)
			// But ParseBodyAsS3 returns slice, so handle all
			msgFailed := false
			var recordEntries []processor.LogAdapter

			for _, s3Record := range s3Records {
				bucket := s3Record.S3.Bucket.Name
				key := s3Record.S3.Object.Key

				if bucket == "" || key == "" {
					logger.Warn("Skipping record with empty bucket or key", "message_id", record.MessageId)
					continue
				}

				log := logger.With("bucket", bucket, "key", key, "message_id", record.MessageId)
				log.Info("Processing S3 object")

				// Find matching processor
				proc := registry.Find(bucket, key)
				if proc == nil {
					log.Info("Skipping object: no matching processor found")
					continue
				}

				// Process logs
				entries, err := proc.Process(ctx, logger, s3Client, bucket, key)
				if err != nil {
					log.Error("Error processing S3 object", "error", err)
					msgFailed = true
					break // Stop processing this SQS message, mark as failed
				}

				if len(entries) > 0 {
					recordEntries = append(recordEntries, entries...)
				}
			}

			mu.Lock()
			defer mu.Unlock()

			if msgFailed {
				response.BatchItemFailures = append(response.BatchItemFailures, events.SQSBatchItemFailure{
					ItemIdentifier: record.MessageId,
				})
			} else if len(recordEntries) > 0 {
				allEntries = append(allEntries, recordEntries...)
			}
		}(record)
	}

	wg.Wait()

	// Send successful entries to OTLP
	if len(allEntries) > 0 {
		logger.Info("Sending collected entries to OTLP", "count", len(allEntries))
		if err := otlpClient.SendLogs(allEntries); err != nil {
			logger.Error("Error sending to OTLP", "error", err)
			return response, err // Returning error triggers full batch failure usually, which is what we want if backend is down
		}
	}

	logger.Info("Lambda execution completed", "failures", len(response.BatchItemFailures))
	return response, nil
}

func main() {
	lambda.Start(handler)
}
