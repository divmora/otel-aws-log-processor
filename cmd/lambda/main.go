package main

import (
	"context"
	"log/slog"
	"os"
	"sync"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	eventsPkg "github.com/divmora/otel-aws-log-processor/pkg/events"
	"github.com/divmora/otel-aws-log-processor/pkg/license"
	"github.com/divmora/otel-aws-log-processor/pkg/parser"
	"github.com/divmora/otel-aws-log-processor/pkg/processor"
	"github.com/divmora/otel-aws-log-processor/pkg/sender"
	"github.com/divmora/otel-aws-log-processor/pkg/utils"
	"strconv"
	"strings"
	"time"
)

var (
	s3Client        *s3.Client
	awsConfig       aws.Config
	cwClients       = make(map[string]*cloudwatch.Client)
	cwMu            sync.RWMutex
	logger          *slog.Logger
	maxConcurrent   int
	registry        *processor.Registry
	otlpClient      *sender.OTLPClient
	quotaTracker    *license.QuotaTracker
	resourceTracker *license.ResourceTracker
	cwRegistry      *license.CloudWatchRegistry
)

func getCloudWatchClientRaw(targetRegion string) *cloudwatch.Client {
	cwMu.RLock()
	client, ok := cwClients[targetRegion]
	cwMu.RUnlock()
	if ok {
		return client
	}

	cwMu.Lock()
	defer cwMu.Unlock()
	if client, ok := cwClients[targetRegion]; ok {
		return client
	}

	client = cloudwatch.NewFromConfig(awsConfig, func(o *cloudwatch.Options) {
		o.Region = targetRegion
	})
	cwClients[targetRegion] = client
	return client
}

func getCloudWatchClient(targetRegion string) license.CloudWatchMetricAPI {
	return getCloudWatchClientRaw(targetRegion)
}

func getActiveResourceCount() int {
	if cwRegistry != nil && cwRegistry.Count() > 0 {
		return cwRegistry.Count()
	}
	if resourceTracker != nil {
		return resourceTracker.Count()
	}
	return 0
}

func init() {
	// Initialize structured logger (JSON format) with LOG_LEVEL support
	var logLevel slog.Level
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LOG_LEVEL"))) {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn", "warning":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	// Initialize AWS SDK v2 configuration and S3 client
	var err error
	awsConfig, err = config.LoadDefaultConfig(context.Background())
	if err != nil {
		logger.Error("Failed to load AWS SDK configuration", "error", err)
	}
	s3Client = s3.NewFromConfig(awsConfig)

	// Load configuration from environment
	otlpEndpoint := utils.GetEnv("OTLP_HTTP_LOGS_ENDPOINT", "http://localhost:4318/v1/logs")
	basicAuthUser := utils.GetEnv("BASIC_AUTH_USERNAME", "")
	basicAuthPass := utils.GetEnv("BASIC_AUTH_PASSWORD", "")
	maxBatchSize := utils.GetEnvInt("MAX_BATCH_SIZE", 500)
	maxRetries := utils.GetEnvInt("MAX_RETRIES", 3)
	maxConcurrent = utils.GetEnvInt("MAX_CONCURRENT", 10)

	// Initialize OTLP Client
	otlpClient = sender.NewOTLPClient(otlpEndpoint, basicAuthUser, basicAuthPass, maxRetries, maxBatchSize, maxConcurrent, logger)

	// Initialize Non-Production Quota Tracker & Metering Engine
	quotaTracker = license.NewQuotaTracker()

	// Initialize Container Resource Tracker
	resourceTracker = license.NewResourceTracker()

	// Initialize CloudWatch Distributed Resource Registry
	cwRegistry = license.NewCloudWatchRegistry(getCloudWatchClientRaw(license.GetCurrentRegion()))

	// Initialize Registry
	registry = processor.NewRegistry()
	registry.SetByteTracker(quotaTracker)
	registry.Register(&processor.ALBProcessor{
		MaxBatchSize:  maxBatchSize,
		MaxConcurrent: maxConcurrent,
		Parser:        &parser.ALBParser{},
		ByteTracker:   quotaTracker,
	})
	registry.Register(&processor.NLBProcessor{
		MaxBatchSize:  maxBatchSize,
		MaxConcurrent: maxConcurrent,
		Parser:        &parser.NLBParser{},
		ByteTracker:   quotaTracker,
	})
	registry.Register(&processor.CloudFrontProcessor{
		MaxBatchSize:  maxBatchSize,
		MaxConcurrent: maxConcurrent,
		Parser:        &parser.CloudFrontParser{},
		ByteTracker:   quotaTracker,
	})
	registry.Register(&processor.WAFProcessor{
		MaxBatchSize:  maxBatchSize,
		MaxConcurrent: maxConcurrent,
		Parser:        &parser.WAFParser{},
		ByteTracker:   quotaTracker,
	})

	// Initial license compliance check
	env := license.DetectEnvironment()
	initStatus, _ := license.Enforce(license.EnforcementOptions{
		Environment:  env,
		QuotaTracker: quotaTracker,
	})
	if initStatus != nil {
		logger.Info("License engine initialized", "status", initStatus.StatusReason, "environment", env, "message", initStatus.Message)
	}
}

func handler(ctx context.Context, sqsEvent events.SQSEvent) (events.SQSEventResponse, error) {
	response := events.SQSEventResponse{
		BatchItemFailures: []events.SQSBatchItemFailure{},
	}

	logger.Info("Lambda triggered", "sqs_record_count", len(sqsEvent.Records))
	if len(sqsEvent.Records) == 0 {
		return response, nil
	}

	failureAction := strings.ToLower(utils.GetEnv("DIVMORA_LICENSE_FAILURE_ACTION", "discard"))
	callerAccount := license.ExtractCallerAccountID(ctx)
	env := license.DetectEnvironment()

	var authTime time.Time
	for _, record := range sqsEvent.Records {
		if sentTs, ok := record.Attributes["SentTimestamp"]; ok && sentTs != "" {
			if ms, err := strconv.ParseInt(sentTs, 10, 64); err == nil && authTime.IsZero() {
				authTime = time.UnixMilli(ms).UTC()
				break
			}
		}
	}

	// 1. Preflight baseline license verification
	// Checks token existence, signature, expiration, and caller AWS account before downloading S3 files.
	preflightStatus, preflightErr := license.PreflightEnforce(license.EnforcementOptions{
		Context:           ctx,
		Environment:       env,
		CallerAccountID:   callerAccount,
		AuthoritativeTime: authTime,
	})
	if preflightErr != nil && license.IsDeterministicLicenseError(preflightErr) {
		logger.Error("Preflight license verification failed in strict mode: terminating batch processing to prevent SQS retry loop",
			"error", preflightErr,
			"environment", env,
			"caller_account", callerAccount,
			"action", failureAction,
		)
		license.EmitCloudWatchEMF(preflightStatus, env, 0, getActiveResourceCount(), quotaTracker.TotalBytesProcessed())

		if failureAction == "dlq" {
			for _, rec := range sqsEvent.Records {
				response.BatchItemFailures = append(response.BatchItemFailures, events.SQSBatchItemFailure{
					ItemIdentifier: rec.MessageId,
				})
			}
		} else {
			response.BatchItemFailures = []events.SQSBatchItemFailure{}
		}
		// Return nil error to SQS poller so SQS does not treat invocation as a crash
		return response, nil
	}

	var allEntries []processor.LogAdapter
	var processedKeys []string
	var lastBucket string
	featureSet := make(map[string]struct{})

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
			var recordKeys []string
			recordFeatures := make(map[string]struct{})

			for _, s3Record := range s3Records {
				bucket := s3Record.S3.Bucket.Name
				key := s3Record.S3.Object.Key

				if bucket == "" || key == "" {
					logger.Warn("Skipping record with empty bucket or key", "message_id", record.MessageId)
					continue
				}

				mu.Lock()
				lastBucket = bucket
				mu.Unlock()

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

				recordKeys = append(recordKeys, key)

				if len(entries) > 0 {
					recordEntries = append(recordEntries, entries...)
					switch proc.Name() {
					case "ALB":
						recordFeatures[license.FeatureParserALB] = struct{}{}
					case "NLB":
						recordFeatures[license.FeatureParserNLB] = struct{}{}
					case "CloudFront":
						if strings.HasSuffix(key, ".parquet") {
							recordFeatures[license.FeatureParserCloudFrontParquet] = struct{}{}
						} else {
							recordFeatures[license.FeatureParserCloudFrontGzip] = struct{}{}
						}
					case "WAF":
						recordFeatures[license.FeatureParserWAF] = struct{}{}
					}
				}
			}

			mu.Lock()
			defer mu.Unlock()

			if msgFailed {
				response.BatchItemFailures = append(response.BatchItemFailures, events.SQSBatchItemFailure{
					ItemIdentifier: record.MessageId,
				})
			} else {
				if len(recordEntries) > 0 {
					allEntries = append(allEntries, recordEntries...)
				}
				if len(recordKeys) > 0 {
					processedKeys = append(processedKeys, recordKeys...)
				}
				for feat := range recordFeatures {
					featureSet[feat] = struct{}{}
				}
			}
		}(record)
	}

	wg.Wait()

	// Extract source account IDs from parsed log records
	sourceAccountMap := make(map[string]struct{})
	for _, entry := range allEntries {
		for _, attr := range entry.GetResourceAttributes() {
			if attr.Key == "cloud.account.id" && attr.Value.StringValue != nil {
				sourceAccountMap[*attr.Value.StringValue] = struct{}{}
			}
		}
	}
	var sourceAccounts []string
	for acc := range sourceAccountMap {
		sourceAccounts = append(sourceAccounts, acc)
	}

	// Detect cross-account log ingestion feature
	if callerAccount != "" {
		for _, acc := range sourceAccounts {
			if acc != "" && acc != callerAccount {
				featureSet[license.FeatureScopeCrossAccount] = struct{}{}
				break
			}
		}
	}

	var exercisedFeatures []string
	for feat := range featureSet {
		exercisedFeatures = append(exercisedFeatures, feat)
	}

	// Extract source resource ARNs from parsed log records and S3 keys
	sourceResourceMap := make(map[string]struct{})
	for _, entry := range allEntries {
		if arn, shortID := license.ExtractResourceFromAttributes(entry.GetResourceAttributes()); arn != "" {
			sourceResourceMap[arn] = struct{}{}
		} else if shortID != "" {
			sourceResourceMap[shortID] = struct{}{}
		}
	}
	for _, k := range processedKeys {
		if arn, shortID := license.ExtractResourceFromS3Key(k); arn != "" {
			sourceResourceMap[arn] = struct{}{}
		} else if shortID != "" {
			sourceResourceMap[shortID] = struct{}{}
		}
	}
	var sourceResources []string
	for res := range sourceResourceMap {
		sourceResources = append(sourceResources, res)
	}

	// Evaluate license compliance
	licStatus, err := license.Enforce(license.EnforcementOptions{
		Context:            ctx,
		Environment:        env,
		CallerAccountID:    callerAccount,
		SourceAccountIDs:   sourceAccounts,
		SourceResourceARNs: sourceResources,
		ExercisedFeatures:  exercisedFeatures,
		BatchRecordCount:   len(allEntries),
		QuotaTracker:       quotaTracker,
		ResourceTracker:    resourceTracker,
		CloudWatchRegistry: cwRegistry,
		BucketName:         lastBucket,
		AuthoritativeTime:  authTime,
	})
	if err != nil {
		if license.IsDeterministicLicenseError(err) {
			logger.Error("Deterministic license compliance failure in strict mode: aborting batch to prevent SQS retry loop",
				"error", err,
				"environment", env,
				"caller_account", callerAccount,
				"action", failureAction,
			)
			license.EmitMetrics(ctx, getCloudWatchClient, licStatus, env, len(allEntries), getActiveResourceCount(), quotaTracker.TotalBytesProcessed(), sourceResources)

			if failureAction == "dlq" {
				for _, rec := range sqsEvent.Records {
					response.BatchItemFailures = append(response.BatchItemFailures, events.SQSBatchItemFailure{
						ItemIdentifier: rec.MessageId,
					})
				}
			} else {
				response.BatchItemFailures = []events.SQSBatchItemFailure{}
			}
			return response, nil
		}
		logger.Error("License enforcement error", "error", err)
		return response, err
	}

	// Update OTLP client with license context
	otlpClient.SetLicenseContext(licStatus, env, callerAccount)

	// Send successful entries to OTLP
	if len(allEntries) > 0 {
		logger.Info("Sending collected entries to OTLP", "count", len(allEntries))
		if err := otlpClient.SendLogs(allEntries); err != nil {
			logger.Error("Error sending to OTLP", "error", err)
			return response, err
		}
	}

	// Emit CloudWatch Metric (asynchronous stdout EMF + cross-region PutMetricData if applicable)
	license.EmitMetrics(ctx, getCloudWatchClient, licStatus, env, len(allEntries), getActiveResourceCount(), quotaTracker.TotalBytesProcessed(), sourceResources)

	logger.Info("Lambda execution completed", "failures", len(response.BatchItemFailures))
	return response, nil
}

func main() {
	lambda.Start(handler)
}
