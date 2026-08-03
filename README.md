# AWS Log to OTel Processor

[![Build Status](https://img.shields.io/github/actions/workflow/status/divmora/otel-aws-log-parser/docker-publish.yml?branch=main)](https://github.com/divmora/otel-aws-log-parser/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/divmora/otel-aws-log-parser)](https://goreportcard.com/report/github.com/divmora/otel-aws-log-parser)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

High-performance Golang implementation for processing AWS Load Balancer (ALB), Network Load Balancer (NLB), WAF, and CloudFront logs, converting them to OpenTelemetry (OTLP) format.

This Lambda function is designed to be triggered via **Amazon SQS**, which receives S3 Event Notifications (or EventBridge notifications) when new log files are delivered to S3.

## Project Structure

```
otel-aws-log-parser/
├── cmd/
│   └── lambda/              # AWS Lambda handler (SQS triggered)
├── pkg/
│   ├── events/              # S3/EventBridge event parsing
│   ├── model/               # OTel data models
│   ├── parser/              # Log parsers (ALB, NLB, WAF, CloudFront)
│   ├── processor/           # Log processors & Logic
│   ├── sender/              # OTLP Client & Batching
│   └── utils/               # Utilities (Env, Time, etc.)
└── Makefile
```

## Features

✅ **Parsers**
- **ALB**: Application Load Balancer access logs.
- **NLB**: Network Load Balancer connection logs.
- **WAF**: Web Application Firewall logs.
- **CloudFront**: Standard access logs (gzip and parquet).

✅ **OTLP Export**
- Converts logs to OpenTelemetry `LogRecord` format.
- Batched sending to any OTLP-compatible backend.
- Configurable retries and concurrency.

✅ **Architecture**
- **SQS Trigger**: Processes events from SQS for reliability and concurrency control.
- **Concurrency**: Parallel processing of files and log lines.
- **Memory Efficient**: Streaming processing of S3 objects.

## Building

### Prerequisites
- Go 1.25+
- Make

### Build Locally
```bash
# Build all binaries to bin/
make build
```

### Run Tests
```bash
make test
```

## Configuration

The Lambda function is configured via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SIGNOZ_OTLP_ENDPOINT` | HTTP URL of the OTLP Log Receiver | `http://localhost:4318/v1/logs` |
| `BASIC_AUTH_USERNAME` | Basic Auth Username (optional) | "" |
| `BASIC_AUTH_PASSWORD` | Basic Auth Password (optional) | "" |
| `MAX_BATCH_SIZE` | Max logs per OTLP request | `500` |
| `MAX_RETRIES` | Max retries for failed sends | `3` |
| `MAX_CONCURRENT` | Max concurrent files/routines | `10` |

## Deployment

### 1. Build Deployment Package

To build for AWS Lambda (`provided.al2023` runtime, ARM64):

```bash
# Using Make (builds lambda.zip)
make lambda-package
```

**Note:** If deploying manually with a custom runtime like `provided.al2023`, ensure the binary inside the zip is named `bootstrap`. The default `make lambda-package` zips the binary named `lambda`. You may need to rename it:

```bash
# Manual Build
GOOS=linux GOARCH=arm64 go build -o bootstrap ./cmd/lambda
zip lambda.zip bootstrap
```

### 2. Infrastructure Setup (Overview)

1.  **S3 Bucket**: Stores your AWS logs.
2.  **SQS Queue**: Receives `ObjectCreated` events from S3 (or via EventBridge).
3.  **Lambda Function**: Consumes messages from the SQS Queue.

### 3. Deploy Lambda

```bash
# Example using AWS CLI
aws lambda create-function \
  --function-name otel-aws-log-parser \
  --runtime provided.al2023 \
  --handler bootstrap \
  --zip-file fileb://lambda.zip \
  --role arn:aws:iam::ACCOUNT:role/lambda-role \
  --architectures arm64 \
  --timeout 300 \
  --memory-size 512 \
  --environment "Variables={SIGNOZ_OTLP_ENDPOINT=https://ingest.your-observability.com/v1/logs,MAX_BATCH_SIZE=1000}"
```

### 4. Configure Trigger

Set the Lambda function to be triggered by the SQS queue.

```bash
aws lambda create-event-source-mapping \
  --function-name otel-aws-log-parser \
  --event-source-arn arn:aws:sqs:REGION:ACCOUNT:queue-name
```

## Contributors

Thank you to all our contributors!

- [Divmora](https://github.com/divmora)

## Code of Conduct

Please note that this project is released with a [Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
