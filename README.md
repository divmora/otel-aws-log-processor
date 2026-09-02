# AWS Log to OTel Processor

[![Latest Release](https://img.shields.io/github/v/release/divmora/otel-aws-log-processor?logo=github)](https://github.com/divmora/otel-aws-log-processor/releases)
[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-blue.svg)](https://github.com/divmora/.github/blob/main/LICENSING.md)
[![CI/CD](https://github.com/divmora/otel-aws-log-processor/actions/workflows/ci.yml/badge.svg)](https://github.com/divmora/otel-aws-log-processor/actions)
[![Security Policy](https://img.shields.io/badge/Security-Policy-green.svg)](SECURITY.md)
[![Go Version](https://img.shields.io/github/go-mod/go-version/divmora/otel-aws-log-processor)](go.mod)
[![Documentation: DeepWiki](https://img.shields.io/badge/docs-DeepWiki-blue.svg)](https://deepwiki.com/divmora/otel-aws-log-processor)

A high-performance Go-based AWS Lambda application that parses and converts AWS access logs into OpenTelemetry (OTLP) log records, exporting them via HTTP to any OTLP-compatible backend (e.g., SigNoz, OpenTelemetry Collector, Coralogix, Datadog).

---

## Overview

This Lambda function is triggered via **Amazon SQS**, which receives S3 ObjectCreated events (either directly or via Amazon EventBridge) when log files are written to S3. It streams, uncompresses, parses, and transforms access logs into semantic OpenTelemetry `LogRecord` batches grouped by target resource ARN/ID.

### Supported AWS Log Types

- **Application Load Balancer (ALB)**: Standard access logs (`.log`, `.log.gz`).
- **Network Load Balancer (NLB)**: TLS and TCP connection logs (`.log`, `.log.gz`).
- **AWS WAF**: Web Application Firewall JSON logs (`.json`, `.gz`).
- **CloudFront**: Standard access logs (`.gz`) and columnar Parquet logs (`.parquet`).

---

## Architecture & Project Layout

```
otel-aws-log-processor/
├── cmd/
│   └── lambda/                # AWS Lambda entrypoint (SQS event consumer)
├── pkg/
│   ├── events/                # S3 and EventBridge SQS event parsing
│   ├── model/                 # OpenTelemetry JSON data models
│   ├── parser/                # Dedicated log parsers (ALB, NLB, WAF, CloudFront)
│   ├── processor/             # File-matching registry and LogAdapter conversions
│   ├── sender/                # OTLP HTTP batching and retry client
│   └── utils/                 # Helpers (AWS trace IDs, URLs, env vars, time)
├── .github/
│   ├── dependabot.yml         # Automated dependency updates
│   └── workflows/             # Reusable CI/CD, release, and PR workflows
├── .goreleaser.yaml           # Multi-architecture binary and Lambda zip packaging
├── Dockerfile                 # Multi-stage container build for provided.al2023
└── Makefile                   # Standardized build and test targets
```

---

## Features & Design

- ⚡ **High Throughput & Memory Efficient**: Streams S3 log objects line-by-line without buffering large compressed files into memory.
- 🔄 **Semantic Resource Batching**: Automatically groups log records by cloud resource ID (e.g., ALB ARN, CloudFront Distribution ID) prior to HTTP dispatch to maintain semantic resource scoping in OTLP backends.
- 🛡️ **Reliable Delivery & Concurrency**: Leverages SQS concurrency controls with configurable HTTP retry backoff and batch size limits.
- 📦 **Multi-Architecture Builds**: Native builds for ARM64 (`provided.al2023`) and AMD64.

---

## Configuration

The Lambda handler is configured entirely via environment variables:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `OTLP_HTTP_LOGS_ENDPOINT` | HTTP destination endpoint for OTLP logs | `http://localhost:4318/v1/logs` |
| `BASIC_AUTH_USERNAME` | Basic authentication username (optional) | `""` |
| `BASIC_AUTH_PASSWORD` | Basic authentication password (optional) | `""` |
| `MAX_BATCH_SIZE` | Max log records per OTLP HTTP batch request | `500` |
| `MAX_RETRIES` | Number of retry attempts on failed HTTP requests | `3` |
| `MAX_CONCURRENT` | Concurrency limit for file processing & HTTP sending | `10` |

---

## AWS IAM Permissions

Deploy the Lambda function with the following least-privilege IAM policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3LogBucketAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::<your-aws-logs-bucket>/*"
    },
    {
      "Sid": "SQSTriggerAccess",
      "Effect": "Allow",
      "Action": [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes"
      ],
      "Resource": "arn:aws:sqs:<region>:<account-id>:<your-log-events-queue>"
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
```

---

## Deployment

### 1. Build Deployment Package

To build the Lambda deployment package for AWS Lambda (`provided.al2023`, ARM64):

```bash
make lambda-package
```

This compiles a stripped `bootstrap` binary and packages it into `lambda.zip`.

### 2. Deploy Lambda Function

```bash
aws lambda create-function \
  --function-name otel-aws-log-processor \
  --runtime provided.al2023 \
  --handler bootstrap \
  --zip-file fileb://lambda.zip \
  --role arn:aws:iam::<ACCOUNT_ID>:role/<lambda-execution-role> \
  --architectures arm64 \
  --timeout 300 \
  --memory-size 512 \
  --environment "Variables={OTLP_HTTP_LOGS_ENDPOINT=https://ingest.your-observability.com/v1/logs,MAX_BATCH_SIZE=500}"
```

### 3. Configure SQS Trigger

```bash
aws lambda create-event-source-mapping \
  --function-name otel-aws-log-processor \
  --event-source-arn arn:aws:sqs:<REGION>:<ACCOUNT_ID>:<queue-name> \
  --batch-size 10
```

---

## Development & Building

### Prerequisites
- **Go 1.25+**: [golang.org](https://golang.org/dl/)
- **Make**: Build automation
- **Docker**: Containerization and multi-arch builds

### Common Make Targets

```bash
# Build binary locally
make build

# Run all unit tests
make test

# Run unit tests with code coverage analysis
make test-coverage

# Format source code
make fmt

# Run linter
make lint

# Package AWS Lambda zip
make lambda-package

# Build local Docker image
make docker-build
```

---

## Community & Contributing

We welcome contributions from the community! Please review our community documents:

- **[Contributing Guide](CONTRIBUTING.md)**: Guidelines for local setup, pull requests, and conventional commits.
- **[Code of Conduct](CODE_OF_CONDUCT.md)**: Community standards and expectations.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure guidelines and SLA.

---

## License & Commercial Use

This project is licensed under the **Business Source License 1.1 (BSL 1.1)** - see the [LICENSE](LICENSE) file for details.

- **Non-Production Use**: Free of charge for local development, staging, QA, testing, CI/CD validation, and evaluation.
- **Change Date**: Converts automatically to the permissive **Apache License, Version 2.0** three (3) years after release.
- **Production & Commercial Deployments**: Production use requires a commercial license (EULA) from DIVMORA Technologies.

For enterprise licensing and commercial inquiries, please contact **[licensing@divmora.com](mailto:licensing@divmora.com)** or visit **[divmora.com](https://divmora.com)**.
