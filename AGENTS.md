# AGENTS.md

Welcome to `otel-aws-log-processor`! This guide provides context, architecture details, and commands for AI agents and human contributors working on this repository.

---

## 🎯 Repository Overview

`otel-aws-log-processor` is a high-performance Go-based AWS Lambda application that parses and converts AWS access logs into OpenTelemetry (OTLP) log records, exporting them via HTTP to OTLP-compatible backends (e.g., SigNoz, OpenTelemetry Collector, Coralogix, Datadog).

### Supported AWS Log Types
- **Application Load Balancer (ALB)**: Raw access logs (`.log`, `.log.gz`)
- **Network Load Balancer (NLB)**: TLS/TCP access logs (`.log`, `.log.gz`)
- **AWS WAF**: JSON-formatted access logs (`.json`, `.gz`)
- **CloudFront**: Standard access logs (`.gz`) and Parquet format (`.parquet`)

---

## 🏗️ Architecture & Directory Structure

```
otel-aws-log-processor/
├── cmd/
│   └── lambda/                   # AWS Lambda entrypoint (triggered by SQS)
├── deploy/
│   └── cloudformation/           # Production AWS CloudFormation templates (Lambda, SQS, DLQ, IAM, alarms)
├── pkg/
│   ├── events/                   # S3 and EventBridge SQS message parsing
│   ├── license/                  # BSL 1.1 license enforcement, preflight checks, CloudWatch distributed registry, CRL sync
│   ├── model/                    # OpenTelemetry JSON data models
│   ├── parser/                   # Dedicated log parsers (ALB, NLB, CloudFront, WAF)
│   ├── processor/                # File-matching registry and LogAdapter conversions
│   ├── sender/                   # OTLP HTTP batching, headers, and retry client
│   ├── utils/                    # Helpers for env vars, parsing, trace IDs, URLs
│   └── version/                  # Semantic versioning, build metadata, and cryptographic release provenance
├── docs/                         # GitHub Pages static documentation portal
├── .github/
│   ├── dependabot.yml            # Automated weekly dependency updates
│   └── workflows/                # Reusable CI/CD, release, pages, and PR workflows
├── .goreleaser.yaml              # Multi-arch binary and Lambda packaging
├── .release-please-config.json   # Release Please configuration
├── .release-please-manifest.json # Release Please version manifest
├── Dockerfile                    # Multi-stage container build for Lambda provided.al2023
├── Makefile                      # Common build, test, and package targets
├── ROADMAP.md                    # Living product roadmap (future capabilities & technical debt)
├── CONTRIBUTING.md               # Contribution workflow and guidelines
├── SECURITY.md                   # Security vulnerability reporting policy
└── LICENSE                       # Divmora Business Source License 1.1 (BSL 1.1)
```

### Key Design Patterns
1. **Registry Pattern (`pkg/processor/processor.go`)**: Processors register against file patterns/prefixes (`Matches(bucket, key) bool`).
2. **Log Adapter Pattern (`pkg/processor/base.go`)**: Parsed records implement `LogAdapter` with `GetResourceKey()`, `GetResourceAttributes()`, and `ToOTel()`.
3. **Resource Grouping & Batching (`pkg/sender/otlp_client.go`)**: Records are grouped by unique resource attributes (e.g., ELB ARN, CloudFront Distribution ID) before sending batches to preserve semantic resource scoping in OTLP.
4. **Streaming Memory Efficiency**: Stream S3 records directly without buffering full decompressed archives in memory.
5. **Two-Phase License Enforcement (Preflight & Runtime)**:
   - **Preflight Verification (`license.PreflightEnforce`)**: Fast baseline check executed before downloading or decompressing S3 archives. Validates token signature, expiration, revocation (CRL), caller AWS account authorization, and all S3 bucket names in the batch (`BucketNames`). Deterministic failures abort immediately with SQS retry suppression to save Lambda compute costs.
   - **Runtime Verification (`license.Enforce`)**: Executed post-parsing to validate exercised features (`FeatureParser*`, `FeatureScopeCrossAccount`), source accounts, monitored resource pack quotas (`MaxResources`), and soft throughput ceilings.
6. **Multi-Bucket Batch Aggregation & Production Defense**:
   - SQS batches can contain records pointing to multiple distinct S3 log buckets.
   - All buckets across all SQS messages are deduplicated and evaluated across both preflight and runtime.
   - `DetectProductionIndicators` evaluates all bucket names in `opts.BucketNames`. If *any* bucket contains a production keyword (`prod`, `production`, `live`, `prd`), production mode is strictly triggered, preventing evasion via mixed dev/prod batches.
7. **Distributed Monitored Resource Registry (`pkg/license/cloudwatch_registry.go`)**:
   - Tracks active monitored resource quotas (`MaxResources`) across decentralized, ephemeral Lambda instances using CloudWatch EMF metrics without requiring an external database.
   - CloudWatch IAM access denial errors (`ErrCloudWatchRegistryAccessDenied`) fail deterministically in strict mode to prevent tampering.
8. **Deterministic License Failure & SQS Retry Suppression**:
   - Distinguishes between transient errors (retried by SQS) and deterministic licensing violations (`IsDeterministicLicenseError`).
   - Suppresses infinite SQS billing retry loops by returning a `nil` error to the Lambda runtime while either routing messages to a DLQ (`DIVMORA_LICENSE_FAILURE_ACTION=dlq`) or acknowledging and discarding them (`discard`).

---

## 🛠️ Development & Tooling Commands

### Prerequisites
- Go 1.26+
- Make

### Common Make Commands
- **Run all unit tests**:
  ```bash
  make test
  ```
- **Run unit tests with coverage**:
  ```bash
  make test-coverage
  ```
- **Build binary locally**:
  ```bash
  make build
  ```
- **Format code**:
  ```bash
  make fmt
  ```
- **Run linter**:
  ```bash
  make lint
  ```
- **Lint CloudFormation templates**:
  ```bash
  make cfn-lint
  ```
- **Package Lambda zip**:
  ```bash
  make lambda-package
  ```
- **Build Docker image**:
  ```bash
  make docker-build
  ```
- **Preview documentation locally**:
  ```bash
  make docs-serve
  ```

---

## ⚙️ Environment Variables & Configuration

The Lambda handler is configured via environment variables:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `OTLP_HTTP_LOGS_ENDPOINT` | HTTP destination endpoint for OTLP logs | `http://localhost:4318/v1/logs` |
| `OTEL_EXPORTER_OTLP_HEADERS` | Custom HTTP headers for OTLP receiver (comma-separated `k=v` or JSON) | `""` |
| `BASIC_AUTH_USERNAME` | Basic authentication username (optional) | `""` |
| `BASIC_AUTH_PASSWORD` | Basic authentication password (optional) | `""` |
| `MAX_BATCH_SIZE` | Max log records per OTLP HTTP batch request | `500` |
| `MAX_RETRIES` | Number of retry attempts on failed HTTP requests | `3` |
| `MAX_CONCURRENT` | Concurrency limit for file processing & HTTP sending | `10` |
| `LOG_LEVEL` | Application logging level (`DEBUG`, `INFO`, `WARN`, `ERROR`) | `INFO` |
| `ENVIRONMENT` | Deployment environment tier (`development`, `staging`, `production`) | `production` |
| `PROJECT_NAME` | Project identifier for project-scoped licenses and multi-tenant isolation | `""` |
| `DIVMORA_LICENSE_KEY` | Commercial Ed25519 license token (required for production) | `""` |
| `DIVMORA_LICENSE_FILE` | Path to commercial license key file | `""` |
| `DIVMORA_LICENSE_MODE` | Enforcement mode: `auto` (strict for prod, warn for non-prod), `strict`, or `warn` | `auto` |
| `DIVMORA_LICENSE_FAILURE_ACTION` | SQS behavior on strict license failure: `discard` (stop retry loop) or `dlq` | `discard` |
| `DIVMORA_CRL` | Inline armored/token Certificate Revocation List (CRL) | `""` |
| `DIVMORA_CRL_FILE` | Path to offline `.divcrl` file | `""` |
| `DIVMORA_CRL_URL` | Remote HTTPS endpoint for dynamic CRL polling with disk caching | `""` |

---

## 📝 Contribution & PR Conventions

- **Conventional Commits**: This repository enforces semantic PR titles (`feat: ...`, `fix: ...`, `chore: ...`, `docs: ...`) via `.github/workflows/semantic-pull-request.yml`.
- **Automated Releases**: Releases and changelog generation are automated via Google's `release-please` action (`.github/workflows/release-please.yml`) and GoReleaser.
- **Living Product Roadmap Management**: `ROADMAP.md` is the central living document tracking future capabilities, optimizations, and technical debt:
  - **Adding Items**: Whenever you or the user identify a capability, optimization, or edge-case improvement for future work, add it to `ROADMAP.md` under the appropriate category.
  - **Deduplication with GitHub Issues**: If an active GitHub Issue already exists or is explicitly created for a feature, bug fix, or task, **do not duplicate it in `ROADMAP.md`**. GitHub Issues track active, assigned, or triaged tasks, while `ROADMAP.md` captures high-level, unassigned architectural vision and backlog capabilities.
  - **Removing Items**: Once a feature is fully implemented, verified with tests, and committed, **remove it from `ROADMAP.md`** immediately to keep the roadmap focused on active upcoming tasks.
- **Tests Required**: Any new parser, processor, or utility must be accompanied by unit tests in the corresponding `*_test.go` file.
