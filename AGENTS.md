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
├── pkg/
│   ├── events/                   # S3 and EventBridge SQS message parsing
│   ├── model/                    # OpenTelemetry JSON data models
│   ├── parser/                   # Dedicated log parsers (ALB, NLB, CloudFront, WAF)
│   ├── processor/                # File-matching registry and LogAdapter conversions
│   ├── sender/                   # OTLP HTTP batching and retry client
│   └── utils/                    # Helpers for env vars, parsing, trace IDs, URLs
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
| `BASIC_AUTH_USERNAME` | Basic authentication username (optional) | `""` |
| `BASIC_AUTH_PASSWORD` | Basic authentication password (optional) | `""` |
| `MAX_BATCH_SIZE` | Max log records per OTLP HTTP batch request | `500` |
| `MAX_RETRIES` | Number of retry attempts on failed HTTP requests | `3` |
| `MAX_CONCURRENT` | Concurrency limit for file processing & HTTP sending | `10` |

---

## 📝 Contribution & PR Conventions

- **Conventional Commits**: This repository enforces semantic PR titles (`feat: ...`, `fix: ...`, `chore: ...`, `docs: ...`) via `.github/workflows/semantic-pull-request.yml`.
- **Automated Releases**: Releases and changelog generation are automated via Google's `release-please` action (`.github/workflows/release-please.yml`) and GoReleaser.
- **Living Product Roadmap Management**: `ROADMAP.md` is the central living document tracking future capabilities, optimizations, and technical debt:
  - **Adding Items**: Whenever you or the user identify a capability, optimization, or edge-case improvement for future work, add it to `ROADMAP.md` under the appropriate category.
  - **Deduplication with GitHub Issues**: If an active GitHub Issue already exists or is explicitly created for a feature, bug fix, or task, **do not duplicate it in `ROADMAP.md`**. GitHub Issues track active, assigned, or triaged tasks, while `ROADMAP.md` captures high-level, unassigned architectural vision and backlog capabilities.
  - **Removing Items**: Once a feature is fully implemented, verified with tests, and committed, **remove it from `ROADMAP.md`** immediately to keep the roadmap focused on active upcoming tasks.
- **Tests Required**: Any new parser, processor, or utility must be accompanied by unit tests in the corresponding `*_test.go` file.
