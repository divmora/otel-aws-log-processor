# AWS Log to OpenTelemetry Processor: Architecture & Operational Manual

`otel-aws-log-processor` is a high-performance, memory-efficient AWS Lambda application engineered in Go. It ingests access logs produced by AWS edge, networking, and security services, parses their contents via streaming readers, maps log attributes to standard OpenTelemetry (OTel) semantic conventions, and exports them in semantic batches over HTTP to any OTLP-compliant receiver.

---

## 1. High-Level Architecture & Pipeline

```mermaid
flowchart TD
    subgraph S3_Events["Ingress Log Storage"]
        S3["Amazon S3 Log Buckets<br/>(AWSLogs/ & aws-waf-logs-*)"]
        EB["Amazon EventBridge / S3 ObjectCreated"]
        SQS["Amazon SQS Queue<br/>(VisibilityTimeout = 6x Lambda Timeout)"]
    end

    subgraph Lambda["Go Lambda Container (provided.al2023)"]
        Handler["Lambda SQS Batch Handler<br/>(ReportBatchItemFailures)"]
        Streamer["Direct S3 Stream Reader<br/>(io.Reader / Gzip / Parquet)"]
        Registry["Parser Registry<br/>(Matches bucket + key pattern)"]
        Adapter["LogAdapter Semantic Transformer"]
        Tracker["ResourceTracker (sync.RWMutex)<br/>Deduplicates Active Endpoints"]
        Enforcer["License Enforcer<br/>(Preflight + Ingest Quota Validation)"]
        Batcher["OTLP HTTP Sender<br/>(Group by ResourceKey, Retry & Backoff)"]
    end

    subgraph Egress["OTLP Observability Backends"]
        OTelCol["OpenTelemetry Collector (/v1/logs)"]
        Backends["SigNoz / Coralogix / Datadog / Grafana"]
        CW["CloudWatch EMF Metrics<br/>(Divmora/LogProcessor)"]
    end

    S3 --> EB --> SQS --> Handler
    Handler --> Streamer
    Streamer --> Registry --> Adapter
    Adapter --> Tracker
    Tracker --> Enforcer
    Enforcer --> Batcher
    Batcher --> OTelCol
    Batcher --> Backends
    Enforcer --> CW
```

### 1.1 Ingestion Flow & Lifecycle
1. **Event Delivery**: As AWS services (ALB, NLB, CloudFront, WAF) write compressed logs to Amazon S3, S3 `ObjectCreated` notifications are dispatched via Amazon EventBridge to an Amazon SQS queue.
2. **Lambda Invocations**: The Lambda handler is triggered with batches of SQS messages (default batch size: 10).
3. **Pre-flight Fast Fail**: In `DIVMORA_LICENSE_MODE=strict`, pre-flight verification validates token integrity, expiration, and environment before initiating S3 network requests. Deterministic license failures are halted immediately, deleting the message (`DIVMORA_LICENSE_FAILURE_ACTION=discard`) to suppress costly SQS retry storms.
4. **Streaming Decompression**: The processor streams S3 objects line-by-line via buffered `io.Reader` scanners without buffering entire archives into memory. RAM utilization remains between 256MB and 512MB even when processing multi-hundred megabyte logs.
5. **Parser Registry**: S3 bucket names and object keys are matched against registered parsers (`Matches(bucket, key)`).
6. **LogAdapter Transformation**: Log lines are converted into typed `LogAdapter` structures that define target resource attributes, log body, severity, timestamps, and OpenTelemetry trace IDs parsed from AWS X-Ray headers.
7. **Monitored Resource Tracking**: In-container `ResourceTracker` registers unique resource ARNs/IDs across concurrent worker routines.
8. **Semantic Grouping & Dispatch**: Records are grouped by unique `ResourceKey` (e.g. TargetGroup ARN or Distribution ID) and dispatched via HTTP POST in batches of up to `MAX_BATCH_SIZE` (default: 500) to the designated OTLP receiver.
9. **CloudWatch EMF Metric Flushing**: Metric payloads adhering to AWS CloudWatch Embedded Metric Format (EMF) are asynchronously emitted, recording `RecordsProcessed`, `LicenseViolations`, and `ActiveMonitoredResources`.

---

## 2. Supported AWS Log Sources

| Log Type | Supported Extensions | Parser Implementation | Resource Identifier | Sample Key Pattern |
|---|---|---|---|---|
| **Application Load Balancer (ALB)** | `.log`, `.log.gz` | Regex streaming parser | TargetGroup ARN or ELB ARN | `AWSLogs/<acct>/elasticloadbalancing/<region>/...` |
| **Network Load Balancer (NLB)** | `.log`, `.log.gz` | Tab/space streaming parser | TargetGroup ARN or NLB ARN | `AWSLogs/<acct>/elasticloadbalancing/<region>/.../net/...` |
| **Amazon CloudFront** | `.gz` (W3C), `.parquet` | W3C Scanner / Parquet reader | Distribution ID (`[A-Z0-9]{8,32}`) | `.../<distribution-id>.<date>-<time>.<hash>.gz` |
| **AWS WAF** | `.json`, `.gz` | JSON streaming parser | WebACL ARN / Name | `aws-waf-logs-.../AWSLogs/<acct>/WAFLogs/...` |

---

## 3. Commercial Licensing: Monitored Resource Packs

### 3.1 Motivation: Decoupling from Raw AWS Accounts
In modern cloud environments adopting AWS Organizations, AWS Control Tower, or Landing Zone Accelerator, companies frequently operate dozens or hundreds of micro-accounts (spoke accounts) for workload isolation.

- **The Problem**: A company with 25 spoke accounts running 1 ALB each would face a 25x license cost penalty under traditional per-account pricing, despite having the exact same infrastructure footprint as a single monolithic account with 25 ALBs.
- **The Solution**: Commercial pricing is pegged to **Monitored Resource Packs** rather than raw AWS account counts.

### 3.2 Definition of a Monitored Resource
A Monitored Resource is any distinct active ingress endpoint from which logs are collected:
1. **ALB**: An Application Load Balancer instance (`...:loadbalancer/app/<name>/<id>`).
2. **NLB**: A Network Load Balancer instance (`...:loadbalancer/net/<name>/<id>`).
3. **CloudFront Distribution**: A distinct CloudFront CDN distribution ID (e.g., `EDFDVBD632BHFR5`).
4. **AWS WAF WebACL**: A Regional or CloudFront WebACL (`.../webacl/<name>/<id>`).

### 3.3 License Token Schema & Claims

License tokens are signed with Ed25519 and contain claims embedded in `claims.Scope`:

```json
{
  "id": "lic_9901abcdef",
  "tier": "pro",
  "product": "otel-aws-log-processor",
  "customer": "Example Corp",
  "features": ["parser.alb", "parser.nlb", "parser.cloudfront.gzip", "parser.waf", "metrics.emf"],
  "limits": {
    "max_resources": 25,
    "max_accounts": 3,
    "max_monthly_gb": 10000,
    "max_container_records": 50000
  },
  "scope": {
    "accounts": ["123456789012", "234567890123", "345678901234"],
    "allowed_resources": [
      "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/*",
      "EDFDVBD632BHFR5"
    ]
  },
  "exp": 1893456000
}
```

#### Fields Reference:
- **`claims.Limits.MaxMonthlyGB` (`int`)**: Specifies the fair-use monthly throughput ceiling in Gigabytes (e.g. `50` for Community, `10000` for Pro 10 TB, `50000` for Enterprise 50 TB).
  - **Backward Compatibility**: If `max_monthly_gb == 0` or omitted, monthly throughput is **uncapped**.
- **`claims.Limits.MaxResources` (`int`)**: Maximum unique active monitored resources allowed across the container's lifecycle.
  - **Backward Compatibility**: If `max_resources == 0` or omitted, resource tracking is **uncapped**.
- **`claims.Limits.MaxAccounts` (`int`)**: Maximum unique AWS account IDs permitted.
- **`claims.Scope.AllowedResources` (`[]string`)**: Optional explicit list of permitted resource ARNs, prefixes, wildcards, or IDs.
  - Supports glob wildcards (`*` and `?`) spanning path boundaries.
  - Supports short ID matching against ARN suffixes.

### 3.4 Runtime Resource Tracking & Enforcement Modes

The container maintains a thread-safe `ResourceTracker` protected by `sync.RWMutex`:

- **`DIVMORA_LICENSE_MODE=warn` (Default)**:
  - If unique resources exceed `MaxResources` or an unauthorized resource is detected, a structured warning log is emitted.
  - Log records continue streaming without dropped telemetry.
  - Records are annotated with `divmora.license.status=resource_quota_exceeded` or `resource_not_allowed`.
- **`DIVMORA_LICENSE_MODE=strict`**:
  - Exceeding `MaxResources` returns `ErrResourceQuotaExceeded`.
  - Processing an unauthorized resource returns `ErrResourceNotAllowed`.
  - With `DIVMORA_LICENSE_FAILURE_ACTION=discard`, SQS messages are cleanly acknowledged to prevent infinite retry loops.

### 3.5 High-Performance Byte Metering & Soft Fair-Use Ceiling

To resolve the **Hyper-Scale Petabyte Under-Monetization Loophole** (where multi-hundred-terabyte pipelines eliminate $250,000+/mo in CloudWatch ingestion while paying only small flat fees), `otel-aws-log-processor` implements high-performance atomic byte tracking:

1. **Zero-Allocation Stream Metering**: `CountingReader` hooks directly into the decompression readers (`io.Reader` scanners, JSON streaming decoders, and Parquet readers). Bytes are recorded via lock-free atomic counters (`atomic.Int64`), adding `<0.5%` CPU overhead with zero memory allocations on the critical path.
2. **100% Non-Blocking Soft Invariant**: When cumulative throughput breaches the fair-use tier allocation (`max_monthly_gb`), **no log records are ever dropped, delayed, or dead-lettered**. Log processing continues uninterrupted at 100% full line rate.
3. **Rate-Limited Structured Warning Banner**: A warning banner is emitted to CloudWatch Logs at most once every 60 minutes per Lambda container:
   ```
   [WARN_FAIR_USE_THROUGHPUT_EXCEEDED] Monthly log volume has exceeded the licensed fair-use allocation (Allocated: 10000 GB). Telemetry processing continues uninterrupted without data loss. Please contact licensing@divmora.com to adjust your commitment tier.
   ```
4. **CloudWatch EMF Metric Synchronization**: Exact byte counts are emitted via AWS CloudWatch Embedded Metric Format (EMF) for automated billing audit synchronization and contractual true-up invoicing.

### 3.6 CloudWatch EMF Metrics Schema

Every batch execution emits metrics in CloudWatch Embedded Metric Format (EMF) under namespaces `Divmora/LogProcessor` and `Divmora/License`:

```json
{
  "_aws": {
    "Timestamp": 1790589879443,
    "CloudWatchMetrics": [
      {
        "Namespace": "Divmora/LogProcessor",
        "Dimensions": [["Environment", "Status", "Region"], ["Environment", "Region"], ["Environment"]],
        "Metrics": [
          {"Name": "RecordsProcessed", "Unit": "Count"},
          {"Name": "BytesProcessed", "Unit": "Bytes"},
          {"Name": "LicenseViolations", "Unit": "Count"},
          {"Name": "ActiveMonitoredResources", "Unit": "Count"}
        ]
      },
      {
        "Namespace": "Divmora/License",
        "Dimensions": [["LicenseID", "Tier", "Region"], ["LicenseID", "Tier"], ["LicenseID", "Tier", "ResourceARN"]],
        "Metrics": [
          {"Name": "BytesProcessed", "Unit": "Bytes"},
          {"Name": "RecordsProcessed", "Unit": "Count"}
        ]
      }
    ]
  },
  "Environment": "production",
  "Region": "eu-central-1",
  "CentralMetricsRegion": "us-east-1",
  "Status": "valid",
  "RecordsProcessed": 1500,
  "BytesProcessed": 10485760,
  "LicenseViolations": 0,
  "ActiveMonitoredResources": 18,
  "LicenseID": "lic_9901abcdef",
  "Tier": "pro",
  "ResourceARN": "arn:aws:elasticloadbalancing:eu-central-1:123456789012:loadbalancer/app/api/50dc6c495c0c9188"
}
```

### 3.7 Centralized Cross-Region Metrics Aggregation

In enterprise multi-region deployments, Lambda functions can execute in any AWS region (e.g. `eu-west-1`, `us-west-2`, `ap-southeast-1`), while operational and billing metrics must be aggregated into a single centralized region:

1. **Signed License Metadata Authoritative Source**:
   The central metrics region is determined directly from the cryptographically signed license token claims:
   - `claims.Metadata["metrics_region"]` (or `claims.Metadata["cloudwatch_metrics_region"]`)
   - Default fallback: **`us-east-1`** (the standard AWS billing and global control plane region).
   - **Zero Environment Variable Dependency**: To guarantee uniform aggregation across all distributed stacks and prevent tenant quota evasion via configuration drift, environment variable overrides are strictly disallowed.

2. **Automated Cross-Region Dispatching**:
   - **Executing in Central Region (`currentRegion == centralRegion`)**: Emits Embedded Metric Format (EMF) directly to `stdout` with **0ms API latency** and zero AWS PutMetricData API cost.
   - **Executing in Remote Region (`currentRegion != centralRegion`)**: Emits EMF to local `stdout` for container observability, and automatically dispatches `PutMetricData` directly across regions to the target central region using the AWS CloudWatch SDK.
   - **Unified Global Aggregation with Regional Drill-Down**: Metrics published to the central region retain the source execution region in the `Region` dimension (`[LicenseID, Tier, Region]`), allowing both global aggregation (`SUM(BytesProcessed)`) and per-region utilization breakdown.

---

## 4. Configuration Reference

All settings are configured through environment variables:

| Environment Variable | Description | Default | Allowed Values |
|---|---|---|---|
| `OTLP_HTTP_LOGS_ENDPOINT` | Destination endpoint for OTLP HTTP JSON logs | `http://localhost:4318/v1/logs` | Valid HTTP/HTTPS URL |
| `BASIC_AUTH_USERNAME` | Basic authentication username for OTLP receiver | `""` | String |
| `BASIC_AUTH_PASSWORD` | Basic authentication password for OTLP receiver | `""` | String |
| `MAX_BATCH_SIZE` | Maximum log records per exported OTLP batch | `500` | Integer (1–5000) |
| `MAX_RETRIES` | Max HTTP retry attempts on transient network/server errors | `3` | Integer (0–10) |
| `MAX_CONCURRENT` | Max concurrent worker goroutines processing files | `10` | Integer (1–50) |
| `ENVIRONMENT` | Deployment environment name | `production` | `development`, `staging`, `production` |
| `DIVMORA_LICENSE_KEY` | Commercial Ed25519 license token | `""` | Valid `DIV1...` token |
| `DIVMORA_LICENSE_FILE` | Path to commercial license key file | `""` | File path |
| `DIVMORA_LICENSE_MODE` | Enforcement behavior upon license non-compliance | `warn` | `warn`, `strict` |
| `DIVMORA_LICENSE_FAILURE_ACTION` | SQS behavior on deterministic license failure | `discard` | `discard`, `dlq` |
| `DIVMORA_CRL` | Armored or token-formatted offline Certificate Revocation List | `""` | Valid `DIVCRL1...` token |
| `DIVMORA_CRL_FILE` | Path to offline `.divcrl` file | `""` | File path |
| `DIVMORA_CRL_URL` | Remote HTTPS endpoint for dynamic CRL polling | `""` | HTTPS URL |

---

## 5. Operational Best Practices

1. **SQS Visibility Timeout**:
   - Always set the SQS queue's `VisibilityTimeout` to at least **6 times the Lambda timeout** (e.g. 1800s if Lambda timeout is 300s). This prevents SQS from redelivering messages while the Lambda container is actively streaming large log files.
2. **Partial Batch Failures**:
   - Always configure the Lambda Event Source Mapping with `FunctionResponseTypes=["ReportBatchItemFailures"]`. This ensures only failed log files in a batch are retried, preventing duplicate logs.
3. **Dead Letter Queue (DLQ)**:
   - Configure a DLQ on the ingestion SQS queue with `maxReceiveCount=3` to capture unprocessable or corrupt log files without blocking the pipeline.
4. **AWS Secrets Manager**:
   - For production deployments, pass `BASIC_AUTH_PASSWORD` or `DIVMORA_LICENSE_KEY` via AWS Secrets Manager secret references to keep credentials out of plain environment variables.
