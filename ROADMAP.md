# AWS Log to OTel Processor Product Roadmap

This document serves as the **living product roadmap** for `otel-aws-log-processor`.
- **Adding Items**: Whenever a new capability, enhancement, or edge-case improvement is identified for the future, add it here under the appropriate category.
- **Deduplication with GitHub Issues**: If an active GitHub Issue already exists or is explicitly created for a feature, bug fix, or task, do not duplicate it in `ROADMAP.md`. GitHub Issues track active, assigned, or triaged tasks, while `ROADMAP.md` captures high-level, unassigned architectural vision and backlog capabilities.
- **Removing Items**: Once a feature is fully implemented, verified, and committed, **remove it from this roadmap**.

---

## 1. Additional AWS Log Types & Sources

- [ ] **Amazon VPC Flow Logs Parser (Plain Text & Parquet)**
  - Parse VPC flow logs (`srcaddr`, `dstaddr`, `srcport`, `dstport`, `protocol`, `packets`, `bytes`, `action`, `log-status`).
  - Map network connection telemetry to OpenTelemetry network semantic conventions (`net.peer.ip`, `net.peer.port`, `net.host.ip`, `net.transport`).
- [ ] **AWS CloudTrail Management & Data Events Parser**
  - Parse CloudTrail JSON digests and single-record events from S3.
  - Map IAM user identity, event source, API actions, and error codes to security-focused OTLP log attributes.
- [ ] **Amazon Route 53 DNS Query Logs**
  - Parse Route 53 query logs from S3/CloudWatch (`resolver_ip`, `query_name`, `query_type`, `response_code`).
  - Map DNS resolution telemetry to standard DNS semantic convention attributes (`dns.question.name`, `dns.question.type`, `dns.response_code`).
- [ ] **Amazon S3 Server Access Logs**
  - Stream and parse S3 bucket access logs (`bucket_owner`, `request_uri`, `http_status`, `bytes_sent`, `turn_around_time`).
  - Map object access patterns and latencies directly into OTLP records.
- [ ] **CloudWatch Logs Subscription Filter Direct Consumer**
  - Add native handler support for direct CloudWatch Logs Kinesis/Firehose/Lambda gzip-encoded payloads (`awslogs` event format) in addition to SQS/S3 file ingest.

---

## 2. Exporter Transports & Resilience

- [ ] **OTLP / gRPC Exporter Transport**
  - Add native high-performance OTLP/gRPC client via HTTP/2 streaming protocol in addition to the existing OTLP/HTTP JSON client.
  - Enable binary Protobuf serialization for maximum throughput and minimal CPU overhead.
- [ ] **Dead-Letter Queue (DLQ) & Transient Buffer Support**
  - Gracefully offload failed OTLP export batches to an SQS DLQ or S3 spillover prefix after exhaustion of retry attempts, guaranteeing zero log loss during downstream collector outages.
- [ ] **mTLS Client Certificate Authentication**
  - Support mutual TLS authentication (`CLIENT_CERT_PATH`, `CLIENT_KEY_PATH`, `CA_CERT_PATH`) for enterprise zero-trust OTLP collectors.

---

## 3. High-Throughput Performance & Memory Optimization

- [ ] **Zero-Copy Streaming Decompression**
  - Stream large gzip archives line-by-line directly through memory buffers to further minimize peak Lambda RAM allocation during high-volume log bursts.
- [ ] **SIMD-Accelerated JSON Parsing**
  - Evaluate `simdjson-go` for ultra-fast WAF and CloudTrail JSON log record parsing on `arm64` Graviton architecture.
- [ ] **Dynamic Batch Sizing by Payload Byte Size**
  - Dynamically compute payload byte size during batch aggregation to respect OTLP collector maximum request payload caps (e.g. 4MB) independently of log record counts.

---

## 4. Telemetry Enrichment & Semantic Standardization

- [ ] **MaxMind GeoIP & ASN Attribute Enrichment**
  - Support optional offline MaxMind GeoLite2/GeoIP2 database lookup (embedded or mounted via AWS Lambda EFS) to enrich client IP addresses with `geo.country_iso_code`, `geo.city_name`, and `geo.asn`.
- [ ] **User-Agent String Parser**
  - Parse `user_agent` strings into standard OpenTelemetry browser, OS, and device attributes (`user_agent.original`, `browser.name`, `os.name`).
- [ ] **Self-Observability Metrics**
  - Emit native OTLP runtime metrics (`otel_aws_logs.records_parsed_total`, `otel_aws_logs.export_duration_ms`, `otel_aws_logs.bytes_processed_total`) to monitor processing efficiency.
