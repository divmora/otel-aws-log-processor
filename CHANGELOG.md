# Changelog

## [0.3.1](https://github.com/divmora/otel-aws-log-processor/compare/v0.3.0...v0.3.1) (2026-10-08)


### Bug Fixes

* **lambda:** pass preflightBucket to PreflightEnforce and extract accounts from S3 keys ([4fb3049](https://github.com/divmora/otel-aws-log-processor/commit/4fb30492327fbacf29e39d57cb18d2bd459e5fb0))
* **license:** support multiple S3 log buckets in SQS event batch ([c5d384f](https://github.com/divmora/otel-aws-log-processor/commit/c5d384fb5cd22e5160823960bb772753e5277fe1))
* **license:** unify violation detection, dispatch preflight metrics, and resolve real cloudfront distribution id ([240891c](https://github.com/divmora/otel-aws-log-processor/commit/240891cc05de9bcc47d16b98793bbeea8a94e313))
* resolve license bypass vulnerabilities and s3 reader error propagation ([cd44262](https://github.com/divmora/otel-aws-log-processor/commit/cd44262eab8310455e59359b9c1c43b6df234b30))
* **sender:** prevent goroutine leak and waitgroup bypass in OTLPClient.SendLogs ([8e76f97](https://github.com/divmora/otel-aws-log-processor/commit/8e76f972f0b57b896d714266fae1c0f5de0a205c))

## [0.3.0](https://github.com/divmora/otel-aws-log-processor/compare/v0.2.0...v0.3.0) (2026-10-07)


### Features

* **events:** support direct S3 notifications and SNS wrappers alongside EventBridge ([56a3934](https://github.com/divmora/otel-aws-log-processor/commit/56a393438dcc266f8105c6e6a3e7e6b710ec8531))
* **iac:** migrate and enhance cloudformation templates in deploy/cloudformation ([336c697](https://github.com/divmora/otel-aws-log-processor/commit/336c6975e144543e2fc2fcdf508190aac0d03250))
* implement BSL 1.1 commercial licensing and Ed25519 binary release signing ([55aa3b8](https://github.com/divmora/otel-aws-log-processor/commit/55aa3b849f29b1a747e60854cafbcb1a695828ef))
* **license:** add CloudWatch distributed resource registry for MaxResources enforcement ([#30](https://github.com/divmora/otel-aws-log-processor/issues/30)) ([aae4e9d](https://github.com/divmora/otel-aws-log-processor/commit/aae4e9ddaaa0c3e9feb3864805484647efbd4d08))
* **license:** add throughput metering, resource pack licensing, and license-go v1.4.0 integration ([#29](https://github.com/divmora/otel-aws-log-processor/issues/29)) ([8b1687d](https://github.com/divmora/otel-aws-log-processor/commit/8b1687df77ce7a4ddaaf24c6e1f4f5e0f675472f))
* **license:** adopt license-go v0.6.0 with release attestation and declarative BSL policy ([b11021e](https://github.com/divmora/otel-aws-log-processor/commit/b11021ed41707734e12c6f688360f4065b0efaeb))
* **license:** default production to strict mode and enforce 10-resource limit in free non-prod ([1ecda3b](https://github.com/divmora/otel-aws-log-processor/commit/1ecda3ba05728bb27753068e80714a754c6fc180))
* **license:** harden non-prod fair-use ceilings and support multi-project and dev commercial licenses ([1752be0](https://github.com/divmora/otel-aws-log-processor/commit/1752be0c0795e69f59220c4b520b329a6c59d072))
* **license:** implement plan tiers and feature entitlement matrix ([#25](https://github.com/divmora/otel-aws-log-processor/issues/25)) ([bba232c](https://github.com/divmora/otel-aws-log-processor/commit/bba232c7fb536e6f586980a6c81260596f0724df))
* **license:** remove legacy 2-part release tokens and adopt full license-go v0.6.0 capabilities ([738d338](https://github.com/divmora/otel-aws-log-processor/commit/738d33852453661ca06954f5695f75baf436289a))
* **license:** scope license alarms, add project to cross-region metrics, and support global registry via license claims ([742fec6](https://github.com/divmora/otel-aws-log-processor/commit/742fec6cffeeaaf60d82ba81293b2a4fa4bc7279))
* **license:** upgrade license-go to v0.7.0 and enhance Docker release attestation ([6dd9c34](https://github.com/divmora/otel-aws-log-processor/commit/6dd9c34869962ad8953899611cdeedc35af9eeec))
* **license:** upgrade to license-go v1.0.0 and standardize Lambda runtime verification without regressions ([#17](https://github.com/divmora/otel-aws-log-processor/issues/17)) ([b13b2ff](https://github.com/divmora/otel-aws-log-processor/commit/b13b2ffd8e0dfb8c02bbe5c663775caaf15a91fb))
* **license:** upgrade to license-go v1.3.1, bump aws-lambda-go, and support offline/online CRL ([#24](https://github.com/divmora/otel-aws-log-processor/issues/24)) ([4b1c71d](https://github.com/divmora/otel-aws-log-processor/commit/4b1c71d7e36245a852ec3122bed582f58b5daf90))
* **license:** wire PROJECT_NAME for multi-project isolation and anti-spoofing ([e9c7384](https://github.com/divmora/otel-aws-log-processor/commit/e9c7384b2bf3473c1051a720e15fddb07375ecbe))


### Bug Fixes

* **docker:** copy bootstrap to LAMBDA_TASK_ROOT and ensure execution permissions ([87172ae](https://github.com/divmora/otel-aws-log-processor/commit/87172ae740582e6797d0273e946fa19769747dca))
* **events:** automatically url-unescape direct s3 notification object keys ([f88baa3](https://github.com/divmora/otel-aws-log-processor/commit/f88baa3c9a7dbb1a4c6f03ca61041c2505d892c1))
* **lambda:** suppress SQS retry loops on deterministic license failure ([#26](https://github.com/divmora/otel-aws-log-processor/issues/26)) ([383d2ed](https://github.com/divmora/otel-aws-log-processor/commit/383d2edcb67986786d1eda22c04753a2edf882c9))
* **license:** harden public key root of trust and defend against environment spoofing ([#30](https://github.com/divmora/otel-aws-log-processor/issues/30)) ([fa212f1](https://github.com/divmora/otel-aws-log-processor/commit/fa212f1a08eeda2036652bbb8a29b54a19c0a8b6))
* **parser:** support NLB TCP logs and add WAF HTTP status code mapping ([#35](https://github.com/divmora/otel-aws-log-processor/issues/35)) ([ac25d65](https://github.com/divmora/otel-aws-log-processor/commit/ac25d653bbfd921c37c627c2b8251bb3a9ac48ee))
* **sender:** reuse HTTP client, close response bodies, and support custom OTLP headers ([#37](https://github.com/divmora/otel-aws-log-processor/issues/37)) ([d8619d3](https://github.com/divmora/otel-aws-log-processor/commit/d8619d35f6e495e7eb62ea2eee92a826f8fe1f17))
* **test:** resolve errcheck and staticcheck lint issues in test files ([6e81b29](https://github.com/divmora/otel-aws-log-processor/commit/6e81b29d7b33081853ca897d94216fc8e60facd3))

## [0.2.0](https://github.com/divmora/otel-aws-log-processor/compare/v0.1.0...v0.2.0) (2026-09-02)


### Features

* initial commit for otel-aws-log-processor ([16f54f1](https://github.com/divmora/otel-aws-log-processor/commit/16f54f120dca578605be46d5c6dc87ad2f8c55f0))
