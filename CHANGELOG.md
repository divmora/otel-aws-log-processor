# Changelog

## [0.3.0](https://github.com/divmora/otel-aws-log-processor/compare/v0.2.0...v0.3.0) (2026-09-17)


### Features

* **events:** support direct S3 notifications and SNS wrappers alongside EventBridge ([56a3934](https://github.com/divmora/otel-aws-log-processor/commit/56a393438dcc266f8105c6e6a3e7e6b710ec8531))
* implement BSL 1.1 commercial licensing and Ed25519 binary release signing ([55aa3b8](https://github.com/divmora/otel-aws-log-processor/commit/55aa3b849f29b1a747e60854cafbcb1a695828ef))
* **license:** adopt license-go v0.6.0 with release attestation and declarative BSL policy ([b11021e](https://github.com/divmora/otel-aws-log-processor/commit/b11021ed41707734e12c6f688360f4065b0efaeb))
* **license:** remove legacy 2-part release tokens and adopt full license-go v0.6.0 capabilities ([738d338](https://github.com/divmora/otel-aws-log-processor/commit/738d33852453661ca06954f5695f75baf436289a))
* **license:** upgrade license-go to v0.7.0 and enhance Docker release attestation ([6dd9c34](https://github.com/divmora/otel-aws-log-processor/commit/6dd9c34869962ad8953899611cdeedc35af9eeec))
* **license:** upgrade to license-go v1.0.0 and standardize Lambda runtime verification without regressions ([#17](https://github.com/divmora/otel-aws-log-processor/issues/17)) ([b13b2ff](https://github.com/divmora/otel-aws-log-processor/commit/b13b2ffd8e0dfb8c02bbe5c663775caaf15a91fb))


### Bug Fixes

* **docker:** copy bootstrap to LAMBDA_TASK_ROOT and ensure execution permissions ([87172ae](https://github.com/divmora/otel-aws-log-processor/commit/87172ae740582e6797d0273e946fa19769747dca))
* **events:** automatically url-unescape direct s3 notification object keys ([f88baa3](https://github.com/divmora/otel-aws-log-processor/commit/f88baa3c9a7dbb1a4c6f03ca61041c2505d892c1))
* **test:** resolve errcheck and staticcheck lint issues in test files ([6e81b29](https://github.com/divmora/otel-aws-log-processor/commit/6e81b29d7b33081853ca897d94216fc8e60facd3))

## [0.2.0](https://github.com/divmora/otel-aws-log-processor/compare/v0.1.0...v0.2.0) (2026-09-02)


### Features

* initial commit for otel-aws-log-processor ([16f54f1](https://github.com/divmora/otel-aws-log-processor/commit/16f54f120dca578605be46d5c6dc87ad2f8c55f0))
