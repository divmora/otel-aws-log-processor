package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/divmora/otel-aws-log-processor/pkg/license"
)

var (
	testHandlerSeed    = []byte("divmora-lambda-handler-test-0123")
	testHandlerPrivKey = ed25519.NewKeyFromSeed(testHandlerSeed)
	testHandlerPubKey  = testHandlerPrivKey.Public().(ed25519.PublicKey)
)

func signTestHandlerToken(claims *license.Claims, privKey ed25519.PrivateKey) string {
	payloadJSON, _ := json.Marshal(claims)
	pB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signedData := []byte(fmt.Sprintf("%s.%s", "DIV1", pB64))
	sig := ed25519.Sign(privKey, signedData)
	sB64 := base64.RawURLEncoding.EncodeToString(sig)
	return fmt.Sprintf("DIV1.%s.%s", pB64, sB64)
}

func TestHandlerLicensingModes(t *testing.T) {
	ctx := context.Background()

	// 1. Test Non-Production Exemption
	t.Run("NonProductionExemption", func(t *testing.T) {
		t.Setenv("ENVIRONMENT", "staging")

		sqsEvent := events.SQSEvent{
			Records: []events.SQSMessage{},
		}

		resp, err := handler(ctx, sqsEvent)
		if err != nil {
			t.Fatalf("unexpected error in staging: %v", err)
		}
		if len(resp.BatchItemFailures) != 0 {
			t.Errorf("expected 0 failures, got %d", len(resp.BatchItemFailures))
		}
	})

	// 2. Test Production Strict Mode without License (Default Discard Action - Suppresses SQS Retry Loop)
	t.Run("ProductionStrictWithoutLicense_DiscardRetrySuppression", func(t *testing.T) {
		t.Setenv("ENVIRONMENT", "production")
		t.Setenv("DIVMORA_LICENSE_MODE", "strict")
		t.Setenv("DIVMORA_LICENSE_KEY", "")
		t.Setenv("DIVMORA_LICENSE_FAILURE_ACTION", "discard")

		sqsEvent := events.SQSEvent{
			Records: []events.SQSMessage{
				{MessageId: "msg-1"},
				{MessageId: "msg-2"},
			},
		}

		resp, err := handler(ctx, sqsEvent)
		if err != nil {
			t.Fatalf("expected nil error to suppress SQS retry loop, got: %v", err)
		}
		if len(resp.BatchItemFailures) != 0 {
			t.Errorf("expected 0 batch item failures (discard mode deletes messages to prevent retry loop), got %d", len(resp.BatchItemFailures))
		}
	})

	// 2b. Test Production Strict Mode without License with DLQ Action
	t.Run("ProductionStrictWithoutLicense_DLQAction", func(t *testing.T) {
		t.Setenv("ENVIRONMENT", "production")
		t.Setenv("DIVMORA_LICENSE_MODE", "strict")
		t.Setenv("DIVMORA_LICENSE_KEY", "")
		t.Setenv("DIVMORA_LICENSE_FAILURE_ACTION", "dlq")

		sqsEvent := events.SQSEvent{
			Records: []events.SQSMessage{
				{MessageId: "msg-1"},
				{MessageId: "msg-2"},
			},
		}

		resp, err := handler(ctx, sqsEvent)
		if err != nil {
			t.Fatalf("expected nil error (container does not crash), got: %v", err)
		}
		if len(resp.BatchItemFailures) != 2 {
			t.Errorf("expected 2 batch item failures for DLQ routing, got %d", len(resp.BatchItemFailures))
		}
	})

	// 3. Test Production Warn Mode without License
	t.Run("ProductionWarnWithoutLicense", func(t *testing.T) {
		t.Setenv("ENVIRONMENT", "production")
		t.Setenv("DIVMORA_LICENSE_MODE", "warn")
		t.Setenv("DIVMORA_LICENSE_KEY", "")

		sqsEvent := events.SQSEvent{
			Records: []events.SQSMessage{},
		}

		resp, err := handler(ctx, sqsEvent)
		if err != nil {
			t.Fatalf("unexpected error in warn mode: %v", err)
		}
		if len(resp.BatchItemFailures) != 0 {
			t.Errorf("expected 0 failures in warn mode, got %d", len(resp.BatchItemFailures))
		}
	})

	// 4. Test Production with Valid Commercial License
	t.Run("ProductionWithValidLicense", func(t *testing.T) {
		license.SetVerificationPublicKey(testHandlerPubKey)
		defer license.ResetVerificationPublicKey()

		claims := &license.Claims{
			ID: "lic_handler_test",
			Customer: license.Customer{
				Name: "Enterprise Customer",
			},
			Product: "otel-aws-log-processor",
			Plan:    license.TierEnterprise,
			Scope: &license.Scope{
				Accounts: []string{"*"},
			},
			IssuedAt:  time.Now().UTC(),
			ExpiresAt: time.Now().UTC().AddDate(1, 0, 0),
		}

		token := signTestHandlerToken(claims, testHandlerPrivKey)

		t.Setenv("ENVIRONMENT", "production")
		t.Setenv("DIVMORA_LICENSE_MODE", "strict")
		t.Setenv("DIVMORA_LICENSE_KEY", token)

		sqsEvent := events.SQSEvent{
			Records: []events.SQSMessage{},
		}

		resp, err := handler(ctx, sqsEvent)
		if err != nil {
			t.Fatalf("unexpected error with valid license: %v", err)
		}
		if len(resp.BatchItemFailures) != 0 {
			t.Errorf("expected 0 failures, got %d", len(resp.BatchItemFailures))
		}
	})

	// 5. Test Production Pro Plan Feature Verification
	t.Run("ProductionProPlanFeatureVerification", func(t *testing.T) {
		license.SetVerificationPublicKey(testHandlerPubKey)
		defer license.ResetVerificationPublicKey()

		proClaims := &license.Claims{
			ID: "lic_handler_pro_test",
			Customer: license.Customer{
				Name: "Pro Customer",
			},
			Product: "otel-aws-log-processor",
			Plan:    license.TierPro,
			Scope: &license.Scope{
				Accounts: []string{"123456789012"},
			},
			IssuedAt:  time.Now().UTC(),
			ExpiresAt: time.Now().UTC().AddDate(1, 0, 0),
		}
		token := signTestHandlerToken(proClaims, testHandlerPrivKey)

		// Pro plan with allowed standard features in strict mode
		optsAllowed := license.EnforcementOptions{
			Environment:       "production",
			EnforcementMode:   "strict",
			LicenseKey:        token,
			CallerAccountID:   "123456789012",
			ExercisedFeatures: []string{license.FeatureParserALB, license.FeatureParserWAF},
			PublicKey:         testHandlerPubKey,
		}
		status, err := license.Enforce(optsAllowed)
		if err != nil || !status.Valid {
			t.Fatalf("expected Pro plan with standard features to be valid: %v", err)
		}

		// Pro plan with unentitled Enterprise feature in strict mode
		optsUnentitled := license.EnforcementOptions{
			Environment:       "production",
			EnforcementMode:   "strict",
			LicenseKey:        token,
			CallerAccountID:   "123456789012",
			ExercisedFeatures: []string{license.FeatureParserCloudFrontParquet},
			PublicKey:         testHandlerPubKey,
		}
		statusUnentitled, err := license.Enforce(optsUnentitled)
		if err == nil {
			t.Fatal("expected error for Pro plan exercising Enterprise Parquet feature in strict mode")
		}
		if statusUnentitled.Valid {
			t.Error("expected status.Valid to be false")
		}
		if statusUnentitled.StatusReason != "feature_not_entitled" {
			t.Errorf("got status reason %s, want feature_not_entitled", statusUnentitled.StatusReason)
		}
	})

	// 6. Test Production Resource Quota Verification
	t.Run("ProductionResourceQuotaVerification", func(t *testing.T) {
		license.SetVerificationPublicKey(testHandlerPubKey)
		defer license.ResetVerificationPublicKey()

		quotaClaims := &license.Claims{
			ID: "lic_handler_quota_test",
			Customer: license.Customer{
				Name: "Resource Pack Customer",
			},
			Product: "otel-aws-log-processor",
			Plan:    license.TierPro,
			Scope: &license.Scope{
				Accounts:     []string{"123456789012"},
				MaxResources: 2,
				AllowedResources: []string{
					"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/*",
				},
			},
			IssuedAt:  time.Now().UTC(),
			ExpiresAt: time.Now().UTC().AddDate(1, 0, 0),
		}
		token := signTestHandlerToken(quotaClaims, testHandlerPrivKey)

		// 1. Within quota (2 resources)
		tracker := license.NewResourceTracker()
		optsWithin := license.EnforcementOptions{
			Environment:     "production",
			EnforcementMode: "strict",
			LicenseKey:      token,
			CallerAccountID: "123456789012",
			SourceResourceARNs: []string{
				"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-1/hash",
				"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-2/hash",
			},
			ResourceTracker: tracker,
			PublicKey:       testHandlerPubKey,
		}
		statusWithin, err := license.Enforce(optsWithin)
		if err != nil || !statusWithin.Valid {
			t.Fatalf("expected within quota to succeed: %v", err)
		}
		if tracker.Count() != 2 {
			t.Errorf("expected 2 active resources, got %d", tracker.Count())
		}

		// 2. Quota breach (3rd resource)
		optsBreach := license.EnforcementOptions{
			Environment:     "production",
			EnforcementMode: "strict",
			LicenseKey:      token,
			CallerAccountID: "123456789012",
			SourceResourceARNs: []string{
				"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-3/hash",
			},
			ResourceTracker: tracker,
			PublicKey:       testHandlerPubKey,
		}
		statusBreach, errBreach := license.Enforce(optsBreach)
		if errBreach == nil {
			t.Fatal("expected quota breach error")
		}
		if !license.IsDeterministicLicenseError(errBreach) {
			t.Errorf("expected deterministic error on quota breach, got: %v", errBreach)
		}
		if statusBreach.Valid || statusBreach.StatusReason != "resource_quota_exceeded" {
			t.Errorf("expected status reason resource_quota_exceeded, got: %s", statusBreach.StatusReason)
		}
	})

	// 7. Test Production Throughput Fair-Use Soft Enforcement (Non-Blocking Invariant)
	t.Run("ProductionThroughputOverage_SoftEnforcementNeverHalts", func(t *testing.T) {
		license.SetVerificationPublicKey(testHandlerPubKey)
		defer license.ResetVerificationPublicKey()

		throughputClaims := &license.Claims{
			ID: "lic_handler_throughput_test",
			Customer: license.Customer{
				Name: "Hyper Scale AdTech Corp",
			},
			Product: "otel-aws-log-processor",
			Plan:    license.TierPro,
			Limits: &license.Limits{
				MaxMonthlyTB: 10,
			},
			Scope: &license.Scope{
				Accounts:     []string{"123456789012"},
				MaxResources: 5,
			},
			IssuedAt:  time.Now().UTC(),
			ExpiresAt: time.Now().UTC().AddDate(1, 0, 0),
		}
		token := signTestHandlerToken(throughputClaims, testHandlerPrivKey)

		t.Setenv("ENVIRONMENT", "production")
		t.Setenv("DIVMORA_LICENSE_MODE", "strict")
		t.Setenv("DIVMORA_LICENSE_KEY", token)
		t.Setenv("DIVMORA_LICENSE_FAILURE_ACTION", "discard")
		t.Setenv("DIVMORA_THROUGHPUT_EXCEEDED", "true")

		// Create SQS messages representing log batches
		sqsEvent := events.SQSEvent{
			Records: []events.SQSMessage{
				{MessageId: "msg-throughput-1", Body: `{"Records":[]}`},
				{MessageId: "msg-throughput-2", Body: `{"Records":[]}`},
			},
		}

		resp, err := handler(ctx, sqsEvent)
		if err != nil {
			t.Fatalf("throughput overage must NEVER halt execution or return error: %v", err)
		}
		if len(resp.BatchItemFailures) != 0 {
			t.Fatalf("expected 0 batch item failures (zero log records must be dropped or dead-lettered on volume overage), got %d", len(resp.BatchItemFailures))
		}

		// Also verify via Enforce directly
		quotaTracker := license.NewQuotaTracker()
		quotaTracker.RecordBytes(100 * 1024 * 1024) // 100 MB
		quotaTracker.SetThroughputExceeded(true)

		status, err := license.Enforce(license.EnforcementOptions{
			Environment:     "production",
			EnforcementMode: "strict",
			LicenseKey:      token,
			CallerAccountID: "123456789012",
			QuotaTracker:    quotaTracker,
			PublicKey:       testHandlerPubKey,
		})
		if err != nil {
			t.Fatalf("expected Enforce to succeed without error on throughput overage, got: %v", err)
		}
		if !status.Valid {
			t.Fatal("expected status.Valid to be true: log processing must continue at 100% full line rate")
		}
		if !status.ThroughputExceeded {
			t.Fatal("expected status.ThroughputExceeded to be true")
		}
		if quotaTracker.TotalBytesProcessed() != 100*1024*1024 {
			t.Errorf("got TotalBytesProcessed %d, want %d", quotaTracker.TotalBytesProcessed(), 100*1024*1024)
		}
	})
}
