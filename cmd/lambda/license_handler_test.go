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

	// 2. Test Production Strict Mode without License
	t.Run("ProductionStrictWithoutLicense", func(t *testing.T) {
		t.Setenv("ENVIRONMENT", "production")
		t.Setenv("DIVMORA_LICENSE_MODE", "strict")
		t.Setenv("DIVMORA_LICENSE_KEY", "")

		sqsEvent := events.SQSEvent{
			Records: []events.SQSMessage{},
		}

		_, err := handler(ctx, sqsEvent)
		if err == nil {
			t.Error("expected error for unlicensed production in strict mode")
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
}
