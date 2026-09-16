package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/divmora/otel-aws-log-processor/pkg/license"
)

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
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate keys: %v", err)
		}
		license.SetVerificationPublicKey(pubKey)
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

		token, err := license.SignLicense(claims, privKey)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}

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
}
