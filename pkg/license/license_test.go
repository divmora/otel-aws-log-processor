package license

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	liblicense "github.com/divmora/license-go/pkg/license"
	"github.com/divmora/otel-aws-log-processor/pkg/model"
)

// Static deterministic test key pair to eliminate dynamic key generation loops.
var (
	testSeed    = []byte("divmora-license-test-seed-012345")
	testPrivKey = ed25519.NewKeyFromSeed(testSeed)
	testPubKey  = testPrivKey.Public().(ed25519.PublicKey)
)

func signTestToken(claims *Claims, privKey ed25519.PrivateKey) string {
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	pB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signedData := []byte(fmt.Sprintf("%s.%s", liblicense.VersionPrefix, pB64))
	sig := ed25519.Sign(privKey, signedData)
	return liblicense.EncodeToken(payloadJSON, sig)
}

func signTestTokenArmored(claims *Claims, privKey ed25519.PrivateKey) string {
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	pB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signedData := []byte(fmt.Sprintf("%s.%s", liblicense.VersionPrefix, pB64))
	sig := ed25519.Sign(privKey, signedData)
	return liblicense.EncodeArmored(payloadJSON, sig)
}

func TestSignAndVerifyToken(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	claims := &Claims{
		ID: "lic_test_123",
		Customer: Customer{
			Name:  "Acme Corp",
			Email: "admin@acme.com",
			OrgID: "org_123",
		},
		Product: "otel-aws-log-processor",
		Plan:    TierEnterprise,
		Scope: &Scope{
			Accounts: []string{"123456789012", "987654321098"},
		},
		Features:        []string{"*"},
		IssuedAt:        now,
		ExpiresAt:       now.AddDate(1, 0, 0),
		GracePeriodDays: 14,
	}

	// 1. Compact token format
	token := signTestToken(claims, testPrivKey)
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	if !strings.HasPrefix(token, "DIV1.") {
		t.Errorf("expected token to start with DIV1., got %s", token)
	}

	// Verify active
	status, err := ParseAndVerifyAt(token, testPubKey, now.AddDate(0, 1, 0))
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}
	if !status.Valid {
		t.Error("expected status to be valid")
	}
	if status.InGracePeriod {
		t.Error("expected not in grace period")
	}
	if status.Claims.Customer.Name != "Acme Corp" {
		t.Errorf("got customer %s, want Acme Corp", status.Claims.Customer.Name)
	}
	if status.Claims.Plan != TierEnterprise {
		t.Errorf("got plan %s, want %s", status.Claims.Plan, TierEnterprise)
	}

	// 2. Armored text format
	armored := signTestTokenArmored(claims, testPrivKey)
	if !strings.Contains(armored, "-----BEGIN DIVMORA LICENSE KEY-----") {
		t.Errorf("expected armored header, got: %s", armored)
	}
	armoredStatus, err := ParseAndVerifyAt(armored, testPubKey, now.AddDate(0, 1, 0))
	if err != nil {
		t.Fatalf("unexpected armored verification error: %v", err)
	}
	if !armoredStatus.Valid || armoredStatus.Claims.ID != "lic_test_123" {
		t.Errorf("armored verification failed: %+v", armoredStatus)
	}

	// Verify Grace Period
	expiredTime := now.AddDate(1, 0, 5) // 5 days past expiry, within 14d grace
	graceStatus, err := ParseAndVerifyAt(token, testPubKey, expiredTime)
	if err != nil {
		t.Fatalf("unexpected error during grace period: %v", err)
	}
	if !graceStatus.Valid || !graceStatus.InGracePeriod {
		t.Error("expected valid within grace period")
	}
	if graceStatus.StatusReason != "grace_period" {
		t.Errorf("got status reason %s, want grace_period", graceStatus.StatusReason)
	}

	// Verify Hard Expired (past 14 days)
	hardExpiredTime := now.AddDate(1, 0, 20)
	hardStatus, err := ParseAndVerifyAt(token, testPubKey, hardExpiredTime)
	if err == nil {
		t.Error("expected error for hard expired license")
	}
	if hardStatus.Valid {
		t.Error("expected invalid for hard expired license")
	}
	if hardStatus.StatusReason != "expired" {
		t.Errorf("got status reason %s, want expired", hardStatus.StatusReason)
	}
}

func TestProductMismatch(t *testing.T) {
	now := time.Now().UTC()

	claims := &Claims{
		ID:        "lic_wrong_prod",
		Customer:  Customer{Name: "Acme Corp"},
		Product:   "other-product",
		Plan:      TierEnterprise,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
	}

	token := signTestToken(claims, testPrivKey)
	_, err := ParseAndVerifyAt(token, testPubKey, now)
	if err == nil {
		t.Error("expected error for mismatched product")
	}
}

func TestTamperedToken(t *testing.T) {
	now := time.Now().UTC()

	claims := &Claims{
		ID:        "lic_tamper",
		Customer:  Customer{Name: "Evil Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierPro,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(0, 1, 0),
	}

	token := signTestToken(claims, testPrivKey)

	// Tamper with payload
	tamperedToken := token[:len(token)-5] + "AAAAA"
	_, err := ParseAndVerifyAt(tamperedToken, testPubKey, now)
	if err == nil {
		t.Error("expected error for tampered token")
	}
}

func TestEnforceNonProduction(t *testing.T) {
	quotaTracker := NewQuotaTracker()

	opts := EnforcementOptions{
		Environment:      "staging",
		BatchRecordCount: 500,
		QuotaTracker:     quotaTracker,
	}

	status, err := Enforce(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Valid {
		t.Error("expected non-production to be valid")
	}
	if status.StatusReason != "non_prod_free" {
		t.Errorf("got status reason %s, want non_prod_free", status.StatusReason)
	}

	// Test Single-Batch Density Ceiling
	denseOpts := EnforcementOptions{
		Environment:      "development",
		BatchRecordCount: 15_000, // exceeds 10,000 ceiling
		QuotaTracker:     quotaTracker,
	}
	denseStatus, err := Enforce(denseOpts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denseStatus.QuotaExceeded {
		t.Error("expected QuotaExceeded for dense batch")
	}
	if denseStatus.StatusReason != "quota_exceeded" {
		t.Errorf("got status %s, want quota_exceeded", denseStatus.StatusReason)
	}

	// Test Container Cumulative Quota
	quotaTracker2 := &QuotaTracker{
		maxBatchRecords:     10_000,
		maxContainerRecords: 1_000,
	}
	quotaTracker2.RecordAndCheckContainerQuota(1_500) // exceed 1,000 limit

	contOpts := EnforcementOptions{
		Environment:      "test",
		BatchRecordCount: 100,
		QuotaTracker:     quotaTracker2,
	}
	contStatus, err := Enforce(contOpts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !contStatus.QuotaExceeded {
		t.Error("expected QuotaExceeded for container ceiling")
	}
}

func TestEnforceProductionWithoutLicense(t *testing.T) {
	// 1. Warn mode (default)
	warnOpts := EnforcementOptions{
		Environment:     "production",
		EnforcementMode: "warn",
		CallerAccountID: "123456789012",
	}

	warnStatus, err := Enforce(warnOpts)
	if err != nil {
		t.Fatalf("unexpected error in warn mode: %v", err)
	}
	if warnStatus.Valid {
		t.Error("expected valid=false for unlicensed production")
	}
	if warnStatus.StatusReason != "unlicensed_production" {
		t.Errorf("got %s, want unlicensed_production", warnStatus.StatusReason)
	}

	// 2. Strict mode
	strictOpts := EnforcementOptions{
		Environment:     "production",
		EnforcementMode: "strict",
		CallerAccountID: "123456789012",
	}

	_, err = Enforce(strictOpts)
	if err == nil {
		t.Error("expected error for unlicensed production in strict mode")
	}
}

func TestEnforceProductionWithLicenseAndAccountScoping(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)

	claims := &Claims{
		ID:       "lic_account_test",
		Customer: Customer{Name: "Target Corp"},
		Product:  "otel-aws-log-processor",
		Plan:     TierEnterprise,
		Scope: &Scope{
			Accounts: []string{"111122223333"},
		},
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
	}

	token := signTestToken(claims, testPrivKey)

	// 1. Matching Caller Account
	matchOpts := EnforcementOptions{
		Environment:     "production",
		LicenseKey:      token,
		CallerAccountID: "111122223333",
		PublicKey:       testPubKey,
		EvaluationTime:  now,
	}
	matchStatus, err := Enforce(matchOpts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matchStatus.Valid {
		t.Error("expected valid status for matching account")
	}

	// 2. Mismatched Caller Account
	mismatchOpts := EnforcementOptions{
		Environment:     "production",
		LicenseKey:      token,
		EnforcementMode: "strict",
		CallerAccountID: "999999999999", // not in allowed
		PublicKey:       testPubKey,
		EvaluationTime:  now,
	}
	_, err = Enforce(mismatchOpts)
	if err == nil {
		t.Error("expected error for mismatched account in strict mode")
	}

	// 3. Mismatched Source Log Account
	srcMismatchOpts := EnforcementOptions{
		Environment:      "production",
		LicenseKey:       token,
		EnforcementMode:  "strict",
		CallerAccountID:  "111122223333",
		SourceAccountIDs: []string{"999999999999"}, // source log from unauthorized account
		PublicKey:        testPubKey,
		EvaluationTime:   now,
	}
	_, err = Enforce(srcMismatchOpts)
	if err == nil {
		t.Error("expected error for mismatched source account in strict mode")
	}
}

func TestClockSkewDefense(t *testing.T) {
	authTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	claims := &Claims{
		ID:        "lic_clock",
		Customer:  Customer{Name: "Time Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierEnterprise,
		IssuedAt:  authTime,
		ExpiresAt: authTime.AddDate(0, 1, 0), // expires in 1 month
	}

	token := signTestToken(claims, testPrivKey)

	// Container clock claiming to be 2 months later (expired),
	// but authoritative AWS time says it is still active (12:00:00 on Sept 15)
	forgedLocalClock := authTime.AddDate(0, 2, 0)

	opts := EnforcementOptions{
		Environment:       "production",
		LicenseKey:        token,
		PublicKey:         testPubKey,
		EvaluationTime:    forgedLocalClock,
		AuthoritativeTime: authTime, // S3 HTTP Date
	}

	status, err := Enforce(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Valid {
		t.Error("expected status to be valid because evaluation anchored to authoritative AWS time")
	}
}

func TestAccountIDExtraction(t *testing.T) {
	albARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-targets/73e2d6bc24d8a067"
	account := ExtractAccountIDFromARN(albARN)
	if account != "123456789012" {
		t.Errorf("got account %s, want 123456789012", account)
	}

	invalidARN := "not-an-arn"
	if ExtractAccountIDFromARN(invalidARN) != "" {
		t.Error("expected empty string for invalid ARN")
	}
}

func TestAppendLicenseAttributes(t *testing.T) {
	var attrs []model.OTelAttribute

	status := &ValidationStatus{
		StatusReason: "valid",
		Claims: &Claims{
			ID:   "lic_100",
			Plan: TierEnterprise,
		},
	}

	updated := AppendLicenseAttributes(attrs, status, "production", "123456789012")
	if len(updated) < 4 {
		t.Errorf("expected at least 4 attributes, got %d", len(updated))
	}

	foundStatus := false
	foundTier := false
	for _, attr := range updated {
		if attr.Key == "divmora.license.status" && *attr.Value.StringValue == "valid" {
			foundStatus = true
		}
		if attr.Key == "divmora.license.tier" && *attr.Value.StringValue == "enterprise" {
			foundTier = true
		}
	}
	if !foundStatus || !foundTier {
		t.Error("expected to find divmora.license.status and divmora.license.tier attributes")
	}
}

func TestNodeLockedLicense_AutoFingerprint(t *testing.T) {
	now := time.Now().UTC()

	fp, err := liblicense.ResolveDefaultFingerprint()
	if err != nil {
		t.Skipf("skipping machine fingerprint test: %v", err)
	}

	// 1. License with matching primary fingerprint
	claims := &Claims{
		ID:          "lic_nodelock_123",
		Customer:    Customer{Name: "NodeLock Corp"},
		Product:     "otel-aws-log-processor",
		Plan:        TierEnterprise,
		Fingerprint: fp.Primary,
		Features:    []string{"*"},
		IssuedAt:    now,
		ExpiresAt:   now.AddDate(1, 0, 0),
	}

	token := signTestToken(claims, testPrivKey)

	status, err := ParseAndVerifyAt(token, testPubKey, now)
	if err != nil {
		t.Fatalf("expected node-locked license to verify successfully: %v", err)
	}
	if !status.Valid {
		t.Errorf("expected status to be valid for matching node fingerprint")
	}

	// 2. License with mismatched fingerprint should fail
	mismatchedClaims := &Claims{
		ID:          "lic_mismatch_123",
		Customer:    Customer{Name: "Mismatch Corp"},
		Product:     "otel-aws-log-processor",
		Plan:        TierEnterprise,
		Fingerprint: "fp:host:0000000000000000",
		Features:    []string{"*"},
		IssuedAt:    now,
		ExpiresAt:   now.AddDate(1, 0, 0),
	}
	mismatchedToken := signTestToken(mismatchedClaims, testPrivKey)
	_, err = ParseAndVerifyAt(mismatchedToken, testPubKey, now)
	if err == nil {
		t.Fatal("expected error verifying license with mismatched node fingerprint, got nil")
	}
}

func TestValidatorSingleton(t *testing.T) {
	v1, err := GetDefaultValidator()
	if err != nil {
		t.Fatalf("unexpected error getting default validator: %v", err)
	}
	if v1 == nil {
		t.Fatal("expected non-nil default validator")
	}

	v2, err := GetDefaultValidator()
	if err != nil {
		t.Fatalf("unexpected error getting default validator second time: %v", err)
	}
	if v1 != v2 {
		t.Error("expected GetDefaultValidator to return singleton instance")
	}

	ResetDefaultValidator()
	v3, err := GetDefaultValidator()
	if err != nil {
		t.Fatalf("unexpected error getting default validator after reset: %v", err)
	}
	if v3 == nil {
		t.Fatal("expected non-nil default validator after reset")
	}
}

func TestPolicyDegradedFallbackClaims(t *testing.T) {
	claims := DefaultFallbackClaims()
	if claims == nil {
		t.Fatal("expected non-nil default fallback claims")
	}
	if claims.Product != "otel-aws-log-processor" {
		t.Errorf("expected product otel-aws-log-processor, got %s", claims.Product)
	}
	if claims.Plan != "community" {
		t.Errorf("expected plan community, got %s", claims.Plan)
	}

	cfg := NewDefaultManagerConfig(nil)
	if cfg.Policy != liblicense.PolicyDegraded {
		t.Errorf("expected PolicyDegraded, got %v", cfg.Policy)
	}
	if cfg.FallbackClaims == nil {
		t.Fatal("expected non-nil FallbackClaims in ManagerConfig")
	}
	if !cfg.AllowDegradedMutations {
		t.Error("expected AllowDegradedMutations to be true")
	}
}

func TestOfflineCRL_VerificationAndRevocation(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)

	activeClaims := &Claims{
		ID:              "lic_active_001",
		Customer:        Customer{Name: "Active Corp"},
		Product:         "otel-aws-log-processor",
		Plan:            TierEnterprise,
		IssuedAt:        now,
		ExpiresAt:       now.AddDate(1, 0, 0),
		GracePeriodDays: 14,
	}
	activeToken := signTestToken(activeClaims, testPrivKey)

	revokedClaims := &Claims{
		ID:              "lic_revoked_001",
		Customer:        Customer{Name: "Revoked Corp"},
		Product:         "otel-aws-log-processor",
		Plan:            TierEnterprise,
		IssuedAt:        now,
		ExpiresAt:       now.AddDate(1, 0, 0),
		GracePeriodDays: 14,
	}
	revokedToken := signTestToken(revokedClaims, testPrivKey)

	// Mint CRL revoking lic_revoked_001
	crlClaims := RevocationListClaims{
		ID:       "crl_test_001",
		IssuedAt: now,
		Entries: []RevocationEntry{
			{
				ID:        "lic_revoked_001",
				RevokedAt: now,
				Reason:    "compromised_key",
			},
		},
	}
	crlToken, err := SignCRL(crlClaims, testPrivKey)
	if err != nil {
		t.Fatalf("failed to sign CRL: %v", err)
	}

	// 1. Before applying CRL, both tokens verify successfully
	statusActive, err := ParseAndVerifyAt(activeToken, testPubKey, now)
	if err != nil || !statusActive.Valid {
		t.Fatalf("expected active token to be valid: %v", err)
	}
	statusRevokedBefore, err := ParseAndVerifyAt(revokedToken, testPubKey, now)
	if err != nil || !statusRevokedBefore.Valid {
		t.Fatalf("expected revoked token to verify before CRL attached: %v", err)
	}

	// 2. Attach CRL via programmatic override
	SetVerificationCRL(crlToken)
	defer ResetVerificationCRL()

	// Active token still passes
	statusActiveAfter, err := ParseAndVerifyAt(activeToken, testPubKey, now)
	if err != nil || !statusActiveAfter.Valid {
		t.Fatalf("expected active token to still be valid after CRL attached: %v", err)
	}

	// Revoked token fails with ErrLicenseRevoked
	statusRevokedAfter, err := ParseAndVerifyAt(revokedToken, testPubKey, now)
	if err == nil {
		t.Fatal("expected error verifying revoked token with CRL active")
	}
	if !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("expected errors.Is(err, ErrLicenseRevoked), got: %v", err)
	}
	if statusRevokedAfter == nil {
		t.Fatal("expected non-nil ValidationStatus for revoked token")
	}
	if statusRevokedAfter.Valid {
		t.Error("expected status.Valid to be false for revoked license")
	}
	if statusRevokedAfter.StatusReason != "revoked" {
		t.Errorf("got status reason %s, want revoked", statusRevokedAfter.StatusReason)
	}
}

func TestOfflineCRL_ArmoredPEM(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)

	claims := &Claims{
		ID:        "lic_armored_crl_revoked",
		Customer:  Customer{Name: "Armored Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierEnterprise,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
	}
	token := signTestToken(claims, testPrivKey)

	crlClaims := RevocationListClaims{
		ID:       "crl_armored_001",
		IssuedAt: now,
		Entries: []RevocationEntry{
			{ID: "lic_armored_crl_revoked", RevokedAt: now, Reason: "payment_failed"},
		},
	}
	armoredCRL, err := SignCRLArmored(crlClaims, testPrivKey)
	if err != nil {
		t.Fatalf("failed to sign armored CRL: %v", err)
	}
	if !strings.Contains(armoredCRL, "-----BEGIN DIVMORA REVOCATION LIST-----") {
		t.Fatalf("expected armored PEM header, got: %s", armoredCRL)
	}

	// Test ParseAndVerifyWithCRL with armored PEM
	status, err := ParseAndVerifyWithCRL(token, testPubKey, now, armoredCRL)
	if err == nil {
		t.Fatal("expected error verifying license revoked by armored CRL")
	}
	if !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("expected ErrLicenseRevoked, got: %v", err)
	}
	if status.Valid {
		t.Error("expected status.Valid=false")
	}
	if status.StatusReason != "revoked" {
		t.Errorf("got status reason %s, want revoked", status.StatusReason)
	}
}

func TestOfflineCRL_LambdaTaskRootSimulation(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)

	claims := &Claims{
		ID:        "lic_lambda_crl_revoked",
		Customer:  Customer{Name: "Serverless Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierEnterprise,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
	}
	token := signTestToken(claims, testPrivKey)

	crlClaims := RevocationListClaims{
		ID:       "crl_lambda_001",
		IssuedAt: now,
		Entries: []RevocationEntry{
			{ID: "lic_lambda_crl_revoked", RevokedAt: now, Reason: "superseded"},
		},
	}
	crlToken, err := SignCRL(crlClaims, testPrivKey)
	if err != nil {
		t.Fatalf("failed to sign CRL: %v", err)
	}

	// Create simulated LAMBDA_TASK_ROOT directory with crl.divcrl
	tempTaskRoot := t.TempDir()
	crlPath := filepath.Join(tempTaskRoot, "crl.divcrl")
	if err := os.WriteFile(crlPath, []byte(crlToken), 0644); err != nil {
		t.Fatalf("failed to write CRL to task root: %v", err)
	}

	t.Setenv("LAMBDA_TASK_ROOT", tempTaskRoot)
	ResetDefaultValidator()
	defer ResetDefaultValidator()

	resolved, err := ResolveOfflineCRL()
	if err != nil {
		t.Fatalf("failed to resolve offline CRL from LAMBDA_TASK_ROOT: %v", err)
	}
	if resolved.FilePath != crlPath {
		t.Errorf("got resolved file %s, want %s", resolved.FilePath, crlPath)
	}

	// Verify that ParseAndVerifyAt detects the revocation via the discovered CRL
	status, err := ParseAndVerifyAt(token, testPubKey, now)
	if err == nil {
		t.Fatal("expected error verifying revoked license discovered in LAMBDA_TASK_ROOT")
	}
	if !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("expected ErrLicenseRevoked, got: %v", err)
	}
	if status.Valid {
		t.Error("expected valid=false")
	}
	if status.StatusReason != "revoked" {
		t.Errorf("got status reason %s, want revoked", status.StatusReason)
	}
}

func TestOfflineCRL_EnvVariables(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)

	claims := &Claims{
		ID:        "lic_env_crl_revoked",
		Customer:  Customer{Name: "Env Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierEnterprise,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
	}
	token := signTestToken(claims, testPrivKey)

	crlClaims := RevocationListClaims{
		ID:       "crl_env_001",
		IssuedAt: now,
		Entries: []RevocationEntry{
			{ID: "lic_env_crl_revoked", RevokedAt: now, Reason: "compliance_violation"},
		},
	}
	crlToken, err := SignCRL(crlClaims, testPrivKey)
	if err != nil {
		t.Fatalf("failed to sign CRL: %v", err)
	}

	// 1. Test DIVMORA_CRL inline token
	t.Setenv("DIVMORA_CRL", crlToken)
	ResetDefaultValidator()

	status, err := ParseAndVerifyAt(token, testPubKey, now)
	if err == nil || !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("expected ErrLicenseRevoked with DIVMORA_CRL env, got: %v", err)
	}
	if status.StatusReason != "revoked" {
		t.Errorf("got status reason %s, want revoked", status.StatusReason)
	}

	// 2. Test DIVMORA_CRL_FILE file path
	t.Setenv("DIVMORA_CRL", "")
	tempFile := filepath.Join(t.TempDir(), "revocations.divcrl")
	if err := os.WriteFile(tempFile, []byte(crlToken), 0644); err != nil {
		t.Fatalf("failed to write CRL file: %v", err)
	}
	t.Setenv("DIVMORA_CRL_FILE", tempFile)
	ResetDefaultValidator()

	statusFile, err := ParseAndVerifyAt(token, testPubKey, now)
	if err == nil || !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("expected ErrLicenseRevoked with DIVMORA_CRL_FILE env, got: %v", err)
	}
	if statusFile.StatusReason != "revoked" {
		t.Errorf("got status reason %s, want revoked", statusFile.StatusReason)
	}
}

func TestOfflineCRL_EnforceStrictAndWarn(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)

	claims := &Claims{
		ID:        "lic_enforce_crl_test",
		Customer:  Customer{Name: "Enforce Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierEnterprise,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
		Scope: &Scope{
			Accounts: []string{"123456789012"},
		},
	}
	token := signTestToken(claims, testPrivKey)

	crlClaims := RevocationListClaims{
		ID:       "crl_enforce_001",
		IssuedAt: now,
		Entries: []RevocationEntry{
			{ID: "lic_enforce_crl_test", RevokedAt: now, Reason: "breach_of_contract"},
		},
	}
	crlToken, err := SignCRL(crlClaims, testPrivKey)
	if err != nil {
		t.Fatalf("failed to sign CRL: %v", err)
	}

	// 1. Warn mode with explicit CRL in EnforcementOptions
	warnOpts := EnforcementOptions{
		Environment:     "production",
		LicenseKey:      token,
		CRL:             crlToken,
		EnforcementMode: "warn",
		CallerAccountID: "123456789012",
		PublicKey:       testPubKey,
		EvaluationTime:  now,
	}
	warnStatus, err := Enforce(warnOpts)
	if err != nil {
		t.Fatalf("unexpected error in warn mode: %v", err)
	}
	if warnStatus.Valid {
		t.Error("expected valid=false for revoked license in warn mode")
	}
	if warnStatus.StatusReason != "revoked" {
		t.Errorf("got status reason %s, want revoked", warnStatus.StatusReason)
	}

	// 2. Strict mode with explicit CRL in EnforcementOptions
	strictOpts := EnforcementOptions{
		Environment:     "production",
		LicenseKey:      token,
		CRL:             crlToken,
		EnforcementMode: "strict",
		CallerAccountID: "123456789012",
		PublicKey:       testPubKey,
		EvaluationTime:  now,
	}
	_, err = Enforce(strictOpts)
	if err == nil {
		t.Fatal("expected error for revoked license in strict mode")
	}
	if !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("expected ErrLicenseRevoked in strict mode, got: %v", err)
	}
}

func TestOnlineCRL_SyncFromHTTP(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)

	claims := &Claims{
		ID:        "lic_online_revoked_1",
		Customer:  Customer{Name: "Online Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierEnterprise,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
	}
	token := signTestToken(claims, testPrivKey)

	crlClaims := RevocationListClaims{
		ID:       "crl_online_001",
		IssuedAt: now,
		Entries: []RevocationEntry{
			{ID: "lic_online_revoked_1", RevokedAt: now, Reason: "payment_fraud"},
		},
	}
	crlToken, err := SignCRL(crlClaims, testPrivKey)
	if err != nil {
		t.Fatalf("failed to sign CRL: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"etag-crl-test"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(crlToken))
	}))
	defer ts.Close()

	cacheFile := filepath.Join(t.TempDir(), "test-crl.cache")

	status, err := ParseAndVerifyWithCRLURL(token, testPubKey, now, ts.URL, cacheFile)
	if err == nil {
		t.Fatal("expected error verifying license revoked via online CRL")
	}
	if !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("expected ErrLicenseRevoked, got: %v", err)
	}
	if status.Valid {
		t.Error("expected valid=false")
	}
	if status.StatusReason != "revoked" {
		t.Errorf("got status reason %s, want revoked", status.StatusReason)
	}

	// Verify disk cache was populated
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		t.Errorf("expected cache file %s to be created", cacheFile)
	}
}

func TestOnlineCRL_EnvVariable(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)

	claims := &Claims{
		ID:        "lic_online_env_revoked",
		Customer:  Customer{Name: "Env Online Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierEnterprise,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
	}
	token := signTestToken(claims, testPrivKey)

	crlClaims := RevocationListClaims{
		ID:       "crl_online_env_001",
		IssuedAt: now,
		Entries: []RevocationEntry{
			{ID: "lic_online_env_revoked", RevokedAt: now, Reason: "compromised_token"},
		},
	}
	crlToken, err := SignCRL(crlClaims, testPrivKey)
	if err != nil {
		t.Fatalf("failed to sign CRL: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(crlToken))
	}))
	defer ts.Close()

	t.Setenv("DIVMORA_CRL_URL", ts.URL)
	t.Setenv("DIVMORA_CRL_CACHE_FILE", filepath.Join(t.TempDir(), "env-crl.cache"))
	ResetDefaultValidator()
	defer ResetDefaultValidator()

	status, err := ParseAndVerifyAt(token, testPubKey, now)
	if err == nil || !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("expected ErrLicenseRevoked via DIVMORA_CRL_URL, got: %v", err)
	}
	if status.StatusReason != "revoked" {
		t.Errorf("got status reason %s, want revoked", status.StatusReason)
	}
}

func TestOnlineCRL_EnforceStrict(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)

	claims := &Claims{
		ID:        "lic_enforce_online_test",
		Customer:  Customer{Name: "Enforce Online Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierEnterprise,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
		Scope: &Scope{
			Accounts: []string{"123456789012"},
		},
	}
	token := signTestToken(claims, testPrivKey)

	crlClaims := RevocationListClaims{
		ID:       "crl_enforce_online_001",
		IssuedAt: now,
		Entries: []RevocationEntry{
			{ID: "lic_enforce_online_test", RevokedAt: now, Reason: "chargeback"},
		},
	}
	crlToken, err := SignCRL(crlClaims, testPrivKey)
	if err != nil {
		t.Fatalf("failed to sign CRL: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(crlToken))
	}))
	defer ts.Close()

	strictOpts := EnforcementOptions{
		Environment:     "production",
		LicenseKey:      token,
		CRLURL:          ts.URL,
		EnforcementMode: "strict",
		CallerAccountID: "123456789012",
		PublicKey:       testPubKey,
		EvaluationTime:  now,
	}
	_, err = Enforce(strictOpts)
	if err == nil {
		t.Fatal("expected error for revoked license with online CRL in strict mode")
	}
	if !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("expected ErrLicenseRevoked in strict mode, got: %v", err)
	}
}

func TestFeatureEntitlements_AssertFeature(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)

	// 1. Non-production environment permits all features free of charge
	devStatus := &ValidationStatus{Valid: true, StatusReason: "non_prod_free"}
	if err := AssertFeature(devStatus, "dev", FeatureParserCloudFrontParquet); err != nil {
		t.Fatalf("expected non-prod to permit parquet, got: %v", err)
	}
	if !HasFeature(devStatus, "dev", FeatureScopeCrossAccount) {
		t.Fatal("expected HasFeature to return true in dev")
	}

	// 2. Unlicensed in production returns ErrCommercialLicenseRequired
	unlicensedStatus := &ValidationStatus{Valid: false, StatusReason: "unlicensed_production"}
	if err := AssertFeature(unlicensedStatus, "production", FeatureParserALB); !errors.Is(err, ErrCommercialLicenseRequired) {
		t.Fatalf("expected ErrCommercialLicenseRequired, got: %v", err)
	}

	// 3. Pro Plan license
	proClaims := &Claims{
		ID:        "lic_pro_test",
		Customer:  Customer{Name: "Pro Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierPro,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
		Scope:     &Scope{Accounts: []string{"123456789012"}},
	}
	proStatus := &ValidationStatus{Valid: true, Claims: proClaims}

	// Standard Pro features permitted
	for _, feat := range []string{FeatureParserALB, FeatureParserNLB, FeatureParserCloudFrontGzip, FeatureParserWAF, FeatureSenderOTLPHTTP} {
		if err := AssertFeature(proStatus, "production", feat); err != nil {
			t.Errorf("expected Pro to permit %s, got: %v", feat, err)
		}
	}

	// Enterprise features denied on Pro
	for _, feat := range []string{FeatureParserCloudFrontParquet, FeatureScopeCrossAccount, FeatureSenderOTLPGRPC, FeatureEnrichmentGeoIP} {
		if err := AssertFeature(proStatus, "production", feat); !errors.Is(err, ErrFeatureNotEntitled) {
			t.Errorf("expected ErrFeatureNotEntitled for %s on Pro, got: %v", feat, err)
		}
	}

	// 4. Enterprise Plan license permits all features
	entClaims := &Claims{
		ID:        "lic_ent_test",
		Customer:  Customer{Name: "Enterprise Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierEnterprise,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
		Scope:     &Scope{Accounts: []string{"123456789012"}},
	}
	entStatus := &ValidationStatus{Valid: true, Claims: entClaims}
	for _, feat := range []string{FeatureParserALB, FeatureParserCloudFrontParquet, FeatureScopeCrossAccount, FeatureSenderOTLPGRPC, FeatureEnrichmentGeoIP} {
		if err := AssertFeature(entStatus, "production", feat); err != nil {
			t.Errorf("expected Enterprise to permit %s, got: %v", feat, err)
		}
	}

	// 5. Explicit feature add-on on Pro license
	proAddonClaims := &Claims{
		ID:        "lic_pro_addon_test",
		Customer:  Customer{Name: "Pro Addon Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierPro,
		Features:  []string{FeatureParserCloudFrontParquet},
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
		Scope:     &Scope{Accounts: []string{"123456789012"}},
	}
	proAddonStatus := &ValidationStatus{Valid: true, Claims: proAddonClaims}
	if err := AssertFeature(proAddonStatus, "production", FeatureParserCloudFrontParquet); err != nil {
		t.Fatalf("expected explicit feature grant to permit parquet on Pro, got: %v", err)
	}
}

func TestFeatureEntitlements_Enforce(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)

	proClaims := &Claims{
		ID:        "lic_pro_enforce",
		Customer:  Customer{Name: "Pro Enforce Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierPro,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
		Scope:     &Scope{Accounts: []string{"123456789012"}},
	}
	proToken := signTestToken(proClaims, testPrivKey)

	// Pro plan exercising standard ALB feature -> Success
	status, err := Enforce(EnforcementOptions{
		Environment:       "production",
		LicenseKey:        proToken,
		EnforcementMode:   "strict",
		CallerAccountID:   "123456789012",
		PublicKey:         testPubKey,
		EvaluationTime:    now,
		ExercisedFeatures: []string{FeatureParserALB, FeatureParserWAF},
	})
	if err != nil || !status.Valid {
		t.Fatalf("expected Pro with standard features to be valid: %v", err)
	}

	// Pro plan exercising unentitled Parquet feature in warn mode -> Warns but no error
	warnStatus, err := Enforce(EnforcementOptions{
		Environment:       "production",
		LicenseKey:        proToken,
		EnforcementMode:   "warn",
		CallerAccountID:   "123456789012",
		PublicKey:         testPubKey,
		EvaluationTime:    now,
		ExercisedFeatures: []string{FeatureParserCloudFrontParquet},
	})
	if err != nil {
		t.Fatalf("expected no error in warn mode for unentitled feature: %v", err)
	}
	if warnStatus.Valid {
		t.Error("expected status.Valid to be false in warn mode for unentitled feature")
	}
	if warnStatus.StatusReason != "feature_not_entitled" {
		t.Errorf("got status reason %s, want feature_not_entitled", warnStatus.StatusReason)
	}

	// Pro plan exercising unentitled Parquet feature in strict mode -> Returns error
	strictStatus, err := Enforce(EnforcementOptions{
		Environment:       "production",
		LicenseKey:        proToken,
		EnforcementMode:   "strict",
		CallerAccountID:   "123456789012",
		PublicKey:         testPubKey,
		EvaluationTime:    now,
		ExercisedFeatures: []string{FeatureParserCloudFrontParquet},
	})
	if err == nil {
		t.Fatal("expected error in strict mode for unentitled feature")
	}
	if !errors.Is(err, ErrFeatureNotEntitled) {
		t.Fatalf("expected errors.Is(err, ErrFeatureNotEntitled), got: %v", err)
	}
	if strictStatus != nil && strictStatus.Valid {
		t.Error("expected strictStatus.Valid to be false")
	}

	// Enterprise plan exercising Parquet in strict mode -> Success
	entClaims := &Claims{
		ID:        "lic_ent_enforce",
		Customer:  Customer{Name: "Ent Enforce Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierEnterprise,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
		Scope:     &Scope{Accounts: []string{"123456789012"}},
	}
	entToken := signTestToken(entClaims, testPrivKey)
	entStatus, err := Enforce(EnforcementOptions{
		Environment:       "production",
		LicenseKey:        entToken,
		EnforcementMode:   "strict",
		CallerAccountID:   "123456789012",
		PublicKey:         testPubKey,
		EvaluationTime:    now,
		ExercisedFeatures: []string{FeatureParserCloudFrontParquet, FeatureScopeCrossAccount},
	})
	if err != nil || !entStatus.Valid {
		t.Fatalf("expected Enterprise to permit Parquet and cross-account: %v", err)
	}
}

func TestIsDeterministicLicenseError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"ErrCommercialLicenseRequired", ErrCommercialLicenseRequired, true},
		{"ErrFeatureNotEntitled", ErrFeatureNotEntitled, true},
		{"ErrLicenseRevoked", ErrLicenseRevoked, true},
		{"AccountMismatch", fmt.Errorf("COMMERCIAL LICENSE ACCOUNT MISMATCH: not authorized"), true},
		{"FeatureUnentitledString", fmt.Errorf("COMMERCIAL LICENSE FEATURE NOT ENTITLED: parser.cloudfront.parquet"), true},
		{"TransientNetworkTimeout", errors.New("dial tcp 10.0.0.1:4318: i/o timeout"), false},
		{"S3ClientNotFound", errors.New("NoSuchKey: The specified key does not exist"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsDeterministicLicenseError(tt.err)
			if got != tt.want {
				t.Errorf("IsDeterministicLicenseError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestPreflightEnforce(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)

	// 1. Non-production permits preflight free of charge
	statusNonProd, err := PreflightEnforce(EnforcementOptions{
		Environment: "staging",
	})
	if err != nil || !statusNonProd.Valid {
		t.Fatalf("expected staging preflight to be valid: %v", err)
	}

	// 2. Strict production without license fails preflight with deterministic error
	statusStrictNoLic, err := PreflightEnforce(EnforcementOptions{
		Environment:     "production",
		EnforcementMode: "strict",
		LicenseKey:      "",
	})
	if err == nil {
		t.Fatal("expected error in strict production preflight without license")
	}
	if !IsDeterministicLicenseError(err) {
		t.Fatalf("expected IsDeterministicLicenseError to be true, got err: %v", err)
	}
	if statusStrictNoLic != nil && statusStrictNoLic.Valid {
		t.Error("expected statusStrictNoLic.Valid to be false")
	}

	// 3. Strict production with valid license passes preflight
	validClaims := &Claims{
		ID:        "lic_preflight_test",
		Customer:  Customer{Name: "Preflight Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierPro,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
		Scope:     &Scope{Accounts: []string{"123456789012"}},
	}
	token := signTestToken(validClaims, testPrivKey)
	statusValid, err := PreflightEnforce(EnforcementOptions{
		Environment:     "production",
		EnforcementMode: "strict",
		LicenseKey:      token,
		CallerAccountID: "123456789012",
		PublicKey:       testPubKey,
		EvaluationTime:  now,
	})
	if err != nil || !statusValid.Valid {
		t.Fatalf("expected valid token to pass preflight: %v", err)
	}
}

func TestResources_PatternMatching(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		resourceARN string
		wantMatch   bool
	}{
		{
			name:        "ExactMatch",
			pattern:     "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/50dc6c495c0c9188",
			resourceARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/50dc6c495c0c9188",
			wantMatch:   true,
		},
		{
			name:        "CaseInsensitiveMatch",
			pattern:     "arn:aws:elasticloadbalancing:US-EAST-1:123456789012:loadbalancer/app/my-alb/50dc6c495c0c9188",
			resourceARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/50dc6c495c0c9188",
			wantMatch:   true,
		},
		{
			name:        "WildcardAccountAndName",
			pattern:     "arn:aws:elasticloadbalancing:us-east-1:*:loadbalancer/app/*",
			resourceARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-checkout/50dc6c495c0c9188",
			wantMatch:   true,
		},
		{
			name:        "WildcardRegionMismatch",
			pattern:     "arn:aws:elasticloadbalancing:us-west-2:*:loadbalancer/app/*",
			resourceARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-checkout/50dc6c495c0c9188",
			wantMatch:   false,
		},
		{
			name:        "WildcardTypeMismatch_NLB_vs_ALB",
			pattern:     "arn:aws:elasticloadbalancing:us-east-1:*:loadbalancer/app/*",
			resourceARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/prod-nlb/50dc6c495c0c9188",
			wantMatch:   false,
		},
		{
			name:        "ShortIDPatternAgainstFullARN",
			pattern:     "app/prod-checkout/*",
			resourceARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-checkout/50dc6c495c0c9188",
			wantMatch:   true,
		},
		{
			name:        "ShortIDPatternAgainstShortID",
			pattern:     "app/prod-checkout/*",
			resourceARN: "app/prod-checkout/50dc6c495c0c9188",
			wantMatch:   true,
		},
		{
			name:        "CloudFrontDistributionID_Exact",
			pattern:     "EDFDVBD632BHFR5",
			resourceARN: "arn:aws:cloudfront::123456789012:distribution/EDFDVBD632BHFR5",
			wantMatch:   true,
		},
		{
			name:        "CloudFrontDistributionID_ShortTarget",
			pattern:     "EDFDVBD632BHFR5",
			resourceARN: "EDFDVBD632BHFR5",
			wantMatch:   true,
		},
		{
			name:        "CloudFrontDistributionID_Mismatch",
			pattern:     "EDFDVBD632BHFR5",
			resourceARN: "arn:aws:cloudfront::123456789012:distribution/OTHERDIST12345",
			wantMatch:   false,
		},
		{
			name:        "CloudFrontWildcardARN",
			pattern:     "arn:aws:cloudfront:*:*:distribution/EDFD*",
			resourceARN: "arn:aws:cloudfront::123456789012:distribution/EDFDVBD632BHFR5",
			wantMatch:   true,
		},
		{
			name:        "WAFWebACL_RegionalWildcard",
			pattern:     "arn:aws:wafv2:us-east-1:*:regional/webacl/*",
			resourceARN: "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-waf/a1b2c3d4",
			wantMatch:   true,
		},
		{
			name:        "WAFWebACL_GlobalVsRegionalMismatch",
			pattern:     "arn:aws:wafv2:us-east-1:*:regional/webacl/*",
			resourceARN: "arn:aws:wafv2::123456789012:global/webacl/prod-waf/a1b2c3d4",
			wantMatch:   false,
		},
		{
			name:        "UniversalWildcard",
			pattern:     "*",
			resourceARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/any-alb/123",
			wantMatch:   true,
		},
		{
			name:        "UniversalAllKeyword",
			pattern:     "all",
			resourceARN: "arn:aws:cloudfront::123456789012:distribution/EDFDVBD632BHFR5",
			wantMatch:   true,
		},
		{
			name:        "EmptyPattern",
			pattern:     "",
			resourceARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/any-alb/123",
			wantMatch:   false,
		},
		{
			name:        "EmptyResource",
			pattern:     "*",
			resourceARN: "",
			wantMatch:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchResourcePattern(tt.pattern, tt.resourceARN)
			if got != tt.wantMatch {
				t.Errorf("MatchResourcePattern(%q, %q) = %v; want %v", tt.pattern, tt.resourceARN, got, tt.wantMatch)
			}
		})
	}
}

func TestScope_ResourcesSerializationAndAccessors(t *testing.T) {
	scopeJSON := `{"accounts":["123456789012"],"resources":["arn:aws:elasticloadbalancing:us-east-1:*:loadbalancer/app/*","EDFDVBD632BHFR5"]}`
	var s Scope
	if err := json.Unmarshal([]byte(scopeJSON), &s); err != nil {
		t.Fatalf("failed to unmarshal Scope: %v", err)
	}

	if len(s.Resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(s.Resources))
	}
	if s.Resources[0] != "arn:aws:elasticloadbalancing:us-east-1:*:loadbalancer/app/*" {
		t.Errorf("unexpected resource[0]: %s", s.Resources[0])
	}
	if s.Resources[1] != "EDFDVBD632BHFR5" {
		t.Errorf("unexpected resource[1]: %s", s.Resources[1])
	}

	marshaled, err := json.Marshal(&s)
	if err != nil {
		t.Fatalf("failed to marshal Scope: %v", err)
	}
	if !strings.Contains(string(marshaled), `"resources":`) {
		t.Errorf("marshaled json missing 'resources': %s", string(marshaled))
	}
	if strings.Contains(string(marshaled), `"allowed_resources":`) {
		t.Errorf("marshaled json should not contain 'allowed_resources': %s", string(marshaled))
	}

	claims := &Claims{
		Limits: &Limits{MaxResources: 2},
		Scope:  &s,
	}
	res := GetResources(claims)
	if len(res) != 2 {
		t.Fatalf("expected GetResources to return 2 items, got %d", len(res))
	}
	if !claims.IsResourceAllowed("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1") {
		t.Error("expected ALB ARN to be allowed")
	}
	if claims.IsResourceAllowed("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/1") {
		t.Error("expected NLB ARN to be disallowed")
	}

	// Verify AssertResource method
	if err := claims.AssertResource("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1"); err != nil {
		t.Errorf("expected AssertResource to succeed, got %v", err)
	}
	errNotAllowed := claims.AssertResource("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/1")
	if errNotAllowed == nil {
		t.Error("expected AssertResource to fail for unauthorized resource")
	}
	if !errors.Is(errNotAllowed, ErrResourceNotAllowed) {
		t.Errorf("expected errors.Is(errNotAllowed, ErrResourceNotAllowed)=true, got false")
	}
	if !errors.Is(errNotAllowed, liblicense.ErrScopeMismatch) {
		t.Errorf("expected errors.Is(errNotAllowed, liblicense.ErrScopeMismatch)=true, got false")
	}
	var resErr *ResourceNotAllowedError
	if !errors.As(errNotAllowed, &resErr) {
		t.Errorf("expected errors.As to populate *ResourceNotAllowedError")
	}

	// Verify CheckResourceLimit method
	if err := claims.CheckResourceLimit(2); err != nil {
		t.Errorf("expected CheckResourceLimit(2) to succeed for max 2, got %v", err)
	}
	errQuota := claims.CheckResourceLimit(3)
	if errQuota == nil {
		t.Error("expected CheckResourceLimit(3) to fail for max 2")
	}
	if !errors.Is(errQuota, ErrResourceQuotaExceeded) {
		t.Errorf("expected errors.Is(errQuota, ErrResourceQuotaExceeded)=true, got false")
	}
	if !errors.Is(errQuota, liblicense.ErrLimitExceeded) {
		t.Errorf("expected errors.Is(errQuota, liblicense.ErrLimitExceeded)=true, got false")
	}
	var quotaErr *ResourceQuotaExceededError
	if !errors.As(errQuota, &quotaErr) {
		t.Errorf("expected errors.As to populate *ResourceQuotaExceededError")
	}

	// Verify legacy unmarshaling from "allowed_resources"
	legacyJSON := `{"accounts":["123456789012"],"allowed_resources":["arn:aws:elasticloadbalancing:us-east-1:*:loadbalancer/app/*"]}`
	var sLegacy Scope
	if err := json.Unmarshal([]byte(legacyJSON), &sLegacy); err != nil {
		t.Fatalf("failed to unmarshal legacy Scope: %v", err)
	}
	if len(sLegacy.Resources) != 1 || sLegacy.Resources[0] != "arn:aws:elasticloadbalancing:us-east-1:*:loadbalancer/app/*" {
		t.Errorf("expected legacy allowed_resources to populate Resources, got %v", sLegacy.Resources)
	}
}

func TestResourceQuota_StrictAndWarn(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	claims := &Claims{
		ID:        "lic_quota_test",
		Customer:  Customer{Name: "Quota Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierPro,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
		Limits: &Limits{
			MaxResources: 2,
		},
		Scope: &Scope{
			Accounts:  []string{"123456789012"},
			Resources: []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/*"},
		},
	}
	token := signTestToken(claims, testPrivKey)

	alb1 := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-1/111"
	alb2 := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-2/222"
	alb3 := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-3/333"
	unauthorizedNLB := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/nlb-1/999"

	// 1. Within quota (2 resources, max 2) in strict mode -> Valid
	t.Run("WithinQuota_Strict", func(t *testing.T) {
		tracker := NewResourceTracker()
		status, err := Enforce(EnforcementOptions{
			Environment:        "production",
			EnforcementMode:    "strict",
			LicenseKey:         token,
			CallerAccountID:    "123456789012",
			SourceResourceARNs: []string{alb1, alb2},
			ResourceTracker:    tracker,
			PublicKey:          testPubKey,
			EvaluationTime:     now,
		})
		if err != nil {
			t.Fatalf("unexpected error within quota: %v", err)
		}
		if !status.Valid {
			t.Errorf("expected status to be valid, got reason %s", status.StatusReason)
		}
		if tracker.Count() != 2 {
			t.Errorf("expected tracker count 2, got %d", tracker.Count())
		}
	})

	// 2. Quota breach in warn mode (3 resources, max 2) -> Soft warning, valid = false, err = nil
	t.Run("QuotaBreach_Warn", func(t *testing.T) {
		tracker := NewResourceTracker()
		status, err := Enforce(EnforcementOptions{
			Environment:        "production",
			EnforcementMode:    "warn",
			LicenseKey:         token,
			CallerAccountID:    "123456789012",
			SourceResourceARNs: []string{alb1, alb2, alb3},
			ResourceTracker:    tracker,
			PublicKey:          testPubKey,
			EvaluationTime:     now,
		})
		if err != nil {
			t.Fatalf("expected nil error in warn mode, got: %v", err)
		}
		if status == nil || status.Valid {
			t.Fatal("expected status.Valid to be false on quota breach")
		}
		if status.StatusReason != "resource_quota_exceeded" {
			t.Errorf("got status reason %s, want resource_quota_exceeded", status.StatusReason)
		}
		if tracker.Count() != 3 {
			t.Errorf("expected tracker count 3, got %d", tracker.Count())
		}
	})

	// 3. Quota breach in strict mode (3 resources, max 2) -> Structured error wrapping ErrResourceQuotaExceeded
	t.Run("QuotaBreach_Strict", func(t *testing.T) {
		tracker := NewResourceTracker()
		status, err := Enforce(EnforcementOptions{
			Environment:        "production",
			EnforcementMode:    "strict",
			LicenseKey:         token,
			CallerAccountID:    "123456789012",
			SourceResourceARNs: []string{alb1, alb2, alb3},
			ResourceTracker:    tracker,
			PublicKey:          testPubKey,
			EvaluationTime:     now,
		})
		if err == nil {
			t.Fatal("expected error on quota breach in strict mode")
		}
		if !errors.Is(err, ErrResourceQuotaExceeded) {
			t.Errorf("expected error to wrap ErrResourceQuotaExceeded, got: %v", err)
		}
		if !IsDeterministicLicenseError(err) {
			t.Errorf("expected IsDeterministicLicenseError to return true, got: %v", err)
		}
		if status != nil && status.Valid {
			t.Error("expected status.Valid to be false")
		}
	})

	// 4. Unauthorized resource in warn mode -> StatusReason = resource_not_allowed, err = nil
	t.Run("UnauthorizedResource_Warn", func(t *testing.T) {
		tracker := NewResourceTracker()
		status, err := Enforce(EnforcementOptions{
			Environment:        "production",
			EnforcementMode:    "warn",
			LicenseKey:         token,
			CallerAccountID:    "123456789012",
			SourceResourceARNs: []string{unauthorizedNLB},
			ResourceTracker:    tracker,
			PublicKey:          testPubKey,
			EvaluationTime:     now,
		})
		if err != nil {
			t.Fatalf("expected nil error in warn mode for unauthorized resource, got: %v", err)
		}
		if status == nil || status.Valid {
			t.Fatal("expected status.Valid to be false for unauthorized resource")
		}
		if status.StatusReason != "resource_not_allowed" {
			t.Errorf("got status reason %s, want resource_not_allowed", status.StatusReason)
		}
	})

	// 5. Unauthorized resource in strict mode -> Structured error wrapping ErrResourceNotAllowed
	t.Run("UnauthorizedResource_Strict", func(t *testing.T) {
		tracker := NewResourceTracker()
		status, err := Enforce(EnforcementOptions{
			Environment:        "production",
			EnforcementMode:    "strict",
			LicenseKey:         token,
			CallerAccountID:    "123456789012",
			SourceResourceARNs: []string{unauthorizedNLB},
			ResourceTracker:    tracker,
			PublicKey:          testPubKey,
			EvaluationTime:     now,
		})
		if err == nil {
			t.Fatal("expected error for unauthorized resource in strict mode")
		}
		if !errors.Is(err, ErrResourceNotAllowed) {
			t.Errorf("expected error to wrap ErrResourceNotAllowed, got: %v", err)
		}
		if !IsDeterministicLicenseError(err) {
			t.Errorf("expected IsDeterministicLicenseError to return true, got: %v", err)
		}
		if status != nil && status.Valid {
			t.Error("expected status.Valid to be false")
		}
	})
}

func TestResourceTracker_LifecycleAndConcurrency(t *testing.T) {
	tracker := NewResourceTracker()
	if tracker.Count() != 0 {
		t.Errorf("expected initial count 0, got %d", tracker.Count())
	}

	// 1. Basic tracking & deduplication
	count, isNew := tracker.Track("res-1")
	if !isNew || count != 1 {
		t.Errorf("expected isNew=true, count=1; got isNew=%v, count=%d", isNew, count)
	}

	// Repeat same resource
	count, isNew = tracker.Track("res-1")
	if isNew || count != 1 {
		t.Errorf("expected isNew=false, count=1 on duplicate; got isNew=%v, count=%d", isNew, count)
	}

	// Add second resource
	count, isNew = tracker.Track("res-2")
	if !isNew || count != 2 {
		t.Errorf("expected isNew=true, count=2; got isNew=%v, count=%d", isNew, count)
	}

	if tracker.Count() != 2 {
		t.Errorf("expected Count()=2, got %d", tracker.Count())
	}

	resources := tracker.Resources()
	if len(resources) != 2 {
		t.Errorf("expected 2 resources, got %d", len(resources))
	}

	// 2. High-concurrency tracking with race detector
	tracker.Reset()
	var wg sync.WaitGroup
	workers := 50
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			resID := fmt.Sprintf("resource-%d", workerID%10) // 10 unique resources across 50 workers
			tracker.Track(resID)
			tracker.Count()
			tracker.Resources()
		}(i)
	}
	wg.Wait()

	if tracker.Count() != 10 {
		t.Errorf("expected 10 unique resources after concurrent tracking, got %d", tracker.Count())
	}
}

func TestLegacyToken_BackwardCompatibility(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)

	// Legacy token: only Accounts specified, MaxResources and Resources omitted (MaxResources == 0)
	legacyClaims := &Claims{
		ID:        "lic_legacy_account_only",
		Customer:  Customer{Name: "Legacy Enterprise Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierEnterprise,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
		Scope: &Scope{
			Accounts: []string{"123456789012"},
		},
	}
	token := signTestToken(legacyClaims, testPrivKey)

	// Verify helper accessors
	if GetMaxResources(legacyClaims) != 0 {
		t.Errorf("expected GetMaxResources=0 for legacy token, got %d", GetMaxResources(legacyClaims))
	}
	if !IsResourceAllowed(legacyClaims, "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/123") {
		t.Error("expected IsResourceAllowed=true for legacy token without Resources")
	}

	// Generate 50 resources from the authorized account
	var manyResources []string
	for i := 0; i < 50; i++ {
		manyResources = append(manyResources, fmt.Sprintf("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-%d/hash", i))
	}

	tracker := NewResourceTracker()
	status, err := Enforce(EnforcementOptions{
		Environment:        "production",
		EnforcementMode:    "strict",
		LicenseKey:         token,
		CallerAccountID:    "123456789012",
		SourceResourceARNs: manyResources,
		ResourceTracker:    tracker,
		PublicKey:          testPubKey,
		EvaluationTime:     now,
	})
	if err != nil {
		t.Fatalf("expected legacy token with MaxResources=0 to be uncapped without error, got: %v", err)
	}
	if !status.Valid {
		t.Errorf("expected status to be valid for legacy token, got reason %s", status.StatusReason)
	}
	if tracker.Count() != 50 {
		t.Errorf("expected tracker to count 50 resources, got %d", tracker.Count())
	}
}

func TestMultiAccountSpokeSetup_ResourceQuota(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)

	// Enterprise license with MaxResources=25, uncapped accounts
	claims := &Claims{
		ID:        "lic_landing_zone_test",
		Customer:  Customer{Name: "FinOps Cloud Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierEnterprise,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
		Limits: &Limits{
			MaxResources: 25,
		},
		Scope: &Scope{},
	}
	token := signTestToken(claims, testPrivKey)

	// Simulate 25 spoke accounts, each running 1 ALB
	var spokeAccounts []string
	var spokeResources []string
	for i := 1; i <= 25; i++ {
		acct := fmt.Sprintf("%012d", i)
		spokeAccounts = append(spokeAccounts, acct)
		spokeResources = append(spokeResources, fmt.Sprintf("arn:aws:elasticloadbalancing:us-east-1:%s:loadbalancer/app/spoke-%d/hash", acct, i))
	}

	tracker := NewResourceTracker()
	status, err := Enforce(EnforcementOptions{
		Environment:        "production",
		EnforcementMode:    "strict",
		LicenseKey:         token,
		CallerAccountID:    "999999999999", // Central logging account
		SourceAccountIDs:   spokeAccounts,
		SourceResourceARNs: spokeResources,
		ResourceTracker:    tracker,
		PublicKey:          testPubKey,
		EvaluationTime:     now,
	})
	if err != nil {
		t.Fatalf("expected 25 spoke accounts with 1 ALB each to succeed under MaxResources=25: %v", err)
	}
	if !status.Valid {
		t.Errorf("expected valid status, got %s", status.StatusReason)
	}
	if tracker.Count() != 25 {
		t.Errorf("expected 25 active tracked resources, got %d", tracker.Count())
	}

	// Now add a 26th spoke account and resource -> exceeds MaxResources: 25
	acct26 := fmt.Sprintf("%012d", 26)
	res26 := fmt.Sprintf("arn:aws:elasticloadbalancing:us-east-1:%s:loadbalancer/app/spoke-26/hash", acct26)

	_, errBreach := Enforce(EnforcementOptions{
		Environment:        "production",
		EnforcementMode:    "strict",
		LicenseKey:         token,
		CallerAccountID:    "999999999999",
		SourceAccountIDs:   []string{acct26},
		SourceResourceARNs: []string{res26},
		ResourceTracker:    tracker,
		PublicKey:          testPubKey,
		EvaluationTime:     now,
	})
	if errBreach == nil {
		t.Fatal("expected quota breach error when 26th resource is added to MaxResources=25")
	}
	if !errors.Is(errBreach, ErrResourceQuotaExceeded) {
		t.Errorf("expected ErrResourceQuotaExceeded, got: %v", errBreach)
	}
}

func TestSingleAccountLargeResourceBreach(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)

	// Pro license with MaxResources: 25 in single account
	claims := &Claims{
		ID:        "lic_single_acct_test",
		Customer:  Customer{Name: "Monolithic Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierPro,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
		Limits: &Limits{
			MaxResources: 25,
		},
		Scope: &Scope{
			Accounts: []string{"123456789012"},
		},
	}
	token := signTestToken(claims, testPrivKey)

	// Single account running 30 ALBs
	var albResources []string
	for i := 1; i <= 30; i++ {
		albResources = append(albResources, fmt.Sprintf("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-%d/hash", i))
	}

	// 1. Strict mode fails with structured deterministic error
	trackerStrict := NewResourceTracker()
	statusStrict, errStrict := Enforce(EnforcementOptions{
		Environment:        "production",
		EnforcementMode:    "strict",
		LicenseKey:         token,
		CallerAccountID:    "123456789012",
		SourceResourceARNs: albResources,
		ResourceTracker:    trackerStrict,
		PublicKey:          testPubKey,
		EvaluationTime:     now,
	})
	if errStrict == nil {
		t.Fatal("expected error in strict mode when single account runs 30 ALBs under MaxResources=25")
	}
	if !errors.Is(errStrict, ErrResourceQuotaExceeded) {
		t.Errorf("expected ErrResourceQuotaExceeded, got: %v", errStrict)
	}
	if !IsDeterministicLicenseError(errStrict) {
		t.Errorf("expected IsDeterministicLicenseError to be true, got: %v", errStrict)
	}
	if statusStrict != nil && statusStrict.Valid {
		t.Error("expected statusStrict.Valid to be false")
	}

	// 2. Warn mode logs warning without dropping traffic
	trackerWarn := NewResourceTracker()
	statusWarn, errWarn := Enforce(EnforcementOptions{
		Environment:        "production",
		EnforcementMode:    "warn",
		LicenseKey:         token,
		CallerAccountID:    "123456789012",
		SourceResourceARNs: albResources,
		ResourceTracker:    trackerWarn,
		PublicKey:          testPubKey,
		EvaluationTime:     now,
	})
	if errWarn != nil {
		t.Fatalf("expected nil error in warn mode, got: %v", errWarn)
	}
	if statusWarn == nil || statusWarn.Valid {
		t.Fatal("expected statusWarn.Valid to be false")
	}
	if statusWarn.StatusReason != "resource_quota_exceeded" {
		t.Errorf("got status reason %s, want resource_quota_exceeded", statusWarn.StatusReason)
	}
}

func TestResourceExtractionHelpers(t *testing.T) {
	// 1. ALB Attributes
	albAttrs := []model.OTelAttribute{
		{Key: "aws.lb.name", Value: model.StringValue("app/my-alb/50dc6c495c0c9188")},
		{Key: "cloud.region", Value: model.StringValue("us-east-1")},
		{Key: "cloud.account.id", Value: model.StringValue("123456789012")},
	}
	arn, shortID := ExtractResourceFromAttributes(albAttrs)
	if arn != "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/50dc6c495c0c9188" {
		t.Errorf("got ALB ARN %s", arn)
	}
	if shortID != "app/my-alb/50dc6c495c0c9188" {
		t.Errorf("got ALB shortID %s", shortID)
	}

	// 2. NLB Attributes
	nlbAttrs := []model.OTelAttribute{
		{Key: "aws.lb.name", Value: model.StringValue("net/my-nlb/1234567890abcdef")},
		{Key: "cloud.region", Value: model.StringValue("eu-west-1")},
		{Key: "cloud.account.id", Value: model.StringValue("987654321098")},
	}
	arnNLB, shortIDNLB := ExtractResourceFromAttributes(nlbAttrs)
	if arnNLB != "arn:aws:elasticloadbalancing:eu-west-1:987654321098:loadbalancer/net/my-nlb/1234567890abcdef" {
		t.Errorf("got NLB ARN %s", arnNLB)
	}
	if shortIDNLB != "net/my-nlb/1234567890abcdef" {
		t.Errorf("got NLB shortID %s", shortIDNLB)
	}

	// 3. CloudFront Attributes
	cfAttrs := []model.OTelAttribute{
		{Key: "aws.cloudfront.distribution_id", Value: model.StringValue("EDFDVBD632BHFR5")},
		{Key: "cloud.account.id", Value: model.StringValue("123456789012")},
	}
	arnCF, shortIDCF := ExtractResourceFromAttributes(cfAttrs)
	if arnCF != "arn:aws:cloudfront::123456789012:distribution/EDFDVBD632BHFR5" {
		t.Errorf("got CloudFront ARN %s", arnCF)
	}
	if shortIDCF != "EDFDVBD632BHFR5" {
		t.Errorf("got CloudFront shortID %s", shortIDCF)
	}

	// 4. WAF Attributes
	wafAttrs := []model.OTelAttribute{
		{Key: "aws.waf.web_acl_id", Value: model.StringValue("arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-waf/uuid")},
	}
	arnWAF, shortIDWAF := ExtractResourceFromAttributes(wafAttrs)
	if arnWAF != "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-waf/uuid" {
		t.Errorf("got WAF ARN %s", arnWAF)
	}
	if shortIDWAF != "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-waf/uuid" {
		t.Errorf("got WAF shortID %s", shortIDWAF)
	}

	// 5. ALB S3 Key
	albKey := "prefix/AWSLogs/123456789012/elasticloadbalancing/us-east-1/2026/09/20/123456789012_elasticloadbalancing_us-east-1_app.my-alb.50dc6c495c0c9188_20260920T0000Z_1.2.3.4_hash.log.gz"
	albKeyARN, albKeyShort := ExtractResourceFromS3Key(albKey)
	if albKeyARN != "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/50dc6c495c0c9188" {
		t.Errorf("got ALB S3 Key ARN %s", albKeyARN)
	}
	if albKeyShort != "app/my-alb/50dc6c495c0c9188" {
		t.Errorf("got ALB S3 Key shortID %s", albKeyShort)
	}

	// 6. CloudFront Gzip S3 Key
	cfKey := "AWSLogs/123456789012/CloudFront/EDFDVBD632BHFR5.2026-09-20-12.d111111abcdef8.gz"
	cfKeyARN, cfKeyShort := ExtractResourceFromS3Key(cfKey)
	if cfKeyARN != "arn:aws:cloudfront::123456789012:distribution/EDFDVBD632BHFR5" {
		t.Errorf("got CloudFront S3 Key ARN %s", cfKeyARN)
	}
	if cfKeyShort != "EDFDVBD632BHFR5" {
		t.Errorf("got CloudFront S3 Key shortID %s", cfKeyShort)
	}

	// 7. CloudFront Parquet S3 Key
	cfParquetKey := "AWSLogs/123456789012/CloudFront/EDFDVBD632BHFR5/2026/09/20/12/EDFDVBD632BHFR5.2026-09-20-12.d111111abcdef8.parquet"
	cfPKeyARN, cfPKeyShort := ExtractResourceFromS3Key(cfParquetKey)
	if cfPKeyARN != "arn:aws:cloudfront::123456789012:distribution/EDFDVBD632BHFR5" {
		t.Errorf("got CloudFront Parquet S3 Key ARN %s", cfPKeyARN)
	}
	if cfPKeyShort != "EDFDVBD632BHFR5" {
		t.Errorf("got CloudFront Parquet S3 Key shortID %s", cfPKeyShort)
	}
}

func TestQuotaTracker_AtomicByteCountingAndConcurrency(t *testing.T) {
	tracker := NewQuotaTracker()

	// Initial count
	if tracker.TotalBytesProcessed() != 0 {
		t.Fatalf("expected initial bytes to be 0, got %d", tracker.TotalBytesProcessed())
	}
	if tracker.TotalCompressedBytes() != 0 {
		t.Fatalf("expected initial compressed bytes to be 0, got %d", tracker.TotalCompressedBytes())
	}

	// High concurrency stress test: 50 goroutines adding 100 chunks of 1024 bytes
	numGoroutines := 50
	chunksPerGoroutine := 100
	chunkSize := int64(1024)
	expectedTotal := int64(numGoroutines*chunksPerGoroutine) * chunkSize

	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < chunksPerGoroutine; j++ {
				tracker.RecordBytes(chunkSize)
				tracker.RecordCompressedBytes(chunkSize / 2)
			}
		}()
	}
	wg.Wait()

	if total := tracker.TotalBytesProcessed(); total != expectedTotal {
		t.Fatalf("got total bytes %d, want %d", total, expectedTotal)
	}
	if totalCompressed := tracker.TotalCompressedBytes(); totalCompressed != expectedTotal/2 {
		t.Fatalf("got total compressed bytes %d, want %d", totalCompressed, expectedTotal/2)
	}

	// Non-positive additions should not change count
	tracker.RecordBytes(0)
	tracker.RecordBytes(-500)
	if total := tracker.TotalBytesProcessed(); total != expectedTotal {
		t.Fatalf("got total bytes %d after non-positive record, want %d", total, expectedTotal)
	}
}

func TestQuotaTracker_FairUseWarningRateLimiting(t *testing.T) {
	tracker := NewQuotaTracker()
	t0 := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

	// 1. First warning at t0 must emit
	if !tracker.LogFairUseWarningAt(25, t0) {
		t.Fatal("expected first fair-use warning to be emitted")
	}

	// 2. Immediate subsequent warning at t0 + 10m must be suppressed
	if tracker.LogFairUseWarningAt(25, t0.Add(10*time.Minute)) {
		t.Fatal("expected fair-use warning at +10m to be rate-limited and suppressed")
	}

	// 3. Warning at t0 + 59m must still be suppressed
	if tracker.LogFairUseWarningAt(25, t0.Add(59*time.Minute)) {
		t.Fatal("expected fair-use warning at +59m to be suppressed")
	}

	// 4. Warning at t0 + 60m (1 hour later) must emit
	if !tracker.LogFairUseWarningAt(25, t0.Add(60*time.Minute)) {
		t.Fatal("expected fair-use warning at +60m to be emitted")
	}

	// 5. Warning at t0 + 75m must be suppressed again
	if tracker.LogFairUseWarningAt(25, t0.Add(75*time.Minute)) {
		t.Fatal("expected fair-use warning at +75m to be suppressed")
	}

	// 6. ResetWarningTime allows immediate re-emission
	tracker.ResetWarningTime()
	if !tracker.LogFairUseWarningAt(25, t0.Add(76*time.Minute)) {
		t.Fatal("expected warning to emit after ResetWarningTime")
	}
}

func TestClaims_LimitsAndMaxMonthlyGB(t *testing.T) {
	// 1. Claims with explicit MaxMonthlyGB and MaxContainerRecords
	jsonClaims := `{
		"id": "lic_gb_test",
		"customer": {"name": "Throughput Customer"},
		"product": "otel-aws-log-processor",
		"plan": "pro",
		"issued_at": "2026-09-01T00:00:00Z",
		"limits": {
			"max_monthly_gb": 25000,
			"max_container_records": 50000
		}
	}`

	var claims Claims
	if err := json.Unmarshal([]byte(jsonClaims), &claims); err != nil {
		t.Fatalf("failed to unmarshal claims: %v", err)
	}

	if claims.Limits == nil {
		t.Fatal("expected claims.Limits to not be nil")
	}
	if claims.Limits.MaxMonthlyGB != 25000 {
		t.Errorf("got MaxMonthlyGB %d, want 25000", claims.Limits.MaxMonthlyGB)
	}
	if claims.Limits.MaxContainerRecords != 50000 {
		t.Errorf("got MaxContainerRecords %d, want 50000", claims.Limits.MaxContainerRecords)
	}
	if gb := GetMaxMonthlyGB(&claims); gb != 25000 {
		t.Errorf("got GetMaxMonthlyGB %d, want 25000", gb)
	}

	// 2. Uncapped / omitted limits
	if gb := GetMaxMonthlyGB(nil); gb != 0 {
		t.Errorf("got GetMaxMonthlyGB(nil) %d, want 0", gb)
	}
	if gb := GetMaxMonthlyGB(&Claims{}); gb != 0 {
		t.Errorf("got GetMaxMonthlyGB(empty) %d, want 0", gb)
	}
	if gb := GetMaxMonthlyGB(&Claims{Limits: &Limits{MaxMonthlyGB: 0}}); gb != 0 {
		t.Errorf("got GetMaxMonthlyGB(0) %d, want 0", gb)
	}
}

func TestEnforce_ThroughputFairUseNonBlocking(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pubKey := privKey.Public().(ed25519.PublicKey)

	// Issue token with MaxMonthlyTB = 25
	token := signTestToken(&Claims{
		ID:        "lic_throughput_soft_test",
		Customer:  Customer{Name: "Soft Enforcement Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierPro,
		IssuedAt:  time.Now().UTC().Add(-1 * time.Hour),
		ExpiresAt: time.Now().UTC().Add(365 * 24 * time.Hour),
		Limits: &Limits{
			MaxMonthlyGB: 25000,
			MaxResources: 10,
		},
		Scope: &Scope{
			Accounts: []string{"123456789012"},
		},
	}, privKey)

	t.Run("WithinThroughputLimit", func(t *testing.T) {
		quotaTracker := NewQuotaTracker()
		quotaTracker.RecordBytes(1024 * 1024) // 1 MB

		status, err := Enforce(EnforcementOptions{
			Environment:     "production",
			LicenseKey:      token,
			PublicKey:       pubKey,
			CallerAccountID: "123456789012",
			QuotaTracker:    quotaTracker,
			EnforcementMode: "strict",
		})
		if err != nil {
			t.Fatalf("unexpected error within throughput limit: %v", err)
		}
		if !status.Valid {
			t.Fatal("expected status.Valid to be true")
		}
		if status.ThroughputExceeded {
			t.Fatal("expected status.ThroughputExceeded to be false")
		}
	})

	t.Run("ThroughputExceeded_Strict_NeverBlocks", func(t *testing.T) {
		quotaTracker := NewQuotaTracker()
		quotaTracker.SetThroughputExceeded(true) // flag throughput overage

		// Crucial acceptance criterion: Even in strict mode, throughput fair-use breach
		// NEVER returns an error, NEVER halts execution, and NEVER drops log records.
		status, err := Enforce(EnforcementOptions{
			Environment:     "production",
			LicenseKey:      token,
			PublicKey:       pubKey,
			CallerAccountID: "123456789012",
			QuotaTracker:    quotaTracker,
			EnforcementMode: "strict",
		})
		if err != nil {
			t.Fatalf("throughput overage must NEVER return an error, got: %v", err)
		}
		if !status.Valid {
			t.Fatal("expected status.Valid to be true on throughput overage")
		}
		if !status.ThroughputExceeded {
			t.Fatal("expected status.ThroughputExceeded to be true")
		}
	})

	t.Run("ThroughputExceeded_ViaEnvVar", func(t *testing.T) {
		t.Setenv("DIVMORA_THROUGHPUT_EXCEEDED", "true")
		quotaTracker := NewQuotaTracker()

		status, err := Enforce(EnforcementOptions{
			Environment:     "production",
			LicenseKey:      token,
			PublicKey:       pubKey,
			CallerAccountID: "123456789012",
			QuotaTracker:    quotaTracker,
			EnforcementMode: "strict",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !status.Valid {
			t.Fatal("expected status.Valid to be true")
		}
		if !status.ThroughputExceeded {
			t.Fatal("expected status.ThroughputExceeded to be true via env var")
		}
	})
}

func TestEmitCloudWatchEMF_WithBytesProcessed(t *testing.T) {
	status := &ValidationStatus{
		Valid:        true,
		StatusReason: "valid",
		Claims: &Claims{
			ID:   "lic_emf_bytes_test",
			Plan: TierEnterprise,
		},
		ThroughputExceeded: true,
	}

	resourceARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/123456"
	recordsProcessed := 1500
	activeResources := 12
	bytesProcessed := int64(10485760) // 10 MB

	payload := BuildEMFPayload(status, "production", recordsProcessed, activeResources, bytesProcessed, []string{resourceARN})
	if payload == nil {
		t.Fatal("expected payload not to be nil")
	}

	// Verify top-level fields
	if payload["Environment"] != "production" {
		t.Errorf("got Environment %v, want production", payload["Environment"])
	}
	if payload["Status"] != "valid" {
		t.Errorf("got Status %v, want valid", payload["Status"])
	}
	if payload["RecordsProcessed"] != recordsProcessed {
		t.Errorf("got RecordsProcessed %v, want %d", payload["RecordsProcessed"], recordsProcessed)
	}
	if payload["BytesProcessed"] != bytesProcessed {
		t.Errorf("got BytesProcessed %v, want %d", payload["BytesProcessed"], bytesProcessed)
	}
	if payload["ActiveMonitoredResources"] != activeResources {
		t.Errorf("got ActiveMonitoredResources %v, want %d", payload["ActiveMonitoredResources"], activeResources)
	}
	if payload["LicenseID"] != "lic_emf_bytes_test" {
		t.Errorf("got LicenseID %v, want lic_emf_bytes_test", payload["LicenseID"])
	}
	if payload["Tier"] != TierEnterprise {
		t.Errorf("got Tier %v, want %s", payload["Tier"], TierEnterprise)
	}
	if payload["ResourceARN"] != resourceARN {
		t.Errorf("got ResourceARN %v, want %s", payload["ResourceARN"], resourceARN)
	}
	if payload["ThroughputExceeded"] != true {
		t.Errorf("got ThroughputExceeded %v, want true", payload["ThroughputExceeded"])
	}

	// Verify CloudWatchMetrics metadata
	awsMeta, ok := payload["_aws"].(map[string]any)
	if !ok {
		t.Fatal("missing _aws in EMF payload")
	}
	cwMetrics, ok := awsMeta["CloudWatchMetrics"].([]map[string]any)
	if !ok || len(cwMetrics) < 2 {
		t.Fatalf("expected at least 2 metric namespaces, got %d", len(cwMetrics))
	}

	// 1. Namespace Divmora/LogProcessor
	logProcNS := cwMetrics[0]
	if logProcNS["Namespace"] != "Divmora/LogProcessor" {
		t.Errorf("got namespace %v, want Divmora/LogProcessor", logProcNS["Namespace"])
	}
	metrics := logProcNS["Metrics"].([]map[string]string)
	hasBytesMetric := false
	for _, m := range metrics {
		if m["Name"] == "BytesProcessed" && m["Unit"] == "Bytes" {
			hasBytesMetric = true
			break
		}
	}
	if !hasBytesMetric {
		t.Error("missing BytesProcessed metric in Divmora/LogProcessor namespace")
	}

	// 2. Namespace Divmora/License
	licenseNS := cwMetrics[1]
	if licenseNS["Namespace"] != "Divmora/License" {
		t.Errorf("got namespace %v, want Divmora/License", licenseNS["Namespace"])
	}

	// Verify FormatEMFPayload produces valid JSON
	jsonStr, err := FormatEMFPayload(status, "production", recordsProcessed, activeResources, bytesProcessed, []string{resourceARN})
	if err != nil {
		t.Fatalf("FormatEMFPayload failed: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("invalid JSON output from FormatEMFPayload: %v", err)
	}
	if parsed["CentralMetricsRegion"] != "us-east-1" {
		t.Errorf("got CentralMetricsRegion %v, want us-east-1", parsed["CentralMetricsRegion"])
	}
}

func TestResolveCentralMetricsRegion(t *testing.T) {
	t.Run("FromMetadata_MetricsRegion", func(t *testing.T) {
		claims := &Claims{
			Metadata: map[string]string{
				"metrics_region": "eu-central-1",
			},
		}
		if r := ResolveCentralMetricsRegion(claims); r != "eu-central-1" {
			t.Errorf("got %q, want eu-central-1", r)
		}
	})

	t.Run("FromMetadata_CloudWatchMetricsRegion", func(t *testing.T) {
		claims := &Claims{
			Metadata: map[string]string{
				"cloudwatch_metrics_region": "us-west-2",
			},
		}
		if r := ResolveCentralMetricsRegion(claims); r != "us-west-2" {
			t.Errorf("got %q, want us-west-2", r)
		}
	})

	t.Run("EmptyMetadata_DefaultsToUsEast1", func(t *testing.T) {
		claims := &Claims{
			Metadata: map[string]string{},
		}
		if r := ResolveCentralMetricsRegion(claims); r != "us-east-1" {
			t.Errorf("got %q, want us-east-1", r)
		}
	})

	t.Run("NilClaims_DefaultsToUsEast1", func(t *testing.T) {
		if r := ResolveCentralMetricsRegion(nil); r != "us-east-1" {
			t.Errorf("got %q, want us-east-1", r)
		}
	})

	t.Run("StrictNoEnvVarOverride", func(t *testing.T) {
		// Even if an operator or malicious user sets CLOUDWATCH_METRICS_REGION,
		// the signed license metadata must remain authoritative to prevent quota tampering or configuration drift.
		t.Setenv("CLOUDWATCH_METRICS_REGION", "ap-southeast-1")
		claims := &Claims{
			Metadata: map[string]string{
				"metrics_region": "eu-west-1",
			},
		}
		if r := ResolveCentralMetricsRegion(claims); r != "eu-west-1" {
			t.Errorf("got %q, want eu-west-1 (env var override must be ignored)", r)
		}

		// When metadata is empty, it strictly defaults to us-east-1, NOT the env var!
		emptyClaims := &Claims{}
		if r := ResolveCentralMetricsRegion(emptyClaims); r != "us-east-1" {
			t.Errorf("got %q, want us-east-1 (env var must not override default)", r)
		}
	})
}

func TestGetCurrentRegion(t *testing.T) {
	t.Run("AWSRegion_Set", func(t *testing.T) {
		t.Setenv("AWS_REGION", "eu-west-1")
		t.Setenv("AWS_DEFAULT_REGION", "us-west-2")
		if r := GetCurrentRegion(); r != "eu-west-1" {
			t.Errorf("got %q, want eu-west-1", r)
		}
	})

	t.Run("AWSDefaultRegion_Fallback", func(t *testing.T) {
		t.Setenv("AWS_REGION", "")
		t.Setenv("AWS_DEFAULT_REGION", "sa-east-1")
		if r := GetCurrentRegion(); r != "sa-east-1" {
			t.Errorf("got %q, want sa-east-1", r)
		}
	})

	t.Run("Default_UsEast1", func(t *testing.T) {
		t.Setenv("AWS_REGION", "")
		t.Setenv("AWS_DEFAULT_REGION", "")
		if r := GetCurrentRegion(); r != "us-east-1" {
			t.Errorf("got %q, want us-east-1", r)
		}
	})
}

type mockCloudWatchMetricAPI struct {
	mu    sync.Mutex
	calls []*cloudwatch.PutMetricDataInput
	err   error
}

func (m *mockCloudWatchMetricAPI) PutMetricData(ctx context.Context, params *cloudwatch.PutMetricDataInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricDataOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, params)
	return &cloudwatch.PutMetricDataOutput{}, m.err
}

func TestPublishCrossRegionMetrics(t *testing.T) {
	mockCW := &mockCloudWatchMetricAPI{}
	t.Setenv("AWS_REGION", "eu-central-1")

	status := &ValidationStatus{
		Valid:        true,
		StatusReason: "valid",
		Claims: &Claims{
			ID:   "lic_cross_reg_test",
			Plan: TierPro,
			Metadata: map[string]string{
				"metrics_region": "us-east-1",
			},
		},
	}

	err := PublishCrossRegionMetrics(context.Background(), mockCW, status, "production", 500, 3, int64(2048000), []string{"arn:aws:elasticloadbalancing:eu-central-1:123456789012:loadbalancer/app/test-alb/123"})
	if err != nil {
		t.Fatalf("PublishCrossRegionMetrics failed: %v", err)
	}

	mockCW.mu.Lock()
	defer mockCW.mu.Unlock()

	if len(mockCW.calls) != 2 {
		t.Fatalf("expected 2 PutMetricData calls (Divmora/LogProcessor and Divmora/License), got %d", len(mockCW.calls))
	}

	// Verify Divmora/LogProcessor
	call1 := mockCW.calls[0]
	if *call1.Namespace != "Divmora/LogProcessor" {
		t.Errorf("call 0 namespace: got %s, want Divmora/LogProcessor", *call1.Namespace)
	}

	// Verify Divmora/License
	call2 := mockCW.calls[1]
	if *call2.Namespace != "Divmora/License" {
		t.Errorf("call 1 namespace: got %s, want Divmora/License", *call2.Namespace)
	}

	// Verify that Region dimension on metric datums reflects the current execution region (eu-central-1)
	hasExecutingRegion := false
	for _, datum := range call2.MetricData {
		for _, dim := range datum.Dimensions {
			if *dim.Name == "Region" && *dim.Value == "eu-central-1" {
				hasExecutingRegion = true
				break
			}
		}
	}
	if !hasExecutingRegion {
		t.Errorf("expected Region=eu-central-1 dimension in License metric data")
	}
}

func TestEmitMetrics_Routing(t *testing.T) {
	t.Run("SameRegion_SkipsSDKCall", func(t *testing.T) {
		t.Setenv("AWS_REGION", "us-east-1")
		mockCW := &mockCloudWatchMetricAPI{}

		status := &ValidationStatus{
			Valid:        true,
			StatusReason: "valid",
			Claims: &Claims{
				ID:   "lic_same_reg",
				Plan: TierEnterprise,
				Metadata: map[string]string{
					"metrics_region": "us-east-1",
				},
			},
		}

		factoryCalled := false
		cwFactory := func(targetRegion string) CloudWatchMetricAPI {
			factoryCalled = true
			return mockCW
		}

		EmitMetrics(context.Background(), cwFactory, status, "production", 100, 1, int64(1024), []string{"arn:aws:alb:1"})

		if factoryCalled {
			t.Error("expected cwFactory NOT to be called when current region == central region")
		}
		if len(mockCW.calls) != 0 {
			t.Errorf("expected 0 SDK calls for same-region, got %d", len(mockCW.calls))
		}
	})

	t.Run("CrossRegion_InvokesSDKCallWithCentralRegion", func(t *testing.T) {
		t.Setenv("AWS_REGION", "ap-southeast-1")
		mockCW := &mockCloudWatchMetricAPI{}

		status := &ValidationStatus{
			Valid:        true,
			StatusReason: "valid",
			Claims: &Claims{
				ID:   "lic_cross_reg",
				Plan: TierEnterprise,
				Metadata: map[string]string{
					"metrics_region": "us-east-1",
				},
			},
		}

		var targetRegionReceived string
		cwFactory := func(targetRegion string) CloudWatchMetricAPI {
			targetRegionReceived = targetRegion
			return mockCW
		}

		EmitMetrics(context.Background(), cwFactory, status, "production", 200, 2, int64(2048), []string{"arn:aws:alb:2"})

		if targetRegionReceived != "us-east-1" {
			t.Errorf("cwFactory received targetRegion %q, want us-east-1", targetRegionReceived)
		}
		if len(mockCW.calls) == 0 {
			t.Error("expected cross-region SDK calls to be made, got 0")
		}
	})
}

func TestLimits_QuotasAndAccessors(t *testing.T) {
	t.Run("JSONUnmarshalAndAccessors", func(t *testing.T) {
		payload := []byte(`{
			"max_resources": 50,
			"max_accounts": 5,
			"max_monthly_gb": 20000,
			"max_container_records": 100000,
			"custom_limit": 999
		}`)

		var l Limits
		if err := json.Unmarshal(payload, &l); err != nil {
			t.Fatalf("failed to unmarshal Limits: %v", err)
		}

		if l.MaxResources != 50 {
			t.Errorf("expected MaxResources=50, got %d", l.MaxResources)
		}
		if l.MaxAccounts != 5 {
			t.Errorf("expected MaxAccounts=5, got %d", l.MaxAccounts)
		}
		if l.MaxMonthlyGB != 20000 {
			t.Errorf("expected MaxMonthlyGB=20000, got %d", l.MaxMonthlyGB)
		}
		if l.MaxContainerRecords != 100000 {
			t.Errorf("expected MaxContainerRecords=100000, got %d", l.MaxContainerRecords)
		}
		if l.Raw["custom_limit"] != 999 {
			t.Errorf("expected Raw[custom_limit]=999, got %d", l.Raw["custom_limit"])
		}

		claims := &Claims{
			Limits: &l,
		}
		if mr := GetMaxResources(claims); mr != 50 {
			t.Errorf("expected GetMaxResources=50, got %d", mr)
		}
		if ma := GetMaxAccounts(claims); ma != 5 {
			t.Errorf("expected GetMaxAccounts=5, got %d", ma)
		}
		if mgb := GetMaxMonthlyGB(claims); mgb != 20000 {
			t.Errorf("expected GetMaxMonthlyGB=20000, got %d", mgb)
		}
	})

	t.Run("NilAndEmptyLimits", func(t *testing.T) {
		if GetMaxResources(nil) != 0 {
			t.Errorf("expected 0 for nil claims")
		}
		if GetMaxAccounts(nil) != 0 {
			t.Errorf("expected 0 for nil claims")
		}
		if GetMaxMonthlyGB(nil) != 0 {
			t.Errorf("expected 0 for nil claims")
		}

		emptyClaims := &Claims{}
		if GetMaxResources(emptyClaims) != 0 {
			t.Errorf("expected 0 for empty claims")
		}
		if GetMaxAccounts(emptyClaims) != 0 {
			t.Errorf("expected 0 for empty claims")
		}
		if GetMaxMonthlyGB(emptyClaims) != 0 {
			t.Errorf("expected 0 for empty claims")
		}
	})

	t.Run("JSONMarshalRoundTrip", func(t *testing.T) {
		l := Limits{
			MaxResources:        15,
			MaxAccounts:         2,
			MaxMonthlyGB:        5000,
			MaxContainerRecords: 50000,
			Raw: map[string]int64{
				"custom_val": 42,
			},
		}

		data, err := json.Marshal(&l)
		if err != nil {
			t.Fatalf("failed to marshal Limits: %v", err)
		}

		var roundTrip Limits
		if err := json.Unmarshal(data, &roundTrip); err != nil {
			t.Fatalf("failed to unmarshal roundtrip: %v", err)
		}

		if roundTrip.MaxResources != 15 {
			t.Errorf("expected MaxResources=15, got %d", roundTrip.MaxResources)
		}
		if roundTrip.MaxAccounts != 2 {
			t.Errorf("expected MaxAccounts=2, got %d", roundTrip.MaxAccounts)
		}
		if roundTrip.MaxMonthlyGB != 5000 {
			t.Errorf("expected MaxMonthlyGB=5000, got %d", roundTrip.MaxMonthlyGB)
		}
		if roundTrip.Raw["custom_val"] != 42 {
			t.Errorf("expected Raw[custom_val]=42, got %d", roundTrip.Raw["custom_val"])
		}
	})
}

func TestPublicKeyOverrideHardening(t *testing.T) {
	// Generate an untrusted rogue Ed25519 key pair
	roguePub, roguePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate rogue key: %v", err)
	}
	roguePubB64 := base64.StdEncoding.EncodeToString(roguePub)

	// Attempt to override the embedded public key using environment variables
	t.Setenv("DIVMORA_PUBLIC_KEY", roguePubB64)
	t.Setenv("DIVMORA_PUBLIC_KEYS_PEM", roguePubB64)

	// Ensure caches are cleared
	ResetDefaultValidator()
	ResetVerificationPublicKey()

	// 1. Verify GetVerificationPublicKey() returns the embedded key, NOT the rogue key
	pubKey, err := GetVerificationPublicKey()
	if err != nil {
		t.Fatalf("GetVerificationPublicKey failed: %v", err)
	}
	if string(pubKey) == string(roguePub) {
		t.Fatal("SECURITY VULNERABILITY: GetVerificationPublicKey() accepted attacker key from DIVMORA_PUBLIC_KEY environment variable")
	}

	// 2. Verify GetVerificationKeyRing() returns the embedded key
	ring, err := GetVerificationKeyRing()
	if err != nil {
		t.Fatalf("GetVerificationKeyRing failed: %v", err)
	}
	if ring.Primary() == nil || string(ring.Primary().PublicKey) == string(roguePub) {
		t.Fatal("SECURITY VULNERABILITY: GetVerificationKeyRing() accepted attacker key from DIVMORA_PUBLIC_KEY environment variable")
	}

	// 3. Verify that a license token signed with the rogue key FAILS cryptographic verification
	now := time.Now().UTC()
	claims := &Claims{
		ID: "lic_forged_enterprise",
		Customer: Customer{
			Name: "Attacker Organization",
		},
		Product:   "otel-aws-log-processor",
		Plan:      TierEnterprise,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
	}
	forgedToken := signTestToken(claims, roguePriv)

	status, err := ParseAndVerifyAt(forgedToken, nil, now)
	if err == nil && (status != nil && status.Valid) {
		t.Fatal("SECURITY VULNERABILITY: ParseAndVerifyAt accepted forged token signed with rogue key via DIVMORA_PUBLIC_KEY")
	}

	// 4. Verify programmatic override for tests via SetVerificationPublicKey still works
	SetVerificationPublicKey(testPubKey)
	defer ResetVerificationPublicKey()

	testToken := signTestToken(claims, testPrivKey)
	validStatus, err := ParseAndVerifyAt(testToken, nil, now)
	if err != nil || validStatus == nil || !validStatus.Valid {
		t.Fatalf("expected programmatic override to succeed, got err: %v", err)
	}
}

func TestDetectProductionIndicators(t *testing.T) {
	tests := []struct {
		name          string
		opts          EnforcementOptions
		envLambdaFn   string
		wantMatched   bool
		wantIndicator string
	}{
		// S3 Bucket matching
		{
			name:          "BucketWithProdPrefix",
			opts:          EnforcementOptions{BucketName: "prod-access-logs"},
			wantMatched:   true,
			wantIndicator: "prod",
		},
		{
			name:          "BucketWithProdSuffix",
			opts:          EnforcementOptions{BucketName: "my-app-prod"},
			wantMatched:   true,
			wantIndicator: "prod",
		},
		{
			name:          "BucketWithProdDelimited",
			opts:          EnforcementOptions{BucketName: "company-prod-alb-logs"},
			wantMatched:   true,
			wantIndicator: "prod",
		},
		{
			name:          "BucketWithProduction",
			opts:          EnforcementOptions{BucketName: "production-waf-logs"},
			wantMatched:   true,
			wantIndicator: "production",
		},
		{
			name:          "BucketWithLive",
			opts:          EnforcementOptions{BucketName: "live-traffic-bucket"},
			wantMatched:   true,
			wantIndicator: "live",
		},
		{
			name:          "BucketWithPrdDot",
			opts:          EnforcementOptions{BucketName: "api.prd.logs"},
			wantMatched:   true,
			wantIndicator: "prd",
		},
		// Benign non-prod substrings (must NOT match)
		{
			name:        "BenignProductCatalog",
			opts:        EnforcementOptions{BucketName: "product-catalog-logs"},
			wantMatched: false,
		},
		{
			name:        "BenignDeliveryService",
			opts:        EnforcementOptions{BucketName: "delivery-service-alb"},
			wantMatched: false,
		},
		{
			name:        "BenignReproduction",
			opts:        EnforcementOptions{BucketName: "reproduction-logs"},
			wantMatched: false,
		},
		{
			name:        "BenignDevBucket",
			opts:        EnforcementOptions{BucketName: "my-dev-bucket"},
			wantMatched: false,
		},
		{
			name:        "BenignStagingBucket",
			opts:        EnforcementOptions{BucketName: "staging-alb-logs"},
			wantMatched: false,
		},
		// AWS Lambda Function Name
		{
			name:          "LambdaFunctionNameProd",
			envLambdaFn:   "otel-log-processor-prod",
			wantMatched:   true,
			wantIndicator: "prod",
		},
		{
			name:          "LambdaFunctionNameProduction",
			envLambdaFn:   "production-log-processor",
			wantMatched:   true,
			wantIndicator: "production",
		},
		{
			name:        "LambdaFunctionNameDev",
			envLambdaFn: "processor-dev",
			wantMatched: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envLambdaFn != "" {
				t.Setenv("AWS_LAMBDA_FUNCTION_NAME", tc.envLambdaFn)
			} else {
				t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "")
			}

			matched, reason := DetectProductionIndicators(tc.opts)
			if matched != tc.wantMatched {
				t.Errorf("DetectProductionIndicators() matched = %v, want %v (reason: %s)", matched, tc.wantMatched, reason)
			}
			if tc.wantMatched && tc.wantIndicator != "" && !strings.Contains(reason, tc.wantIndicator) {
				t.Errorf("expected reason to contain '%s', got '%s'", tc.wantIndicator, reason)
			}
		})
	}

	// Context ARN matching
	t.Run("LambdaContextARNProd", func(t *testing.T) {
		t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "")
		lc := &lambdacontext.LambdaContext{
			InvokedFunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:processor-prod",
		}
		ctx := lambdacontext.NewContext(context.Background(), lc)
		opts := EnforcementOptions{Context: ctx}

		matched, reason := DetectProductionIndicators(opts)
		if !matched {
			t.Errorf("expected matched=true for prod ARN, got false")
		}
		if !strings.Contains(reason, "prod") {
			t.Errorf("expected reason to contain 'prod', got %s", reason)
		}
	})
}

func TestEnforce_EnvironmentVariableSpoofing_StrictMode(t *testing.T) {
	// 1. Spoofing via BucketName in strict mode without license
	opts := EnforcementOptions{
		Environment:     "dev",
		BucketName:      "company-prod-alb-logs",
		EnforcementMode: "strict",
	}

	status, err := Enforce(opts)
	if err == nil {
		t.Fatal("expected error in strict mode when production indicators detected, got nil")
	}
	if !errors.Is(err, ErrCommercialLicenseRequired) {
		t.Errorf("expected ErrCommercialLicenseRequired, got: %v", err)
	}
	if status == nil || status.Valid {
		t.Errorf("expected status.Valid=false, got: %v", status)
	}
	if status.StatusReason != "unlicensed_production" {
		t.Errorf("expected StatusReason=unlicensed_production, got: %s", status.StatusReason)
	}

	// 2. Spoofing via AWS_LAMBDA_FUNCTION_NAME in strict mode
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "otel-processor-prod")
	opts2 := EnforcementOptions{
		Environment:     "development",
		BucketName:      "my-dev-bucket",
		EnforcementMode: "strict",
	}

	status2, err2 := Enforce(opts2)
	if err2 == nil {
		t.Fatal("expected error in strict mode when Lambda function name has prod indicator, got nil")
	}
	if !errors.Is(err2, ErrCommercialLicenseRequired) {
		t.Errorf("expected ErrCommercialLicenseRequired, got: %v", err2)
	}
	if status2 == nil || status2.Valid {
		t.Errorf("expected status.Valid=false")
	}

	// 3. Spoofing via InvokedFunctionArn in strict mode
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "")
	lc := &lambdacontext.LambdaContext{
		InvokedFunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:app-production-handler",
	}
	ctx := lambdacontext.NewContext(context.Background(), lc)
	opts3 := EnforcementOptions{
		Context:         ctx,
		Environment:     "staging",
		EnforcementMode: "strict",
	}

	status3, err3 := Enforce(opts3)
	if err3 == nil {
		t.Fatal("expected error in strict mode when Context ARN has production indicator, got nil")
	}
	if !errors.Is(err3, ErrCommercialLicenseRequired) {
		t.Errorf("expected ErrCommercialLicenseRequired, got: %v", err3)
	}
	if status3 == nil || status3.Valid {
		t.Errorf("expected status.Valid=false")
	}
}

func TestEnforce_EnvironmentVariableSpoofing_WarnMode(t *testing.T) {
	opts := EnforcementOptions{
		Environment:     "dev",
		BucketName:      "company-prod-alb-logs",
		EnforcementMode: "warn",
	}

	status, err := Enforce(opts)
	if err != nil {
		t.Fatalf("expected nil error in warn mode, got: %v", err)
	}
	if !status.Valid {
		t.Errorf("expected status.Valid=true in warn mode")
	}
	if status.StatusReason != "suspected_production" {
		t.Errorf("expected StatusReason=suspected_production, got: %s", status.StatusReason)
	}

	// Verify EMF metrics reflect license violation
	emf := BuildEMFPayload(status, "dev", 100)
	if emf == nil {
		t.Fatal("expected non-nil EMF payload")
	}
	if emf["LicenseViolations"] != 1 {
		t.Errorf("expected LicenseViolations=1 for suspected_production, got: %v", emf["LicenseViolations"])
	}
	if emf["Status"] != "suspected_production" {
		t.Errorf("expected Status=suspected_production, got: %v", emf["Status"])
	}

	// Verify OpenTelemetry resource attributes reflect suspected_production
	attrs := AppendLicenseAttributes(nil, status, "dev", "123456789012")
	var statusAttr string
	for _, a := range attrs {
		if a.Key == "divmora.license.status" && a.Value.StringValue != nil {
			statusAttr = *a.Value.StringValue
		}
	}
	if statusAttr != "suspected_production" {
		t.Errorf("expected divmora.license.status=suspected_production, got: %s", statusAttr)
	}
}

func TestEnforce_EnvironmentVariableSpoofing_CommercialLicenseProvided(t *testing.T) {
	SetVerificationPublicKey(testPubKey)
	defer ResetVerificationPublicKey()

	now := time.Now().UTC()
	claims := &Claims{
		ID: "lic_comm_123",
		Customer: Customer{
			Name: "Acme Corp",
		},
		Product:   "otel-aws-log-processor",
		Plan:      TierEnterprise,
		Scope:     &Scope{Accounts: []string{"123456789012"}},
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
	}
	token := signTestToken(claims, testPrivKey)

	// Even if declared as "dev", when production indicators are present and a commercial token is provided,
	// it evaluates and verifies against the commercial token
	opts := EnforcementOptions{
		Environment:     "dev",
		BucketName:      "company-prod-alb-logs",
		LicenseKey:      token,
		CallerAccountID: "123456789012",
		EnforcementMode: "strict",
		EvaluationTime:  now,
	}

	status, err := Enforce(opts)
	if err != nil {
		t.Fatalf("unexpected error with valid commercial token: %v", err)
	}
	if !status.Valid {
		t.Errorf("expected valid=true with valid commercial token")
	}
	if status.StatusReason != "valid" {
		t.Errorf("expected status=valid, got: %s", status.StatusReason)
	}
}

func TestEnforce_NonProductionFairUseStrictCeiling(t *testing.T) {
	quotaTracker := NewQuotaTracker()

	// 1. Single-batch density ceiling exceeded in strict mode
	denseOpts := EnforcementOptions{
		Environment:      "development",
		BatchRecordCount: 15_000, // exceeds 10,000 ceiling
		QuotaTracker:     quotaTracker,
		EnforcementMode:  "strict",
	}

	status, err := Enforce(denseOpts)
	if err == nil {
		t.Fatal("expected error in strict mode when fair-use density is exceeded, got nil")
	}
	if !errors.Is(err, ErrResourceQuotaExceeded) {
		t.Errorf("expected ErrResourceQuotaExceeded, got: %v", err)
	}
	if status == nil || status.Valid {
		t.Errorf("expected status.Valid=false")
	}
	if !status.QuotaExceeded {
		t.Errorf("expected QuotaExceeded=true")
	}

	// 2. Container cumulative quota exceeded in strict mode
	quotaTracker2 := &QuotaTracker{
		maxBatchRecords:     10_000,
		maxContainerRecords: 1_000,
	}
	quotaTracker2.RecordAndCheckContainerQuota(1_500)

	contOpts := EnforcementOptions{
		Environment:      "test",
		BatchRecordCount: 100,
		QuotaTracker:     quotaTracker2,
		EnforcementMode:  "strict",
	}

	status2, err2 := Enforce(contOpts)
	if err2 == nil {
		t.Fatal("expected error in strict mode when container quota exceeded, got nil")
	}
	if !errors.Is(err2, ErrResourceQuotaExceeded) {
		t.Errorf("expected ErrResourceQuotaExceeded, got: %v", err2)
	}
	if status2 == nil || status2.Valid {
		t.Errorf("expected status.Valid=false")
	}

	// 3. Normal non-production batch within limits in strict mode
	normalOpts := EnforcementOptions{
		Environment:      "development",
		BatchRecordCount: 500,
		QuotaTracker:     NewQuotaTracker(),
		EnforcementMode:  "strict",
	}

	status3, err3 := Enforce(normalOpts)
	if err3 != nil {
		t.Fatalf("unexpected error for normal non-prod batch in strict mode: %v", err3)
	}
	if !status3.Valid {
		t.Errorf("expected Valid=true")
	}
	if status3.StatusReason != "non_prod_free" {
		t.Errorf("expected StatusReason=non_prod_free, got: %s", status3.StatusReason)
	}
}

func TestPreflightEnforce_EnvironmentVariableSpoofing(t *testing.T) {
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "otel-processor-prod")

	opts := EnforcementOptions{
		Environment:     "dev",
		EnforcementMode: "strict",
	}

	status, err := PreflightEnforce(opts)
	if err == nil {
		t.Fatal("expected PreflightEnforce to fail in strict mode when Lambda function has prod indicator")
	}
	if !errors.Is(err, ErrCommercialLicenseRequired) {
		t.Errorf("expected ErrCommercialLicenseRequired, got: %v", err)
	}
	if status == nil || status.Valid {
		t.Errorf("expected status.Valid=false")
	}
}

func TestQuotaTracker_CeilingTamperResistance(t *testing.T) {
	// 1. Attempt to exploit loophole by inflating ceilings via environment variables
	t.Setenv("DIVMORA_NON_PROD_MAX_BATCH", "999999999")
	t.Setenv("DIVMORA_NON_PROD_MAX_CONTAINER", "999999999")

	qt := NewQuotaTracker()
	if qt.maxBatchRecords != DefaultMaxNonProdBatchRecords {
		t.Errorf("expected maxBatchRecords to be clamped to %d, got %d", DefaultMaxNonProdBatchRecords, qt.maxBatchRecords)
	}
	if qt.maxContainerRecords != DefaultMaxNonProdContainerRecords {
		t.Errorf("expected maxContainerRecords to be clamped to %d, got %d", DefaultMaxNonProdContainerRecords, qt.maxContainerRecords)
	}

	// 2. Permitted tightening: environment variables can lower limits for testing
	t.Setenv("DIVMORA_NON_PROD_MAX_BATCH", "50")
	t.Setenv("DIVMORA_NON_PROD_MAX_CONTAINER", "100")

	qtTight := NewQuotaTracker()
	if qtTight.maxBatchRecords != 50 {
		t.Errorf("expected maxBatchRecords=50, got %d", qtTight.maxBatchRecords)
	}
	if qtTight.maxContainerRecords != 100 {
		t.Errorf("expected maxContainerRecords=100, got %d", qtTight.maxContainerRecords)
	}
}

func TestEnforce_CommercialLicenseInDev_Valid(t *testing.T) {
	SetVerificationPublicKey(testPubKey)
	defer ResetVerificationPublicKey()

	now := time.Now().UTC()
	claims := &Claims{
		ID: "lic_dev_test_1",
		Customer: Customer{
			Name:  "Test Dev Customer",
			OrgID: "org_dev_test",
		},
		Product:   "otel-aws-log-processor",
		Plan:      TierEnterprise,
		Scope:     &Scope{Accounts: []string{"111122223333"}},
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
	}
	token := signTestToken(claims, testPrivKey)

	// In a pure dev environment with NO production indicators,
	// providing a valid commercial license key validates as commercial and waives non-prod 10k batch limits
	opts := EnforcementOptions{
		Environment:      "dev",
		BucketName:       "my-dev-alb-logs-bucket",
		LicenseKey:       token,
		CallerAccountID:  "111122223333",
		BatchRecordCount: 15_000, // exceeds non-prod ceiling of 10k
		QuotaTracker:     NewQuotaTracker(),
		EnforcementMode:  "strict",
		EvaluationTime:   now,
	}

	status, err := Enforce(opts)
	if err != nil {
		t.Fatalf("unexpected error with valid commercial token in dev: %v", err)
	}
	if !status.Valid {
		t.Errorf("expected valid=true")
	}
	if status.StatusReason != "valid" {
		t.Errorf("expected status=valid, got: %s", status.StatusReason)
	}
	if status.Claims == nil || status.Claims.Plan != TierEnterprise {
		t.Errorf("expected Enterprise claims attached")
	}

	attrs := AppendLicenseAttributes(nil, status, "dev", "111122223333")
	var tierAttr, idAttr string
	for _, a := range attrs {
		if a.Key == "divmora.license.tier" && a.Value.StringValue != nil {
			tierAttr = *a.Value.StringValue
		}
		if a.Key == "divmora.license.id" && a.Value.StringValue != nil {
			idAttr = *a.Value.StringValue
		}
	}
	if tierAttr != TierEnterprise {
		t.Errorf("expected divmora.license.tier=enterprise, got: %s", tierAttr)
	}
	if idAttr != "lic_dev_test_1" {
		t.Errorf("expected divmora.license.id=lic_dev_test_1, got: %s", idAttr)
	}
}

func TestEnforce_CommercialLicenseInDev_InvalidToken(t *testing.T) {
	SetVerificationPublicKey(testPubKey)
	defer ResetVerificationPublicKey()

	badToken := "eyJhbGciOiJFZERTQSI...corrupted_dev_token"

	// 1. Strict mode: fails fast so developers know their license key is invalid
	strictOpts := EnforcementOptions{
		Environment:     "dev",
		BucketName:      "my-dev-alb-logs",
		LicenseKey:      badToken,
		EnforcementMode: "strict",
	}
	statusStrict, errStrict := Enforce(strictOpts)
	if errStrict == nil {
		t.Fatal("expected invalid token in dev strict mode to return an error")
	}
	if statusStrict == nil || statusStrict.Valid {
		t.Errorf("expected valid=false in strict mode")
	}

	// 2. Warn mode: logs warning and gracefully falls back to non_prod_free under BSL 1.1
	warnOpts := EnforcementOptions{
		Environment:     "dev",
		BucketName:      "my-dev-alb-logs",
		LicenseKey:      badToken,
		EnforcementMode: "warn",
	}
	statusWarn, errWarn := Enforce(warnOpts)
	if errWarn != nil {
		t.Fatalf("unexpected error in warn mode fallback: %v", errWarn)
	}
	if !statusWarn.Valid {
		t.Errorf("expected valid=true in warn mode fallback")
	}
	if statusWarn.StatusReason != "non_prod_free" {
		t.Errorf("expected status=non_prod_free in warn mode, got: %s", statusWarn.StatusReason)
	}
}

func TestEnforce_CommercialLicenseInDev_AccountMismatch(t *testing.T) {
	SetVerificationPublicKey(testPubKey)
	defer ResetVerificationPublicKey()

	now := time.Now().UTC()
	claims := &Claims{
		ID: "lic_dev_acct_test",
		Customer: Customer{
			Name: "Acme Corp",
		},
		Product:   "otel-aws-log-processor",
		Plan:      TierPro,
		Scope:     &Scope{Accounts: []string{"999999999999"}}, // only account 999999999999
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
	}
	token := signTestToken(claims, testPrivKey)

	// Caller is 111122223333 (mismatch)
	// 1. Strict mode fails
	strictOpts := EnforcementOptions{
		Environment:     "dev",
		BucketName:      "my-dev-alb-logs",
		LicenseKey:      token,
		CallerAccountID: "111122223333",
		EnforcementMode: "strict",
		EvaluationTime:  now,
	}
	_, errStrict := Enforce(strictOpts)
	if errStrict == nil {
		t.Fatal("expected account mismatch in dev strict mode to return an error")
	}

	// 2. Warn mode falls back to non_prod_free
	warnOpts := EnforcementOptions{
		Environment:     "dev",
		BucketName:      "my-dev-alb-logs",
		LicenseKey:      token,
		CallerAccountID: "111122223333",
		EnforcementMode: "warn",
		EvaluationTime:  now,
	}
	statusWarn, errWarn := Enforce(warnOpts)
	if errWarn != nil {
		t.Fatalf("unexpected error in warn mode fallback: %v", errWarn)
	}
	if !statusWarn.Valid || statusWarn.StatusReason != "non_prod_free" {
		t.Errorf("expected valid=true and status=non_prod_free, got valid=%v, status=%s", statusWarn.Valid, statusWarn.StatusReason)
	}
}

func TestEnforce_ProductionStrictModeDefault(t *testing.T) {
	// When EnforcementMode is empty and DIVMORA_LICENSE_MODE is unset or "auto",
	// production defaults strictly to strict mode (rejects unlicensed production)
	opts := EnforcementOptions{
		Environment:     "production",
		CallerAccountID: "123456789012",
	}

	status, err := Enforce(opts)
	if err == nil {
		t.Fatal("expected unlicensed production to fail by default under auto/strict enforcement")
	}
	if status == nil || status.Valid {
		t.Errorf("expected status.Valid=false")
	}
	if status.StatusReason != "unlicensed_production" {
		t.Errorf("expected StatusReason=unlicensed_production, got: %s", status.StatusReason)
	}
}

func TestEnforce_NonProductionMaxResources(t *testing.T) {
	generateARNs := func(n int) []string {
		arns := make([]string, n)
		for i := 0; i < n; i++ {
			arns[i] = fmt.Sprintf("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-%d/hash", i)
		}
		return arns
	}

	// 1. Within limit: 10 resources in non-production
	withinTracker := NewResourceTracker()
	withinOpts := EnforcementOptions{
		Environment:        "staging",
		SourceResourceARNs: generateARNs(10),
		ResourceTracker:    withinTracker,
		EnforcementMode:    "strict",
	}
	status1, err1 := Enforce(withinOpts)
	if err1 != nil {
		t.Fatalf("unexpected error for 10 resources in non-prod: %v", err1)
	}
	if !status1.Valid || status1.StatusReason != "non_prod_free" {
		t.Errorf("expected valid non_prod_free, got valid=%v, reason=%s", status1.Valid, status1.StatusReason)
	}

	// 2. Exceeding limit: 11 resources in non-production (warn mode)
	warnTracker := NewResourceTracker()
	warnOpts := EnforcementOptions{
		Environment:        "staging",
		SourceResourceARNs: generateARNs(11),
		ResourceTracker:    warnTracker,
		EnforcementMode:    "warn",
	}
	status2, err2 := Enforce(warnOpts)
	if err2 != nil {
		t.Fatalf("unexpected error in warn mode: %v", err2)
	}
	if !status2.Valid {
		t.Errorf("expected valid=true in warn mode")
	}
	if !status2.QuotaExceeded || status2.StatusReason != "quota_exceeded" {
		t.Errorf("expected quota_exceeded, got QuotaExceeded=%v, reason=%s", status2.QuotaExceeded, status2.StatusReason)
	}

	// 3. Exceeding limit: 11 resources in non-production (strict mode)
	strictTracker := NewResourceTracker()
	strictOpts := EnforcementOptions{
		Environment:        "staging",
		SourceResourceARNs: generateARNs(11),
		ResourceTracker:    strictTracker,
		EnforcementMode:    "strict",
	}
	status3, err3 := Enforce(strictOpts)
	if err3 == nil {
		t.Fatal("expected error in strict mode when exceeding 10 resources in non-prod")
	}
	if !errors.Is(err3, ErrResourceQuotaExceeded) {
		t.Errorf("expected ErrResourceQuotaExceeded, got: %v", err3)
	}
	if status3 == nil || status3.Valid {
		t.Errorf("expected status3.Valid=false")
	}

	// 4. Exceeding 10 resources in non-production WITH a valid commercial Pro license (25 resources)
	SetVerificationPublicKey(testPubKey)
	defer ResetVerificationPublicKey()

	now := time.Now().UTC()
	claims := &Claims{
		ID: "lic_dev_25_res",
		Customer: Customer{
			Name: "Pro Customer",
		},
		Product:   "otel-aws-log-processor",
		Plan:      TierPro,
		Scope:     &Scope{Accounts: []string{"123456789012"}},
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
		Limits: &Limits{
			MaxResources: 25,
		},
	}
	token := signTestToken(claims, testPrivKey)

	proTracker := NewResourceTracker()
	proOpts := EnforcementOptions{
		Environment:        "staging",
		BucketName:         "my-staging-bucket",
		LicenseKey:         token,
		CallerAccountID:    "123456789012",
		SourceResourceARNs: generateARNs(15), // 15 resources (>10 non-prod cap, but <25 pro quota)
		ResourceTracker:    proTracker,
		EnforcementMode:    "strict",
		EvaluationTime:     now,
	}
	statusPro, errPro := Enforce(proOpts)
	if errPro != nil {
		t.Fatalf("unexpected error for commercial license with 15 resources: %v", errPro)
	}
	if !statusPro.Valid || statusPro.StatusReason != "valid" {
		t.Errorf("expected commercial license to authorize 15 resources: valid=%v, reason=%s", statusPro.Valid, statusPro.StatusReason)
	}
}

func TestEnforce_MultiProjectIsolation_NonProd(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	mockCW := newMockCloudWatchRegistryAPI()
	reg := NewCloudWatchRegistry(mockCW)

	// Project A: payments in dev with 6 ALBs
	arnsA := []string{
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/payments-alb-1/111",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/payments-alb-2/222",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/payments-alb-3/333",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/payments-alb-4/444",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/payments-alb-5/555",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/payments-alb-6/666",
	}
	optsA := EnforcementOptions{
		Environment:        "development",
		ProjectName:        "payments",
		BucketName:         "dev-payments-logs",
		SourceResourceARNs: arnsA,
		CloudWatchRegistry: reg,
		EnforcementMode:    "strict",
		EvaluationTime:     now,
	}
	statusA, errA := Enforce(optsA)
	if errA != nil {
		t.Fatalf("unexpected error for project A: %v", errA)
	}
	if !statusA.Valid || statusA.StatusReason != "non_prod_free" {
		t.Errorf("expected project A to succeed as non_prod_free, got status: %+v", statusA)
	}

	// Project B: identity in dev with 6 ALBs (total in dev across projects is 12)
	arnsB := []string{
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/identity-alb-1/aaa",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/identity-alb-2/bbb",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/identity-alb-3/ccc",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/identity-alb-4/ddd",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/identity-alb-5/eee",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/identity-alb-6/fff",
	}
	optsB := EnforcementOptions{
		Environment:        "development",
		ProjectName:        "identity",
		BucketName:         "dev-identity-logs",
		SourceResourceARNs: arnsB,
		CloudWatchRegistry: reg,
		EnforcementMode:    "strict",
		EvaluationTime:     now,
	}
	statusB, errB := Enforce(optsB)
	if errB != nil {
		t.Fatalf("unexpected error for project B: %v (multi-project isolation failed)", errB)
	}
	if !statusB.Valid || statusB.StatusReason != "non_prod_free" {
		t.Errorf("expected project B to succeed as non_prod_free, got status: %+v", statusB)
	}
}

func TestEnforce_CommercialProjectScopedLicense(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	claims := &Claims{
		ID: "lic_project_payments",
		Customer: Customer{
			Name:  "Acme Corp",
			OrgID: "org_acme",
		},
		Product:   "otel-aws-log-processor",
		Plan:      TierPro,
		Scope:     &Scope{Accounts: []string{"123456789012"}},
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
		Metadata: map[string]string{
			"project": "payments",
		},
	}
	token := signTestToken(claims, testPrivKey)

	// 1. Matching project in production -> valid
	optsMatch := EnforcementOptions{
		Environment:     "production",
		ProjectName:     "payments",
		BucketName:      "payments-prod-bucket",
		LicenseKey:      token,
		PublicKey:       testPubKey,
		CallerAccountID: "123456789012",
		EnforcementMode: "strict",
		EvaluationTime:  now,
	}
	statusMatch, errMatch := Enforce(optsMatch)
	if errMatch != nil || !statusMatch.Valid {
		t.Fatalf("expected matching project to succeed, got status: %+v, err: %v", statusMatch, errMatch)
	}

	// 2. Mismatched project in production strict mode -> fails
	optsMismatch := EnforcementOptions{
		Environment:     "production",
		ProjectName:     "analytics",
		BucketName:      "analytics-prod-bucket",
		LicenseKey:      token,
		PublicKey:       testPubKey,
		CallerAccountID: "123456789012",
		EnforcementMode: "strict",
		EvaluationTime:  now,
	}
	statusMismatch, errMismatch := Enforce(optsMismatch)
	if errMismatch == nil {
		t.Fatalf("expected project mismatch error in strict mode, got nil")
	}
	if !errors.Is(errMismatch, liblicense.ErrScopeMismatch) {
		t.Errorf("expected ErrScopeMismatch, got %v", errMismatch)
	}
	if statusMismatch.Valid || statusMismatch.StatusReason != "project_mismatch" {
		t.Errorf("expected project_mismatch status, got %+v", statusMismatch)
	}

	// 3. Mismatched project in non-prod -> falls back to non_prod_free
	optsNonProdMismatch := EnforcementOptions{
		Environment:     "development",
		ProjectName:     "analytics",
		BucketName:      "dev-analytics-logs",
		LicenseKey:      token,
		PublicKey:       testPubKey,
		CallerAccountID: "123456789012",
		EnforcementMode: "warn",
		EvaluationTime:  now,
	}
	statusNonProd, errNonProd := Enforce(optsNonProdMismatch)
	if errNonProd != nil {
		t.Fatalf("expected non-prod fallback to succeed, got %v", errNonProd)
	}
	if !statusNonProd.Valid || statusNonProd.StatusReason != "non_prod_free" {
		t.Errorf("expected non_prod_free fallback, got %+v", statusNonProd)
	}
}

func TestDetectProductionIndicators_ProjectNameAndResourceARNs(t *testing.T) {
	// 1. Production keyword in ProjectName
	hasProd, reason := DetectProductionIndicators(EnforcementOptions{
		Environment: "development",
		ProjectName: "payments-prod-worker",
	})
	if !hasProd {
		t.Errorf("expected production indicator from ProjectName, got false")
	}
	if !strings.Contains(reason, "Project name 'payments-prod-worker' contains production indicator") {
		t.Errorf("unexpected reason: %s", reason)
	}

	// 2. Production keyword in SourceResourceARNs
	hasProdARN, reasonARN := DetectProductionIndicators(EnforcementOptions{
		Environment: "development",
		ProjectName: "payments-dev",
		SourceResourceARNs: []string{
			"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-checkout-alb/50dc6c495c0c9188",
		},
	})
	if !hasProdARN {
		t.Errorf("expected production indicator from SourceResourceARNs, got false")
	}
	if !strings.Contains(reasonARN, "Monitored resource") || !strings.Contains(reasonARN, "prod") {
		t.Errorf("unexpected reason: %s", reasonARN)
	}

	// 3. Clean non-prod ProjectName and ARNs
	cleanProd, _ := DetectProductionIndicators(EnforcementOptions{
		Environment: "development",
		ProjectName: "payments-dev",
		SourceResourceARNs: []string{
			"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/dev-checkout-alb/50dc6c495c0c9188",
		},
	})
	if cleanProd {
		t.Errorf("expected clean dev options not to trigger production indicator")
	}
}

func TestAppendLicenseAttributes_WithProject(t *testing.T) {
	status := &ValidationStatus{
		Valid:        true,
		StatusReason: "non_prod_free",
	}
	var attrs []model.OTelAttribute
	attrs = AppendLicenseAttributes(attrs, status, "development", "123456789012", "payments")

	foundProj := false
	for _, attr := range attrs {
		if attr.Key == "divmora.license.project" && attr.Value.StringValue != nil && *attr.Value.StringValue == "payments" {
			foundProj = true
			break
		}
	}
	if !foundProj {
		t.Errorf("expected divmora.license.project attribute to be stamped with 'payments'")
	}
}

func TestBuildEMFPayload_WithProject(t *testing.T) {
	t.Setenv("PROJECT_NAME", "checkout")
	defer t.Setenv("PROJECT_NAME", "")

	status := &ValidationStatus{
		Valid:        true,
		StatusReason: "valid",
	}
	payload := BuildEMFPayload(status, "production", 100, 5, int64(5000))
	if payload == nil {
		t.Fatalf("expected non-nil EMF payload")
	}
	if proj, ok := payload["Project"].(string); !ok || proj != "checkout" {
		t.Errorf("expected Project='checkout' in EMF payload, got %v", payload["Project"])
	}
}
