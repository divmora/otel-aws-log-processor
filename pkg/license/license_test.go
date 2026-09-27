package license

import (
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

func TestAllowedResources_PatternMatching(t *testing.T) {
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

func TestResourceQuota_StrictAndWarn(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	claims := &Claims{
		ID:        "lic_quota_test",
		Customer:  Customer{Name: "Quota Corp"},
		Product:   "otel-aws-log-processor",
		Plan:      TierPro,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
		Scope: &Scope{
			Accounts:         []string{"123456789012"},
			MaxResources:     2,
			AllowedResources: []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/*"},
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

	// Legacy token: only Accounts specified, MaxResources and AllowedResources omitted (MaxResources == 0)
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
		t.Error("expected IsResourceAllowed=true for legacy token without AllowedResources")
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
		Scope: &Scope{
			MaxResources: 25,
		},
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
		Scope: &Scope{
			Accounts:     []string{"123456789012"},
			MaxResources: 25,
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
