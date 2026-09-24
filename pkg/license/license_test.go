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
