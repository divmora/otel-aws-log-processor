package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
