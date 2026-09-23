package version_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/divmora/otel-aws-log-processor/pkg/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestReleaseKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func TestSignAndVerifyReleaseToken_Success(t *testing.T) {
	pub, priv := generateTestReleaseKeyPair(t)

	claims := &version.ReleaseClaims{
		Version:     "0.2.0",
		GitCommit:   "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
		BuildDate:   "2026-09-12T12:00:00Z",
		Authority:   "DIVMORA Technologies Release Authority",
		AuthorityID: "divmora-prod-release-1",
	}

	token, err := version.SignRelease(claims, priv)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Contains(t, token, ".")

	parsedClaims, err := version.ParseAndVerifyReleaseToken(token, pub)
	require.NoError(t, err)
	require.NotNil(t, parsedClaims)
	assert.Equal(t, "0.2.0", parsedClaims.Version)
	assert.Equal(t, "4b825dc642cb6eb9a060e54bf8d69288fbee4904", parsedClaims.GitCommit)
	assert.Equal(t, "2026-09-12T12:00:00Z", parsedClaims.BuildDate)
	assert.Equal(t, "DIVMORA Technologies Release Authority", parsedClaims.Authority)
}

func TestEvaluateProvenance_VerifiedOfficial(t *testing.T) {
	pub, priv := generateTestReleaseKeyPair(t)
	version.SetReleaseVerificationPublicKey(pub)
	defer version.ResetReleaseVerificationPublicKey()

	origVer := version.Version
	origCommit := version.GitCommit
	origDate := version.BuildDate
	origSig := version.ReleaseSignature
	defer func() {
		version.Version = origVer
		version.GitCommit = origCommit
		version.BuildDate = origDate
		version.ReleaseSignature = origSig
	}()

	version.Version = "0.2.0"
	version.GitCommit = "abcdef123456"
	version.BuildDate = "2026-09-12T12:00:00Z"

	claims := &version.ReleaseClaims{
		Version:   "0.2.0",
		GitCommit: "abcdef123456",
		BuildDate: "2026-09-12T12:00:00Z",
		Authority: "DIVMORA Technologies",
	}
	token, err := version.SignRelease(claims, priv)
	require.NoError(t, err)
	version.ReleaseSignature = token

	info := version.Get()
	require.True(t, info.Provenance.Verified)
	assert.Equal(t, version.ProvenanceVerifiedOfficial, info.Provenance.Status)
	assert.Equal(t, "DIVMORA Technologies", info.Provenance.Authority)
	assert.Empty(t, info.Provenance.Error)

	// Verified release converts to Apache 2.0 when Change Date passes
	changeDate, ok := info.ChangeDate()
	require.True(t, ok)
	assert.False(t, info.IsApacheConverted(changeDate.AddDate(0, 0, -1)))
	assert.True(t, info.IsApacheConverted(changeDate.AddDate(0, 0, 1)))
	assert.Equal(t, "Apache-2.0", info.License(changeDate.AddDate(0, 0, 1)))
}

func TestEvaluateProvenance_UnattestedCustomBuild(t *testing.T) {
	origVer := version.Version
	origCommit := version.GitCommit
	origDate := version.BuildDate
	origSig := version.ReleaseSignature
	defer func() {
		version.Version = origVer
		version.GitCommit = origCommit
		version.BuildDate = origDate
		version.ReleaseSignature = origSig
	}()

	version.Version = "0.2.0"
	version.GitCommit = "custom-commit"
	version.BuildDate = "2026-09-12T12:00:00Z"
	version.ReleaseSignature = "none"

	info := version.Get()
	assert.False(t, info.Provenance.Verified)
	assert.Equal(t, version.ProvenanceUnattestedCustom, info.Provenance.Status)

	// Unattested build NEVER converts to Apache 2.0 even if 4 years elapse
	fourYearsLater := time.Now().UTC().AddDate(4, 0, 0)
	assert.False(t, info.IsApacheConverted(fourYearsLater))
	assert.Equal(t, "BSL-1.1", info.License(fourYearsLater))
}

func TestEvaluateProvenance_TamperedMetadata(t *testing.T) {
	pub, priv := generateTestReleaseKeyPair(t)
	version.SetReleaseVerificationPublicKey(pub)
	defer version.ResetReleaseVerificationPublicKey()

	origVer := version.Version
	origCommit := version.GitCommit
	origDate := version.BuildDate
	origSig := version.ReleaseSignature
	defer func() {
		version.Version = origVer
		version.GitCommit = origCommit
		version.BuildDate = origDate
		version.ReleaseSignature = origSig
	}()

	claims := &version.ReleaseClaims{
		Version:   "0.2.0",
		GitCommit: "aaa111",
		BuildDate: "2026-09-12T12:00:00Z",
		Authority: "DIVMORA Technologies",
	}
	token, err := version.SignRelease(claims, priv)
	require.NoError(t, err)
	version.ReleaseSignature = token

	// Tamper 1: Version mismatch
	version.Version = "0.3.0"
	version.GitCommit = "aaa111"
	version.BuildDate = "2026-09-12T12:00:00Z"
	info := version.Get()
	assert.False(t, info.Provenance.Verified)
	assert.Equal(t, version.ProvenanceTamperedMetadata, info.Provenance.Status)
	assert.Contains(t, info.Provenance.Error, "Version mismatch")

	// Tamper 2: Commit mismatch
	version.Version = "0.2.0"
	version.GitCommit = "bbb222"
	info = version.Get()
	assert.False(t, info.Provenance.Verified)
	assert.Equal(t, version.ProvenanceTamperedMetadata, info.Provenance.Status)
	assert.Contains(t, info.Provenance.Error, "Commit mismatch")

	// Tamper 3: Date mismatch
	version.GitCommit = "aaa111"
	version.BuildDate = "2026-09-13T12:00:00Z"
	info = version.Get()
	assert.False(t, info.Provenance.Verified)
	assert.Equal(t, version.ProvenanceTamperedMetadata, info.Provenance.Status)
	assert.Contains(t, info.Provenance.Error, "Build date mismatch")
}

func TestEvaluateProvenance_TamperedSignature(t *testing.T) {
	pubWrong, _ := generateTestReleaseKeyPair(t)
	_, privSigner := generateTestReleaseKeyPair(t)

	version.SetReleaseVerificationPublicKey(pubWrong)
	defer version.ResetReleaseVerificationPublicKey()

	origSig := version.ReleaseSignature
	defer func() { version.ReleaseSignature = origSig }()

	claims := &version.ReleaseClaims{
		Version:   "0.2.0",
		GitCommit: "aaa111",
		BuildDate: "2026-09-12T12:00:00Z",
	}
	token, err := version.SignRelease(claims, privSigner)
	require.NoError(t, err)
	version.ReleaseSignature = token

	info := version.Get()
	assert.False(t, info.Provenance.Verified)
	assert.Equal(t, version.ProvenanceTamperedSignature, info.Provenance.Status)
}

func TestResolveReleaseSignature_SidecarFile(t *testing.T) {
	pub, priv := generateTestReleaseKeyPair(t)
	version.SetReleaseVerificationPublicKey(pub)
	defer version.ResetReleaseVerificationPublicKey()

	origSig := version.ReleaseSignature
	version.ReleaseSignature = "none"
	defer func() { version.ReleaseSignature = origSig }()

	claims := &version.ReleaseClaims{
		Version:   "0.2.0",
		GitCommit: "aaa111",
		BuildDate: "2026-09-12T12:00:00Z",
	}
	token, err := version.SignRelease(claims, priv)
	require.NoError(t, err)

	tempDir := t.TempDir()
	origWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tempDir))
	defer func() { _ = os.Chdir(origWd) }()

	// Write release.sig in working directory
	sigFile := filepath.Join(tempDir, "release.sig")
	require.NoError(t, os.WriteFile(sigFile, []byte(token), 0644))

	resolved, source := version.ResolveReleaseSignature()
	assert.Equal(t, token, resolved)
	assert.Contains(t, source, "sidecar file")
}

func TestResolveReleaseSignature_LambdaTaskRoot(t *testing.T) {
	origSig := version.ReleaseSignature
	version.ReleaseSignature = "none"
	defer func() { version.ReleaseSignature = origSig }()

	tempDir := t.TempDir()
	expectedToken := "DIVREL1.lambda.token.123"
	sigFile := filepath.Join(tempDir, "release.sig")
	require.NoError(t, os.WriteFile(sigFile, []byte(expectedToken), 0644))

	t.Setenv("LAMBDA_TASK_ROOT", tempDir)

	resolved, source := version.ResolveReleaseSignature()
	assert.Equal(t, expectedToken, resolved)
	assert.Contains(t, source, "sidecar file")
	assert.Contains(t, source, tempDir)
}

func TestSignAndVerifyReleaseToken_ArmoredPEM(t *testing.T) {
	pub, priv := generateTestReleaseKeyPair(t)

	claims := &version.ReleaseClaims{
		Product:     "otel-aws-log-processor",
		Version:     "0.2.0",
		GitCommit:   "1234567890abcdef",
		BuildDate:   "2026-09-16T12:00:00Z",
		Authority:   "DIVMORA Technologies Release Authority",
		AuthorityID: "key-prod-1",
	}

	armored, err := version.SignReleaseArmored(claims, priv)
	require.NoError(t, err)
	assert.Contains(t, armored, "-----BEGIN DIVMORA RELEASE ATTESTATION-----")
	assert.Contains(t, armored, "-----END DIVMORA RELEASE ATTESTATION-----")

	parsed, err := version.ParseAndVerifyReleaseToken(armored, pub)
	require.NoError(t, err)
	assert.Equal(t, "otel-aws-log-processor", parsed.Product)
	assert.Equal(t, "0.2.0", parsed.Version)
	assert.Equal(t, "1234567890abcdef", parsed.GitCommit)
	assert.Equal(t, "key-prod-1", parsed.AuthorityID)
}

func TestEvaluateProvenance_ProductMismatch(t *testing.T) {
	pub, priv := generateTestReleaseKeyPair(t)
	version.SetReleaseVerificationPublicKey(pub)
	defer version.ResetReleaseVerificationPublicKey()

	origVer := version.Version
	origCommit := version.GitCommit
	origDate := version.BuildDate
	origSig := version.ReleaseSignature
	defer func() {
		version.Version = origVer
		version.GitCommit = origCommit
		version.BuildDate = origDate
		version.ReleaseSignature = origSig
	}()

	version.Version = "0.2.0"
	version.GitCommit = "aaa111"
	version.BuildDate = "2026-09-16T12:00:00Z"

	// Signed for another product
	claims := &version.ReleaseClaims{
		Product:   "other-product-agent",
		Version:   "0.2.0",
		GitCommit: "aaa111",
		BuildDate: "2026-09-16T12:00:00Z",
	}
	token, err := version.SignRelease(claims, priv)
	require.NoError(t, err)
	version.ReleaseSignature = token

	info := version.Get()
	assert.False(t, info.Provenance.Verified)
	assert.Equal(t, version.ProvenanceTamperedMetadata, info.Provenance.Status)
	assert.Contains(t, info.Provenance.Error, "Product mismatch")
}

func TestEvaluateProvenance_RejectLegacyTwoPartToken(t *testing.T) {
	pub, priv := generateTestReleaseKeyPair(t)
	version.SetReleaseVerificationPublicKey(pub)
	defer version.ResetReleaseVerificationPublicKey()

	origVer := version.Version
	origCommit := version.GitCommit
	origDate := version.BuildDate
	origSig := version.ReleaseSignature
	defer func() {
		version.Version = origVer
		version.GitCommit = origCommit
		version.BuildDate = origDate
		version.ReleaseSignature = origSig
	}()

	version.Version = "0.2.0"
	version.GitCommit = "c0ffee"
	version.BuildDate = "2026-09-12T12:00:00Z"

	// Construct legacy un-prefixed 2-part token (<payloadB64>.<sigB64>)
	legacyPayload := `{"product":"otel-aws-log-processor","version":"0.2.0","git_commit":"c0ffee","build_date":"2026-09-12T12:00:00Z","authority":"DIVMORA Technologies"}`
	sig := ed25519.Sign(priv, []byte(legacyPayload))
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(legacyPayload))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	legacyToken := fmt.Sprintf("%s.%s", payloadB64, sigB64)

	version.ReleaseSignature = legacyToken

	info := version.Get()
	assert.False(t, info.Provenance.Verified)
	assert.Equal(t, version.ProvenanceTamperedSignature, info.Provenance.Status)
	assert.Contains(t, info.Provenance.Error, "malformed release token: expected canonical DIVREL1 compact token or armored PEM block")
}

func TestDefaultReleasePublicKey(t *testing.T) {
	assert.Equal(t, "K8GS3G93kHK5kfav+jxrLwZMIh710EWVyL0tvHLfE5A=", version.DefaultReleasePublicKeyBase64)

	pub, err := version.GetReleaseVerificationPublicKey()
	require.NoError(t, err)
	assert.Len(t, pub, ed25519.PublicKeySize)
	b64Key := base64.StdEncoding.EncodeToString(pub)
	assert.Equal(t, version.DefaultReleasePublicKeyBase64, b64Key)
}

func TestParseReleasePrivateKeyAndSigning(t *testing.T) {
	pub, priv := generateTestReleaseKeyPair(t)

	// 1. From 64-byte private key base64
	privB64 := base64.StdEncoding.EncodeToString(priv)
	parsedPriv, err := version.ParseReleasePrivateKey(privB64)
	require.NoError(t, err)
	assert.Equal(t, priv, parsedPriv)

	// 2. From 32-byte seed base64
	seed := priv.Seed()
	seedB64 := base64.StdEncoding.EncodeToString(seed)
	parsedFromSeed, err := version.ParseReleasePrivateKey(seedB64)
	require.NoError(t, err)
	assert.Equal(t, priv, parsedFromSeed)

	// 3. Via DIVMORA_RELEASE_PRIVATE_KEY environment variable
	t.Setenv("DIVMORA_RELEASE_PRIVATE_KEY", privB64)
	envPriv, err := version.GetReleaseSigningPrivateKey()
	require.NoError(t, err)
	assert.Equal(t, priv, envPriv)

	// 4. Sign release claims and verify against public key
	claims := &version.ReleaseClaims{
		Product:   "otel-aws-log-processor",
		Version:   "1.3.1",
		GitCommit: "fedcba987654",
		BuildDate: "2026-09-22T12:00:00Z",
		Authority: "DIVMORA Technologies Release Authority",
	}
	token, err := version.SignRelease(claims, envPriv)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	verifiedClaims, err := version.ParseAndVerifyReleaseToken(token, pub)
	require.NoError(t, err)
	assert.Equal(t, "1.3.1", verifiedClaims.Version)
	assert.Equal(t, "fedcba987654", verifiedClaims.GitCommit)
}
