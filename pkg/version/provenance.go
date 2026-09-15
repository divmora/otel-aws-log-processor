package version

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultReleasePublicKeyBase64 is the embedded production Ed25519 public verification key for DIVMORA Technologies.
const DefaultReleasePublicKeyBase64 = "FhmwiOvzcfqm0O1n62EAi101cOsWxDLM4rWE7Y0GbPs="

// ReleaseSignature holds the cryptographic release token injected at compile time via -ldflags:
// -X github.com/divmora/otel-aws-log-processor/pkg/version.ReleaseSignature=<token>
var ReleaseSignature = "none"

var (
	releaseKeyLock     sync.RWMutex
	releaseKeyOverride ed25519.PublicKey
)

// ProvenanceStatus indicates the cryptographic supply-chain verification state of the binary.
type ProvenanceStatus string

const (
	// ProvenanceVerifiedOfficial indicates the binary was officially compiled, attested, and signed by DIVMORA Technologies.
	ProvenanceVerifiedOfficial ProvenanceStatus = "VERIFIED_OFFICIAL_RELEASE"

	// ProvenanceUnattestedCustom indicates a community or custom compilation lacking an official DIVMORA release signature.
	ProvenanceUnattestedCustom ProvenanceStatus = "UNATTESTED_CUSTOM_BUILD"

	// ProvenanceTamperedMetadata indicates an official signature was provided, but compiled metadata (Version, Commit, or BuildDate) differs from the signed payload.
	ProvenanceTamperedMetadata ProvenanceStatus = "TAMPERED_METADATA"

	// ProvenanceTamperedSignature indicates the signature is corrupted or was signed with an unauthorized key.
	ProvenanceTamperedSignature ProvenanceStatus = "TAMPERED_SIGNATURE"
)

// ReleaseClaims represents the canonical metadata envelope signed by DIVMORA Technologies.
type ReleaseClaims struct {
	Version     string `json:"version"`
	GitCommit   string `json:"git_commit"`
	BuildDate   string `json:"build_date"`
	Authority   string `json:"authority"`
	AuthorityID string `json:"authority_id,omitempty"`
}

// ReleaseProvenance holds the verified release attestation state and claims.
type ReleaseProvenance struct {
	Status       ProvenanceStatus `json:"status"`
	Verified     bool             `json:"verified"`
	Authority    string           `json:"authority,omitempty"`
	AuthorityID  string           `json:"authority_id,omitempty"`
	Source       string           `json:"source,omitempty"`
	Error        string           `json:"error,omitempty"`
	SignedClaims *ReleaseClaims   `json:"signed_claims,omitempty"`
}

// SetReleaseVerificationPublicKey sets a programmatic override for the release public verification key (primarily used in tests).
func SetReleaseVerificationPublicKey(key ed25519.PublicKey) {
	releaseKeyLock.Lock()
	defer releaseKeyLock.Unlock()
	releaseKeyOverride = key
}

// ResetReleaseVerificationPublicKey resets the release public verification key override.
func ResetReleaseVerificationPublicKey() {
	releaseKeyLock.Lock()
	defer releaseKeyLock.Unlock()
	releaseKeyOverride = nil
}

// GetReleaseVerificationPublicKey resolves the public key used to verify release tokens.
// Resolution order:
// 1. In-memory programmatic override (via SetReleaseVerificationPublicKey).
// 2. DIVMORA_RELEASE_PUBLIC_KEY or DIVMORA_PUBLIC_KEY environment variable.
// 3. Embedded DefaultReleasePublicKeyBase64.
func GetReleaseVerificationPublicKey() (ed25519.PublicKey, error) {
	releaseKeyLock.RLock()
	if releaseKeyOverride != nil {
		defer releaseKeyLock.RUnlock()
		return releaseKeyOverride, nil
	}
	releaseKeyLock.RUnlock()

	keyStr := os.Getenv("DIVMORA_RELEASE_PUBLIC_KEY")
	if keyStr == "" {
		keyStr = os.Getenv("DIVMORA_PUBLIC_KEY")
	}
	if keyStr == "" {
		keyStr = DefaultReleasePublicKeyBase64
	}

	keyBytes, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		keyBytes, err = base64.RawURLEncoding.DecodeString(keyStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode release verification public key: %w", err)
		}
	}

	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid release verification public key size: expected %d bytes, got %d", ed25519.PublicKeySize, len(keyBytes))
	}

	return ed25519.PublicKey(keyBytes), nil
}

// SignRelease serializes and cryptographically signs a set of ReleaseClaims using an Ed25519 private key,
// returning a URL-safe Base64 token string formatted as "<payload>.<signature>".
func SignRelease(claims *ReleaseClaims, privKey ed25519.PrivateKey) (string, error) {
	if claims == nil {
		return "", errors.New("cannot sign nil release claims")
	}
	if len(privKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid Ed25519 private key size: expected %d bytes, got %d", ed25519.PrivateKeySize, len(privKey))
	}
	if claims.Authority == "" {
		claims.Authority = "DIVMORA Technologies Release Authority"
	}

	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to serialize release claims: %w", err)
	}

	sigBytes := ed25519.Sign(privKey, payloadBytes)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)

	return fmt.Sprintf("%s.%s", payloadB64, sigB64), nil
}

// ParseAndVerifyReleaseToken decodes, parses, and cryptographically verifies an Ed25519 signed release token.
// If pubKey is nil or empty, GetReleaseVerificationPublicKey() is used.
func ParseAndVerifyReleaseToken(token string, pubKey ed25519.PublicKey) (*ReleaseClaims, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("release token cannot be empty")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("malformed release token: expected format '<payload>.<signature>'")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		payloadBytes, err = base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, fmt.Errorf("failed to decode release payload: %w", err)
		}
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		sigBytes, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("failed to decode release signature: %w", err)
		}
	}

	if len(sigBytes) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid release signature size: expected %d bytes, got %d", ed25519.SignatureSize, len(sigBytes))
	}

	if len(pubKey) == 0 {
		var err error
		pubKey, err = GetReleaseVerificationPublicKey()
		if err != nil {
			return nil, err
		}
	}

	if !ed25519.Verify(pubKey, payloadBytes, sigBytes) {
		return nil, errors.New("cryptographic signature verification failed: signature does not match public key")
	}

	var claims ReleaseClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to deserialize release claims: %w", err)
	}

	return &claims, nil
}

// ResolveReleaseSignature resolves the cryptographic release token from:
// 1. Compile-time variable ReleaseSignature (if not empty and not "none")
// 2. DIVMORA_RELEASE_SIGNATURE environment variable
// 3. Sidecar file release.sig or otel-aws-log-processor.sig
func ResolveReleaseSignature() (string, string) {
	// 1. Embedded ldflags
	sig := strings.TrimSpace(ReleaseSignature)
	if sig != "" && sig != "none" {
		return sig, "embedded (ldflags)"
	}

	// 2. Environment variable
	envSig := strings.TrimSpace(os.Getenv("DIVMORA_RELEASE_SIGNATURE"))
	if envSig != "" {
		return envSig, "environment (DIVMORA_RELEASE_SIGNATURE)"
	}

	// 3. Sidecar file candidates
	candidates := []string{
		"release.sig",
		"otel-aws-log-processor.sig",
	}

	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		candidates = append(candidates,
			filepath.Join(execDir, "release.sig"),
			filepath.Join(execDir, "otel-aws-log-processor.sig"),
		)
	}

	for _, path := range candidates {
		if content, err := os.ReadFile(path); err == nil {
			s := strings.TrimSpace(string(content))
			if s != "" {
				return s, fmt.Sprintf("sidecar file (%s)", path)
			}
		}
	}

	return "", "none"
}

// EvaluateProvenance inspects the binary's release signature and verifies that the compiled
// Version, GitCommit, and BuildDate match the signed claims.
func (i Info) EvaluateProvenance(pubKey ed25519.PublicKey) ReleaseProvenance {
	sig, source := ResolveReleaseSignature()
	if sig == "" {
		return ReleaseProvenance{
			Status:   ProvenanceUnattestedCustom,
			Verified: false,
			Source:   source,
			Error:    "No cryptographic release signature present; running as custom/unattested build",
		}
	}

	claims, err := ParseAndVerifyReleaseToken(sig, pubKey)
	if err != nil {
		return ReleaseProvenance{
			Status:   ProvenanceTamperedSignature,
			Verified: false,
			Source:   source,
			Error:    fmt.Sprintf("Release signature verification failed (%s): %v", source, err),
		}
	}

	// Verify Version match (normalize leading "v")
	expectedVer := strings.TrimPrefix(strings.TrimSpace(claims.Version), "v")
	actualVer := strings.TrimPrefix(strings.TrimSpace(i.Version), "v")
	if actualVer != "" && actualVer != "dev" && actualVer != expectedVer {
		return ReleaseProvenance{
			Status:       ProvenanceTamperedMetadata,
			Verified:     false,
			Source:       source,
			Authority:    claims.Authority,
			AuthorityID:  claims.AuthorityID,
			Error:        fmt.Sprintf("Version mismatch: binary compiled as '%s', but signed claims specify '%s'", i.Version, claims.Version),
			SignedClaims: claims,
		}
	}

	// Verify GitCommit match (prefix match allowed for short commit SHAs)
	expectedCommit := strings.TrimSpace(claims.GitCommit)
	actualCommit := strings.TrimSpace(i.GitCommit)
	if actualCommit != "" && actualCommit != "none" && expectedCommit != "" {
		if !strings.HasPrefix(expectedCommit, actualCommit) && !strings.HasPrefix(actualCommit, expectedCommit) {
			return ReleaseProvenance{
				Status:       ProvenanceTamperedMetadata,
				Verified:     false,
				Source:       source,
				Authority:    claims.Authority,
				AuthorityID:  claims.AuthorityID,
				Error:        fmt.Sprintf("Commit mismatch: binary compiled from '%s', but signed claims specify '%s'", i.GitCommit, claims.GitCommit),
				SignedClaims: claims,
			}
		}
	}

	// Verify BuildDate match
	if !datesMatch(i.BuildDate, claims.BuildDate) {
		return ReleaseProvenance{
			Status:       ProvenanceTamperedMetadata,
			Verified:     false,
			Source:       source,
			Authority:    claims.Authority,
			AuthorityID:  claims.AuthorityID,
			Error:        fmt.Sprintf("Build date mismatch: binary compiled with date '%s', but signed claims specify '%s'", i.BuildDate, claims.BuildDate),
			SignedClaims: claims,
		}
	}

	return ReleaseProvenance{
		Status:       ProvenanceVerifiedOfficial,
		Verified:     true,
		Source:       source,
		Authority:    claims.Authority,
		AuthorityID:  claims.AuthorityID,
		SignedClaims: claims,
	}
}

func datesMatch(date1, date2 string) bool {
	if strings.TrimSpace(date1) == strings.TrimSpace(date2) {
		return true
	}
	t1, err1 := parseAnyDate(date1)
	t2, err2 := parseAnyDate(date2)
	if err1 != nil || err2 != nil {
		return false
	}
	diff := t1.Sub(t2)
	return diff >= -2*time.Second && diff <= 2*time.Second
}

func parseAnyDate(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errors.New("unknown date format")
}
