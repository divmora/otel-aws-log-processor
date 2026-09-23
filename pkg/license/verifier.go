package license

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	liblicense "github.com/divmora/license-go/pkg/license"
	"github.com/divmora/otel-aws-log-processor/pkg/version"
)

var (
	validatorMu      sync.RWMutex
	defaultValidator *liblicense.Validator

	crlOverrideLock sync.RWMutex
	crlOverride     string
)

func init() {
	_, _ = InitDefaultValidator()
}

// SetVerificationCRL sets an in-memory programmatic override for the active offline CRL (primarily used in tests).
func SetVerificationCRL(crl string) {
	crlOverrideLock.Lock()
	defer crlOverrideLock.Unlock()
	crlOverride = crl
	ResetDefaultValidator()
}

// ResetVerificationCRL clears any programmatic CRL override.
func ResetVerificationCRL() {
	crlOverrideLock.Lock()
	defer crlOverrideLock.Unlock()
	crlOverride = ""
	ResetDefaultValidator()
}

// ResolveOfflineCRL discovers and resolves an offline Certificate Revocation List (CRL)
// across AWS Lambda, container, and CLI execution environments.
//
// Resolution order:
//  1. In-memory programmatic override (via SetVerificationCRL).
//  2. Explicit source argument(s) if provided.
//  3. DIVMORA_CRL environment variable (inline token or file path).
//  4. DIVMORA_CRL_FILE environment variable (file path).
//  5. AWS Lambda Task Root ($LAMBDA_TASK_ROOT) sidecar files:
//     - crl.divcrl
//     - otel-aws-log-processor.divcrl
//     - revocations.divcrl
//     - .divcrl
//  6. Binary executable directory sidecar files:
//     - crl.divcrl
//     - otel-aws-log-processor.divcrl
//     - revocations.divcrl
//  7. Current working directory sidecar files:
//     - crl.divcrl
//     - otel-aws-log-processor.divcrl
//     - revocations.divcrl
//  8. Standard system path: /etc/divmora/crl.divcrl
func ResolveOfflineCRL(explicitSources ...string) (*liblicense.ResolvedCRL, error) {
	crlOverrideLock.RLock()
	override := crlOverride
	crlOverrideLock.RUnlock()
	if override != "" {
		return &liblicense.ResolvedCRL{
			Content: override,
			Source:  "programmatic_override",
		}, nil
	}

	for _, src := range explicitSources {
		if strings.TrimSpace(src) != "" {
			return liblicense.ResolveCRL(src)
		}
	}

	if envCRL := strings.TrimSpace(os.Getenv("DIVMORA_CRL")); envCRL != "" {
		return liblicense.ResolveCRL(envCRL)
	}

	if envFile := strings.TrimSpace(os.Getenv("DIVMORA_CRL_FILE")); envFile != "" {
		return liblicense.ResolveCRL(envFile)
	}

	var candidates []string
	if taskRoot := strings.TrimSpace(os.Getenv("LAMBDA_TASK_ROOT")); taskRoot != "" {
		candidates = append(candidates,
			filepath.Join(taskRoot, "crl.divcrl"),
			filepath.Join(taskRoot, "otel-aws-log-processor.divcrl"),
			filepath.Join(taskRoot, "revocations.divcrl"),
			filepath.Join(taskRoot, ".divcrl"),
		)
	}

	if execPath, err := os.Executable(); err == nil && execPath != "" {
		execDir := filepath.Dir(execPath)
		candidates = append(candidates,
			filepath.Join(execDir, "crl.divcrl"),
			filepath.Join(execDir, "otel-aws-log-processor.divcrl"),
			filepath.Join(execDir, "revocations.divcrl"),
		)
	}

	candidates = append(candidates,
		"crl.divcrl",
		"otel-aws-log-processor.divcrl",
		"revocations.divcrl",
		".divcrl",
	)

	for _, candidate := range candidates {
		if fi, err := os.Lstat(candidate); err == nil && !fi.IsDir() {
			if fi.Mode()&os.ModeSymlink == 0 {
				if res, err := liblicense.ResolveCRL(candidate); err == nil && res != nil {
					return res, nil
				}
			}
		}
	}

	return liblicense.ResolveCRL()
}

// DefaultValidatorOptions constructs the standard validator options for otel-aws-log-processor.
func DefaultValidatorOptions() []liblicense.ValidatorOption {
	var opts []liblicense.ValidatorOption
	opts = append(opts,
		liblicense.WithProduct("otel-aws-log-processor"),
		liblicense.WithAllowEnvKeyOverride(true),
		liblicense.WithMaxClockDrift(15*time.Minute),
	)

	// Trust organization release key in addition to license keys for CRL / attestation verification
	if orgReleasePub, err := version.GetReleaseVerificationPublicKey(); err == nil && len(orgReleasePub) > 0 {
		opts = append(opts, liblicense.WithAdditionalPublicKeys(orgReleasePub))
	}

	if fp := strings.TrimSpace(os.Getenv("DIVMORA_FINGERPRINT")); fp != "" {
		opts = append(opts, liblicense.WithExpectedFingerprint(fp))
	} else {
		opts = append(opts, liblicense.WithAutoFingerprint(true))
	}

	// 1. Software Version Enforcement:
	vInfo := version.Get()
	if vInfo.Version != "" && vInfo.Version != "dev" {
		opts = append(opts, liblicense.WithCurrentVersion(vInfo.Version))
	}

	// 2. Maintenance / Support Update Cutoff Enforcement:
	if releaseTime, ok := vInfo.ReleaseTime(); ok {
		opts = append(opts, liblicense.WithBuildDate(releaseTime))
	}

	// 3. Certificate Revocation List (CRL) Enforcement (Offline & Online):
	// Priority 1: Check for local offline CRL (bundled sidecars, LAMBDA_TASK_ROOT, DIVMORA_CRL, DIVMORA_CRL_FILE)
	if resolvedCRL, err := ResolveOfflineCRL(); err == nil && resolvedCRL != nil && strings.TrimSpace(resolvedCRL.Content) != "" {
		opts = append(opts, liblicense.WithRevocationList(resolvedCRL.Content))
	} else if crlURL := strings.TrimSpace(os.Getenv("DIVMORA_CRL_URL")); crlURL != "" {
		// Priority 2: Online CRL synchronization from remote distribution endpoint with /tmp disk caching
		cachePath := strings.TrimSpace(os.Getenv("DIVMORA_CRL_CACHE_FILE"))
		if cachePath == "" {
			cachePath = filepath.Join(os.TempDir(), "divmora-crl.cache")
		}
		opts = append(opts,
			liblicense.WithCRLURL(crlURL,
				liblicense.WithCRLSyncCacheFile(cachePath),
				liblicense.WithCRLSyncTimeout(5*time.Second),
			),
		)
	} else {
		// Priority 3: Auto-resolved CRL discovery (supports license token crl_url claims and remote fallback)
		opts = append(opts, liblicense.WithAutoResolvedRevocationList(false))
	}

	return opts
}

// InitDefaultValidator initializes the package-level Validator singleton using
// liblicense.NewValidatorWithFallbackKey to minimize cold-start latency and prevent
// repeated disk key evaluation on warm Lambda invocations.
func InitDefaultValidator() (*liblicense.Validator, error) {
	validatorMu.Lock()
	defer validatorMu.Unlock()

	v, err := liblicense.NewValidatorWithFallbackKey(DefaultPublicKeyBase64, DefaultValidatorOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize license validator: %w", err)
	}
	defaultValidator = v
	return v, nil
}

// GetDefaultValidator returns the initialized package-level Validator singleton.
func GetDefaultValidator() (*liblicense.Validator, error) {
	validatorMu.RLock()
	v := defaultValidator
	validatorMu.RUnlock()
	if v != nil {
		return v, nil
	}
	return InitDefaultValidator()
}

// ResetDefaultValidator clears the package-level Validator singleton (used primarily in tests).
func ResetDefaultValidator() {
	validatorMu.Lock()
	defaultValidator = nil
	validatorMu.Unlock()
}

// DefaultFallbackClaims returns standard fallback claims for serverless degraded mode.
func DefaultFallbackClaims() *Claims {
	return liblicense.DefaultCommunityClaims("otel-aws-log-processor")
}

// NewDefaultManagerConfig returns a ManagerConfig configured with PolicyDegraded and FallbackClaims
// to ensure serverless log processing never panics or drops telemetry if a license file is renewing or missing.
func NewDefaultManagerConfig(validator *liblicense.Validator) liblicense.ManagerConfig {
	if validator == nil {
		var err error
		validator, err = GetDefaultValidator()
		if err != nil {
			validator, _ = liblicense.NewValidatorWithFallbackKey(DefaultPublicKeyBase64, DefaultValidatorOptions()...)
		}
	}
	return liblicense.ManagerConfig{
		Validator:              validator,
		Policy:                 liblicense.PolicyDegraded,
		FallbackClaims:         DefaultFallbackClaims(),
		AllowDegradedMutations: true,
	}
}

// GetValidator returns a Validator configured for the given public key,
// or the singleton defaultValidator if pubKey is nil or empty.
func GetValidator(pubKey ed25519.PublicKey) (*liblicense.Validator, error) {
	if len(pubKey) > 0 {
		return liblicense.NewValidator(pubKey, DefaultValidatorOptions()...)
	}
	return GetDefaultValidator()
}

// ParseAndVerify decodes, parses, and cryptographically verifies an Ed25519 signed license token
// against the current system time in UTC.
// If pubKey is nil or empty, the package-level Validator singleton is used.
func ParseAndVerify(token string, pubKey ed25519.PublicKey) (*ValidationStatus, error) {
	return ParseAndVerifyAt(token, pubKey, time.Now().UTC())
}

// ParseAndVerifyAt decodes, parses, and cryptographically verifies an Ed25519 signed license token
// against a specified evaluation time.
// If pubKey is nil or empty, the package-level Validator singleton is used.
func ParseAndVerifyAt(token string, pubKey ed25519.PublicKey, evalTime time.Time) (*ValidationStatus, error) {
	validator, err := GetValidator(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize license validator: %w", err)
	}
	return verifyWithValidator(token, validator, evalTime)
}

// ParseAndVerifyWithCRL verifies a license token using an explicit offline CRL token or file source.
func ParseAndVerifyWithCRL(token string, pubKey ed25519.PublicKey, evalTime time.Time, crlSource string) (*ValidationStatus, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("license token cannot be empty")
	}

	vOpts := DefaultValidatorOptions()
	crlSource = strings.TrimSpace(crlSource)
	if crlSource != "" {
		if strings.HasPrefix(crlSource, liblicense.ProtocolPrefixCRL+".") || strings.Contains(crlSource, liblicense.PEMTypeRevocationList) {
			vOpts = append(vOpts, liblicense.WithRevocationList(crlSource))
		} else {
			vOpts = append(vOpts, liblicense.WithRevocationListFile(crlSource))
		}
	}

	var validator *liblicense.Validator
	var err error
	if len(pubKey) > 0 {
		validator, err = liblicense.NewValidator(pubKey, vOpts...)
	} else {
		validator, err = liblicense.NewValidatorWithFallbackKey(DefaultPublicKeyBase64, vOpts...)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to initialize license validator with CRL: %w", err)
	}

	return verifyWithValidator(token, validator, evalTime)
}

// ParseAndVerifyWithCRLURL verifies a license token using online CRL synchronization from a remote distribution URL.
// It caches verified revocation lists to disk (defaulting to /tmp/divmora-crl.cache) for air-gap and network failure resilience.
func ParseAndVerifyWithCRLURL(token string, pubKey ed25519.PublicKey, evalTime time.Time, crlURL string, cacheFilePath ...string) (*ValidationStatus, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("license token cannot be empty")
	}

	crlURL = strings.TrimSpace(crlURL)
	if crlURL == "" {
		return nil, errors.New("CRL URL cannot be empty")
	}

	cacheFile := ""
	for _, c := range cacheFilePath {
		if strings.TrimSpace(c) != "" {
			cacheFile = strings.TrimSpace(c)
			break
		}
	}
	if cacheFile == "" {
		cacheFile = filepath.Join(os.TempDir(), "divmora-crl.cache")
	}

	vOpts := DefaultValidatorOptions()
	vOpts = append(vOpts,
		liblicense.WithCRLURL(crlURL,
			liblicense.WithCRLSyncCacheFile(cacheFile),
			liblicense.WithCRLSyncTimeout(5*time.Second),
		),
		liblicense.WithRequireRevocationList(true),
	)

	var validator *liblicense.Validator
	var err error
	if len(pubKey) > 0 {
		validator, err = liblicense.NewValidator(pubKey, vOpts...)
	} else {
		validator, err = liblicense.NewValidatorWithFallbackKey(DefaultPublicKeyBase64, vOpts...)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to initialize license validator with CRL URL: %w", err)
	}

	return verifyWithValidator(token, validator, evalTime)
}

// verifyWithValidator runs verification using a configured liblicense.Validator,
// evaluating expiration, grace period dynamics, scope mismatches, and Certificate Revocation Lists.
func verifyWithValidator(token string, validator *liblicense.Validator, evalTime time.Time) (*ValidationStatus, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("license token cannot be empty")
	}

	if validator == nil {
		return nil, errors.New("license validator cannot be nil")
	}

	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	}

	res, err := validator.VerifyWithResultAt(token, evalTime)
	if err != nil {
		var scopeErr *liblicense.ScopeMismatchError
		if errors.As(err, &scopeErr) {
			// Token signature, product, and expiration are verified; scope is evaluated by Enforce against active targets.
			claims, inspectErr := liblicense.Inspect(token)
			if inspectErr == nil {
				daysRemaining := claims.DaysRemainingAt(evalTime)
				inGrace := claims.IsInGracePeriodAt(evalTime)
				if inGrace {
					daysRemaining = claims.GraceDaysRemainingAt(evalTime)
				}
				statusReason := "valid"
				if inGrace {
					statusReason = "grace_period"
				}
				var msg string
				if inGrace {
					msg = fmt.Sprintf("License expired on %s; currently operating within %d-day grace period (%d days remaining)",
						claims.ExpiresAt.Format("2006-01-02"), claims.GracePeriodDays, daysRemaining)
				} else if claims.IsPerpetual() {
					msg = "Perpetual commercial license is valid and active"
				} else {
					msg = fmt.Sprintf("License is valid and active (%d days remaining)", daysRemaining)
				}
				return &ValidationStatus{
					Valid:         true,
					InGracePeriod: inGrace,
					DaysRemaining: daysRemaining,
					StatusReason:  statusReason,
					Message:       msg,
					Claims:        claims,
				}, nil
			}
		}

		claims, _ := liblicense.Inspect(token)
		statusReason := "invalid"
		if errors.Is(err, liblicense.ErrLicenseRevoked) {
			statusReason = "revoked"
		} else if errors.Is(err, liblicense.ErrExpired) {
			statusReason = "expired"
		}
		return &ValidationStatus{
			Valid:        false,
			StatusReason: statusReason,
			Message:      err.Error(),
			Claims:       claims,
		}, err
	}

	daysRemaining := res.Claims.DaysRemainingAt(evalTime)
	if res.InGracePeriod {
		daysRemaining = res.GraceDaysRemaining
	}

	statusReason := "valid"
	var msg string
	if res.InGracePeriod {
		statusReason = "grace_period"
		msg = fmt.Sprintf("License expired on %s; currently operating within %d-day grace period (%d days remaining)",
			res.Claims.ExpiresAt.Format("2006-01-02"), res.Claims.GracePeriodDays, res.GraceDaysRemaining)
	} else if res.Claims.IsPerpetual() {
		msg = "Perpetual commercial license is valid and active"
	} else {
		msg = fmt.Sprintf("License is valid and active (%d days remaining)", daysRemaining)
	}

	return &ValidationStatus{
		Valid:         true,
		InGracePeriod: res.InGracePeriod,
		DaysRemaining: daysRemaining,
		StatusReason:  statusReason,
		Message:       msg,
		Claims:        res.Claims,
	}, nil
}

// SignCRL serializes and cryptographically signs RevocationListClaims using an Ed25519 private key.
func SignCRL(claims RevocationListClaims, privKey ed25519.PrivateKey, opts ...liblicense.SignCRLOption) (string, error) {
	return liblicense.SignCRL(claims, privKey, opts...)
}

// SignCRLArmored serializes and cryptographically signs RevocationListClaims, returning an armored PEM text block.
func SignCRLArmored(claims RevocationListClaims, privKey ed25519.PrivateKey, opts ...liblicense.SignCRLOption) (string, error) {
	return liblicense.SignCRLArmored(claims, privKey, opts...)
}
