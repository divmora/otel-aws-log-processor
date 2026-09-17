package license

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	liblicense "github.com/divmora/license-go/pkg/license"
	"github.com/divmora/otel-aws-log-processor/pkg/version"
)

var (
	validatorMu      sync.RWMutex
	defaultValidator *liblicense.Validator
)

func init() {
	_, _ = InitDefaultValidator()
}

// DefaultValidatorOptions constructs the standard validator options for otel-aws-log-processor.
func DefaultValidatorOptions() []liblicense.ValidatorOption {
	var opts []liblicense.ValidatorOption
	opts = append(opts,
		liblicense.WithProduct("otel-aws-log-processor"),
		liblicense.WithAllowEnvKeyOverride(true),
		liblicense.WithMaxClockDrift(15*time.Minute),
	)

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
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("license token cannot be empty")
	}

	validator, err := GetValidator(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize license validator: %w", err)
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
		if errors.Is(err, liblicense.ErrExpired) {
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
