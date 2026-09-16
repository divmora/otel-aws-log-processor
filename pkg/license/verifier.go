package license

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	liblicense "github.com/divmora/license-go/pkg/license"
	"github.com/divmora/otel-aws-log-processor/pkg/version"
)

// SignLicense serializes and cryptographically signs a set of Claims using an Ed25519 private key,
// returning a canonical DIV1 compact token string ("DIV1.<payload>.<sig>").
func SignLicense(claims *Claims, privKey ed25519.PrivateKey) (string, error) {
	if claims == nil {
		return "", errors.New("cannot sign nil license claims")
	}
	if len(privKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid Ed25519 private key size: expected %d bytes, got %d", ed25519.PrivateKeySize, len(privKey))
	}

	signer, err := liblicense.NewSigner(privKey)
	if err != nil {
		return "", err
	}
	return signer.Sign(*claims)
}

// SignLicenseArmored serializes and cryptographically signs a set of Claims using an Ed25519 private key,
// returning an armored PEM text block.
func SignLicenseArmored(claims *Claims, privKey ed25519.PrivateKey) (string, error) {
	if claims == nil {
		return "", errors.New("cannot sign nil license claims")
	}
	if len(privKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid Ed25519 private key size: expected %d bytes, got %d", ed25519.PrivateKeySize, len(privKey))
	}

	signer, err := liblicense.NewSigner(privKey)
	if err != nil {
		return "", err
	}
	return signer.SignArmored(*claims)
}

// ParseAndVerify decodes, parses, and cryptographically verifies an Ed25519 signed license token
// against the current system time in UTC.
// If pubKey is nil or empty, GetVerificationPublicKey() is used to resolve the public key.
func ParseAndVerify(token string, pubKey ed25519.PublicKey) (*ValidationStatus, error) {
	return ParseAndVerifyAt(token, pubKey, time.Now().UTC())
}

// ParseAndVerifyAt decodes, parses, and cryptographically verifies an Ed25519 signed license token
// against a specified evaluation time.
// If pubKey is nil or empty, GetVerificationKeyRing() is used to resolve the public key.
func ParseAndVerifyAt(token string, pubKey ed25519.PublicKey, evalTime time.Time) (*ValidationStatus, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("license token cannot be empty")
	}

	var keyRing *liblicense.KeyRing
	if len(pubKey) > 0 {
		keyRing = liblicense.NewKeyRing(pubKey)
	} else {
		resolvedRing, err := GetVerificationKeyRing()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve verification keyring: %w", err)
		}
		keyRing = resolvedRing
	}

	var validatorOpts []liblicense.ValidatorOption
	validatorOpts = append(validatorOpts, liblicense.WithProduct("otel-aws-log-processor"))
	if fp := strings.TrimSpace(os.Getenv("DIVMORA_FINGERPRINT")); fp != "" {
		validatorOpts = append(validatorOpts, liblicense.WithExpectedFingerprint(fp))
	}

	// 1. Software Version Enforcement:
	vInfo := version.Get()
	if vInfo.Version != "" && vInfo.Version != "dev" {
		validatorOpts = append(validatorOpts, liblicense.WithCurrentVersion(vInfo.Version))
	}

	// 2. Maintenance / Support Update Cutoff Enforcement:
	if releaseTime, ok := vInfo.ReleaseTime(); ok {
		validatorOpts = append(validatorOpts, liblicense.WithBuildDate(releaseTime))
	}

	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	}

	// 3. Server Time / Clock Skew Defense via liblicense:
	validatorOpts = append(validatorOpts,
		liblicense.WithAuthoritativeTime(evalTime),
		liblicense.WithMaxClockDrift(15*time.Minute),
	)

	validator, err := liblicense.NewValidatorWithKeyRing(keyRing, validatorOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize license validator: %w", err)
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
