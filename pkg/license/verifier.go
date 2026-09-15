package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SignLicense serializes and cryptographically signs a set of Claims using an Ed25519 private key,
// returning a compact, URL-safe Base64 token string formatted as "<payload>.<signature>".
func SignLicense(claims *Claims, privKey ed25519.PrivateKey) (string, error) {
	if claims == nil {
		return "", errors.New("cannot sign nil license claims")
	}
	if len(privKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid Ed25519 private key size: expected %d bytes, got %d", ed25519.PrivateKeySize, len(privKey))
	}

	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to serialize license claims: %w", err)
	}

	sigBytes := ed25519.Sign(privKey, payloadBytes)

	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)

	return fmt.Sprintf("%s.%s", payloadB64, sigB64), nil
}

// ParseAndVerify decodes, parses, and cryptographically verifies an Ed25519 signed license token
// against the current system time in UTC.
func ParseAndVerify(token string, pubKey ed25519.PublicKey) (*ValidationStatus, error) {
	return ParseAndVerifyAt(token, pubKey, time.Now().UTC())
}

// ParseAndVerifyAt decodes, parses, and cryptographically verifies an Ed25519 signed license token
// against a specified evaluation time.
func ParseAndVerifyAt(token string, pubKey ed25519.PublicKey, evalTime time.Time) (*ValidationStatus, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("license token cannot be empty")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("malformed license token: expected format '<payload>.<signature>'")
	}

	payloadBytes, err := decodeBase64Part(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode license payload: %w", err)
	}

	sigBytes, err := decodeBase64Part(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode license signature: %w", err)
	}

	if len(sigBytes) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature length: expected %d bytes, got %d", ed25519.SignatureSize, len(sigBytes))
	}

	if len(pubKey) == 0 {
		resolvedKey, err := GetVerificationPublicKey()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve verification key: %w", err)
		}
		pubKey = resolvedKey
	}

	if !ed25519.Verify(pubKey, payloadBytes, sigBytes) {
		return nil, errors.New("cryptographic signature verification failed: license token is invalid or has been tampered with")
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse license claims JSON: %w", err)
	}

	if claims.ID == "" {
		return nil, errors.New("invalid license: missing license ID")
	}
	if claims.Customer.Name == "" {
		return nil, errors.New("invalid license: missing customer name")
	}
	if claims.ExpiresAt.IsZero() {
		return nil, errors.New("invalid license: missing expiration date")
	}

	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	}
	now := evalTime.UTC()
	daysRemaining := int(claims.ExpiresAt.Sub(now).Hours() / 24)

	// Active (before ExpiresAt)
	if now.Before(claims.ExpiresAt) {
		return &ValidationStatus{
			Valid:         true,
			InGracePeriod: false,
			DaysRemaining: daysRemaining,
			StatusReason:  "valid",
			Message:       fmt.Sprintf("License is valid and active (%d days remaining)", daysRemaining),
			Claims:        &claims,
		}, nil
	}

	// Past ExpiresAt: check grace period
	graceDays := claims.EffectiveGracePeriodDays()
	graceEnd := claims.ExpiresAt.AddDate(0, 0, graceDays)

	if now.Before(graceEnd) {
		graceRemaining := int(graceEnd.Sub(now).Hours() / 24)
		return &ValidationStatus{
			Valid:         true,
			InGracePeriod: true,
			DaysRemaining: graceRemaining,
			StatusReason:  "grace_period",
			Message: fmt.Sprintf("License expired on %s; currently operating within %d-day grace period (%d days remaining)",
				claims.ExpiresAt.Format("2006-01-02"), graceDays, graceRemaining),
			Claims: &claims,
		}, nil
	}

	// Expired past grace period
	return &ValidationStatus{
		Valid:         false,
		InGracePeriod: false,
		DaysRemaining: 0,
		StatusReason:  "expired",
		Message: fmt.Sprintf("License expired on %s; grace period of %d days has elapsed",
			claims.ExpiresAt.Format("2006-01-02"), graceDays),
		Claims: &claims,
	}, fmt.Errorf("license expired on %s; grace period of %d days has elapsed", claims.ExpiresAt.Format("2006-01-02"), graceDays)
}

func decodeBase64Part(part string) ([]byte, error) {
	// Try RawURLEncoding first
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err == nil {
		return data, nil
	}
	// Try URLEncoding
	data, err = base64.URLEncoding.DecodeString(part)
	if err == nil {
		return data, nil
	}
	// Try RawStdEncoding
	data, err = base64.RawStdEncoding.DecodeString(part)
	if err == nil {
		return data, nil
	}
	// Try StdEncoding
	return base64.StdEncoding.DecodeString(part)
}
