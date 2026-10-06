package license

import (
	"crypto/ed25519"

	liblicense "github.com/divmora/license-go/pkg/license"
)

// DefaultPublicKeyBase64 is the embedded production Ed25519 public verification key for DIVMORA Technologies.
const DefaultPublicKeyBase64 = "o5nIs/8K/bCGz6jRB33Ig1h0ONr37yvVHpddzNnL46U="

func init() {
	// Treat the embedded public verification key as an immutable root of trust.
	// Disable environment-based public key overrides (e.g., DIVMORA_PUBLIC_KEY, DIVMORA_PUBLIC_KEYS_PEM)
	// to prevent runtime trust root spoofing.
	liblicense.SetAllowEnvKeyOverride(false)
}

// SetVerificationPublicKey overrides the active verification key (primarily used in automated tests).
func SetVerificationPublicKey(key ed25519.PublicKey) {
	liblicense.SetVerificationPublicKey(key)
	ResetDefaultValidator()
}

// ResetVerificationPublicKey clears any programmatic override and returns to default resolution.
func ResetVerificationPublicKey() {
	liblicense.ResetVerificationPublicKey()
	ResetDefaultValidator()
}

// GetVerificationKeyRing resolves the KeyRing containing trusted public verification keys.
// Resolution order:
// 1. In-memory programmatic override (via SetVerificationPublicKey or SetVerificationKeyRing).
// 2. Embedded DefaultPublicKeyBase64.
// Environment variable overrides (DIVMORA_PUBLIC_KEY, etc.) are strictly rejected to prevent trust root spoofing.
func GetVerificationKeyRing() (*liblicense.KeyRing, error) {
	resolved, err := liblicense.ResolveKeyRingWithSource(DefaultPublicKeyBase64)
	if err != nil {
		return nil, err
	}
	return resolved.KeyRing, nil
}

// GetVerificationPublicKey resolves the primary Ed25519 public key used to verify license tokens.
// Resolution order:
// 1. In-memory programmatic override (via SetVerificationPublicKey or SetVerificationKeyRing).
// 2. Embedded DefaultPublicKeyBase64.
// Environment variable overrides (DIVMORA_PUBLIC_KEY, etc.) are strictly rejected.
func GetVerificationPublicKey() (ed25519.PublicKey, error) {
	ring, err := GetVerificationKeyRing()
	if err != nil {
		return nil, err
	}
	if ring.Primary() == nil {
		return nil, liblicense.ErrMissingPublicKey
	}
	return ring.Primary().PublicKey, nil
}
