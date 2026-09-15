package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"sync"
)

// DefaultPublicKeyBase64 is the embedded production Ed25519 public verification key for DIVMORA Technologies.
const DefaultPublicKeyBase64 = "o5nIs/8K/bCGz6jRB33Ig1h0ONr37yvVHpddzNnL46U="

var (
	overrideKeyLock sync.RWMutex
	overridePubKey  ed25519.PublicKey
)

// SetVerificationPublicKey overrides the active verification key (primarily used in automated tests).
func SetVerificationPublicKey(key ed25519.PublicKey) {
	overrideKeyLock.Lock()
	defer overrideKeyLock.Unlock()
	overridePubKey = key
}

// ResetVerificationPublicKey clears any programmatic override and returns to default resolution.
func ResetVerificationPublicKey() {
	overrideKeyLock.Lock()
	defer overrideKeyLock.Unlock()
	overridePubKey = nil
}

// GetVerificationPublicKey resolves the Ed25519 public key used to verify license tokens.
// Resolution order:
// 1. In-memory programmatic override (via SetVerificationPublicKey).
// 2. DIVMORA_PUBLIC_KEY environment variable (base64-encoded).
// 3. Embedded DefaultPublicKeyBase64.
func GetVerificationPublicKey() (ed25519.PublicKey, error) {
	overrideKeyLock.RLock()
	if overridePubKey != nil {
		defer overrideKeyLock.RUnlock()
		return overridePubKey, nil
	}
	overrideKeyLock.RUnlock()

	keyStr := os.Getenv("DIVMORA_PUBLIC_KEY")
	if keyStr == "" {
		keyStr = DefaultPublicKeyBase64
	}

	keyBytes, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		// Also try URL-safe base64
		keyBytes, err = base64.RawURLEncoding.DecodeString(keyStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode verification public key: %w", err)
		}
	}

	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid verification public key size: expected %d bytes, got %d", ed25519.PublicKeySize, len(keyBytes))
	}

	return ed25519.PublicKey(keyBytes), nil
}
