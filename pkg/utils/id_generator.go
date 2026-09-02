package utils

import (
	"crypto/rand"
	"fmt"
	"time"
)

// GenerateSpanID generates a random 8-byte hex string (16 chars)
func GenerateSpanID() string {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

// GenerateTraceID generates a random 16-byte hex string (32 chars)
func GenerateTraceID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("%032x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}
