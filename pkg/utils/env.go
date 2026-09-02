package utils

import (
	"os"
	"strconv"
)

// GetEnv retrieves the value of the environment variable named by the key.
// If the variable is present, the value (which may be empty) is returned.
// Otherwise, the returned value will be the default value.
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetEnvInt retrieves the integer value of the environment variable named by the key.
// If the variable is present and valid, the value is returned.
// Otherwise, the returned value will be the default value.
func GetEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if result, err := strconv.Atoi(value); err == nil {
			return result
		}
	}
	return defaultValue
}
