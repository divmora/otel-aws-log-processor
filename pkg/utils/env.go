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

// GetEnvBool retrieves the boolean value of the environment variable named by the key.
// "true", "1", "t", "yes", "y" evaluate to true; "false", "0", "f", "no", "n" evaluate to false.
// Otherwise, defaultValue is returned.
func GetEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}
