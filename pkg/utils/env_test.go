package utils

import (
	"os"
	"testing"
)

func TestGetEnvBool(t *testing.T) {
	key := "TEST_ENV_BOOL_VAL"
	defer os.Unsetenv(key)

	tests := []struct {
		envVal   string
		setEnv   bool
		defVal   bool
		expected bool
	}{
		{setEnv: false, defVal: false, expected: false},
		{setEnv: false, defVal: true, expected: true},
		{setEnv: true, envVal: "true", defVal: false, expected: true},
		{setEnv: true, envVal: "1", defVal: false, expected: true},
		{setEnv: true, envVal: "t", defVal: false, expected: true},
		{setEnv: true, envVal: "TRUE", defVal: false, expected: true},
		{setEnv: true, envVal: "false", defVal: true, expected: false},
		{setEnv: true, envVal: "0", defVal: true, expected: false},
		{setEnv: true, envVal: "f", defVal: true, expected: false},
		{setEnv: true, envVal: "invalid", defVal: true, expected: true},
		{setEnv: true, envVal: "invalid", defVal: false, expected: false},
	}

	for _, tt := range tests {
		if tt.setEnv {
			os.Setenv(key, tt.envVal)
		} else {
			os.Unsetenv(key)
		}

		res := GetEnvBool(key, tt.defVal)
		if res != tt.expected {
			t.Errorf("GetEnvBool(%q set=%v, val=%q, def=%v) = %v, want %v", key, tt.setEnv, tt.envVal, tt.defVal, res, tt.expected)
		}
	}
}

func TestGetEnv(t *testing.T) {
	key := "TEST_ENV_STR_VAL"
	defer os.Unsetenv(key)

	os.Unsetenv(key)
	if got := GetEnv(key, "default"); got != "default" {
		t.Errorf("GetEnv unset = %q, want default", got)
	}

	os.Setenv(key, "custom")
	if got := GetEnv(key, "default"); got != "custom" {
		t.Errorf("GetEnv set = %q, want custom", got)
	}
}

func TestGetEnvInt(t *testing.T) {
	key := "TEST_ENV_INT_VAL"
	defer os.Unsetenv(key)

	os.Unsetenv(key)
	if got := GetEnvInt(key, 42); got != 42 {
		t.Errorf("GetEnvInt unset = %d, want 42", got)
	}

	os.Setenv(key, "100")
	if got := GetEnvInt(key, 42); got != 100 {
		t.Errorf("GetEnvInt valid = %d, want 100", got)
	}

	os.Setenv(key, "not-an-int")
	if got := GetEnvInt(key, 42); got != 42 {
		t.Errorf("GetEnvInt invalid = %d, want 42", got)
	}
}
