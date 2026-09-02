package utils

import (
	"strconv"
	"time"
)

// SafeString ensures the string is not "-", returning empty string if it is.
func SafeString(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// GetMatch safely retrieves a match from a regex result slice.
// It checks bounds and returns an empty string if the index is out of range or if the value is "-".
func GetMatch(matches []string, index int) string {
	if index >= len(matches) {
		return ""
	}
	return SafeString(matches[index])
}

// ParseInt parses a string to int. Returns 0 if empty or "-".
func ParseInt(s string) int {
	if s == "" || s == "-" {
		return 0
	}
	val, _ := strconv.Atoi(s)
	return val
}

// ParseInt64 parses a string to int64. Returns 0 if empty or "-".
func ParseInt64(s string) int64 {
	if s == "" || s == "-" {
		return 0
	}
	val, _ := strconv.ParseInt(s, 10, 64)
	return val
}

// ParseFloat parses a string to float64. Returns 0 if empty or "-".
func ParseFloat(s string) float64 {
	if s == "" || s == "-" {
		return 0
	}
	val, _ := strconv.ParseFloat(s, 64)
	return val
}

// ConvertTimestamp parses a timestamp string to Unix nanoseconds.
func ConvertTimestamp(timeStr string) int64 {
	if timeStr == "" {
		return time.Now().UnixNano()
	}

	t, err := time.Parse("2006-01-02T15:04:05.999999Z", timeStr)
	if err != nil {
		return time.Now().UnixNano()
	}

	return t.UnixNano()
}
