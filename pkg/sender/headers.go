package sender

import (
	"net/url"
	"os"
	"strings"
)

// ParseHeaders parses a comma-separated list of key=value pairs into a map.
// Values can optionally be URL-encoded per OpenTelemetry specification.
func ParseHeaders(headerStr string) map[string]string {
	headers := make(map[string]string)
	headerStr = strings.TrimSpace(headerStr)
	if headerStr == "" {
		return headers
	}

	pairs := strings.Split(headerStr, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		if k == "" {
			continue
		}
		// Unescape value if URL-encoded
		if unescaped, err := url.QueryUnescape(v); err == nil {
			v = unescaped
		}
		headers[k] = v
	}
	return headers
}

// ParseHeadersFromEnv parses custom OTLP headers from environment variables.
// Resolution Order:
// 1. OTEL_EXPORTER_OTLP_HEADERS (general OTLP export headers)
// 2. OTLP_HEADERS (legacy fallback)
// 3. OTEL_EXPORTER_OTLP_LOGS_HEADERS (signal-specific log headers, overrides general)
func ParseHeadersFromEnv() map[string]string {
	headers := make(map[string]string)

	// Base general headers
	if gen := os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"); strings.TrimSpace(gen) != "" {
		for k, v := range ParseHeaders(gen) {
			headers[k] = v
		}
	} else if legacy := os.Getenv("OTLP_HEADERS"); strings.TrimSpace(legacy) != "" {
		for k, v := range ParseHeaders(legacy) {
			headers[k] = v
		}
	}

	// Signal-specific log headers override general headers
	if logs := os.Getenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS"); strings.TrimSpace(logs) != "" {
		for k, v := range ParseHeaders(logs) {
			headers[k] = v
		}
	}

	return headers
}
