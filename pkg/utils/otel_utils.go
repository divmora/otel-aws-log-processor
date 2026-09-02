package utils

import (
	"net/url"
	"strings"
)

// ParseAWSTraceID extracts W3C trace ID from ALB trace ID
// ALB format: Root=1-58337262-36d228ad5d99923122bbe354
// W3C format: 5833726236d228ad5d99923122bbe354 (32 hex chars)
func ParseAWSTraceID(albTraceID string) string {
	if albTraceID == "" || albTraceID == "-" {
		return ""
	}

	// Remove "Root=" prefix
	albTraceID = strings.TrimPrefix(albTraceID, "Root=")

	// Split by hyphens: ['1', '58337262', '36d228ad5d99923122bbe354']
	parts := strings.Split(albTraceID, "-")

	if len(parts) >= 3 {
		// Combine timestamp (8 chars) + unique ID (24 chars) = 32 chars
		traceID := parts[1] + parts[2]

		// Validate it's 32 hex characters
		if len(traceID) == 32 && isHex(traceID) {
			return strings.ToLower(traceID)
		}
	}

	return ""
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ParseRequestURL extracts HTTP attributes from URL
func ParseRequestURL(requestURL string) map[string]string {
	attrs := make(map[string]string)

	if requestURL == "" || requestURL == "-" {
		return attrs
	}

	u, err := url.Parse(requestURL)
	if err != nil {
		return attrs
	}

	if u.Scheme != "" {
		attrs["http.scheme"] = u.Scheme
	}

	if u.Path != "" {
		attrs["url.path"] = u.Path

		if u.RawQuery != "" {
			attrs["url.query"] = u.RawQuery
			attrs["http.target"] = u.Path + "?" + u.RawQuery
		} else {
			attrs["http.target"] = u.Path
		}
	}

	return attrs
}

// ParseRegionAccountFromARN parses region and account ID from an AWS ARN
// ARN format: arn:partition:service:region:account-id:resource-id
// Returns (region, accountID)
func ParseRegionAccountFromARN(arn string) (string, string) {
	if arn == "" || arn == "-" {
		return "", ""
	}

	parts := strings.Split(arn, ":")
	if len(parts) >= 6 {
		return parts[3], parts[4]
	}

	return "", ""
}
