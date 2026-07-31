package utils

import (
	"testing"
)

func TestParseAWSTraceID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Valid trace ID",
			input:    "Root=1-58337262-36d228ad5d99923122bbe354",
			expected: "5833726236d228ad5d99923122bbe354",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Dash",
			input:    "-",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseAWSTraceID(tt.input)
			if result != tt.expected {
				t.Errorf("ParseAWSTraceID(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseRequestURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want map[string]string
	}{
		{
			name: "HTTPS URL with query",
			url:  "https://example.com:443/api/test?foo=bar",
			want: map[string]string{
				"http.scheme": "https",
				"url.path":    "/api/test",
				"url.query":   "foo=bar",
				"http.target": "/api/test?foo=bar",
			},
		},
		{
			name: "HTTP URL without query",
			url:  "http://example.com:80/",
			want: map[string]string{
				"http.scheme": "http",
				"url.path":    "/",
				"http.target": "/",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseRequestURL(tt.url)
			for k, v := range tt.want {
				if result[k] != v {
					t.Errorf("ParseRequestURL()[%q] = %q, want %q", k, result[k], v)
				}
			}
		})
	}
}
