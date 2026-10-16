package utils

import (
	"testing"

	"github.com/divmora/otel-aws-log-processor/pkg/model"
)

func TestParseUserAgent(t *testing.T) {
	tests := []struct {
		name      string
		ua        string
		wantNil   bool
		wantName  string
		wantVer   string
		wantOS    string
		wantOSVer string
		wantDev   string
	}{
		{
			name:    "Empty string",
			ua:      "",
			wantNil: true,
		},
		{
			name:    "Dash",
			ua:      "-",
			wantNil: true,
		},
		{
			name:    "Whitespace only",
			ua:      "   \t\n  ",
			wantNil: true,
		},
		{
			name:      "Chrome on Windows 10",
			ua:        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			wantName:  "Chrome",
			wantVer:   "120.0.0.0",
			wantOS:    "Windows",
			wantOSVer: "10.0",
			wantDev:   "PC",
		},
		{
			name:      "Firefox on macOS",
			ua:        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
			wantName:  "Firefox",
			wantVer:   "119.0",
			wantOS:    "macOS",
			wantOSVer: "10.15",
			wantDev:   "Macintosh",
		},
		{
			name:      "Safari on macOS",
			ua:        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
			wantName:  "Safari",
			wantVer:   "17.1",
			wantOS:    "macOS",
			wantOSVer: "10.15.7",
			wantDev:   "Macintosh",
		},
		{
			name:      "Edge on Windows",
			ua:        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
			wantName:  "Edge",
			wantVer:   "119.0.0.0",
			wantOS:    "Windows",
			wantOSVer: "10.0",
			wantDev:   "PC",
		},
		{
			name:      "Opera on Windows",
			ua:        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 OPR/104.0.0.0",
			wantName:  "Opera",
			wantVer:   "104.0.0.0",
			wantOS:    "Windows",
			wantOSVer: "10.0",
			wantDev:   "PC",
		},
		{
			name:      "Samsung Internet on Android Mobile",
			ua:        "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.154 Mobile Safari/537.36 SamsungBrowser/23.0",
			wantName:  "Samsung Internet",
			wantVer:   "23.0",
			wantOS:    "Android",
			wantOSVer: "13",
			wantDev:   "Mobile",
		},
		{
			name:      "Mobile Safari on iPhone",
			ua:        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
			wantName:  "Safari",
			wantVer:   "17.1",
			wantOS:    "iOS",
			wantOSVer: "17.1",
			wantDev:   "iPhone",
		},
		{
			name:      "Safari on iPad",
			ua:        "Mozilla/5.0 (iPad; CPU OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
			wantName:  "Safari",
			wantVer:   "16.5",
			wantOS:    "iOS",
			wantOSVer: "16.5",
			wantDev:   "iPad",
		},
		{
			name:      "Chrome on Android Tablet",
			ua:        "Mozilla/5.0 (Linux; Android 12; SM-X800) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.136 Safari/537.36",
			wantName:  "Chrome",
			wantVer:   "112.0.5615.136",
			wantOS:    "Android",
			wantOSVer: "12",
			wantDev:   "Tablet",
		},
		{
			name:      "Chrome OS",
			ua:        "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			wantName:  "Chrome",
			wantVer:   "120.0.0.0",
			wantOS:    "Chrome OS",
			wantOSVer: "",
			wantDev:   "PC",
		},
		{
			name:      "Firefox on Linux",
			ua:        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
			wantName:  "Firefox",
			wantVer:   "119.0",
			wantOS:    "Linux",
			wantOSVer: "",
			wantDev:   "PC",
		},
		{
			name:      "Internet Explorer 11 (Trident)",
			ua:        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
			wantName:  "Internet Explorer",
			wantVer:   "11.0",
			wantOS:    "Windows",
			wantOSVer: "6.1",
			wantDev:   "PC",
		},
		{
			name:      "Internet Explorer 10",
			ua:        "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
			wantName:  "Internet Explorer",
			wantVer:   "10.0",
			wantOS:    "Windows",
			wantOSVer: "6.1",
			wantDev:   "PC",
		},
		{
			name:     "curl client",
			ua:       "curl/7.68.0",
			wantName: "curl",
			wantVer:  "7.68.0",
			wantDev:  "Tool",
		},
		{
			name:     "Wget client",
			ua:       "Wget/1.20.3 (linux-gnu)",
			wantName: "Wget",
			wantVer:  "1.20.3",
			wantDev:  "Tool",
		},
		{
			name:     "Postman runtime",
			ua:       "PostmanRuntime/7.29.0",
			wantName: "Postman",
			wantVer:  "7.29.0",
			wantDev:  "Tool",
		},
		{
			name:     "python-requests",
			ua:       "python-requests/2.28.1",
			wantName: "python-requests",
			wantVer:  "2.28.1",
			wantDev:  "Tool",
		},
		{
			name:     "aiohttp",
			ua:       "aiohttp/3.8.1",
			wantName: "aiohttp",
			wantVer:  "3.8.1",
			wantDev:  "Tool",
		},
		{
			name:     "Go HTTP client",
			ua:       "Go-http-client/1.1",
			wantName: "Go-http-client",
			wantVer:  "1.1",
			wantDev:  "Tool",
		},
		{
			name:     "Java client",
			ua:       "Java/11.0.12",
			wantName: "Java",
			wantVer:  "11.0.12",
			wantDev:  "Tool",
		},
		{
			name:     "Apache-HttpClient",
			ua:       "Apache-HttpClient/4.5.13 (Java/11.0.12)",
			wantName: "Apache-HttpClient",
			wantVer:  "4.5.13",
			wantDev:  "Tool",
		},
		{
			name:     "ELB Health Checker",
			ua:       "ELB-HealthChecker/2.0",
			wantName: "ELB-HealthChecker",
			wantVer:  "2.0",
			wantDev:  "AWS",
		},
		{
			name:     "Amazon CloudFront",
			ua:       "Amazon CloudFront",
			wantName: "Amazon CloudFront",
			wantDev:  "AWS",
		},
		{
			name:     "Googlebot",
			ua:       "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			wantName: "Googlebot",
			wantVer:  "2.1",
			wantDev:  "Bot",
		},
		{
			name:     "Bingbot",
			ua:       "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
			wantName: "Bingbot",
			wantVer:  "2.0",
			wantDev:  "Bot",
		},
		{
			name:     "Baiduspider",
			ua:       "Baiduspider+(+http://www.baidu.com/search/spider.htm)",
			wantName: "Baiduspider",
			wantDev:  "Bot",
		},
		{
			name:     "YandexBot",
			ua:       "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
			wantName: "YandexBot",
			wantDev:  "Bot",
		},
		{
			name:     "DuckDuckBot",
			ua:       "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
			wantName: "DuckDuckBot",
			wantDev:  "Bot",
		},
		{
			name:     "FacebookBot",
			ua:       "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
			wantName: "FacebookBot",
			wantDev:  "Bot",
		},
		{
			name:     "Twitterbot",
			ua:       "Twitterbot/1.0",
			wantName: "Twitterbot",
			wantDev:  "Bot",
		},
		{
			name:     "Slackbot",
			ua:       "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
			wantName: "Slackbot",
			wantDev:  "Bot",
		},
		{
			name:     "Generic Custom Client",
			ua:       "CustomAPIClient/3.1.2",
			wantName: "CustomAPIClient",
			wantVer:  "3.1.2",
			wantDev:  "Tool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseUserAgent(tt.ua)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil for %q, got %+v", tt.ua, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected non-nil for %q", tt.ua)
			}
			if got.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tt.wantName)
			}
			if got.Version != tt.wantVer {
				t.Errorf("Version = %q, want %q", got.Version, tt.wantVer)
			}
			if got.OSName != tt.wantOS {
				t.Errorf("OSName = %q, want %q", got.OSName, tt.wantOS)
			}
			if got.OSVersion != tt.wantOSVer {
				t.Errorf("OSVersion = %q, want %q", got.OSVersion, tt.wantOSVer)
			}
			if got.Device != tt.wantDev {
				t.Errorf("Device = %q, want %q", got.Device, tt.wantDev)
			}
		})
	}
}

func TestEnrichUserAgentAttributes(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	var attrs []model.OTelAttribute

	EnrichUserAgentAttributes(&attrs, ua)

	attrMap := make(map[string]string)
	for _, attr := range attrs {
		if attr.Value.StringValue != nil {
			attrMap[attr.Key] = *attr.Value.StringValue
		}
	}

	expected := map[string]string{
		"user_agent.name":       "Chrome",
		"browser.name":          "Chrome",
		"user_agent.version":    "120.0.0.0",
		"browser.version":       "120.0.0.0",
		"user_agent.os.name":    "Windows",
		"os.name":               "Windows",
		"user_agent.os.version": "10.0",
		"os.version":            "10.0",
		"device.name":           "PC",
	}

	for k, wantVal := range expected {
		if gotVal, ok := attrMap[k]; !ok {
			t.Errorf("missing expected attribute %q", k)
		} else if gotVal != wantVal {
			t.Errorf("attribute %q = %q, want %q", k, gotVal, wantVal)
		}
	}

	// Empty UA should not append anything
	prevLen := len(attrs)
	EnrichUserAgentAttributes(&attrs, "-")
	if len(attrs) != prevLen {
		t.Errorf("expected no additional attributes for '-', got len %d, want %d", len(attrs), prevLen)
	}
}

func BenchmarkParseUserAgent(b *testing.B) {
	uaList := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
		"ELB-HealthChecker/2.0",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"curl/7.68.0",
		"-",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ua := uaList[i%len(uaList)]
		_ = ParseUserAgent(ua)
	}
}
