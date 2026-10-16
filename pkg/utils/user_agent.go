package utils

import (
	"regexp"
	"strings"

	"github.com/divmora/otel-aws-log-processor/pkg/model"
)

// UserAgentInfo encapsulates extracted client, browser, OS, and device information
// parsed from HTTP User-Agent strings following OpenTelemetry semantic conventions.
type UserAgentInfo struct {
	Original  string
	Name      string // Browser / client / tool name (e.g. "Chrome", "Firefox", "curl")
	Version   string // Browser / client version (e.g. "120.0.0.0", "7.68.0")
	OSName    string // Operating system name (e.g. "Windows", "macOS", "Linux", "iOS", "Android")
	OSVersion string // Operating system version (e.g. "10.0", "14.2.1")
	Device    string // Device type / model (e.g. "iPhone", "iPad", "Mobile", "Tablet", "PC", "Bot")
}

var (
	// Browser / Client Patterns
	edgRegex       = regexp.MustCompile(`(?i)(?:Edg|Edge|EdgA|EdgiOS)/([0-9.]+)`)
	oprRegex       = regexp.MustCompile(`(?i)(?:OPR|Opera)/([0-9.]+)`)
	samsungRegex   = regexp.MustCompile(`(?i)SamsungBrowser/([0-9.]+)`)
	chromeRegex    = regexp.MustCompile(`(?i)(?:Chrome|CriOS)/([0-9.]+)`)
	firefoxRegex   = regexp.MustCompile(`(?i)(?:Firefox|FxiOS)/([0-9.]+)`)
	safariVerRegex = regexp.MustCompile(`(?i)Version/([0-9.]+).*Safari`)
	safariRawRegex = regexp.MustCompile(`(?i)Safari/([0-9.]+)`)
	msieRegex      = regexp.MustCompile(`(?i)MSIE\s+([0-9.]+)`)
	tridentRegex   = regexp.MustCompile(`(?i)Trident/.*rv:([0-9.]+)`)

	// Tools / HTTP Clients / Crawlers Patterns
	curlRegex        = regexp.MustCompile(`(?i)curl/([0-9.]+)`)
	wgetRegex        = regexp.MustCompile(`(?i)Wget/([0-9.]+)`)
	postmanRegex     = regexp.MustCompile(`(?i)PostmanRuntime/([0-9.]+)`)
	requestsRegex    = regexp.MustCompile(`(?i)python-requests/([0-9.]+)`)
	aiohttpRegex     = regexp.MustCompile(`(?i)aiohttp/([0-9.]+)`)
	goClientRegex    = regexp.MustCompile(`(?i)Go-http-client/([0-9.]+)`)
	javaRegex        = regexp.MustCompile(`(?i)Java/([0-9._]+)`)
	apacheHttpRegex  = regexp.MustCompile(`(?i)Apache-HttpClient/([0-9.]+)`)
	elbHealthRegex   = regexp.MustCompile(`(?i)ELB-HealthChecker/([0-9.]+)`)
	googlebotRegex   = regexp.MustCompile(`(?i)Googlebot/([0-9.]+)`)
	bingbotRegex     = regexp.MustCompile(`(?i)bingbot/([0-9.]+)`)
	genericToolRegex = regexp.MustCompile(`^([A-Za-z0-9_-]+)/([0-9.]+)`)

	// OS Patterns
	winVerRegex  = regexp.MustCompile(`(?i)Windows NT ([0-9.]+)`)
	macVerRegex  = regexp.MustCompile(`(?i)Mac OS X ([0-9_.]+)`)
	iosVerRegex  = regexp.MustCompile(`(?i)(?:iPhone OS|CPU OS|CPU iPhone OS) ([0-9_.]+)`)
	androidRegex = regexp.MustCompile(`(?i)Android(?:[ -]([0-9.]+))?`)
)

// ParseUserAgent extracts structured client, OS, and device information from a raw User-Agent header.
func ParseUserAgent(ua string) *UserAgentInfo {
	ua = strings.TrimSpace(ua)
	if ua == "" || ua == "-" {
		return nil
	}

	info := &UserAgentInfo{Original: ua}
	lowerUA := strings.ToLower(ua)

	// 1. Identify Bots / Crawlers
	if strings.Contains(lowerUA, "googlebot") {
		info.Name = "Googlebot"
		info.Device = "Bot"
		if m := googlebotRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Version = m[1]
		}
	} else if strings.Contains(lowerUA, "bingbot") {
		info.Name = "Bingbot"
		info.Device = "Bot"
		if m := bingbotRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Version = m[1]
		}
	} else if strings.Contains(lowerUA, "baiduspider") {
		info.Name = "Baiduspider"
		info.Device = "Bot"
	} else if strings.Contains(lowerUA, "yandexbot") {
		info.Name = "YandexBot"
		info.Device = "Bot"
	} else if strings.Contains(lowerUA, "duckduckbot") {
		info.Name = "DuckDuckBot"
		info.Device = "Bot"
	} else if strings.Contains(lowerUA, "facebookexternalhit") || strings.Contains(lowerUA, "facebot") {
		info.Name = "FacebookBot"
		info.Device = "Bot"
	} else if strings.Contains(lowerUA, "twitterbot") {
		info.Name = "Twitterbot"
		info.Device = "Bot"
	} else if strings.Contains(lowerUA, "slackbot") {
		info.Name = "Slackbot"
		info.Device = "Bot"
	}

	// 2. Identify AWS Infrastructure & HTTP Clients / Tools (if not already a known bot)
	if info.Name == "" {
		if strings.Contains(lowerUA, "elb-healthchecker") {
			info.Name = "ELB-HealthChecker"
			info.Device = "AWS"
			if m := elbHealthRegex.FindStringSubmatch(ua); len(m) > 1 {
				info.Version = m[1]
			}
		} else if strings.Contains(lowerUA, "amazon cloudfront") {
			info.Name = "Amazon CloudFront"
			info.Device = "AWS"
		} else if m := curlRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Name = "curl"
			info.Version = m[1]
			info.Device = "Tool"
		} else if m := wgetRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Name = "Wget"
			info.Version = m[1]
			info.Device = "Tool"
		} else if m := postmanRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Name = "Postman"
			info.Version = m[1]
			info.Device = "Tool"
		} else if m := requestsRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Name = "python-requests"
			info.Version = m[1]
			info.Device = "Tool"
		} else if m := aiohttpRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Name = "aiohttp"
			info.Version = m[1]
			info.Device = "Tool"
		} else if m := goClientRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Name = "Go-http-client"
			info.Version = m[1]
			info.Device = "Tool"
		} else if m := apacheHttpRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Name = "Apache-HttpClient"
			info.Version = m[1]
			info.Device = "Tool"
		} else if m := javaRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Name = "Java"
			info.Version = m[1]
			info.Device = "Tool"
		}
	}

	// 3. Identify Standard Web Browsers (in priority order to handle user-agent masquerading)
	if info.Name == "" {
		if m := edgRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Name = "Edge"
			info.Version = m[1]
		} else if m := oprRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Name = "Opera"
			info.Version = m[1]
		} else if m := samsungRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Name = "Samsung Internet"
			info.Version = m[1]
		} else if m := chromeRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Name = "Chrome"
			info.Version = m[1]
		} else if m := firefoxRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Name = "Firefox"
			info.Version = m[1]
		} else if m := safariVerRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Name = "Safari"
			info.Version = m[1]
		} else if strings.Contains(ua, "Safari/") {
			info.Name = "Safari"
			if m := safariRawRegex.FindStringSubmatch(ua); len(m) > 1 {
				info.Version = m[1]
			}
		} else if m := msieRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Name = "Internet Explorer"
			info.Version = m[1]
		} else if m := tridentRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.Name = "Internet Explorer"
			info.Version = m[1]
		} else if m := genericToolRegex.FindStringSubmatch(ua); len(m) > 2 && !strings.EqualFold(m[1], "mozilla") {
			// Generic fallback for ClientName/Version (e.g. "MyClient/1.0")
			info.Name = m[1]
			info.Version = m[2]
			info.Device = "Tool"
		}
	}

	// 4. Identify Operating System
	if m := winVerRegex.FindStringSubmatch(ua); len(m) > 1 {
		info.OSName = "Windows"
		info.OSVersion = m[1]
		if info.Device == "" {
			info.Device = "PC"
		}
	} else if strings.Contains(ua, "iPhone") {
		info.OSName = "iOS"
		info.Device = "iPhone"
		if m := iosVerRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.OSVersion = strings.ReplaceAll(m[1], "_", ".")
		}
	} else if strings.Contains(ua, "iPad") {
		info.OSName = "iOS"
		info.Device = "iPad"
		if m := iosVerRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.OSVersion = strings.ReplaceAll(m[1], "_", ".")
		}
	} else if strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X") {
		info.OSName = "macOS"
		if info.Device == "" {
			info.Device = "Macintosh"
		}
		if m := macVerRegex.FindStringSubmatch(ua); len(m) > 1 {
			info.OSVersion = strings.ReplaceAll(m[1], "_", ".")
		}
	} else if m := androidRegex.FindStringSubmatch(ua); len(m) > 0 {
		info.OSName = "Android"
		if len(m) > 1 && m[1] != "" {
			info.OSVersion = m[1]
		}
		if info.Device == "" {
			if strings.Contains(lowerUA, "mobile") {
				info.Device = "Mobile"
			} else {
				info.Device = "Tablet"
			}
		}
	} else if strings.Contains(ua, "CrOS") {
		info.OSName = "Chrome OS"
		if info.Device == "" {
			info.Device = "PC"
		}
	} else if strings.Contains(ua, "Linux") || strings.Contains(ua, "X11") {
		info.OSName = "Linux"
		if info.Device == "" {
			info.Device = "PC"
		}
	}

	// Default device classification if still unknown
	if info.Device == "" {
		if strings.Contains(lowerUA, "mobile") {
			info.Device = "Mobile"
		} else if strings.Contains(lowerUA, "tablet") {
			info.Device = "Tablet"
		} else if strings.Contains(lowerUA, "bot") || strings.Contains(lowerUA, "spider") || strings.Contains(lowerUA, "crawl") {
			info.Device = "Bot"
		}
	}

	return info
}

// EnrichUserAgentAttributes parses the user agent string and appends standard OpenTelemetry
// semantic convention attributes to attrs.
func EnrichUserAgentAttributes(attrs *[]model.OTelAttribute, ua string) {
	info := ParseUserAgent(ua)
	if info == nil {
		return
	}

	if info.Name != "" {
		model.AddAttr(attrs, "user_agent.name", info.Name)
		model.AddAttr(attrs, "browser.name", info.Name)
	}
	if info.Version != "" {
		model.AddAttr(attrs, "user_agent.version", info.Version)
		model.AddAttr(attrs, "browser.version", info.Version)
	}
	if info.OSName != "" {
		model.AddAttr(attrs, "user_agent.os.name", info.OSName)
		model.AddAttr(attrs, "os.name", info.OSName)
	}
	if info.OSVersion != "" {
		model.AddAttr(attrs, "user_agent.os.version", info.OSVersion)
		model.AddAttr(attrs, "os.version", info.OSVersion)
	}
	if info.Device != "" {
		model.AddAttr(attrs, "device.name", info.Device)
	}
}
