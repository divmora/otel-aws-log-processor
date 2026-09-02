package parser

import (
	"encoding/json"
	"fmt"
	"strings"
)

// WAFLogEntry represents a parsed AWS WAF log entry
type WAFLogEntry struct {
	Timestamp                   int64                `json:"timestamp"`
	FormatVersion               int                  `json:"formatVersion"`
	WebACLID                    string               `json:"webaclId"`
	TerminatingRuleID           string               `json:"terminatingRuleId"`
	TerminatingRuleType         string               `json:"terminatingRuleType"`
	Action                      string               `json:"action"`
	TerminatingRuleMatchDetails []MatchDetail        `json:"terminatingRuleMatchDetails"`
	HTTPSourceName              string               `json:"httpSourceName"`
	HTTPSourceID                string               `json:"httpSourceId"`
	RuleGroupList               []RuleGroup          `json:"ruleGroupList"`
	RateBasedRuleList           []RateBasedRule      `json:"rateBasedRuleList"`
	NonTerminatingMatchingRules []NonTerminatingRule `json:"nonTerminatingMatchingRules"`
	RequestHeadersInserted      []Header             `json:"requestHeadersInserted"`
	ResponseCodeSent            *int                 `json:"responseCodeSent"`
	HTTPRequest                 HTTPRequest          `json:"httpRequest"`
	Labels                      []Label              `json:"labels"`
	RequestBodySize             int64                `json:"requestBodySize"`
	RequestBodySizeInspected    int64                `json:"requestBodySizeInspectedByWAF"`
	JA3Fingerprint              string               `json:"ja3Fingerprint"`
	JA4Fingerprint              string               `json:"ja4Fingerprint"`
}

type MatchDetail struct {
	ConditionType string   `json:"conditionType"`
	Location      string   `json:"location"`
	MatchedData   []string `json:"matchedData"`
}

type RuleGroup struct {
	RuleGroupID         string          `json:"ruleGroupId"`
	TerminatingRule     *RuleGroupRule  `json:"terminatingRule"`
	NonTerminatingRules []RuleGroupRule `json:"nonTerminatingRules"`
	ExcludedRules       []ExcludeRule   `json:"excludedRules"`
}

type RuleGroupRule struct {
	RuleID string `json:"ruleId"`
	Action string `json:"action"`
}

type ExcludeRule struct {
	ExclusionType string `json:"exclusionType"`
	RuleID        string `json:"ruleId"`
}

type RateBasedRule struct {
	RateBasedRuleID     string `json:"rateBasedRuleId"`
	RateBasedRuleName   string `json:"rateBasedRuleName"`
	LimitKey            string `json:"limitKey"`
	MaxRateAllowed      int    `json:"maxRateAllowed"`
	EvaluationWindowSec string `json:"evaluationWindowSec"` // Sometimes string in docs
}

type NonTerminatingRule struct {
	RuleID string `json:"ruleId"`
	Action string `json:"action"`
}

type HTTPRequest struct {
	ClientIP    string   `json:"clientIp"`
	Country     string   `json:"country"`
	Headers     []Header `json:"headers"`
	URI         string   `json:"uri"`
	Args        string   `json:"args"`
	HTTPVersion string   `json:"httpVersion"`
	HTTPMethod  string   `json:"httpMethod"`
	RequestID   string   `json:"requestId"`
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Label struct {
	Name string `json:"name"`
}

// WAFParser implements LogParser for WAF logs
type WAFParser struct{}

// ParseLogLine parses a single WAF log line (JSON string)
func (p *WAFParser) ParseLogLine(line string) (*WAFLogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	var entry WAFLogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return &entry, nil
}
