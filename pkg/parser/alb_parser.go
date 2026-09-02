package parser

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/divmora/otel-aws-log-processor/pkg/utils"
)

// ALBLogEntry represents a parsed ALB log entry
type ALBLogEntry struct {
	Type                   string
	Time                   string
	ELB                    string
	ClientIP               string
	ClientPort             int
	TargetIP               string
	TargetPort             int
	RequestProcessingTime  float64
	TargetProcessingTime   float64
	ResponseProcessingTime float64
	ELBStatusCode          int
	TargetStatusCode       string
	ReceivedBytes          int64
	SentBytes              int64
	RequestVerb            string
	RequestURL             string
	RequestProto           string
	UserAgent              string
	SSLCipher              string
	SSLProtocol            string
	TargetGroupARN         string
	TraceID                string
	DomainName             string
	ChosenCertARN          string
	MatchedRulePriority    string
	RequestCreationTime    string
	ActionsExecuted        string
	RedirectURL            string
	LambdaErrorReason      string
	TargetPortList         string
	TargetStatusCodeList   string
	Classification         string
	ClassificationReason   string
	ConnTraceID            string
	TransformedHost        string
	TransformedURI         string
	RequestTransformStatus string
}

// Regex pattern matching Athena schema (same as Python implementation)
// Updated to handle optional trailing fields
var albLogPattern = regexp.MustCompile(
	`^([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) "([^ ]*) (.*) (- |[^ ]*)" "([^"]*)" ([A-Z0-9-_]+) ([A-Za-z0-9.-]*) ([^ ]*) "([^"]*)" "([^"]*)" "([^"]*)" ([-.0-9]*) ([^ ]*) "([^"]*)" "([^"]*)" "([^ ]*)" "([^\s]+?)" "([^\s]+)" "([^ ]*)" "([^ ]*)" ([^ ]*)(?: "([^"]*)")?(?: "([^"]*)")?(?: "([^"]*)")?`,
)

// ALBParser implements LogParser for ALB logs
type ALBParser struct{}

// ParseLogLine parses a single ALB log line
func (p *ALBParser) ParseLogLine(line string) (*ALBLogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, nil
	}

	matches := albLogPattern.FindStringSubmatch(line)
	if matches == nil {
		return nil, fmt.Errorf("failed to parse log line")
	}

	entry := &ALBLogEntry{
		Type:                   utils.GetMatch(matches, 1),
		Time:                   utils.GetMatch(matches, 2),
		ELB:                    utils.GetMatch(matches, 3),
		ClientIP:               utils.GetMatch(matches, 4),
		ClientPort:             utils.ParseInt(utils.GetMatch(matches, 5)),
		TargetIP:               utils.GetMatch(matches, 6),
		TargetPort:             utils.ParseInt(utils.GetMatch(matches, 7)),
		RequestProcessingTime:  utils.ParseFloat(utils.GetMatch(matches, 8)),
		TargetProcessingTime:   utils.ParseFloat(utils.GetMatch(matches, 9)),
		ResponseProcessingTime: utils.ParseFloat(utils.GetMatch(matches, 10)),
		ELBStatusCode:          utils.ParseInt(utils.GetMatch(matches, 11)),
		TargetStatusCode:       utils.GetMatch(matches, 12),
		ReceivedBytes:          utils.ParseInt64(utils.GetMatch(matches, 13)),
		SentBytes:              utils.ParseInt64(utils.GetMatch(matches, 14)),
		RequestVerb:            utils.GetMatch(matches, 15),
		RequestURL:             utils.GetMatch(matches, 16),
		RequestProto:           utils.GetMatch(matches, 17),
		UserAgent:              utils.GetMatch(matches, 18),
		SSLCipher:              utils.GetMatch(matches, 19),
		SSLProtocol:            utils.GetMatch(matches, 20),
		TargetGroupARN:         utils.GetMatch(matches, 21),
		TraceID:                utils.GetMatch(matches, 22),
		DomainName:             utils.GetMatch(matches, 23),
		ChosenCertARN:          utils.GetMatch(matches, 24),
		MatchedRulePriority:    utils.GetMatch(matches, 25),
		RequestCreationTime:    utils.GetMatch(matches, 26),
		ActionsExecuted:        utils.GetMatch(matches, 27),
		RedirectURL:            utils.GetMatch(matches, 28),
		LambdaErrorReason:      utils.GetMatch(matches, 29),
		TargetPortList:         utils.GetMatch(matches, 30),
		TargetStatusCodeList:   utils.GetMatch(matches, 31),
		Classification:         utils.GetMatch(matches, 32),
		ClassificationReason:   utils.GetMatch(matches, 33),
		ConnTraceID:            utils.GetMatch(matches, 34),
		TransformedHost:        utils.GetMatch(matches, 35),
		TransformedURI:         utils.GetMatch(matches, 36),
		RequestTransformStatus: utils.GetMatch(matches, 37),
	}

	return entry, nil
}
