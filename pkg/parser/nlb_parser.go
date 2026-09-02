package parser

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/divmora/otel-aws-log-processor/pkg/utils"
)

// NLBLogEntry represents a parsed NLB log entry
type NLBLogEntry struct {
	Type                      string
	Version                   string
	Time                      string
	ELB                       string
	ListenerID                string
	ClientIP                  string
	ClientPort                int
	TargetIP                  string
	TargetPort                int
	ConnectionTime            float64
	TLSHandshakeTime          float64
	ReceivedBytes             int64
	SentBytes                 int64
	IncomingTLSAlert          string
	ChosenCertARN             string
	ChosenCertSerial          string
	TLSCipher                 string
	TLSProtocolVersion        string
	TLSNamedGroup             string
	DomainName                string
	ALPNFrontEndProtocol      string
	ALPNBackEndProtocol       string
	ALPNClientPreferenceList  string
	TLSConnectionCreationTime string
}

// Regex for NLB logs
// Based on: type version time elb listener client:port destination:port ...
var nlbLogPattern = regexp.MustCompile(
	`^([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*):([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-0-9]*) ([-0-9]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*)`,
)

// NLBParser implements LogParser for NLB logs
type NLBParser struct{}

// ParseLogLine parses a single NLB log line
func (p *NLBParser) ParseLogLine(line string) (*NLBLogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, nil
	}

	matches := nlbLogPattern.FindStringSubmatch(line)
	if matches == nil {
		// Attempt fallback or simpler parsing if feasible, but for now error out
		return nil, fmt.Errorf("failed to parse NLB log line")
	}

	entry := &NLBLogEntry{
		Type:                      utils.GetMatch(matches, 1),
		Version:                   utils.GetMatch(matches, 2),
		Time:                      utils.GetMatch(matches, 3),
		ELB:                       utils.GetMatch(matches, 4),
		ListenerID:                utils.GetMatch(matches, 5),
		ClientIP:                  utils.GetMatch(matches, 6),
		ClientPort:                utils.ParseInt(utils.GetMatch(matches, 7)),
		TargetIP:                  utils.GetMatch(matches, 8),
		TargetPort:                utils.ParseInt(utils.GetMatch(matches, 9)),
		ConnectionTime:            utils.ParseFloat(utils.GetMatch(matches, 10)),
		TLSHandshakeTime:          utils.ParseFloat(utils.GetMatch(matches, 11)),
		ReceivedBytes:             utils.ParseInt64(utils.GetMatch(matches, 12)),
		SentBytes:                 utils.ParseInt64(utils.GetMatch(matches, 13)),
		IncomingTLSAlert:          utils.GetMatch(matches, 14),
		ChosenCertARN:             utils.GetMatch(matches, 15),
		ChosenCertSerial:          utils.GetMatch(matches, 16),
		TLSCipher:                 utils.GetMatch(matches, 17),
		TLSProtocolVersion:        utils.GetMatch(matches, 18),
		TLSNamedGroup:             utils.GetMatch(matches, 19),
		DomainName:                utils.GetMatch(matches, 20),
		ALPNFrontEndProtocol:      utils.GetMatch(matches, 21),
		ALPNBackEndProtocol:       utils.GetMatch(matches, 22),
		ALPNClientPreferenceList:  utils.GetMatch(matches, 23),
		TLSConnectionCreationTime: utils.GetMatch(matches, 24),
	}

	return entry, nil
}
