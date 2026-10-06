package parser

import (
	"fmt"
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

// NLBParser implements LogParser for NLB logs (both TCP and TLS formats)
type NLBParser struct{}

// parseIPPort extracts host and port from an IP:port string, handling IPv4, IPv6, and unrouted targets.
func parseIPPort(s string) (string, int) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" || s == "-1" || s == "- -" {
		return "", 0
	}
	idx := strings.LastIndex(s, ":")
	if idx == -1 {
		return s, 0
	}
	ip := strings.TrimSpace(s[:idx])
	portStr := strings.TrimSpace(s[idx+1:])

	ip = strings.TrimPrefix(ip, "[")
	ip = strings.TrimSuffix(ip, "]")
	if ip == "-" {
		ip = ""
	}

	port := utils.ParseInt(portStr)
	if port < 0 {
		port = 0
	}
	return ip, port
}

// ParseLogLine parses a single NLB log line (supporting 10-field TCP and 22+ field TLS formats)
func (p *NLBParser) ParseLogLine(line string) (*NLBLogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, nil
	}

	fields := strings.Fields(line)
	if len(fields) < 10 {
		return nil, fmt.Errorf("failed to parse NLB log line: expected at least 10 fields, got %d", len(fields))
	}

	clientIP, clientPort := parseIPPort(fields[5])
	targetIP, targetPort := parseIPPort(fields[6])

	entry := &NLBLogEntry{
		Type:           utils.SafeString(fields[0]),
		Version:        utils.SafeString(fields[1]),
		Time:           utils.SafeString(fields[2]),
		ELB:            utils.SafeString(fields[3]),
		ListenerID:     utils.SafeString(fields[4]),
		ClientIP:       clientIP,
		ClientPort:     clientPort,
		TargetIP:       targetIP,
		TargetPort:     targetPort,
		ConnectionTime: utils.ParseFloat(fields[7]),
	}

	// 10-field TCP format:
	// type version time elb listener client:port destination:port connection_time received_bytes sent_bytes
	if len(fields) == 10 {
		entry.ReceivedBytes = utils.ParseInt64(fields[8])
		entry.SentBytes = utils.ParseInt64(fields[9])
		return entry, nil
	}

	// TLS / Full format (22+ fields):
	// ... connection_time tls_handshake_time received_bytes sent_bytes incoming_tls_alert chosen_cert_arn chosen_cert_serial tls_cipher tls_protocol_version tls_named_group domain_name alpn_fe_protocol alpn_be_protocol alpn_client_preference_list tls_connection_creation_time
	if len(fields) >= 22 {
		entry.TLSHandshakeTime = utils.ParseFloat(fields[8])
		entry.ReceivedBytes = utils.ParseInt64(fields[9])
		entry.SentBytes = utils.ParseInt64(fields[10])
		entry.IncomingTLSAlert = utils.SafeString(fields[11])
		entry.ChosenCertARN = utils.SafeString(fields[12])
		entry.ChosenCertSerial = utils.SafeString(fields[13])
		entry.TLSCipher = utils.SafeString(fields[14])
		entry.TLSProtocolVersion = utils.SafeString(fields[15])
		entry.TLSNamedGroup = utils.SafeString(fields[16])
		entry.DomainName = utils.SafeString(fields[17])
		entry.ALPNFrontEndProtocol = utils.SafeString(fields[18])
		entry.ALPNBackEndProtocol = utils.SafeString(fields[19])
		entry.ALPNClientPreferenceList = utils.SafeString(fields[20])
		entry.TLSConnectionCreationTime = utils.SafeString(fields[21])
		return entry, nil
	}

	// Fallback for intermediate lengths (11 to 21 fields):
	if entry.Type == "tcp" {
		entry.ReceivedBytes = utils.ParseInt64(fields[len(fields)-2])
		entry.SentBytes = utils.ParseInt64(fields[len(fields)-1])
		if len(fields) >= 11 {
			entry.TLSHandshakeTime = utils.ParseFloat(fields[8])
		}
	} else {
		entry.TLSHandshakeTime = utils.ParseFloat(fields[8])
		if len(fields) > 9 {
			entry.ReceivedBytes = utils.ParseInt64(fields[9])
		}
		if len(fields) > 10 {
			entry.SentBytes = utils.ParseInt64(fields[10])
		}
	}

	return entry, nil
}
