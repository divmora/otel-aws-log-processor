package parser

import (
	"testing"
)

func TestParseNLBLogLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    *NLBLogEntry
		wantErr bool
	}{
		{
			name: "Valid TLS log",
			line: "tls 2.0 2023-10-01T00:00:00.000000Z app/net-lb/1234567890abcdef listener/net-lb/1234567890abcdef/1234567890abcdef 1.2.3.4:12345 5.6.7.8:80 0.001 0.002 100 200 - arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012 - ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 - example.com h2 - - 2023-10-01T00:00:00.000000Z",
			want: &NLBLogEntry{
				Type:                      "tls",
				Version:                   "2.0",
				Time:                      "2023-10-01T00:00:00.000000Z",
				ELB:                       "app/net-lb/1234567890abcdef",
				ListenerID:                "listener/net-lb/1234567890abcdef/1234567890abcdef",
				ClientIP:                  "1.2.3.4",
				ClientPort:                12345,
				TargetIP:                  "5.6.7.8",
				TargetPort:                80,
				ConnectionTime:            0.001,
				TLSHandshakeTime:          0.002,
				ReceivedBytes:             100,
				SentBytes:                 200,
				ChosenCertARN:             "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
				TLSCipher:                 "ECDHE-RSA-AES128-GCM-SHA256",
				TLSProtocolVersion:        "TLSv1.2",
				DomainName:                "example.com",
				ALPNFrontEndProtocol:      "h2",
				TLSConnectionCreationTime: "2023-10-01T00:00:00.000000Z",
			},
			wantErr: false,
		},
		{
			name: "Valid standard 10-field TCP log",
			line: "tcp 2.0 2023-10-01T00:00:00.000000Z app/net-lb/1234567890abcdef listener/net-lb/1234567890abcdef/1234567890abcdef 1.2.3.4:12345 5.6.7.8:80 0.001 100 200",
			want: &NLBLogEntry{
				Type:           "tcp",
				Version:        "2.0",
				Time:           "2023-10-01T00:00:00.000000Z",
				ELB:            "app/net-lb/1234567890abcdef",
				ListenerID:     "listener/net-lb/1234567890abcdef/1234567890abcdef",
				ClientIP:       "1.2.3.4",
				ClientPort:     12345,
				TargetIP:       "5.6.7.8",
				TargetPort:     80,
				ConnectionTime: 0.001,
				ReceivedBytes:  100,
				SentBytes:      200,
			},
			wantErr: false,
		},
		{
			name: "Valid TCP log with unrouted destination hyphen",
			line: "tcp 2.0 2023-10-01T00:00:00.000000Z app/net-lb/1234567890abcdef listener/net-lb/1234567890abcdef/1234567890abcdef 1.2.3.4:12345 - 0.001 50 0",
			want: &NLBLogEntry{
				Type:           "tcp",
				Version:        "2.0",
				Time:           "2023-10-01T00:00:00.000000Z",
				ELB:            "app/net-lb/1234567890abcdef",
				ListenerID:     "listener/net-lb/1234567890abcdef/1234567890abcdef",
				ClientIP:       "1.2.3.4",
				ClientPort:     12345,
				TargetIP:       "",
				TargetPort:     0,
				ConnectionTime: 0.001,
				ReceivedBytes:  50,
				SentBytes:      0,
			},
			wantErr: false,
		},
		{
			name: "Valid TLS log with unrouted destination hyphen",
			line: "tls 2.0 2023-10-01T00:00:00.000000Z app/net-lb/1234567890abcdef listener/net-lb/1234567890abcdef/1234567890abcdef 1.2.3.4:12345 - 0.001 - 0 0 - - - - - - - - - - -",
			want: &NLBLogEntry{
				Type:           "tls",
				Version:        "2.0",
				Time:           "2023-10-01T00:00:00.000000Z",
				ELB:            "app/net-lb/1234567890abcdef",
				ListenerID:     "listener/net-lb/1234567890abcdef/1234567890abcdef",
				ClientIP:       "1.2.3.4",
				ClientPort:     12345,
				TargetIP:       "",
				TargetPort:     0,
				ConnectionTime: 0.001,
				ReceivedBytes:  0,
				SentBytes:      0,
			},
			wantErr: false,
		},
		{
			name: "Valid TCP log with unrouted destination colon minus one",
			line: "tcp 2.0 2023-10-01T00:00:00.000000Z app/net-lb/1234567890abcdef listener/net-lb/1234567890abcdef/1234567890abcdef 1.2.3.4:12345 -:-1 0.001 0 0",
			want: &NLBLogEntry{
				Type:           "tcp",
				Version:        "2.0",
				Time:           "2023-10-01T00:00:00.000000Z",
				ELB:            "app/net-lb/1234567890abcdef",
				ListenerID:     "listener/net-lb/1234567890abcdef/1234567890abcdef",
				ClientIP:       "1.2.3.4",
				ClientPort:     12345,
				TargetIP:       "",
				TargetPort:     0,
				ConnectionTime: 0.001,
				ReceivedBytes:  0,
				SentBytes:      0,
			},
			wantErr: false,
		},
		{
			name: "Valid TCP log with IPv6 bracketed client and target",
			line: "tcp 2.0 2023-10-01T00:00:00.000000Z app/net-lb/1234567890abcdef listener/net-lb/1234567890abcdef/1234567890abcdef [2001:db8:1234:5678::1]:12345 [2001:db8:1234:5678::2]:80 0.005 300 400",
			want: &NLBLogEntry{
				Type:           "tcp",
				Version:        "2.0",
				Time:           "2023-10-01T00:00:00.000000Z",
				ELB:            "app/net-lb/1234567890abcdef",
				ListenerID:     "listener/net-lb/1234567890abcdef/1234567890abcdef",
				ClientIP:       "2001:db8:1234:5678::1",
				ClientPort:     12345,
				TargetIP:       "2001:db8:1234:5678::2",
				TargetPort:     80,
				ConnectionTime: 0.005,
				ReceivedBytes:  300,
				SentBytes:      400,
			},
			wantErr: false,
		},
		{
			name:    "Empty line returns nil entry without error",
			line:    "",
			want:    nil,
			wantErr: false,
		},
		{
			name:    "Comment line returns nil entry without error",
			line:    "#Version: 2.0",
			want:    nil,
			wantErr: false,
		},
		{
			name:    "Invalid log line too short",
			line:    "invalid log line",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := &NLBParser{}
			got, err := parser.ParseLogLine(tt.line)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseNLBLogLine() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.want == nil {
				if got != nil {
					t.Fatalf("expected nil entry, got %+v", got)
				}
				return
			}
			if got.Type != tt.want.Type {
				t.Errorf("ParseNLBLogLine() Type = %v, want %v", got.Type, tt.want.Type)
			}
			if got.ClientIP != tt.want.ClientIP {
				t.Errorf("ParseNLBLogLine() ClientIP = %v, want %v", got.ClientIP, tt.want.ClientIP)
			}
			if got.ClientPort != tt.want.ClientPort {
				t.Errorf("ParseNLBLogLine() ClientPort = %v, want %v", got.ClientPort, tt.want.ClientPort)
			}
			if got.TargetIP != tt.want.TargetIP {
				t.Errorf("ParseNLBLogLine() TargetIP = %v, want %v", got.TargetIP, tt.want.TargetIP)
			}
			if got.TargetPort != tt.want.TargetPort {
				t.Errorf("ParseNLBLogLine() TargetPort = %v, want %v", got.TargetPort, tt.want.TargetPort)
			}
			if got.ReceivedBytes != tt.want.ReceivedBytes {
				t.Errorf("ParseNLBLogLine() ReceivedBytes = %v, want %v", got.ReceivedBytes, tt.want.ReceivedBytes)
			}
			if got.SentBytes != tt.want.SentBytes {
				t.Errorf("ParseNLBLogLine() SentBytes = %v, want %v", got.SentBytes, tt.want.SentBytes)
			}
			if got.ConnectionTime != tt.want.ConnectionTime {
				t.Errorf("ParseNLBLogLine() ConnectionTime = %v, want %v", got.ConnectionTime, tt.want.ConnectionTime)
			}
		})
	}
}
