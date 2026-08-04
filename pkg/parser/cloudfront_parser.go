package parser

import (
	"fmt"
	"strings"

	"github.com/divmora/otel-aws-log-parser/pkg/utils"
)

// CloudFrontLogEntry represents a parsed CloudFront log entry
// Based on https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/standard-logs-reference.html#BasicDistributionFileFormat
type CloudFrontLogEntry struct {
	Date                    string  // 1. date
	Time                    string  // 2. time
	XEdgeLocation           string  // 3. x-edge-location
	SCBytes                 int64   // 4. sc-bytes
	CIP                     string  // 5. c-ip
	CSMethod                string  // 6. cs-method
	CSHost                  string  // 7. cs(Host)
	CSURIStem               string  // 8. cs-uri-stem
	SCStatus                int     // 9. sc-status
	CSReferer               string  // 10. cs(Referer)
	CSUserAgent             string  // 11. cs(User-Agent)
	CSURIQuery              string  // 12. cs-uri-query
	CSCookie                string  // 13. cs(Cookie)
	XEdgeResultType         string  // 14. x-edge-result-type
	XEdgeRequestID          string  // 15. x-edge-request-id
	XHostHeader             string  // 16. x-host-header
	CSProtocol              string  // 17. cs-protocol
	CSBytes                 int64   // 18. cs-bytes
	TimeTaken               float64 // 19. time-taken
	XForwardedFor           string  // 20. x-forwarded-for
	SSLProtocol             string  // 21. ssl-protocol
	SSLCipher               string  // 22. ssl-cipher
	XEdgeResponseResultType string  // 23. x-edge-response-result-type
	CSProtocolVersion       string  // 24. cs-protocol-version
	FLEStatus               string  // 25. fle-status
	FLEEncryptedFields      int     // 26. fle-encrypted-fields (can be '-' or number)
	CPort                   int     // 27. c-port
	TimeToFirstByte         float64 // 28. time-to-first-byte
	XEdgeDetailedResultType string  // 29. x-edge-detailed-result-type
	SCContentType           string  // 30. sc-content-type
	SCContentLen            int64   // 31. sc-content-len
	SCRangeStart            string  // 32. sc-range-start
	SCRangeEnd              string  // 33. sc-range-end
}

// CloudFrontParquetLogEntry represents a parsed CloudFront Parquet log entry.
// CloudFront v2 logging writes all fields as STRING type, including numbers and nulls ("-").
type CloudFrontParquetLogEntry struct {
	Date                    string `parquet:"date"`
	Time                    string `parquet:"time"`
	XEdgeLocation           string `parquet:"x_edge_location,optional"`
	SCBytes                 string `parquet:"sc_bytes,optional"`
	CIP                     string `parquet:"c_ip,optional"`
	CSMethod                string `parquet:"cs_method,optional"`
	CSHost                  string `parquet:"cs_Host,optional"`
	CSURIStem               string `parquet:"cs_uri_stem,optional"`
	SCStatus                string `parquet:"sc_status,optional"`
	CSReferer               string `parquet:"cs_Referer,optional"`
	CSUserAgent             string `parquet:"cs_User_Agent,optional"`
	CSURIQuery              string `parquet:"cs_uri_query,optional"`
	CSCookie                string `parquet:"cs_Cookie,optional"`
	XEdgeResultType         string `parquet:"x_edge_result_type,optional"`
	XEdgeRequestID          string `parquet:"x_edge_request_id,optional"`
	XHostHeader             string `parquet:"x_host_header,optional"`
	CSProtocol              string `parquet:"cs_protocol,optional"`
	CSBytes                 string `parquet:"cs_bytes,optional"`
	TimeTaken               string `parquet:"time_taken,optional"`
	XForwardedFor           string `parquet:"x_forwarded_for,optional"`
	SSLProtocol             string `parquet:"ssl_protocol,optional"`
	SSLCipher               string `parquet:"ssl_cipher,optional"`
	XEdgeResponseResultType string `parquet:"x_edge_response_result_type,optional"`
	CSProtocolVersion       string `parquet:"cs_protocol_version,optional"`
	FLEStatus               string `parquet:"fle_status,optional"`
	FLEEncryptedFields      string `parquet:"fle_encrypted_fields,optional"`
	CPort                   string `parquet:"c_port,optional"`
	TimeToFirstByte         string `parquet:"time_to_first_byte,optional"`
	XEdgeDetailedResultType string `parquet:"x_edge_detailed_result_type,optional"`
	SCContentType           string `parquet:"sc_content_type,optional"`
	SCContentLen            string `parquet:"sc_content_len,optional"`
	SCRangeStart            string `parquet:"sc_range_start,optional"`
	SCRangeEnd              string `parquet:"sc_range_end,optional"`
}

// ToLogEntry converts the string-based Parquet entry into the strongly-typed CloudFrontLogEntry.
func (p *CloudFrontParquetLogEntry) ToLogEntry() *CloudFrontLogEntry {
	return &CloudFrontLogEntry{
		Date:                    p.Date,
		Time:                    p.Time,
		XEdgeLocation:           p.XEdgeLocation,
		SCBytes:                 utils.ParseInt64(p.SCBytes),
		CIP:                     p.CIP,
		CSMethod:                p.CSMethod,
		CSHost:                  p.CSHost,
		CSURIStem:               p.CSURIStem,
		SCStatus:                utils.ParseInt(p.SCStatus),
		CSReferer:               p.CSReferer,
		CSUserAgent:             p.CSUserAgent,
		CSURIQuery:              p.CSURIQuery,
		CSCookie:                p.CSCookie,
		XEdgeResultType:         p.XEdgeResultType,
		XEdgeRequestID:          p.XEdgeRequestID,
		XHostHeader:             p.XHostHeader,
		CSProtocol:              p.CSProtocol,
		CSBytes:                 utils.ParseInt64(p.CSBytes),
		TimeTaken:               utils.ParseFloat(p.TimeTaken),
		XForwardedFor:           p.XForwardedFor,
		SSLProtocol:             p.SSLProtocol,
		SSLCipher:               p.SSLCipher,
		XEdgeResponseResultType: p.XEdgeResponseResultType,
		CSProtocolVersion:       p.CSProtocolVersion,
		FLEStatus:               p.FLEStatus,
		FLEEncryptedFields:      utils.ParseInt(p.FLEEncryptedFields),
		CPort:                   utils.ParseInt(p.CPort),
		TimeToFirstByte:         utils.ParseFloat(p.TimeToFirstByte),
		XEdgeDetailedResultType: p.XEdgeDetailedResultType,
		SCContentType:           p.SCContentType,
		SCContentLen:            utils.ParseInt64(p.SCContentLen),
		SCRangeStart:            p.SCRangeStart,
		SCRangeEnd:              p.SCRangeEnd,
	}
}

// CloudFrontParser implements LogParser for CloudFront logs
type CloudFrontParser struct{}

// ParseLogLine parses a single CloudFront log line
func (p *CloudFrontParser) ParseLogLine(line string) (*CloudFrontLogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, nil
	}

	fields := strings.Split(line, "\t")
	if len(fields) < 33 {
		return nil, fmt.Errorf("invalid number of fields: got %d, expected 33", len(fields))
	}

	entry := &CloudFrontLogEntry{
		Date:                    fields[0],
		Time:                    fields[1],
		XEdgeLocation:           fields[2],
		SCBytes:                 utils.ParseInt64(fields[3]),
		CIP:                     fields[4],
		CSMethod:                fields[5],
		CSHost:                  fields[6],
		CSURIStem:               fields[7],
		SCStatus:                utils.ParseInt(fields[8]),
		CSReferer:               fields[9],
		CSUserAgent:             fields[10],
		CSURIQuery:              fields[11],
		CSCookie:                fields[12],
		XEdgeResultType:         fields[13],
		XEdgeRequestID:          fields[14],
		XHostHeader:             fields[15],
		CSProtocol:              fields[16],
		CSBytes:                 utils.ParseInt64(fields[17]),
		TimeTaken:               utils.ParseFloat(fields[18]),
		XForwardedFor:           fields[19],
		SSLProtocol:             fields[20],
		SSLCipher:               fields[21],
		XEdgeResponseResultType: fields[22],
		CSProtocolVersion:       fields[23],
		FLEStatus:               fields[24],
		FLEEncryptedFields:      utils.ParseInt(fields[25]),
		CPort:                   utils.ParseInt(fields[26]),
		TimeToFirstByte:         utils.ParseFloat(fields[27]),
		XEdgeDetailedResultType: fields[28],
		SCContentType:           fields[29],
		SCContentLen:            utils.ParseInt64(fields[30]),
		SCRangeStart:            fields[31],
		SCRangeEnd:              fields[32],
	}

	return entry, nil
}

