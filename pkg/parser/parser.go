package parser

// LogParser defines the interface for parsing log files and lines.
// T is the type of the log entry struct.
type LogParser[T any] interface {
	// ParseLogLine parses a single log line and returns the parsed entry.
	ParseLogLine(line string) (*T, error)
}
