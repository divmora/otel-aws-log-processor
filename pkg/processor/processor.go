package processor

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/divmora/otel-aws-log-processor/pkg/model"
)

// LogProcessor defines the interface for processing different log types
type LogProcessor interface {
	// Name returns the unique name of the processor
	Name() string
	// Matches returns true if this processor should handle the given S3 object
	Matches(bucket, key string) bool
	// Process handles the log file and returns OTel-ready adapters
	Process(ctx context.Context, logger *slog.Logger, s3Client *s3.Client, bucket, key string) ([]LogAdapter, error)
}

// ByteTracker defines an interface for atomically recording bytes processed during streaming decompression.
type ByteTracker interface {
	RecordBytes(n int64) int64
}

// ByteTrackable represents a processor that can be configured with a ByteTracker.
type ByteTrackable interface {
	SetByteTracker(bt ByteTracker)
}

// Registry manages the available processors
type Registry struct {
	processors  []LogProcessor
	byteTracker ByteTracker
}

// NewRegistry creates a new processor registry
func NewRegistry() *Registry {
	return &Registry{
		processors: make([]LogProcessor, 0),
	}
}

// SetByteTracker configures a ByteTracker on all registered processors that support it.
func (r *Registry) SetByteTracker(bt ByteTracker) {
	r.byteTracker = bt
	for _, p := range r.processors {
		if trackable, ok := p.(ByteTrackable); ok {
			trackable.SetByteTracker(bt)
		}
	}
}

// Register adds a processor to the registry
func (r *Registry) Register(p LogProcessor) {
	if r.byteTracker != nil {
		if trackable, ok := p.(ByteTrackable); ok {
			trackable.SetByteTracker(r.byteTracker)
		}
	}
	r.processors = append(r.processors, p)
}

// Find returns the first processor that matches the bucket and key
func (r *Registry) Find(bucket, key string) LogProcessor {
	for _, p := range r.processors {
		if p.Matches(bucket, key) {
			return p
		}
	}
	return nil
}

// LogAdapter interface for polymorphic log handling
type LogAdapter interface {
	GetResourceKey() string
	GetResourceAttributes() []model.OTelAttribute
	BuildAttributes() []model.OTelAttribute
	ToOTel() model.OTelLogRecord
}
