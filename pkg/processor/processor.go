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

// Registry manages the available processors
type Registry struct {
	processors []LogProcessor
}

// NewRegistry creates a new processor registry
func NewRegistry() *Registry {
	return &Registry{
		processors: make([]LogProcessor, 0),
	}
}

// Register adds a processor to the registry
func (r *Registry) Register(p LogProcessor) {
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
