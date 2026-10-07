package license

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

// DefaultRegistryNamespace is the unified CloudWatch metrics namespace for otel-aws-log-processor.
const DefaultRegistryNamespace = "Divmora/OALP"

// MetricNameMonitoredResourceActive is the CloudWatch metric name for tracking active monitored resources.
const MetricNameMonitoredResourceActive = "MonitoredResourceActive"

// DefaultRegistrySlidingWindow is the time window over which monitored resources are considered active (1 hour).
const DefaultRegistrySlidingWindow = 1 * time.Hour

// DefaultRegistryLeaseDuration is the in-container cache duration before querying CloudWatch again (3 minutes).
const DefaultRegistryLeaseDuration = 3 * time.Minute

// CloudWatchRegistryAPI defines the subset of the AWS CloudWatch Client API required for distributed registry operations.
type CloudWatchRegistryAPI interface {
	PutMetricData(ctx context.Context, params *cloudwatch.PutMetricDataInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricDataOutput, error)
	GetMetricData(ctx context.Context, params *cloudwatch.GetMetricDataInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error)
	ListMetrics(ctx context.Context, params *cloudwatch.ListMetricsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.ListMetricsOutput, error)
}

// RegistryOption configures operational parameters of the CloudWatchResourceRegistry.
type RegistryOption func(*CloudWatchRegistry)

// WithRegistryNamespace overrides the default CloudWatch namespace ("Divmora/OALP").
func WithRegistryNamespace(ns string) RegistryOption {
	return func(r *CloudWatchRegistry) {
		if strings.TrimSpace(ns) != "" {
			r.namespace = strings.TrimSpace(ns)
		}
	}
}

// WithRegistrySlidingWindow sets the active time window for resource counting.
func WithRegistrySlidingWindow(w time.Duration) RegistryOption {
	return func(r *CloudWatchRegistry) {
		if w > 0 {
			r.slidingWindow = w
		}
	}
}

// WithRegistryLeaseDuration sets the in-container lease cache duration.
func WithRegistryLeaseDuration(l time.Duration) RegistryOption {
	return func(r *CloudWatchRegistry) {
		if l > 0 {
			r.leaseDuration = l
		}
	}
}

type entitlementState struct {
	cachedCount    int
	leaseExpiresAt time.Time
	knownARNs      map[string]struct{}
}

// CloudWatchRegistry implements a distributed, tamper-proof monitored resource registry
// backed by AWS CloudWatch Metrics to enforce MaxResources limits across concurrent Lambda environments.
type CloudWatchRegistry struct {
	client        CloudWatchRegistryAPI
	namespace     string
	slidingWindow time.Duration
	leaseDuration time.Duration

	mu              sync.RWMutex
	lastActiveCount int
	leases          map[string]*entitlementState
	lastHeartbeats  map[string]time.Time
}

// NewCloudWatchRegistry initializes a new CloudWatch-backed distributed resource registry.
func NewCloudWatchRegistry(client CloudWatchRegistryAPI, opts ...RegistryOption) *CloudWatchRegistry {
	r := &CloudWatchRegistry{
		client:         client,
		namespace:      DefaultRegistryNamespace,
		slidingWindow:  DefaultRegistrySlidingWindow,
		leaseDuration:  DefaultRegistryLeaseDuration,
		leases:         make(map[string]*entitlementState),
		lastHeartbeats: make(map[string]time.Time),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// RegisterAndCount records heartbeats for the given resource ARNs under the entitlementKey,
// and returns the total count of distinct active resources within the sliding window across all containers.
func (r *CloudWatchRegistry) RegisterAndCount(ctx context.Context, entitlementKey string, resourceARNs []string, evalTime time.Time) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	}
	entitlementKey = strings.TrimSpace(entitlementKey)
	if entitlementKey == "" {
		entitlementKey = "unlicensed"
	}

	// Filter and deduplicate input ARNs
	uniqueInputs := make(map[string]struct{})
	for _, arn := range resourceARNs {
		arn = strings.TrimSpace(arn)
		if arn != "" {
			uniqueInputs[arn] = struct{}{}
		}
	}

	// If no client is available, fallback to in-container memory tracking
	if r == nil || r.client == nil {
		if r == nil {
			return len(uniqueInputs), nil
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		state := r.leases[entitlementKey]
		if state == nil {
			state = &entitlementState{
				knownARNs: make(map[string]struct{}),
			}
			r.leases[entitlementKey] = state
		}
		for arn := range uniqueInputs {
			state.knownARNs[arn] = struct{}{}
		}
		state.cachedCount = len(state.knownARNs)
		r.lastActiveCount = state.cachedCount
		return state.cachedCount, nil
	}

	// 1. Identify ARNs needing heartbeats (not sent within the last 1 minute to avoid excessive writes)
	toPublish := r.filterHeartbeatsToPublish(entitlementKey, uniqueInputs, evalTime)

	// 2. Publish heartbeats to CloudWatch
	if len(toPublish) > 0 {
		if err := r.publishHeartbeats(ctx, entitlementKey, toPublish, evalTime); err != nil {
			slog.Warn("Failed to publish resource registry heartbeats to CloudWatch", "error", err, "namespace", r.namespace, "entitlement_key", entitlementKey)
			if errors.Is(err, ErrCloudWatchRegistryAccessDenied) {
				return 0, err
			}
		}
	}

	// 3. Evaluate active resource count (using in-container lease cache when valid)
	return r.evaluateActiveCount(ctx, entitlementKey, uniqueInputs, evalTime)
}

func (r *CloudWatchRegistry) filterHeartbeatsToPublish(entitlementKey string, inputs map[string]struct{}, evalTime time.Time) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var toPublish []string
	for arn := range inputs {
		hbKey := entitlementKey + "\x00" + arn
		last, exists := r.lastHeartbeats[hbKey]
		if !exists || evalTime.Sub(last) >= 1*time.Minute {
			toPublish = append(toPublish, arn)
		}
	}
	return toPublish
}

func (r *CloudWatchRegistry) markHeartbeatsPublished(entitlementKey string, arns []string, evalTime time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, arn := range arns {
		hbKey := entitlementKey + "\x00" + arn
		r.lastHeartbeats[hbKey] = evalTime
	}
}

func (r *CloudWatchRegistry) publishHeartbeats(ctx context.Context, entitlementKey string, arns []string, evalTime time.Time) error {
	data := make([]cwtypes.MetricDatum, 0, len(arns))
	for _, arn := range arns {
		data = append(data, cwtypes.MetricDatum{
			MetricName: aws.String(MetricNameMonitoredResourceActive),
			Value:      aws.Float64(1.0),
			Unit:       cwtypes.StandardUnitCount,
			Timestamp:  &evalTime,
			Dimensions: []cwtypes.Dimension{
				{Name: aws.String("EntitlementKey"), Value: aws.String(entitlementKey)},
				{Name: aws.String("ResourceARN"), Value: aws.String(arn)},
			},
		})
	}

	// CloudWatch allows up to 1000 metrics per PutMetricData request; send in chunks of 20
	const chunkSize = 20
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunkARNs := arns[i:end]
		putCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := r.client.PutMetricData(putCtx, &cloudwatch.PutMetricDataInput{
			Namespace:  aws.String(r.namespace),
			MetricData: data[i:end],
		})
		cancel()
		if err != nil {
			if strings.Contains(err.Error(), "AccessDenied") {
				return fmt.Errorf("%w: %v", ErrCloudWatchRegistryAccessDenied, err)
			}
			return err
		}
		r.markHeartbeatsPublished(entitlementKey, chunkARNs, evalTime)
	}
	return nil
}

func (r *CloudWatchRegistry) evaluateActiveCount(ctx context.Context, entitlementKey string, currentInputs map[string]struct{}, evalTime time.Time) (int, error) {
	r.mu.RLock()
	state := r.leases[entitlementKey]
	leaseValid := state != nil && !state.leaseExpiresAt.IsZero() && evalTime.Before(state.leaseExpiresAt)
	r.mu.RUnlock()

	if leaseValid {
		// Fast path: in-container lease cache is valid (0ms overhead)
		r.mu.Lock()
		defer r.mu.Unlock()
		state = r.leases[entitlementKey]
		delta := 0
		for arn := range currentInputs {
			if _, known := state.knownARNs[arn]; !known {
				state.knownARNs[arn] = struct{}{}
				delta++
			}
		}
		state.cachedCount += delta
		r.lastActiveCount = state.cachedCount
		return state.cachedCount, nil
	}

	// Slow path: lease expired or cold start -> query CloudWatch
	_, activeSet, err := r.fetchActiveCountFromCloudWatch(ctx, entitlementKey, evalTime)
	if err != nil {
		// On query failure, fallback to best-effort local known count
		r.mu.Lock()
		defer r.mu.Unlock()
		state = r.leases[entitlementKey]
		if state == nil {
			state = &entitlementState{
				knownARNs: make(map[string]struct{}),
			}
			r.leases[entitlementKey] = state
		}
		for arn := range currentInputs {
			state.knownARNs[arn] = struct{}{}
		}
		if state.cachedCount < len(state.knownARNs) {
			state.cachedCount = len(state.knownARNs)
		}
		r.lastActiveCount = state.cachedCount
		return state.cachedCount, err
	}

	// Merge current input ARNs into activeSet
	for arn := range currentInputs {
		activeSet[arn] = struct{}{}
	}
	finalCount := len(activeSet)

	// Update lease cache
	r.mu.Lock()
	r.leases[entitlementKey] = &entitlementState{
		cachedCount:    finalCount,
		leaseExpiresAt: evalTime.Add(r.leaseDuration),
		knownARNs:      activeSet,
	}
	r.lastActiveCount = finalCount
	r.mu.Unlock()

	return finalCount, nil
}

func (r *CloudWatchRegistry) fetchActiveCountFromCloudWatch(ctx context.Context, entitlementKey string, evalTime time.Time) (int, map[string]struct{}, error) {
	activeSet := make(map[string]struct{})

	// 1. Discover candidate metrics via ListMetrics filtered by EntitlementKey with pagination
	candidateARNs := make(map[string]struct{})
	var nextToken *string

	for {
		listCtx, cancelList := context.WithTimeout(ctx, 5*time.Second)
		listOut, err := r.client.ListMetrics(listCtx, &cloudwatch.ListMetricsInput{
			Namespace:  aws.String(r.namespace),
			MetricName: aws.String(MetricNameMonitoredResourceActive),
			Dimensions: []cwtypes.DimensionFilter{
				{
					Name:  aws.String("EntitlementKey"),
					Value: aws.String(entitlementKey),
				},
			},
			NextToken: nextToken,
		})
		cancelList()
		if err != nil {
			if strings.Contains(err.Error(), "AccessDenied") {
				return 0, activeSet, fmt.Errorf("%w: %v", ErrCloudWatchRegistryAccessDenied, err)
			}
			return 0, activeSet, fmt.Errorf("failed to list metrics from CloudWatch registry: %w", err)
		}

		for _, m := range listOut.Metrics {
			for _, d := range m.Dimensions {
				if d.Name != nil && *d.Name == "ResourceARN" && d.Value != nil && *d.Value != "" {
					candidateARNs[*d.Value] = struct{}{}
				}
			}
		}

		if listOut.NextToken == nil || *listOut.NextToken == "" {
			break
		}
		nextToken = listOut.NextToken
	}

	if len(candidateARNs) == 0 {
		return 0, activeSet, nil
	}

	// 2. Query sample counts over the sliding window [evalTime - slidingWindow, evalTime]
	startTime := evalTime.Add(-r.slidingWindow)
	endTime := evalTime
	periodSeconds := int32(r.slidingWindow.Seconds())
	if periodSeconds < 60 {
		periodSeconds = 60
	}

	var allQueries []cwtypes.MetricDataQuery
	queryToARN := make(map[string]string)
	idx := 0

	for arn := range candidateARNs {
		qID := fmt.Sprintf("r%d", idx)
		allQueries = append(allQueries, cwtypes.MetricDataQuery{
			Id: aws.String(qID),
			MetricStat: &cwtypes.MetricStat{
				Metric: &cwtypes.Metric{
					Namespace:  aws.String(r.namespace),
					MetricName: aws.String(MetricNameMonitoredResourceActive),
					Dimensions: []cwtypes.Dimension{
						{Name: aws.String("EntitlementKey"), Value: aws.String(entitlementKey)},
						{Name: aws.String("ResourceARN"), Value: aws.String(arn)},
					},
				},
				Period: &periodSeconds,
				Stat:   aws.String("SampleCount"),
			},
			ReturnData: aws.Bool(true),
		})
		queryToARN[qID] = arn
		idx++
	}

	// CloudWatch allows up to 500 queries per GetMetricData API call; batch in chunks
	const maxQueriesPerRequest = 500
	for i := 0; i < len(allQueries); i += maxQueriesPerRequest {
		end := i + maxQueriesPerRequest
		if end > len(allQueries) {
			end = len(allQueries)
		}
		chunk := allQueries[i:end]

		var getNextToken *string
		for {
			getCtx, cancelGet := context.WithTimeout(ctx, 5*time.Second)
			getOut, err := r.client.GetMetricData(getCtx, &cloudwatch.GetMetricDataInput{
				MetricDataQueries: chunk,
				StartTime:         &startTime,
				EndTime:           &endTime,
				NextToken:         getNextToken,
			})
			cancelGet()
			if err != nil {
				if strings.Contains(err.Error(), "AccessDenied") {
					return 0, activeSet, fmt.Errorf("%w: %v", ErrCloudWatchRegistryAccessDenied, err)
				}
				return 0, activeSet, fmt.Errorf("failed to query metric data from CloudWatch registry: %w", err)
			}

			for _, res := range getOut.MetricDataResults {
				if res.Id == nil {
					continue
				}
				// If at least one data point was recorded in the sliding window, the resource is active
				if len(res.Values) > 0 {
					totalSamples := 0.0
					for _, v := range res.Values {
						totalSamples += v
					}
					if totalSamples > 0 {
						if arn, ok := queryToARN[*res.Id]; ok {
							activeSet[arn] = struct{}{}
						}
					}
				}
			}

			if getOut.NextToken == nil || *getOut.NextToken == "" {
				break
			}
			getNextToken = getOut.NextToken
		}
	}

	return len(activeSet), activeSet, nil
}

// Reset clears the in-memory lease and observed state (primarily used in automated tests).
func (r *CloudWatchRegistry) Reset() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastActiveCount = 0
	r.leases = make(map[string]*entitlementState)
	r.lastHeartbeats = make(map[string]time.Time)
}

// Count returns the current in-memory cached count of active resources.
func (r *CloudWatchRegistry) Count() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastActiveCount
}
