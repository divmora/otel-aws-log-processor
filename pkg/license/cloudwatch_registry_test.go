package license

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

// mockCloudWatchRegistryAPI implements CloudWatchRegistryAPI with in-memory storage for testing.
type mockCloudWatchRegistryAPI struct {
	mu           sync.Mutex
	dataPoints   map[string]map[string][]time.Time // entitlementKey -> resourceARN -> []timestamps
	recordedData []cwtypes.MetricDatum
	putCalls     int
	listCalls    int
	getCalls     int
	putErr       error
	listErr      error
	getErr       error
}

func newMockCloudWatchRegistryAPI() *mockCloudWatchRegistryAPI {
	return &mockCloudWatchRegistryAPI{
		dataPoints: make(map[string]map[string][]time.Time),
	}
}

func (m *mockCloudWatchRegistryAPI) PutMetricData(ctx context.Context, params *cloudwatch.PutMetricDataInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricDataOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.putCalls++
	if m.putErr != nil {
		return nil, m.putErr
	}

	m.recordedData = append(m.recordedData, params.MetricData...)

	for _, datum := range params.MetricData {
		var entitlementKey, resourceARN string
		for _, dim := range datum.Dimensions {
			if dim.Name != nil && dim.Value != nil {
				if *dim.Name == "EntitlementKey" {
					entitlementKey = *dim.Value
				} else if *dim.Name == "ResourceARN" {
					resourceARN = *dim.Value
				}
			}
		}
		if entitlementKey != "" && resourceARN != "" {
			if m.dataPoints[entitlementKey] == nil {
				m.dataPoints[entitlementKey] = make(map[string][]time.Time)
			}
			ts := time.Now().UTC()
			if datum.Timestamp != nil {
				ts = *datum.Timestamp
			}
			m.dataPoints[entitlementKey][resourceARN] = append(m.dataPoints[entitlementKey][resourceARN], ts)
		}
	}

	return &cloudwatch.PutMetricDataOutput{}, nil
}

func (m *mockCloudWatchRegistryAPI) ListMetrics(ctx context.Context, params *cloudwatch.ListMetricsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.ListMetricsOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listCalls++
	if m.listErr != nil {
		return nil, m.listErr
	}

	var targetKey string
	for _, dim := range params.Dimensions {
		if dim.Name != nil && *dim.Name == "EntitlementKey" && dim.Value != nil {
			targetKey = *dim.Value
		}
	}

	var metrics []cwtypes.Metric
	if resources, ok := m.dataPoints[targetKey]; ok {
		for arn := range resources {
			metrics = append(metrics, cwtypes.Metric{
				Namespace:  params.Namespace,
				MetricName: params.MetricName,
				Dimensions: []cwtypes.Dimension{
					{Name: aws.String("EntitlementKey"), Value: aws.String(targetKey)},
					{Name: aws.String("ResourceARN"), Value: aws.String(arn)},
				},
			})
		}
	}

	return &cloudwatch.ListMetricsOutput{
		Metrics: metrics,
	}, nil
}

func (m *mockCloudWatchRegistryAPI) GetMetricData(ctx context.Context, params *cloudwatch.GetMetricDataInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getCalls++
	if m.getErr != nil {
		return nil, m.getErr
	}

	var results []cwtypes.MetricDataResult
	startTime := time.Time{}
	endTime := time.Time{}
	if params.StartTime != nil {
		startTime = *params.StartTime
	}
	if params.EndTime != nil {
		endTime = *params.EndTime
	}

	for _, query := range params.MetricDataQueries {
		if query.MetricStat == nil {
			continue
		}
		var entitlementKey, resourceARN string
		for _, dim := range query.MetricStat.Metric.Dimensions {
			if dim.Name != nil && dim.Value != nil {
				if *dim.Name == "EntitlementKey" {
					entitlementKey = *dim.Value
				} else if *dim.Name == "ResourceARN" {
					resourceARN = *dim.Value
				}
			}
		}

		samples := 0.0
		if arns, ok := m.dataPoints[entitlementKey]; ok {
			if timestamps, ok := arns[resourceARN]; ok {
				for _, ts := range timestamps {
					if !ts.Before(startTime) && !ts.After(endTime) {
						samples += 1.0
					}
				}
			}
		}

		var values []float64
		if samples > 0 {
			values = append(values, samples)
		}

		results = append(results, cwtypes.MetricDataResult{
			Id:     query.Id,
			Values: values,
		})
	}

	return &cloudwatch.GetMetricDataOutput{
		MetricDataResults: results,
	}, nil
}

func TestResolveEntitlementKey(t *testing.T) {
	// 1. Subscription ID in Metadata takes top priority (Strategy 1)
	claims1 := &Claims{
		ID: "lic_uuid_111",
		Customer: Customer{
			OrgID: "org_acme",
		},
		Metadata: map[string]string{
			"subscription_id": "sub_stripe_999",
		},
	}
	if key := ResolveEntitlementKey(claims1, "production"); key != "sub_stripe_999" {
		t.Errorf("got %s, want sub_stripe_999", key)
	}

	// 2. Project metadata scoped under organization (isolates multiple projects in same org)
	claims2 := &Claims{
		ID: "lic_uuid_222",
		Customer: Customer{
			OrgID: "org_acme",
		},
		Metadata: map[string]string{
			"project": "payments",
		},
	}
	if key := ResolveEntitlementKey(claims2, "production"); key != "org_acme/payments" {
		t.Errorf("got %s, want org_acme/payments", key)
	}

	// 3. Claims.ID isolates projects when no metadata is provided (Strategy 2)
	claims3 := &Claims{
		ID: "lic_uuid_333",
		Customer: Customer{
			OrgID: "org_acme", // same org, but different license ID
		},
	}
	if key := ResolveEntitlementKey(claims3, "production"); key != "lic_uuid_333" {
		t.Errorf("got %s, want lic_uuid_333", key)
	}

	// 4. OrgID fallback if ID is empty
	claims4 := &Claims{
		Customer: Customer{
			OrgID: "org_fallback",
		},
	}
	if key := ResolveEntitlementKey(claims4, "production"); key != "org_fallback" {
		t.Errorf("got %s, want org_fallback", key)
	}

	// 5. Non-production environment fallback (no project)
	if key := ResolveEntitlementKey(nil, "development"); key != "bsl1.1-free" {
		t.Errorf("got %s, want bsl1.1-free", key)
	}

	// 6. Non-production environment with explicit project argument
	if key := ResolveEntitlementKey(nil, "development", "payments"); key != "bsl1.1-free/development/payments" {
		t.Errorf("got %s, want bsl1.1-free/development/payments", key)
	}

	// 7. Non-production environment with PROJECT_NAME env var
	t.Setenv("PROJECT_NAME", "identity")
	if key := ResolveEntitlementKey(nil, "staging"); key != "bsl1.1-free/staging/identity" {
		t.Errorf("got %s, want bsl1.1-free/staging/identity", key)
	}
	t.Setenv("PROJECT_NAME", "")

	// 8. Unlicensed production fallback
	if key := ResolveEntitlementKey(nil, "production"); key != "unlicensed" {
		t.Errorf("got %s, want unlicensed", key)
	}

	// 9. Unlicensed production with project
	if key := ResolveEntitlementKey(nil, "production", "analytics"); key != "unlicensed/analytics" {
		t.Errorf("got %s, want unlicensed/analytics", key)
	}
}

func TestCloudWatchRegistry_Strategy1_RenewalContinuity(t *testing.T) {
	mockCW := newMockCloudWatchRegistryAPI()
	reg := NewCloudWatchRegistry(mockCW, WithRegistryNamespace("Divmora/OALP"))

	subID := "sub_annual_enterprise"
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	// Step 1: Lambda running Token Year 1 registers ALB 1 and ALB 2
	arns := []string{
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-1/111",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-2/222",
	}
	count, err := reg.RegisterAndCount(context.Background(), subID, arns, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}

	// Step 2: Customer renews license, obtaining Token Year 2 with a new License ID
	// Reset container cache to simulate new Lambda container
	regNewContainer := NewCloudWatchRegistry(mockCW, WithRegistryNamespace("Divmora/OALP"))

	// Lambda running Token Year 2 with the same subscription_id processes ALB 1
	count2, err := regNewContainer.RegisterAndCount(context.Background(), subID, []string{arns[0]}, now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// It must discover both alb-1 and alb-2 from CloudWatch!
	if count2 != 2 {
		t.Errorf("expected count 2 (seamless renewal continuity), got %d", count2)
	}
}

func TestCloudWatchRegistry_InContainerLeaseCache(t *testing.T) {
	mockCW := newMockCloudWatchRegistryAPI()
	reg := NewCloudWatchRegistry(mockCW,
		WithRegistryLeaseDuration(3*time.Minute),
		WithRegistrySlidingWindow(1*time.Hour),
	)

	entitlementKey := "lic_test_lease"
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	arn1 := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-cache-1/111"

	// 1. Cold start: queries CloudWatch
	count1, err := reg.RegisterAndCount(context.Background(), entitlementKey, []string{arn1}, now)
	if err != nil {
		t.Fatalf("cold start error: %v", err)
	}
	if count1 != 1 {
		t.Errorf("got count %d, want 1", count1)
	}
	if mockCW.listCalls != 1 || mockCW.getCalls != 1 {
		t.Errorf("expected 1 list and 1 get call, got list=%d get=%d", mockCW.listCalls, mockCW.getCalls)
	}

	// 2. Warm invocation 30s later: must use lease cache (0 calls to ListMetrics and GetMetricData)
	count2, err := reg.RegisterAndCount(context.Background(), entitlementKey, []string{arn1}, now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("warm call error: %v", err)
	}
	if count2 != 1 {
		t.Errorf("got count %d, want 1", count2)
	}
	if mockCW.listCalls != 1 || mockCW.getCalls != 1 {
		t.Errorf("lease cache bypassed: got list=%d get=%d", mockCW.listCalls, mockCW.getCalls)
	}

	// 3. Warm invocation discovering a 2nd ARN during lease: increments locally without re-querying CloudWatch
	arn2 := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-cache-2/222"
	count3, err := reg.RegisterAndCount(context.Background(), entitlementKey, []string{arn2}, now.Add(60*time.Second))
	if err != nil {
		t.Fatalf("warm add error: %v", err)
	}
	if count3 != 2 {
		t.Errorf("got count %d, want 2", count3)
	}
	if mockCW.listCalls != 1 || mockCW.getCalls != 1 {
		t.Errorf("lease cache bypassed during delta: got list=%d get=%d", mockCW.listCalls, mockCW.getCalls)
	}

	// 4. Invocation after lease expiration (4 minutes later): re-queries CloudWatch
	count4, err := reg.RegisterAndCount(context.Background(), entitlementKey, []string{arn1}, now.Add(4*time.Minute))
	if err != nil {
		t.Fatalf("post-lease error: %v", err)
	}
	if count4 != 2 {
		t.Errorf("got count %d, want 2", count4)
	}
	if mockCW.listCalls != 2 || mockCW.getCalls != 2 {
		t.Errorf("expected 2 list and 2 get calls after lease expiry, got list=%d get=%d", mockCW.listCalls, mockCW.getCalls)
	}
}

func TestCloudWatchRegistry_HeartbeatRateLimiting(t *testing.T) {
	mockCW := newMockCloudWatchRegistryAPI()
	reg := NewCloudWatchRegistry(mockCW)

	entitlementKey := "lic_test_heartbeat"
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	arn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-hb/111"

	// Call 1 at T+0s: publishes heartbeat
	_, _ = reg.RegisterAndCount(context.Background(), entitlementKey, []string{arn}, now)
	if mockCW.putCalls != 1 {
		t.Errorf("expected 1 put call, got %d", mockCW.putCalls)
	}

	// Call 2 at T+20s: suppressed by rate limiter
	_, _ = reg.RegisterAndCount(context.Background(), entitlementKey, []string{arn}, now.Add(20*time.Second))
	if mockCW.putCalls != 1 {
		t.Errorf("expected put call to be suppressed, got %d", mockCW.putCalls)
	}

	// Call 3 at T+70s (> 1 min): publishes new heartbeat
	_, _ = reg.RegisterAndCount(context.Background(), entitlementKey, []string{arn}, now.Add(70*time.Second))
	if mockCW.putCalls != 2 {
		t.Errorf("expected 2nd put call after 1 minute, got %d", mockCW.putCalls)
	}
}

func TestCloudWatchRegistry_SlidingWindowDecommissioning(t *testing.T) {
	mockCW := newMockCloudWatchRegistryAPI()
	reg := NewCloudWatchRegistry(mockCW, WithRegistrySlidingWindow(1*time.Hour))

	entitlementKey := "lic_test_decom"
	t0 := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

	// ALB Old had traffic 2 hours ago (outside 1h sliding window)
	arnOld := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-old/111"
	mockCW.dataPoints[entitlementKey] = map[string][]time.Time{
		arnOld: {t0.Add(-2 * time.Hour)},
	}

	// ALB Active has traffic now
	arnActive := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-active/222"
	count, err := reg.RegisterAndCount(context.Background(), entitlementKey, []string{arnActive}, t0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// ALB Old must have aged out; only ALB Active is counted
	if count != 1 {
		t.Errorf("expected count 1 (alb-old aged out), got %d", count)
	}
}

func TestCloudWatchRegistry_QuotaEnforcement(t *testing.T) {
	mockCW := newMockCloudWatchRegistryAPI()
	reg := NewCloudWatchRegistry(mockCW)

	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	claims := &Claims{
		ID: "lic_quota_test",
		Customer: Customer{
			Name: "Acme",
		},
		Product:   "otel-aws-log-processor",
		Plan:      TierPro,
		IssuedAt:  now.AddDate(0, -1, 0),
		ExpiresAt: now.AddDate(0, 11, 0),
		Limits: &Limits{
			MaxResources: 2, // Quota allows maximum 2 resources
		},
	}
	token := signTestToken(claims, testPrivKey)

	arn1 := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-1/1"
	arn2 := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-2/2"
	arn3 := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-3/3"

	// 1. Ingestion of 2 resources: compliant
	status1, err1 := Enforce(EnforcementOptions{
		Environment:        "production",
		LicenseKey:         token,
		PublicKey:          testPubKey,
		CloudWatchRegistry: reg,
		SourceResourceARNs: []string{arn1, arn2},
		EvaluationTime:     now,
	})
	if err1 != nil {
		t.Fatalf("unexpected error for 2 resources: %v", err1)
	}
	if !status1.Valid {
		t.Errorf("expected valid for 2 resources, got status: %s", status1.StatusReason)
	}

	// 2. Ingestion of 3rd resource: exceeds quota of 2
	// Warn mode: returns invalid status without error
	status2, err2 := Enforce(EnforcementOptions{
		Environment:        "production",
		LicenseKey:         token,
		PublicKey:          testPubKey,
		CloudWatchRegistry: reg,
		SourceResourceARNs: []string{arn3},
		EnforcementMode:    "warn",
		EvaluationTime:     now.Add(10 * time.Second),
	})
	if err2 != nil {
		t.Fatalf("warn mode should not return error: %v", err2)
	}
	if status2.Valid {
		t.Error("expected invalid status when quota is exceeded")
	}
	if status2.StatusReason != "resource_quota_exceeded" {
		t.Errorf("got status_reason %s, want resource_quota_exceeded", status2.StatusReason)
	}

	// Strict mode: returns ErrResourceQuotaExceeded error
	status3, err3 := Enforce(EnforcementOptions{
		Environment:        "production",
		LicenseKey:         token,
		PublicKey:          testPubKey,
		CloudWatchRegistry: reg,
		SourceResourceARNs: []string{arn3},
		EnforcementMode:    "strict",
		EvaluationTime:     now.Add(20 * time.Second),
	})
	if err3 == nil {
		t.Fatal("expected error in strict mode when quota is exceeded")
	}
	if !errors.Is(err3, ErrResourceQuotaExceeded) {
		t.Errorf("expected ErrResourceQuotaExceeded, got: %v", err3)
	}
	if status3.Valid {
		t.Error("expected invalid status in strict mode")
	}
}

func TestCloudWatchRegistry_AccessDeniedTamperDefense(t *testing.T) {
	mockCW := newMockCloudWatchRegistryAPI()
	mockCW.listErr = errors.New("AccessDeniedException: User is not authorized to perform: cloudwatch:ListMetrics")

	reg := NewCloudWatchRegistry(mockCW)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	claims := &Claims{
		ID: "lic_tamper_test",
		Customer: Customer{
			Name: "Acme",
		},
		Product:   "otel-aws-log-processor",
		Plan:      TierPro,
		IssuedAt:  now.AddDate(0, -1, 0),
		ExpiresAt: now.AddDate(0, 11, 0),
		Limits: &Limits{
			MaxResources: 5,
		},
	}
	token := signTestToken(claims, testPrivKey)

	// Strict mode: intentional revocation of CloudWatch permissions fails securely
	_, err := Enforce(EnforcementOptions{
		Environment:        "production",
		LicenseKey:         token,
		PublicKey:          testPubKey,
		CloudWatchRegistry: reg,
		SourceResourceARNs: []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb/1"},
		EnforcementMode:    "strict",
		EvaluationTime:     now,
	})
	if err == nil {
		t.Fatal("expected AccessDenied to fail execution in strict mode")
	}
	if !IsDeterministicLicenseError(err) {
		t.Errorf("expected AccessDenied error to be classified as deterministic: %v", err)
	}
	if !strings.Contains(err.Error(), "AccessDenied") && !errors.Is(err, ErrCloudWatchRegistryAccessDenied) {
		t.Errorf("expected AccessDenied in error, got: %v", err)
	}
}

func TestCloudWatchRegistry_NilClientFallback(t *testing.T) {
	reg := NewCloudWatchRegistry(nil)
	count, err := reg.RegisterAndCount(context.Background(), "test_key", []string{"arn1", "arn2"}, time.Now())
	if err != nil {
		t.Fatalf("unexpected error with nil client: %v", err)
	}
	if count != 2 {
		t.Errorf("expected fallback in-memory count 2, got %d", count)
	}
}

func TestCloudWatchRegistry_MultipleProjectsIsolation(t *testing.T) {
	mockCW := newMockCloudWatchRegistryAPI()
	reg := NewCloudWatchRegistry(mockCW)

	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	// Both projects belong to the same organization "org_mega_corp"
	// Project 1 (Payments): quota allows 1 resource
	claimsPayments := &Claims{
		ID: "lic_pay_01",
		Customer: Customer{
			Name:  "MegaCorp",
			OrgID: "org_mega_corp",
		},
		Product:   "otel-aws-log-processor",
		Plan:      TierPro,
		IssuedAt:  now.AddDate(0, -1, 0),
		ExpiresAt: now.AddDate(0, 11, 0),
		Limits: &Limits{
			MaxResources: 1,
		},
	}
	tokenPayments := signTestToken(claimsPayments, testPrivKey)

	// Project 2 (Analytics): quota allows 1 resource
	claimsAnalytics := &Claims{
		ID: "lic_ana_02",
		Customer: Customer{
			Name:  "MegaCorp",
			OrgID: "org_mega_corp",
		},
		Product:   "otel-aws-log-processor",
		Plan:      TierPro,
		IssuedAt:  now.AddDate(0, -1, 0),
		ExpiresAt: now.AddDate(0, 11, 0),
		Limits: &Limits{
			MaxResources: 1,
		},
	}
	tokenAnalytics := signTestToken(claimsAnalytics, testPrivKey)

	arnPaymentsALB := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-payments/1"
	arnAnalyticsALB := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-analytics/2"

	// 1. Evaluate Project 1 (Payments) with 1 ALB
	statusPay, errPay := Enforce(EnforcementOptions{
		Environment:        "production",
		LicenseKey:         tokenPayments,
		PublicKey:          testPubKey,
		CloudWatchRegistry: reg,
		SourceResourceARNs: []string{arnPaymentsALB},
		EvaluationTime:     now,
	})
	if errPay != nil || !statusPay.Valid {
		t.Fatalf("Payments project should be valid within quota: err=%v, valid=%v", errPay, statusPay.Valid)
	}

	// 2. Evaluate Project 2 (Analytics) with 1 ALB in the same account/org
	// If they collided on OrgID, total would be 2, exceeding quota of 1.
	statusAna, errAna := Enforce(EnforcementOptions{
		Environment:        "production",
		LicenseKey:         tokenAnalytics,
		PublicKey:          testPubKey,
		CloudWatchRegistry: reg,
		SourceResourceARNs: []string{arnAnalyticsALB},
		EvaluationTime:     now,
	})
	if errAna != nil || !statusAna.Valid {
		t.Fatalf("Analytics project should be isolated from Payments: err=%v, valid=%v", errAna, statusAna.Valid)
	}
}

func TestResolveRegistryRegion(t *testing.T) {
	// 1. Nil claims defaults to GetCurrentRegion()
	reg := ResolveRegistryRegion(nil)
	if reg != GetCurrentRegion() {
		t.Errorf("got %s, want %s", reg, GetCurrentRegion())
	}

	// 2. Claims with registry_scope: "global" defaults to central metrics region (us-east-1)
	claimsGlobal := &Claims{
		Metadata: map[string]string{
			"registry_scope": "global",
		},
	}
	if reg := ResolveRegistryRegion(claimsGlobal); reg != "us-east-1" {
		t.Errorf("got %s, want us-east-1 for global registry", reg)
	}

	// 3. Claims with explicit registry_region
	claimsExplicit := &Claims{
		Metadata: map[string]string{
			"registry_region": "eu-central-1",
		},
	}
	if reg := ResolveRegistryRegion(claimsExplicit); reg != "eu-central-1" {
		t.Errorf("got %s, want eu-central-1", reg)
	}

	// 4. Claims with registry_scope: "global" and custom metrics_region
	claimsGlobalCustom := &Claims{
		Metadata: map[string]string{
			"registry_scope": "global",
			"metrics_region": "ap-southeast-1",
		},
	}
	if reg := ResolveRegistryRegion(claimsGlobalCustom); reg != "ap-southeast-1" {
		t.Errorf("got %s, want ap-southeast-1", reg)
	}

	// 5. Environment variable override
	t.Setenv("DIVMORA_LICENSE_REGISTRY_REGION", "sa-east-1")
	if reg := ResolveRegistryRegion(nil); reg != "sa-east-1" {
		t.Errorf("got %s, want sa-east-1 from env override", reg)
	}
	t.Setenv("DIVMORA_LICENSE_REGISTRY_REGION", "")
}

func TestPublishCrossRegionMetrics_WithProject(t *testing.T) {
	t.Setenv("PROJECT_NAME", "checkout-payments")
	defer t.Setenv("PROJECT_NAME", "")

	mockCW := newMockCloudWatchRegistryAPI()
	status := &ValidationStatus{
		Valid:        true,
		StatusReason: "valid",
	}

	err := PublishCrossRegionMetrics(context.Background(), mockCW, status, "production", 100, 2, int64(1000))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockCW.mu.Lock()
	defer mockCW.mu.Unlock()

	foundProjectDim := false
	for _, datum := range mockCW.recordedData {
		for _, d := range datum.Dimensions {
			if d.Name != nil && *d.Name == "Project" && d.Value != nil && *d.Value == "checkout-payments" {
				foundProjectDim = true
				break
			}
		}
	}
	if !foundProjectDim {
		t.Errorf("expected Project dimension with value 'checkout-payments' in cross-region metrics")
	}
}
