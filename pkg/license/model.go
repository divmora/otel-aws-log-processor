package license

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	liblicense "github.com/divmora/license-go/pkg/license"
)

// DefaultGracePeriodDays defines the standard grace period window (14 days)
// after a license token expires during which warnings are emitted before hard-blocking.
const DefaultGracePeriodDays = 14

// License tier constants.
const (
	TierCommunity  = "community"
	TierTrial      = "trial"
	TierPro        = "pro"
	TierEnterprise = "enterprise"
)

// Feature entitlement identifiers.
const (
	FeatureParserALB               = "parser.alb"
	FeatureParserNLB               = "parser.nlb"
	FeatureParserCloudFrontGzip    = "parser.cloudfront.gzip"
	FeatureParserCloudFrontParquet = "parser.cloudfront.parquet"
	FeatureParserWAF               = "parser.waf"
	FeatureParserVPCFlow           = "parser.vpc_flow"
	FeatureParserCloudTrail        = "parser.cloudtrail"
	FeatureParserRoute53           = "parser.route53"
	FeatureScopeCrossAccount       = "scope.cross_account"
	FeatureScopeOrganization       = "scope.organization"
	FeatureSenderOTLPHTTP          = "sender.otlp_http"
	FeatureSenderOTLPGRPC          = "sender.otlp_grpc"
	FeatureSecuritySecretsManager  = "security.secrets_manager"
	FeatureSecurityMTLS            = "security.mtls"
	FeatureEnrichmentGeoIP         = "enrichment.geoip"
	FeatureEnrichmentUserAgent     = "enrichment.useragent"
	FeatureMetricsEMF              = "metrics.emf"
)

// TierFeatures maps subscription plans to their default entitled feature flags.
type TierFeatures = liblicense.TierFeatures

// DefaultTierFeatures defines the canonical feature matrix mapping for otel-aws-log-processor plans.
var DefaultTierFeatures = liblicense.TierFeatures{
	TierCommunity: []string{
		"runtime.non_prod",
		FeatureParserALB,
		FeatureParserNLB,
		FeatureParserCloudFrontGzip,
		FeatureParserWAF,
		FeatureSenderOTLPHTTP,
		FeatureSecuritySecretsManager,
		FeatureMetricsEMF,
	},
	TierPro: []string{
		FeatureParserALB,
		FeatureParserNLB,
		FeatureParserCloudFrontGzip,
		FeatureParserWAF,
		FeatureSenderOTLPHTTP,
		FeatureSecuritySecretsManager,
		FeatureMetricsEMF,
	},
	TierEnterprise: []string{
		"*",
	},
}

// Customer encapsulates customer identification metadata within a signed license token.
type Customer = liblicense.Customer

// Scope defines operational boundaries restricting where and on what infrastructure the license is authorized.
type Scope = liblicense.Scope

// Limits defines quota thresholds, throughput allocations, and evaluation constraints.
type Limits struct {
	// MaxResources specifies maximum cumulative monitored resources (ALBs, NLBs, CloudFront, WAF) (0 = unlimited).
	MaxResources int `json:"max_resources,omitempty"`

	// MaxAccounts specifies maximum allowed AWS spoke accounts (0 = unlimited).
	MaxAccounts int `json:"max_accounts,omitempty"`

	// MaxMonthlyGB specifies the fair-use monthly throughput ceiling in Gigabytes (0 = uncapped).
	MaxMonthlyGB int `json:"max_monthly_gb,omitempty"`

	// MaxContainerRecords specifies in-container record limits for non-prod evaluation.
	MaxContainerRecords int64 `json:"max_container_records,omitempty"`

	// Raw contains all raw numeric limits defined in the claims.
	Raw map[string]int64 `json:"raw,omitempty"`
}

// UnmarshalJSON implements custom JSON unmarshaling for Limits to support both structured fields and arbitrary numeric limits.
func (l *Limits) UnmarshalJSON(data []byte) error {
	type Alias Limits
	var aux struct {
		Alias
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*l = Limits(aux.Alias)

	var raw map[string]int64
	if err := json.Unmarshal(data, &raw); err == nil {
		l.Raw = raw
		if l.MaxResources == 0 {
			if v, ok := raw["max_resources"]; ok {
				l.MaxResources = int(v)
			}
		}
		if l.MaxAccounts == 0 {
			if v, ok := raw["max_accounts"]; ok {
				l.MaxAccounts = int(v)
			}
		}
		if l.MaxMonthlyGB == 0 {
			if v, ok := raw["max_monthly_gb"]; ok {
				l.MaxMonthlyGB = int(v)
			}
		}
		if l.MaxContainerRecords == 0 {
			if v, ok := raw["max_container_records"]; ok {
				l.MaxContainerRecords = v
			}
		}
	}
	return nil
}

// MarshalJSON implements custom JSON marshaling for Limits ensuring all fields and Raw limits are included.
func (l *Limits) MarshalJSON() ([]byte, error) {
	out := make(map[string]any)
	for k, v := range l.Raw {
		out[k] = v
	}
	if l.MaxResources > 0 {
		out["max_resources"] = l.MaxResources
	}
	if l.MaxAccounts > 0 {
		out["max_accounts"] = l.MaxAccounts
	}
	if l.MaxMonthlyGB > 0 {
		out["max_monthly_gb"] = l.MaxMonthlyGB
	}
	if l.MaxContainerRecords > 0 {
		out["max_container_records"] = l.MaxContainerRecords
	}
	return json.Marshal(out)
}

// Claims encapsulates the canonical cryptographic claims embedded in a signed license token.
type Claims struct {
	// ID is the unique identifier for this license (e.g. UUIDv4).
	ID string `json:"id"`

	// KeyID optionally identifies the signing key used to issue this token (e.g., "divmora-2026-root" or key fingerprint).
	KeyID string `json:"kid,omitempty"`

	// Customer contains the customer organization identity and tenant details.
	Customer Customer `json:"customer"`

	// Product is the name of the software product (e.g., "gitlab-fleet-governor", "otel-aws-log-processor").
	Product string `json:"product"`

	// Plan designates the subscription or license tier (e.g., "community", "starter", "pro", "enterprise", "trial").
	Plan string `json:"plan"`

	// IssuedAt is the timestamp when the license was created.
	IssuedAt time.Time `json:"issued_at"`

	// NotBefore is the earliest timestamp when the license becomes valid.
	NotBefore time.Time `json:"not_before,omitempty"`

	// ExpiresAt is the timestamp when the license expires.
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// GracePeriodDays specifies the allowed post-expiration grace period in days.
	GracePeriodDays int `json:"grace_period_days,omitempty"`

	// Features is the list of enabled feature flags/entitlements.
	Features []string `json:"features,omitempty"`

	// Limits defines throughput allocations and quota thresholds.
	Limits *Limits `json:"limits,omitempty"`

	// Scope defines operational infrastructure, environment, account, region, namespace, and host boundaries.
	Scope *Scope `json:"scope,omitempty"`

	// Environment restricts usage to a designated environment.
	Environment string `json:"environment,omitempty"`

	// Fingerprint binds the license to a specific cluster ID, hardware signature, or machine hash.
	Fingerprint string `json:"fingerprint,omitempty"`

	// MaxVersion defines the maximum authorized software version.
	MaxVersion string `json:"max_version,omitempty"`

	// AllowedVersions defines an explicit allowlist of version patterns.
	AllowedVersions []string `json:"allowed_versions,omitempty"`

	// MaintenanceExpiresAt specifies the maintenance/support update cutoff date.
	MaintenanceExpiresAt time.Time `json:"maintenance_expires_at,omitempty"`

	// CRLURL specifies an optional remote HTTPS distribution point where revocation lists are published.
	CRLURL string `json:"crl_url,omitempty"`

	// Metadata contains arbitrary key-value custom properties.
	Metadata map[string]string `json:"metadata,omitempty"`

	tierFeatures TierFeatures
}

// WithTierFeatures returns the Claims instance configured with a tier feature matrix.
func (c *Claims) WithTierFeatures(tiers TierFeatures) *Claims {
	if c != nil {
		c.tierFeatures = tiers
	}
	return c
}

// TierFeatures returns the currently attached TierFeatures map.
func (c *Claims) TierFeatures() TierFeatures {
	if c == nil {
		return nil
	}
	return c.tierFeatures
}

// SetTierFeatures updates the attached TierFeatures map.
func (c *Claims) SetTierFeatures(tiers TierFeatures) {
	if c != nil {
		c.tierFeatures = tiers
	}
}

// HasFeature returns true if the specified feature flag is enabled in the license.
func (c *Claims) HasFeature(feature string) bool {
	if c == nil {
		return false
	}
	featureLower := strings.ToLower(strings.TrimSpace(feature))
	if len(c.tierFeatures) > 0 {
		return c.HasFeatureWithTiers(featureLower, c.tierFeatures)
	}
	return hasFeatureInList(featureLower, c.Features)
}

// HasFeatureWithTiers returns true if the feature is entitled according to tier mapping or explicit features.
func (c *Claims) HasFeatureWithTiers(feature string, tierMap TierFeatures) bool {
	if c == nil {
		return false
	}
	featureLower := strings.ToLower(strings.TrimSpace(feature))

	// 1. Check explicit features
	if hasFeatureInList(featureLower, c.Features) {
		return true
	}

	// 2. Check plan tier features
	plan := strings.ToLower(strings.TrimSpace(c.Plan))
	if plan == "" {
		plan = TierCommunity
	}
	if tierFeats, exists := tierMap[plan]; exists {
		if hasFeatureInList(featureLower, tierFeats) {
			return true
		}
	}

	return false
}

// AssertFeature returns nil if the feature is enabled, or ErrFeatureNotEntitled if not.
func (c *Claims) AssertFeature(feature string) error {
	if c.HasFeature(feature) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrFeatureNotEntitled, feature)
}

// IsAccountAllowed reports whether the target cloud tenant or account ID is authorized.
func (c *Claims) IsAccountAllowed(account string) bool {
	if c == nil || c.Scope == nil || len(c.Scope.Accounts) == 0 {
		return true
	}
	return c.Scope.IsAccountAllowed(account)
}

// IsResourceAllowed reports whether the target monitored resource is authorized.
func (c *Claims) IsResourceAllowed(resourceARN string) bool {
	if c == nil || c.Scope == nil || len(c.Scope.Resources) == 0 {
		return true
	}
	return c.Scope.IsResourceAllowed(resourceARN)
}

// AssertResource asserts that resourceARN is authorized by Scope.Resources,
// returning *ResourceNotAllowedError if not.
func (c *Claims) AssertResource(resourceARN string) error {
	if c.IsResourceAllowed(resourceARN) {
		return nil
	}
	return &ResourceNotAllowedError{
		Resource: resourceARN,
		Allowed:  GetResources(c),
	}
}

// CheckResourceLimit checks if activeCount exceeds the licensed max_resources quota.
// If the limit is 0 or uncapped, it returns nil.
// If activeCount exceeds the limit, it returns *ResourceQuotaExceededError.
func (c *Claims) CheckResourceLimit(activeCount int64) error {
	max := GetMaxResources(c)
	if max <= 0 {
		return nil
	}
	if activeCount > int64(max) {
		return &ResourceQuotaExceededError{
			Current: activeCount,
			Allowed: int64(max),
		}
	}
	return nil
}

// DaysRemaining returns days until expiration (positive) or 0 if expired.
func (c *Claims) DaysRemaining() int {
	return c.DaysRemainingAt(time.Now().UTC())
}

// DaysRemainingAt returns the number of full days remaining before expiration at reference time t.
func (c *Claims) DaysRemainingAt(t time.Time) int {
	if c == nil || c.IsPerpetual() {
		return -1
	}
	diff := c.ExpiresAt.Sub(t)
	if diff <= 0 {
		return 0
	}
	return int(diff.Hours() / 24)
}

// GraceDaysRemaining returns remaining grace period days from now.
func (c *Claims) GraceDaysRemaining() int {
	return c.GraceDaysRemainingAt(time.Now().UTC())
}

// GraceDaysRemainingAt returns remaining grace period days at reference time t.
func (c *Claims) GraceDaysRemainingAt(t time.Time, skew ...time.Duration) int {
	if c == nil || c.IsPerpetual() || !c.IsInGracePeriodAt(t, skew...) {
		return 0
	}
	effectiveExp := c.EffectiveExpiration()
	diff := effectiveExp.Sub(t)
	if diff <= 0 {
		return 0
	}
	return int(diff.Hours() / 24)
}

// IsPerpetual reports whether the license never expires.
func (c *Claims) IsPerpetual() bool {
	return c != nil && c.ExpiresAt.IsZero()
}

// IsExpired reports whether the license expiration has passed.
func (c *Claims) IsExpired() bool {
	return c.IsExpiredAt(time.Now().UTC())
}

// IsExpiredAt reports whether the license is expired at reference time t.
func (c *Claims) IsExpiredAt(t time.Time, skew ...time.Duration) bool {
	if c == nil || c.IsPerpetual() {
		return false
	}
	return t.After(c.ExpiresAt)
}

// IsInGracePeriod reports whether the license is within its post-expiration grace period.
func (c *Claims) IsInGracePeriod() bool {
	return c.IsInGracePeriodAt(time.Now().UTC())
}

// IsInGracePeriodAt reports whether the license is within its grace period at reference time t.
func (c *Claims) IsInGracePeriodAt(t time.Time, skew ...time.Duration) bool {
	if c == nil || c.IsPerpetual() {
		return false
	}
	if !c.IsExpiredAt(t, skew...) {
		return false
	}
	return t.Before(c.EffectiveExpiration())
}

// EffectiveExpiration returns the hard cutoff timestamp including grace period.
func (c *Claims) EffectiveExpiration() time.Time {
	if c == nil || c.IsPerpetual() {
		return time.Time{}
	}
	graceDays := c.GracePeriodDays
	if graceDays <= 0 {
		graceDays = DefaultGracePeriodDays
	}
	return c.ExpiresAt.AddDate(0, 0, graceDays)
}

// ValidateClaimsSchema validates the Claims struct against the DIV1 claims schema constraints.
func (c *Claims) ValidateClaimsSchema() error {
	if c.ID == "" {
		return fmt.Errorf("%w: claims.id is required", liblicense.ErrInvalidLicenseFormat)
	}
	if c.Customer.Name == "" {
		return fmt.Errorf("%w: claims.customer.name is required", liblicense.ErrInvalidLicenseFormat)
	}
	if c.Product == "" {
		return fmt.Errorf("%w: claims.product is required", liblicense.ErrInvalidLicenseFormat)
	}
	if c.Plan == "" {
		return fmt.Errorf("%w: claims.plan is required", liblicense.ErrInvalidLicenseFormat)
	}
	if c.IssuedAt.IsZero() {
		return fmt.Errorf("%w: claims.issued_at is required", liblicense.ErrInvalidLicenseFormat)
	}
	return nil
}

// DefaultCommunityClaims returns standard community tier claims for the product.
func DefaultCommunityClaims(product string) *Claims {
	return &Claims{
		ID: "community-default",
		Customer: Customer{
			Name: "Community User",
		},
		Product:  product,
		Plan:     TierCommunity,
		IssuedAt: time.Now().UTC(),
		Scope:    &Scope{},
	}
}

// VerificationResult encapsulates verified license claims alongside explicit grace period dynamics.
type VerificationResult = liblicense.VerificationResult

// BSLPolicy defines the Business Source License 1.1 parameters and Additional Use Grants.
type BSLPolicy = liblicense.BSLPolicy

// BSLAdditionalUseGrant defines permitted non-commercial or free-tier usage rights under BSL 1.1.
type BSLAdditionalUseGrant = liblicense.BSLAdditionalUseGrant

// BSLUsageRequest specifies the operational context to evaluate against BSL 1.1 terms.
type BSLUsageRequest = liblicense.BSLUsageRequest

// BSLEntitlementResult is the evaluation result of a BSLUsageRequest against BSLPolicy.
type BSLEntitlementResult = liblicense.BSLEntitlementResult

// EnforcementPolicy defines how the Manager handles license expiration, missing licenses, or verification failures.
type EnforcementPolicy = liblicense.EnforcementPolicy

// Enforcement policy constants.
const (
	PolicyStrict   = liblicense.PolicyStrict
	PolicyDegraded = liblicense.PolicyDegraded
	PolicyWarnOnly = liblicense.PolicyWarnOnly
)

// Manager encapsulates lifecycle management and continuous monitoring of license state.
type Manager = liblicense.Manager

// ManagerConfig provides configuration parameters for the background License Manager.
type ManagerConfig = liblicense.ManagerConfig

// Certificate Revocation List (CRL) types and errors.
var (
	// ErrLicenseRevoked is returned when a license has been explicitly invalidated by a Certificate Revocation List (CRL).
	ErrLicenseRevoked = liblicense.ErrLicenseRevoked

	// ErrInvalidCRL is returned when a CRL token format, signature, or payload schema is invalid.
	ErrInvalidCRL = liblicense.ErrInvalidCRL

	// ErrCRLExpired is returned when a CRL has exceeded its NextUpdate validity cutoff.
	ErrCRLExpired = liblicense.ErrCRLExpired

	// ErrCRLMissing is returned when a Certificate Revocation List is required by policy but not found.
	ErrCRLMissing = liblicense.ErrCRLMissing

	// ErrFeatureNotEntitled is returned when a requested feature is not granted by the active license tier/plan.
	ErrFeatureNotEntitled = liblicense.ErrFeatureNotEntitled

	// ErrCommercialLicenseRequired is returned when usage exceeds BSL 1.1 grants and requires a commercial license.
	ErrCommercialLicenseRequired = liblicense.ErrCommercialLicenseRequired

	// ErrResourceQuotaExceeded is returned when the count of active monitored resources exceeds MaxResources.
	ErrResourceQuotaExceeded = liblicense.ErrResourceQuotaExceeded

	// ErrResourceNotAllowed is returned when a resource ARN is not authorized by Scope.Resources.
	ErrResourceNotAllowed = liblicense.ErrResourceNotAllowed

	// ErrCloudWatchRegistryAccessDenied is returned when CloudWatch API access is denied during registry operations.
	ErrCloudWatchRegistryAccessDenied = errors.New("access denied to CloudWatch distributed resource registry")
)

// Resource quota and scope structured error types.
type (
	// ResourceQuotaExceededError provides structured details when monitored resource count exceeds quota.
	ResourceQuotaExceededError = liblicense.ResourceQuotaExceededError

	// ResourceNotAllowedError provides structured details when a resource is not authorized by Scope.Resources.
	ResourceNotAllowedError = liblicense.ResourceNotAllowedError
)

// LicenseRevokedError provides structured details when a license has been invalidated by a CRL.
type LicenseRevokedError = liblicense.LicenseRevokedError

// ResolvedCRL encapsulates resolved Certificate Revocation List content and provenance.
type ResolvedCRL = liblicense.ResolvedCRL

// RevocationListClaims contains the authenticated payload of a signed Certificate Revocation List.
type RevocationListClaims = liblicense.RevocationListClaims

// RevocationEntry represents a single invalidated license record within a CRL.
type RevocationEntry = liblicense.RevocationEntry

// Online Certificate Revocation List (CRL) synchronization types.
type (
	// CRLSyncer manages remote fetching, HTTP conditional caching (ETag/304),
	// cryptographic verification, and atomic disk persistence of Certificate Revocation Lists.
	CRLSyncer = liblicense.CRLSyncer

	// CRLSyncConfig defines configuration parameters for dynamic CRL synchronization.
	CRLSyncConfig = liblicense.CRLSyncConfig

	// SyncResult details the outcome of a synchronization cycle.
	SyncResult = liblicense.SyncResult

	// SyncSource identifies the provenance of the revocation claims (remote, not_modified, cache).
	SyncSource = liblicense.SyncSource
)

// GetClaimsPlan returns the subscription plan/tier from Claims.
func GetClaimsPlan(c *Claims) string {
	if c == nil || c.Plan == "" {
		return "community"
	}
	return c.Plan
}

// GetAllowedAccounts returns the list of authorized accounts from Claims.Scope.Accounts.
func GetAllowedAccounts(c *Claims) []string {
	if c == nil || c.Scope == nil {
		return nil
	}
	return c.Scope.Accounts
}

// GetMaxResources returns the maximum authorized monitored resources from Claims.Limits.
// Returns 0 if uncapped or unlimited.
func GetMaxResources(c *Claims) int {
	if c == nil || c.Limits == nil {
		return 0
	}
	if c.Limits.MaxResources > 0 {
		return c.Limits.MaxResources
	}
	if v, ok := c.Limits.Raw["max_resources"]; ok && v > 0 {
		return int(v)
	}
	return 0
}

// GetResources returns the list of authorized resource patterns from Claims.Scope.Resources.
func GetResources(c *Claims) []string {
	if c == nil || c.Scope == nil {
		return nil
	}
	return c.Scope.Resources
}

// GetAllowedResources returns the list of authorized resource patterns from Claims.Scope.Resources.
// Alias for GetResources for compatibility.
func GetAllowedResources(c *Claims) []string {
	return GetResources(c)
}

// GetMaxAccounts returns the maximum allowed AWS accounts from Claims.Limits.
// Returns 0 if uncapped or unlimited.
func GetMaxAccounts(c *Claims) int {
	if c == nil || c.Limits == nil {
		return 0
	}
	if c.Limits.MaxAccounts > 0 {
		return c.Limits.MaxAccounts
	}
	if v, ok := c.Limits.Raw["max_accounts"]; ok && v > 0 {
		return int(v)
	}
	return 0
}

// IsResourceAllowed checks whether a monitored resource ARN or identifier is authorized
// by Claims.Scope.Resources.
// If Resources is nil or empty, all resources are authorized (unrestricted).
func IsResourceAllowed(c *Claims, resourceARN string) bool {
	if c == nil || c.Scope == nil || len(c.Scope.Resources) == 0 {
		return true
	}
	return c.Scope.IsResourceAllowed(resourceARN)
}

// GetMaxMonthlyGB returns the fair-use monthly throughput ceiling in Gigabytes from Claims.Limits.MaxMonthlyGB.
// Returns 0 if uncapped or unlimited.
func GetMaxMonthlyGB(c *Claims) int {
	if c == nil || c.Limits == nil {
		return 0
	}
	if c.Limits.MaxMonthlyGB > 0 {
		return c.Limits.MaxMonthlyGB
	}
	if v, ok := c.Limits.Raw["max_monthly_gb"]; ok && v > 0 {
		return int(v)
	}
	return 0
}

// ResolveCentralMetricsRegion extracts the authoritative centralized CloudWatch metrics region
// from the cryptographically signed license claims metadata, strictly defaulting to "us-east-1".
// No environment variable overrides are permitted to ensure uniform aggregation across all deployed regions.
func ResolveCentralMetricsRegion(c *Claims) string {
	if c != nil && c.Metadata != nil {
		if r, ok := c.Metadata["metrics_region"]; ok && strings.TrimSpace(r) != "" {
			return strings.TrimSpace(r)
		}
		if r, ok := c.Metadata["cloudwatch_metrics_region"]; ok && strings.TrimSpace(r) != "" {
			return strings.TrimSpace(r)
		}
	}
	return "us-east-1"
}

// ResolveEntitlementKey determines the canonical scoping dimension for resource registry metrics.
// Resolution Order:
// 1. Metadata["subscription_id"] (Explicit subscription lineage across annual renewals - Strategy 1)
// 2. Customer.OrgID              (Organization-level tenant lineage - Strategy 1)
// 3. Claims.ID                   (Unique license token UUID - Strategy 2 fallback)
// 4. "bsl1.1-free"               (Non-production / community exemption fallback)
func ResolveEntitlementKey(c *Claims, env string) string {
	if c != nil {
		if c.Metadata != nil {
			if subID := strings.TrimSpace(c.Metadata["subscription_id"]); subID != "" {
				return subID
			}
		}
		if orgID := strings.TrimSpace(c.Customer.OrgID); orgID != "" {
			return orgID
		}
		if c.ID != "" {
			return c.ID
		}
	}
	if IsNonProductionEnvironment(env) {
		return "bsl1.1-free"
	}
	return "unlicensed"
}

// GetCurrentRegion returns the executing AWS region resolved from standard AWS execution environment variables.
// Defaults strictly to "us-east-1" if unset.
func GetCurrentRegion() string {
	r := os.Getenv("AWS_REGION")
	if r == "" {
		r = os.Getenv("AWS_DEFAULT_REGION")
	}
	if r == "" {
		r = "us-east-1"
	}
	return strings.TrimSpace(r)
}

// ValidationStatus represents the outcome of evaluating license compliance for an execution.
type ValidationStatus struct {
	// Valid indicates whether the execution is authorized (either by license, non-prod exemption, or Apache conversion).
	Valid bool `json:"valid"`

	// InGracePeriod indicates whether the license is past its ExpiresAt date but within its grace window.
	InGracePeriod bool `json:"in_grace_period"`

	// DaysRemaining indicates days until expiration (positive) or days left in grace period (negative or 0).
	DaysRemaining int `json:"days_remaining"`

	// QuotaExceeded indicates whether non-production fair-use rate/volume thresholds were exceeded.
	QuotaExceeded bool `json:"quota_exceeded"`

	// ThroughputExceeded indicates whether fair-use monthly throughput ceiling was exceeded.
	ThroughputExceeded bool `json:"throughput_exceeded,omitempty"`

	// StatusReason is a machine-readable status tag (e.g. "valid", "grace_period", "unlicensed_production", "non_prod_free", "quota_exceeded").
	StatusReason string `json:"status_reason"`

	// Message contains human-readable diagnostic details.
	Message string `json:"message"`

	// Claims contains the verified license claims (nil if unlicensed).
	Claims *Claims `json:"claims,omitempty"`
}

// AssertFeature evaluates whether a feature is entitled under the validation status and environment.
// Non-production environments and Apache-converted binaries are entitled to all features free of charge.
// For production workloads with commercial claims, it checks against DefaultTierFeatures and explicit features.
func AssertFeature(status *ValidationStatus, env string, feature string) error {
	if IsNonProductionEnvironment(env) {
		return nil
	}
	if status != nil && status.StatusReason == "apache_converted" {
		return nil
	}
	if status == nil || status.Claims == nil {
		return ErrCommercialLicenseRequired
	}
	return status.Claims.WithTierFeatures(DefaultTierFeatures).AssertFeature(feature)
}

// HasFeature returns true if the feature is entitled under the validation status and environment.
func HasFeature(status *ValidationStatus, env string, feature string) bool {
	return AssertFeature(status, env, feature) == nil
}

// IsDeterministicLicenseError reports whether an error represents a permanent license compliance failure
// that cannot be resolved by an immediate retry (e.g. missing license, expired license, revoked license,
// account mismatch, unentitled feature, resource quota breach, or unauthorized resource).
// In serverless execution (AWS Lambda with SQS), such errors must not trigger unhandled SQS retries
// to prevent infinite retry loops and billing inflation.
func IsDeterministicLicenseError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrCommercialLicenseRequired) ||
		errors.Is(err, ErrFeatureNotEntitled) ||
		errors.Is(err, ErrLicenseRevoked) ||
		errors.Is(err, ErrResourceQuotaExceeded) ||
		errors.Is(err, ErrResourceNotAllowed) ||
		errors.Is(err, ErrCloudWatchRegistryAccessDenied) ||
		errors.Is(err, liblicense.ErrExpired) ||
		errors.Is(err, liblicense.ErrNotYetValid) ||
		errors.Is(err, liblicense.ErrProductMismatch) ||
		errors.Is(err, liblicense.ErrInvalidSignature) ||
		errors.Is(err, liblicense.ErrInvalidLicenseFormat) ||
		errors.Is(err, liblicense.ErrLicenseNotFound) ||
		errors.Is(err, liblicense.ErrScopeMismatch) ||
		errors.Is(err, liblicense.ErrVersionNotEntitled) ||
		errors.Is(err, liblicense.ErrMaintenanceExpired) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "COMMERCIAL LICENSE") ||
		strings.Contains(msg, "license verification failed") ||
		strings.Contains(msg, "ACCOUNT MISMATCH") ||
		strings.Contains(msg, "RESOURCE QUOTA EXCEEDED") ||
		strings.Contains(msg, "RESOURCE NOT ALLOWED") ||
		strings.Contains(msg, "not authorized") ||
		strings.Contains(msg, "AccessDenied")
}

// MatchResourcePattern matches a resource ARN or identifier against a pattern.
// Supported patterns:
//   - "*" or "all": matches any resource
//   - Exact string match (case-insensitive)
//   - Wildcards (* and ?) anywhere in the pattern
//   - Pattern without "arn:aws:" prefix matching against the resource suffix of an ARN
func MatchResourcePattern(pattern string, resourceARN string) bool {
	return liblicense.MatchResourcePattern(pattern, resourceARN)
}

func hasFeatureInList(target string, list []string) bool {
	for _, f := range list {
		fLower := strings.ToLower(strings.TrimSpace(f))
		if fLower == "*" || fLower == "all" || fLower == target {
			return true
		}
		if strings.ContainsAny(fLower, "*?[") {
			if matched, err := path.Match(fLower, target); err == nil && matched {
				return true
			}
		}
	}
	return false
}
