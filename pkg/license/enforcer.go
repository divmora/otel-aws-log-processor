package license

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	liblicense "github.com/divmora/license-go/pkg/license"
	"github.com/divmora/otel-aws-log-processor/pkg/model"
	"github.com/divmora/otel-aws-log-processor/pkg/utils"
	"github.com/divmora/otel-aws-log-processor/pkg/version"
)

// Extra non-production environments supplementing liblicense.DefaultNonProductionEnvironments.
var extraNonProdEnvironments = []string{"preview", "poc"}

// Production environment identifiers.
var prodKeywords = []string{
	"production", "prod", "live", "prd",
}

// IsNonProductionEnvironment returns true if the normalized environment string indicates non-production.
// It evaluates compliance using liblicense's standard Non-Production Additional Use Grant terms.
func IsNonProductionEnvironment(env string) bool {
	grant := liblicense.NewNonProductionGrant("Non-Production Exemption", append(liblicense.DefaultNonProductionEnvironments, extraNonProdEnvironments...)...)
	eval := grant.Evaluate(liblicense.BSLUsageRequest{Environment: env})
	return eval.Matched
}

// DetectEnvironment determines the active environment tier from standard variables.
// Priority: DIVMORA_ENVIRONMENT -> ENVIRONMENT -> STAGE -> APP_ENV -> "production".
func DetectEnvironment() string {
	keys := []string{"DIVMORA_ENVIRONMENT", "ENVIRONMENT", "STAGE", "APP_ENV"}
	for _, k := range keys {
		if val := strings.TrimSpace(os.Getenv(k)); val != "" {
			return strings.ToLower(val)
		}
	}
	return "production"
}

// ExtractAccountIDFromARN extracts the 12-digit AWS Account ID from an AWS ARN string.
// Standard ARN: arn:partition:service:region:account-id:resource...
func ExtractAccountIDFromARN(arnStr string) string {
	parts := strings.Split(strings.TrimSpace(arnStr), ":")
	if len(parts) >= 5 && len(parts[4]) == 12 {
		return parts[4]
	}
	return ""
}

// ExtractCallerAccountID retrieves the AWS Account ID from the AWS Lambda context.
func ExtractCallerAccountID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	lc, ok := lambdacontext.FromContext(ctx)
	if !ok || lc == nil {
		return ""
	}
	return ExtractAccountIDFromARN(lc.InvokedFunctionArn)
}

// ResolveToken determines the active license token from options, environment, or file.
func ResolveToken(key, file string) (string, error) {
	key = strings.TrimSpace(key)
	if key != "" {
		return key, nil
	}

	file = strings.TrimSpace(file)
	if file != "" {
		content, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("failed to read license file %s: %w", file, err)
		}
		return strings.TrimSpace(string(content)), nil
	}

	token, err := liblicense.ResolveToken()
	if err != nil {
		if errors.Is(err, liblicense.ErrLicenseNotFound) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(token), nil
}

// ResourceTracker maintains in-container thread-safe tracking of active unique monitored resource identifiers.
type ResourceTracker struct {
	mu        sync.RWMutex
	resources map[string]struct{}
}

// NewResourceTracker initializes a new thread-safe ResourceTracker.
func NewResourceTracker() *ResourceTracker {
	return &ResourceTracker{
		resources: make(map[string]struct{}),
	}
}

// Track registers a resource identifier and returns the current total unique count and whether it was newly added.
func (rt *ResourceTracker) Track(resourceID string) (int, bool) {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" {
		if rt == nil {
			return 0, false
		}
		rt.mu.RLock()
		defer rt.mu.RUnlock()
		return len(rt.resources), false
	}

	if rt == nil {
		return 0, false
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if _, exists := rt.resources[resourceID]; exists {
		return len(rt.resources), false
	}
	rt.resources[resourceID] = struct{}{}
	return len(rt.resources), true
}

// Count returns the number of unique monitored resources observed in this container lifecycle.
func (rt *ResourceTracker) Count() int {
	if rt == nil {
		return 0
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return len(rt.resources)
}

// Resources returns a copy of all unique tracked resource identifiers.
func (rt *ResourceTracker) Resources() []string {
	if rt == nil {
		return nil
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	res := make([]string, 0, len(rt.resources))
	for k := range rt.resources {
		res = append(res, k)
	}
	return res
}

// Reset clears the tracker state (primarily used in testing).
func (rt *ResourceTracker) Reset() {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.resources = make(map[string]struct{})
}

var (
	albNlbKeyPattern    = regexp.MustCompile(`_elasticloadbalancing_[^_]+_(app|net)\.([^.]+)\.([^._]+)_`)
	cfKeyPattern        = regexp.MustCompile(`(?:^|/)([A-Z0-9]{8,32})\.\d{4}-\d{2}-\d{2}`)
	cfParquetPattern    = regexp.MustCompile(`(?:^|/)([A-Z0-9]{8,32})[._]`)
	wafKeyPattern       = regexp.MustCompile(`aws-waf-logs-([^/]+)`)
	awsLogsAccountRegex = regexp.MustCompile(`(?:^|/)AWSLogs/(\d{12})/`)
)

// ExtractResourceFromAttributes extracts the canonical AWS resource ARN and short identifier
// from OpenTelemetry resource attributes.
func ExtractResourceFromAttributes(attrs []model.OTelAttribute) (arn string, shortID string) {
	var lbName, distID, webACLID, accountID, region string
	for _, attr := range attrs {
		if attr.Value.StringValue == nil {
			continue
		}
		val := *attr.Value.StringValue
		switch attr.Key {
		case "aws.lb.name":
			lbName = val
		case "aws.cloudfront.distribution_id":
			distID = val
		case "aws.waf.web_acl_id":
			webACLID = val
		case "cloud.account.id":
			accountID = val
		case "cloud.region":
			region = val
		}
	}

	if lbName != "" {
		shortID = lbName
		if region != "" && accountID != "" {
			arn = fmt.Sprintf("arn:aws:elasticloadbalancing:%s:%s:loadbalancer/%s", region, accountID, lbName)
		} else {
			arn = lbName
		}
		return arn, shortID
	}

	if distID != "" {
		shortID = distID
		if accountID != "" {
			arn = fmt.Sprintf("arn:aws:cloudfront::%s:distribution/%s", accountID, distID)
		} else {
			arn = fmt.Sprintf("arn:aws:cloudfront:::distribution/%s", distID)
		}
		return arn, shortID
	}

	if webACLID != "" {
		shortID = webACLID
		if strings.HasPrefix(webACLID, "arn:aws:") {
			arn = webACLID
		} else if accountID != "" {
			if region == "" || region == "global" {
				arn = fmt.Sprintf("arn:aws:wafv2::%s:global/webacl/%s", accountID, webACLID)
			} else {
				arn = fmt.Sprintf("arn:aws:wafv2:%s:%s:regional/webacl/%s", region, accountID, webACLID)
			}
		} else {
			arn = webACLID
		}
		return arn, shortID
	}

	return "", ""
}

// ExtractResourceFromS3Key extracts the canonical AWS resource ARN and short identifier
// from standard AWS S3 log object keys.
func ExtractResourceFromS3Key(key string) (arn string, shortID string) {
	accountID, region := utils.ParseRegionAccountFromS3Key(key)
	if accountID == "" {
		if m := awsLogsAccountRegex.FindStringSubmatch(key); len(m) >= 2 {
			accountID = m[1]
		}
	}

	if matches := albNlbKeyPattern.FindStringSubmatch(key); len(matches) >= 4 {
		lbType := matches[1]
		lbName := matches[2]
		lbHash := matches[3]
		shortID = fmt.Sprintf("%s/%s/%s", lbType, lbName, lbHash)
		if region != "" && accountID != "" {
			arn = fmt.Sprintf("arn:aws:elasticloadbalancing:%s:%s:loadbalancer/%s", region, accountID, shortID)
		} else {
			arn = shortID
		}
		return arn, shortID
	}

	if matches := cfKeyPattern.FindStringSubmatch(key); len(matches) >= 2 {
		shortID = matches[1]
		if accountID != "" {
			arn = fmt.Sprintf("arn:aws:cloudfront::%s:distribution/%s", accountID, shortID)
		} else {
			arn = fmt.Sprintf("arn:aws:cloudfront:::distribution/%s", shortID)
		}
		return arn, shortID
	}

	if strings.HasSuffix(key, ".parquet") {
		if matches := cfParquetPattern.FindStringSubmatch(key); len(matches) >= 2 {
			shortID = matches[1]
			if accountID != "" {
				arn = fmt.Sprintf("arn:aws:cloudfront::%s:distribution/%s", accountID, shortID)
			} else {
				arn = fmt.Sprintf("arn:aws:cloudfront:::distribution/%s", shortID)
			}
			return arn, shortID
		}
	}

	if matches := wafKeyPattern.FindStringSubmatch(key); len(matches) >= 2 {
		shortID = matches[1]
		if strings.HasPrefix(shortID, "arn:aws:") {
			arn = shortID
		} else if accountID != "" {
			if region == "" || region == "global" {
				arn = fmt.Sprintf("arn:aws:wafv2::%s:global/webacl/%s", accountID, shortID)
			} else {
				arn = fmt.Sprintf("arn:aws:wafv2:%s:%s:regional/webacl/%s", region, accountID, shortID)
			}
		} else {
			arn = shortID
		}
		return arn, shortID
	}

	return "", ""
}

// EnforcementOptions encapsulates the operational parameters required to evaluate
// compliance with the Business Source License 1.1 terms.
type EnforcementOptions struct {
	Context            context.Context
	Environment        string
	LicenseKey         string
	LicenseFile        string
	CRL                string // Optional explicit inline CRL token or PEM block
	CRLFile            string // Optional explicit path to CRL file
	CRLURL             string // Optional explicit remote CRL URL for online synchronization
	EnforcementMode    string // "warn" (default) or "strict"
	CallerAccountID    string
	SourceAccountIDs   []string
	SourceResourceARNs []string // Unique resource ARNs or identifiers extracted from logs
	BatchRecordCount   int
	QuotaTracker       *QuotaTracker
	ResourceTracker    *ResourceTracker
	BucketName         string
	ExercisedFeatures  []string
	PublicKey          ed25519.PublicKey
	EvaluationTime     time.Time
	AuthoritativeTime  time.Time
}

// Enforce evaluates the execution against the Business Source License 1.1 terms:
// 1. Automatic Apache 2.0 Change Date check (3 years from release).
// 2. Authoritative AWS time clock skew defense.
// 3. Non-production exemption with in-container and batch fair-use ceilings.
// 4. Production commercial license verification with AWS account scoping.
func Enforce(opts EnforcementOptions) (*ValidationStatus, error) {
	evalTime := opts.EvaluationTime
	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	}

	// 1. Clock skew defense: anchor to AWS authoritative time (from S3 HTTP Date or SQS SentTimestamp)
	if !opts.AuthoritativeTime.IsZero() {
		authTime := opts.AuthoritativeTime.UTC()
		drift := evalTime.Sub(authTime)
		if drift < -15*time.Minute || drift > 15*time.Minute {
			slog.Warn("SYSTEM CLOCK SKEW DETECTED: Container clock drifts significantly from AWS authoritative server time. Anchoring evaluation to authoritative time.",
				"container_clock", evalTime.Format(time.RFC3339),
				"authoritative_clock", authTime.Format(time.RFC3339),
				"drift", drift.String(),
			)
			evalTime = authTime
		}
	}

	// 0. BSL 1.1 Change Date Check (Apache 2.0 conversion after 3 years)
	vInfo := version.Get()
	bslPolicy := GetBSLPolicy()
	if bslPolicy.IsConverted(evalTime) || vInfo.IsApacheConverted(evalTime) {
		changeDate, _ := vInfo.ChangeDate()
		return &ValidationStatus{
			Valid:        true,
			StatusReason: "apache_converted",
			Message:      fmt.Sprintf("Automatically converted to Apache License 2.0 on %s under BSL 1.1 terms. Unrestricted usage permitted.", changeDate.Format("2006-01-02")),
		}, nil
	}

	// Resolve environment
	env := strings.TrimSpace(opts.Environment)
	if env == "" {
		env = DetectEnvironment()
	}

	isNonProd := IsNonProductionEnvironment(env)
	usageReq := liblicense.BSLUsageRequest{
		Environment: env,
		Time:        evalTime,
		Metadata: map[string]string{
			"bucket": opts.BucketName,
		},
	}
	entitlement := bslPolicy.EvaluateEntitlement(usageReq)

	// Resolve enforcement mode ("warn" default vs "strict")
	mode := strings.ToLower(strings.TrimSpace(opts.EnforcementMode))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(os.Getenv("DIVMORA_LICENSE_MODE")))
	}
	if mode == "" {
		mode = "warn"
	}

	// 2. Non-Production Exemption Path
	if isNonProd || entitlement.Authorized {
		// Heuristic check: Bucket name matches production keywords
		if opts.BucketName != "" {
			lowerBucket := strings.ToLower(opts.BucketName)
			for _, pk := range prodKeywords {
				if strings.Contains(lowerBucket, pk) {
					slog.Warn("SUSPECTED PRODUCTION MISCONFIGURATION: Environment is declared as non-production, but S3 log bucket name contains production indicators.",
						"environment", env,
						"bucket", opts.BucketName,
						"hint", "Ensure production workloads are licensed under DIVMORA commercial terms",
					)
					break
				}
			}
		}

		quotaExceeded := false
		var quotaReason string

		// Fair-use quota checks
		if opts.QuotaTracker != nil && opts.BatchRecordCount > 0 {
			// Check single-invocation density
			if densityExceeded, reason := opts.QuotaTracker.CheckBatchDensity(opts.BatchRecordCount); densityExceeded {
				quotaExceeded = true
				quotaReason = reason
				slog.Warn("NON-PRODUCTION FAIR-USE DENSITY CEILING EXCEEDED: Single log archive contains production-scale record density",
					"reason", reason,
					"records", opts.BatchRecordCount,
				)
			}

			// Check container cumulative quota
			if containerExceeded, total, reason := opts.QuotaTracker.RecordAndCheckContainerQuota(opts.BatchRecordCount); containerExceeded {
				quotaExceeded = true
				quotaReason = reason
				slog.Warn("NON-PRODUCTION FAIR-USE CONTAINER CEILING EXCEEDED: Cumulative container volume exceeds fair-use limit",
					"reason", reason,
					"cumulative_records", total,
				)
			}
		}

		statusReason := "non_prod_free"
		msg := fmt.Sprintf("Non-production environment '%s' authorized free of charge under BSL 1.1 Additional Use Grant", env)
		if quotaExceeded {
			statusReason = "quota_exceeded"
			msg = fmt.Sprintf("Non-production environment '%s' active, but fair-use volume ceiling was exceeded: %s", env, quotaReason)
		}

		return &ValidationStatus{
			Valid:         true,
			StatusReason:  statusReason,
			QuotaExceeded: quotaExceeded,
			Message:       msg,
		}, nil
	}

	// 3. Production Path: Requires Valid Commercial Token
	token, err := ResolveToken(opts.LicenseKey, opts.LicenseFile)
	if err != nil {
		if mode == "strict" {
			return nil, err
		}
		slog.Warn("Failed to resolve commercial license token", "error", err)
	}

	// Resolve caller AWS account ID if omitted
	callerAccount := opts.CallerAccountID
	if callerAccount == "" {
		callerAccount = ExtractCallerAccountID(opts.Context)
	}

	// Missing Token in Production
	if token == "" {
		msg := "COMMERCIAL LICENSE REQUIRED: Running in production without a valid commercial license. Please obtain a license from licensing@divmora.com or visit https://divmora.com"
		slog.Warn("COMMERCIAL LICENSE REQUIRED",
			"environment", env,
			"caller_account", callerAccount,
			"contact", "licensing@divmora.com",
		)

		status := &ValidationStatus{
			Valid:        false,
			StatusReason: "unlicensed_production",
			Message:      msg,
		}

		if mode == "strict" {
			return status, fmt.Errorf("%s", msg)
		}
		return status, nil
	}

	// Parse and verify token
	var status *ValidationStatus
	if opts.CRL != "" || opts.CRLFile != "" {
		crlSrc := opts.CRL
		if crlSrc == "" {
			crlSrc = opts.CRLFile
		}
		status, err = ParseAndVerifyWithCRL(token, opts.PublicKey, evalTime, crlSrc)
	} else if opts.CRLURL != "" {
		status, err = ParseAndVerifyWithCRLURL(token, opts.PublicKey, evalTime, opts.CRLURL)
	} else {
		status, err = ParseAndVerifyAt(token, opts.PublicKey, evalTime)
	}
	if err != nil {
		if errors.Is(err, ErrLicenseRevoked) {
			slog.Error("COMMERCIAL LICENSE REVOKED: Active commercial license has been explicitly invalidated by Certificate Revocation List (CRL)",
				"error", err,
				"contact", "licensing@divmora.com",
			)
		} else {
			slog.Warn("Commercial license verification failed", "error", err)
		}
		if mode == "strict" {
			return status, fmt.Errorf("commercial license verification failed: %w", err)
		}
		return status, nil
	}

	// Verify Caller AWS Account ID against AllowedAWSAccounts
	if callerAccount != "" && !status.Claims.IsAccountAllowed(callerAccount) {
		mismatchMsg := fmt.Sprintf("COMMERCIAL LICENSE ACCOUNT MISMATCH: License is restricted to AWS accounts %v, but active Lambda caller account is '%s'",
			GetAllowedAccounts(status.Claims), callerAccount)
		slog.Warn(mismatchMsg, "contact", "licensing@divmora.com")
		status.Valid = false
		status.StatusReason = "account_mismatch"
		status.Message = mismatchMsg

		if mode == "strict" {
			return status, fmt.Errorf("%s", mismatchMsg)
		}
		return status, nil
	}

	// Verify Source AWS Account IDs extracted from parsed log records
	for _, srcAccount := range opts.SourceAccountIDs {
		if srcAccount != "" && !status.Claims.IsAccountAllowed(srcAccount) {
			mismatchMsg := fmt.Sprintf("COMMERCIAL LICENSE SOURCE ACCOUNT MISMATCH: License is restricted to AWS accounts %v, but traffic source log record originates from account '%s'",
				GetAllowedAccounts(status.Claims), srcAccount)
			slog.Warn(mismatchMsg, "contact", "licensing@divmora.com")
			status.Valid = false
			status.StatusReason = "source_account_mismatch"
			status.Message = mismatchMsg

			if mode == "strict" {
				return status, fmt.Errorf("%s", mismatchMsg)
			}
			return status, nil
		}
	}

	// Verify Feature Entitlements for Exercised Features
	for _, feat := range opts.ExercisedFeatures {
		feat = strings.TrimSpace(feat)
		if feat == "" {
			continue
		}
		if featErr := AssertFeature(status, env, feat); featErr != nil {
			unentitledMsg := fmt.Sprintf("COMMERCIAL LICENSE FEATURE NOT ENTITLED: Feature '%s' is not authorized by active license tier '%s'",
				feat, GetClaimsPlan(status.Claims))
			slog.Warn(unentitledMsg, "feature", feat, "tier", GetClaimsPlan(status.Claims), "contact", "licensing@divmora.com")
			status.Valid = false
			status.StatusReason = "feature_not_entitled"
			status.Message = unentitledMsg

			if mode == "strict" {
				return status, fmt.Errorf("%s: %w", unentitledMsg, featErr)
			}
			return status, nil
		}
	}

	// Verify Resource Entitlements for Source Resource ARNs against AllowedResources
	for _, resARN := range opts.SourceResourceARNs {
		resARN = strings.TrimSpace(resARN)
		if resARN == "" {
			continue
		}
		if !status.Claims.IsResourceAllowed(resARN) {
			mismatchMsg := fmt.Sprintf("COMMERCIAL LICENSE RESOURCE NOT ALLOWED: License does not authorize resource '%s' (allowed: %v)",
				resARN, GetAllowedResources(status.Claims))
			slog.Warn(mismatchMsg, "resource", resARN, "contact", "licensing@divmora.com")
			status.Valid = false
			status.StatusReason = "resource_not_allowed"
			status.Message = mismatchMsg

			if mode == "strict" {
				return status, fmt.Errorf("%s: %w", mismatchMsg, ErrResourceNotAllowed)
			}
			return status, nil
		}
	}

	// Track and verify Monitored Resource Quota (MaxResources)
	if opts.ResourceTracker != nil {
		for _, res := range opts.SourceResourceARNs {
			if res != "" {
				opts.ResourceTracker.Track(res)
			}
		}
	}

	maxResources := GetMaxResources(status.Claims)
	activeResources := 0
	if opts.ResourceTracker != nil {
		activeResources = opts.ResourceTracker.Count()
	} else {
		activeResources = len(opts.SourceResourceARNs)
	}

	if maxResources > 0 && activeResources > maxResources {
		quotaMsg := fmt.Sprintf("COMMERCIAL LICENSE RESOURCE QUOTA EXCEEDED: Active monitored resources (%d) exceeds authorized quota (%d)",
			activeResources, maxResources)
		slog.Warn(quotaMsg, "active_resources", activeResources, "max_resources", maxResources, "contact", "licensing@divmora.com")
		status.Valid = false
		status.StatusReason = "resource_quota_exceeded"
		status.Message = quotaMsg

		if mode == "strict" {
			return status, fmt.Errorf("%s: %w", quotaMsg, ErrResourceQuotaExceeded)
		}
		return status, nil
	}

	// Track and evaluate soft fair-use monthly throughput ceiling
	maxMonthlyTB := GetMaxMonthlyTB(status.Claims)
	if maxMonthlyTB > 0 && opts.QuotaTracker != nil {
		if opts.QuotaTracker.CheckThroughputQuota(maxMonthlyTB) {
			opts.QuotaTracker.LogFairUseWarningAt(maxMonthlyTB, evalTime)
			status.ThroughputExceeded = true
		}
	}

	// Handle Grace Period Notices
	if status.InGracePeriod {
		slog.Warn("COMMERCIAL LICENSE NOTICE: License has expired but is operating within its grace period",
			"customer", status.Claims.Customer.Name,
			"expires_at", status.Claims.ExpiresAt.Format("2006-01-02"),
			"days_remaining_in_grace", status.DaysRemaining,
			"contact", "licensing@divmora.com",
		)
	} else {
		slog.Info("Commercial license verified and active",
			"tier", GetClaimsPlan(status.Claims),
			"customer", status.Claims.Customer.Name,
			"days_remaining", status.DaysRemaining,
		)
	}

	return status, nil
}

// PreflightEnforce performs a fast baseline license compliance check
// (environment, token validity, expiration, revocation, and caller account authorization)
// before downloading and decompressing S3 log objects.
func PreflightEnforce(opts EnforcementOptions) (*ValidationStatus, error) {
	opts.SourceAccountIDs = nil
	opts.SourceResourceARNs = nil
	opts.ExercisedFeatures = nil
	opts.BatchRecordCount = 0
	return Enforce(opts)
}

// AppendLicenseAttributes stamps telemetry metadata into OpenTelemetry Resource Attributes.
func AppendLicenseAttributes(attrs []model.OTelAttribute, status *ValidationStatus, env string, accountID string) []model.OTelAttribute {
	if status == nil {
		status = &ValidationStatus{
			StatusReason: "unlicensed_production",
		}
	}

	tier := "none"
	licenseID := "unlicensed"
	if status.Claims != nil {
		tier = GetClaimsPlan(status.Claims)
		licenseID = status.Claims.ID
	} else if IsNonProductionEnvironment(env) {
		tier = "non-production"
		licenseID = "bsl1.1-free"
	}

	model.AddAttr(&attrs, "divmora.license.status", status.StatusReason)
	model.AddAttr(&attrs, "divmora.license.tier", tier)
	model.AddAttr(&attrs, "divmora.license.id", licenseID)
	model.AddAttr(&attrs, "divmora.license.environment", env)
	if accountID != "" {
		model.AddAttr(&attrs, "divmora.license.account", accountID)
	}
	if status.Claims != nil {
		if mr := GetMaxResources(status.Claims); mr > 0 {
			model.AddInt64Attr(&attrs, "divmora.license.max_resources", int64(mr))
		}
	}

	return attrs
}

// BuildEMFPayload constructs the CloudWatch Embedded Metric Format (EMF) map.
// extra can optionally provide:
// - extra[0]: active monitored resources count (int)
// - extra[1]: bytes processed (int64 or int)
// - extra[2]: resource ARNs ([]string or string)
func BuildEMFPayload(status *ValidationStatus, env string, recordsProcessed int, extra ...any) map[string]any {
	statusTag := "unknown"
	if status != nil {
		statusTag = status.StatusReason
	}

	violations := 0
	if status != nil && (status.StatusReason == "unlicensed_production" ||
		status.StatusReason == "revoked" ||
		status.StatusReason == "feature_not_entitled" ||
		status.StatusReason == "resource_quota_exceeded" ||
		status.StatusReason == "resource_not_allowed" ||
		status.StatusReason == "account_mismatch" ||
		status.StatusReason == "source_account_mismatch" ||
		status.QuotaExceeded) {
		violations = 1
	}

	activeRes := 0
	var bytesProcessed int64
	var resourceARNs []string

	if len(extra) > 0 {
		switch v := extra[0].(type) {
		case int:
			if v >= 0 {
				activeRes = v
			}
		case int64:
			if v >= 0 {
				activeRes = int(v)
			}
		}
	}
	if len(extra) > 1 {
		switch v := extra[1].(type) {
		case int64:
			if v >= 0 {
				bytesProcessed = v
			}
		case int:
			if v >= 0 {
				bytesProcessed = int64(v)
			}
		}
	}
	if len(extra) > 2 {
		switch v := extra[2].(type) {
		case []string:
			resourceARNs = v
		case string:
			if v != "" {
				resourceARNs = []string{v}
			}
		}
	}

	if recordsProcessed <= 0 && bytesProcessed <= 0 && violations == 0 && activeRes == 0 {
		return nil
	}

	var licenseID string
	var tier string
	if status != nil && status.Claims != nil {
		licenseID = status.Claims.ID
		tier = GetClaimsPlan(status.Claims)
	}

	var primaryResource string
	if len(resourceARNs) > 0 {
		primaryResource = resourceARNs[0]
	}

	region := GetCurrentRegion()
	var centralRegion string
	if status != nil && status.Claims != nil {
		centralRegion = ResolveCentralMetricsRegion(status.Claims)
	} else {
		centralRegion = ResolveCentralMetricsRegion(nil)
	}

	cloudWatchMetrics := []map[string]any{
		{
			"Namespace": "Divmora/LogProcessor",
			"Dimensions": [][]string{
				{"Environment", "Status", "Region"},
				{"Environment", "Region"},
				{"Environment"},
			},
			"Metrics": []map[string]string{
				{"Name": "RecordsProcessed", "Unit": "Count"},
				{"Name": "BytesProcessed", "Unit": "Bytes"},
				{"Name": "LicenseViolations", "Unit": "Count"},
				{"Name": "ActiveMonitoredResources", "Unit": "Count"},
			},
		},
	}

	if licenseID != "" {
		licenseDims := [][]string{
			{"LicenseID", "Tier", "Region"},
			{"LicenseID", "Tier"},
		}
		if primaryResource != "" {
			licenseDims = append(licenseDims, []string{"LicenseID", "Tier", "ResourceARN"})
		}
		cloudWatchMetrics = append(cloudWatchMetrics, map[string]any{
			"Namespace":  "Divmora/License",
			"Dimensions": licenseDims,
			"Metrics": []map[string]string{
				{"Name": "BytesProcessed", "Unit": "Bytes"},
				{"Name": "RecordsProcessed", "Unit": "Count"},
			},
		})
	}

	emf := map[string]any{
		"_aws": map[string]any{
			"Timestamp":         time.Now().UnixMilli(),
			"CloudWatchMetrics": cloudWatchMetrics,
		},
		"Environment":              env,
		"Region":                   region,
		"CentralMetricsRegion":     centralRegion,
		"Status":                   statusTag,
		"RecordsProcessed":         recordsProcessed,
		"BytesProcessed":           bytesProcessed,
		"LicenseViolations":        violations,
		"ActiveMonitoredResources": activeRes,
	}

	if licenseID != "" {
		emf["LicenseID"] = licenseID
		emf["Tier"] = tier
	}
	if primaryResource != "" {
		emf["ResourceARN"] = primaryResource
	}
	if status != nil && status.ThroughputExceeded {
		emf["ThroughputExceeded"] = true
	}

	return emf
}

// FormatEMFPayload generates the JSON string for CloudWatch Embedded Metric Format (EMF).
func FormatEMFPayload(status *ValidationStatus, env string, recordsProcessed int, extra ...any) (string, error) {
	payload := BuildEMFPayload(status, env, recordsProcessed, extra...)
	if payload == nil {
		return "", nil
	}
	bytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// EmitCloudWatchEMF writes an asynchronous CloudWatch Embedded Metric Format (EMF) log
// to stdout with zero API latency.
func EmitCloudWatchEMF(status *ValidationStatus, env string, recordsProcessed int, extra ...any) {
	str, err := FormatEMFPayload(status, env, recordsProcessed, extra...)
	if err == nil && str != "" {
		// Write directly to stdout for CloudWatch ingestion
		fmt.Println(str)
	}
}

// CloudWatchMetricAPI defines the interface for publishing metric data to Amazon CloudWatch.
type CloudWatchMetricAPI interface {
	PutMetricData(ctx context.Context, params *cloudwatch.PutMetricDataInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricDataOutput, error)
}

// CloudWatchClientFactory resolves a regional CloudWatch client for cross-region metric dispatch.
type CloudWatchClientFactory func(targetRegion string) CloudWatchMetricAPI

// PublishCrossRegionMetrics sends metrics directly to the target centralized region via CloudWatch PutMetricData API.
// It is invoked when the executing Lambda region differs from the central metrics region.
func PublishCrossRegionMetrics(ctx context.Context, cw CloudWatchMetricAPI, status *ValidationStatus, env string, recordsProcessed int, extra ...any) error {
	if cw == nil {
		return nil
	}

	var activeRes int
	var bytesProcessed int64
	var resourceARNs []string

	if len(extra) > 0 {
		if v, ok := extra[0].(int); ok {
			activeRes = v
		}
	}
	if len(extra) > 1 {
		switch v := extra[1].(type) {
		case int64:
			bytesProcessed = v
		case int:
			bytesProcessed = int64(v)
		}
	}
	if len(extra) > 2 {
		switch v := extra[2].(type) {
		case []string:
			resourceARNs = v
		case string:
			if v != "" {
				resourceARNs = []string{v}
			}
		}
	}

	var violations int
	statusTag := "unlicensed_production"
	if status != nil {
		statusTag = status.StatusReason
		if !status.Valid {
			violations = 1
		}
	}

	if recordsProcessed <= 0 && bytesProcessed <= 0 && violations == 0 && activeRes == 0 {
		return nil
	}

	currentRegion := GetCurrentRegion()

	var licenseID, tier, primaryResource string
	if status != nil && status.Claims != nil {
		licenseID = status.Claims.ID
		tier = GetClaimsPlan(status.Claims)
	}
	if len(resourceARNs) > 0 {
		primaryResource = resourceARNs[0]
	}

	now := time.Now().UTC()

	// 1. Divmora/LogProcessor metrics
	dimsFull := []cwtypes.Dimension{
		{Name: aws.String("Environment"), Value: aws.String(env)},
		{Name: aws.String("Status"), Value: aws.String(statusTag)},
		{Name: aws.String("Region"), Value: aws.String(currentRegion)},
	}
	dimsEnvRegion := []cwtypes.Dimension{
		{Name: aws.String("Environment"), Value: aws.String(env)},
		{Name: aws.String("Region"), Value: aws.String(currentRegion)},
	}
	dimsEnvOnly := []cwtypes.Dimension{
		{Name: aws.String("Environment"), Value: aws.String(env)},
	}

	var logProcessorData []cwtypes.MetricDatum
	for _, dims := range [][]cwtypes.Dimension{dimsFull, dimsEnvRegion, dimsEnvOnly} {
		logProcessorData = append(logProcessorData,
			cwtypes.MetricDatum{
				MetricName: aws.String("RecordsProcessed"),
				Value:      aws.Float64(float64(recordsProcessed)),
				Unit:       cwtypes.StandardUnitCount,
				Dimensions: dims,
				Timestamp:  &now,
			},
			cwtypes.MetricDatum{
				MetricName: aws.String("BytesProcessed"),
				Value:      aws.Float64(float64(bytesProcessed)),
				Unit:       cwtypes.StandardUnitBytes,
				Dimensions: dims,
				Timestamp:  &now,
			},
		)
		if violations > 0 {
			logProcessorData = append(logProcessorData, cwtypes.MetricDatum{
				MetricName: aws.String("LicenseViolations"),
				Value:      aws.Float64(float64(violations)),
				Unit:       cwtypes.StandardUnitCount,
				Dimensions: dims,
				Timestamp:  &now,
			})
		}
		if activeRes > 0 {
			logProcessorData = append(logProcessorData, cwtypes.MetricDatum{
				MetricName: aws.String("ActiveMonitoredResources"),
				Value:      aws.Float64(float64(activeRes)),
				Unit:       cwtypes.StandardUnitCount,
				Dimensions: dims,
				Timestamp:  &now,
			})
		}
	}

	putCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := cw.PutMetricData(putCtx, &cloudwatch.PutMetricDataInput{
		Namespace:  aws.String("Divmora/LogProcessor"),
		MetricData: logProcessorData,
	})
	if err != nil {
		slog.Warn("Failed to send cross-region LogProcessor metric data", "error", err)
	}

	// 2. Divmora/License metrics (if commercial license present)
	if licenseID != "" {
		dimsLicFull := []cwtypes.Dimension{
			{Name: aws.String("LicenseID"), Value: aws.String(licenseID)},
			{Name: aws.String("Tier"), Value: aws.String(tier)},
			{Name: aws.String("Region"), Value: aws.String(currentRegion)},
		}
		dimsLicAgg := []cwtypes.Dimension{
			{Name: aws.String("LicenseID"), Value: aws.String(licenseID)},
			{Name: aws.String("Tier"), Value: aws.String(tier)},
		}

		var licenseData []cwtypes.MetricDatum
		for _, dims := range [][]cwtypes.Dimension{dimsLicFull, dimsLicAgg} {
			licenseData = append(licenseData,
				cwtypes.MetricDatum{
					MetricName: aws.String("BytesProcessed"),
					Value:      aws.Float64(float64(bytesProcessed)),
					Unit:       cwtypes.StandardUnitBytes,
					Dimensions: dims,
					Timestamp:  &now,
				},
				cwtypes.MetricDatum{
					MetricName: aws.String("RecordsProcessed"),
					Value:      aws.Float64(float64(recordsProcessed)),
					Unit:       cwtypes.StandardUnitCount,
					Dimensions: dims,
					Timestamp:  &now,
				},
			)
		}

		if primaryResource != "" {
			dimsLicRes := []cwtypes.Dimension{
				{Name: aws.String("LicenseID"), Value: aws.String(licenseID)},
				{Name: aws.String("Tier"), Value: aws.String(tier)},
				{Name: aws.String("ResourceARN"), Value: aws.String(primaryResource)},
			}
			licenseData = append(licenseData,
				cwtypes.MetricDatum{
					MetricName: aws.String("BytesProcessed"),
					Value:      aws.Float64(float64(bytesProcessed)),
					Unit:       cwtypes.StandardUnitBytes,
					Dimensions: dimsLicRes,
					Timestamp:  &now,
				},
				cwtypes.MetricDatum{
					MetricName: aws.String("RecordsProcessed"),
					Value:      aws.Float64(float64(recordsProcessed)),
					Unit:       cwtypes.StandardUnitCount,
					Dimensions: dimsLicRes,
					Timestamp:  &now,
				},
			)
		}

		_, licErr := cw.PutMetricData(putCtx, &cloudwatch.PutMetricDataInput{
			Namespace:  aws.String("Divmora/License"),
			MetricData: licenseData,
		})
		if licErr != nil {
			slog.Warn("Failed to send cross-region License metric data", "error", licErr)
		}
	}

	return nil
}

// EmitMetrics emits metrics to CloudWatch.
//  1. It always writes Embedded Metric Format (EMF) to stdout for asynchronous zero-latency ingestion in the local region.
//  2. If the executing region differs from the central metrics region resolved from license metadata (or default us-east-1),
//     it dispatches PutMetricData to the central region via the provided CloudWatchClientFactory so that metrics are aggregated
//     uniformly in a single centralized region without any reliance on environment variables.
func EmitMetrics(ctx context.Context, cwFactory CloudWatchClientFactory, status *ValidationStatus, env string, recordsProcessed int, extra ...any) {
	// 1. Always emit local EMF stdout
	EmitCloudWatchEMF(status, env, recordsProcessed, extra...)

	// 2. Cross-region check
	currentRegion := GetCurrentRegion()
	var centralRegion string
	if status != nil && status.Claims != nil {
		centralRegion = ResolveCentralMetricsRegion(status.Claims)
	} else {
		centralRegion = ResolveCentralMetricsRegion(nil)
	}

	if currentRegion != centralRegion && cwFactory != nil {
		cw := cwFactory(centralRegion)
		if cw != nil {
			_ = PublishCrossRegionMetrics(ctx, cw, status, env, recordsProcessed, extra...)
		}
	}
}

// GetBSLPolicy returns the canonical BSL 1.1 licensing policy for otel-aws-log-processor,
// including autonomous Apache 2.0 Change Date conversion and Additional Use Grants.
func GetBSLPolicy() liblicense.BSLPolicy {
	vInfo := version.Get()
	var releaseDate time.Time
	// Layer 3: Only certified, officially attested releases convert to open source upon Change Date.
	// Unattested builds maintain ReleaseDate as zero so they do not convert based on self-reported timestamps.
	if vInfo.Provenance.Verified {
		if relTime, ok := vInfo.ReleaseTime(); ok {
			releaseDate = relTime
		}
	}

	nonProdGrant := liblicense.NewNonProductionGrant("Non-Production Exemption", append(liblicense.DefaultNonProductionEnvironments, extraNonProdEnvironments...)...)

	return liblicense.BSLPolicy{
		Product:           "otel-aws-log-processor",
		ReleaseDate:       releaseDate,
		ChangePeriodYears: 3,
		AdditionalUseGrants: []liblicense.BSLAdditionalUseGrant{
			nonProdGrant,
		},
	}
}
