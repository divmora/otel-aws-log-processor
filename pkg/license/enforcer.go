package license

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambdacontext"
	liblicense "github.com/divmora/license-go/pkg/license"
	"github.com/divmora/otel-aws-log-processor/pkg/model"
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

// EnforcementOptions encapsulates the operational parameters required to evaluate
// compliance with the Business Source License 1.1 terms.
type EnforcementOptions struct {
	Context           context.Context
	Environment       string
	LicenseKey        string
	LicenseFile       string
	CRL               string // Optional explicit inline CRL token or PEM block
	CRLFile           string // Optional explicit path to CRL file
	CRLURL            string // Optional explicit remote CRL URL for online synchronization
	EnforcementMode   string // "warn" (default) or "strict"
	CallerAccountID   string
	SourceAccountIDs  []string
	BatchRecordCount  int
	QuotaTracker      *QuotaTracker
	BucketName        string
	ExercisedFeatures []string
	PublicKey         ed25519.PublicKey
	EvaluationTime    time.Time
	AuthoritativeTime time.Time
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

	return attrs
}

// EmitCloudWatchEMF writes an asynchronous CloudWatch Embedded Metric Format (EMF) log
// to stdout with zero API latency.
func EmitCloudWatchEMF(status *ValidationStatus, env string, recordsProcessed int) {
	statusTag := "unknown"
	if status != nil {
		statusTag = status.StatusReason
	}

	violations := 0
	if status != nil && (status.StatusReason == "unlicensed_production" || status.StatusReason == "revoked" || status.StatusReason == "feature_not_entitled" || status.QuotaExceeded) {
		violations = 1
	}

	if recordsProcessed <= 0 && violations == 0 {
		return
	}

	emf := map[string]any{
		"_aws": map[string]any{
			"Timestamp": time.Now().UnixMilli(),
			"CloudWatchMetrics": []map[string]any{
				{
					"Namespace": "Divmora/LogProcessor",
					"Dimensions": [][]string{
						{"Environment", "Status"},
					},
					"Metrics": []map[string]string{
						{"Name": "RecordsProcessed", "Unit": "Count"},
						{"Name": "LicenseViolations", "Unit": "Count"},
					},
				},
			},
		},
		"Environment":       env,
		"Status":            statusTag,
		"RecordsProcessed":  recordsProcessed,
		"LicenseViolations": violations,
	}

	bytes, err := json.Marshal(emf)
	if err == nil {
		// Write directly to stdout for CloudWatch ingestion
		fmt.Println(string(bytes))
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
