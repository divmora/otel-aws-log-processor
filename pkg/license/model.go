package license

import (
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

// Customer encapsulates customer identification metadata within a signed license token.
type Customer = liblicense.Customer

// Claims encapsulates the canonical cryptographic claims embedded in a signed license token.
type Claims = liblicense.Claims

// Scope defines operational boundaries restricting where and on what infrastructure the license is authorized.
type Scope = liblicense.Scope

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

	// StatusReason is a machine-readable status tag (e.g. "valid", "grace_period", "unlicensed_production", "non_prod_free", "quota_exceeded").
	StatusReason string `json:"status_reason"`

	// Message contains human-readable diagnostic details.
	Message string `json:"message"`

	// Claims contains the verified license claims (nil if unlicensed).
	Claims *Claims `json:"claims,omitempty"`
}
