package license

import (
	"strings"
	"time"
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
type Customer struct {
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
	OrgID string `json:"org_id,omitempty"`
}

// Claims encapsulates the canonical cryptographic claims embedded in a signed license token.
type Claims struct {
	// ID is the unique identifier for the issued license (e.g. "lic_9b1deb4d").
	ID string `json:"id"`

	// Customer contains licensee details.
	Customer Customer `json:"customer"`

	// Tier indicates the subscription tier: "enterprise", "pro", "trial", or "community".
	Tier string `json:"tier"`

	// AllowedAWSAccounts restricts license validity to specific AWS Account IDs (e.g. ["123456789012"]).
	// If empty or containing "*", the license is valid across any AWS account.
	AllowedAWSAccounts []string `json:"allowed_aws_accounts,omitempty"`

	// Features lists the authorized feature flags enabled for this license (e.g. ["parquet", "waf", "*"]).
	Features []string `json:"features,omitempty"`

	// IssuedAt is the timestamp when the license was minted.
	IssuedAt time.Time `json:"issued_at"`

	// ExpiresAt is the timestamp after which the license enters expiration / grace period.
	ExpiresAt time.Time `json:"expires_at"`

	// GracePeriodDays specifies how many days past ExpiresAt the software continues operating
	// with warning notices before hard blocking. If 0, DefaultGracePeriodDays is used.
	GracePeriodDays int `json:"grace_period_days,omitempty"`
}

// EffectiveGracePeriodDays returns the configured grace period days or DefaultGracePeriodDays.
func (c *Claims) EffectiveGracePeriodDays() int {
	if c.GracePeriodDays <= 0 {
		return DefaultGracePeriodDays
	}
	return c.GracePeriodDays
}

// HasFeature returns true if the license grants access to the specified feature name.
// Licenses containing "all" or "*" grant all features.
func (c *Claims) HasFeature(feature string) bool {
	for _, f := range c.Features {
		if f == "*" || f == "all" || strings.EqualFold(f, feature) {
			return true
		}
	}
	return false
}

// IsAccountAllowed checks if the provided AWS Account ID satisfies the license's AllowedAWSAccounts.
// If AllowedAWSAccounts is empty or contains "*", any account is permitted.
func (c *Claims) IsAccountAllowed(accountID string) bool {
	if len(c.AllowedAWSAccounts) == 0 {
		return true
	}
	accountID = strings.TrimSpace(accountID)
	for _, allowed := range c.AllowedAWSAccounts {
		allowed = strings.TrimSpace(allowed)
		if allowed == "*" || allowed == "all" || (accountID != "" && allowed == accountID) {
			return true
		}
	}
	return false
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
