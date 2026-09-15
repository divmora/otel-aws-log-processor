package version

import (
	"testing"
	"time"
)

func TestGet(t *testing.T) {
	info := Get()
	if info.Version == "" {
		t.Error("expected non-empty version")
	}
	if info.GoVersion == "" {
		t.Error("expected non-empty go version")
	}
	if info.Platform == "" {
		t.Error("expected non-empty platform")
	}

	str := info.String()
	if str == "" {
		t.Error("expected non-empty string representation")
	}

	jsonStr, err := info.JSON()
	if err != nil {
		t.Fatalf("unexpected error formatting JSON: %v", err)
	}
	if jsonStr == "" {
		t.Error("expected non-empty JSON representation")
	}
}

func TestReleaseTimeAndChangeDate(t *testing.T) {
	// 1. Valid RFC3339 after genesis with verified provenance
	info := Info{
		BuildDate: "2026-09-15T12:00:00Z",
		Provenance: ReleaseProvenance{
			Verified: true,
			Status:   ProvenanceVerifiedOfficial,
		},
	}
	relTime, ok := info.ReleaseTime()
	if !ok {
		t.Fatal("expected valid release time")
	}
	expectedRel := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	if !relTime.Equal(expectedRel) {
		t.Errorf("got %v, want %v", relTime, expectedRel)
	}

	changeDate, ok := info.ChangeDate()
	if !ok {
		t.Fatal("expected valid change date")
	}
	expectedChange := time.Date(2029, 9, 15, 12, 0, 0, 0, time.UTC)
	if !changeDate.Equal(expectedChange) {
		t.Errorf("got %v, want %v", changeDate, expectedChange)
	}

	// Before ChangeDate -> BSL-1.1
	beforeChange := time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
	if info.IsApacheConverted(beforeChange) {
		t.Error("expected not converted before change date")
	}
	if info.License(beforeChange) != "BSL-1.1" {
		t.Errorf("got license %s, want BSL-1.1", info.License(beforeChange))
	}

	// After ChangeDate -> Apache-2.0 (with verified provenance)
	afterChange := time.Date(2029, 10, 1, 0, 0, 0, 0, time.UTC)
	if !info.IsApacheConverted(afterChange) {
		t.Error("expected converted after change date")
	}
	if info.License(afterChange) != "Apache-2.0" {
		t.Errorf("got license %s, want Apache-2.0", info.License(afterChange))
	}

	// 2. Unverified provenance after ChangeDate -> stays BSL-1.1
	unverifiedInfo := Info{
		BuildDate: "2026-09-15T12:00:00Z",
		Provenance: ReleaseProvenance{
			Verified: false,
			Status:   ProvenanceUnattestedCustom,
		},
	}
	if unverifiedInfo.IsApacheConverted(afterChange) {
		t.Error("expected unverified build not to convert to Apache 2.0")
	}
	if unverifiedInfo.License(afterChange) != "BSL-1.1" {
		t.Errorf("got license %s, want BSL-1.1", unverifiedInfo.License(afterChange))
	}

	// 3. Date prior to ProductGenesisEpoch (fraudulent build date)
	forgedInfo := Info{
		BuildDate: "2025-01-01T00:00:00Z",
		Provenance: ReleaseProvenance{
			Verified: true,
			Status:   ProvenanceVerifiedOfficial,
		},
	}
	if _, ok := forgedInfo.ReleaseTime(); ok {
		t.Error("expected false for build date prior to ProductGenesisEpoch")
	}
	if _, ok := forgedInfo.ChangeDate(); ok {
		t.Error("expected false for change date on forged build date")
	}
	if forgedInfo.IsApacheConverted(time.Now()) {
		t.Error("expected forged info not to be converted")
	}

	// 3. Unknown or malformed date
	unknownInfo := Info{BuildDate: "unknown"}
	if _, ok := unknownInfo.ReleaseTime(); ok {
		t.Error("expected false for unknown build date")
	}
}
