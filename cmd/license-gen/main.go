package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	liblicense "github.com/divmora/license-go/pkg/license"
	"github.com/divmora/otel-aws-log-processor/pkg/license"
	"github.com/divmora/otel-aws-log-processor/pkg/version"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	switch subcommand {
	case "keygen":
		handleKeygen(os.Args[2:])
	case "generate":
		handleGenerate(os.Args[2:])
	case "status":
		handleStatus(os.Args[2:])
	case "bsl-eval":
		handleBSLEval(os.Args[2:])
	case "inspect":
		handleInspect(os.Args[2:])
	case "sign-release":
		handleSignRelease(os.Args[2:])
	case "verify-release":
		handleVerifyRelease(os.Args[2:])
	case "inspect-release":
		handleInspectRelease(os.Args[2:])
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`DIVMORA License Generator & Verifier CLI (license-gen)

Usage:
  license-gen <command> [flags]

Commands:
  keygen          Generate a new Ed25519 cryptographic key pair (base64 and/or PEM files)
  generate        Mint and sign a new commercial license token
  status          Display standardized terminal license status card and quota table
  bsl-eval        Evaluate BSL 1.1 dual-licensing entitlement and Additional Use Grants
  inspect         Decode and inspect license claims without verification
  sign-release    Cryptographically sign official release metadata for binary provenance
  verify-release  Cryptographically verify an official release attestation token
  inspect-release Decode and inspect release attestation claims without verification

Examples:
  # Generate a keypair and save as PEM files
  license-gen keygen --pub-file=public.pem --priv-file=private.pem

  # Generate a 1-year enterprise license for AWS account 123456789012
  license-gen generate \
    --customer="Acme Corp" \
    --org-id="org_123" \
    --tier="enterprise" \
    --accounts="123456789012" \
    --duration-days=365 \
    --private-key="<base64-private-key>"

  # Display license status card
  license-gen status --token="<token>"

  # Evaluate BSL 1.1 entitlement for staging environment
  license-gen bsl-eval --env="staging"

  # Sign an official release
  license-gen sign-release \
    --version="0.2.0" \
    --commit="abcdef123456" \
    --build-date="2026-09-12T12:00:00Z" \
    --private-key="<base64-private-key>" \
    --out-file="release.sig"

  # Inspect an attestation token offline
  license-gen inspect-release --file="release.sig"`)
}

func handleKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	pubFile := fs.String("pub-file", "", "Optional path to write public key in PEM format")
	privFile := fs.String("priv-file", "", "Optional path to write private key in PEM format")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate keypair: %v\n", err)
		os.Exit(1)
	}

	pubB64 := base64.StdEncoding.EncodeToString(pubKey)
	privB64 := base64.StdEncoding.EncodeToString(privKey)

	if *privFile != "" {
		if err := liblicense.SavePrivateKeyToPEMFile(privKey, *privFile, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save private key to %s: %v\n", *privFile, err)
			os.Exit(1)
		}
	}
	if *pubFile != "" {
		if err := liblicense.SavePublicKeyToPEMFile(pubKey, *pubFile, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save public key to %s: %v\n", *pubFile, err)
			os.Exit(1)
		}
	}

	fmt.Println("Generated Ed25519 Key Pair:")
	fmt.Printf("  Public Verification Key (embed in code or DIVMORA_PUBLIC_KEY):\n    %s\n\n", pubB64)
	fmt.Printf("  Private Signing Key (keep secret!):\n    %s\n", privB64)
	if *pubFile != "" {
		fmt.Printf("  Saved Public Key PEM : %s\n", *pubFile)
	}
	if *privFile != "" {
		fmt.Printf("  Saved Private Key PEM: %s\n", *privFile)
	}
}

func handleGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)

	customerName := fs.String("customer", "", "Customer name (required)")
	customerEmail := fs.String("email", "", "Customer email")
	orgID := fs.String("org-id", "", "Customer organization ID")
	product := fs.String("product", "otel-aws-log-processor", "Product identifier")
	tier := fs.String("tier", license.TierEnterprise, "Subscription tier (enterprise, pro, trial, community)")
	accounts := fs.String("accounts", "*", "Comma-separated list of allowed AWS Account IDs (or '*' for any)")
	features := fs.String("features", "*", "Comma-separated list of enabled features (or '*' for all)")
	durationDays := fs.Int("duration-days", 365, "License validity duration in days")
	gracePeriodDays := fs.Int("grace-period-days", 14, "Grace period in days after expiration")
	privKeyB64 := fs.String("private-key", "", "Base64-encoded Ed25519 private signing key (or set DIVMORA_PRIVATE_KEY)")
	armoredFlag := fs.Bool("armored", false, "Generate human-readable armored text block format")
	outFileFlag := fs.String("out-file", "", "Write license token to file")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *customerName == "" {
		fmt.Fprintln(os.Stderr, "Error: --customer is required")
		fs.Usage()
		os.Exit(1)
	}

	keyStr := strings.TrimSpace(*privKeyB64)
	if keyStr == "" {
		keyStr = strings.TrimSpace(os.Getenv("DIVMORA_PRIVATE_KEY"))
	}
	if keyStr == "" {
		fmt.Fprintln(os.Stderr, "Error: --private-key or DIVMORA_PRIVATE_KEY is required")
		os.Exit(1)
	}

	privKeyBytes, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		privKeyBytes, err = base64.RawURLEncoding.DecodeString(keyStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding private key: %v\n", err)
			os.Exit(1)
		}
	}

	if len(privKeyBytes) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "Invalid Ed25519 private key size: expected %d, got %d\n", ed25519.PrivateKeySize, len(privKeyBytes))
		os.Exit(1)
	}

	now := time.Now().UTC()
	expiresAt := now.AddDate(0, 0, *durationDays)

	// Parse accounts
	var accList []string
	for _, a := range strings.Split(*accounts, ",") {
		if a = strings.TrimSpace(a); a != "" {
			accList = append(accList, a)
		}
	}

	// Parse features
	var featList []string
	for _, f := range strings.Split(*features, ",") {
		if f = strings.TrimSpace(f); f != "" {
			featList = append(featList, f)
		}
	}

	licID := fmt.Sprintf("lic_%x", now.UnixNano())
	claims := &license.Claims{
		ID: licID,
		Customer: license.Customer{
			Name:  *customerName,
			Email: *customerEmail,
			OrgID: *orgID,
		},
		Product: *product,
		Plan:    *tier,
		Scope: &license.Scope{
			Accounts: accList,
		},
		Features:        featList,
		IssuedAt:        now,
		ExpiresAt:       expiresAt,
		GracePeriodDays: *gracePeriodDays,
	}

	var token string
	if *armoredFlag {
		token, err = license.SignLicenseArmored(claims, ed25519.PrivateKey(privKeyBytes))
	} else {
		token, err = license.SignLicense(claims, ed25519.PrivateKey(privKeyBytes))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to sign license: %v\n", err)
		os.Exit(1)
	}

	if *outFileFlag != "" {
		if err := os.WriteFile(*outFileFlag, []byte(token+"\n"), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing license to %s: %v\n", *outFileFlag, err)
			os.Exit(1)
		}
	}

	fmt.Println("Commercial License Generated Successfully!")
	fmt.Printf("  License ID:   %s\n", claims.ID)
	fmt.Printf("  Customer:     %s\n", claims.Customer.Name)
	fmt.Printf("  Product:      %s\n", claims.Product)
	fmt.Printf("  Tier / Plan:  %s\n", claims.Plan)
	if claims.Scope != nil && len(claims.Scope.Accounts) > 0 {
		fmt.Printf("  AWS Accounts: %s\n", strings.Join(claims.Scope.Accounts, ", "))
	}
	fmt.Printf("  Expires:      %s (%d days)\n", claims.ExpiresAt.Format("2006-01-02"), *durationDays)
	if *outFileFlag != "" {
		fmt.Printf("  Saved To:     %s\n", *outFileFlag)
	}
	fmt.Println("\nLicense Token (set as DIVMORA_LICENSE_KEY):")
	fmt.Println(token)
}

func handleInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	tokenFlag := fs.String("token", "", "License token string")
	fileFlag := fs.String("file", "", "Path to license token file")
	jsonFlag := fs.Bool("json", false, "Output claims in JSON format")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	token, err := license.ResolveToken(*tokenFlag, *fileFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving token: %v\n", err)
		os.Exit(1)
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "Error: please provide --token or --file")
		os.Exit(1)
	}

	claims, err := liblicense.Inspect(token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to inspect license claims: %v\n", err)
		os.Exit(1)
	}

	if *jsonFlag {
		claimsJSON, _ := json.MarshalIndent(claims, "", "  ")
		fmt.Println(string(claimsJSON))
		return
	}

	fmt.Print(claims.FormatStatus())
}

func handleStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	tokenFlag := fs.String("token", "", "License token string")
	fileFlag := fs.String("file", "", "Path to license token file")
	compactFlag := fs.Bool("compact", false, "Compact terminal card format")
	jsonFlag := fs.Bool("json", false, "Output status in JSON format")
	timeFlag := fs.String("time", "", "Reference evaluation timestamp (RFC3339 or YYYY-MM-DD)")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	evalTime := time.Now().UTC()
	if *timeFlag != "" {
		t, err := time.Parse(time.RFC3339, *timeFlag)
		if err != nil {
			t, err = time.Parse("2006-01-02", *timeFlag)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --time format: %v\n", err)
			os.Exit(1)
		}
		evalTime = t.UTC()
	}

	token, err := license.ResolveToken(*tokenFlag, *fileFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving license: %v\n", err)
		os.Exit(1)
	}

	vInfo := version.Get()
	if token == "" {
		bslPolicy := license.GetBSLPolicy()
		changeDate := bslPolicy.ChangeDate()
		isConverted := bslPolicy.IsConverted(evalTime)

		if *jsonFlag {
			out := map[string]any{
				"status":             "active",
				"tier":               "community",
				"license":            bslPolicy.EffectiveLicense(evalTime),
				"apache_converted":   isConverted,
				"change_date":        changeDate.Format("2006-01-02"),
				"days_to_conversion": bslPolicy.DaysUntilConversion(evalTime),
				"message":            "Running under BSL 1.1 Non-Production Free Exemption",
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(out)
			return
		}

		fmt.Println("================================================================================")
		fmt.Println("OTel AWS Log Processor License Status")
		fmt.Println("================================================================================")
		fmt.Printf("Active License   : %s\n", bslPolicy.EffectiveLicense(evalTime))
		fmt.Printf("Software Version : %s\n", vInfo.Version)
		if relTime, ok := vInfo.ReleaseTime(); ok {
			fmt.Printf("Release Date     : %s\n", relTime.Format("2006-01-02"))
		}
		fmt.Printf("Change Date      : %s (Converts to Apache License 2.0)\n", changeDate.Format("2006-01-02"))
		fmt.Printf("Days to Convert  : %d days\n", bslPolicy.DaysUntilConversion(evalTime))
		fmt.Println("Non-Production   : Free & unrestricted (dev, staging, QA, CI/CD)")
		fmt.Println("Production       : Commercial subscription required for production workloads")
		fmt.Println("================================================================================")
		fmt.Println("\nTo configure a commercial license:")
		fmt.Println("  export DIVMORA_LICENSE_KEY=\"<token>\"")
		fmt.Println("  or visit https://divmora.com / contact licensing@divmora.com")
		return
	}

	status, err := license.ParseAndVerifyAt(token, nil, evalTime)
	if err != nil {
		if *jsonFlag {
			out := map[string]any{
				"valid":   false,
				"status":  "invalid",
				"error":   err.Error(),
				"message": "Cryptographic license verification failed",
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(out)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "License Verification Failed: %v\n", err)
		os.Exit(1)
	}

	if *jsonFlag {
		out := map[string]any{
			"valid":           status.Valid,
			"status":          status.StatusReason,
			"in_grace_period": status.InGracePeriod,
			"days_remaining":  status.DaysRemaining,
			"message":         status.Message,
			"claims":          status.Claims,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}

	formatOpts := []liblicense.StatusFormatterOption{
		liblicense.WithStatusBannerTitle("OTEL AWS LOG PROCESSOR COMMERCIAL LICENSE"),
		liblicense.WithStatusCompact(*compactFlag),
		liblicense.WithStatusTime(evalTime),
	}
	fmt.Print(status.Claims.FormatStatus(formatOpts...))
}

func handleBSLEval(args []string) {
	fs := flag.NewFlagSet("bsl-eval", flag.ExitOnError)
	envFlag := fs.String("env", "production", "Environment name to evaluate (e.g. production, staging, dev)")
	bucketFlag := fs.String("bucket", "", "Optional S3 bucket name")
	timeFlag := fs.String("time", "", "Reference evaluation timestamp (RFC3339 or YYYY-MM-DD)")
	jsonFlag := fs.Bool("json", false, "Output in JSON format")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	evalTime := time.Now().UTC()
	if *timeFlag != "" {
		t, err := time.Parse(time.RFC3339, *timeFlag)
		if err != nil {
			t, err = time.Parse("2006-01-02", *timeFlag)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --time format: %v\n", err)
			os.Exit(1)
		}
		evalTime = t.UTC()
	}

	policy := license.GetBSLPolicy()
	usageReq := liblicense.BSLUsageRequest{
		Environment: *envFlag,
		Time:        evalTime,
		Metadata: map[string]string{
			"bucket": *bucketFlag,
		},
	}

	result := policy.EvaluateEntitlement(usageReq)

	if *jsonFlag {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
		return
	}

	fmt.Println("================================================================================")
	fmt.Println("DIVMORA BSL 1.1 Entitlement Evaluation")
	fmt.Println("================================================================================")
	fmt.Printf("Product          : %s\n", policy.Product)
	fmt.Printf("Environment      : %s\n", *envFlag)
	fmt.Printf("Evaluation Time  : %s\n", evalTime.Format(time.RFC3339))
	fmt.Printf("Effective License: %s\n", result.EffectiveLicense)
	fmt.Printf("Authorized       : %t\n", result.Authorized)
	if result.MatchingGrant != "" {
		fmt.Printf("Matching Grant   : %s\n", result.MatchingGrant)
	}
	fmt.Printf("Decision         : %s\n", result.GrantType)
	fmt.Printf("Change Date      : %s\n", result.ChangeDate.Format("2006-01-02"))
	fmt.Printf("Days to Convert  : %d days\n", result.DaysUntilConversion)
	fmt.Printf("Reason           : %s\n", result.Reason)
	fmt.Println("================================================================================")
}

func handleInspectRelease(args []string) {
	fs := flag.NewFlagSet("inspect-release", flag.ExitOnError)
	tokenFlag := fs.String("token", "", "Release token string or armored PEM")
	fileFlag := fs.String("file", "", "Path to release token file")
	fileFlagShort := fs.String("f", "", "Alias for --file")
	jsonFlag := fs.Bool("json", false, "Output claims in JSON format")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	filePath := *fileFlag
	if filePath == "" {
		filePath = *fileFlagShort
	}

	token := strings.TrimSpace(*tokenFlag)
	var claims *liblicense.ReleaseClaims
	var err error

	if token == "" && filePath != "" {
		claims, err = liblicense.InspectReleaseFromFile(filePath)
	} else if token != "" {
		claims, err = liblicense.InspectRelease(token)
	} else {
		fmt.Fprintln(os.Stderr, "Error: please provide --token or --file")
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to inspect release claims: %v\n", err)
		os.Exit(1)
	}

	if *jsonFlag {
		claimsJSON, _ := json.MarshalIndent(claims, "", "  ")
		fmt.Println(string(claimsJSON))
		return
	}

	fmt.Print(claims.FormatInspect())
}

func resolvePrivateKey(inlineKey, keyFile string) ([]byte, error) {
	keyStr := strings.TrimSpace(inlineKey)
	if keyStr == "" && keyFile != "" {
		content, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file: %w", err)
		}
		keyStr = strings.TrimSpace(string(content))
	}
	if keyStr == "" {
		keyStr = strings.TrimSpace(os.Getenv("DIVMORA_RELEASE_PRIVATE_KEY"))
		if keyStr == "" {
			keyStr = strings.TrimSpace(os.Getenv("DIVMORA_PRIVATE_KEY"))
		}
	}
	if keyStr == "" {
		return nil, fmt.Errorf("private key is required (use --private-key, --private-key-file, or DIVMORA_PRIVATE_KEY)")
	}

	privKeyBytes, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		privKeyBytes, err = base64.RawURLEncoding.DecodeString(keyStr)
		if err != nil {
			return nil, fmt.Errorf("error decoding base64 private key: %w", err)
		}
	}

	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size: expected %d bytes, got %d", ed25519.PrivateKeySize, len(privKeyBytes))
	}

	return privKeyBytes, nil
}

func handleSignRelease(args []string) {
	fs := flag.NewFlagSet("sign-release", flag.ExitOnError)

	productFlag := fs.String("product", "otel-aws-log-processor", "Product identifier (e.g. otel-aws-log-processor)")
	ver := fs.String("version", "", "Release version string (e.g. 0.2.0, required)")
	commit := fs.String("commit", "", "Git commit SHA (required)")
	buildDate := fs.String("build-date", "", "RFC3339 build timestamp (default: current UTC time)")
	releaseDateFlag := fs.String("release-date", "", "Optional RFC3339 release timestamp (defaults to build date)")
	binaryFlag := fs.String("binary", "", "Optional path to binary executable to compute and embed SHA-256 digest")
	digestFlag := fs.String("digest", "", "Optional explicit binary digest (e.g. sha256:...)")
	armoredFlag := fs.Bool("armored", false, "Output as armored PEM block rather than compact token")
	authority := fs.String("authority", "DIVMORA Technologies Release Authority", "Release signing authority")
	authorityID := fs.String("authority-id", "", "Optional authority identifier")
	privKeyFlag := fs.String("private-key", "", "Base64-encoded Ed25519 private signing key")
	privKeyFile := fs.String("private-key-file", "", "Path to file containing private key")
	outFile := fs.String("out-file", "", "Path to write release signature token to (e.g. release.sig)")
	outFileShort := fs.String("o", "", "Alias for --out-file")
	tokenOnly := fs.Bool("token-only", false, "Print only the signed token string without decorations")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	targetOutFile := *outFile
	if targetOutFile == "" {
		targetOutFile = *outFileShort
	}

	if *ver == "" {
		fmt.Fprintln(os.Stderr, "Error: --version is required")
		os.Exit(1)
	}
	if *commit == "" {
		fmt.Fprintln(os.Stderr, "Error: --commit is required")
		os.Exit(1)
	}

	date := strings.TrimSpace(*buildDate)
	if date == "" {
		date = time.Now().UTC().Format(time.RFC3339)
	} else {
		if _, err := time.Parse(time.RFC3339, date); err != nil {
			if _, err := time.Parse("2006-01-02", date); err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid build-date format (expected RFC3339 e.g. 2026-09-12T12:00:00Z): %v\n", err)
				os.Exit(1)
			}
		}
	}

	relDate := strings.TrimSpace(*releaseDateFlag)
	if relDate == "" {
		relDate = date
	} else {
		if _, err := time.Parse(time.RFC3339, relDate); err != nil {
			if _, err := time.Parse("2006-01-02", relDate); err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid release-date format (expected RFC3339 e.g. 2026-09-12T12:00:00Z): %v\n", err)
				os.Exit(1)
			}
		}
	}

	binaryDigest := strings.TrimSpace(*digestFlag)
	if binaryDigest == "" && *binaryFlag != "" {
		d, err := liblicense.ComputeFileDigest(*binaryFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to compute binary digest from %s: %v\n", *binaryFlag, err)
			os.Exit(1)
		}
		binaryDigest = d
	}

	privKeyBytes, err := resolvePrivateKey(*privKeyFlag, *privKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	claims := &version.ReleaseClaims{
		Product:      *productFlag,
		Version:      *ver,
		GitCommit:    *commit,
		BuildDate:    date,
		ReleaseDate:  relDate,
		BinaryDigest: binaryDigest,
		Authority:    *authority,
		AuthorityID:  *authorityID,
	}

	var token string
	if *armoredFlag {
		token, err = version.SignReleaseArmored(claims, ed25519.PrivateKey(privKeyBytes))
	} else {
		token, err = version.SignRelease(claims, ed25519.PrivateKey(privKeyBytes))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing release: %v\n", err)
		os.Exit(1)
	}

	if targetOutFile != "" {
		if err := os.WriteFile(targetOutFile, []byte(token+"\n"), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing release signature to %s: %v\n", targetOutFile, err)
			os.Exit(1)
		}
	}

	if *tokenOnly {
		fmt.Println(token)
		return
	}

	parsedDate, _ := time.Parse(time.RFC3339, date)
	changeDate := parsedDate.AddDate(version.BSLChangePeriodYears, 0, 0)

	fmt.Println("================================================================================")
	fmt.Println("DIVMORA Technologies: Cryptographic Release Attestation")
	fmt.Println("================================================================================")
	fmt.Printf("Product         : %s\n", *productFlag)
	fmt.Printf("Version         : %s\n", *ver)
	fmt.Printf("Git Commit      : %s\n", *commit)
	fmt.Printf("Build Date      : %s\n", date)
	if relDate != date {
		fmt.Printf("Release Date    : %s\n", relDate)
	}
	if binaryDigest != "" {
		fmt.Printf("Binary Digest   : %s\n", binaryDigest)
	}
	fmt.Printf("Authority       : %s\n", *authority)
	if *authorityID != "" {
		fmt.Printf("Authority ID    : %s\n", *authorityID)
	}
	fmt.Printf("Apache 2.0 Date : %s (Converts under BSL 1.1 Change Date terms)\n", changeDate.Format("2006-01-02"))
	if targetOutFile != "" {
		fmt.Printf("Saved Signature : %s\n", targetOutFile)
	}
	fmt.Println("\nRelease Signature Token (pass via ldflags or release.sig):")
	fmt.Println(token)
}

func handleVerifyRelease(args []string) {
	fs := flag.NewFlagSet("verify-release", flag.ExitOnError)
	tokenFlag := fs.String("token", "", "Release token string or armored PEM")
	fileFlag := fs.String("file", "", "Path to release token file")
	fileFlagShort := fs.String("f", "", "Alias for --file")
	pubKeyFlag := fs.String("public-key", "", "Base64-encoded Ed25519 public key")
	pubKeyFile := fs.String("public-key-file", "", "Path to file containing public key")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	filePath := *fileFlag
	if filePath == "" {
		filePath = *fileFlagShort
	}

	token := strings.TrimSpace(*tokenFlag)
	if token == "" && filePath != "" {
		content, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading release token file %s: %v\n", filePath, err)
			os.Exit(1)
		}
		token = strings.TrimSpace(string(content))
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "Error: please provide --token or --file")
		os.Exit(1)
	}

	var pubKey ed25519.PublicKey
	pubKeyStr := strings.TrimSpace(*pubKeyFlag)
	if pubKeyStr == "" && *pubKeyFile != "" {
		content, err := os.ReadFile(*pubKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading public key file %s: %v\n", *pubKeyFile, err)
			os.Exit(1)
		}
		pubKeyStr = strings.TrimSpace(string(content))
	}
	if pubKeyStr != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(pubKeyStr)
		if err != nil {
			keyBytes, err = base64.RawURLEncoding.DecodeString(pubKeyStr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decoding base64 public key: %v\n", err)
				os.Exit(1)
			}
		}
		if len(keyBytes) != ed25519.PublicKeySize {
			fmt.Fprintf(os.Stderr, "Error: invalid public key size (%d bytes, expected %d)\n", len(keyBytes), ed25519.PublicKeySize)
			os.Exit(1)
		}
		pubKey = ed25519.PublicKey(keyBytes)
	}

	claims, err := version.ParseAndVerifyReleaseToken(token, pubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Release verification failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Official DIVMORA Release Attestation Verified!")
	fmt.Printf("  Product:          %s\n", claims.Product)
	fmt.Printf("  Version:          %s\n", claims.Version)
	fmt.Printf("  Git Commit:       %s\n", claims.GitCommit)
	fmt.Printf("  Build Date:       %s\n", claims.BuildDate)
	if claims.ReleaseDate != "" && claims.ReleaseDate != claims.BuildDate {
		fmt.Printf("  Release Date:     %s\n", claims.ReleaseDate)
	}
	if claims.BinaryDigest != "" {
		fmt.Printf("  Binary Digest:    %s\n", claims.BinaryDigest)
	}
	fmt.Printf("  Authority:        %s\n", claims.Authority)
	if claims.AuthorityID != "" {
		fmt.Printf("  Authority ID:     %s\n", claims.AuthorityID)
	}
}
