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
		handleKeygen()
	case "generate":
		handleGenerate(os.Args[2:])
	case "inspect":
		handleInspect(os.Args[2:])
	case "sign-release":
		handleSignRelease(os.Args[2:])
	case "verify-release":
		handleVerifyRelease(os.Args[2:])
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`DIVMORA License Generator CLI (license-gen)

Usage:
  license-gen <command> [flags]

Commands:
  keygen          Generate a new Ed25519 cryptographic key pair
  generate        Mint and sign a new commercial license token
  inspect         Decode and inspect a signed license token
  sign-release    Cryptographically sign official release metadata for binary provenance
  verify-release  Cryptographically verify an official release attestation token

Examples:
  # Generate a keypair
  license-gen keygen

  # Generate a 1-year enterprise license for AWS account 123456789012
  license-gen generate \
    --customer="Acme Corp" \
    --org-id="org_123" \
    --tier="enterprise" \
    --accounts="123456789012" \
    --duration-days=365 \
    --private-key="<base64-private-key>"

  # Inspect a token
  license-gen inspect --token="<token>"

  # Sign an official release
  license-gen sign-release \
    --version="0.2.0" \
    --commit="abcdef123456" \
    --build-date="2026-09-12T12:00:00Z" \
    --private-key="<base64-private-key>" \
    --out-file="release.sig"`)
}

func handleKeygen() {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate keypair: %v\n", err)
		os.Exit(1)
	}

	pubB64 := base64.StdEncoding.EncodeToString(pubKey)
	privB64 := base64.StdEncoding.EncodeToString(privKey)

	fmt.Println("Generated Ed25519 Key Pair:")
	fmt.Printf("  Public Verification Key (embed in code or DIVMORA_PUBLIC_KEY):\n    %s\n\n", pubB64)
	fmt.Printf("  Private Signing Key (keep secret!):\n    %s\n", privB64)
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

	status, err := license.ParseAndVerify(token, nil)
	if err != nil {
		fmt.Printf("Validation Warning: %v\n", err)
	}

	if status != nil && status.Claims != nil {
		claimsJSON, _ := json.MarshalIndent(status.Claims, "", "  ")
		fmt.Printf("Status:        %s\n", status.StatusReason)
		fmt.Printf("Valid:         %t\n", status.Valid)
		fmt.Printf("Grace Period:  %t\n", status.InGracePeriod)
		fmt.Printf("Days Remaining:%d\n", status.DaysRemaining)
		fmt.Printf("Message:       %s\n\n", status.Message)
		fmt.Println("Decoded Claims:")
		fmt.Println(string(claimsJSON))
	}
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
