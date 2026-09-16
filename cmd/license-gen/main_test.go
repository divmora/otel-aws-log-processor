package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKeyPair(t *testing.T) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv)
}

func TestLicenseGen_KeygenPEMFiles(t *testing.T) {
	tmpDir := t.TempDir()
	pubFile := filepath.Join(tmpDir, "public.pem")
	privFile := filepath.Join(tmpDir, "private.pem")

	handleKeygen([]string{"--pub-file=" + pubFile, "--priv-file=" + privFile})

	assert.FileExists(t, pubFile)
	assert.FileExists(t, privFile)

	pubContent, err := os.ReadFile(pubFile)
	require.NoError(t, err)
	assert.Contains(t, string(pubContent), "-----BEGIN PUBLIC KEY-----")

	privContent, err := os.ReadFile(privFile)
	require.NoError(t, err)
	assert.Contains(t, string(privContent), "-----BEGIN PRIVATE KEY-----")
}

func TestLicenseGen_BSLEval(t *testing.T) {
	// 1. Staging non-production should be authorized
	assert.NotPanics(t, func() {
		handleBSLEval([]string{"--env=staging"})
	})

	// 2. JSON output for production should run without panic
	assert.NotPanics(t, func() {
		handleBSLEval([]string{"--env=production", "--json"})
	})
}

func TestLicenseGen_StatusWithoutLicense(t *testing.T) {
	assert.NotPanics(t, func() {
		handleStatus([]string{"--json"})
	})
}

func TestLicenseGen_SignAndInspectRelease(t *testing.T) {
	_, privB64 := generateTestKeyPair(t)
	tmpDir := t.TempDir()
	sigFile := filepath.Join(tmpDir, "release.sig")

	// 1. Sign release to file
	handleSignRelease([]string{
		"--version=0.2.0",
		"--commit=4b825dc",
		"--private-key=" + privB64,
		"--out-file=" + sigFile,
		"--armored",
	})
	assert.FileExists(t, sigFile)

	content, err := os.ReadFile(sigFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "-----BEGIN DIVMORA RELEASE ATTESTATION-----")

	// 2. Inspect release from file
	assert.NotPanics(t, func() {
		handleInspectRelease([]string{"--file=" + sigFile})
	})

	// 3. Inspect release JSON
	assert.NotPanics(t, func() {
		handleInspectRelease([]string{"--file=" + sigFile, "--json"})
	})
}

func TestLicenseGen_GenerateAndInspect(t *testing.T) {
	_, privB64 := generateTestKeyPair(t)
	tmpDir := t.TempDir()
	licFile := filepath.Join(tmpDir, "license.lic")

	handleGenerate([]string{
		"--customer=Acme Test Corp",
		"--tier=pro",
		"--accounts=111122223333",
		"--duration-days=30",
		"--private-key=" + privB64,
		"--out-file=" + licFile,
	})
	assert.FileExists(t, licFile)

	content, err := os.ReadFile(licFile)
	require.NoError(t, err)
	token := strings.TrimSpace(string(content))
	assert.True(t, strings.HasPrefix(token, "DIV1."))

	// Inspect claims
	assert.NotPanics(t, func() {
		handleInspect([]string{"--file=" + licFile})
	})
	assert.NotPanics(t, func() {
		handleInspect([]string{"--file=" + licFile, "--json"})
	})
}
