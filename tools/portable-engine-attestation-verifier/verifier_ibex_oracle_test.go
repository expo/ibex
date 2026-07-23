package main

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// The first real expo/ibex public attestation, produced by hermes-artifacts.yml
// run 30004214526 at commit 63181c76. See testdata/.../SOURCE.md.
const (
	ibexOracleDirectory   = "testdata/oracle/ibex-hermes-portable-macos-arm64-v63181c76"
	ibexOracleBundleSize  = 10939
	ibexOracleBundleSHA   = "daec71832c567fcca5e8e991acdb23250c6a548d2ca0fc866ace0bece89eada0"
	ibexOracleSubjectSHA  = "96617169e267c3626701ccc3f726965e79422ad9326b245310498769f89141fb"
	ibexOracleSubjectName = "hermes-portable-macos-arm64-release-ac8c6e6c80ec-p08e6330d9fab-ba45d927d725f2-bl4f6a4476f400-a4d422defe361-i6e939803e5b0-oapple-63181c76ca129c3becd85e570db454e1787c3633.tar.gz"
)

func ibexOracleStableExpectations() map[string]any {
	return map[string]any{
		"schema":               expectationsSchemaPublicV1,
		"subjectName":          ibexOracleSubjectName,
		"repository":           "expo/ibex",
		"repositoryId":         "1268046138",
		"repositoryOwnerId":    "12504344",
		"workflowPath":         ".github/workflows/hermes-artifacts.yml",
		"workflowName":         "Hermes artifact cache",
		"sourceRef":            "refs/heads/main",
		"sourceRevision":       "63181c76ca129c3becd85e570db454e1787c3633",
		"allowedTriggers":      []string{"push", "workflow_dispatch"},
		"runnerEnvironment":    githubHostedRunner,
		"repositoryVisibility": publicVisibility,
		"certificateIssuer":    githubOIDCIssuer,
		"buildType":            currentGitHubBuildType,
		"trustedRoot": map[string]any{
			"profile": "sigstore-public-good-rekor-v1",
			"sha256":  publicTrustedRootSHA256,
			"size":    publicTrustedRootSize,
		},
	}
}

// The complete offline cryptographic path against the real expo/ibex bundle:
// strict public-profile shape (empty rfc3161 array, keyid, and the .24 repo
// snapshot claim all measured here), expectations-derived certificate identity,
// certificate chain to the pinned public-good Fulcio, embedded SCT against the
// pinned CT logs, Rekor inclusion, DSSE signature, the single-subject Ibex
// statement joined to its signed subject digest, and validateStatement +
// validateCertificateClaims (the full public certificate-claim set, .24
// included). The 12 MB artifact bytes are not vendored; the subject digest the
// bundle signs is what verifyFiles would compute from them.
func TestIbexPublicOracleVerifiesTheRealArtifactOffline(t *testing.T) {
	t.Parallel()

	raw := mustReadFile(t, filepath.Join(ibexOracleDirectory, "bundle.json"))
	if len(raw) != ibexOracleBundleSize {
		t.Fatalf("oracle bundle size: want %d, got %d", ibexOracleBundleSize, len(raw))
	}
	if got := hex.EncodeToString(sha256Digest(raw)); got != ibexOracleBundleSHA {
		t.Fatalf("oracle bundle digest: want %s, got %s", ibexOracleBundleSHA, got)
	}

	profile, err := parsePublicBundleProfile(raw)
	if err != nil {
		t.Fatalf("parsePublicBundleProfile: %v", err)
	}
	if !containsCTExtension(profile.cert) {
		t.Fatal("ibex public leaf must embed a signed certificate timestamp")
	}

	stable, err := parseStableExpectations(mustMarshalJSON(t, ibexOracleStableExpectations()), publicTrustProfile)
	if err != nil {
		t.Fatalf("parseStableExpectations: %v", err)
	}
	expected, claims, err := deriveSignedExpectations(stable, profile)
	if err != nil {
		t.Fatalf("deriveSignedExpectations: %v", err)
	}
	if expected.Trigger != "push" || expected.RepositoryVisibility != publicVisibility {
		t.Fatalf("derived expectations are wrong: %+v", expected)
	}

	subjectDigest, err := hex.DecodeString(ibexOracleSubjectSHA)
	if err != nil {
		t.Fatal(err)
	}
	var artifactDigest [sha256.Size]byte
	copy(artifactDigest[:], subjectDigest)

	// Statement and certificate claims: the parts verifyFiles runs before the
	// sigstore-go cryptographic verification. The .24 repo-snapshot extension is
	// only exercised on a real public leaf.
	if err := validateStatement(profile.statement, expected, claims, artifactDigest); err != nil {
		t.Fatalf("validateStatement: %v", err)
	}
	if err := validateCertificateClaims(profile.cert, expected, claims, publicTrustProfile); err != nil {
		t.Fatalf("validateCertificateClaims: %v", err)
	}

	// Full sigstore-go cryptographic verification against the pinned public-good
	// trusted root and the bundle's own signed subject digest.
	trustedMaterial, err := loadPinnedTrustedRoot(publicTrustProfile)
	if err != nil {
		t.Fatalf("loadPinnedTrustedRoot: %v", err)
	}
	var parsedBundle bundle.Bundle
	if err := parsedBundle.UnmarshalJSON(raw); err != nil {
		t.Fatalf("sigstore-go rejected ibex bundle: %v", err)
	}
	identity, err := certificateIdentity(expected, claims)
	if err != nil {
		t.Fatalf("certificateIdentity: %v", err)
	}
	verifier, err := verify.NewVerifier(trustedMaterial, publicTrustProfile.verifierOptions()...)
	if err != nil {
		t.Fatalf("construct transparency-log verifier: %v", err)
	}
	verified, err := verifier.Verify(&parsedBundle, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", subjectDigest),
		verify.WithCertificateIdentity(identity),
	))
	if err != nil {
		t.Fatalf("offline verification of the real ibex bundle failed: %v", err)
	}
	if len(verified.VerifiedTimestamps) != 1 || verified.VerifiedTimestamps[0].Type != publicTrustProfile.timestampType {
		t.Fatalf("expected exactly one Tlog-integrated timestamp, got %#v", verified.VerifiedTimestamps)
	}

	// A wrong subject digest must fail the same policy.
	wrong := append([]byte(nil), subjectDigest...)
	wrong[0] ^= 0xff
	if _, err := verifier.Verify(&parsedBundle, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", wrong),
		verify.WithCertificateIdentity(identity),
	)); err == nil {
		t.Fatal("tampered subject digest unexpectedly verified")
	}
}

// A public-repo expectations document that names the wrong visibility or trust
// root must not admit the real bundle.
func TestIbexPublicOracleRejectsMisdeclaredExpectations(t *testing.T) {
	t.Parallel()

	wrongVisibility := ibexOracleStableExpectations()
	wrongVisibility["repositoryVisibility"] = privateVisibility
	if _, err := parseStableExpectations(mustMarshalJSON(t, wrongVisibility), publicTrustProfile); err == nil ||
		!strings.Contains(err.Error(), "repositoryVisibility") {
		t.Fatalf("private visibility admitted for the public ibex profile: %v", err)
	}
}

func sha256Digest(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}
