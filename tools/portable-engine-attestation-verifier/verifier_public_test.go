package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	publicOracleDirectory = "testdata/oracle/github-cli-v2.93.0-public-provenance"
	// The oracle bundle's artifact subject: gh_2.93.0_linux_amd64.tar.gz.
	publicOracleSubjectSHA256 = "02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0"
	publicOracleBundleSHA256  = "3335d20534e5118e8a716ceafea8dafb30b85fcd6ce7a87bff8a0ade960da105"
	publicOracleBundleSize    = 14020
)

func publicOracleStableExpectations() map[string]any {
	return map[string]any{
		"schema":               expectationsSchemaPublicV1,
		"subjectName":          "gh_2.93.0_linux_amd64.tar.gz",
		"repository":           "cli/cli",
		"repositoryId":         "212613049",
		"repositoryOwnerId":    "59704711",
		"workflowPath":         ".github/workflows/deployment.yml",
		"workflowName":         "Deployment",
		"sourceRef":            "refs/heads/trunk",
		"sourceRevision":       "f96972ce1c11fdb8eaa556257fde962a363dffde",
		"allowedTriggers":      []string{"workflow_dispatch"},
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

func TestPublicTrustedRootIsPinnedAndCarriesTransparencyAuthority(t *testing.T) {
	t.Parallel()

	raw, err := trustFiles.ReadFile(publicTrustProfile.rootPath)
	if err != nil {
		t.Fatalf("read embedded public root: %v", err)
	}
	if len(raw) != publicTrustedRootSize {
		t.Fatalf("root size: want %d, got %d", publicTrustedRootSize, len(raw))
	}
	digest := sha256.Sum256(raw)
	if got := hex.EncodeToString(digest[:]); got != publicTrustedRootSHA256 {
		t.Fatalf("root digest: want %s, got %s", publicTrustedRootSHA256, got)
	}
	trusted, err := loadPinnedTrustedRoot(publicTrustProfile)
	if err != nil {
		t.Fatalf("loadPinnedTrustedRoot: %v", err)
	}
	if len(trusted.RekorLogs()) == 0 || len(trusted.CTLogs()) == 0 {
		t.Fatal("public-good root must grant transparency-log and CT authority")
	}
	if len(trusted.FulcioCertificateAuthorities()) == 0 {
		t.Fatal("public-good root must carry Fulcio certificate authorities")
	}
}

// The complete offline cryptographic path for a real public-repository
// GitHub attestation: strict public-profile bundle shape, expectations-derived
// certificate identity, certificate chain to the pinned public-good Fulcio,
// embedded SCT against the pinned CT logs, Rekor inclusion, DSSE signature,
// and the artifact-digest subject join — everything except reading artifact
// bytes from disk, which the private oracle tests cover through the shared
// digestExactRegular path. The statement itself (21 subjects, cli/cli
// release layout) is intentionally outside the single-subject Ibex statement
// profile, so validateStatement is not exercised here; it is pinned against
// the first real Ibex public bundle instead.
func TestPublicOracleCryptographicPathVerifiesOffline(t *testing.T) {
	t.Parallel()

	raw := mustReadFile(t, filepath.Join(publicOracleDirectory, "bundle.json"))
	if len(raw) != publicOracleBundleSize {
		t.Fatalf("oracle bundle size: want %d, got %d", publicOracleBundleSize, len(raw))
	}
	digest := sha256.Sum256(raw)
	if got := hex.EncodeToString(digest[:]); got != publicOracleBundleSHA256 {
		t.Fatalf("oracle bundle digest: want %s, got %s", publicOracleBundleSHA256, got)
	}

	profile, err := parsePublicBundleProfile(raw)
	if err != nil {
		t.Fatalf("parsePublicBundleProfile: %v", err)
	}
	if !containsCTExtension(profile.cert) {
		t.Fatal("public oracle leaf must embed a signed certificate timestamp")
	}

	expectationsRaw := mustMarshalJSON(t, publicOracleStableExpectations())
	stable, err := parseStableExpectations(expectationsRaw, publicTrustProfile)
	if err != nil {
		t.Fatalf("parseStableExpectations: %v", err)
	}
	expected, claims, err := deriveSignedExpectations(stable, profile)
	if err != nil {
		t.Fatalf("deriveSignedExpectations: %v", err)
	}
	if expected.Trigger != "workflow_dispatch" || expected.RunID == "" || expected.RunAttempt == "" {
		t.Fatalf("derived run identity is incomplete: %+v", expected)
	}
	if expected.RepositoryVisibility != publicVisibility {
		t.Fatalf("derived visibility: want %q, got %q", publicVisibility, expected.RepositoryVisibility)
	}

	trustedMaterial, err := loadPinnedTrustedRoot(publicTrustProfile)
	if err != nil {
		t.Fatalf("loadPinnedTrustedRoot: %v", err)
	}
	var parsedBundle bundle.Bundle
	if err := parsedBundle.UnmarshalJSON(raw); err != nil {
		t.Fatalf("sigstore-go rejected oracle bundle: %v", err)
	}
	identity, err := certificateIdentity(expected, claims)
	if err != nil {
		t.Fatalf("certificateIdentity: %v", err)
	}
	verifier, err := verify.NewVerifier(trustedMaterial, publicTrustProfile.verifierOptions()...)
	if err != nil {
		t.Fatalf("construct transparency-log verifier: %v", err)
	}
	subjectDigest, err := hex.DecodeString(publicOracleSubjectSHA256)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.Verify(
		&parsedBundle,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha256", subjectDigest),
			verify.WithCertificateIdentity(identity),
		),
	)
	if err != nil {
		t.Fatalf("offline public-good verification failed: %v", err)
	}
	if len(verified.VerifiedTimestamps) != 1 || verified.VerifiedTimestamps[0].Type != publicTrustProfile.timestampType {
		t.Fatalf("expected exactly one Tlog-integrated timestamp, got %#v", verified.VerifiedTimestamps)
	}

	// A wrong subject digest must fail the same policy.
	wrongDigest := append([]byte(nil), subjectDigest...)
	wrongDigest[0] ^= 0xff
	if _, err := verifier.Verify(
		&parsedBundle,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha256", wrongDigest),
			verify.WithCertificateIdentity(identity),
		),
	); err == nil {
		t.Fatal("tampered subject digest unexpectedly verified")
	}
}

func TestPublicExpectationsRejectPrivateShapes(t *testing.T) {
	t.Parallel()

	base := publicOracleStableExpectations()
	base["repositoryVisibility"] = privateVisibility
	if _, err := parseStableExpectations(mustMarshalJSON(t, base), publicTrustProfile); err == nil ||
		!strings.Contains(err.Error(), "repositoryVisibility") {
		t.Fatalf("private visibility unexpectedly admitted by public profile: %v", err)
	}

	pinned := publicOracleStableExpectations()
	trustedRoot := pinned["trustedRoot"].(map[string]any)
	trustedRoot["profile"] = "github-private-signed-timestamp-v1"
	if _, err := parseStableExpectations(mustMarshalJSON(t, pinned), publicTrustProfile); err == nil ||
		!strings.Contains(err.Error(), "trustedRoot") {
		t.Fatalf("private trust-root pin unexpectedly admitted by public profile: %v", err)
	}
}

func TestProfilesRejectEachOthersBundles(t *testing.T) {
	t.Parallel()

	publicRaw := mustReadFile(t, filepath.Join(publicOracleDirectory, "bundle.json"))
	if _, err := parsePrivateBundleProfile(publicRaw); err == nil {
		t.Fatal("Rekor-bearing public bundle unexpectedly admitted by the private profile")
	}

	privateRaw := mustReadFile(t, filepath.Join(githubPrivateOracleDirectory, "bundle.json"))
	if _, err := parsePublicBundleProfile(privateRaw); err == nil {
		t.Fatal("TSA-only private bundle unexpectedly admitted by the public profile")
	}
}

func TestPublicProfileRequiresEmptyTimestampDataAndSCT(t *testing.T) {
	t.Parallel()

	raw := mustReadFile(t, filepath.Join(publicOracleDirectory, "bundle.json"))
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	material := document["verificationMaterial"].(map[string]any)

	material["timestampVerificationData"] = map[string]any{"rfc3161Timestamps": []any{}}
	mutated, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsePublicBundleProfile(mutated); err == nil ||
		!strings.Contains(err.Error(), "timestampVerificationData") {
		t.Fatalf("non-empty timestampVerificationData unexpectedly admitted: %v", err)
	}
}
