package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	githubPrivateOracleDirectory = "testdata/oracle/github-cli-v2.93.0-private"
	sigstorePublicOracleBundle   = "testdata/oracle/sigstore-go-v1.2.2-public/othername.bundle.json"
	githubPrivateOracleOutput    = `{"bundle":{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","sha256":"4f8c096e38a0eee242574ab100d16701928605409225e59784a3636f742bb27e","size":4885},"expectationsDigest":"9d8908dd1dc6e6e4ba050b2c3723d9b0cece523a40a14f7a2c4ebe9c51c0ab83","provenance":{"buildType":"https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1","builderId":"https://github.com/actions/runner/github-hosted","invocationId":"https://github.com/actions/attest-demo/actions/runs/8788389601/attempts/1","predicateType":"https://slsa.dev/provenance/v1","statementType":"https://in-toto.io/Statement/v1"},"schema":"ibex/github-private-artifact-attestation-verification/1","signer":{"issuer":"https://token.actions.githubusercontent.com","repository":"actions/attest-demo","repositoryId":"763287532","repositoryOwnerId":"44036562","repositoryVisibility":"private","runAttempt":"1","runId":"8788389601","runnerEnvironment":"github-hosted","san":"https://github.com/actions/attest-demo/.github/workflows/build-python.yml@refs/heads/main","sourceRef":"refs/heads/main","sourceRevision":"a6c23b9806c593664f68637c8f9d45dfcf98b2db","trigger":"workflow_dispatch","workflowName":"Build package and publish to PyPI","workflowPath":".github/workflows/build-python.yml"},"subject":{"name":"github_provenance_demo-0.0.12-py3-none-any.whl","sha256":"ae57936def59bc4c75edd3a837d89bcefc6d3a5e31d55a6fa7a71624f92c3c3b","size":1437},"timestamp":{"type":"TimestampAuthority","uri":"timestamp.githubapp.com","value":"2024-04-22T17:33:26Z"},"trustRoot":{"profile":"github-private-signed-timestamp-v1","sha256":"484cdfe1a7c65479c5ba2a22193d1be90f0020db1997de696ab207434c62fbb7","size":31645}}`
)

// This is an upstream GitHub CLI oracle, not an Ibex publisher corpus and not
// evidence that any Ibex workflow is authorized. It exercises the complete
// offline cryptographic path against a real GitHub-private TSA-only bundle.
func TestGitHubPrivateOracleOnlyVerifiesOffline(t *testing.T) {
	t.Parallel()

	artifact := materializeOracleArtifact(t)
	bundle := filepath.Join(githubPrivateOracleDirectory, "bundle.json")
	expected := filepath.Join(githubPrivateOracleDirectory, "expectations.json")

	first, err := verifyFiles(bundle, artifact, expected)
	if err != nil {
		t.Fatalf("verifyFiles: %v", err)
	}
	if string(first) != githubPrivateOracleOutput {
		t.Fatalf("canonical result changed\nwant: %s\n got: %s", githubPrivateOracleOutput, first)
	}
	if _, err := parseStrictJSON(first); err != nil {
		t.Fatalf("canonical result is not strict I-JSON: %v", err)
	}
	second, err := verifyFiles(bundle, artifact, expected)
	if err != nil {
		t.Fatalf("second verifyFiles: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("verification result is not deterministic")
	}

	var stdout bytes.Buffer
	if err := run([]string{"--bundle", bundle, "--artifact", artifact, "--expectations", expected}, &stdout, io.Discard); err != nil {
		t.Fatalf("run: %v", err)
	}
	if stdout.String() != githubPrivateOracleOutput+"\n" {
		t.Fatalf("CLI emitted non-canonical or extra output: %q", stdout.String())
	}
}

func TestStableV2ExpectationsDeriveOnlySignedRunObservations(t *testing.T) {
	t.Parallel()

	artifact := materializeOracleArtifact(t)
	bundle := filepath.Join(githubPrivateOracleDirectory, "bundle.json")
	stable := oracleStableExpectations(t)
	raw := mustMarshalJSON(t, stable)
	expected := writeTempFile(t, "stable-expectations.json", raw)

	result, err := verifyFiles(bundle, artifact, expected)
	if err != nil {
		t.Fatalf("verifyFiles with stable expectations: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(result, &decoded); err != nil {
		t.Fatalf("decode v2 result: %v", err)
	}
	if decoded["schema"] != verificationSchemaV2 {
		t.Fatalf("verification schema: %#v", decoded["schema"])
	}
	digest := sha256.Sum256(raw)
	if decoded["expectationsDigest"] != hex.EncodeToString(digest[:]) {
		t.Fatalf("v2 result does not bind the stable expectations bytes")
	}
	signer := objectMember(t, decoded, "signer")
	if signer["trigger"] != "workflow_dispatch" || signer["runId"] != "8788389601" || signer["runAttempt"] != "1" {
		t.Fatalf("signed run observations were not derived exactly: %#v", signer)
	}

	mutations := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"repository id", func(value map[string]any) { value["repositoryId"] = "763287533" }},
		{"trigger set", func(value map[string]any) { value["allowedTriggers"] = []any{"push"} }},
		{"build type", func(value map[string]any) { value["buildType"] = currentGitHubBuildType }},
		{"trusted root", func(value map[string]any) { objectMember(t, value, "trustedRoot")["sha256"] = strings.Repeat("0", 64) }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := cloneJSONObject(t, stable)
			mutation.mutate(changed)
			changedPath := writeTempFile(t, "changed-expectations.json", mustMarshalJSON(t, changed))
			if _, err := verifyFiles(bundle, artifact, changedPath); err == nil {
				t.Fatal("mutated stable authority unexpectedly verified")
			}
		})
	}
}

func TestPinnedGitHubPrivateRoot(t *testing.T) {
	t.Parallel()

	raw, err := trustFiles.ReadFile("trust/github-private/trusted_root.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != trustedRootSize {
		t.Fatalf("root size: want %d, got %d", trustedRootSize, len(raw))
	}
	digest := sha256.Sum256(raw)
	if got := hex.EncodeToString(digest[:]); got != trustedRootSHA256 {
		t.Fatalf("root digest: want %s, got %s", trustedRootSHA256, got)
	}
	trusted, err := loadPinnedTrustedRoot()
	if err != nil {
		t.Fatalf("loadPinnedTrustedRoot: %v", err)
	}
	if len(trusted.RekorLogs()) != 0 || len(trusted.CTLogs()) != 0 {
		t.Fatal("GitHub-private root unexpectedly grants transparency-log authority")
	}
}

func TestUpstreamOracleBytesRemainExact(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path   string
		size   int
		sha256 string
	}{
		{
			filepath.Join(githubPrivateOracleDirectory, "bundle.json"),
			4885,
			"4f8c096e38a0eee242574ab100d16701928605409225e59784a3636f742bb27e",
		},
		{
			sigstorePublicOracleBundle,
			6613,
			"e4d4db1b4cbd232fe2a021a7290345d24e6f07f447629cbff51c8cfc52492ed8",
		},
	}
	for _, test := range tests {
		raw := mustReadFile(t, test.path)
		if len(raw) != test.size {
			t.Fatalf("%s size: want %d, got %d", test.path, test.size, len(raw))
		}
		digest := sha256.Sum256(raw)
		if got := hex.EncodeToString(digest[:]); got != test.sha256 {
			t.Fatalf("%s digest: want %s, got %s", test.path, test.sha256, got)
		}
	}
}

func TestOfficialPublicGoodOracleIsRejected(t *testing.T) {
	t.Parallel()

	// This is the upstream sigstore-go v1.2.2 public-good test bundle. It has a
	// Rekor entry and intentionally does not fit the GitHub-private TSA profile.
	raw := mustReadFile(t, sigstorePublicOracleBundle)
	root := decodeJSONObject(t, raw)
	material := objectMember(t, root, "verificationMaterial")
	if len(arrayMember(t, material, "tlogEntries")) == 0 {
		t.Fatal("upstream public-good oracle no longer contains a Rekor entry")
	}
	if _, err := parsePrivateBundleProfile(raw); err == nil {
		t.Fatal("public-good bundle unexpectedly matched the private profile")
	}
}

func TestOfficialPublicCertificateSCTIsRejectedInPrivateEnvelope(t *testing.T) {
	t.Parallel()

	publicRoot := decodeJSONObject(t, mustReadFile(t, sigstorePublicOracleBundle))
	publicCertificate := objectMember(t, objectMember(t, publicRoot, "verificationMaterial"), "certificate")
	privateRoot := oracleBundleObject(t)
	privateMaterial := objectMember(t, privateRoot, "verificationMaterial")
	privateMaterial["certificate"] = publicCertificate
	if _, err := parsePrivateBundleProfile(mustMarshalJSON(t, privateRoot)); err == nil || !strings.Contains(err.Error(), "SCT") {
		t.Fatalf("official public SCT certificate was not rejected explicitly: %v", err)
	}
}

func TestBundleProfileIsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*testing.T, map[string]any)
	}{
		{
			name: "even empty transparency log field",
			mutate: func(t *testing.T, root map[string]any) {
				objectMember(t, root, "verificationMaterial")["tlogEntries"] = []any{}
			},
		},
		{
			name: "unknown top-level field",
			mutate: func(_ *testing.T, root map[string]any) {
				root["extra"] = "not admitted"
			},
		},
		{
			name: "no timestamp",
			mutate: func(t *testing.T, root map[string]any) {
				material := objectMember(t, root, "verificationMaterial")
				timestampData := objectMember(t, material, "timestampVerificationData")
				timestampData["rfc3161Timestamps"] = []any{}
			},
		},
		{
			name: "two timestamps",
			mutate: func(t *testing.T, root map[string]any) {
				material := objectMember(t, root, "verificationMaterial")
				timestampData := objectMember(t, material, "timestampVerificationData")
				timestamps := arrayMember(t, timestampData, "rfc3161Timestamps")
				timestampData["rfc3161Timestamps"] = append(timestamps, timestamps[0])
			},
		},
		{
			name: "two signatures",
			mutate: func(t *testing.T, root map[string]any) {
				envelope := objectMember(t, root, "dsseEnvelope")
				signatures := arrayMember(t, envelope, "signatures")
				envelope["signatures"] = append(signatures, signatures[0])
			},
		},
		{
			name: "certificate chain instead of leaf",
			mutate: func(t *testing.T, root map[string]any) {
				material := objectMember(t, root, "verificationMaterial")
				certificate := material["certificate"]
				delete(material, "certificate")
				material["x509CertificateChain"] = map[string]any{"certificates": []any{certificate}}
			},
		},
		{
			name: "noncanonical base64",
			mutate: func(t *testing.T, root map[string]any) {
				envelope := objectMember(t, root, "dsseEnvelope")
				signature := objectIndex(t, arrayMember(t, envelope, "signatures"), 0)
				signature["sig"] = strings.TrimRight(signature["sig"].(string), "=")
			},
		},
		{
			name: "oversized signature",
			mutate: func(t *testing.T, root map[string]any) {
				envelope := objectMember(t, root, "dsseEnvelope")
				signature := objectIndex(t, arrayMember(t, envelope, "signatures"), 0)
				signature["sig"] = base64.StdEncoding.EncodeToString(make([]byte, maximumSignatureBytes+1))
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := oracleBundleObject(t)
			test.mutate(t, root)
			raw := mustMarshalJSON(t, root)
			if _, err := parsePrivateBundleProfile(raw); err == nil {
				t.Fatal("mutated bundle unexpectedly matched the private profile")
			}
		})
	}
}

func TestCryptographicTamperingIsRejected(t *testing.T) {
	t.Parallel()

	bundlePath := filepath.Join(githubPrivateOracleDirectory, "bundle.json")
	expectationsPath := filepath.Join(githubPrivateOracleDirectory, "expectations.json")

	t.Run("artifact", func(t *testing.T) {
		artifact := mustReadFile(t, materializeOracleArtifact(t))
		artifact[len(artifact)-1] ^= 1
		artifactPath := writeTempFile(t, "artifact.whl", artifact)
		if _, err := verifyFiles(bundlePath, artifactPath, expectationsPath); err == nil {
			t.Fatal("tampered artifact unexpectedly verified")
		}
	})

	for _, target := range []string{"signature", "timestamp"} {
		target := target
		t.Run(target, func(t *testing.T) {
			root := oracleBundleObject(t)
			if target == "signature" {
				envelope := objectMember(t, root, "dsseEnvelope")
				signature := objectIndex(t, arrayMember(t, envelope, "signatures"), 0)
				signature["sig"] = mutateCanonicalBase64(t, signature["sig"].(string))
			} else {
				material := objectMember(t, root, "verificationMaterial")
				timestampData := objectMember(t, material, "timestampVerificationData")
				timestamp := objectIndex(t, arrayMember(t, timestampData, "rfc3161Timestamps"), 0)
				timestamp["signedTimestamp"] = mutateCanonicalBase64(t, timestamp["signedTimestamp"].(string))
			}
			mutatedBundle := writeTempFile(t, "bundle.json", mustMarshalJSON(t, root))
			if _, err := verifyFiles(mutatedBundle, materializeOracleArtifact(t), expectationsPath); err == nil {
				t.Fatalf("tampered %s unexpectedly verified", target)
			}
		})
	}
}

func TestEveryExternalExpectationIsEnforced(t *testing.T) {
	t.Parallel()

	bundle := filepath.Join(githubPrivateOracleDirectory, "bundle.json")
	artifact := materializeOracleArtifact(t)
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"subject name", func(e map[string]any) { e["subjectName"] = "other.whl" }},
		{"repository", func(e map[string]any) {
			e["repository"] = "actions/other"
			e["certificateSAN"] = "https://github.com/actions/other/.github/workflows/build-python.yml@refs/heads/main"
		}},
		{"repository id", func(e map[string]any) { e["repositoryId"] = "763287533" }},
		{"repository owner id", func(e map[string]any) { e["repositoryOwnerId"] = "44036563" }},
		{"workflow path", func(e map[string]any) {
			e["workflowPath"] = ".github/workflows/other.yml"
			e["certificateSAN"] = "https://github.com/actions/attest-demo/.github/workflows/other.yml@refs/heads/main"
		}},
		{"workflow name", func(e map[string]any) { e["workflowName"] = "Other workflow" }},
		{"source ref", func(e map[string]any) {
			e["sourceRef"] = "refs/heads/release"
			e["certificateSAN"] = "https://github.com/actions/attest-demo/.github/workflows/build-python.yml@refs/heads/release"
		}},
		{"source revision", func(e map[string]any) { e["sourceRevision"] = strings.Repeat("0", 40) }},
		{"trigger", func(e map[string]any) { e["trigger"] = "push" }},
		{"runner environment", func(e map[string]any) { e["runnerEnvironment"] = "self-hosted" }},
		{"repository visibility", func(e map[string]any) { e["repositoryVisibility"] = "public" }},
		{"run id", func(e map[string]any) { e["runId"] = "8788389602" }},
		{"run attempt", func(e map[string]any) { e["runAttempt"] = "2" }},
		{"certificate SAN", func(e map[string]any) { e["certificateSAN"] = "https://github.com/actions/other" }},
		{"certificate issuer", func(e map[string]any) { e["certificateIssuer"] = "https://example.invalid" }},
		{"build type", func(e map[string]any) {
			e["buildType"] = currentGitHubBuildType
			e["builderId"] = e["certificateSAN"]
		}},
		{"builder id", func(e map[string]any) { e["builderId"] = "https://github.com/actions/other" }},
		{"schema", func(e map[string]any) { e["schema"] = "ibex/unknown/1" }},
		{"missing field", func(e map[string]any) { delete(e, "runAttempt") }},
		{"unknown field", func(e map[string]any) { e["extra"] = "no" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			expected := oracleExpectationsObject(t)
			test.mutate(expected)
			expectationsPath := writeTempFile(t, "expectations.json", mustMarshalJSON(t, expected))
			if _, err := verifyFiles(bundle, artifact, expectationsPath); err == nil {
				t.Fatal("mutated external expectation unexpectedly verified")
			}
		})
	}
}

func TestCurrentAttestBuildProvenanceV2StatementShapeOracleOnly(t *testing.T) {
	t.Parallel()

	// The workflow pins actions/attest-build-provenance v2.4.0 at commit
	// e8998f949152b193b063cb0ec769d69d929409be. That official source
	// snapshot uses this build type, runner_environment, and builder shape.
	// This synthetic statement-shape test is not a signed Ibex corpus.
	profile, err := parsePrivateBundleProfile(mustReadFile(t, filepath.Join(githubPrivateOracleDirectory, "bundle.json")))
	if err != nil {
		t.Fatal(err)
	}
	expected, claims, err := parseExpectations(mustReadFile(t, filepath.Join(githubPrivateOracleDirectory, "expectations.json")))
	if err != nil {
		t.Fatal(err)
	}
	statement := cloneJSONObject(t, profile.statement)
	predicate := objectMember(t, statement, "predicate")
	definition := objectMember(t, predicate, "buildDefinition")
	definition["buildType"] = currentGitHubBuildType
	github := objectMember(t, objectMember(t, definition, "internalParameters"), "github")
	github["runner_environment"] = githubHostedRunner
	builder := objectMember(t, objectMember(t, predicate, "runDetails"), "builder")
	builder["id"] = claims.workflowURI
	expected.BuildType = currentGitHubBuildType
	expected.BuilderID = claims.workflowURI

	artifact := mustReadFile(t, materializeOracleArtifact(t))
	digest := sha256.Sum256(artifact)
	if err := validateStatement(statement, expected, claims, digest); err != nil {
		t.Fatalf("current action v2 statement shape rejected: %v", err)
	}

	delete(github, "runner_environment")
	if err := validateStatement(statement, expected, claims, digest); err == nil {
		t.Fatal("current action shape without runner_environment unexpectedly accepted")
	}
	github["runner_environment"] = githubHostedRunner
	expected.BuildType = legacyGitHubBuildType
	expected.BuilderID = legacyGitHubBuilderID
	definition["buildType"] = legacyGitHubBuildType
	builder["id"] = legacyGitHubBuilderID
	if err := validateStatement(statement, expected, claims, digest); err == nil {
		t.Fatal("legacy shape with current-only runner_environment unexpectedly accepted")
	}
}

func TestCertificateProfileIsClosed(t *testing.T) {
	t.Parallel()

	profile, err := parsePrivateBundleProfile(mustReadFile(t, filepath.Join(githubPrivateOracleDirectory, "bundle.json")))
	if err != nil {
		t.Fatal(err)
	}
	expected, claims, err := parseExpectations(mustReadFile(t, filepath.Join(githubPrivateOracleDirectory, "expectations.json")))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCertificateClaims(profile.cert, expected, claims); err != nil {
		t.Fatalf("oracle certificate rejected: %v", err)
	}

	t.Run("SCT extension", func(t *testing.T) {
		leaf := *profile.cert
		leaf.Extensions = append([]pkix.Extension(nil), profile.cert.Extensions...)
		leaf.Extensions = append(leaf.Extensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, Value: []byte{0x05, 0x00}})
		if !containsCTExtension(&leaf) {
			t.Fatal("SCT extension was not detected")
		}
	})

	t.Run("hidden second GeneralName", func(t *testing.T) {
		leaf := *profile.cert
		leaf.Extensions = append([]pkix.Extension(nil), profile.cert.Extensions...)
		first, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(expected.CertificateSAN)})
		if err != nil {
			t.Fatal(err)
		}
		second, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("hidden.example")})
		if err != nil {
			t.Fatal(err)
		}
		sequence, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: append(first, second...)})
		if err != nil {
			t.Fatal(err)
		}
		for index := range leaf.Extensions {
			if leaf.Extensions[index].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
				leaf.Extensions[index].Value = sequence
			}
		}
		if _, err := exactCertificateURISAN(&leaf); err == nil {
			t.Fatal("second GeneralName unexpectedly accepted")
		}
	})

	t.Run("duplicate subjectAltName extension", func(t *testing.T) {
		leaf := *profile.cert
		leaf.Extensions = append([]pkix.Extension(nil), profile.cert.Extensions...)
		for _, extension := range profile.cert.Extensions {
			if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
				leaf.Extensions = append(leaf.Extensions, extension)
				break
			}
		}
		if _, err := exactCertificateURISAN(&leaf); err == nil {
			t.Fatal("duplicate subjectAltName extension unexpectedly accepted")
		}
	})

	t.Run("duplicate Sigstore extension", func(t *testing.T) {
		leaf := *profile.cert
		leaf.Extensions = append([]pkix.Extension(nil), profile.cert.Extensions...)
		for _, extension := range profile.cert.Extensions {
			if strings.HasPrefix(extension.Id.String(), "1.3.6.1.4.1.57264.1.") {
				leaf.Extensions = append(leaf.Extensions, extension)
				break
			}
		}
		if _, err := exactSigstoreExtensions(&leaf); err == nil {
			t.Fatal("duplicate Sigstore extension unexpectedly accepted")
		}
	})

	t.Run("unknown Sigstore extension", func(t *testing.T) {
		leaf := *profile.cert
		leaf.Extensions = append([]pkix.Extension(nil), profile.cert.Extensions...)
		value, err := asn1.Marshal("unexpected")
		if err != nil {
			t.Fatal(err)
		}
		leaf.Extensions = append(leaf.Extensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 23}, Value: value})
		if err := validateCertificateClaims(&leaf, expected, claims); err == nil {
			t.Fatal("unknown Sigstore extension unexpectedly accepted")
		}
	})
}

func TestRegularFileAndInputCaps(t *testing.T) {
	t.Parallel()

	empty := writeTempFile(t, "empty", nil)
	if _, _, err := readExactRegular(empty, maximumBundleBytes); err == nil {
		t.Fatal("empty structured input unexpectedly accepted")
	}
	if _, _, err := digestExactRegular(empty); err == nil {
		t.Fatal("empty artifact unexpectedly accepted")
	}

	oversize := writeTempFile(t, "oversize", []byte{0})
	if err := os.Truncate(oversize, maximumExpectationsBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readExactRegular(oversize, maximumExpectationsBytes); err == nil {
		t.Fatal("oversized structured input unexpectedly accepted")
	}

	oversizedArtifact := writeTempFile(t, "oversized-artifact", []byte{0})
	if err := os.Truncate(oversizedArtifact, maximumArtifactBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := digestExactRegular(oversizedArtifact); err == nil {
		t.Fatal("artifact larger than the transport policy unexpectedly accepted")
	}

	target := writeTempFile(t, "target", []byte("data"))
	symlink := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, symlink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, _, err := readExactRegular(symlink, maximumBundleBytes); err == nil {
		t.Fatal("symlink unexpectedly accepted")
	}
}

func TestExpectationSyntaxIsCanonicalAndClosed(t *testing.T) {
	t.Parallel()

	tests := []func(map[string]any){
		func(e map[string]any) { e["subjectName"] = "." },
		func(e map[string]any) { e["subjectName"] = "../artifact" },
		func(e map[string]any) { e["repository"] = "owner/.." },
		func(e map[string]any) { e["workflowPath"] = ".github/workflows/../other.yml" },
		func(e map[string]any) { e["sourceRef"] = "refs/heads/main@evil" },
		func(e map[string]any) { e["sourceRef"] = "refs/heads/main#fragment" },
		func(e map[string]any) { e["sourceRevision"] = strings.Repeat("A", 40) },
		func(e map[string]any) { e["runId"] = "01" },
		func(e map[string]any) { e["runAttempt"] = "0" },
		func(e map[string]any) { e["runAttempt"] = float64(1) },
		func(e map[string]any) { e["trigger"] = "pull request" },
	}
	for index, mutate := range tests {
		expected := oracleExpectationsObject(t)
		mutate(expected)
		if _, _, err := parseExpectations(mustMarshalJSON(t, expected)); err == nil {
			t.Fatalf("invalid expectation case %d unexpectedly parsed", index)
		}
	}
}

func TestCLIRejectsIncompleteOrExtraArguments(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	if err := run(nil, &stdout, io.Discard); err == nil {
		t.Fatal("missing arguments unexpectedly accepted")
	}
	if stdout.Len() != 0 {
		t.Fatalf("failed command wrote stdout: %q", stdout.String())
	}
	if err := run([]string{"--bundle", "b", "--artifact", "a", "--expectations", "e", "extra"}, &stdout, io.Discard); err == nil {
		t.Fatal("positional argument unexpectedly accepted")
	}
	if stdout.Len() != 0 {
		t.Fatalf("failed command wrote stdout: %q", stdout.String())
	}
}

func materializeOracleArtifact(t *testing.T) string {
	t.Helper()
	encoded := mustReadFile(t, filepath.Join(githubPrivateOracleDirectory, "artifact.whl.base64"))
	decoded, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		t.Fatalf("decode oracle artifact: %v", err)
	}
	digest := sha256.Sum256(decoded)
	if got := hex.EncodeToString(digest[:]); got != "ae57936def59bc4c75edd3a837d89bcefc6d3a5e31d55a6fa7a71624f92c3c3b" {
		t.Fatalf("oracle artifact digest: %s", got)
	}
	return writeTempFile(t, "github_provenance_demo-0.0.12-py3-none-any.whl", decoded)
}

func oracleBundleObject(t *testing.T) map[string]any {
	t.Helper()
	return decodeJSONObject(t, mustReadFile(t, filepath.Join(githubPrivateOracleDirectory, "bundle.json")))
}

func oracleExpectationsObject(t *testing.T) map[string]any {
	t.Helper()
	return decodeJSONObject(t, mustReadFile(t, filepath.Join(githubPrivateOracleDirectory, "expectations.json")))
}

func oracleStableExpectations(t *testing.T) map[string]any {
	t.Helper()
	full := oracleExpectationsObject(t)
	return map[string]any{
		"schema":               expectationsSchemaV2,
		"subjectName":          full["subjectName"],
		"repository":           full["repository"],
		"repositoryId":         full["repositoryId"],
		"repositoryOwnerId":    full["repositoryOwnerId"],
		"workflowPath":         full["workflowPath"],
		"workflowName":         full["workflowName"],
		"sourceRef":            full["sourceRef"],
		"sourceRevision":       full["sourceRevision"],
		"allowedTriggers":      []any{"push", "workflow_dispatch"},
		"runnerEnvironment":    full["runnerEnvironment"],
		"repositoryVisibility": full["repositoryVisibility"],
		"certificateIssuer":    full["certificateIssuer"],
		"buildType":            full["buildType"],
		"trustedRoot": map[string]any{
			"profile": "github-private-signed-timestamp-v1",
			"sha256":  trustedRootSHA256,
			"size":    trustedRootSize,
		},
	}
}

func decodeJSONObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatalf("decode test JSON: %v", err)
	}
	return object
}

func cloneJSONObject(t *testing.T, object map[string]any) map[string]any {
	t.Helper()
	return decodeJSONObject(t, mustMarshalJSON(t, object))
}

func objectMember(t *testing.T, object map[string]any, field string) map[string]any {
	t.Helper()
	result, ok := object[field].(map[string]any)
	if !ok {
		t.Fatalf("test fixture %q is not an object", field)
	}
	return result
}

func arrayMember(t *testing.T, object map[string]any, field string) []any {
	t.Helper()
	result, ok := object[field].([]any)
	if !ok {
		t.Fatalf("test fixture %q is not an array", field)
	}
	return result
}

func objectIndex(t *testing.T, array []any, index int) map[string]any {
	t.Helper()
	if index >= len(array) {
		t.Fatalf("test fixture index %d is absent", index)
	}
	result, ok := array[index].(map[string]any)
	if !ok {
		t.Fatalf("test fixture index %d is not an object", index)
	}
	return result
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

func mustMarshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal test JSON: %v", err)
	}
	return raw
}

func writeTempFile(t *testing.T, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func mutateCanonicalBase64(t *testing.T, encoded string) string {
	t.Helper()
	if encoded == "" {
		t.Fatal("cannot mutate empty base64")
	}
	replacement := byte('A')
	if encoded[0] == replacement {
		replacement = 'B'
	}
	mutated := string(replacement) + encoded[1:]
	if _, err := base64.StdEncoding.DecodeString(mutated); err != nil {
		t.Fatalf("base64 mutation was not structurally valid: %v", err)
	}
	return mutated
}
