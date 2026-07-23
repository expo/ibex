package main

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	maximumBundleBytes       = 16 * 1024 * 1024
	maximumArtifactBytes     = 1024 * 1024 * 1024
	maximumExpectationsBytes = 64 * 1024
	maximumCertificateBytes  = 64 * 1024
	maximumTimestampBytes    = 1024 * 1024
	maximumStatementBytes    = 8 * 1024 * 1024
	maximumSignatureBytes    = 16 * 1024
	bundleMediaType          = "application/vnd.dev.sigstore.bundle.v0.3+json"
	trustedRootMediaType     = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
	expectationsSchemaV1     = "ibex/github-private-artifact-attestation-expectations/1"
	expectationsSchemaV2     = "ibex/github-private-artifact-attestation-expectations/2"
	verificationSchemaV1     = "ibex/github-private-artifact-attestation-verification/1"
	verificationSchemaV2     = "ibex/github-private-artifact-attestation-verification/2"
	statementType            = "https://in-toto.io/Statement/v1"
	predicateType            = "https://slsa.dev/provenance/v1"
	payloadType              = "application/vnd.in-toto+json"
	githubOIDCIssuer         = "https://token.actions.githubusercontent.com"
	githubHostedRunner       = "github-hosted"
	privateVisibility        = "private"
	legacyGitHubBuildType    = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"
	currentGitHubBuildType   = "https://actions.github.io/buildtypes/workflow/v1"
	legacyGitHubBuilderID    = "https://github.com/actions/runner/github-hosted"
	trustedRootSHA256        = "484cdfe1a7c65479c5ba2a22193d1be90f0020db1997de696ab207434c62fbb7"
	trustedRootSize          = 31645
)

// @ref LLP 0035#threat-model-and-trust-roots — trust is pinned independently
// of the artifact channel and verification remains offline.
// The root is the independently reviewed raw TUF target, not a root fetched
// beside the bundle. Its exact target digest and size are rechecked before use.
// Rotation is therefore a reviewed source update, never an online fallback.
//
//go:embed trust/github-private/trusted_root.json trust/sigstore-public-good/trusted_root.json
var trustFiles embed.FS

type expectations struct {
	Schema               string
	SubjectName          string
	Repository           string
	RepositoryID         string
	RepositoryOwnerID    string
	WorkflowPath         string
	WorkflowName         string
	SourceRef            string
	SourceRevision       string
	Trigger              string
	RunnerEnvironment    string
	RepositoryVisibility string
	RunID                string
	RunAttempt           string
	CertificateSAN       string
	CertificateIssuer    string
	BuildType            string
	BuilderID            string
}

// v2 carries only stable admission policy. Run identity and the selected
// allowed trigger are derived from the signed certificate, then required to
// join the signed SLSA statement. This prevents an artifact channel from
// supplying its own repository/workflow authority while avoiding a circular
// requirement for callers to know signed run-specific observations first.
type stableExpectations struct {
	Schema               string
	SubjectName          string
	Repository           string
	RepositoryID         string
	RepositoryOwnerID    string
	WorkflowPath         string
	WorkflowName         string
	SourceRef            string
	SourceRevision       string
	AllowedTriggers      []string
	RunnerEnvironment    string
	RepositoryVisibility string
	CertificateIssuer    string
	BuildType            string
}

type derivedClaims struct {
	repositoryURL string
	ownerURL      string
	workflowURI   string
	invocationURI string
	dependencyURI string
}

type rawBundleProfile struct {
	statement map[string]any
	cert      *x509.Certificate
}

type canonicalResult struct {
	Schema             string                     `json:"schema"`
	TrustRoot          canonicalTrustRoot         `json:"trustRoot"`
	ExpectationsDigest string                     `json:"expectationsDigest"`
	Bundle             canonicalBundle            `json:"bundle"`
	Subject            canonicalSubject           `json:"subject"`
	Signer             canonicalSigner            `json:"signer"`
	Provenance         canonicalProvenance        `json:"provenance"`
	Timestamp          canonicalVerifiedTimestamp `json:"timestamp"`
}

type canonicalTrustRoot struct {
	Profile string `json:"profile"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

type canonicalBundle struct {
	MediaType string `json:"mediaType"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
}

type canonicalSubject struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type canonicalSigner struct {
	Issuer               string `json:"issuer"`
	SAN                  string `json:"san"`
	Repository           string `json:"repository"`
	RepositoryID         string `json:"repositoryId"`
	RepositoryOwnerID    string `json:"repositoryOwnerId"`
	WorkflowPath         string `json:"workflowPath"`
	WorkflowName         string `json:"workflowName"`
	SourceRef            string `json:"sourceRef"`
	SourceRevision       string `json:"sourceRevision"`
	Trigger              string `json:"trigger"`
	RunnerEnvironment    string `json:"runnerEnvironment"`
	RepositoryVisibility string `json:"repositoryVisibility"`
	RunID                string `json:"runId"`
	RunAttempt           string `json:"runAttempt"`
}

type canonicalProvenance struct {
	StatementType string `json:"statementType"`
	PredicateType string `json:"predicateType"`
	BuildType     string `json:"buildType"`
	BuilderID     string `json:"builderId"`
	InvocationID  string `json:"invocationId"`
}

type canonicalVerifiedTimestamp struct {
	Type  string `json:"type"`
	URI   string `json:"uri"`
	Value string `json:"value"`
}

func verifyFiles(bundlePath, artifactPath, expectationsPath string) ([]byte, error) {
	expectationsRaw, expectationsSize, err := readExactRegular(expectationsPath, maximumExpectationsBytes)
	if err != nil {
		return nil, fmt.Errorf("read expectations: %w", err)
	}

	bundleRaw, bundleSize, err := readExactRegular(bundlePath, maximumBundleBytes)
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	// The trust profile is selected by the expectations schema alone. A
	// schema peek that fails leaves the private default in place; the full
	// expectations parse below still reports that failure after the bundle
	// parse, preserving the original error precedence.
	tp := privateTrustProfile
	if peeked, peekErr := parseExpectationSchema(expectationsRaw); peekErr == nil && peeked == expectationsSchemaPublicV1 {
		tp = publicTrustProfile
	}
	profile, err := tp.parseBundle(bundleRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s bundle profile: %w", tp.label, err)
	}

	expectationSchema, err := parseExpectationSchema(expectationsRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid expectations: %w", err)
	}
	var expected expectations
	var claims derivedClaims
	resultSchema := verificationSchemaV1
	switch expectationSchema {
	case expectationsSchemaV1:
		expected, claims, err = parseExpectations(expectationsRaw)
	case expectationsSchemaV2:
		var stable stableExpectations
		stable, err = parseStableExpectations(expectationsRaw, privateTrustProfile)
		if err == nil {
			expected, claims, err = deriveSignedExpectations(stable, profile)
		}
		resultSchema = verificationSchemaV2
	case expectationsSchemaPublicV1:
		var stable stableExpectations
		stable, err = parseStableExpectations(expectationsRaw, publicTrustProfile)
		if err == nil {
			expected, claims, err = deriveSignedExpectations(stable, profile)
		}
		resultSchema = verificationSchemaPublicV1
	default:
		err = fmt.Errorf("schema: unsupported expectations schema %q", expectationSchema)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid expectations: %w", err)
	}

	artifactDigest, artifactSize, err := digestExactRegular(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	if err := validateStatement(profile.statement, expected, claims, artifactDigest); err != nil {
		return nil, fmt.Errorf("invalid signed provenance statement: %w", err)
	}
	if err := validateCertificateClaims(profile.cert, expected, claims, tp); err != nil {
		return nil, fmt.Errorf("invalid signing certificate claims: %w", err)
	}

	trustedMaterial, err := loadPinnedTrustedRoot(tp)
	if err != nil {
		return nil, err
	}
	var parsedBundle bundle.Bundle
	if err := parsedBundle.UnmarshalJSON(bundleRaw); err != nil {
		return nil, fmt.Errorf("sigstore-go rejected bundle: %w", err)
	}
	identity, err := certificateIdentity(expected, claims)
	if err != nil {
		return nil, fmt.Errorf("construct certificate policy: %w", err)
	}
	verifier, err := verify.NewVerifier(trustedMaterial, tp.verifierOptions()...)
	if err != nil {
		return nil, fmt.Errorf("construct %s verifier: %w", tp.verifierLabel, err)
	}
	verified, err := verifier.Verify(
		&parsedBundle,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha256", artifactDigest[:]),
			verify.WithCertificateIdentity(identity),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("offline Sigstore verification failed: %w", err)
	}
	if verified.Statement == nil || verified.Signature == nil || verified.Signature.Certificate == nil {
		return nil, fmt.Errorf("sigstore-go returned an incomplete certificate-signed verification result")
	}
	if len(verified.VerifiedTimestamps) != 1 || verified.VerifiedTimestamps[0].Type != tp.timestampType {
		return nil, fmt.Errorf("expected exactly one verified %s timestamp, got %#v", tp.timestampLabel, verified.VerifiedTimestamps)
	}
	timestamp := verified.VerifiedTimestamps[0]

	if artifactSize > maxIJSONInteger || bundleSize > maxIJSONInteger || expectationsSize > maxIJSONInteger {
		return nil, fmt.Errorf("a result size is outside the I-JSON safe integer range")
	}
	bundleDigest := sha256.Sum256(bundleRaw)
	expectationsDigest := sha256.Sum256(expectationsRaw)
	result := canonicalResult{
		Schema: resultSchema,
		TrustRoot: canonicalTrustRoot{
			Profile: tp.rootProfile,
			SHA256:  tp.rootSHA256,
			Size:    int64(tp.rootSize),
		},
		ExpectationsDigest: hex.EncodeToString(expectationsDigest[:]),
		Bundle: canonicalBundle{
			MediaType: bundleMediaType,
			SHA256:    hex.EncodeToString(bundleDigest[:]),
			Size:      bundleSize,
		},
		Subject: canonicalSubject{
			Name:   expected.SubjectName,
			SHA256: hex.EncodeToString(artifactDigest[:]),
			Size:   artifactSize,
		},
		Signer: canonicalSigner{
			Issuer:               expected.CertificateIssuer,
			SAN:                  expected.CertificateSAN,
			Repository:           expected.Repository,
			RepositoryID:         expected.RepositoryID,
			RepositoryOwnerID:    expected.RepositoryOwnerID,
			WorkflowPath:         expected.WorkflowPath,
			WorkflowName:         expected.WorkflowName,
			SourceRef:            expected.SourceRef,
			SourceRevision:       expected.SourceRevision,
			Trigger:              expected.Trigger,
			RunnerEnvironment:    expected.RunnerEnvironment,
			RepositoryVisibility: expected.RepositoryVisibility,
			RunID:                expected.RunID,
			RunAttempt:           expected.RunAttempt,
		},
		Provenance: canonicalProvenance{
			StatementType: statementType,
			PredicateType: predicateType,
			BuildType:     expected.BuildType,
			BuilderID:     expected.BuilderID,
			InvocationID:  claims.invocationURI,
		},
		Timestamp: canonicalVerifiedTimestamp{
			Type:  timestamp.Type,
			URI:   timestamp.URI,
			Value: timestamp.Timestamp.UTC().Format(time.RFC3339Nano),
		},
	}
	plain, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("encode verification result: %w", err)
	}
	canonical, err := jsoncanonicalizer.Transform(plain)
	if err != nil {
		return nil, fmt.Errorf("canonicalize verification result: %w", err)
	}
	return canonical, nil
}

func parseExpectationSchema(raw []byte) (string, error) {
	value, err := parseStrictJSON(raw)
	if err != nil {
		return "", err
	}
	object, err := objectAt(value, "$")
	if err != nil {
		return "", err
	}
	return stringAt(object["schema"], "$.schema")
}

func parseStableExpectations(raw []byte, tp trustProfile) (stableExpectations, error) {
	value, err := parseStrictJSON(raw)
	if err != nil {
		return stableExpectations{}, err
	}
	object, err := objectAt(value, "$")
	if err != nil {
		return stableExpectations{}, err
	}
	fields := []string{
		"schema", "subjectName", "repository", "repositoryId", "repositoryOwnerId",
		"workflowPath", "workflowName", "sourceRef", "sourceRevision", "allowedTriggers",
		"runnerEnvironment", "repositoryVisibility", "certificateIssuer", "buildType", "trustedRoot",
	}
	if err := exactFields(object, "$", fields...); err != nil {
		return stableExpectations{}, err
	}
	get := func(field string) (string, error) { return stringAt(object[field], "$."+field) }
	s := stableExpectations{}
	stringFields := []struct {
		name string
		dest *string
	}{
		{"schema", &s.Schema},
		{"subjectName", &s.SubjectName},
		{"repository", &s.Repository},
		{"repositoryId", &s.RepositoryID},
		{"repositoryOwnerId", &s.RepositoryOwnerID},
		{"workflowPath", &s.WorkflowPath},
		{"workflowName", &s.WorkflowName},
		{"sourceRef", &s.SourceRef},
		{"sourceRevision", &s.SourceRevision},
		{"runnerEnvironment", &s.RunnerEnvironment},
		{"repositoryVisibility", &s.RepositoryVisibility},
		{"certificateIssuer", &s.CertificateIssuer},
		{"buildType", &s.BuildType},
	}
	for _, field := range stringFields {
		*field.dest, err = get(field.name)
		if err != nil {
			return stableExpectations{}, err
		}
	}
	if s.Schema != tp.stableExpectationsSchema {
		return stableExpectations{}, fmt.Errorf("schema: expected %q, got %q", tp.stableExpectationsSchema, s.Schema)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}$`).MatchString(s.Repository) {
		return stableExpectations{}, fmt.Errorf("repository must be one exact owner/name pair")
	}
	if repositoryName := strings.SplitN(s.Repository, "/", 2)[1]; repositoryName == "." || repositoryName == ".." {
		return stableExpectations{}, fmt.Errorf("repository name must not be a path pseudo-component")
	}
	if s.SubjectName == "" || len(s.SubjectName) > 255 || s.SubjectName == "." || s.SubjectName == ".." || path.Base(s.SubjectName) != s.SubjectName || strings.Contains(s.SubjectName, "\\") || hasControlCharacter(s.SubjectName) {
		return stableExpectations{}, fmt.Errorf("subjectName must be one non-empty basename")
	}
	if s.WorkflowPath == "" || len(s.WorkflowPath) > 1024 || !strings.HasPrefix(s.WorkflowPath, ".github/workflows/") || path.Clean(s.WorkflowPath) != s.WorkflowPath || !regexp.MustCompile(`^[A-Za-z0-9_./-]+\.ya?ml$`).MatchString(s.WorkflowPath) {
		return stableExpectations{}, fmt.Errorf("workflowPath must be a normalized .github/workflows/ path")
	}
	if s.WorkflowName == "" || len(s.WorkflowName) > 256 || hasControlCharacter(s.WorkflowName) {
		return stableExpectations{}, fmt.Errorf("workflowName must not be empty")
	}
	if err := requireCanonicalGitRef(s.SourceRef); err != nil {
		return stableExpectations{}, err
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(s.SourceRevision) {
		return stableExpectations{}, fmt.Errorf("sourceRevision must be exactly 40 lowercase hexadecimal digits")
	}
	if err := requireCanonicalPositiveDecimal("repositoryId", s.RepositoryID); err != nil {
		return stableExpectations{}, err
	}
	if err := requireCanonicalPositiveDecimal("repositoryOwnerId", s.RepositoryOwnerID); err != nil {
		return stableExpectations{}, err
	}
	triggerValues, err := arrayAt(object["allowedTriggers"], "$.allowedTriggers")
	if err != nil {
		return stableExpectations{}, err
	}
	if len(triggerValues) == 0 || len(triggerValues) > 16 {
		return stableExpectations{}, fmt.Errorf("allowedTriggers must contain 1..16 exact events")
	}
	for index, value := range triggerValues {
		trigger, err := stringAt(value, fmt.Sprintf("$.allowedTriggers[%d]", index))
		if err != nil {
			return stableExpectations{}, err
		}
		if !regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`).MatchString(trigger) {
			return stableExpectations{}, fmt.Errorf("allowedTriggers contains a non-canonical GitHub event")
		}
		if index > 0 && s.AllowedTriggers[index-1] >= trigger {
			return stableExpectations{}, fmt.Errorf("allowedTriggers must be UTF-8 sorted and unique")
		}
		s.AllowedTriggers = append(s.AllowedTriggers, trigger)
	}
	if s.RunnerEnvironment != githubHostedRunner {
		return stableExpectations{}, fmt.Errorf("runnerEnvironment must be %q", githubHostedRunner)
	}
	if s.RepositoryVisibility != tp.visibility {
		return stableExpectations{}, fmt.Errorf("repositoryVisibility must be %q for this %s profile", tp.visibility, tp.kind)
	}
	if s.CertificateIssuer != githubOIDCIssuer {
		return stableExpectations{}, fmt.Errorf("certificateIssuer must be %q", githubOIDCIssuer)
	}
	if s.BuildType != legacyGitHubBuildType && s.BuildType != currentGitHubBuildType {
		return stableExpectations{}, fmt.Errorf("buildType is not one of the two closed GitHub workflow/v1 layouts")
	}
	trustedRoot, err := objectAt(object["trustedRoot"], "$.trustedRoot")
	if err != nil {
		return stableExpectations{}, err
	}
	if err := exactFields(trustedRoot, "$.trustedRoot", "profile", "sha256", "size"); err != nil {
		return stableExpectations{}, err
	}
	if err := exactString(trustedRoot, "profile", tp.rootProfile, "$.trustedRoot"); err != nil {
		return stableExpectations{}, err
	}
	if err := exactString(trustedRoot, "sha256", tp.rootSHA256, "$.trustedRoot"); err != nil {
		return stableExpectations{}, err
	}
	rootSize, ok := trustedRoot["size"].(strictJSONNumber)
	if !ok || string(rootSize) != strconv.Itoa(tp.rootSize) {
		return stableExpectations{}, fmt.Errorf("$.trustedRoot.size must equal the embedded root size %d", tp.rootSize)
	}
	return s, nil
}

func deriveSignedExpectations(stable stableExpectations, profile rawBundleProfile) (expectations, derivedClaims, error) {
	values, err := exactSigstoreExtensions(profile.cert)
	if err != nil {
		return expectations{}, derivedClaims{}, err
	}
	trigger := values["2"]
	allowed := false
	for _, candidate := range stable.AllowedTriggers {
		if candidate == trigger {
			allowed = true
			break
		}
	}
	if !allowed {
		return expectations{}, derivedClaims{}, fmt.Errorf("signed trigger %q is outside allowedTriggers", trigger)
	}
	runID, runAttempt, err := parseInvocationIdentity(values["21"], stable.Repository)
	if err != nil {
		return expectations{}, derivedClaims{}, err
	}
	owner := strings.SplitN(stable.Repository, "/", 2)[0]
	claims := derivedClaims{
		repositoryURL: "https://github.com/" + stable.Repository,
		ownerURL:      "https://github.com/" + owner,
		workflowURI:   "https://github.com/" + stable.Repository + "/" + stable.WorkflowPath + "@" + stable.SourceRef,
		invocationURI: values["21"],
		dependencyURI: "git+https://github.com/" + stable.Repository + "@" + stable.SourceRef,
	}
	builderID := claims.workflowURI
	if stable.BuildType == legacyGitHubBuildType {
		builderID = legacyGitHubBuilderID
	}
	return expectations{
		Schema:               stable.Schema,
		SubjectName:          stable.SubjectName,
		Repository:           stable.Repository,
		RepositoryID:         stable.RepositoryID,
		RepositoryOwnerID:    stable.RepositoryOwnerID,
		WorkflowPath:         stable.WorkflowPath,
		WorkflowName:         stable.WorkflowName,
		SourceRef:            stable.SourceRef,
		SourceRevision:       stable.SourceRevision,
		Trigger:              trigger,
		RunnerEnvironment:    stable.RunnerEnvironment,
		RepositoryVisibility: stable.RepositoryVisibility,
		RunID:                runID,
		RunAttempt:           runAttempt,
		CertificateSAN:       claims.workflowURI,
		CertificateIssuer:    stable.CertificateIssuer,
		BuildType:            stable.BuildType,
		BuilderID:            builderID,
	}, claims, nil
}

func parseInvocationIdentity(invocation, repository string) (string, string, error) {
	prefix := "https://github.com/" + repository + "/actions/runs/"
	if !strings.HasPrefix(invocation, prefix) {
		return "", "", fmt.Errorf("signed invocation URI is outside the expected repository")
	}
	parts := strings.Split(strings.TrimPrefix(invocation, prefix), "/attempts/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("signed invocation URI has no exact run/attempt identity")
	}
	if err := requireCanonicalPositiveDecimal("runId", parts[0]); err != nil {
		return "", "", err
	}
	if err := requireCanonicalPositiveDecimal("runAttempt", parts[1]); err != nil {
		return "", "", err
	}
	if prefix+parts[0]+"/attempts/"+parts[1] != invocation {
		return "", "", fmt.Errorf("signed invocation URI is not canonical")
	}
	return parts[0], parts[1], nil
}

func parseExpectations(raw []byte) (expectations, derivedClaims, error) {
	value, err := parseStrictJSON(raw)
	if err != nil {
		return expectations{}, derivedClaims{}, err
	}
	object, err := objectAt(value, "$")
	if err != nil {
		return expectations{}, derivedClaims{}, err
	}
	fields := []string{
		"schema", "subjectName", "repository", "repositoryId", "repositoryOwnerId",
		"workflowPath", "workflowName", "sourceRef", "sourceRevision", "trigger",
		"runnerEnvironment", "repositoryVisibility", "runId", "runAttempt",
		"certificateSAN", "certificateIssuer", "buildType", "builderId",
	}
	if err := exactFields(object, "$", fields...); err != nil {
		return expectations{}, derivedClaims{}, err
	}
	get := func(field string) (string, error) { return stringAt(object[field], "$."+field) }
	e := expectations{}
	values := []*string{
		&e.Schema, &e.SubjectName, &e.Repository, &e.RepositoryID, &e.RepositoryOwnerID,
		&e.WorkflowPath, &e.WorkflowName, &e.SourceRef, &e.SourceRevision, &e.Trigger,
		&e.RunnerEnvironment, &e.RepositoryVisibility, &e.RunID, &e.RunAttempt,
		&e.CertificateSAN, &e.CertificateIssuer, &e.BuildType, &e.BuilderID,
	}
	for index, field := range fields {
		*values[index], err = get(field)
		if err != nil {
			return expectations{}, derivedClaims{}, err
		}
	}
	if e.Schema != expectationsSchemaV1 {
		return expectations{}, derivedClaims{}, fmt.Errorf("schema: expected %q, got %q", expectationsSchemaV1, e.Schema)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}$`).MatchString(e.Repository) {
		return expectations{}, derivedClaims{}, fmt.Errorf("repository must be one exact owner/name pair")
	}
	if repositoryName := strings.SplitN(e.Repository, "/", 2)[1]; repositoryName == "." || repositoryName == ".." {
		return expectations{}, derivedClaims{}, fmt.Errorf("repository name must not be a path pseudo-component")
	}
	if e.SubjectName == "" || len(e.SubjectName) > 255 || e.SubjectName == "." || e.SubjectName == ".." || path.Base(e.SubjectName) != e.SubjectName || strings.Contains(e.SubjectName, "\\") || hasControlCharacter(e.SubjectName) {
		return expectations{}, derivedClaims{}, fmt.Errorf("subjectName must be one non-empty basename")
	}
	if e.WorkflowPath == "" || len(e.WorkflowPath) > 1024 || !strings.HasPrefix(e.WorkflowPath, ".github/workflows/") || path.Clean(e.WorkflowPath) != e.WorkflowPath || !regexp.MustCompile(`^[A-Za-z0-9_./-]+\.ya?ml$`).MatchString(e.WorkflowPath) {
		return expectations{}, derivedClaims{}, fmt.Errorf("workflowPath must be a normalized .github/workflows/ path")
	}
	if e.WorkflowName == "" || len(e.WorkflowName) > 256 || hasControlCharacter(e.WorkflowName) {
		return expectations{}, derivedClaims{}, fmt.Errorf("workflowName must not be empty")
	}
	if err := requireCanonicalGitRef(e.SourceRef); err != nil {
		return expectations{}, derivedClaims{}, err
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(e.SourceRevision) {
		return expectations{}, derivedClaims{}, fmt.Errorf("sourceRevision must be exactly 40 lowercase hexadecimal digits")
	}
	for label, value := range map[string]string{
		"repositoryId": e.RepositoryID, "repositoryOwnerId": e.RepositoryOwnerID,
		"runId": e.RunID, "runAttempt": e.RunAttempt,
	} {
		if err := requireCanonicalPositiveDecimal(label, value); err != nil {
			return expectations{}, derivedClaims{}, err
		}
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`).MatchString(e.Trigger) {
		return expectations{}, derivedClaims{}, fmt.Errorf("trigger must be one canonical GitHub event name")
	}
	if e.RunnerEnvironment != githubHostedRunner {
		return expectations{}, derivedClaims{}, fmt.Errorf("runnerEnvironment must be %q", githubHostedRunner)
	}
	if e.RepositoryVisibility != privateVisibility {
		return expectations{}, derivedClaims{}, fmt.Errorf("repositoryVisibility must be %q for this private profile", privateVisibility)
	}
	if e.CertificateIssuer != githubOIDCIssuer {
		return expectations{}, derivedClaims{}, fmt.Errorf("certificateIssuer must be %q", githubOIDCIssuer)
	}
	if e.BuildType != legacyGitHubBuildType && e.BuildType != currentGitHubBuildType {
		return expectations{}, derivedClaims{}, fmt.Errorf("buildType is not one of the two closed GitHub workflow/v1 layouts")
	}

	owner := strings.SplitN(e.Repository, "/", 2)[0]
	claims := derivedClaims{
		repositoryURL: "https://github.com/" + e.Repository,
		ownerURL:      "https://github.com/" + owner,
		workflowURI:   "https://github.com/" + e.Repository + "/" + e.WorkflowPath + "@" + e.SourceRef,
		invocationURI: "https://github.com/" + e.Repository + "/actions/runs/" + e.RunID + "/attempts/" + e.RunAttempt,
		dependencyURI: "git+https://github.com/" + e.Repository + "@" + e.SourceRef,
	}
	if e.CertificateSAN != claims.workflowURI {
		return expectations{}, derivedClaims{}, fmt.Errorf("certificateSAN must equal the repository/workflow/ref-derived URI %q", claims.workflowURI)
	}
	if e.BuildType == legacyGitHubBuildType {
		if e.BuilderID != legacyGitHubBuilderID {
			return expectations{}, derivedClaims{}, fmt.Errorf("legacy workflow/v1 builderId must be %q", legacyGitHubBuilderID)
		}
	} else if e.BuilderID != claims.workflowURI {
		return expectations{}, derivedClaims{}, fmt.Errorf("current workflow/v1 builderId must join the exact job workflow URI %q", claims.workflowURI)
	}
	return e, claims, nil
}

func parsePrivateBundleProfile(raw []byte) (rawBundleProfile, error) {
	value, err := parseStrictJSON(raw)
	if err != nil {
		return rawBundleProfile{}, err
	}
	rootObject, err := objectAt(value, "$")
	if err != nil {
		return rawBundleProfile{}, err
	}
	if err := exactFields(rootObject, "$", "mediaType", "verificationMaterial", "dsseEnvelope"); err != nil {
		return rawBundleProfile{}, err
	}
	if err := exactString(rootObject, "mediaType", bundleMediaType, "$"); err != nil {
		return rawBundleProfile{}, err
	}

	material, err := objectAt(rootObject["verificationMaterial"], "$.verificationMaterial")
	if err != nil {
		return rawBundleProfile{}, err
	}
	// GitHub-private attestations use a TSA and deliberately have no Rekor or
	// CT material. Even an empty tlogEntries field is outside this exact profile.
	if err := exactFields(material, "$.verificationMaterial", "certificate", "timestampVerificationData"); err != nil {
		return rawBundleProfile{}, err
	}
	leaf, err := parseBundleLeafCertificate(material)
	if err != nil {
		return rawBundleProfile{}, err
	}
	if containsCTExtension(leaf) {
		return rawBundleProfile{}, fmt.Errorf("certificate transparency/SCT extensions are forbidden in the GitHub-private profile")
	}

	timestampData, err := objectAt(material["timestampVerificationData"], "$.verificationMaterial.timestampVerificationData")
	if err != nil {
		return rawBundleProfile{}, err
	}
	if err := exactFields(timestampData, "$.verificationMaterial.timestampVerificationData", "rfc3161Timestamps"); err != nil {
		return rawBundleProfile{}, err
	}
	timestamps, err := arrayAt(timestampData["rfc3161Timestamps"], "$.verificationMaterial.timestampVerificationData.rfc3161Timestamps")
	if err != nil {
		return rawBundleProfile{}, err
	}
	if len(timestamps) != 1 {
		return rawBundleProfile{}, fmt.Errorf("expected exactly one RFC3161 timestamp, got %d", len(timestamps))
	}
	timestampObject, err := objectAt(timestamps[0], "$.verificationMaterial.timestampVerificationData.rfc3161Timestamps[0]")
	if err != nil {
		return rawBundleProfile{}, err
	}
	if err := exactFields(timestampObject, "$.verificationMaterial.timestampVerificationData.rfc3161Timestamps[0]", "signedTimestamp"); err != nil {
		return rawBundleProfile{}, err
	}
	timestampDER, err := canonicalBase64(timestampObject["signedTimestamp"], "$.verificationMaterial.timestampVerificationData.rfc3161Timestamps[0].signedTimestamp")
	if err != nil {
		return rawBundleProfile{}, err
	}
	if len(timestampDER) < 1 || len(timestampDER) > maximumTimestampBytes {
		return rawBundleProfile{}, fmt.Errorf("RFC3161 timestamp size must be 1..%d bytes", maximumTimestampBytes)
	}

	statement, err := parseBundleStatement(rootObject)
	if err != nil {
		return rawBundleProfile{}, err
	}
	return rawBundleProfile{statement: statement, cert: leaf}, nil
}

func parseBundleLeafCertificate(material map[string]any) (*x509.Certificate, error) {
	certificateObject, err := objectAt(material["certificate"], "$.verificationMaterial.certificate")
	if err != nil {
		return nil, err
	}
	if err := exactFields(certificateObject, "$.verificationMaterial.certificate", "rawBytes"); err != nil {
		return nil, err
	}
	certificateDER, err := canonicalBase64(certificateObject["rawBytes"], "$.verificationMaterial.certificate.rawBytes")
	if err != nil {
		return nil, err
	}
	if len(certificateDER) < 1 || len(certificateDER) > maximumCertificateBytes {
		return nil, fmt.Errorf("certificate DER size must be 1..%d bytes", maximumCertificateBytes)
	}
	leaf, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	return leaf, nil
}

func parseBundleStatement(rootObject map[string]any) (map[string]any, error) {
	envelope, err := objectAt(rootObject["dsseEnvelope"], "$.dsseEnvelope")
	if err != nil {
		return nil, err
	}
	if err := exactFields(envelope, "$.dsseEnvelope", "payload", "payloadType", "signatures"); err != nil {
		return nil, err
	}
	if err := exactString(envelope, "payloadType", payloadType, "$.dsseEnvelope"); err != nil {
		return nil, err
	}
	payload, err := canonicalBase64(envelope["payload"], "$.dsseEnvelope.payload")
	if err != nil {
		return nil, err
	}
	if len(payload) < 1 || len(payload) > maximumStatementBytes {
		return nil, fmt.Errorf("DSSE statement size must be 1..%d bytes", maximumStatementBytes)
	}
	statementValue, err := parseStrictJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("DSSE payload is not strict I-JSON: %w", err)
	}
	statement, err := objectAt(statementValue, "$ DSSE payload")
	if err != nil {
		return nil, err
	}
	signatures, err := arrayAt(envelope["signatures"], "$.dsseEnvelope.signatures")
	if err != nil {
		return nil, err
	}
	if len(signatures) != 1 {
		return nil, fmt.Errorf("expected exactly one DSSE signature, got %d", len(signatures))
	}
	signature, err := objectAt(signatures[0], "$.dsseEnvelope.signatures[0]")
	if err != nil {
		return nil, err
	}
	if err := exactFields(signature, "$.dsseEnvelope.signatures[0]", "sig"); err != nil {
		return nil, err
	}
	if signatureBytes, err := canonicalBase64(signature["sig"], "$.dsseEnvelope.signatures[0].sig"); err != nil {
		return nil, err
	} else if len(signatureBytes) < 1 || len(signatureBytes) > maximumSignatureBytes {
		return nil, fmt.Errorf("DSSE signature size must be 1..%d bytes", maximumSignatureBytes)
	}
	return statement, nil
}

// @ref LLP 0035#transport-and-distribution-provenance — the signed subject,
// source revision, workflow, ref, run, and publisher identity are exact joins.
func validateStatement(statement map[string]any, expected expectations, claims derivedClaims, artifactDigest [sha256.Size]byte) error {
	if err := exactFields(statement, "$", "_type", "subject", "predicateType", "predicate"); err != nil {
		return err
	}
	if err := exactString(statement, "_type", statementType, "$"); err != nil {
		return err
	}
	if err := exactString(statement, "predicateType", predicateType, "$"); err != nil {
		return err
	}
	subjects, err := arrayAt(statement["subject"], "$.subject")
	if err != nil {
		return err
	}
	if len(subjects) != 1 {
		return fmt.Errorf("$.subject: expected exactly one subject, got %d", len(subjects))
	}
	subject, err := objectAt(subjects[0], "$.subject[0]")
	if err != nil {
		return err
	}
	if err := exactFields(subject, "$.subject[0]", "name", "digest"); err != nil {
		return err
	}
	if err := exactString(subject, "name", expected.SubjectName, "$.subject[0]"); err != nil {
		return err
	}
	digest, err := objectAt(subject["digest"], "$.subject[0].digest")
	if err != nil {
		return err
	}
	if err := exactFields(digest, "$.subject[0].digest", "sha256"); err != nil {
		return err
	}
	if err := exactString(digest, "sha256", hex.EncodeToString(artifactDigest[:]), "$.subject[0].digest"); err != nil {
		return err
	}

	predicate, err := objectAt(statement["predicate"], "$.predicate")
	if err != nil {
		return err
	}
	if err := exactFields(predicate, "$.predicate", "buildDefinition", "runDetails"); err != nil {
		return err
	}
	definition, err := objectAt(predicate["buildDefinition"], "$.predicate.buildDefinition")
	if err != nil {
		return err
	}
	if err := exactFields(definition, "$.predicate.buildDefinition", "buildType", "externalParameters", "internalParameters", "resolvedDependencies"); err != nil {
		return err
	}
	if err := exactString(definition, "buildType", expected.BuildType, "$.predicate.buildDefinition"); err != nil {
		return err
	}
	external, err := objectAt(definition["externalParameters"], "$.predicate.buildDefinition.externalParameters")
	if err != nil {
		return err
	}
	if err := exactFields(external, "$.predicate.buildDefinition.externalParameters", "workflow"); err != nil {
		return err
	}
	workflow, err := objectAt(external["workflow"], "$.predicate.buildDefinition.externalParameters.workflow")
	if err != nil {
		return err
	}
	if err := exactFields(workflow, "$.predicate.buildDefinition.externalParameters.workflow", "ref", "repository", "path"); err != nil {
		return err
	}
	if err := exactString(workflow, "ref", expected.SourceRef, "$.predicate.buildDefinition.externalParameters.workflow"); err != nil {
		return err
	}
	if err := exactString(workflow, "repository", claims.repositoryURL, "$.predicate.buildDefinition.externalParameters.workflow"); err != nil {
		return err
	}
	if err := exactString(workflow, "path", expected.WorkflowPath, "$.predicate.buildDefinition.externalParameters.workflow"); err != nil {
		return err
	}

	internal, err := objectAt(definition["internalParameters"], "$.predicate.buildDefinition.internalParameters")
	if err != nil {
		return err
	}
	if err := exactFields(internal, "$.predicate.buildDefinition.internalParameters", "github"); err != nil {
		return err
	}
	github, err := objectAt(internal["github"], "$.predicate.buildDefinition.internalParameters.github")
	if err != nil {
		return err
	}
	githubFields := []string{"event_name", "repository_id", "repository_owner_id"}
	if expected.BuildType == currentGitHubBuildType {
		githubFields = append(githubFields, "runner_environment")
	}
	if err := exactFields(github, "$.predicate.buildDefinition.internalParameters.github", githubFields...); err != nil {
		return err
	}
	if err := exactString(github, "event_name", expected.Trigger, "$.predicate.buildDefinition.internalParameters.github"); err != nil {
		return err
	}
	if err := exactString(github, "repository_id", expected.RepositoryID, "$.predicate.buildDefinition.internalParameters.github"); err != nil {
		return err
	}
	if err := exactString(github, "repository_owner_id", expected.RepositoryOwnerID, "$.predicate.buildDefinition.internalParameters.github"); err != nil {
		return err
	}
	if expected.BuildType == currentGitHubBuildType {
		if err := exactString(github, "runner_environment", expected.RunnerEnvironment, "$.predicate.buildDefinition.internalParameters.github"); err != nil {
			return err
		}
	}

	dependencies, err := arrayAt(definition["resolvedDependencies"], "$.predicate.buildDefinition.resolvedDependencies")
	if err != nil {
		return err
	}
	if len(dependencies) != 1 {
		return fmt.Errorf("$.predicate.buildDefinition.resolvedDependencies: expected exactly one source, got %d", len(dependencies))
	}
	dependency, err := objectAt(dependencies[0], "$.predicate.buildDefinition.resolvedDependencies[0]")
	if err != nil {
		return err
	}
	if err := exactFields(dependency, "$.predicate.buildDefinition.resolvedDependencies[0]", "uri", "digest"); err != nil {
		return err
	}
	if err := exactString(dependency, "uri", claims.dependencyURI, "$.predicate.buildDefinition.resolvedDependencies[0]"); err != nil {
		return err
	}
	dependencyDigest, err := objectAt(dependency["digest"], "$.predicate.buildDefinition.resolvedDependencies[0].digest")
	if err != nil {
		return err
	}
	if err := exactFields(dependencyDigest, "$.predicate.buildDefinition.resolvedDependencies[0].digest", "gitCommit"); err != nil {
		return err
	}
	if err := exactString(dependencyDigest, "gitCommit", expected.SourceRevision, "$.predicate.buildDefinition.resolvedDependencies[0].digest"); err != nil {
		return err
	}

	runDetails, err := objectAt(predicate["runDetails"], "$.predicate.runDetails")
	if err != nil {
		return err
	}
	if err := exactFields(runDetails, "$.predicate.runDetails", "builder", "metadata"); err != nil {
		return err
	}
	builder, err := objectAt(runDetails["builder"], "$.predicate.runDetails.builder")
	if err != nil {
		return err
	}
	if err := exactFields(builder, "$.predicate.runDetails.builder", "id"); err != nil {
		return err
	}
	if err := exactString(builder, "id", expected.BuilderID, "$.predicate.runDetails.builder"); err != nil {
		return err
	}
	metadata, err := objectAt(runDetails["metadata"], "$.predicate.runDetails.metadata")
	if err != nil {
		return err
	}
	if err := exactFields(metadata, "$.predicate.runDetails.metadata", "invocationId"); err != nil {
		return err
	}
	return exactString(metadata, "invocationId", claims.invocationURI, "$.predicate.runDetails.metadata")
}

func validateCertificateClaims(leaf *x509.Certificate, expected expectations, claims derivedClaims, tp trustProfile) error {
	rawSAN, err := exactCertificateURISAN(leaf)
	if err != nil {
		return err
	}
	if rawSAN != expected.CertificateSAN {
		return fmt.Errorf("expected raw URI SAN %q, got %q", expected.CertificateSAN, rawSAN)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != expected.CertificateSAN {
		return fmt.Errorf("expected one URI SAN %q, got %v", expected.CertificateSAN, leaf.URIs)
	}
	if len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 {
		return fmt.Errorf("unexpected non-URI subject alternative names")
	}
	if len(leaf.Issuer.Organization) != 1 || leaf.Issuer.Organization[0] != tp.issuerOrganization {
		return fmt.Errorf("leaf issuer organization is not the %s CA", tp.label)
	}

	values, err := exactSigstoreExtensions(leaf)
	if err != nil {
		return err
	}
	want := map[string]string{
		"1":  expected.CertificateIssuer,
		"2":  expected.Trigger,
		"3":  expected.SourceRevision,
		"4":  expected.WorkflowName,
		"5":  expected.Repository,
		"6":  expected.SourceRef,
		"8":  expected.CertificateIssuer,
		"9":  claims.workflowURI,
		"10": expected.SourceRevision,
		"11": expected.RunnerEnvironment,
		"12": claims.repositoryURL,
		"13": expected.SourceRevision,
		"14": expected.SourceRef,
		"15": expected.RepositoryID,
		"16": claims.ownerURL,
		"17": expected.RepositoryOwnerID,
		"18": claims.workflowURI,
		"19": expected.SourceRevision,
		"20": expected.Trigger,
		"21": claims.invocationURI,
		"22": expected.RepositoryVisibility,
	}
	if len(values) != len(want) {
		return fmt.Errorf("expected %d exact Sigstore claim extensions, got %d", len(want), len(values))
	}
	for oid, expectedValue := range want {
		actual, ok := values[oid]
		if !ok {
			return fmt.Errorf("missing Sigstore certificate extension 1.3.6.1.4.1.57264.1.%s", oid)
		}
		if actual != expectedValue {
			return fmt.Errorf("Sigstore extension 1.3.6.1.4.1.57264.1.%s: expected %q, got %q", oid, expectedValue, actual)
		}
	}
	return nil
}

func exactCertificateURISAN(leaf *x509.Certificate) (string, error) {
	subjectAltNameOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	var sanExtension *pkix.Extension
	for index := range leaf.Extensions {
		if leaf.Extensions[index].Id.Equal(subjectAltNameOID) {
			if sanExtension != nil {
				return "", fmt.Errorf("certificate has duplicate subjectAltName extensions")
			}
			sanExtension = &leaf.Extensions[index]
		}
	}
	if sanExtension == nil {
		return "", fmt.Errorf("certificate has no subjectAltName extension")
	}
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(sanExtension.Value, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return "", fmt.Errorf("certificate subjectAltName is not one canonical DER sequence")
	}
	contents := sequence.Bytes
	var names []asn1.RawValue
	for len(contents) > 0 {
		var name asn1.RawValue
		contents, err = asn1.Unmarshal(contents, &name)
		if err != nil {
			return "", fmt.Errorf("parse certificate subjectAltName GeneralName: %w", err)
		}
		names = append(names, name)
	}
	if len(names) != 1 || names[0].Class != asn1.ClassContextSpecific || names[0].Tag != 6 || names[0].IsCompound {
		return "", fmt.Errorf("certificate subjectAltName must contain exactly one URI GeneralName")
	}
	for _, character := range names[0].Bytes {
		if character > 0x7f || character < 0x21 {
			return "", fmt.Errorf("certificate URI SAN is not printable IA5 text")
		}
	}
	return string(names[0].Bytes), nil
}

func exactSigstoreExtensions(leaf *x509.Certificate) (map[string]string, error) {
	const prefix = "1.3.6.1.4.1.57264.1."
	legacy := map[string]bool{"1": true, "2": true, "3": true, "4": true, "5": true, "6": true}
	values := map[string]string{}
	for _, extension := range leaf.Extensions {
		oid := extension.Id.String()
		if !strings.HasPrefix(oid, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(oid, prefix)
		if _, exists := values[suffix]; exists {
			return nil, fmt.Errorf("duplicate Sigstore certificate extension %s", oid)
		}
		var value string
		if legacy[suffix] {
			if !utf8.Valid(extension.Value) {
				return nil, fmt.Errorf("Sigstore certificate extension %s is not UTF-8", oid)
			}
			value = string(extension.Value)
		} else {
			if err := certificate.ParseDERString(extension.Value, &value); err != nil {
				return nil, fmt.Errorf("parse Sigstore certificate extension %s: %w", oid, err)
			}
		}
		values[suffix] = value
	}
	return values, nil
}

func certificateIdentity(expected expectations, claims derivedClaims) (verify.CertificateIdentity, error) {
	san, err := verify.NewSANMatcher(expected.CertificateSAN, "")
	if err != nil {
		return verify.CertificateIdentity{}, err
	}
	issuer, err := verify.NewIssuerMatcher(expected.CertificateIssuer, "")
	if err != nil {
		return verify.CertificateIdentity{}, err
	}
	extensions := certificate.Extensions{
		GithubWorkflowTrigger:               expected.Trigger,
		GithubWorkflowSHA:                   expected.SourceRevision,
		GithubWorkflowName:                  expected.WorkflowName,
		GithubWorkflowRepository:            expected.Repository,
		GithubWorkflowRef:                   expected.SourceRef,
		BuildSignerURI:                      claims.workflowURI,
		BuildSignerDigest:                   expected.SourceRevision,
		RunnerEnvironment:                   expected.RunnerEnvironment,
		SourceRepositoryURI:                 claims.repositoryURL,
		SourceRepositoryDigest:              expected.SourceRevision,
		SourceRepositoryRef:                 expected.SourceRef,
		SourceRepositoryIdentifier:          expected.RepositoryID,
		SourceRepositoryOwnerURI:            claims.ownerURL,
		SourceRepositoryOwnerIdentifier:     expected.RepositoryOwnerID,
		BuildConfigURI:                      claims.workflowURI,
		BuildConfigDigest:                   expected.SourceRevision,
		BuildTrigger:                        expected.Trigger,
		RunInvocationURI:                    claims.invocationURI,
		SourceRepositoryVisibilityAtSigning: expected.RepositoryVisibility,
	}
	return verify.NewCertificateIdentity(san, issuer, extensions)
}

func loadPinnedTrustedRoot(tp trustProfile) (*root.TrustedRoot, error) {
	raw, err := trustFiles.ReadFile(tp.rootPath)
	if err != nil {
		return nil, fmt.Errorf("read embedded %s trusted root: %w", tp.label, err)
	}
	if len(raw) != tp.rootSize {
		return nil, fmt.Errorf("embedded %s trusted root size: expected %d, got %d", tp.label, tp.rootSize, len(raw))
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != tp.rootSHA256 {
		return nil, fmt.Errorf("embedded %s trusted root digest mismatch", tp.label)
	}
	value, err := parseStrictJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("embedded %s trusted root is not strict I-JSON: %w", tp.label, err)
	}
	object, err := objectAt(value, "$ trusted root")
	if err != nil {
		return nil, err
	}
	if err := exactFields(object, "$ trusted root", tp.rootFields...); err != nil {
		return nil, err
	}
	if err := exactString(object, "mediaType", trustedRootMediaType, "$ trusted root"); err != nil {
		return nil, err
	}
	cas, err := arrayAt(object["certificateAuthorities"], "$ trusted root.certificateAuthorities")
	if err != nil || len(cas) == 0 {
		return nil, fmt.Errorf("trusted root must contain %s certificate authorities", tp.authorityLabel)
	}
	trusted, err := root.NewTrustedRootFromJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("sigstore-go rejected embedded %s trusted root: %w", tp.label, err)
	}
	if tp.kind == "public" {
		tlogs, err := arrayAt(object["tlogs"], "$ trusted root.tlogs")
		if err != nil || len(tlogs) == 0 {
			return nil, fmt.Errorf("trusted root must contain %s transparency logs", tp.authorityLabel)
		}
		ctlogs, err := arrayAt(object["ctlogs"], "$ trusted root.ctlogs")
		if err != nil || len(ctlogs) == 0 {
			return nil, fmt.Errorf("trusted root must contain %s certificate-transparency logs", tp.authorityLabel)
		}
		if len(trusted.RekorLogs()) == 0 || len(trusted.CTLogs()) == 0 {
			return nil, fmt.Errorf("%s trusted root is missing transparency-log authority", tp.label)
		}
		return trusted, nil
	}
	tsas, err := arrayAt(object["timestampAuthorities"], "$ trusted root.timestampAuthorities")
	if err != nil || len(tsas) == 0 {
		return nil, fmt.Errorf("trusted root must contain %s timestamp authorities", tp.authorityLabel)
	}
	if len(trusted.RekorLogs()) != 0 || len(trusted.CTLogs()) != 0 {
		return nil, fmt.Errorf("%s trusted root unexpectedly contains transparency-log authority", tp.label)
	}
	return trusted, nil
}

func containsCTExtension(leaf *x509.Certificate) bool {
	const ctOIDPrefix = "1.3.6.1.4.1.11129.2.4."
	for _, extension := range leaf.Extensions {
		if strings.HasPrefix(extension.Id.String(), ctOIDPrefix) {
			return true
		}
	}
	return false
}

func canonicalBase64(value any, where string) ([]byte, error) {
	encoded, err := stringAt(value, where)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid standard base64: %w", where, err)
	}
	if base64.StdEncoding.EncodeToString(decoded) != encoded {
		return nil, fmt.Errorf("%s: base64 is not in canonical padded form", where)
	}
	return decoded, nil
}

func readExactRegular(filePath string, maximum int64) ([]byte, int64, error) {
	file, size, err := openExactRegular(filePath)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	if size < 1 || size > maximum {
		return nil, 0, fmt.Errorf("file size must be 1..%d bytes, got %d", maximum, size)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(raw)) != size {
		return nil, 0, fmt.Errorf("file changed while being read: stat size %d, read %d", size, len(raw))
	}
	return raw, size, nil
}

func digestExactRegular(filePath string) ([sha256.Size]byte, int64, error) {
	var zero [sha256.Size]byte
	file, size, err := openExactRegular(filePath)
	if err != nil {
		return zero, 0, err
	}
	defer file.Close()
	if size < 1 || size > maximumArtifactBytes {
		return zero, 0, fmt.Errorf("artifact size must be 1..%d bytes, got %d", maximumArtifactBytes, size)
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, maximumArtifactBytes+1))
	if err != nil {
		return zero, 0, err
	}
	if written != size {
		return zero, 0, fmt.Errorf("artifact changed while being read: stat size %d, read %d", size, written)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest, size, nil
}

func openExactRegular(filePath string) (*os.File, int64, error) {
	before, err := os.Lstat(filePath)
	if err != nil {
		return nil, 0, err
	}
	if !before.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("path must directly name a regular file (symlinks are rejected)")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, 0, err
	}
	after, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		file.Close()
		return nil, 0, fmt.Errorf("path changed between no-follow inspection and open")
	}
	return file, after.Size(), nil
}

func requireCanonicalPositiveDecimal(label, value string) error {
	if !regexp.MustCompile(`^[1-9][0-9]*$`).MatchString(value) {
		return fmt.Errorf("%s must be a canonical positive decimal string", label)
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed > uint64(maxIJSONInteger) {
		return fmt.Errorf("%s must fit the I-JSON safe integer range", label)
	}
	return nil
}

func hasControlCharacter(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func requireCanonicalGitRef(value string) error {
	if len(value) < len("refs/a") || len(value) > 1024 || !strings.HasPrefix(value, "refs/") ||
		strings.HasSuffix(value, "/") || strings.HasSuffix(value, ".") ||
		strings.Contains(value, "..") || strings.Contains(value, "//") ||
		!regexp.MustCompile(`^[A-Za-z0-9._/+\-]+$`).MatchString(value) {
		return fmt.Errorf("sourceRef must be one canonical, unambiguous refs/... string")
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || strings.HasPrefix(component, ".") || strings.HasSuffix(component, ".lock") {
			return fmt.Errorf("sourceRef must be one canonical, unambiguous refs/... string")
		}
	}
	return nil
}
