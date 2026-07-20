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
	expectationsSchema       = "ibex/github-private-artifact-attestation-expectations/2"
	verificationSchema       = "ibex/github-private-artifact-attestation-verification/1"
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
//go:embed trust/github-private/trusted_root.json
var trustFiles embed.FS

type expectations struct {
	Schema               string
	SubjectName          string
	Repository           string
	RepositoryID         string
	RepositoryOwnerID    string
	WorkflowPath         string
	SourceRef            string
	SourceRevision       string
	AllowedTriggers      []string
	RunnerEnvironment    string
	RepositoryVisibility string
	CertificateSAN       string
	CertificateIssuer    string
	BuildType            string
	BuilderID            string
}

type derivedClaims struct {
	repositoryURL string
	ownerURL      string
	workflowURI   string
	dependencyURI string
}

type observedClaims struct {
	workflowName  string
	trigger       string
	invocationURI string
	runID         string
	runAttempt    string
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
	expected, claims, err := parseExpectations(expectationsRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid expectations: %w", err)
	}

	bundleRaw, bundleSize, err := readExactRegular(bundlePath, maximumBundleBytes)
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	profile, err := parsePrivateBundleProfile(bundleRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid GitHub-private bundle profile: %w", err)
	}

	artifactDigest, artifactSize, err := digestExactRegular(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	observed, err := validateCertificateClaims(profile.cert, expected, claims)
	if err != nil {
		return nil, fmt.Errorf("invalid signing certificate claims: %w", err)
	}
	if err := validateStatement(profile.statement, expected, claims, observed, artifactDigest); err != nil {
		return nil, fmt.Errorf("invalid signed provenance statement: %w", err)
	}

	trustedMaterial, err := loadPinnedTrustedRoot()
	if err != nil {
		return nil, err
	}
	var parsedBundle bundle.Bundle
	if err := parsedBundle.UnmarshalJSON(bundleRaw); err != nil {
		return nil, fmt.Errorf("sigstore-go rejected bundle: %w", err)
	}
	identity, err := certificateIdentity(expected, claims, observed)
	if err != nil {
		return nil, fmt.Errorf("construct certificate policy: %w", err)
	}
	verifier, err := verify.NewVerifier(trustedMaterial, verify.WithSignedTimestamps(1))
	if err != nil {
		return nil, fmt.Errorf("construct signed-timestamp-only verifier: %w", err)
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
	if len(verified.VerifiedTimestamps) != 1 || verified.VerifiedTimestamps[0].Type != "TimestampAuthority" {
		return nil, fmt.Errorf("expected exactly one verified RFC3161 timestamp, got %#v", verified.VerifiedTimestamps)
	}
	timestamp := verified.VerifiedTimestamps[0]

	if artifactSize > maxIJSONInteger || bundleSize > maxIJSONInteger || expectationsSize > maxIJSONInteger {
		return nil, fmt.Errorf("a result size is outside the I-JSON safe integer range")
	}
	bundleDigest := sha256.Sum256(bundleRaw)
	expectationsDigest := sha256.Sum256(expectationsRaw)
	result := canonicalResult{
		Schema: verificationSchema,
		TrustRoot: canonicalTrustRoot{
			Profile: "github-private-signed-timestamp-v1",
			SHA256:  trustedRootSHA256,
			Size:    trustedRootSize,
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
			WorkflowName:         observed.workflowName,
			SourceRef:            expected.SourceRef,
			SourceRevision:       expected.SourceRevision,
			Trigger:              observed.trigger,
			RunnerEnvironment:    expected.RunnerEnvironment,
			RepositoryVisibility: expected.RepositoryVisibility,
			RunID:                observed.runID,
			RunAttempt:           observed.runAttempt,
		},
		Provenance: canonicalProvenance{
			StatementType: statementType,
			PredicateType: predicateType,
			BuildType:     expected.BuildType,
			BuilderID:     expected.BuilderID,
			InvocationID:  observed.invocationURI,
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
		"workflowPath", "sourceRef", "sourceRevision", "allowedTriggers",
		"runnerEnvironment", "repositoryVisibility",
		"certificateSAN", "certificateIssuer", "buildType", "builderId",
	}
	if err := exactFields(object, "$", fields...); err != nil {
		return expectations{}, derivedClaims{}, err
	}
	get := func(field string) (string, error) { return stringAt(object[field], "$."+field) }
	e := expectations{}
	stringFields := []string{
		"schema", "subjectName", "repository", "repositoryId", "repositoryOwnerId",
		"workflowPath", "sourceRef", "sourceRevision", "runnerEnvironment",
		"repositoryVisibility", "certificateSAN", "certificateIssuer", "buildType",
		"builderId",
	}
	values := []*string{
		&e.Schema, &e.SubjectName, &e.Repository, &e.RepositoryID, &e.RepositoryOwnerID,
		&e.WorkflowPath, &e.SourceRef, &e.SourceRevision, &e.RunnerEnvironment,
		&e.RepositoryVisibility, &e.CertificateSAN, &e.CertificateIssuer, &e.BuildType,
		&e.BuilderID,
	}
	for index, field := range stringFields {
		*values[index], err = get(field)
		if err != nil {
			return expectations{}, derivedClaims{}, err
		}
	}
	allowedTriggers, err := arrayAt(object["allowedTriggers"], "$.allowedTriggers")
	if err != nil {
		return expectations{}, derivedClaims{}, err
	}
	if len(allowedTriggers) < 1 || len(allowedTriggers) > 2 {
		return expectations{}, derivedClaims{}, fmt.Errorf("allowedTriggers must contain one or two admitted events")
	}
	for index, value := range allowedTriggers {
		trigger, err := stringAt(value, fmt.Sprintf("$.allowedTriggers[%d]", index))
		if err != nil {
			return expectations{}, derivedClaims{}, err
		}
		if trigger != "push" && trigger != "workflow_dispatch" {
			return expectations{}, derivedClaims{}, fmt.Errorf("allowedTriggers contains an event outside the closed publisher profile: %q", trigger)
		}
		if index > 0 && e.AllowedTriggers[index-1] >= trigger {
			return expectations{}, derivedClaims{}, fmt.Errorf("allowedTriggers must be strictly sorted and unique")
		}
		e.AllowedTriggers = append(e.AllowedTriggers, trigger)
	}
	if e.Schema != expectationsSchema {
		return expectations{}, derivedClaims{}, fmt.Errorf("schema: expected %q, got %q", expectationsSchema, e.Schema)
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
	if err := requireCanonicalGitRef(e.SourceRef); err != nil {
		return expectations{}, derivedClaims{}, err
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(e.SourceRevision) {
		return expectations{}, derivedClaims{}, fmt.Errorf("sourceRevision must be exactly 40 lowercase hexadecimal digits")
	}
	for label, value := range map[string]string{
		"repositoryId": e.RepositoryID, "repositoryOwnerId": e.RepositoryOwnerID,
	} {
		if err := requireCanonicalPositiveDecimal(label, value); err != nil {
			return expectations{}, derivedClaims{}, err
		}
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
	certificateObject, err := objectAt(material["certificate"], "$.verificationMaterial.certificate")
	if err != nil {
		return rawBundleProfile{}, err
	}
	if err := exactFields(certificateObject, "$.verificationMaterial.certificate", "rawBytes"); err != nil {
		return rawBundleProfile{}, err
	}
	certificateDER, err := canonicalBase64(certificateObject["rawBytes"], "$.verificationMaterial.certificate.rawBytes")
	if err != nil {
		return rawBundleProfile{}, err
	}
	if len(certificateDER) < 1 || len(certificateDER) > maximumCertificateBytes {
		return rawBundleProfile{}, fmt.Errorf("certificate DER size must be 1..%d bytes", maximumCertificateBytes)
	}
	leaf, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return rawBundleProfile{}, fmt.Errorf("parse leaf certificate: %w", err)
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

	envelope, err := objectAt(rootObject["dsseEnvelope"], "$.dsseEnvelope")
	if err != nil {
		return rawBundleProfile{}, err
	}
	if err := exactFields(envelope, "$.dsseEnvelope", "payload", "payloadType", "signatures"); err != nil {
		return rawBundleProfile{}, err
	}
	if err := exactString(envelope, "payloadType", payloadType, "$.dsseEnvelope"); err != nil {
		return rawBundleProfile{}, err
	}
	payload, err := canonicalBase64(envelope["payload"], "$.dsseEnvelope.payload")
	if err != nil {
		return rawBundleProfile{}, err
	}
	if len(payload) < 1 || len(payload) > maximumStatementBytes {
		return rawBundleProfile{}, fmt.Errorf("DSSE statement size must be 1..%d bytes", maximumStatementBytes)
	}
	statementValue, err := parseStrictJSON(payload)
	if err != nil {
		return rawBundleProfile{}, fmt.Errorf("DSSE payload is not strict I-JSON: %w", err)
	}
	statement, err := objectAt(statementValue, "$ DSSE payload")
	if err != nil {
		return rawBundleProfile{}, err
	}
	signatures, err := arrayAt(envelope["signatures"], "$.dsseEnvelope.signatures")
	if err != nil {
		return rawBundleProfile{}, err
	}
	if len(signatures) != 1 {
		return rawBundleProfile{}, fmt.Errorf("expected exactly one DSSE signature, got %d", len(signatures))
	}
	signature, err := objectAt(signatures[0], "$.dsseEnvelope.signatures[0]")
	if err != nil {
		return rawBundleProfile{}, err
	}
	if err := exactFields(signature, "$.dsseEnvelope.signatures[0]", "sig"); err != nil {
		return rawBundleProfile{}, err
	}
	if signatureBytes, err := canonicalBase64(signature["sig"], "$.dsseEnvelope.signatures[0].sig"); err != nil {
		return rawBundleProfile{}, err
	} else if len(signatureBytes) < 1 || len(signatureBytes) > maximumSignatureBytes {
		return rawBundleProfile{}, fmt.Errorf("DSSE signature size must be 1..%d bytes", maximumSignatureBytes)
	}
	return rawBundleProfile{statement: statement, cert: leaf}, nil
}

// @ref LLP 0035#transport-and-distribution-provenance — the signed subject,
// source revision, workflow, ref, run, and publisher identity are exact joins.
func validateStatement(statement map[string]any, expected expectations, claims derivedClaims, observed observedClaims, artifactDigest [sha256.Size]byte) error {
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
	if err := exactString(github, "event_name", observed.trigger, "$.predicate.buildDefinition.internalParameters.github"); err != nil {
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
	return exactString(metadata, "invocationId", observed.invocationURI, "$.predicate.runDetails.metadata")
}

func validateCertificateClaims(leaf *x509.Certificate, expected expectations, claims derivedClaims) (observedClaims, error) {
	rawSAN, err := exactCertificateURISAN(leaf)
	if err != nil {
		return observedClaims{}, err
	}
	if rawSAN != expected.CertificateSAN {
		return observedClaims{}, fmt.Errorf("expected raw URI SAN %q, got %q", expected.CertificateSAN, rawSAN)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != expected.CertificateSAN {
		return observedClaims{}, fmt.Errorf("expected one URI SAN %q, got %v", expected.CertificateSAN, leaf.URIs)
	}
	if len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 {
		return observedClaims{}, fmt.Errorf("unexpected non-URI subject alternative names")
	}
	if len(leaf.Issuer.Organization) != 1 || leaf.Issuer.Organization[0] != "GitHub, Inc." {
		return observedClaims{}, fmt.Errorf("leaf issuer organization is not the GitHub-private CA")
	}

	values, err := exactSigstoreExtensions(leaf)
	if err != nil {
		return observedClaims{}, err
	}
	if len(values) != 21 {
		return observedClaims{}, fmt.Errorf("expected 21 exact Sigstore claim extensions, got %d", len(values))
	}
	trigger, ok := values["2"]
	if !ok {
		return observedClaims{}, fmt.Errorf("missing Sigstore certificate extension 1.3.6.1.4.1.57264.1.2")
	}
	triggerAllowed := false
	for _, allowed := range expected.AllowedTriggers {
		triggerAllowed = triggerAllowed || trigger == allowed
	}
	if !triggerAllowed {
		return observedClaims{}, fmt.Errorf("signed workflow trigger %q is outside allowedTriggers", trigger)
	}
	workflowName, ok := values["4"]
	if !ok || workflowName == "" || len(workflowName) > 256 || hasControlCharacter(workflowName) {
		return observedClaims{}, fmt.Errorf("signed workflow name is absent or malformed")
	}
	invocationURI, ok := values["21"]
	if !ok {
		return observedClaims{}, fmt.Errorf("missing Sigstore certificate extension 1.3.6.1.4.1.57264.1.21")
	}
	invocationPattern := regexp.MustCompile(
		`^https://github\.com/` + regexp.QuoteMeta(expected.Repository) + `/actions/runs/([1-9][0-9]*)/attempts/([1-9][0-9]*)$`,
	)
	invocationParts := invocationPattern.FindStringSubmatch(invocationURI)
	if len(invocationParts) != 3 {
		return observedClaims{}, fmt.Errorf("signed run invocation URI is not canonical for repository %q", expected.Repository)
	}
	if err := requireCanonicalPositiveDecimal("signed runId", invocationParts[1]); err != nil {
		return observedClaims{}, err
	}
	if err := requireCanonicalPositiveDecimal("signed runAttempt", invocationParts[2]); err != nil {
		return observedClaims{}, err
	}
	observed := observedClaims{
		workflowName:  workflowName,
		trigger:       trigger,
		invocationURI: invocationURI,
		runID:         invocationParts[1],
		runAttempt:    invocationParts[2],
	}
	want := map[string]string{
		"1":  expected.CertificateIssuer,
		"2":  observed.trigger,
		"3":  expected.SourceRevision,
		"4":  observed.workflowName,
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
		"20": observed.trigger,
		"21": observed.invocationURI,
		"22": expected.RepositoryVisibility,
	}
	for oid, expectedValue := range want {
		actual, ok := values[oid]
		if !ok {
			return observedClaims{}, fmt.Errorf("missing Sigstore certificate extension 1.3.6.1.4.1.57264.1.%s", oid)
		}
		if actual != expectedValue {
			return observedClaims{}, fmt.Errorf("Sigstore extension 1.3.6.1.4.1.57264.1.%s: expected %q, got %q", oid, expectedValue, actual)
		}
	}
	return observed, nil
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

func certificateIdentity(expected expectations, claims derivedClaims, observed observedClaims) (verify.CertificateIdentity, error) {
	san, err := verify.NewSANMatcher(expected.CertificateSAN, "")
	if err != nil {
		return verify.CertificateIdentity{}, err
	}
	issuer, err := verify.NewIssuerMatcher(expected.CertificateIssuer, "")
	if err != nil {
		return verify.CertificateIdentity{}, err
	}
	extensions := certificate.Extensions{
		GithubWorkflowTrigger:               observed.trigger,
		GithubWorkflowSHA:                   expected.SourceRevision,
		GithubWorkflowName:                  observed.workflowName,
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
		BuildTrigger:                        observed.trigger,
		RunInvocationURI:                    observed.invocationURI,
		SourceRepositoryVisibilityAtSigning: expected.RepositoryVisibility,
	}
	return verify.NewCertificateIdentity(san, issuer, extensions)
}

func loadPinnedTrustedRoot() (*root.TrustedRoot, error) {
	raw, err := trustFiles.ReadFile("trust/github-private/trusted_root.json")
	if err != nil {
		return nil, fmt.Errorf("read embedded GitHub-private trusted root: %w", err)
	}
	if len(raw) != trustedRootSize {
		return nil, fmt.Errorf("embedded GitHub-private trusted root size: expected %d, got %d", trustedRootSize, len(raw))
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != trustedRootSHA256 {
		return nil, fmt.Errorf("embedded GitHub-private trusted root digest mismatch")
	}
	value, err := parseStrictJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("embedded GitHub-private trusted root is not strict I-JSON: %w", err)
	}
	object, err := objectAt(value, "$ trusted root")
	if err != nil {
		return nil, err
	}
	if err := exactFields(object, "$ trusted root", "mediaType", "certificateAuthorities", "timestampAuthorities"); err != nil {
		return nil, err
	}
	if err := exactString(object, "mediaType", trustedRootMediaType, "$ trusted root"); err != nil {
		return nil, err
	}
	cas, err := arrayAt(object["certificateAuthorities"], "$ trusted root.certificateAuthorities")
	if err != nil || len(cas) == 0 {
		return nil, fmt.Errorf("trusted root must contain GitHub certificate authorities")
	}
	tsas, err := arrayAt(object["timestampAuthorities"], "$ trusted root.timestampAuthorities")
	if err != nil || len(tsas) == 0 {
		return nil, fmt.Errorf("trusted root must contain GitHub timestamp authorities")
	}
	trusted, err := root.NewTrustedRootFromJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("sigstore-go rejected embedded GitHub-private trusted root: %w", err)
	}
	if len(trusted.RekorLogs()) != 0 || len(trusted.CTLogs()) != 0 {
		return nil, fmt.Errorf("GitHub-private trusted root unexpectedly contains transparency-log authority")
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
