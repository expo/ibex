// The Sigstore public-good trust profile for GitHub artifact attestations on
// public repositories, prepared for the ibex public flip. GitHub signs a
// public repository's workflow-initiated provenance through the public-good
// Fulcio (issuer organization "sigstore.dev"), embeds a signed certificate
// timestamp, and records exactly one dsse Rekor entry carrying both an
// inclusion promise and an inclusion proof, while the bundle's
// timestampVerificationData is present but empty. Every one of those facts
// was measured from a live public-repository attestation (cli/cli v2.93.0)
// rather than assumed; the profile admits exactly that shape and nothing
// wider.
//
// @ref LLP 0035#threat-model-and-trust-roots — the public-good root is pinned
// and embedded exactly like the GitHub-private root; verification remains
// offline, and rotation is a reviewed source update.
package main

import (
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	expectationsSchemaPublicV1 = "ibex/github-public-artifact-attestation-expectations/1"
	verificationSchemaPublicV1 = "ibex/github-public-artifact-attestation-verification/1"
	publicVisibility           = "public"
	publicTrustedRootSHA256    = "3c2cc7f357dc064ec527fdcd78da6e9245c21a381e1abaa0f2b62b186bcac1a1"
	publicTrustedRootSize      = 5748
	maximumTlogFieldBytes      = 1024 * 1024
	maximumTlogHashes          = 64
)

// trustProfile carries every fact that distinguishes the GitHub-private
// signed-timestamp profile from the Sigstore public-good Rekor profile. All
// selection happens through the expectations schema; a bundle can never
// choose its own trust profile.
type trustProfile struct {
	kind                     string
	label                    string
	authorityLabel           string
	rootProfile              string
	rootPath                 string
	rootSHA256               string
	rootSize                 int
	rootFields               []string
	stableExpectationsSchema string
	visibility               string
	issuerOrganization       string
	verifierLabel            string
	timestampType            string
	timestampLabel           string
}

var privateTrustProfile = trustProfile{
	kind:                     "private",
	label:                    "GitHub-private",
	authorityLabel:           "GitHub",
	rootProfile:              "github-private-signed-timestamp-v1",
	rootPath:                 "trust/github-private/trusted_root.json",
	rootSHA256:               trustedRootSHA256,
	rootSize:                 trustedRootSize,
	rootFields:               []string{"mediaType", "certificateAuthorities", "timestampAuthorities"},
	stableExpectationsSchema: expectationsSchemaV2,
	visibility:               privateVisibility,
	issuerOrganization:       "GitHub, Inc.",
	verifierLabel:            "signed-timestamp-only",
	timestampType:            "TimestampAuthority",
	timestampLabel:           "RFC3161",
}

var publicTrustProfile = trustProfile{
	kind:                     "public",
	label:                    "Sigstore public-good",
	authorityLabel:           "Sigstore public-good",
	rootProfile:              "sigstore-public-good-rekor-v1",
	rootPath:                 "trust/sigstore-public-good/trusted_root.json",
	rootSHA256:               publicTrustedRootSHA256,
	rootSize:                 publicTrustedRootSize,
	rootFields:               []string{"mediaType", "tlogs", "ctlogs", "certificateAuthorities", "timestampAuthorities"},
	stableExpectationsSchema: expectationsSchemaPublicV1,
	visibility:               publicVisibility,
	issuerOrganization:       "sigstore.dev",
	verifierLabel:            "transparency-log",
	timestampType:            "Tlog",
	timestampLabel:           "transparency-log-integrated",
}

func (tp trustProfile) parseBundle(raw []byte) (rawBundleProfile, error) {
	if tp.kind == "public" {
		return parsePublicBundleProfile(raw)
	}
	return parsePrivateBundleProfile(raw)
}

// The public profile demands the transparency evidence the private profile
// forbids: a signed certificate timestamp in the leaf and exactly one dsse
// Rekor entry with both an inclusion promise and an inclusion proof. The
// timestamp source is the Rekor-integrated time, so the bundle's
// timestampVerificationData must be present and exactly empty.
func (tp trustProfile) verifierOptions() []verify.VerifierOption {
	if tp.kind == "public" {
		return []verify.VerifierOption{
			verify.WithTransparencyLog(1),
			verify.WithIntegratedTimestamps(1),
			verify.WithSignedCertificateTimestamps(1),
		}
	}
	return []verify.VerifierOption{verify.WithSignedTimestamps(1)}
}

func parsePublicBundleProfile(raw []byte) (rawBundleProfile, error) {
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
	if err := exactFields(material, "$.verificationMaterial", "certificate", "tlogEntries", "timestampVerificationData"); err != nil {
		return rawBundleProfile{}, err
	}
	leaf, err := parseBundleLeafCertificate(material)
	if err != nil {
		return rawBundleProfile{}, err
	}
	if !containsCTExtension(leaf) {
		return rawBundleProfile{}, fmt.Errorf("a signed certificate timestamp is required in the public-good profile")
	}

	if err := parsePublicTlogEntries(material); err != nil {
		return rawBundleProfile{}, err
	}

	// The verified timestamp comes from Rekor integration, not a TSA. The
	// bundle's timestampVerificationData must therefore carry no RFC3161
	// timestamp. Two equivalent empty spellings were measured from real
	// public-repository bundles: an empty object (`{}`, sigstore-go v1.2.2
	// GitHub CLI export) and an explicit empty array
	// (`{"rfc3161Timestamps": []}`, GitHub's expo/ibex hermes-artifacts
	// producer, 2026-07-23). Accept both; reject any other field and any
	// non-empty timestamp list — real TSA material is outside this profile.
	timestampData, err := objectAt(material["timestampVerificationData"], "$.verificationMaterial.timestampVerificationData")
	if err != nil {
		return rawBundleProfile{}, err
	}
	for key := range timestampData {
		if key != "rfc3161Timestamps" {
			return rawBundleProfile{}, fmt.Errorf(
				"$.verificationMaterial.timestampVerificationData has unexpected field %q", key)
		}
	}
	if raw, present := timestampData["rfc3161Timestamps"]; present {
		timestamps, err := arrayAt(raw, "$.verificationMaterial.timestampVerificationData.rfc3161Timestamps")
		if err != nil {
			return rawBundleProfile{}, err
		}
		if len(timestamps) != 0 {
			return rawBundleProfile{}, fmt.Errorf(
				"public-good profile rejects %d RFC3161 timestamp(s); the verified timestamp is Rekor-integrated", len(timestamps))
		}
	}

	statement, err := parseBundleStatement(rootObject)
	if err != nil {
		return rawBundleProfile{}, err
	}
	return rawBundleProfile{statement: statement, cert: leaf}, nil
}

func parsePublicTlogEntries(material map[string]any) error {
	entries, err := arrayAt(material["tlogEntries"], "$.verificationMaterial.tlogEntries")
	if err != nil {
		return err
	}
	if len(entries) != 1 {
		return fmt.Errorf("expected exactly one transparency-log entry, got %d", len(entries))
	}
	where := "$.verificationMaterial.tlogEntries[0]"
	entry, err := objectAt(entries[0], where)
	if err != nil {
		return err
	}
	if err := exactFields(entry, where, "logIndex", "logId", "kindVersion", "integratedTime", "inclusionPromise", "inclusionProof", "canonicalizedBody"); err != nil {
		return err
	}
	for _, field := range []string{"logIndex", "integratedTime"} {
		text, err := stringAt(entry[field], where+"."+field)
		if err != nil {
			return err
		}
		if err := requireCanonicalPositiveDecimal(field, text); err != nil {
			return err
		}
	}
	logID, err := objectAt(entry["logId"], where+".logId")
	if err != nil {
		return err
	}
	if err := exactFields(logID, where+".logId", "keyId"); err != nil {
		return err
	}
	if err := boundedBase64(logID["keyId"], where+".logId.keyId"); err != nil {
		return err
	}
	kindVersion, err := objectAt(entry["kindVersion"], where+".kindVersion")
	if err != nil {
		return err
	}
	if err := exactFields(kindVersion, where+".kindVersion", "kind", "version"); err != nil {
		return err
	}
	if err := exactString(kindVersion, "kind", "dsse", where+".kindVersion"); err != nil {
		return err
	}
	if err := exactString(kindVersion, "version", "0.0.1", where+".kindVersion"); err != nil {
		return err
	}
	promise, err := objectAt(entry["inclusionPromise"], where+".inclusionPromise")
	if err != nil {
		return err
	}
	if err := exactFields(promise, where+".inclusionPromise", "signedEntryTimestamp"); err != nil {
		return err
	}
	if err := boundedBase64(promise["signedEntryTimestamp"], where+".inclusionPromise.signedEntryTimestamp"); err != nil {
		return err
	}
	proof, err := objectAt(entry["inclusionProof"], where+".inclusionProof")
	if err != nil {
		return err
	}
	if err := exactFields(proof, where+".inclusionProof", "logIndex", "rootHash", "treeSize", "hashes", "checkpoint"); err != nil {
		return err
	}
	for _, field := range []string{"logIndex", "treeSize"} {
		text, err := stringAt(proof[field], where+".inclusionProof."+field)
		if err != nil {
			return err
		}
		if err := requireCanonicalPositiveDecimal(field, text); err != nil {
			return err
		}
	}
	if err := boundedBase64(proof["rootHash"], where+".inclusionProof.rootHash"); err != nil {
		return err
	}
	hashes, err := arrayAt(proof["hashes"], where+".inclusionProof.hashes")
	if err != nil {
		return err
	}
	if len(hashes) == 0 || len(hashes) > maximumTlogHashes {
		return fmt.Errorf("inclusion proof must contain 1..%d hashes, got %d", maximumTlogHashes, len(hashes))
	}
	for index, hash := range hashes {
		if err := boundedBase64(hash, fmt.Sprintf("%s.inclusionProof.hashes[%d]", where, index)); err != nil {
			return err
		}
	}
	checkpoint, err := objectAt(proof["checkpoint"], where+".inclusionProof.checkpoint")
	if err != nil {
		return err
	}
	if err := exactFields(checkpoint, where+".inclusionProof.checkpoint", "envelope"); err != nil {
		return err
	}
	envelope, err := stringAt(checkpoint["envelope"], where+".inclusionProof.checkpoint.envelope")
	if err != nil {
		return err
	}
	if envelope == "" || len(envelope) > maximumTlogFieldBytes {
		return fmt.Errorf("checkpoint envelope size must be 1..%d bytes", maximumTlogFieldBytes)
	}
	return boundedBase64(entry["canonicalizedBody"], where+".canonicalizedBody")
}

func boundedBase64(value any, where string) error {
	decoded, err := canonicalBase64(value, where)
	if err != nil {
		return err
	}
	if len(decoded) < 1 || len(decoded) > maximumTlogFieldBytes {
		return fmt.Errorf("%s size must be 1..%d bytes", where, maximumTlogFieldBytes)
	}
	return nil
}
