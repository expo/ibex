import { describe, expect, test } from "bun:test";

import { canonicalJson } from "./capsec-contract.mjs";
import {
  validateRestrictedObserverTranscriptPair,
} from "./run-restricted-exact-observer-equivalence.mjs";
import { taggedDigest } from "./restricted-exact-target-report.mjs";

const testName = "host::embedder_artifacts::tests::restricted_exact_observer_build_equivalence_transcript";
const fields = [
  "descriptorSnapshot",
  "checkpointBytes",
  "eventAndPollResults",
  "callbackTranscript",
  "poisonState",
  "teardownResult",
];

function transcript() {
  return {
    schema: "ibex/restricted-exact-observer-equivalence-transcript/1",
    descriptorSnapshot: [1, 0, 1],
    checkpointBytes: [161, 1],
    eventAndPollResults: { stableEvent: 0, poll: 1 },
    callbackTranscript: { operationId: 1000, dispatchBytes: [193, 1] },
    poisonState: { staleEvent: -1, poll: -1 },
    teardownResult: { destroyReturned: true, successorRun: 0 },
  };
}

function build(label, observerEnabled, value) {
  const raw = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
  const command = ["cargo", "test", "-p", "ibex-runtime", "--lib", "--release"];
  if (observerEnabled) command.push("--features", "capsec-conformance-observer");
  command.push("--no-run", "--message-format=json");
  return {
    label,
    observerEnabled,
    featureSet: observerEnabled ? ["capsec-conformance-observer"] : [],
    buildCommand: command,
    executeCommand: [
      "<compiled-rust-test-binary>",
      testName,
      "--exact",
      "--nocapture",
      "--test-threads=1",
    ],
    testBinaryDigest: `sha256-${"A".repeat(43)}`,
    transcriptRawBase64: raw.toString("base64"),
    transcriptRawContentDigest: taggedDigest(raw),
    transcriptCanonicalDigest: taggedDigest(Buffer.from(canonicalJson(value), "utf8")),
    transcript: value,
    exitCode: 0,
    resultMarker: `ibex-restricted-observer-equivalence:passed:${label}`,
  };
}

function fixture() {
  const disabledTranscript = transcript();
  const enabledTranscript = structuredClone(disabledTranscript);
  const builds = [
    build("observer-disabled", false, disabledTranscript),
    build("observer-enabled", true, enabledTranscript),
  ];
  return {
    builds,
    comparison: {
      fields,
      rawBytesEqual: true,
      canonicalEqual: true,
      canonicalTranscriptDigest: builds[0].transcriptCanonicalDigest,
    },
  };
}

describe("LLP 0033 restricted observer non-interference", () => {
  test("accepts only the exact two-build production transcript pair", () => {
    expect(() => validateRestrictedObserverTranscriptPair(fixture())).not.toThrow();
  });

  test("rejects feature confusion, field omission, and a real behavioral difference", () => {
    const confused = fixture();
    confused.builds[1].featureSet = [];
    expect(() => validateRestrictedObserverTranscriptPair(confused)).toThrow("build drift");

    const omitted = fixture();
    delete omitted.builds[0].transcript.poisonState;
    expect(() => validateRestrictedObserverTranscriptPair(omitted)).toThrow();

    const divergent = fixture();
    divergent.builds[1] = build(
      "observer-enabled",
      true,
      {
        ...divergent.builds[1].transcript,
        poisonState: { staleEvent: 0, poll: 0 },
      },
    );
    expect(() => validateRestrictedObserverTranscriptPair(divergent)).toThrow(
      "transcripts differ",
    );
  });
});
