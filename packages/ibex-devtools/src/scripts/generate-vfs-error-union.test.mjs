import { describe, expect, test } from "bun:test";
import {
  assertLanguageConsumers,
  buildPairwiseCorpus,
  validateVfsErrorUnion,
} from "./generate-vfs-error-union.mjs";

const reasons = [
  ["stale-session", "StaleSession", "STALE_SESSION", 2, 0],
  ["closed-operation", "ClosedOperation", "CLOSED_OPERATION", 1, 1],
  ["policy-denied", "PolicyDenied", "POLICY_DENIED", 7, 2],
].map(([id, rustVariant, suffix, discriminant, precedence]) => ({
  id,
  rustVariant,
  cConstant: `EX_HOST_VFS_RESULT_${suffix}`,
  discriminant,
  precedence,
  code: suffix,
  phase: "test",
}));

function fixture() {
  return {
    schema: "ibex/llp0023-vfs-error-union/1",
    abiVersion: 1,
    reasons: structuredClone(reasons),
    perStageRule: ["containment", "authorization", "existence"],
  };
}

function languageConsumers(union, { extraRustReason = false } = {}) {
  const rustConstants = [
    "pub const EX_HOST_VFS_RESULT_OK: u32 = 0;",
    ...union.reasons.map(
      (reason) =>
        `pub const ${reason.cConstant}: u32 = ${reason.discriminant};`,
    ),
  ].join("\n");
  const extraVariant = extraRustReason ? "    ExtraReason,\n" : "";
  const extraDiscriminant = extraRustReason
    ? `        crate::vfs::VfsReason::ExtraReason => ${union.reasons[0].cConstant},\n`
    : "";
  const extraPrecedence = extraRustReason
    ? "            VfsReason::ExtraReason => 0,\n"
    : "";
  const extraCode = extraRustReason
    ? `            VfsReason::ExtraReason => "${union.reasons[0].code}",\n`
    : "";
  return {
    rust: `${rustConstants}\nfn vfs_reason_discriminant(reason: crate::vfs::VfsReason) -> u32 {\n    match reason {\n${union.reasons
      .map(
        (reason) =>
          `        crate::vfs::VfsReason::${reason.rustVariant} => ${reason.cConstant},`,
      )
      .join("\n")}\n${extraDiscriminant}    }\n}\n`,
    header: `enum {\n  EX_HOST_VFS_RESULT_OK = 0,\n${union.reasons
      .map(
        (reason) => `  ${reason.cConstant} = ${reason.discriminant},`,
      )
      .join("\n")}\n};\n`,
    vfs: `pub enum VfsReason {\n${union.reasons
      .map((reason) => `    ${reason.rustVariant},`)
      .join("\n")}\n${extraVariant}}\nimpl VfsReason {\n    fn precedence(self) -> u8 {\n        match self {\n${union.reasons
      .map(
        (reason) =>
          `            VfsReason::${reason.rustVariant} => ${reason.precedence},`,
      )
      .join("\n")}\n${extraPrecedence}        }\n    }\n    fn code(self) -> &'static str {\n        match self {\n${union.reasons
      .map(
        (reason) =>
          `            VfsReason::${reason.rustVariant} => "${reason.code}",`,
      )
      .join("\n")}\n${extraCode}        }\n    }\n}\n`,
    posixFs: union.reasons
      .map(
        (reason) =>
          `case ${reason.cConstant}: return {"${reason.code}", "test"};`,
      )
      .join("\n"),
  };
}

describe("LLP 0023 VFS error union", () => {
  test("generates every unordered precedence pair", () => {
    const value = validateVfsErrorUnion(fixture());
    const corpus = buildPairwiseCorpus(value, JSON.stringify(value));
    expect(corpus.reasonCount).toBe(3);
    expect(corpus.pairCount).toBe(3);
    expect(corpus.pairs.map((pair) => pair.id)).toEqual([
      "stale-session-before-closed-operation",
      "stale-session-before-policy-denied",
      "closed-operation-before-policy-denied",
    ]);
  });

  test("a new reason requires its own unique order", () => {
    const value = fixture();
    value.reasons.push({
      ...value.reasons[2],
      id: "new-reason",
      rustVariant: "NewReason",
      cConstant: "EX_HOST_VFS_RESULT_NEW_REASON",
      discriminant: 99,
    });
    expect(() => validateVfsErrorUnion(value)).toThrow("VFS precedence ranks must be unique");
  });

  test("stale session is always tier zero", () => {
    const value = fixture();
    value.reasons[0].precedence = 1;
    value.reasons[1].precedence = 0;
    expect(() => validateVfsErrorUnion(value)).toThrow(
      "stale-session must precede every path/operation reason",
    );
  });

  test("rejects a Rust-only reason even when it reuses an existing projection", () => {
    const value = validateVfsErrorUnion(fixture());
    expect(() =>
      assertLanguageConsumers(
        value,
        languageConsumers(value, { extraRustReason: true }),
      ),
    ).toThrow(/VfsReason variants.*extra=\["ExtraReason"\]/u);
  });

  test("accepts consumers whose reason sets and projections are exact", () => {
    const value = validateVfsErrorUnion(fixture());
    expect(() =>
      assertLanguageConsumers(value, languageConsumers(value)),
    ).not.toThrow();
  });
});
