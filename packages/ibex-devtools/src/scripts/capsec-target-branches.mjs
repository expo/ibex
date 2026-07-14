/**
 * Normalize source-derived implementation branch labels and select the exact
 * branch set that can execute on a target cell.
 *
 * Branch selection is inventory evidence, not conformance evidence. A target
 * cell still remains unsupported until every selected branch obligation has an
 * executed result. Keeping this logic shared by generation and validation
 * prevents a free-form implementation reference from promoting the wrong
 * backend.
 *
 * @ref LLP 0021#generated-semantic-datasets — backend/target cells join exact
 * source-derived implementation branches before fixtures can promote them.
 */

const OPERATING_SYSTEM_VARIANTS = new Set([
  "android",
  "ios",
  "linux",
  "macos",
  "windows",
]);
const OPERATING_SYSTEM_FAMILIES = new Set(["apple", "posix"]);
const RUNTIME_VARIANTS = new Set(["binary", "worklet"]);

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalStringSet(values) {
  return [...new Set(values)].sort(compareText);
}

export function targetOperatingSystem(target) {
  const triple = target?.triple;
  if (typeof triple !== "string") {
    throw new Error("target branch selection requires a target triple");
  }
  if (/^[a-z0-9_]+-linux-android(?:eabi)?[0-9]*$/u.test(triple)) {
    return "android";
  }
  if (/^[a-z0-9_]+-apple-ios(?:-[a-z0-9_]+)?$/u.test(triple)) return "ios";
  if (/^[a-z0-9_]+-apple-darwin$/u.test(triple)) return "macos";
  if (/^[a-z0-9_]+-(?:pc|uwp)-windows-(?:gnu|gnullvm|msvc)$/u.test(triple)) {
    return "windows";
  }
  if (/^[a-z0-9_]+-(?:unknown-)?linux-[a-z0-9_]+$/u.test(triple)) {
    return "linux";
  }
  throw new Error(`unsupported target triple for branch selection ${triple}`);
}

export function targetApplicabilityForVariant(targetVariant) {
  if (targetVariant === "all") return { kind: "all" };
  if (targetVariant === "default") return { kind: "fallback" };
  if (OPERATING_SYSTEM_VARIANTS.has(targetVariant)) {
    return { kind: "operating-system", value: targetVariant };
  }
  if (OPERATING_SYSTEM_FAMILIES.has(targetVariant)) {
    return { kind: "operating-system-family", value: targetVariant };
  }
  if (RUNTIME_VARIANTS.has(targetVariant)) {
    return { kind: "runtime-variant", value: targetVariant };
  }
  if (/^conditional:[A-Z][A-Z0-9_]*$/u.test(targetVariant)) {
    return {
      kind: "build-condition",
      value: targetVariant.slice("conditional:".length),
    };
  }
  if (/^linux:[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(targetVariant)) {
    return {
      kind: "linux-backend",
      value: targetVariant.slice("linux:".length),
    };
  }
  throw new Error(
    `unreviewed implementation target variant ${JSON.stringify(targetVariant)}`,
  );
}

function sameApplicability(left, right) {
  return left?.kind === right?.kind && left?.value === right?.value;
}

function familyMatchesOperatingSystem(family, operatingSystem) {
  if (family === "apple") {
    return operatingSystem === "ios" || operatingSystem === "macos";
  }
  if (family === "posix") {
    return operatingSystem !== "windows";
  }
  return false;
}

/**
 * Select every implementation branch that may execute for this exact target.
 * Platform-specific branches take precedence over family and fallback rows;
 * universal, build-condition, and runtime-variant branches remain explicit so
 * a conformance run cannot prove only one reachable configuration by accident.
 */
export function applicableImplementationBranchIds(rows, target) {
  if (!Array.isArray(rows) || rows.length === 0) return [];
  const operatingSystem = targetOperatingSystem(target);
  const always = [];
  const exact = [];
  const family = [];
  const fallback = [];

  for (const row of rows) {
    if (typeof row?.branchId !== "string") {
      throw new Error("implementation branch selection requires branchId");
    }
    const expected = targetApplicabilityForVariant(row.targetVariant);
    if (!sameApplicability(row.targetApplicability, expected)) {
      throw new Error(
        `${row.branchId}: target applicability disagrees with target variant ${row.targetVariant}`,
      );
    }
    switch (expected.kind) {
      case "all":
      case "build-condition":
      case "runtime-variant":
        always.push(row.branchId);
        break;
      case "operating-system":
        if (expected.value === operatingSystem) exact.push(row.branchId);
        break;
      case "linux-backend":
        if (operatingSystem === "linux") exact.push(row.branchId);
        break;
      case "operating-system-family":
        if (familyMatchesOperatingSystem(expected.value, operatingSystem)) {
          family.push({ branchId: row.branchId, family: expected.value });
        }
        break;
      case "fallback":
        fallback.push(row.branchId);
        break;
      default:
        throw new Error(
          `${row.branchId}: unsupported target applicability ${expected.kind}`,
        );
    }
  }

  let selectedPlatform = exact;
  if (selectedPlatform.length === 0) {
    const preferredFamilies =
      operatingSystem === "ios" || operatingSystem === "macos"
        ? ["apple", "posix"]
        : operatingSystem === "windows"
          ? []
          : ["posix"];
    for (const preferredFamily of preferredFamilies) {
      selectedPlatform = family
        .filter((row) => row.family === preferredFamily)
        .map((row) => row.branchId);
      if (selectedPlatform.length > 0) break;
    }
  }
  if (selectedPlatform.length === 0) selectedPlatform = fallback;

  return canonicalStringSet([...always, ...selectedPlatform]);
}
