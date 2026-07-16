/**
 * Private pre-bootstrap host inputs shared by compatibility modules.
 *
 * @ref LLP 0023#6-path-bearing-observables — the original host navigator is
 * consumed through typed APIs; it must not be copied onto a package-readable
 * root global with an open, host-dependent member domain.
 */

let hostNavigatorInput: object | undefined;

type BootstrapCompatibilityControl = Readonly<{
  bun: boolean;
  fixture: boolean;
  fixtureBun: boolean;
  fixed: boolean;
}>;

const BOOTSTRAP_COMPATIBILITY_ENVIRONMENT_NAMES = new Set([
  "EXACT_COMPAT_BUN",
  "EXACT_COMPAT_TEST",
  "EXACT_TEST_SECTION",
]);

const bootstrapCompatibilityControl: BootstrapCompatibilityControl = (() => {
  // __exactSetEnv is the native armed-runtime marker. Once it is present,
  // absence or corruption of the carrier is an authenticated false value,
  // never permission to fall back to the mutable principal environment.
  const fixed =
    typeof (globalThis as { __exactSetEnv?: unknown }).__exactSetEnv ===
    "function";
  const disabled = Object.freeze({
    bun: false,
    fixture: false,
    fixtureBun: false,
    fixed,
  });
  try {
    const value = (globalThis as { __exactCompatModes?: unknown })
      .__exactCompatModes;
    if (!Array.isArray(value)) return disabled;

    const supported = new Set(["bun", "fixture", "fixture:bun"]);
    const modes = new Set<string>();
    for (const mode of value) {
      if (typeof mode !== "string" || !supported.has(mode) || modes.has(mode)) {
        return Object.freeze({ ...disabled, fixed });
      }
      modes.add(mode);
    }
    if (modes.has("fixture:bun") && !modes.has("fixture")) {
      return Object.freeze({ ...disabled, fixed });
    }

    return Object.freeze({
      bun: modes.has("bun"),
      fixture: modes.has("fixture"),
      fixtureBun: modes.has("fixture:bun"),
      fixed,
    });
  } catch {
    return disabled;
  }
})();

export function captureHostNavigatorInput(value: unknown): void {
  if (
    hostNavigatorInput === undefined &&
    value !== null &&
    typeof value === "object"
  ) {
    hostNavigatorInput = value;
  }
}

export function getHostNavigatorInput(): object | undefined {
  return hostNavigatorInput;
}

/**
 * Read one of the fixed, digest-bound bootstrap compatibility controls after
 * the temporary root-global carrier has been sealed. This intentionally does
 * not expose an open environment map to package code.
 */
export function readBootstrapCompatibilityControl(
  key: string,
): string | undefined {
  if (key === "EXACT_COMPAT_BUN" && bootstrapCompatibilityControl.bun)
    return "1";
  if (key === "EXACT_COMPAT_TEST" && bootstrapCompatibilityControl.fixture)
    return "1";
  if (key === "EXACT_TEST_SECTION" && bootstrapCompatibilityControl.fixtureBun)
    return "bun";
  return undefined;
}

/**
 * Whether an absent compatibility value is an authenticated false value.
 * Armed callers must not fall through to a mutable principal environment for
 * these three names; unarmed compatibility runtimes retain that legacy path.
 */
export function isBootstrapCompatibilityControlFixed(key: string): boolean {
  return (
    bootstrapCompatibilityControl.fixed &&
    BOOTSTRAP_COMPATIBILITY_ENVIRONMENT_NAMES.has(key)
  );
}
