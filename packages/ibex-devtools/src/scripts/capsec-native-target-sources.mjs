/**
 * Native translation units that build.rs replaces with Windows-specific
 * implementations. Source discovery still scans these files so the complete
 * cross-target inventory remains visible, but a registration found only here
 * belongs to the POSIX-family branch and must not become a Windows fallback.
 *
 * @ref LLP 0001#current-buildrs-support-honest-status — exact-target evidence
 * intersects source-discovered registrations with the translation units that
 * build.rs selects for that target.
 */
export const WINDOWS_REPLACED_NATIVE_IMPLEMENTATION_SOURCES = Object.freeze([
  "src/engine/hermes_runtime_crypto.cc",
  "src/engine/hermes_runtime_debugger.cc",
  "src/engine/hermes_runtime_dns.cc",
  "src/engine/hermes_runtime_fs.cc",
  "src/engine/hermes_runtime_net.cc",
  "src/engine/hermes_runtime_osinfo.cc",
  "src/engine/hermes_runtime_process.cc",
  "src/engine/hermes_runtime_process_setup.cc",
]);

const windowsReplacedSources = new Set(
  WINDOWS_REPLACED_NATIVE_IMPLEMENTATION_SOURCES,
);

export function nativeImplementationSourceIsReplacedOnWindows(sourceRef) {
  const separator = sourceRef.indexOf("#");
  const sourcePath =
    separator === -1 ? sourceRef : sourceRef.slice(0, separator);
  return windowsReplacedSources.has(sourcePath);
}

// stream-enhance.js is installed by the default process-setup translation unit
// and by the non-Windows lazy-bootstrap path. The Windows process-setup
// replacement intentionally does not evaluate it; the shared runtime treats
// its signal/rejection hooks as optional inputs.
const POSIX_LEGACY_BOOTSTRAP_SOURCES = new Set([
  "src/engine/bootstrap/stream-enhance.js",
]);

export function legacyBootstrapTargetVariant(sourcePath) {
  return POSIX_LEGACY_BOOTSTRAP_SOURCES.has(sourcePath)
    ? "posix"
    : "default";
}
