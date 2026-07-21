import path from "node:path";

/**
 * Serialize a filesystem-relative path as a host-independent identity.
 * Native paths remain authoritative for I/O; persisted provenance always uses
 * `/` so one source tree produces one policy on every host.
 */
export function portableRelativePath(from, to, pathApi = path) {
  return pathApi.relative(from, to).split(pathApi.sep).join("/");
}
