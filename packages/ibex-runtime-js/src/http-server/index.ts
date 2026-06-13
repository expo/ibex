/**
 * `exact:http` runtime surface for JS adapters and examples.
 *
 * The canonical runtime implementation is provided from Rust module loader via
 * `exact:http`, and this file exposes the same API contract for
 * TypeScript-aware consumers.
 */

import { serve as runtimeServe } from './index.js';

export type ServeHandle = {
  close: (opts?: { force?: boolean }) => Promise<void>;
  ref: () => void;
  unref: () => void;
  address: () => { port: number; family: string; address: string } | string | null;
};

export type ServeOptions = {
  fetch: (request: Request) => Promise<Response> | Response;
  port?: number;
  hostname?: string;
};

// Bun resolves this workspace package through the TypeScript facade during
// development, so the facade must forward the live implementation instead of
// only carrying types.
export const serve: (options: ServeOptions) => Promise<ServeHandle> = runtimeServe;
