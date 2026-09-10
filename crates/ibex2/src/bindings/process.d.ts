/** Host-installed capabilities. Type imports install nothing and grant nothing.
 * Native effects run with the host OS identity; executable grants are not a
 * child sandbox. No Node child_process, streams, events, or shell API. */
export interface Processes {
  spawn(command: ProcessCommand, signal?: ProcessAbortSignal): Promise<ChildProcess>;
  pty(command: ProcessCommand, size: PtySize, signal?: ProcessAbortSignal): Promise<PtyProcess>;
}
export interface ProcessCommand {
  /** Exact absolute native executable; no PATH search or implicit shell. */
  executable: string;
  args: readonly string[];
  cwd: string;
  /** Complete child environment, including TERM/PATH if wanted. */
  env: Readonly<Record<string, string>>;
}
/** A standard AbortSignal satisfies this structural interface. */
export interface ProcessAbortSignal {
  readonly aborted: boolean;
  readonly reason: unknown;
  addEventListener(type: "abort", listener: () => void, options?: { once?: boolean }): void;
  removeEventListener(type: "abort", listener: () => void): void;
}
export interface ProcessStatus { readonly code: number | null; readonly signal: number | null; readonly success: boolean }
export interface ProcessOutput {
  /** Demand-driven, 1..65536 bytes; null means EOF. One pending read per stream. */
  read(maxBytes?: number): Promise<Uint8Array | null>;
}
export interface ProcessInput {
  /** At most 65536 bytes. Resolves after all bytes are written. No queued writes. */
  write(bytes: ArrayBuffer | Uint8Array): Promise<void>;
}
export interface PipeInput extends ProcessInput { close(): Promise<void> }
export interface ProcessLifetime {
  readonly pid: number;
  /** Does not drain output. Consume stdout/stderr concurrently when necessary. */
  wait(): Promise<ProcessStatus>;
  cancel(): Promise<ProcessStatus>;
  /** Idempotent cancellation and descriptor cleanup, including after wait. */
  close(): Promise<ProcessStatus>;
}
export interface ChildProcess extends ProcessLifetime {
  readonly stdin: PipeInput;
  readonly stdout: ProcessOutput;
  readonly stderr: ProcessOutput;
}
export interface PtySize { rows: number; cols: number }
export interface PtyProcess extends ProcessLifetime {
  readonly input: ProcessInput;
  readonly output: ProcessOutput;
  resize(size: PtySize): Promise<void>;
}
