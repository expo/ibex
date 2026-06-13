export type AgentLogLevel = "debug" | "info" | "warn" | "error" | string;
export type AgentLogSource = "runtime" | "renderer" | "host" | "agent" | string;

export interface AgentLogEntry {
  entryId: string;
  timestamp: number;
  source: AgentLogSource;
  level: AgentLogLevel;
  message: string;
  stack?: string;
  componentStack?: string;
  context?: Record<string, unknown>;
  rootId?: number;
  snapshotId?: string;
  count: number;
  firstTimestamp: number;
  lastTimestamp: number;
}

const MAX_AGENT_LOG_ENTRIES = 1000;
const DEDUP_WINDOW_MS = 1000;

type AgentLogListener = (entry: AgentLogEntry) => void;

export interface AgentLogInput {
  source: AgentLogSource;
  level: AgentLogLevel;
  message: string;
  stack?: string;
  componentStack?: string;
  context?: Record<string, unknown>;
  rootId?: number;
  snapshotId?: string;
  timestamp?: number;
}

const entries: AgentLogEntry[] = [];
const listeners = new Set<AgentLogListener>();
let nextEntryId = 1;

function currentTimestamp(): number {
  return Date.now();
}

function cloneContext(
  context: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (!context) {
    return undefined;
  }
  return { ...context };
}

function canCollapse(
  previous: AgentLogEntry | undefined,
  next: AgentLogInput,
  timestamp: number,
): previous is AgentLogEntry {
  if (!previous) {
    return false;
  }

  if (timestamp - previous.lastTimestamp > DEDUP_WINDOW_MS) {
    return false;
  }

  return (
    previous.source === next.source &&
    previous.level === next.level &&
    previous.message === next.message &&
    previous.stack === next.stack &&
    previous.componentStack === next.componentStack &&
    previous.rootId === next.rootId
  );
}

export function recordAgentLog(
  input: AgentLogInput,
): { entry: AgentLogEntry; created: boolean } {
  const timestamp = input.timestamp ?? currentTimestamp();
  const previous = entries.length > 0 ? entries[entries.length - 1] : undefined;

  if (canCollapse(previous, input, timestamp)) {
    previous.count += 1;
    previous.lastTimestamp = timestamp;
    previous.timestamp = timestamp;
    if (input.snapshotId) {
      previous.snapshotId = input.snapshotId;
    }
    if (input.context) {
      previous.context = cloneContext(input.context);
    }
    return { entry: previous, created: false };
  }

  const entry: AgentLogEntry = {
    entryId: String(nextEntryId),
    timestamp,
    source: input.source,
    level: input.level,
    message: input.message,
    stack: input.stack,
    componentStack: input.componentStack,
    context: cloneContext(input.context),
    rootId: input.rootId,
    snapshotId: input.snapshotId,
    count: 1,
    firstTimestamp: timestamp,
    lastTimestamp: timestamp,
  };
  nextEntryId += 1;

  entries.push(entry);
  if (entries.length > MAX_AGENT_LOG_ENTRIES) {
    entries.shift();
  }

  for (const listener of listeners) {
    try {
      listener(entry);
    } catch (error) {
      console.error("[AgentLogs] listener failed:", error);
    }
  }

  return { entry, created: true };
}

export function getAgentLogEntries(): AgentLogEntry[] {
  return entries.slice();
}

export function subscribeAgentLogs(listener: AgentLogListener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function _resetAgentLogState(): void {
  entries.length = 0;
  listeners.clear();
  nextEntryId = 1;
}
