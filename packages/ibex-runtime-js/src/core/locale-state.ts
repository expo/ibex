// @system @ref LLP 0011#state-modules — startup imports only locale state.
import {
  canonicalizeLocaleTag,
  directionForLocaleTag,
  parseLocaleTag,
  type LocaleDirection,
} from './i18n-helpers.js';

export interface ExactLocaleSnapshot {
  readonly language: string;
  readonly region: string;
  readonly tag: string;
  readonly tags: readonly string[];
  readonly direction: LocaleDirection;
  readonly uses24Hour: boolean;
}

export interface NativeLocaleSnapshot {
  readonly tag?: string;
  readonly tags?: readonly string[];
  readonly uses24Hour?: boolean;
}

export interface ExactLocaleOverride {
  readonly locale?: string;
  readonly direction?: LocaleDirection;
}

export type ExactLocaleListener = (snapshot: ExactLocaleSnapshot) => void;

interface ExactLocaleRuntimeState {
  snapshot: ExactLocaleSnapshot;
  override: ExactLocaleOverride | null;
  listeners: Set<ExactLocaleListener>;
  changeTimer: ReturnType<typeof setTimeout> | null;
}

declare global {
  // eslint-disable-next-line no-var
  var __exactLocaleState: ExactLocaleRuntimeState | undefined;
  // eslint-disable-next-line no-var
  var __exactLocaleSnapshot: NativeLocaleSnapshot | undefined;
  // eslint-disable-next-line no-var
  var __exactLocaleChanged: ((snapshot?: NativeLocaleSnapshot | null) => void) | undefined;
}

function freezeSnapshot(snapshot: ExactLocaleSnapshot): ExactLocaleSnapshot {
  return Object.freeze({
    ...snapshot,
    tags: Object.freeze([...snapshot.tags]),
  });
}

export function readNativeLocaleSnapshot(): NativeLocaleSnapshot | null {
  const nativeSnapshot = globalThis.__exactLocaleSnapshot;
  if (nativeSnapshot && typeof nativeSnapshot === 'object') {
    return nativeSnapshot;
  }

  const g = globalThis as typeof globalThis & {
    __exactLocale?: unknown;
    __exactLanguage?: unknown;
    __exactHostNavigator?: {
      language?: unknown;
      languages?: unknown;
    };
  };

  const hostNavigator =
    g.__exactHostNavigator && typeof g.__exactHostNavigator === 'object'
      ? g.__exactHostNavigator
      : undefined;
  const hostLanguages = Array.isArray(hostNavigator?.languages)
    ? hostNavigator.languages.filter((entry): entry is string => typeof entry === 'string' && entry.length > 0)
    : [];
  const hostLanguage =
    typeof hostNavigator?.language === 'string' && hostNavigator.language.length > 0
      ? hostNavigator.language
      : undefined;

  const fallbackTag =
    typeof g.__exactLocale === 'string' && g.__exactLocale.length > 0
      ? g.__exactLocale
      : typeof g.__exactLanguage === 'string' && g.__exactLanguage.length > 0
        ? g.__exactLanguage
        : hostLanguage;

  if (!fallbackTag && hostLanguages.length === 0) {
    return null;
  }

  return {
    tag: fallbackTag,
    tags: hostLanguages,
  };
}

function detectUses24Hour(localeTag: string): boolean {
  if (typeof Intl !== 'object' || !Intl || typeof Intl.DateTimeFormat !== 'function') {
    return false;
  }

  try {
    const resolved = new Intl.DateTimeFormat(localeTag, { hour: 'numeric' }).resolvedOptions();
    if (typeof resolved.hour12 === 'boolean') {
      return resolved.hour12 === false;
    }
    if (typeof resolved.hourCycle === 'string') {
      return resolved.hourCycle === 'h23' || resolved.hourCycle === 'h24';
    }
  } catch {
    // Ignore Intl failures and fall back to 12-hour.
  }

  return false;
}

function buildLocaleSnapshot(
  nativeSnapshot: NativeLocaleSnapshot | null,
  override: ExactLocaleOverride | null,
): ExactLocaleSnapshot {
  const rawTags = Array.isArray(nativeSnapshot?.tags)
    ? nativeSnapshot.tags.filter((entry): entry is string => typeof entry === 'string' && entry.length > 0)
    : [];
  const primaryTag = canonicalizeLocaleTag(
    override?.locale ??
      nativeSnapshot?.tag ??
      rawTags[0] ??
      'en-US',
  );
  const tags =
    override?.locale != null
      ? [primaryTag]
      : rawTags.length > 0
        ? rawTags.map((tag) => canonicalizeLocaleTag(tag))
        : [primaryTag];
  const parsed = parseLocaleTag(primaryTag);
  const region = parsed.region ?? '';
  const uses24Hour =
    typeof nativeSnapshot?.uses24Hour === 'boolean'
      ? nativeSnapshot.uses24Hour
      : detectUses24Hour(primaryTag);

  return freezeSnapshot({
    language: parsed.language,
    region,
    tag: primaryTag,
    tags: Object.freeze(tags),
    direction: override?.direction ?? directionForLocaleTag(primaryTag),
    uses24Hour,
  });
}

function createDefaultState(): ExactLocaleRuntimeState {
  return {
    snapshot: buildLocaleSnapshot(readNativeLocaleSnapshot(), null),
    override: null,
    listeners: new Set(),
    changeTimer: null,
  };
}

function getLocaleState(): ExactLocaleRuntimeState {
  if (!globalThis.__exactLocaleState) {
    globalThis.__exactLocaleState = createDefaultState();
  }
  return globalThis.__exactLocaleState;
}

function dispatchLocaleChange(state: ExactLocaleRuntimeState): void {
  const snapshot = state.snapshot;
  for (const listener of state.listeners) {
    try {
      listener(snapshot);
    } catch {
      // Ignore listener failures.
    }
  }
}

function scheduleLocaleChange(state: ExactLocaleRuntimeState): void {
  if (state.changeTimer != null) {
    clearTimeout(state.changeTimer);
  }

  state.changeTimer = setTimeout(() => {
    state.changeTimer = null;
    dispatchLocaleChange(state);
  }, 100);
}

export function updateLocaleSnapshot(
  nativeSnapshot: NativeLocaleSnapshot | null,
  override: ExactLocaleOverride | null,
  notify: boolean,
): ExactLocaleSnapshot {
  const state = getLocaleState();
  const nextSnapshot = buildLocaleSnapshot(nativeSnapshot, override);
  const prevSnapshot = state.snapshot;
  state.snapshot = nextSnapshot;
  state.override = override;

  const changed =
    prevSnapshot.tag !== nextSnapshot.tag ||
    prevSnapshot.direction !== nextSnapshot.direction ||
    prevSnapshot.uses24Hour !== nextSnapshot.uses24Hour ||
    prevSnapshot.tags.length !== nextSnapshot.tags.length ||
    prevSnapshot.tags.some((tag, index) => tag !== nextSnapshot.tags[index]);

  if (notify && changed) {
    scheduleLocaleChange(state);
  }

  return nextSnapshot;
}

export function subscribeExactLocaleChanges(listener: ExactLocaleListener): () => void {
  const state = getLocaleState();
  state.listeners.add(listener);
  return () => {
    state.listeners.delete(listener);
  };
}

export function getExactLocaleSnapshot(): ExactLocaleSnapshot {
  return getLocaleState().snapshot;
}

export function getExactLocaleOverride(): ExactLocaleOverride | null {
  return getLocaleState().override;
}

export function refreshExactLocale(): ExactLocaleSnapshot {
  return updateLocaleSnapshot(readNativeLocaleSnapshot(), getLocaleState().override, true);
}

export function setExactLocaleOverride(override: ExactLocaleOverride | null): ExactLocaleSnapshot {
  return updateLocaleSnapshot(readNativeLocaleSnapshot(), override, true);
}

export function clearExactLocaleOverride(): ExactLocaleSnapshot {
  return setExactLocaleOverride(null);
}

export function _resetExactLocaleForTests(): void {
  const state = globalThis.__exactLocaleState;
  if (state?.changeTimer != null) {
    clearTimeout(state.changeTimer);
  }
  delete globalThis.__exactLocaleState;
  delete globalThis.__exactLocaleChanged;
  delete globalThis.__exactLocaleSnapshot;
}
