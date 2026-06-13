import {
  getExactLocaleOverride,
  getExactLocaleSnapshot,
  readNativeLocaleSnapshot,
  subscribeExactLocaleChanges,
  updateLocaleSnapshot,
  type ExactLocaleListener,
  type ExactLocaleSnapshot,
  type NativeLocaleSnapshot,
} from './locale-state.js';

export {
  _resetExactLocaleForTests,
  clearExactLocaleOverride,
  getExactLocaleSnapshot,
  refreshExactLocale,
  setExactLocaleOverride,
  subscribeExactLocaleChanges,
  type ExactLocaleSnapshot,
} from './locale-state.js';

interface ExactLocaleNamespace {
  readonly language: string;
  readonly region: string;
  readonly tag: string;
  readonly tags: readonly string[];
  readonly direction: ExactLocaleSnapshot['direction'];
  readonly uses24Hour: boolean;
  addListener(event: 'change', listener: ExactLocaleListener): () => void;
}

function createLocaleNamespace(): ExactLocaleNamespace {
  return {
    get language() {
      return getExactLocaleSnapshot().language;
    },
    get region() {
      return getExactLocaleSnapshot().region;
    },
    get tag() {
      return getExactLocaleSnapshot().tag;
    },
    get tags() {
      return getExactLocaleSnapshot().tags;
    },
    get direction() {
      return getExactLocaleSnapshot().direction;
    },
    get uses24Hour() {
      return getExactLocaleSnapshot().uses24Hour;
    },
    addListener(_event: 'change', listener: ExactLocaleListener): () => void {
      return subscribeExactLocaleChanges(listener);
    },
  };
}

export function installExactLocaleGlobal(): ExactLocaleNamespace {
  const g = globalThis as typeof globalThis & {
    Exact?: Record<string, unknown>;
  };

  if (typeof g.Exact !== 'object' || g.Exact === null) {
    g.Exact = {};
  }

  const exact = g.Exact as Record<string, unknown>;
  const existing = exact.locale;
  if (existing && typeof existing === 'object' && typeof (existing as ExactLocaleNamespace).addListener === 'function') {
    return existing as ExactLocaleNamespace;
  }

  updateLocaleSnapshot(readNativeLocaleSnapshot(), getExactLocaleOverride(), false);

  const locale = createLocaleNamespace();
  Object.defineProperty(exact, 'locale', {
    value: locale,
    writable: true,
    configurable: true,
    enumerable: true,
  });

  globalThis.__exactLocaleChanged = (snapshot?: NativeLocaleSnapshot | null) => {
    if (snapshot && typeof snapshot === 'object') {
      globalThis.__exactLocaleSnapshot = snapshot;
    }
    updateLocaleSnapshot(
      snapshot ?? readNativeLocaleSnapshot(),
      getExactLocaleOverride(),
      true,
    );
  };

  return locale;
}
