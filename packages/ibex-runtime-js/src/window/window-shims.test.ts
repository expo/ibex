// ENG-22979 — regression tests for the web `window` compatibility shim:
//   1. matchMedia() must not leak MediaQueryList instances forever.
//   2. A platform event carrying both accessibility and appearance must keep
//      the explicit appearance (not revert it to the accessibility default).
//   3. Compound / list / negated media queries must evaluate every condition.
//   4. location.assign/replace must resolve relative URLs.
// Each test imports a fresh module copy via a unique query string so the
// module-local singletons (mediaQueryLists registry, location) start clean.
// Run with: bun test.

import { expect, test } from 'bun:test';

function setScreen(width: number, height: number): void {
  (globalThis as Record<string, unknown>).__exactGetScreenInfo = () => ({
    width,
    height,
    scale: 2,
    fontScale: 1,
  });
}

test('matchMedia does not strongly retain dropped MediaQueryList instances (ENG-22979)', async () => {
  const mod = await import('./index.ts?eng22979-leak');
  setScreen(400, 800);

  // Create a MediaQueryList and immediately drop the test's only strong
  // reference. If the module registry held it strongly, it could never be
  // collected and the WeakRef below would keep deref()-ing to the instance.
  let mql: unknown = mod.window.matchMedia('(prefers-color-scheme: dark)');
  const ref = new WeakRef(mql as object);
  mql = null;

  // JSC clears WeakRefs only after the current job; yield, then force GC.
  let collected = false;
  for (let i = 0; i < 20 && !collected; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
    (Bun as unknown as { gc: (sync: boolean) => void }).gc(true);
    collected = ref.deref() === undefined;
  }
  expect(collected).toBe(true);
});

test('compound / list / negated media queries evaluate all conditions (ENG-22979)', async () => {
  const mod = await import('./index.ts?eng22979-media');
  const { window } = mod;

  // A desktop-width window must NOT match a tablet-only band. Pre-fix this
  // returned the min-width result and never checked max-width.
  setScreen(1440, 900);
  expect(window.matchMedia('(min-width: 768px) and (max-width: 1024px)').matches).toBe(false);

  // A tablet-width window matches the same band.
  setScreen(800, 1200);
  expect(window.matchMedia('(min-width: 768px) and (max-width: 1024px)').matches).toBe(true);

  // Comma-separated lists are a union (logical OR).
  setScreen(1440, 900);
  expect(window.matchMedia('(max-width: 600px), (min-width: 1200px)').matches).toBe(true);
  setScreen(900, 900);
  expect(window.matchMedia('(max-width: 600px), (min-width: 1200px)').matches).toBe(false);

  // `not` negates, `only` is a no-op modifier, bare media types are honored.
  setScreen(1440, 900);
  expect(window.matchMedia('not (max-width: 600px)').matches).toBe(true);
  expect(window.matchMedia('only screen and (min-width: 768px)').matches).toBe(true);
  expect(window.matchMedia('screen').matches).toBe(true);
  expect(window.matchMedia('print').matches).toBe(false);
});

test('platform event with both accessibility and appearance keeps appearance (ENG-22979)', async () => {
  const g = globalThis as Record<string, unknown>;
  setScreen(400, 800);

  // Establish a known light baseline (sibling tests share this process and may
  // have left the global dark).
  g.__exactAppearanceState = { colorScheme: 'light', reducedMotion: false };

  // Mimic the real accessibility handler: it mirrors its own colorScheme into
  // __exactAppearanceState, defaulting to 'light' when the record omits one.
  g.__exactAccessibilityChanged = (snapshot: { colorScheme?: string } | null) => {
    const colorScheme = snapshot?.colorScheme === 'dark' ? 'dark' : 'light';
    g.__exactAppearanceState = { colorScheme, reducedMotion: false };
  };

  const mod = await import('./index.ts?eng22979-a11y');
  const dark = mod.window.matchMedia('(prefers-color-scheme: dark)');
  expect(dark.matches).toBe(false);

  // A single platform event carries BOTH an accessibility record (no
  // colorScheme -> defaults light) and an explicit dark appearance. The
  // explicit appearance must win instead of being dropped.
  (g.__exactAndroidDispatchPlatformEvent as (e: unknown, s: unknown) => void)(
    { type: 'configuration' },
    { accessibility: { isBoldTextEnabled: true }, appearance: { colorScheme: 'dark' } },
  );

  expect(dark.matches).toBe(true);
  expect((g.__exactAppearanceState as { colorScheme?: string }).colorScheme).toBe('dark');

  delete g.__exactAccessibilityChanged;
});

test('location.assign/replace resolve relative and absolute URLs (ENG-22979)', async () => {
  const mod = await import('./index.ts?eng22979-loc');
  const { location } = mod.window;

  // A root-relative path must update pathname AND search, not just href.
  location.assign('/profile?tab=2');
  expect(location.href).toBe('exact://app/profile?tab=2');
  expect(location.pathname).toBe('/profile');
  expect(location.search).toBe('?tab=2');

  // An absolute URL replaces the current location wholesale.
  location.replace('https://example.com/x?y=1#frag');
  expect(location.protocol).toBe('https:');
  expect(location.hostname).toBe('example.com');
  expect(location.pathname).toBe('/x');
  expect(location.search).toBe('?y=1');
  expect(location.hash).toBe('#frag');
});

// ENG-23140 — an MQL with an active 'change' listener must be kept alive (HTML
// spec) even when the app drops its own reference; ENG-22979's WeakRef fix
// over-collected these, so dark-mode/resize reactions silently died after GC.
test('an MQL with an active change listener survives GC and keeps firing (ENG-23140)', async () => {
  const g = globalThis as Record<string, unknown>;
  setScreen(400, 800);
  g.__exactAppearanceState = { colorScheme: 'light', reducedMotion: false };
  const mod = await import('./index.ts?eng23140-retain');

  let fired = 0;
  const onChange = () => {
    fired += 1;
  };
  let mql: unknown = mod.window.matchMedia('(prefers-color-scheme: dark)');
  const ref = new WeakRef(mql as object);
  (mql as { addEventListener: (t: string, f: () => void) => void }).addEventListener(
    'change',
    onChange,
  );
  mql = null;

  for (let i = 0; i < 10; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
    (Bun as unknown as { gc: (sync: boolean) => void }).gc(true);
  }
  // Still alive: the change listener pins it.
  expect(ref.deref()).toBeDefined();

  (g.__exactAndroidDispatchPlatformEvent as (e: unknown, s: unknown) => void)(
    { type: 'configuration' },
    { appearance: { colorScheme: 'dark' } },
  );
  expect(fired).toBe(1);

  // Removing the last listener drops the strong retention: collectable again
  // (preserves ENG-22979's leak fix for listener-less MQLs).
  let alive: unknown = ref.deref();
  (alive as { removeEventListener: (t: string, f: () => void) => void }).removeEventListener(
    'change',
    onChange,
  );
  alive = null;
  let collected = false;
  for (let i = 0; i < 20 && !collected; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
    (Bun as unknown as { gc: (sync: boolean) => void }).gc(true);
    collected = ref.deref() === undefined;
  }
  expect(collected).toBe(true);
});

test('an onchange handler also retains the MQL across GC (ENG-23140)', async () => {
  const g = globalThis as Record<string, unknown>;
  setScreen(400, 800);
  g.__exactAppearanceState = { colorScheme: 'light', reducedMotion: false };
  const mod = await import('./index.ts?eng23140-onchange');

  let fired = 0;
  let mql: unknown = mod.window.matchMedia('(prefers-color-scheme: dark)');
  const ref = new WeakRef(mql as object);
  (mql as { onchange: (() => void) | null }).onchange = () => {
    fired += 1;
  };
  mql = null;

  for (let i = 0; i < 10; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
    (Bun as unknown as { gc: (sync: boolean) => void }).gc(true);
  }
  expect(ref.deref()).toBeDefined();

  (g.__exactAndroidDispatchPlatformEvent as (e: unknown, s: unknown) => void)(
    { type: 'configuration' },
    { appearance: { colorScheme: 'dark' } },
  );
  expect(fired).toBe(1);
});
