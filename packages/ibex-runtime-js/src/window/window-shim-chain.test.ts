// ENG-22805 — a second copy of the window module can evaluate in the same
// runtime (the embedded runtime bundle boots one; a bundled agent/app
// bootstrap evaluates another). The host notify hooks it installs at module
// eval must CHAIN to any previously installed hook instead of clobbering it:
// each copy owns its own mediaQueryLists registry while `globalThis.matchMedia`
// stays bound to the first copy, so a clobbered hook leaves the first copy's
// matchMedia listeners permanently deaf to host appearance/resize
// notifications (root cause of ENG-22789). Run with: bun test.

import { expect, test } from 'bun:test';

test('host notify hooks chain across repeat module evaluation', async () => {
  const g = globalThis as Record<string, any>;

  // A hook installed before any runtime copy evaluates (a host seam).
  const preexisting: string[] = [];
  g.__exactWindowNotifyMediaChange = (next: { colorScheme?: string }) => {
    preexisting.push(`media:${next?.colorScheme}`);
  };
  g.__exactWindowNotifyResize = () => {
    preexisting.push('resize');
  };
  g.__exactAndroidDispatchPlatformEvent = () => {
    preexisting.push('android');
  };
  g.__exactAppearanceState = { colorScheme: 'light' };

  // Two distinct evaluations of the same module in one runtime (distinct
  // query strings are distinct module instances).
  const copy1 = await import('./index.ts?eng22805=1');
  const copy2 = await import('./index.ts?eng22805=2');
  expect(copy1).not.toBe(copy2);

  // One MediaQueryList registered in each copy's module-local registry.
  const mql1 = copy1.window.matchMedia('(prefers-color-scheme: dark)');
  const mql2 = copy2.window.matchMedia('(prefers-color-scheme: dark)');
  expect(mql1.matches).toBe(false);
  expect(mql2.matches).toBe(false);

  const changes: string[] = [];
  mql1.addEventListener('change', () => changes.push('copy1'));
  mql2.addEventListener('change', () => changes.push('copy2'));

  // The host notifies once through the single global hook.
  g.__exactWindowNotifyMediaChange({ colorScheme: 'dark' });

  // Both copies' registries observed it (pre-fix, the first copy stayed
  // permanently deaf), and the pre-existing host hook still fired.
  expect(mql1.matches).toBe(true);
  expect(mql2.matches).toBe(true);
  expect(changes.sort()).toEqual(['copy1', 'copy2']);
  expect(preexisting).toContain('media:dark');

  // Resize and the Android platform-event hook chain the same way.
  g.__exactWindowNotifyResize();
  expect(preexisting).toContain('resize');
  g.__exactAndroidDispatchPlatformEvent('appearance', null);
  expect(preexisting).toContain('android');
});
