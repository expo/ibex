// ENG-22979 — regression tests for the react-native compatibility shim:
//   5. Dimensions.get() must reflect host-pushed dimension payloads so the
//      getter and the change listeners agree.
//   6. Linking.openURL() (outbound open) must NOT emit the app's incoming
//      deep-link 'url' event.
// Each test imports a fresh module copy via a unique query string. The module
// installs its host hooks on globalThis at eval, so the last-imported copy owns
// them — which is the copy under test here.
// Run with: bun test.

import { expect, test } from 'bun:test';

test('Dimensions.get reflects host-pushed dimensions and agrees with listeners (ENG-22979)', async () => {
  const g = globalThis as Record<string, unknown>;
  g.__exactGetScreenInfo = () => ({ width: 400, height: 800, scale: 2, fontScale: 1 });

  const rn = await import('./index.ts?eng22979-dims');

  // Before any push, the getter mirrors the live native screen info.
  expect(rn.Dimensions.get('window').width).toBe(400);

  const received: Array<{ window: { width: number } }> = [];
  const sub = rn.Dimensions.addEventListener('change', (payload) => {
    received.push(payload as { window: { width: number } });
  });

  // Host pushes a new window size (the native screen info is left unchanged).
  (g.__exactReactNativeNotifyDimensionsChange as (next: unknown) => void)({
    window: { width: 800, height: 1200, scale: 3, fontScale: 1 },
    screen: { width: 800, height: 1200, scale: 3, fontScale: 1 },
  });

  const got = rn.Dimensions.get('window');
  expect(got.width).toBe(800);
  expect(got.height).toBe(1200);

  // The getter and the change listener report the same value (pre-fix the
  // getter kept returning the stale 400 while the listener saw 800).
  expect(received.at(-1)?.window.width).toBe(800);
  sub.remove();
});

test('Linking.openURL does not emit the incoming url event, but host notifications still do (ENG-22979)', async () => {
  const g = globalThis as Record<string, unknown>;
  delete g.__exactOpenURL; // exercise the fallback open path

  const rn = await import('./index.ts?eng22979-open');

  const events: string[] = [];
  const sub = rn.Linking.addEventListener('url', (event) => events.push(event.url));

  // Outbound open of an external URL must NOT fire the app's deep-link event.
  await rn.Linking.openURL('https://example.com/page');
  expect(events).toEqual([]);

  // A genuine incoming link delivered by the host still fires it exactly once.
  (g.__exactReactNativeNotifyURL as (url: string) => void)('exact://app/incoming');
  expect(events).toEqual(['exact://app/incoming']);
  sub.remove();
});
