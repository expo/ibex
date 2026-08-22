// Host-monotonic second rAF argument (Exact LLP 0488 W4 native evidence).
// Run with: bun test packages/ibex-runtime-js/src/scheduling/animation-frame-host-monotonic.test.ts
import { afterEach, describe, expect, test } from 'bun:test';

import { setNativeSchedulingModule } from '../native/NativeModules';
import { requestAnimationFrame } from './AnimationFrame';

afterEach(() => {
  setNativeSchedulingModule(null as never);
});

describe('requestAnimationFrame host-monotonic timestamp', () => {
  test('forwards the host stamp as the second callback argument', async () => {
    const delivered: Array<(hostMs?: number) => void> = [];
    setNativeSchedulingModule({
      requestAnimationFrame(callback) {
        delivered.push(callback);
      },
    });
    const seen: Array<[number, number | undefined]> = [];
    requestAnimationFrame((time, hostMs) => seen.push([time, hostMs]));
    requestAnimationFrame((time, hostMs) => seen.push([time, hostMs]));
    expect(delivered).toHaveLength(1);
    delivered[0]!(1234.5);
    expect(seen).toHaveLength(2);
    for (const [time, hostMs] of seen) {
      expect(Number.isFinite(time)).toBe(true);
      expect(hostMs).toBe(1234.5);
    }
  });

  test('passes undefined when the host supplies no clock or a malformed one', () => {
    const delivered: Array<(hostMs?: number) => void> = [];
    setNativeSchedulingModule({
      requestAnimationFrame(callback) {
        delivered.push(callback);
      },
    });
    const seen: Array<number | undefined> = [];
    requestAnimationFrame((_, hostMs) => seen.push(hostMs));
    delivered[0]!();
    requestAnimationFrame((_, hostMs) => seen.push(hostMs));
    delivered[1]!(Number.NaN);
    requestAnimationFrame((_, hostMs) => seen.push(hostMs));
    delivered[2]!(-1);
    expect(seen).toEqual([undefined, undefined, undefined]);
  });
});
