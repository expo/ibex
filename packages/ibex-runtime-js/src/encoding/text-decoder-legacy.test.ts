// ENG-22972 #5 — regression coverage for legacy multi-byte TextDecoder handling.
//
// gbk/big5/shift_jis/euc-jp/euc-kr/gb18030/iso-2022-jp are accepted as
// constructor labels but had no JS decoder. decode() constructed a *fresh*
// native decoder on every call (discarding {stream:true} state, so a multi-byte
// sequence split across chunks was silently corrupted) and, when no native
// decoder was available, fell through to _decodeUTF8 — decoding e.g. Shift-JIS
// bytes as UTF-8 garbage with no error.
//
// Fixes verified here: (a) the native decoder is created once and cached on the
// TextDecoder instance so streaming state survives across decode() calls;
// (b) when no native decoder supports the encoding, decode() throws instead of
// silently producing UTF-8 garbage.
//
// The module captures `globalThis.TextDecoder` as its native delegate at load
// time, so we install a controllable stub BEFORE requiring the module (bun's own
// native TextDecoder has an unrelated Shift-JIS streaming bug and is not a
// reliable oracle). The stub models a native decoder that supports 'shift_jis'
// (with correct lead-byte streaming state) but NOT 'gbk'. Run: bun test.

import { expect, test, describe } from 'bun:test';
import { createRequire } from 'module';

// A minimal stateful DBCS decoder: lead bytes (>= 0x81) start a 2-byte sequence
// whose state must persist across decode() calls for streaming to work.
function combine(lead: number, trail: number): string {
  if (lead === 0x82 && trail === 0xa0) return 'あ'; // Shift_JIS あ
  if (lead === 0x82 && trail === 0xa2) return 'い'; // Shift_JIS い
  return '�';
}

let stubConstructCount = 0;

class StubNativeDecoder {
  private _lead = 0;
  constructor(label?: string, _opts?: { fatal?: boolean; ignoreBOM?: boolean }) {
    stubConstructCount++;
    // Simulate a native runtime that supports shift_jis but not gbk.
    if (label !== 'shift_jis') {
      throw new RangeError(`stub native decoder does not support '${label}'`);
    }
  }
  decode(input?: any, options?: { stream?: boolean }): string {
    const stream = !!(options && options.stream);
    const bytes: Uint8Array = input && input.length ? input : new Uint8Array(0);
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (this._lead !== 0) {
        out += combine(this._lead, b);
        this._lead = 0;
      } else if (b >= 0x81) {
        this._lead = b; // buffer lead byte (streaming state)
      } else {
        out += String.fromCharCode(b);
      }
    }
    if (!stream && this._lead !== 0) {
      out += '�';
      this._lead = 0;
    }
    return out;
  }
}

// Install stub, load the module (which captures it as NativeTextDecoderImpl),
// then immediately restore the real global so sibling test files are unaffected.
const g = globalThis as Record<string, any>;
const OriginalTextDecoder = g.TextDecoder;
g.TextDecoder = StubNativeDecoder;
const require = createRequire(import.meta.url);
const mod = require('./TextDecoder.ts');
g.TextDecoder = OriginalTextDecoder;
const ModuleTextDecoder: typeof import('./TextDecoder').TextDecoder = mod.TextDecoder;

describe('TextDecoder legacy multi-byte (ENG-22972 #5)', () => {
  test('non-streaming decode of a supported legacy encoding works', () => {
    const d = new ModuleTextDecoder('shift_jis');
    expect(d.decode(new Uint8Array([0x82, 0xa0, 0x82, 0xa2]))).toBe('あい');
  });

  test('label normalizes to the canonical encoding name', () => {
    expect(new ModuleTextDecoder('sjis').encoding).toBe('shift_jis');
    expect(new ModuleTextDecoder('x-sjis').encoding).toBe('shift_jis');
  });

  test('streaming: a multi-byte char split across decode() calls decodes correctly', () => {
    // Was corrupted because each decode() built a fresh native decoder, losing
    // the buffered lead byte. Now the cached instance preserves it.
    const d = new ModuleTextDecoder('shift_jis');
    const before = stubConstructCount;
    let out = '';
    out += d.decode(new Uint8Array([0x82]), { stream: true });        // buffered lead
    out += d.decode(new Uint8Array([0xa0, 0x82]), { stream: true });  // あ + buffered lead
    out += d.decode(new Uint8Array([0xa2]));                          // い (flush)
    expect(out).toBe('あい');
    // Exactly one native decoder was constructed for the whole stream.
    expect(stubConstructCount - before).toBe(1);
  });

  test('unsupported legacy encoding throws instead of decoding as UTF-8 garbage', () => {
    const d = new ModuleTextDecoder('gbk');
    // 中 in GBK is 0xD6 0xD0; decoding these as UTF-8 would silently yield U+FFFD
    // garbage. We must throw instead.
    expect(() => d.decode(new Uint8Array([0xd6, 0xd0]))).toThrow(TypeError);
  });

  test('unsupported legacy encoding still decodes empty input to ""', () => {
    const d = new ModuleTextDecoder('big5');
    expect(d.decode(new Uint8Array(0))).toBe('');
    expect(d.decode()).toBe('');
  });

  test('UTF-8 decoding is unaffected by the legacy path', () => {
    const d = new ModuleTextDecoder('utf-8');
    expect(d.decode(new Uint8Array([0xe4, 0xb8, 0xad]))).toBe('中');
  });
});
