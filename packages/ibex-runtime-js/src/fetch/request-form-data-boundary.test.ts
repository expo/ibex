// Regression: Request used to encode FormData once to choose Content-Type,
// then encode it again when the native fetch bridge asked for bytes. Each
// encoding chose a random boundary, so the header described delimiters that
// did not exist in the transmitted body.

import { describe, expect, test } from 'bun:test';
import { FormData } from '../blob/FormData.ts';
import { Request } from './Request.ts';

function multipartBoundary(request: Request): string {
  const contentType = request.headers.get('content-type') || '';
  const match = /(?:^|;)\s*boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(contentType);
  expect(match).not.toBeNull();
  return (match![1] || match![2]);
}

function assertEveryDelimiterUses(bytes: Uint8Array, boundary: string, fields: number): void {
  const body = new TextDecoder().decode(bytes);
  const delimiter = `--${boundary}`;
  expect(body.startsWith(`${delimiter}\r\n`)).toBe(true);
  expect(body.endsWith(`${delimiter}--\r\n`)).toBe(true);
  expect(body.split(delimiter).length - 1).toBe(fields + 1);

  const delimiterLines = body.match(/^--[^\r\n]+/gm) || [];
  expect(delimiterLines).toHaveLength(fields + 1);
  for (let i = 0; i < delimiterLines.length - 1; i++) {
    expect(delimiterLines[i]).toBe(delimiter);
  }
  expect(delimiterLines[delimiterLines.length - 1]).toBe(`${delimiter}--`);
}

describe('Request FormData boundary identity', () => {
  test('header, native-send bytes, and clone all retain one encoded boundary', async () => {
    const form = new FormData();
    form.append('first', 'one');
    form.append('second', 'two');

    const request = new Request('https://example.test/upload', {
      method: 'POST',
      body: form as any,
    });
    const clone = request.clone();
    const boundary = multipartBoundary(request);

    expect(multipartBoundary(clone)).toBe(boundary);
    const sendBytes = await request.getBodyAsUint8Array();
    const cloneBytes = await clone.getBodyAsUint8Array();
    expect(sendBytes).not.toBeNull();
    expect(cloneBytes).not.toBeNull();
    assertEveryDelimiterUses(sendBytes!, boundary, 2);
    assertEveryDelimiterUses(cloneBytes!, boundary, 2);
    expect(Array.from(cloneBytes!)).toEqual(Array.from(sendBytes!));

    // This is the same lifecycle used by fetch after handing the bytes to the
    // native bridge; marking it consumed must not trigger another encoding.
    request.markBodyAsUsedForFetch();
    expect(request.bodyUsed).toBe(true);
  });
});
