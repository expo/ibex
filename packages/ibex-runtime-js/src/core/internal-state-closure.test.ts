import { afterEach, describe, expect, test } from 'bun:test';

import {
  _resetExactAccessibilityForTests,
  getExactAccessibilitySnapshot,
  updateAccessibilitySnapshot,
} from './accessibility-state.js';
import {
  _resetExactLocaleForTests,
  getExactLocaleSnapshot,
  updateLocaleSnapshot,
} from './locale-state.js';

afterEach(() => {
  _resetExactAccessibilityForTests();
  _resetExactLocaleForTests();
});

describe('shared runtime state closure', () => {
  test('keeps normalized locale state off globalThis', () => {
    const snapshot = updateLocaleSnapshot(
      { tag: 'fr-FR', tags: ['fr-FR'], uses24Hour: true },
      null,
      false,
    );

    expect(getExactLocaleSnapshot()).toBe(snapshot);
    expect(snapshot).toMatchObject({
      language: 'fr',
      region: 'FR',
      tag: 'fr-FR',
      uses24Hour: true,
    });
    expect('__exactLocaleState' in globalThis).toBe(false);
  });

  test('keeps normalized accessibility state off globalThis', () => {
    const snapshot = updateAccessibilitySnapshot(
      {
        colorScheme: 'dark',
        fontScale: 1.25,
        prefersReducedMotion: true,
      },
      false,
    );

    expect(getExactAccessibilitySnapshot()).toBe(snapshot);
    expect(snapshot).toMatchObject({
      colorScheme: 'dark',
      fontScale: 1.25,
      prefersReducedMotion: true,
    });
    expect('__exactAccessibilityState' in globalThis).toBe(false);
  });
});
