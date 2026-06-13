/**
 * Stub for ReadableStream compatibility installs.
 * This file exists to satisfy imports when building the runtime bundle.
 */

declare const globalThis: any;

export function installExactReadableStreamCompat(): void {
  const g = globalThis;

  // Fix CountQueuingStrategy.name and ByteLengthQueuingStrategy.name.
  // When Babel transpiles class declarations and terser minifies them, the
  // function .name property ends up as a single-char identifier instead of
  // the class name. Fix this eagerly after the lazy globals are installed.
  //
  // We access the global to trigger the lazy getter (if it's still lazy),
  // then redefine the name property on the constructor function.
  const nameFixes: [string, string][] = [
    ['CountQueuingStrategy', 'CountQueuingStrategy'],
    ['ByteLengthQueuingStrategy', 'ByteLengthQueuingStrategy'],
    ['ReadableStream', 'ReadableStream'],
    ['WritableStream', 'WritableStream'],
    ['TransformStream', 'TransformStream'],
    ['ReadableStreamDefaultReader', 'ReadableStreamDefaultReader'],
    ['ReadableStreamBYOBReader', 'ReadableStreamBYOBReader'],
  ];

  for (const [globalName, expectedName] of nameFixes) {
    try {
      const ctor = g[globalName];
      if (typeof ctor === 'function' && ctor.name !== expectedName) {
        try {
          Object.defineProperty(ctor, 'name', {
            value: expectedName,
            configurable: true,
            writable: false,
            enumerable: false,
          });
        } catch (_) {
          // Ignore if name is not configurable
        }
      }
    } catch (_) {
      // Ignore errors
    }
  }
}
