// @ts-nocheck
/**
 * structuredClone implementation for Exact runtime
 * 
 * Implements the HTML structured clone algorithm.
 * @see https://html.spec.whatwg.org/multipage/structured-data.html#structuredclone
 */

import { DOMException, createDataCloneError } from '../events/DOMException';
import { isDetachedArrayBuffer, markDetachedArrayBuffer } from '../arraybuffer-detach';
import { Blob as ExactBlob } from '../blob/Blob';
import { File as ExactFile } from '../blob/File';

// Lazy imports to break circular dependency:
// Blob → streams/ReadableStream → clone/structuredClone → Blob
let _Blob: typeof import('../blob/Blob').Blob | undefined;
let _File: typeof import('../blob/File').File | undefined;
function getBlobClasses() {
  if (!_Blob) {
    // Keep constructor lookup lazy so the module does not touch Blob/File until
    // structuredClone actually needs them, while still relying on normal ESM
    // resolution instead of CommonJS `require()` path heuristics.
    _Blob = ExactBlob;
    _File = ExactFile;
  }
  return { Blob: _Blob!, File: _File! };
}
import {
  structuredCloneCloneSymbol,
  structuredCloneTransferSymbol,
} from './transferableSymbols';

export interface StructuredSerializeOptions {
  transfer?: Transferable[];
}

// Types that can be transferred (ownership moves, original becomes neutered)
type Transferable = ArrayBuffer | object;

export { isDetachedArrayBuffer, markDetachedArrayBuffer } from '../arraybuffer-detach';

/**
 * Creates a deep copy of a value using the structured clone algorithm.
 * 
 * Supported types:
 * - Primitives (undefined, null, boolean, number, string, bigint)
 * - Date
 * - RegExp
 * - Array
 * - Object (plain objects)
 * - Map
 * - Set
 * - ArrayBuffer
 * - TypedArrays (Uint8Array, Int32Array, etc.)
 * - DataView
 * - Blob
 * - File
 * - Error (partial - only message and name)
 * 
 * NOT supported:
 * - Functions
 * - Symbols (as values - ignored as keys)
 * - DOM nodes
 * - WeakMap, WeakSet, WeakRef
 * - Generators, Promises
 * - SharedArrayBuffer (Hermes limitation)
 */
export function structuredClone<T>(
  value: T,
  options?: StructuredSerializeOptions
): T {
  const transfer = options?.transfer ?? [];
  const transferSet = new Set<object>();

  for (const transferable of transfer) {
    if (
      !(transferable instanceof ArrayBuffer) &&
      !(
        transferable &&
        typeof transferable === 'object' &&
        structuredCloneTransferSymbol in transferable
      )
    ) {
      throw createDataCloneError(
        'The object could not be cloned.'
      );
    }
    if (transferable && typeof transferable === 'object') {
      if (transferSet.has(transferable)) {
        throw createDataCloneError('The object could not be cloned.');
      }
      transferSet.add(transferable);
    }
  }

  // Track already-cloned objects to handle circular references
  const cloneMap = new Map<object, object>();

  const cloned = cloneInternal(value, cloneMap, transferSet);

  for (const transferable of transfer) {
    if (transferable instanceof ArrayBuffer) {
      markDetachedArrayBuffer(transferable);
    }
  }

  return cloned;
}

type ImageDataLike = {
  data: Uint8ClampedArray;
  width: number;
  height: number;
  colorSpace?: string;
};

function getGlobalDOMExceptionConstructor():
  | (new (message?: string, name?: string) => DOMException)
  | undefined {
  return typeof globalThis === 'object' &&
    globalThis !== null &&
    typeof (globalThis as any).DOMException === 'function'
    ? ((globalThis as any).DOMException as new (message?: string, name?: string) => DOMException)
    : undefined;
}

function isDomExceptionInstance(value: object): value is DOMException {
  if (value instanceof DOMException) {
    return true;
  }
  const GlobalDOMException = getGlobalDOMExceptionConstructor();
  return typeof GlobalDOMException === 'function' && value instanceof GlobalDOMException;
}

function getGlobalImageDataConstructor():
  | (new (
      data: Uint8ClampedArray,
      width: number,
      height?: number,
      settings?: { colorSpace?: string }
    ) => ImageDataLike)
  | undefined {
  return typeof globalThis === 'object' &&
    globalThis !== null &&
    typeof (globalThis as any).ImageData === 'function'
    ? ((globalThis as any).ImageData as new (
        data: Uint8ClampedArray,
        width: number,
        height?: number,
        settings?: { colorSpace?: string }
      ) => ImageDataLike)
    : undefined;
}

function isImageDataInstance(value: object): value is ImageDataLike {
  const ImageDataCtor = getGlobalImageDataConstructor();
  return typeof ImageDataCtor === 'function' && value instanceof ImageDataCtor;
}

function cloneInternal<T>(
  value: T,
  cloneMap: Map<object, object>,
  transferSet: Set<object>
): T {
  // Handle primitives
  if (value === null || value === undefined) {
    return value;
  }

  const type = typeof value;

  if (type === 'boolean' || type === 'number' || type === 'string' || type === 'bigint') {
    return value;
  }

  if (type === 'symbol') {
    throw createDataCloneError('Symbols cannot be cloned');
  }

  if (type === 'function') {
    throw createDataCloneError('Functions cannot be cloned');
  }

  // At this point, value must be an object
  const obj = value as unknown as object;

  // Check for circular reference
  if (cloneMap.has(obj)) {
    return cloneMap.get(obj) as T;
  }

  if (transferSet.has(obj)) {
    if (obj instanceof ArrayBuffer) {
      const clone = obj.slice(0);
      cloneMap.set(obj, clone);
      return clone as T;
    }
    if (structuredCloneTransferSymbol in obj) {
      const transferClone = (obj as any)[structuredCloneTransferSymbol]();
      cloneMap.set(obj, transferClone);
      return transferClone as T;
    }
  }

  if (structuredCloneCloneSymbol in obj) {
    const clone = (obj as any)[structuredCloneCloneSymbol]();
    cloneMap.set(obj, clone);
    return clone as T;
  }

  if (structuredCloneTransferSymbol in obj) {
    throw createDataCloneError('The object could not be cloned.');
  }

  // Handle specific object types
  if (obj instanceof Date) {
    const clone = new Date(obj.getTime());
    cloneMap.set(obj, clone);
    return clone as T;
  }

  if (obj instanceof RegExp) {
    const clone = new RegExp(obj.source, obj.flags);
    cloneMap.set(obj, clone);
    return clone as T;
  }

  if (isDomExceptionInstance(obj)) {
    const DOMExceptionCtor =
      (typeof (obj as any).constructor === 'function'
        ? ((obj as any).constructor as new (message?: string, name?: string) => DOMException)
        : undefined) ??
      getGlobalDOMExceptionConstructor() ??
      DOMException;
    const clone = new DOMExceptionCtor(obj.message, obj.name);
    if (typeof (obj as any).stack === 'string') {
      (clone as any).stack = (obj as any).stack;
    }
    if ('cause' in obj) {
      (clone as any).cause = cloneInternal((obj as any).cause, cloneMap, transferSet);
    }
    cloneMap.set(obj, clone);
    return clone as T;
  }

  if (obj instanceof Error) {
    const ErrorConstructor = obj.constructor as ErrorConstructor;
    const clone = new ErrorConstructor(obj.message);
    clone.name = obj.name;
    if (typeof (obj as any).stack === 'string') {
      (clone as any).stack = (obj as any).stack;
    }
    // Optionally copy cause if present
    if ('cause' in obj) {
      (clone as any).cause = cloneInternal((obj as any).cause, cloneMap, transferSet);
    }
    cloneMap.set(obj, clone);
    return clone as T;
  }

  if (isImageDataInstance(obj)) {
    const ImageDataCtor = getGlobalImageDataConstructor();
    if (!ImageDataCtor) {
      throw createDataCloneError('The object could not be cloned.');
    }

    const clonedData = cloneInternal(obj.data, cloneMap, transferSet) as Uint8ClampedArray;
    let clone: ImageDataLike;
    try {
      clone = new ImageDataCtor(clonedData, obj.width, obj.height, {
        colorSpace: obj.colorSpace,
      });
    } catch {
      clone = new ImageDataCtor(clonedData, obj.width, obj.height);
    }
    cloneMap.set(obj, clone as object);
    return clone as T;
  }

  if (obj instanceof ArrayBuffer) {
    // Clone the buffer
    const clone = obj.slice(0);
    cloneMap.set(obj, clone);
    return clone as T;
  }

  // Handle TypedArrays
  if (ArrayBuffer.isView(obj) && !(obj instanceof DataView)) {
    const TypedArrayConstructor = obj.constructor as new (buffer: ArrayBuffer, byteOffset: number, length: number) => typeof obj;
    const sourceBuffer = obj.buffer as ArrayBuffer;
    
    // Clone the buffer portion
    const clonedBuffer = sourceBuffer.slice(obj.byteOffset, obj.byteOffset + obj.byteLength);
    const clone = new TypedArrayConstructor(clonedBuffer, 0, (obj as any).length);
    cloneMap.set(obj, clone);
    return clone as T;
  }

  if (obj instanceof DataView) {
    const sourceBuffer = obj.buffer as ArrayBuffer;
    // Per spec: clone the entire underlying buffer and preserve byteOffset
    const clonedBuffer = sourceBuffer.slice(0);
    const clone = new DataView(clonedBuffer, obj.byteOffset, obj.byteLength);
    cloneMap.set(obj, clone);
    return clone as T;
  }

  if (obj instanceof Map) {
    const clone = new Map();
    cloneMap.set(obj, clone);
    for (const [key, val] of obj) {
      // Keys are also cloned
      const clonedKey = cloneInternal(key, cloneMap, transferSet);
      const clonedVal = cloneInternal(val, cloneMap, transferSet);
      clone.set(clonedKey, clonedVal);
    }
    return clone as T;
  }

  if (obj instanceof Set) {
      const clone = new Set();
      cloneMap.set(obj, clone);
      for (const item of obj) {
      clone.add(cloneInternal(item, cloneMap, transferSet));
      }
    return clone as T;
  }

  // Blob and File
  const { Blob: BlobClass, File: FileClass } = getBlobClasses();
  if (obj instanceof FileClass) {
    const bytes = (obj as any)._getBytes();
    const clone = new FileClass([bytes], (obj as any).name, {
      type: (obj as any).type,
      lastModified: (obj as any).lastModified,
    });
    cloneMap.set(obj, clone);
    return clone as T;
  }

  if (obj instanceof BlobClass) {
    const bytes = (obj as any)._getBytes();
    const clone = new BlobClass([bytes], { type: (obj as any).type });
    cloneMap.set(obj, clone);
    return clone as T;
  }

  // Handle Arrays
  if (Array.isArray(obj)) {
      const clone: any[] = [];
      cloneMap.set(obj, clone);
      for (let i = 0; i < obj.length; i++) {
      clone[i] = cloneInternal(obj[i], cloneMap, transferSet);
      }
    return clone as T;
  }

  // Handle plain objects
  // Check if it's a plain object (not a class instance with special behavior)
  const proto = Object.getPrototypeOf(obj);
  if (proto === null || proto === Object.prototype) {
    const clone: Record<string, unknown> = {};
    cloneMap.set(obj, clone);
    
    // Clone own enumerable string-keyed properties
    for (const key of Object.keys(obj)) {
      clone[key] = cloneInternal((obj as any)[key], cloneMap, transferSet);
    }
    
    return clone as T;
  }

  // Object with unknown prototype - try to clone as plain object with warning
  // This handles objects that are "object-like" but may have custom prototypes
  if (typeof obj === 'object') {
    const clone: Record<string, unknown> = {};
    cloneMap.set(obj, clone);
    
    for (const key of Object.keys(obj)) {
      clone[key] = cloneInternal((obj as any)[key], cloneMap, transferSet);
    }
    
    return clone as T;
  }

  throw createDataCloneError(`Object of type ${obj.constructor?.name ?? 'unknown'} cannot be cloned`);
}

export default structuredClone;
