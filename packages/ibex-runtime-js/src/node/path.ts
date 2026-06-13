/**
 * path module implementation for Exact runtime (Node.js compatibility)
 *
 * Provides path manipulation utilities compatible with Node.js path module.
 * Since mobile apps run on Unix-like systems (iOS/Android), we only implement
 * the POSIX path semantics.
 *
 * @see https://nodejs.org/api/path.html
 */

/**
 * Path segment separator (always '/' on mobile platforms)
 */
export const sep = '/';

/**
 * Path delimiter for PATH-like environment variables
 */
export const delimiter = ':';

/**
 * Platform-specific path object (POSIX)
 */
export const posix = {
  sep: '/',
  delimiter: ':',
  basename,
  dirname,
  extname,
  format,
  isAbsolute,
  join,
  normalize,
  parse,
  relative,
  resolve,
  toNamespacedPath,
  posix: undefined as unknown as any,
};

/**
 * Windows path object (stub - not supported on mobile)
 */
export const win32 = {
  sep: '\\',
  delimiter: ';',
  basename: () => { throw new Error('win32 paths not supported'); },
  dirname: () => { throw new Error('win32 paths not supported'); },
  extname: () => { throw new Error('win32 paths not supported'); },
  format: () => { throw new Error('win32 paths not supported'); },
  isAbsolute: () => { throw new Error('win32 paths not supported'); },
  join: () => { throw new Error('win32 paths not supported'); },
  normalize: () => { throw new Error('win32 paths not supported'); },
  parse: () => { throw new Error('win32 paths not supported'); },
  relative: () => { throw new Error('win32 paths not supported'); },
  resolve: () => { throw new Error('win32 paths not supported'); },
  toNamespacedPath: () => { throw new Error('win32 paths not supported'); },
  win32: undefined as unknown as any,
};

export interface ParsedPath {
  root: string;
  dir: string;
  base: string;
  ext: string;
  name: string;
}

export interface FormatInputPathObject {
  root?: string;
  dir?: string;
  base?: string;
  ext?: string;
  name?: string;
}

/**
 * Return the last portion of a path.
 *
 * @param path - The path to evaluate
 * @param suffix - An optional suffix to remove
 * @returns The last portion of the path
 *
 * @example
 * path.basename('/foo/bar/baz.txt') // 'baz.txt'
 * path.basename('/foo/bar/baz.txt', '.txt') // 'baz'
 */
export function basename(path: string, suffix?: string): string {
  if (typeof path !== 'string') {
    throw new TypeError('Path must be a string');
  }

  // Remove trailing slashes
  let end = path.length;
  while (end > 0 && path[end - 1] === '/') {
    end--;
  }

  if (end === 0) {
    return '';
  }

  // Find start of basename
  let start = end - 1;
  while (start >= 0 && path[start] !== '/') {
    start--;
  }
  start++;

  let base = path.slice(start, end);

  // Remove suffix if provided
  if (suffix && base.endsWith(suffix)) {
    base = base.slice(0, -suffix.length);
  }

  return base;
}

/**
 * Return the directory name of a path.
 *
 * @param path - The path to evaluate
 * @returns The directory name
 *
 * @example
 * path.dirname('/foo/bar/baz.txt') // '/foo/bar'
 */
export function dirname(path: string): string {
  if (typeof path !== 'string') {
    throw new TypeError('Path must be a string');
  }

  if (path.length === 0) {
    return '.';
  }

  // Check if path is absolute
  const isAbs = path[0] === '/';

  // Remove trailing slashes
  let end = path.length;
  while (end > 1 && path[end - 1] === '/') {
    end--;
  }

  // Find the last separator
  let last = end - 1;
  while (last > 0 && path[last] !== '/') {
    last--;
  }

  if (last === 0) {
    return isAbs ? '/' : '.';
  }

  // Remove trailing slashes from result
  while (last > 1 && path[last - 1] === '/') {
    last--;
  }

  return path.slice(0, last);
}

/**
 * Return the extension of the path.
 *
 * @param path - The path to evaluate
 * @returns The extension (including the dot)
 *
 * @example
 * path.extname('index.html') // '.html'
 * path.extname('index.coffee.md') // '.md'
 */
export function extname(path: string): string {
  if (typeof path !== 'string') {
    throw new TypeError('Path must be a string');
  }

  const base = basename(path);
  const dotIndex = base.lastIndexOf('.');

  // No dot, or dot is first character (hidden file)
  if (dotIndex <= 0) {
    return '';
  }

  return base.slice(dotIndex);
}

/**
 * Return a path string from an object.
 *
 * @param pathObject - Object with path components
 * @returns The formatted path string
 */
export function format(pathObject: FormatInputPathObject): string {
  if (pathObject === null || typeof pathObject !== 'object') {
    throw new TypeError('Path object must be an object');
  }

  const { root = '', dir, base, ext = '', name = '' } = pathObject;

  // If dir is provided, use it; otherwise use root
  const directory = dir !== undefined ? dir : root;

  // If base is provided, use it; otherwise construct from name + ext
  const filename = base !== undefined ? base : `${name}${ext}`;

  if (!directory) {
    return filename;
  }

  if (directory === root) {
    return `${directory}${filename}`;
  }

  return `${directory}/${filename}`;
}

/**
 * Determine if a path is absolute.
 *
 * @param path - The path to check
 * @returns true if the path is absolute
 *
 * @example
 * path.isAbsolute('/foo/bar') // true
 * path.isAbsolute('foo/bar') // false
 */
export function isAbsolute(path: string): boolean {
  if (typeof path !== 'string') {
    throw new TypeError('Path must be a string');
  }

  return path.length > 0 && path[0] === '/';
}

/**
 * Join all arguments together and normalize the resulting path.
 *
 * @param paths - A sequence of paths to join
 * @returns The joined path
 *
 * @example
 * path.join('/foo', 'bar', 'baz/asdf', 'quux', '..') // '/foo/bar/baz/asdf'
 */
export function join(...paths: string[]): string {
  if (paths.length === 0) {
    return '.';
  }

  let joined = '';
  for (const path of paths) {
    if (typeof path !== 'string') {
      throw new TypeError('Path must be a string');
    }
    if (path.length > 0) {
      if (joined.length === 0) {
        joined = path;
      } else {
        joined += '/' + path;
      }
    }
  }

  if (joined.length === 0) {
    return '.';
  }

  return normalize(joined);
}

/**
 * Normalize a path, resolving '..' and '.' segments.
 *
 * @param path - The path to normalize
 * @returns The normalized path
 *
 * @example
 * path.normalize('/foo/bar//baz/asdf/quux/..') // '/foo/bar/baz/asdf'
 */
export function normalize(path: string): string {
  if (typeof path !== 'string') {
    throw new TypeError('Path must be a string');
  }

  if (path.length === 0) {
    return '.';
  }

  const isAbs = path[0] === '/';
  const trailingSep = path[path.length - 1] === '/';

  // Split into segments and process
  const segments = path.split('/');
  const result: string[] = [];

  for (const segment of segments) {
    if (segment === '' || segment === '.') {
      continue;
    }

    if (segment === '..') {
      if (result.length > 0 && result[result.length - 1] !== '..') {
        result.pop();
      } else if (!isAbs) {
        result.push('..');
      }
    } else {
      result.push(segment);
    }
  }

  let normalized = result.join('/');

  if (isAbs) {
    normalized = '/' + normalized;
  }

  if (trailingSep && normalized.length > 0 && normalized[normalized.length - 1] !== '/') {
    normalized += '/';
  }

  if (normalized.length === 0) {
    return isAbs ? '/' : '.';
  }

  return normalized;
}

/**
 * Parse a path into an object with its components.
 *
 * @param path - The path to parse
 * @returns An object with root, dir, base, ext, and name
 *
 * @example
 * path.parse('/home/user/file.txt')
 * // { root: '/', dir: '/home/user', base: 'file.txt', ext: '.txt', name: 'file' }
 */
export function parse(path: string): ParsedPath {
  if (typeof path !== 'string') {
    throw new TypeError('Path must be a string');
  }

  const root = path[0] === '/' ? '/' : '';
  const dir = dirname(path);
  const base = basename(path);
  const ext = extname(path);
  const name = ext ? base.slice(0, -ext.length) : base;

  return { root, dir, base, ext, name };
}

/**
 * Solve the relative path from `from` to `to`.
 *
 * @param from - The source path
 * @param to - The destination path
 * @returns The relative path
 *
 * @example
 * path.relative('/data/orandea/test/aaa', '/data/orandea/impl/bbb')
 * // '../../impl/bbb'
 */
export function relative(from: string, to: string): string {
  if (typeof from !== 'string') {
    throw new TypeError('From path must be a string');
  }
  if (typeof to !== 'string') {
    throw new TypeError('To path must be a string');
  }

  if (from === to) {
    return '';
  }

  // Resolve both paths
  const fromAbs = resolve(from);
  const toAbs = resolve(to);

  if (fromAbs === toAbs) {
    return '';
  }

  // Split into segments
  const fromParts = fromAbs.split('/').filter(Boolean);
  const toParts = toAbs.split('/').filter(Boolean);

  // Find common prefix
  let commonLength = 0;
  const minLength = Math.min(fromParts.length, toParts.length);
  while (commonLength < minLength && fromParts[commonLength] === toParts[commonLength]) {
    commonLength++;
  }

  // Build relative path
  const upCount = fromParts.length - commonLength;
  const relativeParts: string[] = [];

  for (let i = 0; i < upCount; i++) {
    relativeParts.push('..');
  }

  for (let i = commonLength; i < toParts.length; i++) {
    relativeParts.push(toParts[i]);
  }

  return relativeParts.join('/') || '.';
}

/**
 * Resolve a sequence of paths into an absolute path.
 *
 * @param paths - A sequence of paths to resolve
 * @returns The resolved absolute path
 *
 * @example
 * path.resolve('/foo/bar', './baz') // '/foo/bar/baz'
 * path.resolve('/foo/bar', '/tmp/file/') // '/tmp/file'
 */
export function resolve(...paths: string[]): string {
  let resolvedPath = '';
  let resolvedAbsolute = false;

  // Process from right to left, stopping at first absolute path
  for (let i = paths.length - 1; i >= -1 && !resolvedAbsolute; i--) {
    let path: string;

    if (i >= 0) {
      path = paths[i];
      if (typeof path !== 'string') {
        throw new TypeError('Path must be a string');
      }
    } else {
      // Use cwd as implicit first argument
      path = (globalThis as any).process?.cwd?.() ?? '/';
    }

    if (path.length === 0) {
      continue;
    }

    resolvedPath = path + '/' + resolvedPath;
    resolvedAbsolute = path[0] === '/';
  }

  // Normalize and remove trailing slash
  resolvedPath = normalize(resolvedPath);

  if (resolvedAbsolute) {
    return resolvedPath.length > 0 ? resolvedPath : '/';
  }

  return resolvedPath.length > 0 ? resolvedPath : '.';
}

/**
 * Return the path unchanged (no-op on POSIX systems).
 * On Windows, this would convert to a namespace path.
 *
 * @param path - The path to convert
 * @returns The same path
 */
export function toNamespacedPath(path: string): string {
  // No-op on POSIX
  return path;
}

/**
 * Default export with all path functions
 */
const path = {
  sep,
  delimiter,
  posix,
  win32,
  basename,
  dirname,
  extname,
  format,
  isAbsolute,
  join,
  normalize,
  parse,
  relative,
  resolve,
  toNamespacedPath,
};

posix.posix = posix;
win32.win32 = win32;

export default path;
