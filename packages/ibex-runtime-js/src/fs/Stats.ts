/**
 * Node.js-compatible Stats class.
 */

export class Stats {
  dev: number = 0;
  ino: number = 0;
  mode: number;
  nlink: number = 1;
  uid: number = 0;
  gid: number = 0;
  rdev: number = 0;
  size: number;
  blksize: number = 4096;
  blocks: number;
  atimeMs: number;
  mtimeMs: number;
  ctimeMs: number;
  birthtimeMs: number;
  atime: Date;
  mtime: Date;
  ctime: Date;
  birthtime: Date;

  private _isFile: boolean;
  private _isDirectory: boolean;
  private _isSymlink: boolean;

  constructor(raw: {
    size: number;
    mtime_ms: number;
    is_dir: boolean;
    is_file: boolean;
    is_symlink?: boolean;
    mode: number;
  }) {
    this.size = raw.size;
    this.mode = raw.mode;
    this.blocks = Math.ceil(raw.size / 512);
    this.mtimeMs = raw.mtime_ms;
    this.atimeMs = raw.mtime_ms;
    this.ctimeMs = raw.mtime_ms;
    this.birthtimeMs = raw.mtime_ms;
    this.mtime = new Date(raw.mtime_ms);
    this.atime = new Date(raw.mtime_ms);
    this.ctime = new Date(raw.mtime_ms);
    this.birthtime = new Date(raw.mtime_ms);
    this._isFile = raw.is_file;
    this._isDirectory = raw.is_dir;
    this._isSymlink = raw.is_symlink ?? false;
  }

  isFile(): boolean {
    return this._isFile;
  }

  isDirectory(): boolean {
    return this._isDirectory;
  }

  isBlockDevice(): boolean {
    return false;
  }

  isCharacterDevice(): boolean {
    return false;
  }

  isSymbolicLink(): boolean {
    return this._isSymlink;
  }

  isFIFO(): boolean {
    return false;
  }

  isSocket(): boolean {
    return false;
  }
}
