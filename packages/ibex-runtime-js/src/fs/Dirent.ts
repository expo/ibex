import { Stats } from './Stats';

export class Dirent {
  readonly name: string;
  private readonly stats: Stats;

  constructor(name: string, stats: Stats) {
    this.name = name;
    this.stats = stats;
  }

  isFile(): boolean {
    return this.stats.isFile();
  }

  isDirectory(): boolean {
    return this.stats.isDirectory();
  }

  isBlockDevice(): boolean {
    return this.stats.isBlockDevice();
  }

  isCharacterDevice(): boolean {
    return this.stats.isCharacterDevice();
  }

  isSymbolicLink(): boolean {
    return this.stats.isSymbolicLink();
  }

  isFIFO(): boolean {
    return this.stats.isFIFO();
  }

  isSocket(): boolean {
    return this.stats.isSocket();
  }
}
