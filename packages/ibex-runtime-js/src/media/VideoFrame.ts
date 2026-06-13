import { createDataCloneError } from "../events/DOMException";
import {
  structuredCloneCloneSymbol,
  structuredCloneTransferSymbol,
} from "../clone/transferableSymbols";

export interface VideoFrameInit {
  format?: string;
  timestamp?: number;
  codedWidth?: number;
  codedHeight?: number;
}

export class VideoFrame {
  _exactData: any;
  _exactClosed = false;
  format: string | null;
  timestamp: number | undefined;
  codedWidth: number | undefined;
  codedHeight: number | undefined;

  constructor(data: any, init: VideoFrameInit = {}) {
    this._exactData = data;
    this.format = init.format ?? null;
    this.timestamp = init.timestamp;
    this.codedWidth = init.codedWidth;
    this.codedHeight = init.codedHeight;
  }

  close(): void {
    this._exactClosed = true;
    this.format = null;
  }

  [structuredCloneCloneSymbol](): VideoFrame {
    if (this._exactClosed || this.format === null) {
      throw createDataCloneError();
    }
    return new VideoFrame(this._exactData, {
      format: this.format,
      timestamp: this.timestamp,
      codedWidth: this.codedWidth,
      codedHeight: this.codedHeight,
    });
  }

  [structuredCloneTransferSymbol](): VideoFrame {
    const clone = this[structuredCloneCloneSymbol]();
    this.close();
    return clone;
  }

  get [Symbol.toStringTag](): string {
    return "VideoFrame";
  }
}

export default VideoFrame;
