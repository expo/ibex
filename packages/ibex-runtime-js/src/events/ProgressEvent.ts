/**
 * ProgressEvent - Event for tracking progress of operations
 * 
 * Used by XMLHttpRequest, FileReader, and fetch progress tracking.
 * @see https://xhr.spec.whatwg.org/#interface-progressevent
 */

import { Event, EventInit } from './Event';

export interface ProgressEventInit extends EventInit {
  lengthComputable?: boolean;
  loaded?: number;
  total?: number;
}

export class ProgressEvent extends Event {
  readonly lengthComputable: boolean;
  readonly loaded: number;
  readonly total: number;

  constructor(type: string, eventInitDict?: ProgressEventInit) {
    super(type, eventInitDict);
    this.lengthComputable = eventInitDict?.lengthComputable ?? false;
    this.loaded = eventInitDict?.loaded ?? 0;
    this.total = eventInitDict?.total ?? 0;
  }

  get [Symbol.toStringTag](): string {
    return 'ProgressEvent';
  }
}

export default ProgressEvent;
