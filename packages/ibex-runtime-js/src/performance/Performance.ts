// @ts-nocheck
/**
 * Performance - Web Standard Performance API Implementation
 *
 * @see https://www.w3.org/TR/hr-time/
 * @see https://www.w3.org/TR/user-timing/
 */

import { EventTarget } from "../events/EventTarget";

export interface PerformanceMarkOptions {
  detail?: any;
  startTime?: number;
}

export interface PerformanceMeasureOptions {
  detail?: any;
  start?: string | number;
  duration?: number;
  end?: string | number;
}

export interface PerformanceEntryInit {
  name: string;
  entryType: string;
  startTime: number;
  duration: number;
}

export class PerformanceEntry {
  readonly name: string;
  readonly entryType: string;
  readonly startTime: number;
  readonly duration: number;

  constructor(init: PerformanceEntryInit) {
    this.name = init.name;
    this.entryType = init.entryType;
    this.startTime = init.startTime;
    this.duration = init.duration;
  }

  toJSON(): object {
    return {
      name: this.name,
      entryType: this.entryType,
      startTime: this.startTime,
      duration: this.duration,
    };
  }
}

export class PerformanceMark extends PerformanceEntry {
  readonly detail: any;

  constructor(name: string, options?: PerformanceMarkOptions) {
    super({
      name,
      entryType: "mark",
      startTime: options?.startTime ?? performance?.now?.() ?? Date.now(),
      duration: 0,
    });
    this.detail = options?.detail;
  }
}

export class PerformanceMeasure extends PerformanceEntry {
  readonly detail: any;

  constructor(
    name: string,
    startTime: number,
    duration: number,
    detail?: any
  ) {
    super({
      name,
      entryType: "measure",
      startTime,
      duration,
    });
    this.detail = detail;
  }
}

// Native module for high-resolution timing
export interface PerformanceModule {
  now(): number;
  timeOrigin: number;
}

let nativeModule: PerformanceModule | null = null;

export function setNativePerformanceModule(module: PerformanceModule): void {
  nativeModule = module;
}

// Fallback using Date.now() with offset
const fallbackTimeOrigin = Date.now();
const fallbackModule: PerformanceModule = {
  now: () => Date.now() - fallbackTimeOrigin,
  timeOrigin: fallbackTimeOrigin,
};

function getModule(): PerformanceModule {
  return nativeModule ?? fallbackModule;
}

// Cap on how many timeline entries the buffer retains. mark()/measure() have no
// clearMarks/clearMeasures discipline in most apps, so a library marking per
// frame at 60fps would otherwise retain ~200k entries/hour forever. When the cap
// is exceeded the oldest entries are evicted (FIFO). (ENG-22985)
const MAX_TIMELINE_ENTRIES = 10000;

export class Performance {
  private _marks: Map<string, PerformanceMark[]> = new Map();
  private _measures: Map<string, PerformanceMeasure[]> = new Map();
  private _entries: PerformanceEntry[] = [];
  // True while `_entries` is in non-decreasing startTime order (the common case,
  // since now() is monotonic). Lets getEntries* skip the O(n log n) re-sort on
  // every call and only sort when an out-of-order startTime was inserted. (ENG-22985)
  private _entriesSorted = true;

  // Append an entry to the timeline, tracking sort order and enforcing the cap.
  private _recordEntry(entry: PerformanceEntry): void {
    const entries = this._entries;
    const last = entries.length > 0 ? entries[entries.length - 1] : undefined;
    if (last !== undefined && entry.startTime < last.startTime) {
      this._entriesSorted = false;
    }
    entries.push(entry);

    if (entries.length > MAX_TIMELINE_ENTRIES) {
      const evicted = entries.shift();
      if (evicted !== undefined) {
        this._evictFromBucket(evicted);
      }
    }
  }

  // Drop an evicted entry from its by-name bucket (`_marks`/`_measures`) too, so
  // eviction bounds those maps as well and getEntriesByName stays consistent.
  private _evictFromBucket(entry: PerformanceEntry): void {
    const bucketMap =
      entry.entryType === "mark"
        ? this._marks
        : entry.entryType === "measure"
        ? this._measures
        : null;
    if (!bucketMap) {
      return;
    }
    const bucket = bucketMap.get(entry.name);
    if (!bucket) {
      return;
    }
    const idx = bucket.indexOf(entry as any);
    if (idx !== -1) {
      bucket.splice(idx, 1);
    }
    if (bucket.length === 0) {
      bucketMap.delete(entry.name);
    }
  }

  /**
   * Time origin (when the runtime started)
   */
  get timeOrigin(): number {
    return getModule().timeOrigin;
  }

  /**
   * Current high-resolution timestamp in milliseconds
   */
  now(): number {
    return getModule().now();
  }

  /**
   * Create a performance mark
   */
  mark(markName: string, markOptions?: PerformanceMarkOptions): PerformanceMark {
    const mark = new PerformanceMark(markName, {
      ...markOptions,
      startTime: markOptions?.startTime ?? this.now(),
    });

    let marks = this._marks.get(markName);
    if (!marks) {
      marks = [];
      this._marks.set(markName, marks);
    }
    marks.push(mark);
    this._recordEntry(mark);

    return mark;
  }

  /**
   * Create a performance measure between two marks or times
   */
  measure(
    measureName: string,
    startOrMeasureOptions?: string | PerformanceMeasureOptions,
    endMark?: string
  ): PerformanceMeasure {
    let startTime: number;
    let endTime: number;
    let detail: any;

    if (typeof startOrMeasureOptions === "string" || startOrMeasureOptions === undefined) {
      // Legacy signature: measure(name, startMark?, endMark?)
      const startMarkName = startOrMeasureOptions;

      if (startMarkName) {
        const startMarks = this._marks.get(startMarkName);
        if (!startMarks || startMarks.length === 0) {
          throw new DOMException(
            `Failed to execute 'measure': The mark '${startMarkName}' does not exist.`,
            "SyntaxError"
          );
        }
        startTime = startMarks[startMarks.length - 1].startTime;
      } else {
        startTime = 0;
      }

      if (endMark) {
        const endMarks = this._marks.get(endMark);
        if (!endMarks || endMarks.length === 0) {
          throw new DOMException(
            `Failed to execute 'measure': The mark '${endMark}' does not exist.`,
            "SyntaxError"
          );
        }
        endTime = endMarks[endMarks.length - 1].startTime;
      } else {
        endTime = this.now();
      }
    } else {
      // Modern signature: measure(name, options)
      const options = startOrMeasureOptions;
      detail = options.detail;

      if (options.start !== undefined) {
        if (typeof options.start === "string") {
          const startMarks = this._marks.get(options.start);
          if (!startMarks || startMarks.length === 0) {
            throw new DOMException(
              `Failed to execute 'measure': The mark '${options.start}' does not exist.`,
              "SyntaxError"
            );
          }
          startTime = startMarks[startMarks.length - 1].startTime;
        } else {
          startTime = options.start;
        }
      } else {
        startTime = 0;
      }

      if (options.end !== undefined) {
        if (typeof options.end === "string") {
          const endMarks = this._marks.get(options.end);
          if (!endMarks || endMarks.length === 0) {
            throw new DOMException(
              `Failed to execute 'measure': The mark '${options.end}' does not exist.`,
              "SyntaxError"
            );
          }
          endTime = endMarks[endMarks.length - 1].startTime;
        } else {
          endTime = options.end;
        }
      } else if (options.duration !== undefined) {
        endTime = startTime + options.duration;
      } else {
        endTime = this.now();
      }
    }

    const duration = endTime - startTime;
    const measure = new PerformanceMeasure(measureName, startTime, duration, detail);

    let measures = this._measures.get(measureName);
    if (!measures) {
      measures = [];
      this._measures.set(measureName, measures);
    }
    measures.push(measure);
    this._recordEntry(measure);

    return measure;
  }

  /**
   * Clear marks by name (or all marks if no name given)
   */
  clearMarks(markName?: string): void {
    if (markName) {
      this._marks.delete(markName);
      this._entries = this._entries.filter(
        (e) => !(e.entryType === "mark" && e.name === markName)
      );
    } else {
      this._marks.clear();
      this._entries = this._entries.filter((e) => e.entryType !== "mark");
    }
  }

  /**
   * Clear measures by name (or all measures if no name given)
   */
  clearMeasures(measureName?: string): void {
    if (measureName) {
      this._measures.delete(measureName);
      this._entries = this._entries.filter(
        (e) => !(e.entryType === "measure" && e.name === measureName)
      );
    } else {
      this._measures.clear();
      this._entries = this._entries.filter((e) => e.entryType !== "measure");
    }
  }

  /**
   * Get all entries
   */
  getEntries(): PerformanceEntry[] {
    const copy = [...this._entries];
    // `_entries` (and any filter of it, which preserves order) is already sorted
    // by startTime in the common monotonic case, so only sort when needed. (ENG-22985)
    if (!this._entriesSorted) {
      copy.sort((a, b) => a.startTime - b.startTime);
    }
    return copy;
  }

  /**
   * Get entries by name
   */
  getEntriesByName(name: string, type?: string): PerformanceEntry[] {
    const filtered = this._entries.filter(
      (e) => e.name === name && (!type || e.entryType === type)
    );
    if (!this._entriesSorted) {
      filtered.sort((a, b) => a.startTime - b.startTime);
    }
    return filtered;
  }

  /**
   * Get entries by type
   */
  getEntriesByType(type: string): PerformanceEntry[] {
    const filtered = this._entries.filter((e) => e.entryType === type);
    if (!this._entriesSorted) {
      filtered.sort((a, b) => a.startTime - b.startTime);
    }
    return filtered;
  }

  // Resource timing (stubs for compatibility)
  clearResourceTimings(): void {
    // No-op in Exact (no resource timing)
  }

  setResourceTimingBufferSize(_maxSize: number): void {
    // No-op in Exact
  }

  toJSON(): object {
    return {
      timeOrigin: this.timeOrigin,
    };
  }
}

// Mix in EventTarget methods on Performance.prototype so that
// `performance instanceof EventTarget` is true and addEventListener/
// dispatchEvent work correctly (per spec, Performance extends EventTarget).
// We do this as a mixin instead of class inheritance because Babel's
// ES5 transpilation of `class Performance extends EventTarget` doesn't
// properly set up the prototype chain when compiled to an IIFE for Hermes.
// EventTarget's constructor never runs for Performance (no super call), but its
// methods lazily initialize their listener storage, so BOTH the singleton and
// `new Performance()` instances have working addEventListener now. (ENG-22985)
Object.setPrototypeOf(Performance.prototype, EventTarget.prototype);

// Create singleton
export const performance = new Performance();

// =============================================================================
// PerformanceObserver
// =============================================================================

export interface PerformanceObserverInit {
  entryTypes?: string[];
  type?: string;
  buffered?: boolean;
}

export interface PerformanceObserverCallbackOptions {
  droppedEntriesCount?: number;
}

export type PerformanceObserverCallback = (
  entries: PerformanceObserverEntryList,
  observer: PerformanceObserver,
  options?: PerformanceObserverCallbackOptions
) => void;

export class PerformanceObserverEntryList {
  private _entries: PerformanceEntry[];

  constructor(entries: PerformanceEntry[]) {
    this._entries = entries;
  }

  getEntries(): PerformanceEntry[] {
    return [...this._entries].sort((a, b) => a.startTime - b.startTime);
  }

  getEntriesByName(name: string, type?: string): PerformanceEntry[] {
    return this._entries
      .filter((e) => e.name === name && (!type || e.entryType === type))
      .sort((a, b) => a.startTime - b.startTime);
  }

  getEntriesByType(type: string): PerformanceEntry[] {
    return this._entries
      .filter((e) => e.entryType === type)
      .sort((a, b) => a.startTime - b.startTime);
  }
}

// Store active observers
const observers = new Set<PerformanceObserver>();

/**
 * PerformanceObserver enables observing performance timeline entries.
 */
export class PerformanceObserver {
  private _callback: PerformanceObserverCallback;
  private _entryTypes: Set<string> = new Set();
  private _buffer: PerformanceEntry[] = [];
  private _isObserving = false;
  private _scheduled = false;

  /**
   * Supported entry types.
   */
  static get supportedEntryTypes(): readonly string[] {
    return Object.freeze(['mark', 'measure']);
  }

  constructor(callback: PerformanceObserverCallback) {
    if (typeof callback !== 'function') {
      throw new TypeError('Callback must be a function');
    }
    this._callback = callback;
  }

  /**
   * Start observing performance entries.
   */
  observe(options: PerformanceObserverInit): void {
    if (!options.entryTypes && !options.type) {
      throw new TypeError('Either entryTypes or type must be specified');
    }

    if (options.entryTypes && options.type) {
      throw new TypeError('Cannot specify both entryTypes and type');
    }

    this._entryTypes.clear();

    if (options.entryTypes) {
      for (let i = 0; i < options.entryTypes.length; i++) {
        const type = options.entryTypes[i];
        if (PerformanceObserver.supportedEntryTypes.includes(type)) {
          this._entryTypes.add(type);
        }
      }
    } else if (options.type) {
      if (PerformanceObserver.supportedEntryTypes.includes(options.type)) {
        this._entryTypes.add(options.type);
      }
    }

    if (this._entryTypes.size === 0) {
      // Per spec: if no supported entry types remain, silently return
      return;
    }

    // If buffered, only works with single `type` API (not `entryTypes`)
    if (options.buffered && options.type) {
      const existingEntries: PerformanceEntry[] = [];
      const timelineEntries = performance.getEntries();
      for (let i = 0; i < timelineEntries.length; i++) {
        const entry = timelineEntries[i];
        if (this._entryTypes.has(entry.entryType)) {
          existingEntries.push(entry);
        }
      }
      if (existingEntries.length > 0) {
        this._buffer.push(...existingEntries);
        this._scheduleCallback();
      }
    }

    this._isObserving = true;
    observers.add(this);
  }

  /**
   * Stop observing.
   */
  disconnect(): void {
    this._isObserving = false;
    this._buffer = [];
    observers.delete(this);
  }

  /**
   * Get buffered entries and clear the buffer.
   */
  takeRecords(): PerformanceEntry[] {
    const entries = [...this._buffer];
    this._buffer = [];
    return entries;
  }

  /**
   * Internal: Called when a new entry is added.
   */
  _notify(entry: PerformanceEntry): void {
    if (!this._isObserving) return;
    if (!this._entryTypes.has(entry.entryType)) return;

    this._buffer.push(entry);
    this._scheduleCallback();
  }

  private _scheduleCallback(): void {
    if (this._scheduled) return;
    this._scheduled = true;
    const observer = this;

    queueMicrotask(function() {
      observer._scheduled = false;
      if (observer._buffer.length === 0) return;

      const entries = observer.takeRecords();
      const list = new PerformanceObserverEntryList(entries);
      
      try {
        observer._callback(list, observer);
      } catch (e) {
        console.error('PerformanceObserver callback error:', e);
      }
    });
  }
}

/**
 * Notify all observers of a new entry.
 * Called internally when marks/measures are created.
 */
export function notifyObservers(entry: PerformanceEntry): void {
  for (const observer of observers) {
    observer._notify(entry);
  }
}

// Patch Performance to notify observers
const originalMark = Performance.prototype.mark;
Performance.prototype.mark = function(markName: string, markOptions?: PerformanceMarkOptions): PerformanceMark {
  const mark = originalMark.call(this, markName, markOptions);
  notifyObservers(mark);
  return mark;
};

const originalMeasure = Performance.prototype.measure;
Performance.prototype.measure = function(
  measureName: string,
  startOrMeasureOptions?: string | PerformanceMeasureOptions,
  endMark?: string
): PerformanceMeasure {
  const measure = originalMeasure.call(this, measureName, startOrMeasureOptions, endMark);
  notifyObservers(measure);
  return measure;
};
