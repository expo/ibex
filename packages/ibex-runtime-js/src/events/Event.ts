/**
 * Event - Web Standard Event Implementation
 *
 * @see https://dom.spec.whatwg.org/#interface-event
 */

export interface EventInit {
  bubbles?: boolean;
  cancelable?: boolean;
  composed?: boolean;
}

// Shared getter function defined OUTSIDE the class so it is available before
// any Event instances are constructed (Babel transpiles static class fields as
// post-class assignments, but the constructor may run before those assignments
// in the same IIFE scope).  Per spec, desc1.get === desc2.get for different
// Event instances, so a single shared function is required.
const _isTrustedGetter = function(this: Event): boolean {
  return false;
};

export class Event {
  // Event phase constants
  static readonly NONE = 0;
  static readonly CAPTURING_PHASE = 1;
  static readonly AT_TARGET = 2;
  static readonly BUBBLING_PHASE = 3;

  readonly type: string;
  readonly bubbles: boolean;
  readonly cancelable: boolean;
  readonly composed: boolean;
  readonly timeStamp: number;
  // Mutable during dispatch
  private _target: EventTarget | null = null;
  private _currentTarget: EventTarget | null = null;
  private _eventPhase: number = Event.NONE;
  private _defaultPrevented: boolean = false;
  private _stopPropagationFlag: boolean = false;
  private _stopImmediatePropagationFlag: boolean = false;
  private _inPassiveListener: boolean = false;
  private _dispatchFlag: boolean = false;

  constructor(type: string, eventInitDict?: EventInit) {
    this.type = type;
    this.bubbles = eventInitDict?.bubbles ?? false;
    this.cancelable = eventInitDict?.cancelable ?? false;
    this.composed = eventInitDict?.composed ?? false;
    // Sandboxed embedders (snapback's deterministic handler tier) deny the
    // ambient clocks at runtime; an Event constructed on an internal dispatch
    // path (e.g. rejectionhandled) must not throw through that denial — a
    // zero timeStamp is truthful there, since no clock is observable at all.
    this.timeStamp = (() => {
      try {
        return performance?.now?.() ?? Date.now();
      } catch {
        return 0;
      }
    })();
    // Per spec, isTrusted must be an own property with a getter (no setter)
    // so that it shows up in Object.getOwnPropertyDescriptor().
    Object.defineProperty(this, "isTrusted", {
      get: _isTrustedGetter,
      configurable: false,
      enumerable: true,
    });
  }

  get target(): EventTarget | null {
    return this._target;
  }

  get currentTarget(): EventTarget | null {
    return this._currentTarget;
  }

  get eventPhase(): number {
    return this._eventPhase;
  }

  get defaultPrevented(): boolean {
    return this._defaultPrevented;
  }

  preventDefault(): void {
    if (this.cancelable && !this._inPassiveListener) {
      this._defaultPrevented = true;
    }
    // Per spec: calling preventDefault in a passive listener should be a no-op
    // but implementations may log a warning
  }

  stopPropagation(): void {
    this._stopPropagationFlag = true;
  }

  stopImmediatePropagation(): void {
    this._stopPropagationFlag = true;
    this._stopImmediatePropagationFlag = true;
  }

  composedPath(): EventTarget[] {
    // In a non-DOM environment, the path is just the target
    if (this._target) {
      return [this._target];
    }
    return [];
  }

  // Internal methods for EventTarget dispatch
  /** @internal */
  _setTarget(target: EventTarget | null): void {
    this._target = target;
  }

  /** @internal */
  _setCurrentTarget(currentTarget: EventTarget | null): void {
    this._currentTarget = currentTarget;
  }

  /** @internal */
  _setEventPhase(phase: number): void {
    this._eventPhase = phase;
  }

  /** @internal */
  _isPropagationStopped(): boolean {
    return this._stopPropagationFlag;
  }

  /** @internal */
  _isImmediatePropagationStopped(): boolean {
    return this._stopImmediatePropagationFlag;
  }

  /** @internal */
  _resetFlags(): void {
    // Per the DOM spec's dispatch algorithm, once dispatch finishes only the
    // propagation flags are unset. The canceled flag (defaultPrevented) is NOT
    // reset: it must remain observable to the caller after dispatchEvent returns
    // (the common `if (e.defaultPrevented)` follow-up) and it persists across a
    // later re-dispatch of the same Event. (ENG-22985)
    this._stopPropagationFlag = false;
    this._stopImmediatePropagationFlag = false;
    this._eventPhase = Event.NONE;
    this._inPassiveListener = false;
  }

  /** @internal */
  _isBeingDispatched(): boolean {
    return this._dispatchFlag;
  }

  /** @internal */
  _setDispatchFlag(value: boolean): void {
    this._dispatchFlag = value;
  }

  /** @internal */
  _setInPassiveListener(passive: boolean): void {
    this._inPassiveListener = passive;
  }
}

export interface CustomEventInit<T = any> extends EventInit {
  detail?: T;
}

export class CustomEvent<T = any> extends Event {
  readonly detail: T;

  constructor(type: string, eventInitDict?: CustomEventInit<T>) {
    super(type, eventInitDict);
    this.detail = eventInitDict?.detail as T;
  }
}
