/**
 * AbortController - Web Standard AbortController Implementation
 *
 * @see https://dom.spec.whatwg.org/#interface-abortcontroller
 */

import { AbortSignal } from "./AbortSignal";

export class AbortController {
  private _signal: AbortSignal;

  constructor() {
    this._signal = new AbortSignal();
  }

  get signal(): AbortSignal {
    return this._signal;
  }

  abort(reason?: any): void {
    (this._signal as any)._abort(reason);
  }
}
