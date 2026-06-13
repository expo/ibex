// @ts-nocheck
/**
 * Events module - EventTarget, Event, CustomEvent, DOMException, and specialized events
 */

export { Event, CustomEvent } from "./Event";
export type { EventInit, CustomEventInit } from "./Event";

export { EventTarget } from "./EventTarget";
export type {
  EventListener,
  EventListenerObject,
  EventListenerOrEventListenerObject,
  AddEventListenerOptions,
  EventListenerOptions,
} from "./EventTarget";

export {
  DOMException,
  createAbortError,
  createNetworkError,
  createTimeoutError,
  createQuotaExceededError,
  createDataCloneError,
  createInvalidStateError,
  createNotSupportedError,
  createSyntaxError,
  createSecurityError,
  createOperationError,
} from "./DOMException";

// Specialized event types
export { MessageEvent } from "./MessageEvent";
export type { MessageEventInit, MessageEventSource } from "./MessageEvent";

export { CloseEvent } from "./CloseEvent";
export type { CloseEventInit } from "./CloseEvent";

export { ErrorEvent } from "./ErrorEvent";
export type { ErrorEventInit } from "./ErrorEvent";

export { ProgressEvent } from "./ProgressEvent";
export type { ProgressEventInit } from "./ProgressEvent";

export { KeyboardEvent } from "./KeyboardEvent";
export type { KeyboardEventInit } from "./KeyboardEvent";

export { FocusEvent } from "./FocusEvent";
export type { FocusEventInit } from "./FocusEvent";

export { PromiseRejectionEvent } from "./PromiseRejectionEvent";
export type { PromiseRejectionEventInit } from "./PromiseRejectionEvent";
