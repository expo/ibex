/**
 * Security module exports
 * 
 * Provides capability-based security for the Exact runtime.
 * @see JS_RUNTIME_SECURITY.md
 */

export * from './Capabilities';
export * from './Permissions';

// Re-export CapabilityDeniedError and related types from DOMException
export { 
  CapabilityDeniedError,
  type CapabilityDenialReason,
  type CapabilityDenialCategory,
} from '../events/DOMException';
