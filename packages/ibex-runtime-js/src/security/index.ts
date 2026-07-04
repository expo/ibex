/**
 * Security module exports
 * 
 * Provides capability-based security for the Ibex runtime.
 * @see LLP 0013
 */

export * from './Capabilities';
export * from './Permissions';

// Re-export CapabilityDeniedError and related types from DOMException
export { 
  CapabilityDeniedError,
  type CapabilityDenialReason,
  type CapabilityDenialCategory,
} from '../events/DOMException';
