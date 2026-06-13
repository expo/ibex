/**
 * DOMException - Web Standard DOMException Implementation
 *
 * @see https://webidl.spec.whatwg.org/#dfn-DOMException
 */

// Legacy error code mapping
// Note: NotAllowedError (0) is a newer error without a legacy code
const legacyErrorCodes: Record<string, number> = {
  IndexSizeError: 1,
  DOMStringSizeError: 2,
  HierarchyRequestError: 3,
  WrongDocumentError: 4,
  InvalidCharacterError: 5,
  NoDataAllowedError: 6,
  NoModificationAllowedError: 7,
  NotFoundError: 8,
  NotSupportedError: 9,
  InUseAttributeError: 10,
  InvalidStateError: 11,
  SyntaxError: 12,
  InvalidModificationError: 13,
  NamespaceError: 14,
  InvalidAccessError: 15,
  ValidationError: 16,
  TypeMismatchError: 17,
  SecurityError: 18,
  NetworkError: 19,
  AbortError: 20,
  URLMismatchError: 21,
  QuotaExceededError: 22,
  TimeoutError: 23,
  InvalidNodeTypeError: 24,
  DataCloneError: 25,
  // Modern errors without legacy codes
  NotAllowedError: 0,
  OperationError: 0,
  NotReadableError: 0,
  UnknownError: 0,
  ConstraintError: 0,
  TransactionInactiveError: 0,
  ReadOnlyError: 0,
  VersionError: 0,
};

export class DOMException implements Error {
  // Legacy error code constants
  declare static readonly INDEX_SIZE_ERR: number;
  declare static readonly DOMSTRING_SIZE_ERR: number;
  declare static readonly HIERARCHY_REQUEST_ERR: number;
  declare static readonly WRONG_DOCUMENT_ERR: number;
  declare static readonly INVALID_CHARACTER_ERR: number;
  declare static readonly NO_DATA_ALLOWED_ERR: number;
  declare static readonly NO_MODIFICATION_ALLOWED_ERR: number;
  declare static readonly NOT_FOUND_ERR: number;
  declare static readonly NOT_SUPPORTED_ERR: number;
  declare static readonly INUSE_ATTRIBUTE_ERR: number;
  declare static readonly INVALID_STATE_ERR: number;
  declare static readonly SYNTAX_ERR: number;
  declare static readonly INVALID_MODIFICATION_ERR: number;
  declare static readonly NAMESPACE_ERR: number;
  declare static readonly INVALID_ACCESS_ERR: number;
  declare static readonly VALIDATION_ERR: number;
  declare static readonly TYPE_MISMATCH_ERR: number;
  declare static readonly SECURITY_ERR: number;
  declare static readonly NETWORK_ERR: number;
  declare static readonly ABORT_ERR: number;
  declare static readonly URL_MISMATCH_ERR: number;
  declare static readonly QUOTA_EXCEEDED_ERR: number;
  declare static readonly TIMEOUT_ERR: number;
  declare static readonly INVALID_NODE_TYPE_ERR: number;
  declare static readonly DATA_CLONE_ERR: number;

  readonly name: string;
  readonly message: string;
  readonly code: number;
  stack?: string;

  constructor(message?: string, name?: string) {
    this.message = message ?? "";
    this.name = name ?? "Error";
    this.code = legacyErrorCodes[this.name] ?? 0;

    // Maintain proper stack trace in V8/Hermes
    if (typeof Error.captureStackTrace === "function") {
      Error.captureStackTrace(this, DOMException);
    } else {
      this.stack = new Error(this.message).stack;
    }
  }

  // Override toString for proper formatting
  toString(): string {
    return `${this.name}: ${this.message}`;
  }
}

Object.setPrototypeOf(DOMException.prototype, Error.prototype);
Object.setPrototypeOf(DOMException, Error);
Object.defineProperties(DOMException, {
  INDEX_SIZE_ERR: { value: 1, enumerable: true, configurable: true },
  DOMSTRING_SIZE_ERR: { value: 2, enumerable: true, configurable: true },
  HIERARCHY_REQUEST_ERR: { value: 3, enumerable: true, configurable: true },
  WRONG_DOCUMENT_ERR: { value: 4, enumerable: true, configurable: true },
  INVALID_CHARACTER_ERR: { value: 5, enumerable: true, configurable: true },
  NO_DATA_ALLOWED_ERR: { value: 6, enumerable: true, configurable: true },
  NO_MODIFICATION_ALLOWED_ERR: { value: 7, enumerable: true, configurable: true },
  NOT_FOUND_ERR: { value: 8, enumerable: true, configurable: true },
  NOT_SUPPORTED_ERR: { value: 9, enumerable: true, configurable: true },
  INUSE_ATTRIBUTE_ERR: { value: 10, enumerable: true, configurable: true },
  INVALID_STATE_ERR: { value: 11, enumerable: true, configurable: true },
  SYNTAX_ERR: { value: 12, enumerable: true, configurable: true },
  INVALID_MODIFICATION_ERR: { value: 13, enumerable: true, configurable: true },
  NAMESPACE_ERR: { value: 14, enumerable: true, configurable: true },
  INVALID_ACCESS_ERR: { value: 15, enumerable: true, configurable: true },
  VALIDATION_ERR: { value: 16, enumerable: true, configurable: true },
  TYPE_MISMATCH_ERR: { value: 17, enumerable: true, configurable: true },
  SECURITY_ERR: { value: 18, enumerable: true, configurable: true },
  NETWORK_ERR: { value: 19, enumerable: true, configurable: true },
  ABORT_ERR: { value: 20, enumerable: true, configurable: true },
  URL_MISMATCH_ERR: { value: 21, enumerable: true, configurable: true },
  QUOTA_EXCEEDED_ERR: { value: 22, enumerable: true, configurable: true },
  TIMEOUT_ERR: { value: 23, enumerable: true, configurable: true },
  INVALID_NODE_TYPE_ERR: { value: 24, enumerable: true, configurable: true },
  DATA_CLONE_ERR: { value: 25, enumerable: true, configurable: true },
});

// Ensure constructor.name survives minification/bundling.
Object.defineProperty(DOMException, 'name', { value: 'DOMException', configurable: true });
Object.defineProperty(DOMException.prototype, Symbol.toStringTag, {
  value: 'DOMException',
  configurable: true,
});

function createGlobalDOMException(message: string, name: string): DOMException {
  const globalCtor =
    typeof globalThis === "object" &&
    globalThis !== null &&
    typeof (globalThis as any).DOMException === "function"
      ? ((globalThis as any).DOMException as new (message?: string, name?: string) => DOMException)
      : DOMException;
  return new globalCtor(message, name);
}

// Common exception factory functions for convenience
export function createAbortError(message = "The operation was aborted."): DOMException {
  return createGlobalDOMException(message, "AbortError");
}

export function createNetworkError(message = "A network error occurred."): DOMException {
  return createGlobalDOMException(message, "NetworkError");
}

export function createTimeoutError(message = "The operation timed out."): DOMException {
  return createGlobalDOMException(message, "TimeoutError");
}

export function createQuotaExceededError(message = "The quota has been exceeded."): DOMException {
  return createGlobalDOMException(message, "QuotaExceededError");
}

export function createDataCloneError(message = "The object could not be cloned."): DOMException {
  return createGlobalDOMException(message, "DataCloneError");
}

export function createInvalidStateError(message = "The object is in an invalid state."): DOMException {
  return createGlobalDOMException(message, "InvalidStateError");
}

export function createNotSupportedError(message = "The operation is not supported."): DOMException {
  return createGlobalDOMException(message, "NotSupportedError");
}

export function createSyntaxError(message = "A syntax error occurred."): DOMException {
  return createGlobalDOMException(message, "SyntaxError");
}

export function createSecurityError(message = "A security error occurred."): DOMException {
  return createGlobalDOMException(message, "SecurityError");
}

export function createOperationError(message = "The operation failed."): DOMException {
  return createGlobalDOMException(message, "OperationError");
}

/**
 * Create a NotAllowedError for capability/permission denials.
 * Used when a capability check fails.
 * @see JS_RUNTIME_SECURITY.md Section 10
 */
export function createNotAllowedError(message = "The request is not allowed."): DOMException {
  return createGlobalDOMException(message, "NotAllowedError");
}

/**
 * Denial reasons for capability errors.
 * Aligned with JS_CAPABILITY_SECURITY_MODEL_SPEC_AND_PLAN.md
 * 
 * Note: Uses string intersection to allow unknown reasons for forward compatibility.
 * New OS versions may introduce new denial reasons.
 */
export type CapabilityDenialReason =
  | 'os_denied'          // User denied at OS level
  | 'os_restricted'      // System policy (parental controls, MDM)
  | 'broker_denied'      // View broker denied
  | 'module_not_granted' // Import capability missing
  | 'app_not_granted'    // App root capability missing
  | 'requires_settings'  // User must enable in Settings
  | 'capability_unknown' // Capability not recognized by runtime
  | 'os_version_too_low' // OS version doesn't support this capability
  | 'temporarily_unavailable' // Capability temporarily unavailable
  | (string & {});       // Forward compatibility for unknown reasons

/**
 * Broad categories for denial reasons.
 * Use this in switch statements for forward-compatible handling.
 */
export type CapabilityDenialCategory =
  | 'user_action_required'    // User can fix by granting permission
  | 'system_restricted'       // System policy prevents access
  | 'not_configured'          // App/module hasn't been granted capability
  | 'temporarily_unavailable' // May work later
  | 'permanently_unavailable' // Will never work on this device/OS
  | 'unknown';                // Unrecognized reason - handle gracefully

/**
 * Error thrown when a capability check fails.
 * Extends DOMException with additional context for capability denials.
 * 
 * Designed for forward compatibility:
 * - Use `reasonCategory` for switch statements (handles unknown reasons)
 * - Use `denialReason` for logging/debugging (may contain future values)
 * - Check `canRequestAgain` to know if prompting user is possible
 * 
 * @example
 * ```ts
 * try {
 *   requireCapability('device:location');
 * } catch (e) {
 *   if (e instanceof CapabilityDeniedError) {
 *     switch (e.reasonCategory) {
 *       case 'user_action_required':
 *         showPermissionPrompt(e.settingsUrl);
 *         break;
 *       case 'permanently_unavailable':
 *         hideLocationFeature();
 *         break;
 *       default:
 *         showGenericError(e.getUserMessage());
 *     }
 *   }
 * }
 * ```
 * 
 * @see JS_CAPABILITY_SECURITY_MODEL_SPEC_AND_PLAN.md
 */
export class CapabilityDeniedError extends DOMException {
  /**
   * The capability that was denied
   */
  readonly capability: string;
  
  /**
   * The specific reason for the denial.
   * May contain values not in CapabilityDenialReason type for forward compatibility.
   */
  readonly denialReason: CapabilityDenialReason;
  
  /**
   * Broad category for the denial reason.
   * Use this for switch statements to handle unknown reasons gracefully.
   */
  readonly reasonCategory: CapabilityDenialCategory;
  
  /**
   * Whether the capability can be requested again (e.g., via permission prompt)
   */
  readonly canRequestAgain: boolean;
  
  /**
   * URL to settings where user can enable this capability (platform-specific)
   */
  readonly settingsUrl?: string;
  
  /**
   * Additional platform-specific metadata.
   * May contain information about why the capability was denied.
   */
  readonly metadata?: Record<string, unknown>;

  constructor(
    capability: string,
    reason: CapabilityDenialReason = 'module_not_granted',
    canRequestAgain: boolean = false,
    settingsUrl?: string,
    metadata?: Record<string, unknown>,
  ) {
    super(`Capability denied: ${capability}`, 'NotAllowedError');
    this.capability = capability;
    this.denialReason = reason;
    this.reasonCategory = this._categorizeReason(reason);
    this.canRequestAgain = canRequestAgain;
    this.settingsUrl = settingsUrl;
    this.metadata = metadata;
    
    // Maintain proper stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, CapabilityDeniedError);
    }
  }

  /**
   * Categorize a denial reason for forward-compatible handling.
   */
  private _categorizeReason(reason: CapabilityDenialReason): CapabilityDenialCategory {
    switch (reason) {
      case 'os_denied':
      case 'requires_settings':
        return 'user_action_required';
      
      case 'os_restricted':
        return 'system_restricted';
      
      case 'broker_denied':
      case 'module_not_granted':
      case 'app_not_granted':
        return 'not_configured';
      
      case 'temporarily_unavailable':
        return 'temporarily_unavailable';
      
      case 'capability_unknown':
      case 'os_version_too_low':
        return 'permanently_unavailable';
      
      default:
        // Unknown reason - return 'unknown' for forward compatibility
        return 'unknown';
    }
  }

  /**
   * Returns a user-friendly message based on the denial reason.
   * Handles unknown reasons gracefully.
   */
  getUserMessage(): string {
    // Handle known reasons with specific messages
    switch (this.denialReason) {
      case 'os_denied':
        return `Permission for ${this.capability} was denied. ${this.canRequestAgain ? 'You can request access again.' : 'Please enable it in system settings.'}`;
      case 'os_restricted':
        return `Access to ${this.capability} is restricted by system policy.`;
      case 'broker_denied':
        return `The application does not have permission for ${this.capability}.`;
      case 'module_not_granted':
        return `This module does not have the ${this.capability} capability.`;
      case 'app_not_granted':
        return `This application does not have the ${this.capability} capability.`;
      case 'requires_settings':
        return `Please enable ${this.capability} in Settings.`;
      case 'capability_unknown':
        return `The capability ${this.capability} is not available on this device.`;
      case 'os_version_too_low':
        return `The capability ${this.capability} requires a newer operating system version.`;
      case 'temporarily_unavailable':
        return `The capability ${this.capability} is temporarily unavailable. Please try again later.`;
    }
    
    // For unknown reasons, use category to provide helpful message
    switch (this.reasonCategory) {
      case 'user_action_required':
        return `Permission required for ${this.capability}. Please grant access in settings.`;
      case 'system_restricted':
        return `Access to ${this.capability} is restricted.`;
      case 'not_configured':
        return `The capability ${this.capability} has not been configured.`;
      case 'temporarily_unavailable':
        return `${this.capability} is temporarily unavailable.`;
      case 'permanently_unavailable':
        return `${this.capability} is not available on this device.`;
      default:
        return `Capability denied: ${this.capability}`;
    }
  }
  
  /**
   * Check if this error is for an unknown/future reason.
   * Useful for logging or analytics.
   */
  isUnknownReason(): boolean {
    return this.reasonCategory === 'unknown';
  }
}

/**
 * Create a NotAllowedError specifically for capability denials.
 * Includes the capability name in the message for debugging.
 * 
 * @deprecated Use CapabilityDeniedError directly for more context
 */
export function createCapabilityDeniedError(
  capability: string,
  reason?: CapabilityDenialReason,
  canRequestAgain?: boolean,
  settingsUrl?: string,
  metadata?: Record<string, unknown>,
): CapabilityDeniedError {
  return new CapabilityDeniedError(capability, reason, canRequestAgain, settingsUrl, metadata);
}
