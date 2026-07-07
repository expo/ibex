/**
 * Capability Security System for Ibex Runtime
 * 
 * Implements the capability-based security model described by LLP 0013.
 * 
 * The effective permission for any privileged action is the intersection of:
 * 1. OS Permission (root) - enforced at native layer
 * 2. App Root Capabilities - set when runtime is created
 * 3. View Broker Grant - per-view user consent
 * 4. Module Import Capabilities - per-module grants
 * 
 * @see LLP 0013
 * @see LLP 0014
 */

import { 
  CapabilityDeniedError, 
  createCapabilityDeniedError,
  type CapabilityDenialReason,
} from '../events/DOMException';
import { CapabilityBit } from './capability-bits.generated';

export { CapabilityBit } from './capability-bits.generated';

// ============================================================================
// Capability Types
// ============================================================================

/**
 * Capability categories aligned with LLP 0013.
 */
export type CapabilityCategory =
  | 'fs'
  | 'network'
  | 'env'
  | 'process'
  | 'ipc'
  | 'crypto'
  | 'time'
  | 'device'
  | 'storage'
  | 'clipboard'
  | 'sqlite';

/**
 * Full capability specification with optional parameters.
 * Examples:
 * - "network:fetch" - general fetch capability
 * - "network:fetch:api.example.com" - fetch to specific host
 * - "fs:read:/data" - read from specific path
 * - "device:location" - device location access
 */
export type Capability = string;

/**
 * Denial reasons aligned with LLP 0013.
 * 
 * Note: This is intentionally a string type (not a union) to allow for
 * forward compatibility with new denial reasons from future OS versions.
 * Use DenialReasonCategory for switch statements to handle unknown reasons.
 */
export type DenialReason =
  | 'os_denied'          // User denied at OS level
  | 'os_restricted'      // System policy (parental controls, MDM)
  | 'broker_denied'      // View broker denied
  | 'module_not_granted' // Import capability missing
  | 'app_not_granted'    // App root capability missing
  | 'requires_settings'  // User must enable in Settings
  | 'capability_unknown' // Capability not recognized by runtime
  | 'os_version_too_low' // OS version doesn't support this capability
  | 'temporarily_unavailable' // Capability temporarily unavailable (e.g., airplane mode)
  | (string & {});       // Allow unknown reasons for forward compatibility

/**
 * Broad categories for denial reasons.
 * Use this for switch statements to handle unknown specific reasons gracefully.
 * 
 * @example
 * ```ts
 * const category = getDenialReasonCategory(error.denialReason);
 * switch (category) {
 *   case 'user_action_required':
 *     // Show UI to guide user to settings
 *     break;
 *   case 'permanently_unavailable':
 *     // Hide the feature entirely
 *     break;
 *   case 'temporarily_unavailable':
 *     // Show retry option
 *     break;
 *   default:
 *     // Generic "permission denied" message
 * }
 * ```
 */
export type DenialReasonCategory =
  | 'user_action_required'    // User can fix by granting permission
  | 'system_restricted'       // System policy prevents access
  | 'not_configured'          // App/module hasn't been granted capability
  | 'temporarily_unavailable' // May work later (network issues, etc.)
  | 'permanently_unavailable' // Will never work (OS too old, etc.)
  | 'unknown';                // Unrecognized reason

/**
 * Map a denial reason to its broad category for forward-compatible handling.
 */
export function getDenialReasonCategory(reason: DenialReason): DenialReasonCategory {
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
      // Forward compatibility: unknown reasons default to 'unknown'
      // This allows new OS-specific reasons to be handled gracefully
      return 'unknown';
  }
}

/**
 * Capability check result with reason for denials
 */
export interface CapabilityCheckResult {
  allowed: boolean;
  reason?: DenialReason;
  capability: Capability;
  /** Whether the capability can be requested again */
  canRequestAgain?: boolean;
}

/**
 * Audit log event for capability checks
 */
export interface CapabilityAuditEvent {
  event: 'capability_granted' | 'capability_denied';
  /** The action being performed */
  action: 'check' | 'request' | 'use';
  capability: Capability;
  moduleId?: number;
  source: 'os' | 'broker' | 'module' | 'app';
  reason?: string;
  timestamp: number;
}

// ============================================================================
// Native Capability Module Interface
// ============================================================================

/**
 * Interface for the native capability checking module.
 * The native layer is the authoritative source for capability enforcement.
 */
export interface NativeCapabilityModule {
  /**
   * Check if a capability is granted.
   * This should verify all layers: OS, app root, broker, and module.
   */
  checkCapability(capability: Capability, moduleId?: number): boolean;
  
  /**
   * Request a capability from the broker (may trigger user prompt).
   * Returns true if granted, false if denied.
   */
  requestCapability(capability: Capability): Promise<boolean>;
  
  /**
   * Get the current capability grants for the view.
   */
  getGrantedCapabilities(): Capability[];
  
  /**
   * Register an audit callback for capability events.
   */
  onAuditEvent?(callback: (event: CapabilityAuditEvent) => void): void;
}

// ============================================================================
// Capability Registry
// ============================================================================

let _nativeCapabilityModule: NativeCapabilityModule | null = null;
let _auditCallbacks: Array<(event: CapabilityAuditEvent) => void> = [];

// In-memory fallback for testing (grants everything)
let _testMode = false;
let _testGrants = new Set<Capability>();
let _silentMode = false;

// Strict mode - when enabled, denies capabilities without native module
// Default is lax mode (allows all) to avoid friction during development
let _strictMode = false;

// Track capabilities we've warned about to reduce console noise
const _warnedCapabilities = new Set<Capability>();

/**
 * Check if we should suppress security warnings (for tests).
 */
export function isSilentMode(): boolean {
  return _silentMode;
}

/**
 * Check if strict capability enforcement is enabled.
 */
export function isStrictMode(): boolean {
  return _strictMode;
}

/**
 * Enable strict capability enforcement.
 *
 * When strict mode is enabled, capability checks will DENY requests
 * when no native capability module is available. This is the secure
 * behavior for production apps.
 *
 * By default, the capability system is LAX - it allows all capabilities
 * when no native module is present, to reduce friction during development.
 *
 * Call this during app initialization for production builds:
 * ```ts
 * import { enableStrictMode } from '@exact/runtime/security';
 *
 * if (__PROD__) {
 *   enableStrictMode();
 * }
 * ```
 *
 * The native layer should call this automatically for release builds.
 */
export function enableStrictMode(): void {
  _strictMode = true;
}

/**
 * Disable strict capability enforcement (return to lax mode).
 * Primarily useful for testing.
 */
export function disableStrictMode(): void {
  _strictMode = false;
}

/**
 * Set the native capability module.
 * Called by the native layer during runtime initialization.
 */
export function setNativeCapabilityModule(module: NativeCapabilityModule): void {
  _nativeCapabilityModule = module;
  
  // Register audit callback forwarding
  if (module.onAuditEvent) {
    module.onAuditEvent((event) => {
      _auditCallbacks.forEach(cb => {
        try {
          cb(event);
        } catch (e) {
          console.error('Capability audit callback error:', e);
        }
      });
    });
  }
}

/**
 * Get the native capability module.
 */
export function getNativeCapabilityModule(): NativeCapabilityModule | null {
  return _nativeCapabilityModule;
}

/**
 * Options for test mode.
 */
export interface TestModeOptions {
  /** Capability grants to pre-configure */
  grants?: Capability[];
  /** Suppress security warnings in console (default: true) */
  silent?: boolean;
}

/**
 * Enable test mode with specified grants.
 * WARNING: Only use in test environments!
 *
 * @param grantsOrOptions - Either an array of grants (legacy) or options object
 */
export function enableTestMode(grantsOrOptions: Capability[] | TestModeOptions = {}): void {
  if (_strictMode) {
    throw new Error('Cannot enable capability test mode when strict mode is enabled');
  }

  // Handle legacy array signature
  if (Array.isArray(grantsOrOptions)) {
    _testMode = true;
    _testGrants = new Set(grantsOrOptions);
    _silentMode = true; // Default to silent for legacy callers (tests)
    return;
  }

  const options = grantsOrOptions;
  _testMode = true;
  _testGrants = new Set(options.grants ?? []);
  _silentMode = options.silent ?? true;
}

/**
 * Disable test mode.
 */
export function disableTestMode(): void {
  _testMode = false;
  _testGrants.clear();
  _silentMode = false;
}

/**
 * Add a capability grant in test mode.
 */
export function addTestGrant(capability: Capability): void {
  if (!_testMode) {
    throw new Error('Test mode not enabled');
  }
  _testGrants.add(capability);
}

// ============================================================================
// Capability Checking
// ============================================================================

/**
 * Check if a capability is granted.
 * 
 * @param capability The capability to check (e.g., "network:fetch", "device:location")
 * @param moduleId Optional module ID for per-module checks
 * @returns CapabilityCheckResult with allowed status and denial reason
 */
export function checkCapability(capability: Capability, moduleId?: number): CapabilityCheckResult {
  // Fast path: if moduleId provided and we have a cached bitmask
  if (moduleId !== undefined && !_testMode) {
    const bit = getCapabilityBit(capability);
    if (bit !== undefined) {
      const bits = _effectiveBits.get(moduleId);
      if (bits) {
        const gen = _cachedGeneration.get(moduleId);
        if (gen === _permissionGeneration) {
          const allowed = bit < 32
            ? (bits[0] & (1 << bit)) !== 0
            : (bits[1] & (1 << (bit - 32))) !== 0;
          if (allowed) {
            return { allowed: true, capability };
          }
          // Fall through to slow path for detailed denial reason
        }
      }
    }
  }

  // Test mode - check in-memory grants
  if (_testMode) {
    const allowed = [..._testGrants].some((grant) => capabilityMatches(capability, grant));
    
    logAuditEvent({
      event: allowed ? 'capability_granted' : 'capability_denied',
      action: 'check',
      capability,
      moduleId,
      source: 'module',
      reason: allowed ? undefined : 'Test mode: capability not in grants',
      timestamp: Date.now(),
    });
    
    return {
      allowed,
      reason: allowed ? undefined : 'module_not_granted',
      capability,
    };
  }
  
  // Native module - delegate to native layer
  if (_nativeCapabilityModule) {
    const allowed = _nativeCapabilityModule.checkCapability(capability, moduleId);
    return {
      allowed,
      reason: allowed ? undefined : 'module_not_granted',
      capability,
    };
  }
  
  // No native module and not in test mode
  // Behavior depends on strict mode:
  // - Strict mode (opt-in): deny all - secure for production
  // - Lax mode (default): allow all - friendly for development

  if (_strictMode) {
    if (!_silentMode) {
      console.warn(`[Security] Capability denied (strict mode): ${capability}`);
    }
    return {
      allowed: false,
      reason: 'app_not_granted',
      capability,
    };
  }

  // Lax mode - allow with warning (only warn once per capability to reduce noise)
  if (!_silentMode && !_warnedCapabilities.has(capability)) {
    _warnedCapabilities.add(capability);
    console.warn(
      `[Security] No capability module available. ` +
      `Allowing "${capability}" in lax mode. ` +
      `Call enableStrictMode() for production security.`
    );
  }

  return {
    allowed: true,
    capability,
  };
}

/**
 * Require a capability, throwing CapabilityDeniedError if not granted.
 * Use this for synchronous capability checks.
 * 
 * @param capability The capability to require
 * @param moduleId Optional module ID
 * @throws CapabilityDeniedError if capability is denied
 */
export function requireCapability(capability: Capability, moduleId?: number): void {
  const result = checkCapability(capability, moduleId);
  if (!result.allowed) {
    throw new CapabilityDeniedError(
      capability,
      result.reason,
      result.canRequestAgain,
    );
  }
}

/**
 * Request a capability from the broker.
 * This may trigger a user permission prompt.
 * 
 * @param capability The capability to request
 * @returns Promise resolving to true if granted, false if denied
 */
export async function requestCapability(capability: Capability): Promise<boolean> {
  // Test mode
  if (_testMode) {
    return _testGrants.has(capability) || 
           _testGrants.has('*') ||
           _testGrants.has(capability.split(':')[0] + ':*');
  }
  
  // Native module
  if (_nativeCapabilityModule) {
    return _nativeCapabilityModule.requestCapability(capability);
  }
  
  // No native module - behavior depends on strict mode
  return !_strictMode;
}

/**
 * Get all currently granted capabilities.
 */
export function getGrantedCapabilities(): Capability[] {
  if (_testMode) {
    return Array.from(_testGrants);
  }
  
  if (_nativeCapabilityModule) {
    return _nativeCapabilityModule.getGrantedCapabilities();
  }
  
  return [];
}

// ============================================================================
// Audit Logging
// ============================================================================

/**
 * Register a callback for capability audit events.
 * 
 * @param callback Function called for each audit event
 * @returns Unsubscribe function
 */
export function onCapabilityAudit(
  callback: (event: CapabilityAuditEvent) => void
): () => void {
  _auditCallbacks.push(callback);
  return () => {
    const index = _auditCallbacks.indexOf(callback);
    if (index !== -1) {
      _auditCallbacks.splice(index, 1);
    }
  };
}

/**
 * Log an audit event.
 * Called internally and can be called by native layer.
 */
export function logAuditEvent(event: CapabilityAuditEvent): void {
  _auditCallbacks.forEach(cb => {
    try {
      cb(event);
    } catch (e) {
      console.error('Capability audit callback error:', e);
    }
  });
}

// ============================================================================
// Capability Introspection (Future-Proofing)
// ============================================================================

/**
 * Permission status for a capability.
 * Mirrors common OS permission states.
 */
export type CapabilityStatus =
  | 'granted'        // Permission is granted
  | 'denied'         // Permission was explicitly denied
  | 'not_determined' // User hasn't been asked yet
  | 'restricted'     // System policy prevents access
  | 'limited'        // Partial access (e.g., limited photo selection)
  | 'unknown';       // Status cannot be determined

/**
 * Detailed information about a capability.
 * Use this to understand what a capability is and how to handle it.
 */
export interface CapabilityInfo {
  /** The capability string */
  capability: Capability;
  
  /** Whether this capability is recognized by the runtime */
  exists: boolean;
  
  /** Current permission status */
  status: CapabilityStatus;
  
  /** Whether the app can request this capability (show permission prompt) */
  canRequest: boolean;
  
  /** Whether the capability is currently usable */
  isUsable: boolean;
  
  /** Minimum OS version required (e.g., "iOS 14.0", "Android 13") */
  minimumOSVersion?: string;
  
  /** Current OS version */
  currentOSVersion?: string;
  
  /** If deprecated, what capability replaces this one */
  replacedBy?: Capability[];
  
  /** If this is a new capability, what it replaces */
  replaces?: Capability[];
  
  /** Human-readable description of what this capability grants */
  description?: string;
  
  /** URL to open system settings for this capability */
  settingsUrl?: string;
  
  /** Additional platform-specific metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Information about the capability system itself.
 */
export interface CapabilitySystemInfo {
  /** Version of the capability API */
  apiVersion: string;
  
  /** List of all known capabilities */
  knownCapabilities: Capability[];
  
  /** Operating system name */
  osName: 'ios' | 'android' | 'web' | 'windows' | 'macos' | 'unknown';
  
  /** Operating system version */
  osVersion: string;
  
  /** Ibex runtime version */
  runtimeVersion: string;
}

/**
 * Extended native module interface for introspection.
 * Native implementations should implement these for full future-proofing support.
 */
export interface NativeCapabilityModuleV2 extends NativeCapabilityModule {
  /** Get detailed information about a capability */
  getCapabilityInfo?(capability: Capability): CapabilityInfo;
  
  /** Get system information */
  getSystemInfo?(): CapabilitySystemInfo;
  
  /** Get capabilities required by an API */
  getRequiredCapabilities?(apiName: string): Capability[];
  
  /** Check if a capability exists (is known to the system) */
  capabilityExists?(capability: Capability): boolean;
}

// Current API version - bump when making breaking changes
const CAPABILITY_API_VERSION = '1.0.0';

/**
 * Get detailed information about a capability.
 * 
 * Use this to:
 * - Check if a capability exists before using it
 * - Determine if user can be prompted for permission
 * - Get the settings URL to direct users to enable permission
 * - Check OS version requirements
 * 
 * @example
 * ```ts
 * const info = getCapabilityInfo('device:location:precise');
 * if (!info.exists) {
 *   // Fall back to coarse location
 *   const coarseInfo = getCapabilityInfo('device:location');
 *   // ...
 * } else if (info.status === 'denied' && !info.canRequest) {
 *   // Direct user to settings
 *   showSettingsPrompt(info.settingsUrl);
 * }
 * ```
 */
export function getCapabilityInfo(capability: Capability): CapabilityInfo {
  // Check if native module supports introspection
  const module = _nativeCapabilityModule as NativeCapabilityModuleV2 | null;
  if (module?.getCapabilityInfo) {
    return module.getCapabilityInfo(capability);
  }
  
  // Fallback implementation for testing and development
  const isKnown = isKnownCapability(capability);
  const checkResult = checkCapability(capability);
  
  return {
    capability,
    exists: isKnown,
    status: checkResult.allowed ? 'granted' : 'not_determined',
    canRequest: isKnown && !checkResult.allowed,
    isUsable: checkResult.allowed,
    description: getCapabilityDescription(capability),
  };
}

/**
 * Get information about the capability system.
 */
export function getCapabilitySystemInfo(): CapabilitySystemInfo {
  const module = _nativeCapabilityModule as NativeCapabilityModuleV2 | null;
  if (module?.getSystemInfo) {
    return module.getSystemInfo();
  }

  const fallback = getFallbackCapabilitySystemInfo();

  // Fallback for testing
  return {
    apiVersion: CAPABILITY_API_VERSION,
    knownCapabilities: Object.values(Capabilities),
    osName: fallback.osName,
    osVersion: fallback.osVersion,
    runtimeVersion: fallback.runtimeVersion,
  };
}

function getFallbackCapabilitySystemInfo(): Pick<
  CapabilitySystemInfo,
  'osName' | 'osVersion' | 'runtimeVersion'
> {
  const globalHints = globalThis as {
    __exactPlatform?: unknown;
    __exactPlatformVersion?: unknown;
    process?: {
      platform?: unknown;
      version?: unknown;
      __exactOSRelease?: unknown;
      __exactOSVersion?: unknown;
    };
  };
  const processHints =
    globalHints.process && typeof globalHints.process === 'object'
      ? globalHints.process
      : undefined;
  const platform = readNonEmptyString(globalHints.__exactPlatform) ??
    readNonEmptyString(processHints?.platform);
  const osName = normalizeCapabilityOSName(platform);

  // @ref LLP 0008#os-info — Android permission diagnostics use the Java host SDK version.
  const osVersion = osName === 'android'
    ? readNonEmptyString(globalHints.__exactPlatformVersion) ??
      readNonEmptyString(processHints?.__exactOSRelease) ??
      stripAndroidVersionPrefix(readNonEmptyString(processHints?.__exactOSVersion)) ??
      'unknown'
    : 'unknown';

  return {
    osName,
    osVersion,
    runtimeVersion: readNonEmptyString(processHints?.version) ?? 'development',
  };
}

function readNonEmptyString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function stripAndroidVersionPrefix(value: string | undefined): string | undefined {
  if (!value) return undefined;
  return value.replace(/^Android\s+/, '');
}

function normalizeCapabilityOSName(platform: string | undefined): CapabilitySystemInfo['osName'] {
  return platform === 'android' ? 'android' : 'unknown';
}

/**
 * Get the capabilities required by a specific API.
 * 
 * Use this to understand what permissions an API needs before calling it,
 * allowing you to request permissions proactively or show appropriate UI.
 * 
 * @example
 * ```ts
 * const required = getRequiredCapabilities('Geolocation.getCurrentPosition');
 * for (const cap of required) {
 *   const info = getCapabilityInfo(cap);
 *   if (!info.isUsable && info.canRequest) {
 *     await requestCapability(cap);
 *   }
 * }
 * ```
 */
export function getRequiredCapabilities(apiName: string): Capability[] {
  const module = _nativeCapabilityModule as NativeCapabilityModuleV2 | null;
  if (module?.getRequiredCapabilities) {
    return module.getRequiredCapabilities(apiName);
  }
  
  // Fallback: built-in API to capability mapping
  const apiCapabilityMap = getApiCapabilityMap();
  return apiCapabilityMap[apiName] ?? [];
}

/**
 * Check if a capability is known to the current runtime.
 * 
 * Use this to check for capabilities that may not exist on older OS versions
 * or runtime versions before attempting to use them.
 */
export function isKnownCapability(capability: Capability): boolean {
  const module = _nativeCapabilityModule as NativeCapabilityModuleV2 | null;
  if (module?.capabilityExists) {
    return module.capabilityExists(capability);
  }
  
  // Fallback: check against known capabilities
  const knownValues = Object.values(Capabilities) as string[];
  if (knownValues.includes(capability)) {
    return true;
  }
  
  // Check if it's a parameterized version of a known capability
  // e.g., "network:fetch:api.example.com" matches "network:fetch"
  const { category, action } = parseCapability(capability);
  const baseCapability = `${category}:${action}`;
  return knownValues.includes(baseCapability);
}

/**
 * Get the built-in mapping of API names to required capabilities.
 * Uses a getter function to avoid circular dependency issues.
 */
function getApiCapabilityMap(): Record<string, Capability[]> {
  return {
    // Fetch API
    'fetch': ['network:fetch'],
    'Request': ['network:fetch'],
    
    // WebSocket
    'WebSocket': ['network:connect'],
    'dns.lookup': ['network:resolve'],
    'dns.resolve': ['network:resolve'],
    'dns.reverse': ['network:resolve'],
    
    // Storage
    'localStorage': ['storage:local'],
    'localStorage.getItem': ['storage:local'],
    'localStorage.setItem': ['storage:local'],
    'sessionStorage': ['storage:session'],
    
    // Crypto
    'crypto.getRandomValues': ['crypto:random'],
    'crypto.randomUUID': ['crypto:random'],
    'crypto.subtle': ['crypto:subtle'],
    'crypto.subtle.encrypt': ['crypto:subtle'],
    'crypto.subtle.decrypt': ['crypto:subtle'],
    'crypto.subtle.sign': ['crypto:subtle'],
    'crypto.subtle.verify': ['crypto:subtle'],
    
    // Geolocation
    'Geolocation.getCurrentPosition': ['device:location'],
    'Geolocation.watchPosition': ['device:location'],
    
    // Clipboard
    'navigator.clipboard.read': ['clipboard:read'],
    'navigator.clipboard.readText': ['clipboard:read'],
    'navigator.clipboard.write': ['clipboard:write'],
    'navigator.clipboard.writeText': ['clipboard:write'],
    
    // Notifications
    'Notification': ['device:notifications'],
    'Notification.requestPermission': ['device:notifications'],
  };
}

/**
 * Get a human-readable description of a capability.
 */
function getCapabilityDescription(capability: Capability): string {
  const descriptions: Record<string, string> = {
    'network:fetch': 'Make network requests to remote servers',
    'network:connect': 'Establish persistent network connections',
    'network:resolve': 'Resolve hostnames with DNS',
    'network:local': 'Access devices on your local network',
    'storage:local': 'Store data locally on your device',
    'storage:session': 'Store temporary session data',
    'device:location': 'Access your location',
    'device:location:precise': 'Access your precise location',
    'device:location:whenInUse': 'Access location while using the app',
    'device:location:always': 'Access location even in background',
    'device:camera': 'Access your camera',
    'device:microphone': 'Access your microphone',
    'device:photos': 'Access your photos',
    'device:contacts': 'Access your contacts',
    'device:bluetooth': 'Use Bluetooth',
    'device:biometrics': 'Use Face ID or fingerprint',
    'device:notifications': 'Send you notifications',
    'crypto:random': 'Generate random numbers',
    'crypto:subtle': 'Use cryptographic operations',
    'clipboard:read': 'Read from clipboard',
    'clipboard:write': 'Write to clipboard',
  };
  
  return descriptions[capability] ?? `Access ${capability}`;
}

// ============================================================================
// Bitset Fast Path
// ============================================================================

/**
 * Get the bit position for a capability.
 * For parameterized caps like "network:fetch:api.example.com",
 * extracts base "network:fetch" and looks up its bit.
 *
 * @returns Bit position (0-55) or undefined if not a well-known capability
 */
export function getCapabilityBit(capability: Capability): number | undefined {
  // Fast path: direct lookup. Capability is an open string type, so read the
  // generated const map through a string-keyed view.
  const bits: Partial<Record<string, number>> = CapabilityBit;
  const direct = bits[capability];
  if (direct !== undefined) return direct;

  // Parameterized capability: extract base
  const { category, action } = parseCapability(capability);
  return bits[`${category}:${action}`];
}

function getDirectCapabilityBit(capability: Capability): number | undefined {
  const bits: Partial<Record<string, number>> = CapabilityBit;
  return bits[capability];
}

/**
 * Module effective bitmasks: moduleId -> [lo32, hi32]
 * Precomputed intersection of all 4 security layers for each module.
 */
const _effectiveBits: Map<number, [number, number]> = new Map();

/** Generation counter for permission changes */
let _permissionGeneration = 0;

/** Per-module cached generation */
const _cachedGeneration: Map<number, number> = new Map();

/**
 * Get the current permission generation counter.
 * Increments whenever permissions change, invalidating cached bitmasks.
 */
export function getPermissionGeneration(): number {
  return _permissionGeneration;
}

/**
 * Increment the permission generation counter.
 * Call this when any permission layer changes (OS, app, broker, or module grants).
 */
export function invalidatePermissionCache(): void {
  _permissionGeneration++;
}

/**
 * Set the effective capability bitmask for a module.
 * Called at module load time with the precomputed intersection of all 4 layers.
 *
 * @param moduleId The module's numeric ID
 * @param capabilities Array of granted capability strings
 */
export function setModuleCapabilities(moduleId: number, capabilities: Capability[]): void {
  // Grant capabilities through native layer
  if (typeof (globalThis as any).__exactGrantCapability === 'function') {
    for (const cap of capabilities) {
      (globalThis as any).__exactGrantCapability(moduleId, cap);
    }
  }

  // Set up fast-path bitmask cache
  let lo = 0;
  let hi = 0;
  for (const cap of capabilities) {
    const bit = getDirectCapabilityBit(cap);
    if (bit !== undefined) {
      if (bit < 32) {
        lo |= (1 << bit);
      } else {
        hi |= (1 << (bit - 32));
      }
    }
  }
  _effectiveBits.set(moduleId, [lo, hi]);
  _cachedGeneration.set(moduleId, _permissionGeneration);
}

/**
 * Clear capability bitmask for a module.
 * Call when a module is unloaded.
 */
export function clearModuleCapabilities(moduleId: number): void {
  _effectiveBits.delete(moduleId);
  _cachedGeneration.delete(moduleId);
}

/**
 * Fast boolean capability check — no allocation on the success path.
 * Returns true if the module has the capability, false otherwise.
 *
 * This is the hot path: a single Map lookup + bitwise AND.
 *
 * @param moduleId The module's numeric ID
 * @param capability The capability to check
 * @returns true if allowed, false if denied or unknown
 */
export function checkCapabilityFast(moduleId: number, capability: Capability): boolean {
  const bit = getCapabilityBit(capability);
  if (bit === undefined) return false; // unknown capability

  const bits = _effectiveBits.get(moduleId);
  if (!bits) return false;

  // Check generation
  const gen = _cachedGeneration.get(moduleId);
  if (gen !== _permissionGeneration) return false; // stale cache

  if (bit < 32) {
    return (bits[0] & (1 << bit)) !== 0;
  }
  return (bits[1] & (1 << (bit - 32))) !== 0;
}

// ============================================================================
// Capability Helpers
// ============================================================================

/**
 * Parse a capability string into category and action.
 * 
 * @param capability Full capability string (e.g., "network:fetch:api.example.com")
 * @returns Parsed capability parts
 */
export function parseCapability(capability: Capability): {
  category: string;
  action: string;
  resource?: string;
} {
  const parts = capability.split(':');
  return {
    category: parts[0] || '',
    action: parts[1] || '',
    resource: parts[2],
  };
}

/**
 * Check if a capability matches a grant pattern.
 * Supports wildcards like "network:*" or "*".
 * 
 * @param capability The capability to check
 * @param grant The grant pattern to match against
 */
export function capabilityMatches(capability: Capability, grant: Capability): boolean {
  if (grant === '*') return true;
  if (grant === capability) return true;
  
  const capParts = capability.split(':');
  const grantParts = grant.split(':');

  const wildcardIndex = grantParts.indexOf('*');
  if (wildcardIndex !== -1 && wildcardIndex !== grantParts.length - 1) {
    return false;
  }

  const compareLength = wildcardIndex === grantParts.length - 1
    ? grantParts.length - 1
    : grantParts.length;

  if (capParts.length < compareLength) {
    return false;
  }

  for (let i = 0; i < compareLength; i++) {
    if (grantParts[i] !== capParts[i]) return false;
  }

  // @ref LLP 0013#current-state — native matching allows a base grant to cover
  // parameterized checks; resource-scoped grants only match exact resources
  // unless they end in a trailing wildcard.
  return wildcardIndex === grantParts.length - 1 || grantParts.length <= capParts.length;
}

// ============================================================================
// Common Capability Constants
// ============================================================================

/**
 * Well-known capability names for type safety.
 * @see LLP 0013
 * @see LLP 0014
 */
export const Capabilities = {
  // Network
  NETWORK_FETCH: 'network:fetch',
  NETWORK_CONNECT: 'network:connect',
  NETWORK_RESOLVE: 'network:resolve',
  NETWORK_LISTEN: 'network:listen',
  NETWORK_LOCAL: 'network:local', // Local network access (mDNS, Bonjour)
  
  // File System
  FS_READ: 'fs:read',
  FS_WRITE: 'fs:write',
  FS_LIST: 'fs:list',
  FS_WATCH: 'fs:watch',
  
  // Environment
  ENV_READ: 'env:read',
  
  // Process
  PROCESS_SPAWN: 'process:spawn',
  PROCESS_SIGNAL: 'process:signal',
  PROCESS_CWD: 'process:cwd',
  
  // Device - Location (granular capability namespace)
  DEVICE_LOCATION: 'device:location',
  DEVICE_LOCATION_WHEN_IN_USE: 'device:location:whenInUse',
  DEVICE_LOCATION_ALWAYS: 'device:location:always',
  DEVICE_LOCATION_PRECISE: 'device:location:precise',
  DEVICE_LOCATION_REDUCED: 'device:location:reduced',
  
  // Device - Camera/Microphone
  DEVICE_CAMERA: 'device:camera',
  DEVICE_MICROPHONE: 'device:microphone',
  
  // Device - Photos (granular capability namespace)
  DEVICE_PHOTOS: 'device:photos',
  DEVICE_PHOTOS_READ: 'device:photos:read',
  DEVICE_PHOTOS_WRITE: 'device:photos:write',
  DEVICE_PHOTOS_LIMITED: 'device:photos:limited',
  
  // Device - Contacts
  DEVICE_CONTACTS: 'device:contacts',
  DEVICE_CONTACTS_READ: 'device:contacts:read',
  DEVICE_CONTACTS_WRITE: 'device:contacts:write',
  
  // Device - Sensors
  DEVICE_SENSORS: 'device:sensors',
  DEVICE_MOTION: 'device:motion',
  
  // Device - Bluetooth (granular capability namespace)
  DEVICE_BLUETOOTH: 'device:bluetooth',
  DEVICE_BLUETOOTH_SCAN: 'device:bluetooth:scan',
  DEVICE_BLUETOOTH_CONNECT: 'device:bluetooth:connect',
  DEVICE_BLUETOOTH_ADVERTISE: 'device:bluetooth:advertise',
  
  // Device - Biometrics (Face ID, Touch ID, fingerprint)
  DEVICE_BIOMETRICS: 'device:biometrics',
  
  // Device - Credentials (Keychain/Credential Manager)
  DEVICE_CREDENTIALS: 'device:credentials',
  DEVICE_CREDENTIALS_READ: 'device:credentials:read',
  DEVICE_CREDENTIALS_WRITE: 'device:credentials:write',
  
  // Device - Notifications
  DEVICE_NOTIFICATIONS: 'device:notifications',
  
  // Device - Calendar
  DEVICE_CALENDAR: 'device:calendar',
  DEVICE_CALENDAR_READ: 'device:calendar:read',
  DEVICE_CALENDAR_WRITE: 'device:calendar:write',
  
  // Device - Reminders
  DEVICE_REMINDERS: 'device:reminders',
  
  // Device - Health (HealthKit/Health Connect)
  DEVICE_HEALTH: 'device:health',
  DEVICE_HEALTH_READ: 'device:health:read',
  DEVICE_HEALTH_WRITE: 'device:health:write',
  
  // Storage
  STORAGE_LOCAL: 'storage:local',
  STORAGE_SESSION: 'storage:session',
  STORAGE_PERSIST: 'storage:persist', // Request persistent storage
  
  // SQLite
  SQLITE_READ: 'sqlite:read',
  SQLITE_WRITE: 'sqlite:write',
  
  // Clipboard
  CLIPBOARD_READ: 'clipboard:read',
  CLIPBOARD_WRITE: 'clipboard:write',
  
  // Crypto
  CRYPTO_RANDOM: 'crypto:random',
  CRYPTO_SUBTLE: 'crypto:subtle',
  
  // Time
  TIME_NOW: 'time:now',
  TIME_HIGHRES: 'time:highres',
  
  // IPC
  IPC_CHANNEL: 'ipc:channel',
} as const;

export type WellKnownCapability = typeof Capabilities[keyof typeof Capabilities];
