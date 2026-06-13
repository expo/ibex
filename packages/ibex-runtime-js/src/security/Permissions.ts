import type {
  CapabilityDenialCategory,
  CapabilityDenialReason,
} from "../events/DOMException.js";

import { runtimeInfo } from "../bootstrap.js";
import {
  checkCapability,
  getCapabilitySystemInfo,
  getDenialReasonCategory,
} from "./Capabilities.js";
import {
  Location,
  getLocationPermissionDetails,
  type LocationPermissionDetails,
} from "../location/index.js";
import {
  CAMERA_FEATURES,
  CAMERA_PERMISSIONS,
  getCameraPermissionDetails,
  getMicrophonePermissionDetails,
  type CameraPermissionDetails,
} from "../camera/index.js";

export type PermissionState = "granted" | "denied" | "prompt" | "unavailable";
export type AccessLayerResult = "allowed" | "denied";
export type AccessBlockingLayer = "os" | "appRoot" | "viewBroker" | "moduleDeclared";

export interface RuntimePlatformInfo {
  os: string;
  family: string;
  runtime: string;
  osVersion?: string;
}

export interface RuntimeOSPermissionEntry {
  state: PermissionState;
  canRequestAgain: boolean | null;
  settingsUrl?: string;
  operations: string[];
  label: string;
  platformDetail?: Record<string, unknown>;
}

export interface RuntimeAccessEntry {
  allowed: boolean;
  layers: {
    os: AccessLayerResult;
    appRoot: AccessLayerResult | null;
    viewBroker: AccessLayerResult | null;
    moduleDeclared: AccessLayerResult | null;
  };
  blockedBy: AccessBlockingLayer[];
  denialReason?: CapabilityDenialReason;
  denialCategory?: CapabilityDenialCategory;
  canRequestAgain?: boolean;
  settingsUrl?: string;
  explanation: string;
  operations: string[];
}

interface PermissionProvider {
  publicPermission: string;
  runtimePermission: string;
  domain: string;
  label: string;
  moduleName: string;
  getFeatures(): string[];
  getOperations(): string[];
  query(): Promise<PermissionDetailsLike>;
}

type PermissionDetailsLike = Pick<
  LocationPermissionDetails,
  "state" | "canRequestAgain" | "settingsUrl" | "platformDetail"
> &
  Pick<
    CameraPermissionDetails,
    "state" | "canRequestAgain" | "settingsUrl" | "platformDetail"
  >;

const LOCATION_FOREGROUND_PERMISSION = "device:location:foreground";
const LOCATION_RUNTIME_PERMISSION = "device:location:whenInUse";

const LOCATION_PROVIDER: PermissionProvider = {
  publicPermission: LOCATION_FOREGROUND_PERMISSION,
  runtimePermission: LOCATION_RUNTIME_PERMISSION,
  domain: "location",
  label: "Foreground location",
  moduleName: "exact/location",
  getFeatures: () => Array.from(Location.features),
  getOperations: () =>
    Object.entries(Location.permissions as Record<string, readonly string[]>)
      .filter(([, permissions]) => permissions.includes(LOCATION_RUNTIME_PERMISSION))
      .map(([operation]) => `exact/location.${operation}`),
  query: () => getLocationPermissionDetails(),
};

const CAMERA_BACK_PROVIDER: PermissionProvider = {
  publicPermission: "device:camera:back",
  runtimePermission: "device:camera",
  domain: "camera",
  label: "Back camera",
  moduleName: "exact/camera",
  getFeatures: () => Array.from(CAMERA_FEATURES),
  getOperations: () =>
    Object.entries(CAMERA_PERMISSIONS)
      .filter(([, permissions]) => permissions.includes("device:camera:back"))
      .map(([operation]) => `exact/camera.${operation}`),
  query: () => getCameraPermissionDetails(),
};

const CAMERA_FRONT_PROVIDER: PermissionProvider = {
  publicPermission: "device:camera:front",
  runtimePermission: "device:camera",
  domain: "camera",
  label: "Front camera",
  moduleName: "exact/camera",
  getFeatures: () => Array.from(CAMERA_FEATURES),
  getOperations: () =>
    Object.entries(CAMERA_PERMISSIONS)
      .filter(([, permissions]) => permissions.includes("device:camera:front"))
      .map(([operation]) => `exact/camera.${operation}`),
  query: () => getCameraPermissionDetails(),
};

const MICROPHONE_PROVIDER: PermissionProvider = {
  publicPermission: "device:microphone",
  runtimePermission: "device:microphone",
  domain: "microphone",
  label: "Microphone",
  moduleName: "exact/camera",
  getFeatures: () => Array.from(CAMERA_FEATURES),
  getOperations: () =>
    Object.entries(CAMERA_PERMISSIONS)
      .filter(([, permissions]) => permissions.includes("device:microphone"))
      .map(([operation]) => `exact/camera.${operation}`),
  query: () => getMicrophonePermissionDetails(),
};

const PERMISSION_PROVIDERS: PermissionProvider[] = [
  LOCATION_PROVIDER,
  CAMERA_BACK_PROVIDER,
  CAMERA_FRONT_PROVIDER,
  MICROPHONE_PROVIDER,
];

export function getRegisteredPermissionNames(filter?: string): string[] {
  return getPermissionProviders(filter).map((provider) => provider.publicPermission);
}

export function getRegisteredFeatures(): Record<string, string[]> {
  const features: Record<string, string[]> = {};
  for (const provider of PERMISSION_PROVIDERS) {
    const moduleFeatures = provider.getFeatures();
    if (moduleFeatures.length === 0) {
      continue;
    }
    features[provider.moduleName] = moduleFeatures;
  }
  return features;
}

export async function queryRegisteredPermissions(
  filter?: string,
): Promise<Record<string, RuntimeOSPermissionEntry>> {
  const permissions: Record<string, RuntimeOSPermissionEntry> = {};

  for (const provider of getPermissionProviders(filter)) {
    const details = await provider.query();
    permissions[provider.publicPermission] = {
      state: details.state,
      canRequestAgain: details.canRequestAgain,
      settingsUrl: details.settingsUrl,
      operations: provider.getOperations(),
      label: provider.label,
      platformDetail: details.platformDetail,
    };
  }

  return permissions;
}

export async function evaluateRegisteredPermissionAccess(
  permission: string,
  _options: {
    rootId?: number;
    viewId?: number;
  } = {},
): Promise<RuntimeAccessEntry> {
  const provider = findPermissionProvider(permission);
  if (!provider) {
    throw new Error(`Unknown permission: ${permission}`);
  }

  const permissionDetails = await provider.query();
  const capabilityCheck = checkCapability(provider.runtimePermission);

  const osLayer: AccessLayerResult =
    permissionDetails.state === "granted" ? "allowed" : "denied";

  let appRootLayer: AccessLayerResult | null = null;
  if (capabilityCheck.allowed) {
    appRootLayer = "allowed";
  } else if (capabilityCheck.reason === "app_not_granted") {
    appRootLayer = "denied";
  }

  const blockedBy: AccessBlockingLayer[] = [];
  if (osLayer === "denied") {
    blockedBy.push("os");
  }
  if (appRootLayer === "denied") {
    blockedBy.push("appRoot");
  }

  const denialReason = deriveDenialReason(permissionDetails, blockedBy[0], capabilityCheck.reason);
  const denialCategory =
    denialReason != null
      ? (getDenialReasonCategory(denialReason) as CapabilityDenialCategory)
      : undefined;

  return {
    allowed: blockedBy.length === 0,
    layers: {
      os: osLayer,
      appRoot: appRootLayer,
      viewBroker: null,
      moduleDeclared: null,
    },
    blockedBy,
    denialReason,
    denialCategory,
    canRequestAgain:
      blockedBy[0] === "os" ? permissionDetails.canRequestAgain ?? undefined : undefined,
    settingsUrl:
      blockedBy[0] === "os" ? permissionDetails.settingsUrl : undefined,
    explanation: buildAccessExplanation(permissionDetails, blockedBy, appRootLayer),
    operations: provider.getOperations(),
  };
}

export function getRuntimePlatformInfo(): RuntimePlatformInfo {
  const systemInfo = getCapabilitySystemInfo();
  const globalHints = globalThis as {
    __exactPlatform?: unknown;
    HermesInternal?: unknown;
  };
  const runtime =
    typeof runtimeInfo === "object" && runtimeInfo !== null ? runtimeInfo : undefined;
  const exactPlatform =
    typeof globalHints.__exactPlatform === "string" && globalHints.__exactPlatform.length > 0
      ? globalHints.__exactPlatform
      : undefined;
  const runtimePlatform =
    exactPlatform ?? (typeof runtime?.platform === "string" ? runtime.platform : "unknown");
  const runtimeEngine =
    typeof runtime?.engine === "string" && runtime.engine.length > 0
      ? runtime.engine
      : typeof globalHints.HermesInternal !== "undefined"
        ? "hermes"
        : "unknown";
  const rawOs = systemInfo.osName !== "unknown"
    ? systemInfo.osName
    : normalizePlatformName(runtimePlatform);

  return {
    os: rawOs,
    family: inferPlatformFamily(rawOs),
    runtime: runtimeEngine.toLowerCase(),
    osVersion: systemInfo.osVersion !== "unknown" ? systemInfo.osVersion : undefined,
  };
}

function getPermissionProviders(filter?: string): PermissionProvider[] {
  if (!filter) {
    return PERMISSION_PROVIDERS.slice();
  }

  return PERMISSION_PROVIDERS.filter((provider) =>
    globMatches(filter, provider.publicPermission),
  );
}

function findPermissionProvider(permission: string): PermissionProvider | null {
  const normalized = permission.trim();
  for (const provider of PERMISSION_PROVIDERS) {
    if (
      provider.publicPermission === normalized ||
      provider.runtimePermission === normalized
    ) {
      return provider;
    }
  }
  return null;
}

function globMatches(pattern: string, value: string): boolean {
  const escaped = pattern
    .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`).test(value);
}

function deriveDenialReason(
  details: PermissionDetailsLike,
  blockedBy: AccessBlockingLayer | undefined,
  capabilityReason: CapabilityDenialReason | undefined,
): CapabilityDenialReason | undefined {
  if (blockedBy === "appRoot") {
    return "app_not_granted";
  }

  if (blockedBy !== "os") {
    return capabilityReason;
  }

  if (details.state === "prompt") {
    return undefined;
  }

  if (details.settingsUrl && details.canRequestAgain === false) {
    return "requires_settings";
  }

  if (details.platformDetail?.nativeStatus === "restricted") {
    return "os_restricted";
  }

  return "os_denied";
}

function buildAccessExplanation(
  details: PermissionDetailsLike,
  blockedBy: AccessBlockingLayer[],
  appRootLayer: AccessLayerResult | null,
): string {
  if (blockedBy.length === 0) {
    return "All currently surfaced layers grant access. View-broker and module-declaration introspection are not implemented yet, so those layers are omitted.";
  }

  if (blockedBy[0] === "os") {
    if (details.state === "prompt") {
      return "OS permission has not been granted yet. The next use may trigger a permission prompt.";
    }
    if (details.platformDetail?.nativeStatus === "restricted") {
      return "The OS is restricting access to this permission. The app cannot resolve that restriction in-process.";
    }
    if (details.settingsUrl) {
      return "The OS is currently blocking this permission. The user likely needs to re-enable it in Settings.";
    }
    return "The OS is currently denying this permission.";
  }

  if (blockedBy[0] === "appRoot" && appRootLayer === "denied") {
    return "The app-level capability configuration is blocking this permission before any view-specific checks run.";
  }

  return "Access is denied by the current runtime configuration.";
}

function normalizePlatformName(platform: string): string {
  switch (platform) {
    case "darwin":
      return "ios";
    case "browser":
      return "web";
    case "win32":
      return "windows";
    case "mac":
      return "macos";
    default:
      return platform;
  }
}

function inferPlatformFamily(os: string): string {
  switch (os) {
    case "ios":
    case "macos":
    case "visionos":
      return "apple";
    case "android":
      return "android";
    case "web":
      return "web";
    case "windows":
      return "windows";
    default:
      return "unknown";
  }
}
