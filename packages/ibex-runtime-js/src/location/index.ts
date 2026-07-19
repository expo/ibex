import { CapabilityDeniedError, DOMException } from '../events/DOMException.js';
import { getHostNavigatorInput } from '../core/host-inputs.js';

const FOREGROUND_PERMISSION = 'device:location:whenInUse';

type LocationPermissionOperation =
  | 'getCurrentPosition'
  | 'watchPosition'
  | 'clearWatch';

const LOCATION_PERMISSIONS: Readonly<Record<LocationPermissionOperation, readonly string[]>> =
  Object.freeze({
  getCurrentPosition: Object.freeze([FOREGROUND_PERMISSION]),
  watchPosition: Object.freeze([FOREGROUND_PERMISSION]),
  clearWatch: Object.freeze([]),
  });

const UNSUPPORTED_MESSAGE = 'Location is not supported on this platform';

type LocationFeature =
  | 'getCurrentPosition'
  | 'watchPosition'
  | 'highAccuracy'
  | 'altitude';

type LegacyPermissionStatus =
  | 'notDetermined'
  | 'denied'
  | 'authorizedWhenInUse'
  | 'authorizedAlways'
  | 'restricted';

type LegacyLocationAccuracy =
  | 'best'
  | 'nearestTenMeters'
  | 'hundredMeters'
  | 'kilometer'
  | 'threeKilometers';

interface LegacyLocationResult {
  latitude: number;
  longitude: number;
  altitude: number;
  horizontalAccuracy: number;
  verticalAccuracy: number;
  timestamp: number;
}

interface LegacyLocationModule {
  requestPermission(level: 'whenInUse' | 'always'): Promise<{ status: LegacyPermissionStatus }>;
  getCurrentLocation(
    accuracy: LegacyLocationAccuracy,
    timeoutMs?: number,
  ): Promise<LegacyLocationResult>;
  startUpdates(accuracy: LegacyLocationAccuracy, distanceFilter?: number): void;
  stopUpdates(): void;
  getPermissionStatus(): LegacyPermissionStatus;
  isLocationServicesEnabled?(): boolean;
  onLocationUpdate(callback: (location: LegacyLocationResult) => void): () => void;
  onError(callback: (error: { code: string; message: string }) => void): () => void;
}

interface HostGeolocationLike {
  clearWatch(watchId: number): void;
  getCurrentPosition(
    success: PositionCallback,
    error?: PositionErrorCallback | null,
    options?: PositionOptions,
  ): void;
  watchPosition(
    success: PositionCallback,
    error?: PositionErrorCallback | null,
    options?: PositionOptions,
  ): number;
}

interface HostNavigatorLike {
  geolocation?: HostGeolocationLike;
  permissions?: {
    query(descriptor: { name: string }): Promise<{ state?: string }>;
  };
}

interface LocationBackend {
  readonly features: ReadonlySet<LocationFeature>;

  getCurrentPosition(options?: PositionOptions): Promise<GeolocationPosition>;
  getCurrentPositionGlobal(
    success: PositionCallback,
    error?: PositionErrorCallback | null,
    options?: PositionOptions,
  ): void;
  watchPosition(
    success: PositionCallback,
    error?: PositionErrorCallback | null,
    options?: PositionOptions,
  ): number;
  clearWatch(watchId: number): void;
}

declare global {
  var __exactAndroidLocation:
    | {
        getPermissionStatus?: () => LegacyPermissionStatus;
        getCurrentLocation?: (
          accuracy: LegacyLocationAccuracy,
          timeoutMs?: number,
        ) => LegacyLocationResult;
        isLocationServicesEnabled?: () => boolean;
      }
    | undefined;
}

export type LocationPermissionState = 'granted' | 'denied' | 'prompt' | 'unavailable';

export interface LocationPermissionDetails {
  state: LocationPermissionState;
  canRequestAgain: boolean | null;
  settingsUrl?: string;
  platformDetail?: Record<string, unknown>;
}

export class ExactGeolocationPositionError implements GeolocationPositionError, Error {
  declare static readonly PERMISSION_DENIED: 1;
  declare static readonly POSITION_UNAVAILABLE: 2;
  declare static readonly TIMEOUT: 3;

  readonly PERMISSION_DENIED = ExactGeolocationPositionError.PERMISSION_DENIED;
  readonly POSITION_UNAVAILABLE = ExactGeolocationPositionError.POSITION_UNAVAILABLE;
  readonly TIMEOUT = ExactGeolocationPositionError.TIMEOUT;

  readonly name = 'GeolocationPositionError';
  readonly message: string;
  readonly code: 1 | 2 | 3;
  stack?: string;

  constructor(code: 1 | 2 | 3, message?: string) {
    this.message = message ?? defaultErrorMessage(code);
    this.code = code;
    this.stack = new Error(this.message).stack;
  }
}

Object.setPrototypeOf(ExactGeolocationPositionError.prototype, Error.prototype);
Object.setPrototypeOf(ExactGeolocationPositionError, Error);
Object.defineProperties(ExactGeolocationPositionError, {
  PERMISSION_DENIED: { value: 1, enumerable: true, configurable: true },
  POSITION_UNAVAILABLE: { value: 2, enumerable: true, configurable: true },
  TIMEOUT: { value: 3, enumerable: true, configurable: true },
});

class UnsupportedLocationBackend implements LocationBackend {
  readonly features: ReadonlySet<LocationFeature> = new Set();

  async getCurrentPosition(): Promise<GeolocationPosition> {
    throw new DOMException(UNSUPPORTED_MESSAGE, 'NotSupportedError');
  }

  getCurrentPositionGlobal(
    _success: PositionCallback,
    error?: PositionErrorCallback | null,
  ): void {
    queueMicrotask(() => {
      error?.(new ExactGeolocationPositionError(ExactGeolocationPositionError.POSITION_UNAVAILABLE));
    });
  }

  watchPosition(
    _success: PositionCallback,
    error?: PositionErrorCallback | null,
  ): number {
    const watchId = nextUnsupportedWatchId++;
    queueMicrotask(() => {
      error?.(new ExactGeolocationPositionError(ExactGeolocationPositionError.POSITION_UNAVAILABLE));
    });
    return watchId;
  }

  clearWatch(_watchId: number): void {}
}

class BrowserLocationBackend implements LocationBackend {
  readonly features: ReadonlySet<LocationFeature> = new Set([
    'getCurrentPosition',
    'watchPosition',
  ]);

  private readonly geolocation: HostGeolocationLike;

  constructor(geolocation: HostGeolocationLike) {
    this.geolocation = geolocation;
  }

  getCurrentPosition(options?: PositionOptions): Promise<GeolocationPosition> {
    return new Promise((resolve, reject) => {
      this.geolocation.getCurrentPosition(
        (position) => resolve(position),
        (error) => reject(mapModuleError(error)),
        options,
      );
    });
  }

  getCurrentPositionGlobal(
    success: PositionCallback,
    error?: PositionErrorCallback | null,
    options?: PositionOptions,
  ): void {
    this.geolocation.getCurrentPosition(
      success,
      error
        ? (positionError) => {
            error(normalizePositionError(positionError));
          }
        : undefined,
      options,
    );
  }

  watchPosition(
    success: PositionCallback,
    error?: PositionErrorCallback | null,
    options?: PositionOptions,
  ): number {
    return this.geolocation.watchPosition(
      success,
      error
        ? (positionError) => {
            error(normalizePositionError(positionError));
          }
        : undefined,
      options,
    );
  }

  clearWatch(watchId: number): void {
    this.geolocation.clearWatch(watchId);
  }
}

class NativeLocationBackend implements LocationBackend {
  readonly features: ReadonlySet<LocationFeature> = new Set([
    'getCurrentPosition',
    'watchPosition',
    'highAccuracy',
    'altitude',
  ]);

  private modulePromise: Promise<LegacyLocationModule> | null = null;
  private nextWatchId = 1;
  private watchers = new Map<number, NativeWatchRegistration>();
  private unsubscribeLocationUpdates: (() => void) | null = null;
  private unsubscribeErrors: (() => void) | null = null;
  private activeAccuracy: LegacyLocationAccuracy | null = null;
  private activeDistanceFilter: number | null = null;
  private updatesStarted = false;

  async getCurrentPosition(options?: PositionOptions): Promise<GeolocationPosition> {
    const module = await this.loadModule();
    await ensureNativePermission(module);

    try {
      const location = await withTimeout(
        module.getCurrentLocation(mapAccuracy(options), options?.timeout),
        options?.timeout,
        () =>
          new ExactGeolocationPositionError(
            ExactGeolocationPositionError.TIMEOUT,
            'Location request timed out',
          ),
      );
      return toGeolocationPosition(location);
    } catch (error) {
      throw mapNativeModuleError(error);
    }
  }

  getCurrentPositionGlobal(
    success: PositionCallback,
    error?: PositionErrorCallback | null,
    options?: PositionOptions,
  ): void {
    void this.getCurrentPosition(options)
      .then((position) => {
        success(position);
      })
      .catch((err) => {
        error?.(toGlobalPositionError(err));
      });
  }

  watchPosition(
    success: PositionCallback,
    error?: PositionErrorCallback | null,
    options?: PositionOptions,
  ): number {
    const watchId = this.nextWatchId++;
    this.watchers.set(watchId, { success, error, options });
    void this.startWatch(watchId);
    return watchId;
  }

  clearWatch(watchId: number): void {
    this.watchers.delete(watchId);
    void this.refreshUpdates();
  }

  private async startWatch(watchId: number): Promise<void> {
    const registration = this.watchers.get(watchId);
    if (!registration) return;

    try {
      const module = await this.loadModule();
      await ensureNativePermission(module);
      if (!this.watchers.has(watchId)) return;

      this.ensureSubscriptions(module);
      await this.refreshUpdates();
    } catch (error) {
      if (!this.watchers.has(watchId)) return;
      this.watchers.delete(watchId);
      registration.error?.(toGlobalPositionError(error));
      void this.refreshUpdates();
    }
  }

  private ensureSubscriptions(module: LegacyLocationModule): void {
    if (!this.unsubscribeLocationUpdates) {
      this.unsubscribeLocationUpdates = module.onLocationUpdate((location) => {
        const position = toGeolocationPosition(location);
        for (const watcher of this.watchers.values()) {
          watcher.success(position);
        }
      });
    }

    if (!this.unsubscribeErrors) {
      this.unsubscribeErrors = module.onError((nativeError) => {
        const positionError = nativeErrorToPositionError(nativeError);
        const shouldTerminate = positionError.code === ExactGeolocationPositionError.PERMISSION_DENIED;

        for (const watcher of this.watchers.values()) {
          watcher.error?.(positionError);
        }

        if (shouldTerminate) {
          this.watchers.clear();
          void this.refreshUpdates();
        }
      });
    }
  }

  private async refreshUpdates(): Promise<void> {
    const module = await this.loadModule().catch(() => null);
    if (!module) return;

    if (this.watchers.size === 0) {
      if (this.updatesStarted) {
        module.stopUpdates();
        this.updatesStarted = false;
        this.activeAccuracy = null;
        this.activeDistanceFilter = null;
      }
      return;
    }

    const desiredAccuracy = computeWatchAccuracy(this.watchers.values());
    const desiredDistanceFilter = computeDistanceFilter(this.watchers.values());

    if (
      this.updatesStarted &&
      this.activeAccuracy === desiredAccuracy &&
      this.activeDistanceFilter === desiredDistanceFilter
    ) {
      return;
    }

    if (this.updatesStarted) {
      module.stopUpdates();
    }

    module.startUpdates(desiredAccuracy, desiredDistanceFilter);
    this.updatesStarted = true;
    this.activeAccuracy = desiredAccuracy;
    this.activeDistanceFilter = desiredDistanceFilter;
  }

  private loadModule(): Promise<LegacyLocationModule> {
    if (!this.modulePromise) {
      this.modulePromise = loadLegacyLocationModule().catch((error: unknown) => {
        this.modulePromise = null;
        throw error;
      });
    }

    return this.modulePromise;
  }
}

interface NativeWatchRegistration {
  error?: PositionErrorCallback | null;
  options?: PositionOptions;
  success: PositionCallback;
}

function defaultErrorMessage(code: 1 | 2 | 3): string {
  switch (code) {
    case ExactGeolocationPositionError.PERMISSION_DENIED:
      return 'Location permission denied';
    case ExactGeolocationPositionError.TIMEOUT:
      return 'Location request timed out';
    case ExactGeolocationPositionError.POSITION_UNAVAILABLE:
    default:
      return 'Location is unavailable';
  }
}

function toGeolocationPosition(location: LegacyLocationResult): GeolocationPosition {
  const coords = {
    latitude: location.latitude,
    longitude: location.longitude,
    accuracy: location.horizontalAccuracy,
    altitude: Number.isFinite(location.altitude) ? location.altitude : null,
    altitudeAccuracy: Number.isFinite(location.verticalAccuracy)
      ? location.verticalAccuracy
      : null,
    heading: null,
    speed: null,
    toJSON(): Omit<GeolocationCoordinates, 'toJSON'> {
      return {
        latitude: this.latitude,
        longitude: this.longitude,
        accuracy: this.accuracy,
        altitude: this.altitude,
        altitudeAccuracy: this.altitudeAccuracy,
        heading: this.heading,
        speed: this.speed,
      };
    },
  } satisfies GeolocationCoordinates;

  return {
    coords,
    timestamp: location.timestamp,
    toJSON(): Omit<GeolocationPosition, 'toJSON'> {
      return {
        coords: this.coords,
        timestamp: this.timestamp,
      };
    },
  } satisfies GeolocationPosition;
}

function normalizePositionError(
  error: GeolocationPositionError,
): ExactGeolocationPositionError {
  if (error instanceof ExactGeolocationPositionError) {
    return error;
  }

  return new ExactGeolocationPositionError(
    normalizePositionErrorCode(error?.code),
    error?.message,
  );
}

function normalizePositionErrorCode(code: number | undefined): 1 | 2 | 3 {
  if (code === ExactGeolocationPositionError.PERMISSION_DENIED) {
    return ExactGeolocationPositionError.PERMISSION_DENIED;
  }
  if (code === ExactGeolocationPositionError.TIMEOUT) {
    return ExactGeolocationPositionError.TIMEOUT;
  }
  return ExactGeolocationPositionError.POSITION_UNAVAILABLE;
}

function mapModuleError(error: GeolocationPositionError): Error {
  const normalized = normalizePositionError(error);
  if (normalized.code === ExactGeolocationPositionError.PERMISSION_DENIED) {
    return new CapabilityDeniedError(FOREGROUND_PERMISSION, 'os_denied', false);
  }

  return normalized;
}

function mapNativeModuleError(error: unknown): Error {
  if (error instanceof CapabilityDeniedError) {
    return error;
  }

  if (error instanceof DOMException && error.name === 'NotSupportedError') {
    return error;
  }

  if (error instanceof ExactGeolocationPositionError) {
    return error;
  }

  if (error instanceof Error) {
    const message = error.message.toLowerCase();
    if (message.includes('permission_denied')) {
      return new CapabilityDeniedError(FOREGROUND_PERMISSION, 'os_denied', false);
    }
    if (message.includes('timed out')) {
      return new ExactGeolocationPositionError(
        ExactGeolocationPositionError.TIMEOUT,
        error.message,
      );
    }
    return new ExactGeolocationPositionError(
      ExactGeolocationPositionError.POSITION_UNAVAILABLE,
      error.message,
    );
  }

  return new ExactGeolocationPositionError(ExactGeolocationPositionError.POSITION_UNAVAILABLE);
}

function toGlobalPositionError(error: unknown): GeolocationPositionError {
  if (error instanceof CapabilityDeniedError) {
    return new ExactGeolocationPositionError(
      ExactGeolocationPositionError.PERMISSION_DENIED,
      error.message,
    );
  }

  if (error instanceof DOMException && error.name === 'NotSupportedError') {
    return new ExactGeolocationPositionError(
      ExactGeolocationPositionError.POSITION_UNAVAILABLE,
      error.message,
    );
  }

  if (error instanceof ExactGeolocationPositionError) {
    return error;
  }

  if (error instanceof Error && error.message.toLowerCase().includes('timed out')) {
    return new ExactGeolocationPositionError(
      ExactGeolocationPositionError.TIMEOUT,
      error.message,
    );
  }

  return new ExactGeolocationPositionError(
    ExactGeolocationPositionError.POSITION_UNAVAILABLE,
    error instanceof Error ? error.message : undefined,
  );
}

function nativeErrorToPositionError(error: { code?: string; message?: string }): GeolocationPositionError {
  const code = error.code?.toUpperCase();
  if (code === 'PERMISSION_DENIED') {
    return new ExactGeolocationPositionError(
      ExactGeolocationPositionError.PERMISSION_DENIED,
      error.message,
    );
  }
  if (code === 'TIMEOUT') {
    return new ExactGeolocationPositionError(ExactGeolocationPositionError.TIMEOUT, error.message);
  }
  return new ExactGeolocationPositionError(
    ExactGeolocationPositionError.POSITION_UNAVAILABLE,
    error.message,
  );
}

async function ensureNativePermission(module: LegacyLocationModule): Promise<void> {
  const currentStatus = module.getPermissionStatus();
  const immediateError = permissionStatusToError(currentStatus);
  if (immediateError) {
    throw immediateError;
  }

  if (isAuthorizedStatus(currentStatus)) {
    return;
  }

  const result = await module.requestPermission('whenInUse');
  const requestError = permissionStatusToError(result.status);
  if (requestError) {
    throw requestError;
  }

  if (!isAuthorizedStatus(result.status)) {
    throw new CapabilityDeniedError(FOREGROUND_PERMISSION, 'os_denied', false);
  }
}

function permissionStatusToError(status: LegacyPermissionStatus): CapabilityDeniedError | null {
  if (status === 'denied') {
    return new CapabilityDeniedError(FOREGROUND_PERMISSION, 'os_denied', false);
  }
  if (status === 'restricted') {
    return new CapabilityDeniedError(FOREGROUND_PERMISSION, 'os_restricted', false);
  }
  return null;
}

function isAuthorizedStatus(status: LegacyPermissionStatus): boolean {
  return status === 'authorizedWhenInUse' || status === 'authorizedAlways';
}

function mapAccuracy(options?: PositionOptions): LegacyLocationAccuracy {
  return options?.enableHighAccuracy ? 'best' : 'hundredMeters';
}

function computeWatchAccuracy(
  watchers: IterableIterator<NativeWatchRegistration>,
): LegacyLocationAccuracy {
  for (const watcher of watchers) {
    if (watcher.options?.enableHighAccuracy) {
      return 'best';
    }
  }
  return 'hundredMeters';
}

function computeDistanceFilter(
  watchers: IterableIterator<NativeWatchRegistration>,
): number {
  let desired = 10;
  for (const watcher of watchers) {
    if (typeof watcher.options?.maximumAge === 'number' && watcher.options.maximumAge <= 1000) {
      desired = Math.min(desired, 1);
    }
  }
  return desired;
}

function getHostNavigator(): HostNavigatorLike | undefined {
  const globalValue = globalThis as typeof globalThis & {
    navigator?: HostNavigatorLike & { __exactNavigator?: boolean };
  };

  const exactHostNavigator = getHostNavigatorInput() as
    | (HostNavigatorLike & { __exactNavigator?: boolean })
    | undefined;
  if (exactHostNavigator && exactHostNavigator.__exactNavigator !== true) {
    return exactHostNavigator;
  }

  const navigatorValue = globalValue.navigator;
  if (navigatorValue && navigatorValue.__exactNavigator !== true) {
    return navigatorValue;
  }

  return undefined;
}

function getHostGeolocation(): HostGeolocationLike | null {
  const hostNavigator = getHostNavigator();
  if (!hostNavigator?.geolocation) {
    return null;
  }
  return hostNavigator.geolocation;
}

function getHostPermissionsQuery():
  | ((descriptor: { name: string }) => Promise<{ state?: string }>)
  | null {
  const hostNavigator = getHostNavigator();
  if (typeof hostNavigator?.permissions?.query === 'function') {
    return hostNavigator.permissions.query.bind(hostNavigator.permissions);
  }

  const navigatorValue = (globalThis as typeof globalThis & {
    navigator?: {
      permissions?: {
        query(descriptor: { name: string }): Promise<{ state?: string }>;
      };
    };
  }).navigator;

  if (typeof navigatorValue?.permissions?.query === 'function') {
    return navigatorValue.permissions.query.bind(navigatorValue.permissions);
  }

  return null;
}

function hasNativeLocationBridge(): boolean {
  const bridge = globalThis.__exactAndroidLocation;
  return !!(
    bridge &&
    typeof bridge.getPermissionStatus === 'function' &&
    typeof bridge.getCurrentLocation === 'function'
  );
}

let legacyLocationModulePromise: Promise<LegacyLocationModule> | null = null;

function normalizeLegacyPermissionStatus(value: unknown): LegacyPermissionStatus {
  switch (value) {
    case 'authorizedWhenInUse':
    case 'authorizedAlways':
    case 'denied':
    case 'restricted':
    case 'notDetermined':
      return value;
    default:
      return 'denied';
  }
}

function androidLocationError(error: unknown): { code: string; message: string } {
  const message = error instanceof Error ? error.message : String(error ?? 'Android location failed');
  const upper = message.toUpperCase();
  if (upper.includes('PERMISSION_DENIED')) {
    return { code: 'PERMISSION_DENIED', message };
  }
  if (upper.includes('TIMEOUT') || upper.includes('TIMED OUT')) {
    return { code: 'TIMEOUT', message };
  }
  return { code: 'POSITION_UNAVAILABLE', message };
}

class AndroidLocationModule implements LegacyLocationModule {
  private locationListeners = new Set<(location: LegacyLocationResult) => void>();
  private errorListeners = new Set<(error: { code: string; message: string }) => void>();
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private pollInFlight = false;
  private pollAccuracy: LegacyLocationAccuracy = 'hundredMeters';
  private pollTimeoutMs = 10000;

  async requestPermission(_level: 'whenInUse' | 'always'): Promise<{ status: LegacyPermissionStatus }> {
    return { status: this.getPermissionStatus() };
  }

  async getCurrentLocation(
    accuracy: LegacyLocationAccuracy,
    timeoutMs?: number,
  ): Promise<LegacyLocationResult> {
    const bridge = globalThis.__exactAndroidLocation;
    if (!bridge || typeof bridge.getCurrentLocation !== 'function') {
      throw new ExactGeolocationPositionError(
        ExactGeolocationPositionError.POSITION_UNAVAILABLE,
        UNSUPPORTED_MESSAGE,
      );
    }
    return bridge.getCurrentLocation(
      accuracy,
      typeof timeoutMs === 'number' && Number.isFinite(timeoutMs) && timeoutMs > 0
        ? timeoutMs
        : 10000,
    );
  }

  startUpdates(accuracy: LegacyLocationAccuracy, distanceFilter?: number): void {
    this.stopUpdates();
    this.pollAccuracy = accuracy;
    this.pollTimeoutMs = 10000;
    const intervalMs =
      typeof distanceFilter === 'number' && Number.isFinite(distanceFilter) && distanceFilter <= 1
        ? 1000
        : 5000;

    const poll = () => {
      if (this.pollInFlight || this.locationListeners.size === 0) {
        return;
      }
      this.pollInFlight = true;
      void this.getCurrentLocation(this.pollAccuracy, this.pollTimeoutMs)
        .then((location) => {
          for (const listener of [...this.locationListeners]) {
            listener(location);
          }
        })
        .catch((error) => {
          const nativeError = androidLocationError(error);
          for (const listener of [...this.errorListeners]) {
            listener(nativeError);
          }
        })
        .finally(() => {
          this.pollInFlight = false;
        });
    };

    poll();
    this.pollTimer = setInterval(poll, intervalMs);
  }

  stopUpdates(): void {
    if (this.pollTimer != null) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    this.pollInFlight = false;
  }

  getPermissionStatus(): LegacyPermissionStatus {
    return normalizeLegacyPermissionStatus(globalThis.__exactAndroidLocation?.getPermissionStatus?.());
  }

  isLocationServicesEnabled(): boolean {
    const bridge = globalThis.__exactAndroidLocation;
    return typeof bridge?.isLocationServicesEnabled === 'function'
      ? bridge.isLocationServicesEnabled()
      : true;
  }

  onLocationUpdate(callback: (location: LegacyLocationResult) => void): () => void {
    this.locationListeners.add(callback);
    return () => {
      this.locationListeners.delete(callback);
    };
  }

  onError(callback: (error: { code: string; message: string }) => void): () => void {
    this.errorListeners.add(callback);
    return () => {
      this.errorListeners.delete(callback);
    };
  }
}

function loadLegacyLocationModule(): Promise<LegacyLocationModule> {
  legacyLocationModulePromise ??= hasNativeLocationBridge()
    ? Promise.resolve(new AndroidLocationModule())
    : Promise.reject(
        new ExactGeolocationPositionError(
          ExactGeolocationPositionError.POSITION_UNAVAILABLE,
          UNSUPPORTED_MESSAGE,
        ),
      );

  return legacyLocationModulePromise;
}

export async function getLocationPermissionDetails(): Promise<LocationPermissionDetails> {
  const hostGeolocation = getHostGeolocation();
  if (hostGeolocation) {
    const query = getHostPermissionsQuery();
    if (query) {
      try {
        const result = await query({ name: 'geolocation' });
        const state = result?.state;
        if (state === 'granted') {
          return {
            state: 'granted',
            canRequestAgain: false,
            platformDetail: {
              permissionState: 'granted',
            },
          };
        }
        if (state === 'denied') {
          return {
            state: 'denied',
            canRequestAgain: false,
            platformDetail: {
              permissionState: 'denied',
            },
          };
        }
        if (state === 'prompt') {
          return {
            state: 'prompt',
            canRequestAgain: true,
            platformDetail: {
              permissionState: 'prompt',
            },
          };
        }
      } catch {
        // Fall through to the conservative browser fallback below.
      }
    }

    return {
      state: 'prompt',
      canRequestAgain: null,
      platformDetail: {
        permissionState: 'unknown',
      },
    };
  }

  if (hasNativeLocationBridge()) {
    const module = await loadLegacyLocationModule();
    const nativeStatus = module.getPermissionStatus();
    const isLocationServicesEnabled = module.isLocationServicesEnabled?.() ?? true;

    if (!isLocationServicesEnabled) {
      return {
        state: 'denied',
        canRequestAgain: false,
        settingsUrl: 'app-settings:location',
        platformDetail: {
          nativeStatus,
          isLocationServicesEnabled,
        },
      };
    }

    switch (nativeStatus) {
      case 'authorizedWhenInUse':
      case 'authorizedAlways':
        return {
          state: 'granted',
          canRequestAgain: false,
          platformDetail: {
            nativeStatus,
            isLocationServicesEnabled,
          },
        };
      case 'denied':
        return {
          state: 'denied',
          canRequestAgain: false,
          settingsUrl: 'app-settings:location',
          platformDetail: {
            nativeStatus,
            isLocationServicesEnabled,
          },
        };
      case 'restricted':
        return {
          state: 'denied',
          canRequestAgain: false,
          settingsUrl: 'app-settings:location',
          platformDetail: {
            nativeStatus,
            isLocationServicesEnabled,
          },
        };
      case 'notDetermined':
      default:
        return {
          state: 'prompt',
          canRequestAgain: true,
          platformDetail: {
            nativeStatus,
            isLocationServicesEnabled,
          },
        };
    }
  }

  return {
    state: 'unavailable',
    canRequestAgain: false,
    platformDetail: {
      reason: 'location_unavailable',
    },
  };
}

const unsupportedBackend = new UnsupportedLocationBackend();
let nativeBackend: NativeLocationBackend | null = null;
let nextUnsupportedWatchId = 1;

function getLocationBackend(): LocationBackend {
  const hostGeolocation = getHostGeolocation();
  if (hostGeolocation) {
    return new BrowserLocationBackend(hostGeolocation);
  }

  if (hasNativeLocationBridge()) {
    if (!nativeBackend) {
      nativeBackend = new NativeLocationBackend();
    }
    return nativeBackend;
  }

  return unsupportedBackend;
}

function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number | undefined,
  createTimeoutError: () => Error,
): Promise<T> {
  if (timeoutMs == null || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return promise;
  }

  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const timeoutId = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(createTimeoutError());
    }, timeoutMs);

    void promise.then(
      (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutId);
        resolve(value);
      },
      (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutId);
        reject(error);
      },
    );
  });
}

class ExactGeolocation implements Geolocation {
  clearWatch(watchId: number): void {
    getLocationBackend().clearWatch(watchId);
  }

  getCurrentPosition(
    success: PositionCallback,
    error?: PositionErrorCallback | null,
    options?: PositionOptions,
  ): void {
    getLocationBackend().getCurrentPositionGlobal(success, error, options);
  }

  watchPosition(
    success: PositionCallback,
    error?: PositionErrorCallback | null,
    options?: PositionOptions,
  ): number {
    return getLocationBackend().watchPosition(success, error, options);
  }
}

class ExactLocationModule {
  readonly permissions = LOCATION_PERMISSIONS;

  get features(): ReadonlySet<LocationFeature> {
    return new Set(getLocationBackend().features);
  }

  getCurrentPosition(options?: PositionOptions): Promise<GeolocationPosition> {
    return getLocationBackend().getCurrentPosition(options);
  }

  watchPosition(
    success: PositionCallback,
    error?: PositionErrorCallback | null,
    options?: PositionOptions,
  ): number {
    return getLocationBackend().watchPosition(success, error, options);
  }

  clearWatch(watchId: number): void {
    getLocationBackend().clearWatch(watchId);
  }
}

const geolocation = new ExactGeolocation();

export function getGeolocation(): Geolocation {
  return geolocation;
}

export const Location = new ExactLocationModule();

export type ExactLocationPermissions = typeof LOCATION_PERMISSIONS;
