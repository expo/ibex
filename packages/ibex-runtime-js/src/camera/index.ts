/**
 * Exact camera runtime core.
 *
 * This module intentionally keeps the browser-facing camera implementation out
 * of the React wrapper package so that:
 * 1. the permission/access layer can query camera state without importing React
 * 2. the agent server can inspect active camera sessions directly
 * 3. the `exact/camera` React package can stay thin and mostly declarative
 *
 * The current implementation is explicitly web-first. It provides the public
 * RFC 0044 surface area in a way that works today in browser development and
 * in the camera lab, while keeping the internal contracts shaped so that
 * native backends can replace or augment this logic later.
 */

import { CapabilityDeniedError, DOMException } from "../events/DOMException.js";
import { deriveSceneObjectsFromSignals } from "./scene";

const __DEV__ = process.env.NODE_ENV !== "production";

declare global {
  var __hostCall:
    | ((operation: string, argsJson: string) => unknown)
    | undefined;
  var __exactPlatform: string | undefined;
}

interface ExactRuntimeModuleMetadata {
  moduleId?: number;
  version?: string;
  stateOffset?: number | null;
  stateSize?: number;
}

interface ExactRuntimeModuleMetadataBridge {
  __moduleMetadata?: Record<string, ExactRuntimeModuleMetadata>;
  getModuleMetadata?: (name: string) => ExactRuntimeModuleMetadata | null;
}

const NATIVE_CAMERA_MODULE_NAME = "com.exact.camera";
const MIN_NATIVE_CAMERA_MODULE_VERSION = "0.2.0";

export type CameraPosition = "front" | "back" | "external";
export type CameraResizeMode = "cover" | "contain" | "stretch";
export type CameraPreviewMode = "native" | "processed";
export type CameraFlashMode = "off" | "on" | "auto";
export type CameraProcessingMode = "auto" | "reduced" | "none";
export type CameraPixelFormat = "yuv420" | "nv12" | "bgra";
export type CameraVideoCodec = "h264" | "h265";
export type PermissionState = "granted" | "denied" | "prompt" | "unavailable";
export type CameraIntent =
  | "selfie"
  | "barcode-scan"
  | "video-call"
  | "document-scan"
  | "pro-photo"
  | (string & {});
export type CameraCapturePath =
  | "photo-pipeline"
  | "snapshot-path-b"
  | "processed-photo-pass";
export type CameraThermalState = "nominal" | "fair" | "serious" | "critical";
export type CaptureDowngradeFeature =
  | "processing"
  | "raw-capture"
  | "flash"
  | "retroactive-audio"
  | "effects"
  | "manual-controls"
  | "retroactive-buffer";
export type CapturePlanBlocker =
  | "permission-denied"
  | "device-unavailable"
  | "pipeline-not-enabled"
  | "plan-stale";
export type CapturePlanWarning =
  | "thermal-critical"
  | "format-incompatible"
  | "intent-requires-processing"
  | "thermal-serious";

export interface CameraPoint {
  x: number;
  y: number;
}

export interface CameraRect extends CameraPoint {
  width: number;
  height: number;
}

export interface CameraLens {
  type: "ultrawide" | "wide" | "telephoto";
  focalLength: number;
  aperture: number;
  minFocusDistance: number;
}

export interface CameraFormat {
  photoWidth: number;
  photoHeight: number;
  videoWidth: number;
  videoHeight: number;
  minFps: number;
  maxFps: number;
  supportsHdr: boolean;
  supportsDepth: boolean;
  pixelFormat: CameraPixelFormat;
  videoStabilization: Array<"off" | "standard" | "cinematic" | "auto">;
}

export interface CameraCapabilities {
  flash: boolean;
  torch: boolean;
  depth: boolean;
  lidar: boolean;
  hdr: boolean;
  lowLight: boolean;
  manualFocus: boolean;
  manualExposure: boolean;
  manualWhiteBalance: boolean;
  rawCapture: boolean;
  processingControl: boolean;
  multiCamera: boolean;
  retroactiveRecording: boolean;
}

export interface CameraDevice {
  id: string;
  position: CameraPosition;
  name: string;
  isVirtual: boolean;
  lenses: CameraLens[];
  minZoom: number;
  maxZoom: number;
  formats: CameraFormat[];
  capabilities: CameraCapabilities;
}

export interface CameraPermissionDetails {
  state: PermissionState;
  canRequestAgain: boolean | null;
  settingsUrl?: string;
  platformDetail?: Record<string, unknown>;
}

export interface CameraError {
  code:
    | "device/unavailable"
    | "device/in-use"
    | "device/disconnected"
    | "device/configuration-failed"
    | "permission/camera-denied"
    | "permission/microphone-denied"
    | "permission/capability-denied"
    | "session/limit-exceeded"
    | "session/audio-conflict"
    | "session/interrupted"
    | "session/memory-pressure"
    | "capture/failed"
    | "capture/pipeline-disabled"
    | "capture/plan-stale"
    | "capture/no-buffer-data"
    | "capture/insufficient-storage"
    | "capture/codec-unsupported"
    | "capture/microphone-unavailable"
    | "capture/timeout"
    | "processor/failed"
    | "processor/overload";
  message: string;
  cause?: Error;
  recoverable: boolean;
}

export interface CameraStatusEvent {
  code:
    | "session/resumed"
    | "session/path-b-activated"
    | "session/path-b-deactivated"
    | "session/thermal-warning"
    | "session/thermal-downgrade"
    | "recording/frames-dropped";
  message: string;
}

export interface CameraPhotoResult {
  uri: string;
  width: number;
  height: number;
  exif?: Record<string, unknown>;
  rawUri: string | null;
  metadata: Record<string, unknown>;
  provenance: CaptureProvenance;
  analysis?: CaptureAnalysis;
}

export interface CameraBurstResult {
  photos: Array<{
    uri: string;
    width: number;
    height: number;
    timestamp: number;
  }>;
  provenance: CaptureProvenance;
}

export interface CameraVideoResult {
  uri: string;
  duration: number;
  size: number;
  retroactiveSeconds?: number;
  retroactiveAudioAvailable?: boolean;
  provenance: CaptureProvenance;
}

export interface CameraSnapshotResult {
  uri: string;
  width: number;
  height: number;
  provenance: CaptureProvenance;
  analysis?: CaptureAnalysis;
}

export type CameraCaptureResult = CameraPhotoResult | CameraSnapshotResult;

export interface CaptureAnalysis {
  faces?: number;
  blur?: number;
  exposure?: "under" | "good" | "over";
  hasGps?: boolean;
  dominantSubject?: string;
  barcodes?: Array<{ type: string; data: string }>;
}

export interface CaptureDowngrade {
  feature: CaptureDowngradeFeature;
  requested: string;
  actual: string;
  reason: string;
}

export interface CaptureProvenance {
  capturePath: CameraCapturePath;
  intent?: string;
  previewMode: CameraPreviewMode;
  pathBActive: boolean;
  deviceId: string;
  isVirtual: boolean;
  formatSummary: string;
  processing: CameraProcessingMode;
  effectsApplied: boolean;
  downgrades: CaptureDowngrade[];
  thermalState: CameraThermalState;
  flashFired: boolean;
  locationEmbedded: boolean;
  timestamp: number;
  frameId: number | null;
  activeSettings: {
    flash: CameraFlashMode;
    zoom: number;
    processing: CameraProcessingMode;
    intent: string | null;
  };
  qualityMetrics: {
    brightness: number | null;
    blur: number | null;
    glare: number | null;
  } | null;
  analysisAtCapture: {
    faces: number | null;
    barcodes: number | null;
    dominantSubject: string | null;
  } | null;
}

export interface CameraCapturePlan {
  allowed: boolean;
  blockers: CapturePlanBlocker[];
  warnings: CapturePlanWarning[];
  advisory: string | null;
  planVersion: number;
  validUntilMs: number;
  recommendedDeviceId: string | null;
  recommendedFormat: CameraFormat | null;
  plannedCapturePath: CameraCapturePath;
  requiredPermissions: string[];
  optionalPermissions: string[];
  requiresProcessingPipeline: boolean;
  estimatedWarmupMs: number;
  estimatedCaptureLatencyMs: number;
  thermalState: CameraThermalState;
  fallbacks: Array<{
    kind:
      | "switch-device"
      | "drop-effect"
      | "use-snapshot"
      | "disable-raw"
      | "continue-without-location";
    reason: string;
  }>;
}

export interface CameraReadiness {
  ready: boolean;
  score: number;
  staleMs: number;
  frameId: number;
  reasons: string[];
  suggestions: string[];
  metrics: {
    brightness?: number;
    blur?: number;
    glare?: number;
    motion?: number;
    subjectCoverage?: number;
    horizonLevel?: number;
  };
}

export interface SessionCapabilities {
  maxSimultaneousSessions: number;
  simultaneousDevices: Array<{
    deviceIds: string[];
    perDeviceConstraints: Array<{
      deviceId: string;
      maxVideoWidth: number;
      maxVideoHeight: number;
    }> | null;
  }>;
  estimatedMemoryBudgetMB: number;
  capture: {
    photo: boolean;
    snapshot: boolean;
    video: boolean;
  };
}

export type CameraSceneFeature =
  | "objects"
  | "text"
  | "barcodes"
  | "faces"
  | "brightness"
  | "blur"
  | "dominantColors";

export interface CameraSceneRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface CameraSceneSnapshot {
  frameId: number | null;
  objects?: Array<{
    label: string;
    bounds: CameraSceneRect;
    confidence: number;
  }>;
  text?: Array<{
    value: string;
    bounds: CameraSceneRect;
  }>;
  barcodes?: Array<{
    type: string;
    data: string;
    bounds: CameraSceneRect;
  }>;
  faces?: Array<{
    bounds: CameraSceneRect;
  }>;
  brightness?: number;
  blur?: number;
  dominantColors?: string[];
  unavailableFeatures?: Array<{
    feature: CameraSceneFeature;
    reason: string;
  }>;
}

export interface CameraProcessorStateSnapshot {
  frameId: number | null;
  timestamp: number | null;
  result: unknown;
}

export type CameraWaitForCondition =
  | { barcodes: { minCount: number } }
  | { faces: { minCount: number } }
  | { text: { contains: string } }
  | { brightness: { above?: number; below?: number } }
  | { processorResult: { key: string; notNull: boolean } };

export interface CameraWaitForResult {
  matched: boolean;
  elapsed: number;
  frameId: number | null;
  snapshot?: Record<string, unknown>;
  reason?: "timeout" | "budget-exhausted";
}

export interface CameraReplayExport {
  uri: string;
  seconds: number;
  frameCount: number;
  startFrameId: number;
  endFrameId: number;
}

export interface CameraRecordedCapture {
  captureId: string;
  result: CameraCaptureResult;
}

export interface CameraCodeScannerResult {
  type: string;
  data: string;
  bounds: CameraRect;
  corners: CameraPoint[];
}

export interface CameraAnalysisSnapshot {
  histogram?: {
    r: number[];
    g: number[];
    b: number[];
    lum: number[];
  };
  clipping?: {
    r: number;
    g: number;
    b: number;
  };
  fps: number;
  frameId: number;
}

export interface CameraAnalysisOptions {
  histogram?: boolean;
  clipping?: boolean;
  fps?: number;
}

export interface CameraCodeScanner {
  types: string[];
  fps?: number;
  onScanned: (codes: CameraCodeScannerResult[]) => void;
}

export interface CameraRecordingProgress {
  elapsedSeconds: number;
  bytesWritten: number;
}

export interface CameraPhotoOptions {
  flash?: CameraFlashMode;
  format?: "heic" | "jpeg" | "png";
  quality?: number;
  raw?: boolean;
  exif?: boolean;
  location?: boolean;
  shutterSound?: boolean;
  processing?: CameraProcessingMode;
  depth?: boolean;
}

export interface CameraBurstOptions {
  count: number;
  interval?: number;
  format?: "heic" | "jpeg" | "png";
  quality?: number;
}

export interface CameraSnapshotOptions {
  quality?: number;
  format?: "jpeg" | "png";
}

export interface CameraRecordingOptions {
  codec?: CameraVideoCodec;
  maxDuration?: number;
  audio?: boolean;
  location?: boolean;
  includeRetroactive?: boolean;
  recordingFps?: number;
  onFinished?: (video: CameraVideoResult) => void;
  onError?: (error: CameraError) => void;
  onProgress?: (info: CameraRecordingProgress) => void;
}

export interface PlanCaptureOptions {
  intent: CameraIntent;
  minQuality?: "photo" | "snapshot" | "any";
  returnAnalysis?: boolean;
}

export interface IntentCaptureOptions extends PlanCaptureOptions {
  planVersion?: number;
}

export interface CameraFrameProcessor<Result = unknown> {
  kind: "exact-camera-frame-processor";
  source: string;
  fps: number;
  onResult?: (result: Result) => void;
}

export interface CameraSessionOptions {
  id?: string;
  device?: CameraDevice | null;
  position?: CameraPosition;
  active?: boolean;
  intent?: CameraIntent;
  photo?: boolean;
  video?: boolean;
  previewMode?: CameraPreviewMode;
  zoom?: number;
  mirror?: boolean;
  resizeMode?: CameraResizeMode;
  flash?: CameraFlashMode;
  torch?: boolean;
  autoFocus?: boolean;
  autoExposure?: boolean;
  autoWhiteBalance?: boolean;
  focusDistance?: number;
  exposureBias?: number;
  iso?: number;
  shutterSpeed?: number;
  whiteBalance?: number;
  processing?: CameraProcessingMode;
  format?: CameraFormat | null;
  frameProcessor?: CameraFrameProcessor | null;
  codeScanner?: CameraCodeScanner | null;
  retroactiveBuffer?: number;
  retroactiveAudio?: boolean;
  outputOrientation?: "device" | "locked";
  audioSessionPolicy?: "mixWithOthers" | "playAndRecord" | "soloAmbient";
  onInitialized?: () => void;
  onError?: (error: CameraError) => void;
  onStatusChange?: (event: CameraStatusEvent) => void;
  onShutter?: () => void;
}

export interface CameraSessionSnapshot {
  id: string;
  deviceId: string | null;
  deviceName: string | null;
  position: CameraPosition;
  intent: CameraIntent | null;
  active: boolean;
  initialized: boolean;
  previewMode: CameraPreviewMode;
  photo: boolean;
  video: boolean;
  pathBActive: boolean;
  frameProcessorActive: boolean;
  codeScannerActive: boolean;
  usingVirtualCamera: boolean;
  recordingState: "inactive" | "recording" | "paused";
  mirror: boolean;
  resizeMode: CameraResizeMode;
  zoom: number;
  thermalState: CameraThermalState;
  lastFrameId: number | null;
  renderSize: { width: number; height: number } | null;
  streamSize: { width: number; height: number } | null;
  lastError: CameraError | null;
}

export interface CameraSessionDiagnostics {
  framesReceived: number;
  framesProcessed: number;
  framesDropped: number;
  processorFps: number;
  pathBActivations: number;
  lastFrameTimestamp: number | null;
  lastProcessorTimestamp: number | null;
  recordingBytesWritten: number;
  recordingChunks: number;
  barcodeDetectorAvailable: boolean;
  workerActive: boolean;
  virtualSourceType: string | null;
}

export interface CameraSessionBindings {
  container: HTMLElement;
  video: HTMLVideoElement;
  processedCanvas: HTMLCanvasElement;
}

export interface CameraAgentFrameCaptureOptions {
  format?: "png" | "jpeg";
  quality?: number;
  space?: "view" | "sensor";
}

export interface CameraAgentSessionHandle {
  id: string;
  getSnapshot(): CameraSessionSnapshot;
  getDiagnostics(): CameraSessionDiagnostics;
  getPlanContext?(): Pick<
    CameraSessionOptions,
    "format" | "processing" | "photo" | "previewMode"
  >;
  captureFrame(options?: CameraAgentFrameCaptureOptions): Promise<Blob>;
  takePhoto(options?: CameraPhotoOptions): Promise<CameraPhotoResult>;
  takeSnapshot?(options?: CameraSnapshotOptions): Promise<CameraSnapshotResult>;
  focus(point: CameraPoint): Promise<void>;
  computeAnalysis(options: CameraAnalysisOptions): CameraAnalysisSnapshot | null;
  getProcessorState?(): CameraProcessorStateSnapshot | null;
  getScene?(options?: {
    features?: CameraSceneFeature[];
  }): Promise<CameraSceneSnapshot>;
  exportReplay?(options: {
    seconds: number;
  }): Promise<CameraReplayExport>;
}

type VirtualCameraSource =
  | {
      type: "generated";
      pattern?: "color-bars" | "gradient" | "counter";
    }
  | {
      type: "image";
      uri: string;
    }
  | {
      type: "video";
      uri: string;
    }
  | {
      type: "screen";
      viewRef?: unknown;
    }
  | {
      type: "remote";
      url: string;
    };

export interface VirtualCameraConfig {
  source: VirtualCameraSource;
  loop?: boolean;
  fps?: number;
  resolution?: {
    width: number;
    height: number;
  };
}

interface NativeCameraHostPermissionResponse extends CameraPermissionDetails {}

interface NativeCameraHostDevicesResponse {
  devices: CameraDevice[];
}

interface NativeCameraHostSessionCapabilitiesResponse extends SessionCapabilities {}

interface MediaTrackCapabilitiesLike {
  zoom?: {
    min?: number;
    max?: number;
  };
  torch?: boolean;
  frameRate?: {
    min?: number;
    max?: number;
  };
  width?: {
    min?: number;
    max?: number;
  };
  height?: {
    min?: number;
    max?: number;
  };
}

type MediaTrackWithCapabilities = MediaStreamTrack & {
  getCapabilities?: () => MediaTrackCapabilitiesLike;
};

interface MediaRecorderWithRequestData extends MediaRecorder {
  requestData(): void;
}

type CameraPermissionNavigator = Navigator;

interface BarcodeDetectorShape {
  detect(source: CanvasImageSource): Promise<DetectedBarcodeShape[]>;
}

interface BarcodeDetectorCtor {
  new (options?: { formats?: string[] }): BarcodeDetectorShape;
  getSupportedFormats?: () => Promise<string[]>;
}

interface DetectedBarcodeShape {
  rawValue?: string;
  format?: string;
  boundingBox?: DOMRectReadOnly;
  cornerPoints?: Array<{ x: number; y: number }>;
}

interface TextDetectorShape {
  detect(source: CanvasImageSource): Promise<DetectedTextShape[]>;
}

interface TextDetectorCtor {
  new (): TextDetectorShape;
}

interface DetectedTextShape {
  rawValue?: string;
  boundingBox?: DOMRectReadOnly;
}

interface FaceDetectorShape {
  detect(source: CanvasImageSource): Promise<DetectedFaceShape[]>;
}

interface FaceDetectorCtor {
  new (options?: { fastMode?: boolean; maxDetectedFaces?: number }): FaceDetectorShape;
}

interface DetectedFaceShape {
  boundingBox?: DOMRectReadOnly;
}

interface WindowWithCameraApis extends Window {
  BarcodeDetector?: BarcodeDetectorCtor;
  TextDetector?: TextDetectorCtor;
  FaceDetector?: FaceDetectorCtor;
}

interface ImageCaptureLike {
  takePhoto?: () => Promise<Blob>;
}

interface ImageCaptureCtorLike {
  new (track: MediaStreamTrack): ImageCaptureLike;
}

interface FrameLoopToken {
  kind: "video-frame-callback" | "raf";
  id: number;
}

interface WorkerProcessResponse {
  outputBuffer?: ArrayBuffer;
  result?: unknown;
}

interface WorkerPendingRequest {
  resolve: (value: WorkerProcessResponse) => void;
  reject: (error: Error) => void;
}

interface RollingChunk {
  blob: Blob;
  timestamp: number;
  startedAt: number;
  endedAt: number;
  durationMs: number;
  size: number;
  includesAudio: boolean;
}

const CAMERA_OPERATION_PERMISSIONS = Object.freeze({
  takePhoto: Object.freeze(["device:camera:back", "device:camera:front"]),
  takeBurst: Object.freeze(["device:camera:back", "device:camera:front"]),
  takeSnapshot: Object.freeze([]),
  startRecording: Object.freeze([
    "device:camera:back",
    "device:camera:front",
    "device:microphone",
  ]),
});

export const CAMERA_FEATURES = Object.freeze([
  "preview",
  "photo",
  "burst",
  "snapshot",
  "recording",
  "intentCapture",
  "readiness",
  "frameProcessor",
  "processedPreview",
  "codeScanner",
  "virtualCamera",
  "analysis",
]);

export const CAMERA_PERMISSIONS = CAMERA_OPERATION_PERMISSIONS;

const DEFAULT_WEB_FORMATS = [
  {
    photoWidth: 640,
    photoHeight: 480,
    videoWidth: 640,
    videoHeight: 480,
    minFps: 15,
    maxFps: 30,
    supportsHdr: false,
    supportsDepth: false,
    pixelFormat: "bgra",
    videoStabilization: ["off", "auto"],
  },
  {
    photoWidth: 1280,
    photoHeight: 720,
    videoWidth: 1280,
    videoHeight: 720,
    minFps: 15,
    maxFps: 30,
    supportsHdr: false,
    supportsDepth: false,
    pixelFormat: "bgra",
    videoStabilization: ["off", "auto"],
  },
  {
    photoWidth: 1920,
    photoHeight: 1080,
    videoWidth: 1920,
    videoHeight: 1080,
    minFps: 15,
    maxFps: 60,
    supportsHdr: false,
    supportsDepth: false,
    pixelFormat: "bgra",
    videoStabilization: ["off", "auto"],
  },
  {
    photoWidth: 3840,
    photoHeight: 2160,
    videoWidth: 3840,
    videoHeight: 2160,
    minFps: 24,
    maxFps: 60,
    supportsHdr: false,
    supportsDepth: false,
    pixelFormat: "bgra",
    videoStabilization: ["off", "auto"],
  },
] satisfies CameraFormat[];

const DEFAULT_VIRTUAL_CONFIG: VirtualCameraConfig = {
  source: {
    type: "generated",
    pattern: "counter",
  },
  fps: 30,
  resolution: {
    width: 1280,
    height: 720,
  },
  loop: true,
};

const DEFAULT_CAMERA_CAPABILITIES: CameraCapabilities = Object.freeze({
  flash: false,
  torch: false,
  depth: false,
  lidar: false,
  hdr: false,
  lowLight: false,
  manualFocus: false,
  manualExposure: false,
  manualWhiteBalance: false,
  rawCapture: false,
  processingControl: false,
  multiCamera: true,
  retroactiveRecording: true,
});

const DEFAULT_CAPTURE_ANALYSIS: CaptureAnalysis = Object.freeze({
  faces: 0,
  blur: 0,
  exposure: "good",
  hasGps: false,
  dominantSubject: "scene",
  barcodes: [],
});

const BARCODE_INTENT_TYPES = Object.freeze([
  "qr",
  "ean-13",
  "ean-8",
  "code-128",
  "code-39",
  "code-93",
  "upc-a",
  "upc-e",
  "pdf-417",
  "aztec",
  "data-matrix",
  "itf",
]);

export const CAMERA_SCENE_FEATURES = Object.freeze<CameraSceneFeature[]>([
  "objects",
  "text",
  "faces",
  "barcodes",
  "brightness",
  "blur",
  "dominantColors",
]);

const deviceSubscribers = new Set<() => void>();
const registrySubscribers = new Set<() => void>();
const activeSessions = new Map<string, CameraAgentSessionHandle>();
const lastSessionCaptures = new Map<string, CameraRecordedCapture>();

const virtualCameraConfigs = new Map<string, VirtualCameraConfig>();
let defaultVirtualCameraConfig: VirtualCameraConfig = { ...DEFAULT_VIRTUAL_CONFIG };

let cachedDevices: CameraDevice[] = [];
let devicesRefreshPromise: Promise<CameraDevice[]> | null = null;
let mediaDeviceListenersInstalled = false;

function supportsBrowserCameraApis(): boolean {
  return typeof navigator !== "undefined" && !!navigator.mediaDevices;
}

function getNavigator(): CameraPermissionNavigator | null {
  if (typeof navigator === "undefined") {
    return null;
  }
  return navigator;
}

function isNativeCameraHostEnvironment(): boolean {
  // Native Exact runtimes expose a synchronous bridge through `__hostCall`.
  // Browsers never set `__exactPlatform`, so this is the clean runtime split
  // between the web camera backend and the Apple host-backed one.
  return (
    typeof globalThis.__hostCall === "function" &&
    typeof globalThis.__exactPlatform === "string" &&
    globalThis.__exactPlatform.length > 0 &&
    globalThis.__exactPlatform !== "web"
  );
}

function readNativeCameraModuleMetadata(): ExactRuntimeModuleMetadata | null {
  const exact = (globalThis as typeof globalThis & {
    exact?: ExactRuntimeModuleMetadataBridge;
  }).exact;

  if (!exact) {
    return null;
  }

  if (typeof exact.getModuleMetadata === "function") {
    try {
      return exact.getModuleMetadata(NATIVE_CAMERA_MODULE_NAME);
    } catch {
      return null;
    }
  }

  const metadata = exact.__moduleMetadata?.[NATIVE_CAMERA_MODULE_NAME];
  return metadata ?? null;
}

function parseModuleVersion(version: string): number[] | null {
  const segments = version.trim().split(".");
  if (segments.length === 0) {
    return null;
  }

  const parsed: number[] = [];
  for (const segment of segments) {
    const match = /^\d+/.exec(segment);
    if (!match) {
      return null;
    }
    parsed.push(Number.parseInt(match[0], 10));
  }

  return parsed;
}

function isModuleVersionAtLeast(actual: string, minimum: string): boolean {
  const actualParts = parseModuleVersion(actual);
  const minimumParts = parseModuleVersion(minimum);
  if (!actualParts || !minimumParts) {
    return false;
  }

  const length = Math.max(actualParts.length, minimumParts.length);
  for (let index = 0; index < length; index += 1) {
    const actualValue = actualParts[index] ?? 0;
    const minimumValue = minimumParts[index] ?? 0;

    if (actualValue > minimumValue) {
      return true;
    }
    if (actualValue < minimumValue) {
      return false;
    }
  }

  return true;
}

export function hasNativeCameraHost(): boolean {
  if (!isNativeCameraHostEnvironment()) {
    return false;
  }

  const metadata = readNativeCameraModuleMetadata();
  return typeof metadata?.version === "string"
    && isModuleVersionAtLeast(metadata.version, MIN_NATIVE_CAMERA_MODULE_VERSION);
}

export function invokeNativeCameraHostCall<T>(
  operation: string,
  payload?: unknown,
): T | undefined {
  const hostCall = globalThis.__hostCall;
  if (typeof hostCall !== "function") {
    return undefined;
  }

  return hostCall(
    operation,
    typeof payload === "undefined" ? "{}" : JSON.stringify(payload),
  ) as T;
}

function normalizeNativePermissionResponse(
  response: NativeCameraHostPermissionResponse | null | undefined,
  fallbackSettingsUrl: string,
): CameraPermissionDetails {
  if (!response) {
    return {
      state: "unavailable",
      canRequestAgain: false,
      settingsUrl: fallbackSettingsUrl,
      platformDetail: {
        reason: "native_camera_host_unavailable",
      },
    };
  }

  return {
    state: response.state ?? "unavailable",
    canRequestAgain:
      typeof response.canRequestAgain === "boolean" || response.canRequestAgain === null
        ? response.canRequestAgain
        : false,
    settingsUrl: response.settingsUrl ?? fallbackSettingsUrl,
    platformDetail: response.platformDetail,
  };
}

function getWindowObject(): WindowWithCameraApis | null {
  if (typeof window === "undefined") {
    return null;
  }
  return window as WindowWithCameraApis;
}

function createSessionId(): string {
  if (
    (globalThis as { __exactRuntimeContext?: string }).__exactRuntimeContext !== "shell" &&
    typeof crypto !== "undefined" &&
    typeof crypto.randomUUID === "function"
  ) {
    try {
      return crypto.randomUUID();
    } catch {
      // Native shells may expose crypto while withholding random-byte capability.
    }
  }
  return `camera-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
}

function createCaptureId(): string {
  if (
    (globalThis as { __exactRuntimeContext?: string }).__exactRuntimeContext !== "shell" &&
    typeof crypto !== "undefined" &&
    typeof crypto.randomUUID === "function"
  ) {
    try {
      return `cap-${crypto.randomUUID()}`;
    } catch {
      // Native shells may expose crypto while withholding random-byte capability.
    }
  }
  return `cap-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
}

function createUrlForBlob(blob: Blob): string {
  return URL.createObjectURL(blob);
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function normalizeFacingFromLabel(label: string): CameraPosition {
  const normalized = label.toLowerCase();
  if (
    normalized.includes("front") ||
    normalized.includes("facetime") ||
    normalized.includes("user") ||
    normalized.includes("selfie")
  ) {
    return "front";
  }
  if (
    normalized.includes("back") ||
    normalized.includes("rear") ||
    normalized.includes("environment")
  ) {
    return "back";
  }
  return "external";
}

function cloneCameraFormats(): CameraFormat[] {
  return DEFAULT_WEB_FORMATS.map((format) => ({
    ...format,
    videoStabilization: [...format.videoStabilization],
  }));
}

function cloneCameraCapabilities(): CameraCapabilities {
  return { ...DEFAULT_CAMERA_CAPABILITIES };
}

function getCameraPermissionName(position: CameraPosition): string {
  switch (position) {
    case "front":
      return "device:camera:front";
    case "external":
      return "device:camera:external";
    default:
      return "device:camera:back";
  }
}

function getIntentPreferredPosition(intent: CameraIntent): CameraPosition {
  switch (intent) {
    case "selfie":
    case "video-call":
      return "front";
    default:
      return "back";
  }
}

function getIntentReadinessThreshold(intent: CameraIntent): number {
  switch (intent) {
    case "document-scan":
      return 0.75;
    case "barcode-scan":
      return 0.6;
    default:
      return 0.7;
  }
}

function isLatencySensitiveIntent(intent: CameraIntent): boolean {
  return intent === "barcode-scan" || intent === "video-call";
}

function isQualityFirstIntent(intent: CameraIntent): boolean {
  return intent === "document-scan" || intent === "pro-photo" || intent === "selfie";
}

function normalizeCodeType(type: string): string {
  return type.trim().toLowerCase().replaceAll("_", "-");
}

function clampScore(value: number): number {
  return Math.max(0, Math.min(1, value));
}

function estimateBrightnessFromHistogram(
  histogram: CameraAnalysisSnapshot["histogram"],
): number | undefined {
  const luminance = histogram?.lum;
  if (!luminance || luminance.length === 0) {
    return undefined;
  }

  let weightedSum = 0;
  let total = 0;
  for (let index = 0; index < luminance.length; index += 1) {
    const count = luminance[index] ?? 0;
    weightedSum += index * count;
    total += count;
  }

  if (total <= 0) {
    return undefined;
  }

  return weightedSum / (255 * total);
}

function estimateBlurFromAnalysis(analysis: CameraAnalysisSnapshot | null): number {
  const clipping = analysis?.clipping;
  if (!clipping) {
    return 0.18;
  }

  // This is intentionally simple. We want a stable, cross-platform proxy for
  // "likely blurry" without pretending we already have a full ML readiness
  // model on every backend.
  const clippedAverage = (clipping.r + clipping.g + clipping.b) / 3;
  return clampScore(0.12 + clippedAverage * 0.55);
}

function estimateGlareFromAnalysis(analysis: CameraAnalysisSnapshot | null): number {
  const clipping = analysis?.clipping;
  if (!clipping) {
    return 0;
  }
  return clampScore(Math.max(clipping.r, clipping.g, clipping.b));
}

function resolveSessionDevice(
  snapshot: Pick<CameraSessionSnapshot, "deviceId" | "position">,
  devices: CameraDevice[],
): CameraDevice | null {
  if (snapshot.deviceId) {
    return devices.find((device) => device.id === snapshot.deviceId) ?? null;
  }
  return chooseCameraDevice(devices, snapshot.position) ?? null;
}

function summarizeFormat(
  device: CameraDevice | null,
  format: CameraFormat | null | undefined,
): string {
  const resolvedFormat = format ?? device?.formats[0] ?? null;
  if (!resolvedFormat) {
    return "unknown";
  }
  return `${resolvedFormat.photoWidth}x${resolvedFormat.photoHeight}@${resolvedFormat.maxFps}`;
}

function defaultSnapshotQuality(intent: CameraIntent): "photo" | "snapshot" | "any" {
  if (intent === "video-call" || intent === "barcode-scan") {
    return "any";
  }
  return "photo";
}

function selectRecommendedFormat(
  device: CameraDevice | null,
  intent: CameraIntent,
): CameraFormat | null {
  if (!device) {
    return null;
  }

  switch (intent) {
    case "pro-photo":
      return chooseCameraFormat(device, [{ photoResolution: "max" }]);
    case "video-call":
      return chooseCameraFormat(device, [{ videoAspectRatio: 16 / 9 }, { fps: 30 }]);
    default:
      return chooseCameraFormat(device, [{ photoResolution: "max" }]);
  }
}

function createPlanVersion(signature: string): number {
  let hash = 0;
  for (let index = 0; index < signature.length; index += 1) {
    hash = (hash * 31 + signature.charCodeAt(index)) >>> 0;
  }
  return hash;
}

export function resolveCameraIntentOptions(
  intent: CameraIntent | undefined,
): Partial<CameraSessionOptions> {
  if (!intent) {
    return {};
  }

  switch (intent) {
    case "selfie":
      return {
        position: "front",
        mirror: true,
        photo: true,
      };
    case "barcode-scan":
      return {
        position: "back",
        photo: true,
        torch: false,
        codeScanner: {
          types: [...BARCODE_INTENT_TYPES],
          onScanned: () => {
            // Intent defaults cannot safely invent user callbacks. The React
            // wrapper replaces this placeholder when the caller provides one.
          },
        },
      };
    case "video-call":
      return {
        position: "front",
        video: true,
        previewMode: "processed",
      };
    case "document-scan":
      return {
        position: "back",
        flash: "auto",
        processing: "none",
      };
    case "pro-photo":
      return {
        position: "back",
        photo: true,
        processing: "none",
      };
    default:
      return {};
  }
}

function chooseCapturePath(
  snapshot: CameraSessionSnapshot,
  intent: CameraIntent,
  minQuality: "photo" | "snapshot" | "any",
): CameraCapturePath {
  if (minQuality === "photo") {
    return snapshot.previewMode === "processed"
      ? "processed-photo-pass"
      : "photo-pipeline";
  }

  if (minQuality === "snapshot") {
    return "snapshot-path-b";
  }

  if (snapshot.previewMode === "processed") {
    return "processed-photo-pass";
  }

  if (isLatencySensitiveIntent(intent) && snapshot.pathBActive) {
    return "snapshot-path-b";
  }

  if (isQualityFirstIntent(intent)) {
    return "photo-pipeline";
  }

  return "photo-pipeline";
}

export async function planCameraCapture(input: {
  snapshot: CameraSessionSnapshot;
  devices: CameraDevice[];
  sessionOptions: Pick<
    CameraSessionOptions,
    "format" | "processing" | "photo" | "previewMode"
  >;
  options: PlanCaptureOptions;
}): Promise<CameraCapturePlan> {
  const minQuality = input.options.minQuality ?? defaultSnapshotQuality(input.options.intent);
  const activeDevice = resolveSessionDevice(input.snapshot, input.devices);
  const recommendedPosition = getIntentPreferredPosition(input.options.intent);
  const recommendedDevice = chooseCameraDevice(input.devices, recommendedPosition);
  const recommendedFormat = selectRecommendedFormat(
    recommendedDevice ?? activeDevice,
    input.options.intent,
  );
  const plannedCapturePath = chooseCapturePath(
    input.snapshot,
    input.options.intent,
    minQuality,
  );
  const requiredPermissions = [getCameraPermissionName(input.snapshot.position)];
  const optionalPermissions: string[] = [];
  const blockers: CapturePlanBlocker[] = [];
  const warnings: CapturePlanWarning[] = [];
  const fallbacks: CameraCapturePlan["fallbacks"] = [];

  const permission = await getCameraPermissionDetails();
  if (permission.state !== "granted" && !input.snapshot.usingVirtualCamera) {
    blockers.push("permission-denied");
  }
  if (!activeDevice) {
    blockers.push("device-unavailable");
  }
  if (
    (plannedCapturePath === "photo-pipeline" || plannedCapturePath === "processed-photo-pass") &&
    input.snapshot.photo === false
  ) {
    blockers.push("pipeline-not-enabled");
  }
  if (input.snapshot.thermalState === "serious") {
    warnings.push("thermal-serious");
  }
  if (input.snapshot.thermalState === "critical") {
    warnings.push("thermal-critical");
    if (plannedCapturePath === "processed-photo-pass") {
      fallbacks.push({
        kind: "drop-effect",
        reason: "thermal state too high for processed capture; effects will be disabled",
      });
    }
  }
  if (
    recommendedFormat &&
    input.sessionOptions.format &&
    recommendedFormat !== input.sessionOptions.format
  ) {
    warnings.push("format-incompatible");
  }

  const requiresProcessingPipeline =
    input.options.intent === "barcode-scan" || input.options.intent === "video-call";
  if (requiresProcessingPipeline && !input.snapshot.pathBActive) {
    warnings.push("intent-requires-processing");
    fallbacks.push({
      kind: "use-snapshot",
      reason: "Path B is cold; the first capture may fall back to the photo pipeline.",
    });
  }
  if (
    recommendedDevice &&
    input.snapshot.deviceId &&
    recommendedDevice.id !== input.snapshot.deviceId
  ) {
    fallbacks.push({
      kind: "switch-device",
      reason: `Intent ${input.options.intent} is a better match for ${recommendedDevice.name}.`,
    });
  }

  const estimatedWarmupMs =
    plannedCapturePath === "snapshot-path-b" && !input.snapshot.pathBActive ? 150 : 0;
  const estimatedCaptureLatencyMs =
    (plannedCapturePath === "snapshot-path-b" ? 50 : 200) + estimatedWarmupMs;
  const advisory =
    blockers.length > 0
      ? null
      : recommendedDevice && recommendedDevice.id !== input.snapshot.deviceId
        ? `${recommendedDevice.name} is the optimal device for ${input.options.intent}.`
        : `Current session is ready for ${input.options.intent}.`;

  const planSignature = JSON.stringify({
    deviceId: input.snapshot.deviceId,
    position: input.snapshot.position,
    intent: input.options.intent,
    minQuality,
    returnAnalysis: input.options.returnAnalysis === true,
    photo: input.snapshot.photo,
    previewMode: input.snapshot.previewMode,
    thermalState: input.snapshot.thermalState,
    permissionState: permission.state,
  });

  return {
    allowed: blockers.length === 0,
    blockers,
    warnings,
    advisory,
    planVersion: createPlanVersion(planSignature),
    validUntilMs: Date.now() + 2_000,
    recommendedDeviceId:
      recommendedDevice && recommendedDevice.id !== input.snapshot.deviceId
        ? recommendedDevice.id
        : null,
    recommendedFormat:
      recommendedFormat && recommendedFormat !== input.sessionOptions.format
        ? recommendedFormat
        : null,
    plannedCapturePath,
    requiredPermissions,
    optionalPermissions,
    requiresProcessingPipeline,
    estimatedWarmupMs,
    estimatedCaptureLatencyMs,
    thermalState: input.snapshot.thermalState,
    fallbacks,
  };
}

export function buildCaptureProvenance(input: {
  snapshot: CameraSessionSnapshot;
  sessionOptions: Pick<
    CameraSessionOptions,
    "flash" | "zoom" | "processing" | "format" | "intent"
  >;
  capturePath: CameraCapturePath;
  analysis?: CameraAnalysisSnapshot | null;
  captureAnalysis?: CaptureAnalysis;
  request?: Pick<CameraPhotoOptions, "flash" | "processing" | "location" | "raw">;
  actualProcessing?: CameraProcessingMode;
  flashFired?: boolean;
  locationEmbedded?: boolean;
  rawUri?: string | null;
}): CaptureProvenance {
  const requestedProcessing = input.request?.processing ?? input.sessionOptions.processing ?? "auto";
  const actualProcessing = input.actualProcessing ?? requestedProcessing;
  const downgrades: CaptureDowngrade[] = [];

  if (requestedProcessing !== actualProcessing) {
    downgrades.push({
      feature: "processing",
      requested: requestedProcessing,
      actual: actualProcessing,
      reason: "The requested capture processing level was downgraded by the platform.",
    });
  }

  if (input.request?.raw === true && !input.rawUri) {
    downgrades.push({
      feature: "raw-capture",
      requested: "true",
      actual: "false",
      reason: "RAW capture is not available for this device/session.",
    });
  }

  const brightness = estimateBrightnessFromHistogram(input.analysis?.histogram);
  const blur = estimateBlurFromAnalysis(input.analysis ?? null);
  const glare = estimateGlareFromAnalysis(input.analysis ?? null);

  return {
    capturePath: input.capturePath,
    intent: input.sessionOptions.intent ?? undefined,
    previewMode: input.snapshot.previewMode,
    pathBActive: input.snapshot.pathBActive,
    deviceId: input.snapshot.deviceId ?? "unknown-device",
    isVirtual: input.snapshot.usingVirtualCamera,
    formatSummary: summarizeFormat(
      resolveSessionDevice(input.snapshot, cachedDevices),
      input.sessionOptions.format,
    ),
    processing: actualProcessing,
    effectsApplied:
      input.capturePath !== "processed-photo-pass" || input.snapshot.thermalState !== "critical",
    downgrades,
    thermalState: input.snapshot.thermalState,
    flashFired: input.flashFired === true,
    locationEmbedded: input.locationEmbedded === true,
    timestamp: Date.now(),
    frameId: input.capturePath === "photo-pipeline" ? null : input.snapshot.lastFrameId,
    activeSettings: {
      flash: input.request?.flash ?? input.sessionOptions.flash ?? "auto",
      zoom: input.sessionOptions.zoom ?? input.snapshot.zoom,
      processing: actualProcessing,
      intent: input.sessionOptions.intent ?? null,
    },
    qualityMetrics:
      typeof brightness === "number" || typeof blur === "number" || typeof glare === "number"
        ? {
            brightness: brightness ?? null,
            blur,
            glare,
          }
        : null,
    analysisAtCapture: input.captureAnalysis
      ? {
          faces: input.captureAnalysis.faces ?? null,
          barcodes: input.captureAnalysis.barcodes?.length ?? null,
          dominantSubject: input.captureAnalysis.dominantSubject ?? null,
        }
      : null,
  };
}

export function buildCaptureAnalysis(input: {
  intent: CameraIntent | undefined;
  analysis: CameraAnalysisSnapshot | null;
  hasLocation: boolean;
  barcodes?: Array<{ type: string; data: string }>;
}): CaptureAnalysis {
  const brightness = estimateBrightnessFromHistogram(input.analysis?.histogram);
  const blur = estimateBlurFromAnalysis(input.analysis);
  const exposure: CaptureAnalysis["exposure"] =
    brightness == null ? "good" : brightness < 0.25 ? "under" : brightness > 0.9 ? "over" : "good";

  return {
    ...DEFAULT_CAPTURE_ANALYSIS,
    blur,
    exposure,
    hasGps: input.hasLocation,
    dominantSubject:
      input.intent === "document-scan"
        ? "document"
        : input.intent === "barcode-scan"
          ? "barcode"
          : input.intent === "selfie" || input.intent === "video-call"
            ? "person"
            : "scene",
    barcodes: input.barcodes ?? [],
  };
}

export function evaluateCameraReadiness(input: {
  snapshot: CameraSessionSnapshot | null;
  analysis: CameraAnalysisSnapshot | null;
  options: {
    intent: CameraIntent;
    readyThreshold?: number;
  };
}): CameraReadiness {
  const snapshot = input.snapshot;
  const threshold = input.options.readyThreshold ?? getIntentReadinessThreshold(input.options.intent);
  const brightness = estimateBrightnessFromHistogram(input.analysis?.histogram);
  const blur = estimateBlurFromAnalysis(input.analysis);
  const glare = estimateGlareFromAnalysis(input.analysis);
  const reasons: string[] = [];
  const suggestions: string[] = [];

  if (!snapshot?.initialized) {
    reasons.push("readiness-throttled");
  }
  if (brightness != null && brightness < 0.2) {
    reasons.push("too-dark");
    suggestions.push("increase-light");
  }
  if (brightness != null && brightness > 0.95) {
    reasons.push("too-bright");
    suggestions.push("reduce-light");
  }
  if (blur > 0.4) {
    reasons.push("too-blurry");
    suggestions.push("hold-steady");
  }
  if (input.options.intent === "document-scan" && glare > 0.5) {
    reasons.push("glare-too-high");
    suggestions.push("reduce-glare");
  }
  if (input.options.intent === "barcode-scan" && !snapshot?.codeScannerActive) {
    reasons.push("low-contrast");
    suggestions.push("move-closer");
  }
  if (input.options.intent === "selfie" && snapshot?.position !== "front") {
    reasons.push("face-off-center");
    suggestions.push("center-subject");
  }

  const brightnessScore = brightness == null ? 0.75 : brightness < 0.2 ? 0.25 : brightness > 0.95 ? 0.35 : 0.9;
  const blurScore = 1 - clampScore(blur);
  const glarePenalty = input.options.intent === "document-scan" ? glare * 0.35 : 0;
  const sessionPenalty = snapshot?.lastError ? 0.35 : 0;
  const score = clampScore((brightnessScore * 0.45) + (blurScore * 0.45) - glarePenalty - sessionPenalty);

  return {
    ready: score >= threshold && reasons.length === 0,
    score,
    staleMs: snapshot?.lastFrameId != null ? 0 : 2_000,
    frameId: input.analysis?.frameId ?? snapshot?.lastFrameId ?? 0,
    reasons,
    suggestions,
    metrics: {
      brightness,
      blur,
      glare,
      motion: 0,
      subjectCoverage: snapshot?.initialized ? 0.8 : 0,
      horizonLevel: 0,
    },
  };
}

function makePhysicalDevice(device: MediaDeviceInfo): CameraDevice {
  return {
    id: device.deviceId,
    position: normalizeFacingFromLabel(device.label),
    name: device.label || "Camera",
    isVirtual: false,
    lenses: [],
    minZoom: 1,
    maxZoom: 4,
    formats: cloneCameraFormats(),
    capabilities: cloneCameraCapabilities(),
  };
}

function getVirtualCameraIds(): string[] {
  const ids = new Set<string>(["virtual-back", "virtual-front"]);
  for (const id of virtualCameraConfigs.keys()) {
    ids.add(id);
  }
  return Array.from(ids);
}

function getVirtualCameraConfig(deviceId: string): VirtualCameraConfig {
  return virtualCameraConfigs.get(deviceId) ?? defaultVirtualCameraConfig;
}

function makeVirtualDevice(deviceId: string): CameraDevice {
  const position: CameraPosition = deviceId.includes("front")
    ? "front"
    : deviceId.includes("back")
      ? "back"
      : "external";
  const config = getVirtualCameraConfig(deviceId);
  const resolution = config.resolution ?? DEFAULT_VIRTUAL_CONFIG.resolution!;

  return {
    id: deviceId,
    position,
    name:
      position === "front"
        ? "Virtual Front Camera"
        : position === "back"
          ? "Virtual Back Camera"
          : "Virtual Camera",
    isVirtual: true,
    lenses: [],
    minZoom: 1,
    maxZoom: 1,
    formats: [
      {
        photoWidth: resolution.width,
        photoHeight: resolution.height,
        videoWidth: resolution.width,
        videoHeight: resolution.height,
        minFps: config.fps ?? 30,
        maxFps: config.fps ?? 30,
        supportsHdr: false,
        supportsDepth: false,
        pixelFormat: "bgra",
        videoStabilization: ["off"],
      },
    ],
    capabilities: {
      ...cloneCameraCapabilities(),
      multiCamera: true,
    },
  };
}

function installMediaDeviceListeners(): void {
  if (mediaDeviceListenersInstalled) {
    return;
  }
  const nav = getNavigator();
  if (!nav?.mediaDevices || typeof nav.mediaDevices.addEventListener !== "function") {
    return;
  }
  mediaDeviceListenersInstalled = true;
  nav.mediaDevices.addEventListener("devicechange", () => {
    void refreshCameraDevices();
  });
}

export async function listCameraDevices(): Promise<CameraDevice[]> {
  if (hasNativeCameraHost()) {
    try {
      const response = invokeNativeCameraHostCall<NativeCameraHostDevicesResponse>(
        "camera.devices.list",
      );
      cachedDevices = response?.devices ?? [];
    } catch {
      cachedDevices = [];
    }

    for (const subscriber of deviceSubscribers) {
      subscriber();
    }

    return cachedDevices.slice();
  }

  installMediaDeviceListeners();

  if (devicesRefreshPromise) {
    return devicesRefreshPromise;
  }

  devicesRefreshPromise = (async () => {
    const devices: CameraDevice[] = [];
    const nav = getNavigator();

    if (nav?.mediaDevices?.enumerateDevices) {
      try {
        const discovered = await nav.mediaDevices.enumerateDevices();
        for (const device of discovered) {
          if (device.kind !== "videoinput") {
            continue;
          }
          devices.push(makePhysicalDevice(device));
        }
      } catch {
        // Ignore enumerate failures and fall back to virtual devices below.
      }
    }

    if (__DEV__) {
      for (const virtualId of getVirtualCameraIds()) {
        devices.push(makeVirtualDevice(virtualId));
      }
    }

    cachedDevices = devices;
    for (const subscriber of deviceSubscribers) {
      subscriber();
    }
    devicesRefreshPromise = null;
    return devices;
  })();

  return devicesRefreshPromise;
}

export async function refreshCameraDevices(): Promise<CameraDevice[]> {
  devicesRefreshPromise = null;
  return listCameraDevices();
}

export function getCachedCameraDevices(): CameraDevice[] {
  return cachedDevices.slice();
}

export function subscribeCameraDevices(listener: () => void): () => void {
  deviceSubscribers.add(listener);
  return () => {
    deviceSubscribers.delete(listener);
  };
}

export function subscribeCameraRegistry(listener: () => void): () => void {
  registrySubscribers.add(listener);
  return () => {
    registrySubscribers.delete(listener);
  };
}

function emitRegistryChange(): void {
  for (const subscriber of registrySubscribers) {
    subscriber();
  }
}

export function registerCameraAgentSession(handle: CameraAgentSessionHandle): void {
  activeSessions.set(handle.id, handle);
  emitRegistryChange();
}

export function unregisterCameraAgentSession(sessionId: string): void {
  if (activeSessions.delete(sessionId)) {
    lastSessionCaptures.delete(sessionId);
    emitRegistryChange();
  }
}

export function recordCameraSessionCapture(
  sessionId: string,
  result: CameraCaptureResult,
): CameraRecordedCapture {
  const capture = {
    captureId: createCaptureId(),
    result,
  } satisfies CameraRecordedCapture;
  lastSessionCaptures.set(sessionId, capture);
  emitRegistryChange();
  return capture;
}

export function getActiveCameraSessionLastCapture(
  sessionId?: string,
): CameraRecordedCapture | null {
  const resolvedSessionId = sessionId ?? getActiveCameraSession()?.id;
  if (!resolvedSessionId) {
    return null;
  }
  return lastSessionCaptures.get(resolvedSessionId) ?? null;
}

function getSessionDeviceAliases(snapshot: Pick<CameraSessionSnapshot, "deviceId" | "position">): string[] {
  const aliases = new Set<string>();
  if (snapshot.deviceId) {
    aliases.add(snapshot.deviceId);
  }
  aliases.add(snapshot.position);
  return Array.from(aliases);
}

function doesCombinationMatch(
  deviceIds: string[],
  snapshots: Array<Pick<CameraSessionSnapshot, "deviceId" | "position">>,
): boolean {
  if (deviceIds.length !== snapshots.length) {
    return false;
  }

  const remaining = snapshots.map((snapshot) => new Set(getSessionDeviceAliases(snapshot)));
  for (const requiredId of deviceIds) {
    const matchIndex = remaining.findIndex((aliases) => aliases.has(requiredId));
    if (matchIndex === -1) {
      return false;
    }
    remaining.splice(matchIndex, 1);
  }
  return remaining.length === 0;
}

function formatFitsConstraint(
  format: CameraFormat | null | undefined,
  constraint:
    | {
        deviceId: string;
        maxVideoWidth: number;
        maxVideoHeight: number;
      }
    | undefined,
): boolean {
  if (!format || !constraint) {
    return true;
  }
  return (
    format.videoWidth <= constraint.maxVideoWidth &&
    format.videoHeight <= constraint.maxVideoHeight
  );
}

export function getCameraSessionAdmissionError(input: {
  snapshot: Pick<CameraSessionSnapshot, "id" | "deviceId" | "position" | "active">;
  format?: CameraFormat | null;
}): CameraError | null {
  if (input.snapshot.active === false) {
    return null;
  }

  const otherActiveSnapshots = listActiveCameraSessions().filter((session) => {
    return session.id !== input.snapshot.id && session.active;
  });
  const desiredSnapshots = [...otherActiveSnapshots, input.snapshot];
  const capabilities = getSessionCapabilities();

  if (desiredSnapshots.length > capabilities.maxSimultaneousSessions) {
    return makeCameraError(
      "session/limit-exceeded",
      `This platform supports at most ${capabilities.maxSimultaneousSessions} simultaneous camera session${capabilities.maxSimultaneousSessions === 1 ? "" : "s"}.`,
      false,
    );
  }

  if (
    desiredSnapshots.length > 1 &&
    capabilities.simultaneousDevices.length > 0 &&
    !capabilities.simultaneousDevices.some((combination) => {
      return doesCombinationMatch(combination.deviceIds, desiredSnapshots);
    })
  ) {
    return makeCameraError(
      "session/limit-exceeded",
      "The requested camera-device combination is not supported on this platform.",
      false,
    );
  }

  if (desiredSnapshots.length > 1) {
    const matchingCombination = capabilities.simultaneousDevices.find((combination) => {
      return doesCombinationMatch(combination.deviceIds, desiredSnapshots);
    });
    const constraint = matchingCombination?.perDeviceConstraints?.find((entry) => {
      return getSessionDeviceAliases(input.snapshot).includes(entry.deviceId);
    });

    if (!formatFitsConstraint(input.format, constraint)) {
      return makeCameraError(
        "session/limit-exceeded",
        `The requested format exceeds the supported multi-camera limit of ${constraint?.maxVideoWidth ?? 0}x${constraint?.maxVideoHeight ?? 0} for this device combination.`,
        false,
      );
    }
  }

  return null;
}

export function listActiveCameraSessions(): CameraSessionSnapshot[] {
  return Array.from(activeSessions.values()).map((session) => session.getSnapshot());
}

export function getActiveCameraSession(sessionId?: string): CameraAgentSessionHandle | null {
  if (sessionId) {
    return activeSessions.get(sessionId) ?? null;
  }
  const first = activeSessions.values().next();
  return first.done ? null : first.value;
}

export function getActiveCameraSessionDiagnostics(
  sessionId?: string,
): CameraSessionDiagnostics | null {
  const session = getActiveCameraSession(sessionId);
  return session ? session.getDiagnostics() : null;
}

export async function captureActiveCameraSessionFrame(
  sessionId?: string,
  options: CameraAgentFrameCaptureOptions = {},
): Promise<Blob | null> {
  const session = getActiveCameraSession(sessionId);
  if (!session) {
    return null;
  }
  return session.captureFrame(options);
}

export async function takeActiveCameraSessionPhoto(
  sessionId?: string,
  options: CameraPhotoOptions = {},
): Promise<CameraPhotoResult | null> {
  const session = getActiveCameraSession(sessionId);
  if (!session) {
    return null;
  }
  return session.takePhoto(options);
}

export function getActiveCameraSessionProcessorState(
  sessionId?: string,
): CameraProcessorStateSnapshot | null {
  const session = getActiveCameraSession(sessionId);
  if (!session?.getProcessorState) {
    return {
      frameId: null,
      timestamp: null,
      result: null,
    };
  }
  return session.getProcessorState();
}

export async function focusActiveCameraSession(
  point: CameraPoint,
  sessionId?: string,
): Promise<boolean> {
  const session = getActiveCameraSession(sessionId);
  if (!session) {
    return false;
  }
  await session.focus(point);
  return true;
}

export function getCameraSceneFeatures(): CameraSceneFeature[] {
  if (hasNativeCameraHost()) {
    return ["objects", "barcodes", "faces", "text", "brightness", "blur", "dominantColors"];
  }

  const features: CameraSceneFeature[] = ["brightness", "blur", "dominantColors"];
  const barcodeDetector = getBarcodeDetector();
  const faceDetector = getFaceDetector();
  const textDetector = getTextDetector();

  if (barcodeDetector) {
    features.push("barcodes");
  }
  if (faceDetector) {
    features.push("faces");
  }
  if (textDetector) {
    features.push("text");
  }
  if (barcodeDetector || faceDetector || textDetector) {
    features.unshift("objects");
  }

  return features;
}

function deriveSceneFromAnalysis(
  analysis: CameraAnalysisSnapshot | null,
  frameId: number | null,
  requestedFeatures?: CameraSceneFeature[],
): CameraSceneSnapshot {
  const features = requestedFeatures ?? getCameraSceneFeatures();
  const supportedByFallback = new Set<CameraSceneFeature>(["brightness", "blur"]);
  const brightnessRequested = features.includes("brightness");
  const blurRequested = features.includes("blur");
  const unavailableFeatures = features
    .filter((feature) => !supportedByFallback.has(feature))
    .map((feature) => ({
      feature,
      reason: "scene/ml-unavailable",
    }));

  return {
    frameId,
    brightness: brightnessRequested
      ? estimateBrightnessFromHistogram(analysis?.histogram)
      : undefined,
    blur: blurRequested ? estimateBlurFromAnalysis(analysis) : undefined,
    unavailableFeatures: unavailableFeatures.length > 0 ? unavailableFeatures : undefined,
  };
}

export async function getActiveCameraSessionScene(
  sessionId?: string,
  options: {
    features?: CameraSceneFeature[];
  } = {},
): Promise<CameraSceneSnapshot | null> {
  const session = getActiveCameraSession(sessionId);
  if (!session) {
    return null;
  }

  if (session.getScene) {
    return session.getScene(options);
  }

  const snapshot = session.getSnapshot();
  const requestedFeatures = options.features ?? getCameraSceneFeatures();
  const analysis = session.computeAnalysis({
    histogram: requestedFeatures.includes("brightness"),
    clipping: requestedFeatures.includes("blur"),
    fps: 0,
  });
  return deriveSceneFromAnalysis(analysis, snapshot.lastFrameId, requestedFeatures);
}

export async function planActiveCameraSessionCapture(
  sessionId: string | undefined,
  options: PlanCaptureOptions,
): Promise<CameraCapturePlan | null> {
  const session = getActiveCameraSession(sessionId);
  if (!session) {
    return null;
  }

  const snapshot = session.getSnapshot();
  const planContext =
    session.getPlanContext?.() ?? {
      format: null,
      processing: "auto" as const,
      photo: snapshot.photo,
      previewMode: snapshot.previewMode,
    };
  const devices = cachedDevices.length > 0 ? cachedDevices.slice() : await listCameraDevices();
  if (
    snapshot.deviceId &&
    !devices.some((device) => device.id === snapshot.deviceId)
  ) {
    devices.unshift({
      id: snapshot.deviceId,
      position: snapshot.position,
      name: snapshot.deviceName ?? "Camera",
      isVirtual: snapshot.usingVirtualCamera,
      lenses: [],
      minZoom: 1,
      maxZoom: Math.max(1, snapshot.zoom),
      formats: planContext.format ? [planContext.format] : [],
      capabilities: {
        ...cloneCameraCapabilities(),
        multiCamera: getSessionCapabilities().maxSimultaneousSessions > 1,
      },
    });
  }

  return planCameraCapture({
    snapshot,
    devices,
    sessionOptions: planContext,
    options,
  });
}

export function getActiveCameraSessionReadiness(
  sessionId: string | undefined,
  options: {
    intent: CameraIntent;
    readyThreshold?: number;
  },
): CameraReadiness | null {
  const session = getActiveCameraSession(sessionId);
  if (!session) {
    return null;
  }

  return evaluateCameraReadiness({
    snapshot: session.getSnapshot(),
    analysis: session.computeAnalysis({
      histogram: true,
      clipping: true,
      fps: 0,
    }),
    options,
  });
}

function getValueAtPath(root: unknown, key: string): unknown {
  if (!key) {
    return undefined;
  }

  return key.split(".").reduce<unknown>((current, segment) => {
    if (typeof current !== "object" || current === null) {
      return undefined;
    }
    return (current as Record<string, unknown>)[segment];
  }, root);
}

function matchWaitForCondition(
  condition: CameraWaitForCondition,
  scene: CameraSceneSnapshot | null,
  processorState: CameraProcessorStateSnapshot | null,
): Record<string, unknown> | null {
  if ("barcodes" in condition) {
    const barcodes = scene?.barcodes ?? [];
    if (barcodes.length >= Math.max(1, condition.barcodes.minCount)) {
      return { barcodes };
    }
    return null;
  }

  if ("faces" in condition) {
    const faces = scene?.faces ?? [];
    if (faces.length >= Math.max(1, condition.faces.minCount)) {
      return { faces };
    }
    return null;
  }

  if ("text" in condition) {
    const query = condition.text.contains.toLowerCase();
    const text = scene?.text ?? [];
    const matches = text.filter((entry) => entry.value.toLowerCase().includes(query));
    return matches.length > 0 ? { text: matches } : null;
  }

  if ("brightness" in condition) {
    const brightness = scene?.brightness;
    if (typeof brightness !== "number") {
      return null;
    }
    if (typeof condition.brightness.above === "number" && brightness <= condition.brightness.above) {
      return null;
    }
    if (typeof condition.brightness.below === "number" && brightness >= condition.brightness.below) {
      return null;
    }
    return { brightness };
  }

  if ("processorResult" in condition) {
    const value = getValueAtPath(processorState?.result, condition.processorResult.key);
    if (condition.processorResult.notNull && value == null) {
      return null;
    }
    return {
      processorResult: {
        key: condition.processorResult.key,
        value,
      },
    };
  }

  return null;
}

export async function waitForActiveCameraSessionCondition(
  sessionId: string | undefined,
  options: {
    condition: CameraWaitForCondition;
    timeout: number;
  },
): Promise<CameraWaitForResult | null> {
  const session = getActiveCameraSession(sessionId);
  if (!session) {
    return null;
  }

  const startedAt = Date.now();
  let consecutiveMatches = 0;
  let lastFrameId = session.getSnapshot().lastFrameId;

  while (Date.now() - startedAt <= options.timeout) {
    const processorState = getActiveCameraSessionProcessorState(sessionId);
    const requestedFeatures: CameraSceneFeature[] = [];
    if ("barcodes" in options.condition) {
      requestedFeatures.push("barcodes");
    }
    if ("faces" in options.condition) {
      requestedFeatures.push("faces");
    }
    if ("text" in options.condition) {
      requestedFeatures.push("text");
    }
    if ("brightness" in options.condition) {
      requestedFeatures.push("brightness");
    }
    const scene = await getActiveCameraSessionScene(sessionId, {
      features: requestedFeatures.length > 0 ? requestedFeatures : undefined,
    });
    const matchedSnapshot = matchWaitForCondition(options.condition, scene, processorState);
    lastFrameId = scene?.frameId ?? processorState?.frameId ?? lastFrameId ?? null;

    if ("processorResult" in options.condition) {
      if (matchedSnapshot) {
        return {
          matched: true,
          elapsed: Date.now() - startedAt,
          frameId: lastFrameId ?? null,
          snapshot: matchedSnapshot,
        };
      }
    } else if (matchedSnapshot) {
      consecutiveMatches += 1;
      if (consecutiveMatches >= 2) {
        return {
          matched: true,
          elapsed: Date.now() - startedAt,
          frameId: lastFrameId ?? null,
          snapshot: matchedSnapshot,
        };
      }
    } else {
      consecutiveMatches = 0;
    }

    await new Promise<void>((resolve) => {
      setTimeout(resolve, 200);
    });
  }

  return {
    matched: false,
    elapsed: Date.now() - startedAt,
    frameId: lastFrameId ?? null,
    reason: "timeout",
  };
}

export async function exportActiveCameraSessionReplay(
  sessionId: string | undefined,
  options: {
    seconds: number;
  },
): Promise<CameraReplayExport | null> {
  const session = getActiveCameraSession(sessionId);
  if (!session?.exportReplay) {
    return null;
  }
  return session.exportReplay(options);
}

export function createCameraFrameProcessor<Result = unknown>(
  processor: (frame: unknown) => Result,
  options: {
    fps?: number;
    onResult?: (result: Result) => void;
  } = {},
): CameraFrameProcessor<Result> {
  return {
    kind: "exact-camera-frame-processor",
    source: processor.toString(),
    fps: options.fps ?? 30,
    onResult: options.onResult,
  };
}

export function isCameraFrameProcessor(
  value: unknown,
): value is CameraFrameProcessor {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as CameraFrameProcessor).kind === "exact-camera-frame-processor"
  );
}

function getPermissionsQuery():
  | ((descriptor: { name: string }) => Promise<{ state?: string }>)
  | null {
  const nav = getNavigator();
  const permissionsObject = (nav as Navigator & {
    permissions?: {
      query(descriptor: { name: string }): Promise<{ state?: string }>;
    };
  } | null)?.permissions;
  if (typeof permissionsObject?.query === "function") {
    return permissionsObject.query.bind(permissionsObject);
  }
  return null;
}

function cameraApisUnavailable(): CameraPermissionDetails {
  return {
    state: "unavailable",
    canRequestAgain: false,
    platformDetail: {
      reason: "camera_unavailable",
    },
  };
}

function canUseVirtualCameraWithoutOsPermission(): boolean {
  if (!__DEV__) {
    return false;
  }

  // The built-in virtual camera should bypass OS permission only in the
  // simulator/CI-style case where the real browser camera backend is absent.
  // If getUserMedia exists, we keep the normal permission flow even when the
  // current discovered device list happens to be virtual-only.
  return !supportsBrowserCameraApis();
}

function createVirtualCameraGrantedPermission(): CameraPermissionDetails {
  return {
    state: "granted",
    canRequestAgain: null,
    platformDetail: {
      grantedBy: "virtual-camera",
    },
  };
}

async function queryPermissionState(
  name: "camera" | "microphone",
): Promise<CameraPermissionDetails | null> {
  const query = getPermissionsQuery();
  if (!query) {
    return null;
  }

  try {
    const result = await query({ name });
    if (result.state === "granted") {
      return {
        state: "granted",
        canRequestAgain: false,
        platformDetail: {
          permissionState: "granted",
        },
      };
    }
    if (result.state === "denied") {
      return {
        state: "denied",
        canRequestAgain: false,
        platformDetail: {
          permissionState: "denied",
        },
      };
    }
    if (result.state === "prompt") {
      return {
        state: "prompt",
        canRequestAgain: true,
        platformDetail: {
          permissionState: "prompt",
        },
      };
    }
  } catch {
    // Some browsers throw for these permission names. We intentionally fall
    // through to the conservative fallback instead of treating that as a hard
    // denial.
  }

  return null;
}

function normalizeMediaError(error: unknown): CameraPermissionDetails {
  if (error instanceof Error) {
    const name = error.name.toLowerCase();
    if (name.includes("notallowed") || name.includes("security")) {
      return {
        state: "denied",
        canRequestAgain: true,
        settingsUrl: "app-settings:camera",
        platformDetail: {
          errorName: error.name,
        },
      };
    }
    if (name.includes("notfound") || name.includes("overconstrained")) {
      return cameraApisUnavailable();
    }
  }

  return {
    state: "prompt",
    canRequestAgain: true,
    platformDetail: {
      reason: "permission_state_unknown",
    },
  };
}

async function requestMediaPermission(
  constraints: MediaStreamConstraints,
  settingsUrl: string,
): Promise<CameraPermissionDetails> {
  const nav = getNavigator();
  if (!nav?.mediaDevices?.getUserMedia) {
    return cameraApisUnavailable();
  }

  try {
    const stream = await nav.mediaDevices.getUserMedia(constraints);
    for (const track of stream.getTracks()) {
      track.stop();
    }

    // Browser camera labels and device ids often become fully available only
    // after the first successful permission grant. Refresh the cached inventory
    // right away so any already-mounted picker can promote from the development
    // virtual fallback to the real hardware without waiting for a later
    // `devicechange` event that some browsers never emit for permission-only
    // transitions.
    if (constraints.video) {
      try {
        await refreshCameraDevices();
      } catch {
        // Permission was granted successfully even if the follow-up enumerate
        // pass fails, so keep the permission result authoritative here.
      }
    }

    return {
      state: "granted",
      canRequestAgain: false,
      settingsUrl,
      platformDetail: {
        grantedBy: "getUserMedia",
      },
    };
  } catch (error) {
    return normalizeMediaError(error);
  }
}

export async function getCameraPermissionDetails(): Promise<CameraPermissionDetails> {
  if (hasNativeCameraHost()) {
    try {
      return normalizeNativePermissionResponse(
        invokeNativeCameraHostCall<NativeCameraHostPermissionResponse>(
          "camera.permission.get",
          { name: "camera" },
        ),
        "app-settings:camera",
      );
    } catch {
      return cameraApisUnavailable();
    }
  }

  if (canUseVirtualCameraWithoutOsPermission()) {
    return createVirtualCameraGrantedPermission();
  }

  if (!supportsBrowserCameraApis()) {
    return cameraApisUnavailable();
  }

  const queried = await queryPermissionState("camera");
  if (queried) {
    return queried;
  }

  return {
    state: "prompt",
    canRequestAgain: true,
    settingsUrl: "app-settings:camera",
    platformDetail: {
      permissionState: "unknown",
    },
  };
}

export async function requestCameraPermission(): Promise<CameraPermissionDetails> {
  if (hasNativeCameraHost()) {
    try {
      return normalizeNativePermissionResponse(
        invokeNativeCameraHostCall<NativeCameraHostPermissionResponse>(
          "camera.permission.request",
          { name: "camera" },
        ),
        "app-settings:camera",
      );
    } catch {
      return cameraApisUnavailable();
    }
  }

  if (canUseVirtualCameraWithoutOsPermission()) {
    return createVirtualCameraGrantedPermission();
  }

  return requestMediaPermission({ video: true }, "app-settings:camera");
}

export async function getMicrophonePermissionDetails(): Promise<CameraPermissionDetails> {
  if (hasNativeCameraHost()) {
    try {
      return normalizeNativePermissionResponse(
        invokeNativeCameraHostCall<NativeCameraHostPermissionResponse>(
          "camera.permission.get",
          { name: "microphone" },
        ),
        "app-settings:microphone",
      );
    } catch {
      return cameraApisUnavailable();
    }
  }

  if (!supportsBrowserCameraApis()) {
    return cameraApisUnavailable();
  }

  const queried = await queryPermissionState("microphone");
  if (queried) {
    return queried;
  }

  return {
    state: "prompt",
    canRequestAgain: true,
    settingsUrl: "app-settings:microphone",
    platformDetail: {
      permissionState: "unknown",
    },
  };
}

export async function requestMicrophonePermission(): Promise<CameraPermissionDetails> {
  if (hasNativeCameraHost()) {
    try {
      return normalizeNativePermissionResponse(
        invokeNativeCameraHostCall<NativeCameraHostPermissionResponse>(
          "camera.permission.request",
          { name: "microphone" },
        ),
        "app-settings:microphone",
      );
    } catch {
      return cameraApisUnavailable();
    }
  }

  return requestMediaPermission({ audio: true }, "app-settings:microphone");
}

export function configureVirtualCamera(
  deviceOrConfig: string | VirtualCameraConfig,
  maybeConfig?: VirtualCameraConfig,
): void {
  if (typeof deviceOrConfig === "string") {
    virtualCameraConfigs.set(deviceOrConfig, maybeConfig ?? { ...DEFAULT_VIRTUAL_CONFIG });
  } else {
    defaultVirtualCameraConfig = deviceOrConfig;
  }
  void refreshCameraDevices();
}

function normalizeSessionCapabilities(
  response: NativeCameraHostSessionCapabilitiesResponse | null | undefined,
): SessionCapabilities | null {
  if (!response) {
    return null;
  }

  const capture =
    typeof response.capture === "object" && response.capture !== null
      ? response.capture
      : null;

  return {
    maxSimultaneousSessions:
      typeof response.maxSimultaneousSessions === "number"
        ? response.maxSimultaneousSessions
        : 1,
    simultaneousDevices: Array.isArray(response.simultaneousDevices)
      ? response.simultaneousDevices.map((entry) => ({
          deviceIds: Array.isArray(entry.deviceIds)
            ? entry.deviceIds.filter((value): value is string => typeof value === "string")
            : [],
          perDeviceConstraints:
            entry.perDeviceConstraints == null
              ? null
              : entry.perDeviceConstraints
                  .filter(
                    (constraint): constraint is {
                      deviceId: string;
                      maxVideoWidth: number;
                      maxVideoHeight: number;
                    } =>
                      typeof constraint?.deviceId === "string" &&
                      typeof constraint?.maxVideoWidth === "number" &&
                      typeof constraint?.maxVideoHeight === "number",
                  )
                  .map((constraint) => ({
                    deviceId: constraint.deviceId,
                    maxVideoWidth: constraint.maxVideoWidth,
                    maxVideoHeight: constraint.maxVideoHeight,
                  })),
        }))
      : [],
    estimatedMemoryBudgetMB:
      typeof response.estimatedMemoryBudgetMB === "number"
        ? response.estimatedMemoryBudgetMB
        : 256,
    capture: {
      photo:
        typeof capture?.photo === "boolean"
          ? capture.photo
          : true,
      snapshot:
        typeof capture?.snapshot === "boolean"
          ? capture.snapshot
          : true,
      video:
        typeof capture?.video === "boolean"
          ? capture.video
          : true,
    },
  };
}

function buildDerivedSessionCapabilities(devices: CameraDevice[]): SessionCapabilities {
  if (devices.length === 0) {
    return {
      maxSimultaneousSessions: 1,
      simultaneousDevices: [],
      estimatedMemoryBudgetMB: 256,
      capture: {
        photo: true,
        snapshot: true,
        video: true,
      },
    };
  }

  const combinations: SessionCapabilities["simultaneousDevices"] = [];
  for (let leftIndex = 0; leftIndex < devices.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < devices.length; rightIndex += 1) {
      const left = devices[leftIndex]!;
      const right = devices[rightIndex]!;

      // The default runtime policy only exposes pairs that represent distinct
      // camera viewpoints. This keeps the admission checks deterministic on the
      // web and mirrors the RFC's "front/back/external" examples without
      // pretending every browser can open two identical physical cameras.
      if (left.position === right.position) {
        continue;
      }

      combinations.push({
        deviceIds: [left.id, right.id],
        perDeviceConstraints: null,
      });
    }
  }

  return {
    maxSimultaneousSessions:
      combinations.length > 0 ? Math.min(2, devices.length) : 1,
    simultaneousDevices: combinations,
    estimatedMemoryBudgetMB: 256,
    capture: {
      photo: true,
      snapshot: true,
      video: true,
    },
  };
}

export function getSessionCapabilities(): SessionCapabilities {
  if (hasNativeCameraHost()) {
    try {
      const response = normalizeSessionCapabilities(
        invokeNativeCameraHostCall<NativeCameraHostSessionCapabilitiesResponse>(
          "camera.sessionCapabilities.get",
        ),
      );
      if (response) {
        return response;
      }
    } catch {
      // Fall through to the derived runtime defaults below.
    }
  }

  return buildDerivedSessionCapabilities(cachedDevices);
}

export function getCameraCapabilities(): {
  maxSimultaneousSessions: number;
  simultaneousDevices: Array<[CameraPosition, CameraPosition]>;
} {
  const sessionCapabilities = getSessionCapabilities();
  const devices = cachedDevices;
  const resolvePosition = (deviceId: string): CameraPosition => {
    return devices.find((device) => device.id === deviceId)?.position
      ?? (deviceId as CameraPosition)
      ?? "back";
  };
  return {
    maxSimultaneousSessions: sessionCapabilities.maxSimultaneousSessions,
    simultaneousDevices: sessionCapabilities.simultaneousDevices.map((entry) => [
      resolvePosition(entry.deviceIds[0] ?? "back"),
      resolvePosition(entry.deviceIds[1] ?? "front"),
    ]),
  };
}

function pickRecordingMimeType(codec: CameraVideoCodec): string | null {
  if (typeof MediaRecorder === "undefined") {
    return null;
  }

  const candidates =
    codec === "h265"
      ? [
          "video/mp4;codecs=hvc1",
          "video/webm;codecs=vp9,opus",
          "video/webm;codecs=vp8,opus",
          "video/webm",
        ]
      : [
          "video/mp4;codecs=avc1.42E01E,mp4a.40.2",
          "video/webm;codecs=vp8,opus",
          "video/webm",
        ];

  for (const candidate of candidates) {
    if (MediaRecorder.isTypeSupported(candidate)) {
      return candidate;
    }
  }

  return null;
}

function clamp01(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }
  return Math.max(0, Math.min(1, value));
}

function computeOrientation(width: number, height: number):
  | "portrait"
  | "landscape-left"
  | "landscape-right"
  | "portrait-upside-down" {
  if (width >= height) {
    return "landscape-left";
  }
  return "portrait";
}

function computeDrawRect(
  sourceWidth: number,
  sourceHeight: number,
  targetWidth: number,
  targetHeight: number,
  resizeMode: CameraResizeMode,
): CameraRect {
  if (
    resizeMode === "stretch" ||
    sourceWidth <= 0 ||
    sourceHeight <= 0 ||
    targetWidth <= 0 ||
    targetHeight <= 0
  ) {
    return {
      x: 0,
      y: 0,
      width: targetWidth,
      height: targetHeight,
    };
  }

  const sourceAspect = sourceWidth / sourceHeight;
  const targetAspect = targetWidth / targetHeight;
  const cover = resizeMode === "cover";
  const sourceIsWider = sourceAspect > targetAspect;

  if (cover ? sourceIsWider : !sourceIsWider) {
    const height = targetHeight;
    const width = height * sourceAspect;
    return {
      x: (targetWidth - width) / 2,
      y: 0,
      width,
      height,
    };
  }

  const width = targetWidth;
  const height = width / sourceAspect;
  return {
    x: 0,
    y: (targetHeight - height) / 2,
    width,
    height,
  };
}

function sensorRectToViewRect(
  rect: CameraRect,
  sourceWidth: number,
  sourceHeight: number,
  targetWidth: number,
  targetHeight: number,
  resizeMode: CameraResizeMode,
  mirror: boolean,
): CameraRect {
  const drawRect = computeDrawRect(
    sourceWidth,
    sourceHeight,
    targetWidth,
    targetHeight,
    resizeMode,
  );
  const mapped: CameraRect = {
    x: drawRect.x + (rect.x / sourceWidth) * drawRect.width,
    y: drawRect.y + (rect.y / sourceHeight) * drawRect.height,
    width: (rect.width / sourceWidth) * drawRect.width,
    height: (rect.height / sourceHeight) * drawRect.height,
  };

  if (mirror) {
    mapped.x = targetWidth - (mapped.x + mapped.width);
  }

  return {
    x: mapped.x / targetWidth,
    y: mapped.y / targetHeight,
    width: mapped.width / targetWidth,
    height: mapped.height / targetHeight,
  };
}

function drawSourceIntoTarget(
  context: CanvasRenderingContext2D,
  source: CanvasImageSource,
  sourceWidth: number,
  sourceHeight: number,
  targetWidth: number,
  targetHeight: number,
  resizeMode: CameraResizeMode,
  mirror: boolean,
): void {
  context.clearRect(0, 0, targetWidth, targetHeight);
  context.save();
  const drawRect = computeDrawRect(
    sourceWidth,
    sourceHeight,
    targetWidth,
    targetHeight,
    resizeMode,
  );

  if (mirror) {
    context.translate(targetWidth, 0);
    context.scale(-1, 1);
    context.drawImage(
      source,
      drawRect.x,
      drawRect.y,
      drawRect.width,
      drawRect.height,
    );
  } else {
    context.drawImage(
      source,
      drawRect.x,
      drawRect.y,
      drawRect.width,
      drawRect.height,
    );
  }
  context.restore();
}

function rgbaToBgra(data: Uint8ClampedArray): ArrayBuffer {
  const output = new Uint8Array(data.length);
  for (let index = 0; index < data.length; index += 4) {
    output[index] = data[index + 2];
    output[index + 1] = data[index + 1];
    output[index + 2] = data[index];
    output[index + 3] = data[index + 3];
  }
  return output.buffer;
}

function bgraToRgba(data: Uint8Array): Uint8ClampedArray {
  const output = new Uint8ClampedArray(new ArrayBuffer(data.length));
  for (let index = 0; index < data.length; index += 4) {
    output[index] = data[index + 2];
    output[index + 1] = data[index + 1];
    output[index + 2] = data[index];
    output[index + 3] = data[index + 3];
  }
  return output;
}

async function canvasToBlob(
  canvas: HTMLCanvasElement,
  type: "image/png" | "image/jpeg",
  quality: number,
): Promise<Blob> {
  return new Promise<Blob>((resolve, reject) => {
    canvas.toBlob(
      (blob) => {
        if (!blob) {
          reject(new Error("Canvas serialization failed"));
          return;
        }
        resolve(blob);
      },
      type,
      quality,
    );
  });
}

async function getBestEffortLocation(): Promise<Record<string, unknown> | undefined> {
  if (typeof navigator === "undefined" || !navigator.geolocation) {
    return undefined;
  }

  return new Promise((resolve) => {
    navigator.geolocation.getCurrentPosition(
      (position) => {
        resolve({
          latitude: position.coords.latitude,
          longitude: position.coords.longitude,
          accuracy: position.coords.accuracy,
          timestamp: position.timestamp,
        });
      },
      () => resolve(undefined),
      {
        enableHighAccuracy: true,
        timeout: 2_000,
        maximumAge: 5_000,
      },
    );
  });
}

function makeCameraError(
  code: CameraError["code"],
  message: string,
  recoverable: boolean,
  cause?: Error,
): CameraError {
  return {
    code,
    message,
    recoverable,
    cause,
  };
}

function toPermissionDeniedError(error: unknown, microphone = false): CameraError {
  const fallback = makeCameraError(
    microphone ? "permission/microphone-denied" : "permission/camera-denied",
    microphone ? "Microphone permission denied." : "Camera permission denied.",
    true,
    error instanceof Error ? error : undefined,
  );

  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    "message" in error &&
    "recoverable" in error
  ) {
    return error as CameraError;
  }

  if (!(error instanceof Error)) {
    return fallback;
  }

  const normalized = error.name.toLowerCase();
  if (normalized.includes("notallowed") || normalized.includes("security")) {
    return fallback;
  }

  if (normalized.includes("notreadable")) {
    return makeCameraError(
      "device/in-use",
      "The camera is already in use by another application or tab.",
      true,
      error,
    );
  }

  if (normalized.includes("notfound") || normalized.includes("overconstrained")) {
    return makeCameraError(
      "device/unavailable",
      "No matching camera device is currently available.",
      false,
      error,
    );
  }

  return makeCameraError(
    "device/configuration-failed",
    error.message || "Failed to configure the requested camera session.",
    true,
    error,
  );
}

function isTransientVideoPlayInterruption(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  const normalizedName = error.name.toLowerCase();
  const normalizedMessage = error.message.toLowerCase();
  return (
    normalizedName.includes("abort") ||
    normalizedMessage.includes("play() request was interrupted") ||
    normalizedMessage.includes("interrupted by a new load request") ||
    normalizedMessage.includes("interrupted by a call to pause")
  );
}

function createBlankCanvas(): HTMLCanvasElement {
  if (typeof document === "undefined") {
    throw new Error("Camera runtime requires a DOM-capable environment.");
  }
  return document.createElement("canvas");
}

function getBarcodeDetector(): BarcodeDetectorCtor | null {
  const win = getWindowObject();
  return win?.BarcodeDetector ?? null;
}

function getTextDetector(): TextDetectorCtor | null {
  const win = getWindowObject();
  return win?.TextDetector ?? null;
}

function getFaceDetector(): FaceDetectorCtor | null {
  const win = getWindowObject();
  return win?.FaceDetector ?? null;
}

function getImageCaptureCtor(): ImageCaptureCtorLike | null {
  const value = globalThis as typeof globalThis & {
    ImageCapture?: ImageCaptureCtorLike;
  };
  return value.ImageCapture ?? null;
}

async function maybeCaptureTrackPhoto(track: MediaStreamTrack): Promise<Blob | null> {
  const ctor = getImageCaptureCtor();
  if (!ctor) {
    return null;
  }

  try {
    const capture = new ctor(track);
    if (typeof capture.takePhoto !== "function") {
      return null;
    }
    return await capture.takePhoto();
  } catch {
    return null;
  }
}

class VirtualCameraController {
  readonly canvas: HTMLCanvasElement;
  readonly stream: MediaStream;

  private readonly context: CanvasRenderingContext2D;
  private readonly config: VirtualCameraConfig;
  private readonly deviceId: string;
  private rafHandle: number | null = null;
  private stopped = false;
  private imageElement: HTMLImageElement | null = null;
  private videoElement: HTMLVideoElement | null = null;
  private frameCounter = 0;

  constructor(deviceId: string, config: VirtualCameraConfig) {
    this.deviceId = deviceId;
    this.config = config;
    this.canvas = createBlankCanvas();
    const resolution = config.resolution ?? DEFAULT_VIRTUAL_CONFIG.resolution!;
    this.canvas.width = resolution.width;
    this.canvas.height = resolution.height;
    const context = this.canvas.getContext("2d");
    if (!context) {
      throw new Error("2D canvas context is required for the virtual camera.");
    }
    this.context = context;
    this.stream = this.canvas.captureStream(config.fps ?? 30);
  }

  async start(): Promise<void> {
    if (this.stopped) {
      return;
    }

    switch (this.config.source.type) {
      case "image":
        await this.prepareImage(this.config.source.uri);
        break;
      case "video":
        await this.prepareVideo(this.config.source.uri);
        break;
      default:
        break;
    }

    const render = () => {
      if (this.stopped) {
        return;
      }

      this.renderFrame();
      this.rafHandle = requestAnimationFrame(render);
    };

    render();
  }

  stop(): void {
    this.stopped = true;
    if (this.rafHandle != null) {
      cancelAnimationFrame(this.rafHandle);
      this.rafHandle = null;
    }
    if (this.videoElement) {
      this.videoElement.pause();
      this.videoElement.src = "";
    }
    for (const track of this.stream.getTracks()) {
      track.stop();
    }
  }

  getSourceType(): string {
    return this.config.source.type;
  }

  private async prepareImage(uri: string): Promise<void> {
    const image = new Image();
    image.crossOrigin = "anonymous";
    image.src = uri;
    await image.decode();
    this.imageElement = image;
  }

  private async prepareVideo(uri: string): Promise<void> {
    const video = document.createElement("video");
    video.src = uri;
    video.loop = this.config.loop ?? true;
    video.muted = true;
    video.playsInline = true;
    await video.play();
    this.videoElement = video;
  }

  private renderFrame(): void {
    const width = this.canvas.width;
    const height = this.canvas.height;
    this.context.clearRect(0, 0, width, height);

    switch (this.config.source.type) {
      case "generated":
        this.renderGenerated(width, height);
        break;
      case "image":
        if (this.imageElement) {
          drawSourceIntoTarget(
            this.context,
            this.imageElement,
            this.imageElement.width,
            this.imageElement.height,
            width,
            height,
            "cover",
            false,
          );
        }
        break;
      case "video":
        if (this.videoElement && this.videoElement.videoWidth > 0 && this.videoElement.videoHeight > 0) {
          drawSourceIntoTarget(
            this.context,
            this.videoElement,
            this.videoElement.videoWidth,
            this.videoElement.videoHeight,
            width,
            height,
            "cover",
            false,
          );
        }
        break;
      case "screen":
        this.renderFallbackLabel("screen source unsupported");
        break;
      case "remote":
        this.renderFallbackLabel(`remote source: ${this.config.source.url}`);
        break;
    }

    this.frameCounter += 1;
  }

  private renderFallbackLabel(text: string): void {
    this.context.fillStyle = "#10131c";
    this.context.fillRect(0, 0, this.canvas.width, this.canvas.height);
    this.context.fillStyle = "#f4f7ff";
    this.context.font = "700 42px ui-sans-serif";
    this.context.fillText("Virtual Camera", 40, 90);
    this.context.font = "500 28px ui-sans-serif";
    this.context.fillText(text, 40, 150);
  }

  private renderGenerated(width: number, height: number): void {
    const pattern =
      this.config.source.type === "generated"
        ? this.config.source.pattern ?? "counter"
        : "counter";
    if (pattern === "color-bars") {
      const colors = ["#f94144", "#f3722c", "#f9c74f", "#90be6d", "#43aa8b", "#577590"];
      const barWidth = width / colors.length;
      colors.forEach((color, index) => {
        this.context.fillStyle = color;
        this.context.fillRect(index * barWidth, 0, barWidth, height);
      });
      return;
    }

    if (pattern === "gradient") {
      const gradient = this.context.createLinearGradient(0, 0, width, height);
      gradient.addColorStop(0, "#03254c");
      gradient.addColorStop(0.5, "#1f7a8c");
      gradient.addColorStop(1, "#bfdbf7");
      this.context.fillStyle = gradient;
      this.context.fillRect(0, 0, width, height);
      return;
    }

    const hue = (Date.now() / 20) % 360;
    this.context.fillStyle = `hsl(${hue}, 55%, 14%)`;
    this.context.fillRect(0, 0, width, height);

    this.context.fillStyle = `hsl(${(hue + 90) % 360}, 75%, 58%)`;
    this.context.fillRect(40, 40, width - 80, height - 80);

    this.context.fillStyle = "#0b1020";
    this.context.font = "700 48px ui-monospace";
    this.context.fillText(this.deviceId, 64, 120);
    this.context.font = "600 120px ui-monospace";
    this.context.fillText(String(this.frameCounter), 64, height / 2);
    this.context.font = "500 28px ui-sans-serif";
    this.context.fillText(new Date().toISOString(), 64, height - 80);
  }
}

class WorkerFrameProcessorRuntime {
  private worker: Worker | null = null;
  private pending = new Map<number, WorkerPendingRequest>();
  private requestId = 1;
  private currentSource: string | null = null;

  async updateProcessor(processor: CameraFrameProcessor | null): Promise<void> {
    if (!processor) {
      this.dispose();
      return;
    }

    if (this.worker && this.currentSource === processor.source) {
      return;
    }

    this.dispose();
    this.currentSource = processor.source;

    const worker = new Worker(
      new URL("./processor.worker.ts", import.meta.url),
      { type: "module" },
    );
    worker.onmessage = (event: MessageEvent) => {
      const payload = event.data as
        | { type: "result"; id: number; result?: unknown; outputBuffer?: ArrayBuffer }
        | { type: "error"; id: number; message: string };
      const pending = this.pending.get(payload.id);
      if (!pending) {
        return;
      }
      this.pending.delete(payload.id);

      if (payload.type === "error") {
        pending.reject(new Error(payload.message));
        return;
      }

      pending.resolve({
        outputBuffer: payload.outputBuffer,
        result: payload.result,
      });
    };

    worker.postMessage({
      type: "init",
      source: processor.source,
    });
    this.worker = worker;
  }

  async processFrame(message: {
    inputBuffer: ArrayBuffer;
    width: number;
    height: number;
    timestamp: number;
    previewMode: CameraPreviewMode;
    resizeMode: CameraResizeMode;
    mirror: boolean;
    targetWidth: number;
    targetHeight: number;
    isCaptureFrame: boolean;
  }): Promise<WorkerProcessResponse> {
    if (!this.worker) {
      throw new Error("Frame processor worker has not been initialized.");
    }

    const id = this.requestId++;
    const resultPromise = new Promise<WorkerProcessResponse>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });

    this.worker.postMessage(
      {
        type: "frame",
        id,
        ...message,
      },
      [message.inputBuffer],
    );

    return resultPromise;
  }

  dispose(): void {
    for (const pending of this.pending.values()) {
      pending.reject(new Error("Frame processor worker terminated."));
    }
    this.pending.clear();
    this.worker?.terminate();
    this.worker = null;
    this.currentSource = null;
  }

  get active(): boolean {
    return this.worker != null;
  }
}

function usesRetroactiveBuffer(options: Pick<CameraSessionOptions, "retroactiveBuffer">): boolean {
  return (options.retroactiveBuffer ?? 0) > 0;
}

function areFrameProcessorPipelinesEquivalent(
  left: CameraFrameProcessor | null | undefined,
  right: CameraFrameProcessor | null | undefined,
): boolean {
  if (!left && !right) {
    return true;
  }
  if (!left || !right) {
    return false;
  }
  return left.source === right.source;
}

interface CameraStateSubscriber {
  (): void;
}

export class WebCameraSessionController implements CameraAgentSessionHandle {
  readonly id: string;

  private options: CameraSessionOptions;
  private bindings: CameraSessionBindings | null = null;
  private readonly rawCanvas = createBlankCanvas();
  private readonly rawContext: CanvasRenderingContext2D;
  private readonly outputCanvas = createBlankCanvas();
  private readonly outputContext: CanvasRenderingContext2D;
  private readonly scratchCanvas = createBlankCanvas();
  private readonly scratchContext: CanvasRenderingContext2D;
  private readonly subscribers = new Set<CameraStateSubscriber>();
  private readonly frameProcessorRuntime = new WorkerFrameProcessorRuntime();
  private lifecycleTask: Promise<void> = Promise.resolve();

  private mediaStream: MediaStream | null = null;
  private audioStream: MediaStream | null = null;
  private rollingAudioStream: MediaStream | null = null;
  private rollingRecorderSource: MediaStream | null = null;
  private virtualController: VirtualCameraController | null = null;
  private resizeObserver: ResizeObserver | null = null;
  private frameLoopToken: FrameLoopToken | null = null;
  private initialized = false;
  private started = false;
  private lastError: CameraError | null = null;
  private pathBActive = false;
  private processingBusy = false;
  private hasProcessedPreviewFrame = false;
  private recordingState: "inactive" | "recording" | "paused" = "inactive";
  private recordingStartedAt = 0;
  private recordingBytesWritten = 0;
  private recordingChunks = 0;
  private recordingTimer: ReturnType<typeof setInterval> | null = null;
  private currentRecorder: MediaRecorderWithRequestData | null = null;
  private currentRecordingOptions: CameraRecordingOptions | null = null;
  private currentRecordingChunks: Blob[] = [];
  private discardNextRecording = false;
  private rollingRecorder: MediaRecorderWithRequestData | null = null;
  private rollingChunks: RollingChunk[] = [];
  private rollingRecorderHasAudio = false;
  private rollingRecorderUsesProcessedPreview = false;
  private lastRollingChunkEndedAt = 0;
  private reportedRetroactiveAudioUnavailable = false;
  private lastCodeScanAt = 0;
  private frameCounter = 0;
  private lastProcessorState: CameraProcessorStateSnapshot = {
    frameId: null,
    timestamp: null,
    result: null,
  };
  private diagnostics: CameraSessionDiagnostics = {
    framesReceived: 0,
    framesProcessed: 0,
    framesDropped: 0,
    processorFps: 0,
    pathBActivations: 0,
    lastFrameTimestamp: null,
    lastProcessorTimestamp: null,
    recordingBytesWritten: 0,
    recordingChunks: 0,
    barcodeDetectorAvailable: getBarcodeDetector() != null,
    workerActive: false,
    virtualSourceType: null,
  };

  constructor(options: CameraSessionOptions = {}) {
    this.id = options.id ?? createSessionId();
    this.options = {
      position: "back",
      active: true,
      intent: undefined,
      photo: true,
      video: false,
      previewMode: "native",
      zoom: 1,
      mirror: false,
      resizeMode: "cover",
      flash: "auto",
      torch: false,
      autoFocus: true,
      autoExposure: true,
      autoWhiteBalance: true,
      processing: "auto",
      retroactiveBuffer: 0,
      ...options,
    };

    const rawContext = this.rawCanvas.getContext("2d", {
      willReadFrequently: true,
    });
    const outputContext = this.outputCanvas.getContext("2d");
    const scratchContext = this.scratchCanvas.getContext("2d");
    if (!rawContext || !outputContext || !scratchContext) {
      throw new Error("Camera runtime requires 2D canvas support.");
    }
    this.rawContext = rawContext;
    this.outputContext = outputContext;
    this.scratchContext = scratchContext;

    registerCameraAgentSession(this);
  }

  getSnapshot(): CameraSessionSnapshot {
    return {
      id: this.id,
      deviceId: this.options.device?.id ?? null,
      deviceName: this.options.device?.name ?? null,
      position: this.options.device?.position ?? this.options.position ?? "back",
      intent: this.options.intent ?? null,
      active: this.options.active !== false,
      initialized: this.initialized,
      previewMode: this.options.previewMode ?? "native",
      photo: this.photoEnabled,
      video: this.videoEnabled,
      pathBActive: this.pathBActive,
      frameProcessorActive: isCameraFrameProcessor(this.options.frameProcessor),
      codeScannerActive: !!this.options.codeScanner,
      usingVirtualCamera: this.options.device?.isVirtual === true || this.virtualController != null,
      recordingState: this.recordingState,
      mirror: this.options.mirror === true,
      resizeMode: this.options.resizeMode ?? "cover",
      zoom: this.options.zoom ?? 1,
      thermalState: "nominal",
      lastFrameId: this.frameCounter > 0 ? this.frameCounter : null,
      renderSize: this.getRenderSize(),
      streamSize: this.getStreamSize(),
      lastError: this.lastError,
    };
  }

  getDiagnostics(): CameraSessionDiagnostics {
    return {
      ...this.diagnostics,
      workerActive: this.frameProcessorRuntime.active,
    };
  }

  getPlanContext(): Pick<
    CameraSessionOptions,
    "format" | "processing" | "photo" | "previewMode"
  > {
    return {
      format: this.options.format ?? null,
      processing: this.options.processing ?? "auto",
      photo: this.photoEnabled,
      previewMode: this.options.previewMode ?? "native",
    };
  }

  getProcessorState(): CameraProcessorStateSnapshot {
    return { ...this.lastProcessorState };
  }

  subscribe(listener: CameraStateSubscriber): () => void {
    this.subscribers.add(listener);
    return () => {
      this.subscribers.delete(listener);
    };
  }

  attach(bindings: CameraSessionBindings): void {
    this.bindings = bindings;
    this.installResizeObserver();
    void this.enqueueLifecycle(async () => {
      await this.syncLifecycle();
    });
  }

  detach(): void {
    this.bindings = null;
    this.stopResizeObserver();
    void this.enqueueLifecycle(async () => {
      await this.stopSession();
    });
  }

  updateOptions(nextOptions: CameraSessionOptions): void {
    const previous = this.options;
    this.options = {
      ...this.options,
      ...nextOptions,
    };

    const requiresRestart =
      previous.device?.id !== this.options.device?.id ||
      previous.position !== this.options.position ||
      previous.format !== this.options.format;
    const requiresLifecycleSync =
      previous.active !== this.options.active ||
      previous.previewMode !== this.options.previewMode ||
      previous.resizeMode !== this.options.resizeMode ||
      previous.mirror !== this.options.mirror ||
      usesRetroactiveBuffer(previous) !== usesRetroactiveBuffer(this.options) ||
      (previous.retroactiveAudio === true) !== (this.options.retroactiveAudio === true) ||
      (!!previous.codeScanner) !== (!!this.options.codeScanner) ||
      !areFrameProcessorPipelinesEquivalent(previous.frameProcessor, this.options.frameProcessor);
    const requiresTrackSettingsRefresh =
      previous.zoom !== this.options.zoom ||
      previous.torch !== this.options.torch;

    // Camera components re-render frequently while a session is active because
    // controller snapshots drive preview overlays and diagnostics. Most of
    // those renders only swap callback identities, so avoid enqueuing a full
    // lifecycle sync unless something that materially changes the session did.
    if (!requiresRestart && !requiresLifecycleSync && !requiresTrackSettingsRefresh) {
      return;
    }

    void this.enqueueLifecycle(async () => {
      if (requiresRestart) {
        await this.restartSession();
        return;
      }

      if (requiresLifecycleSync) {
        await this.syncLifecycle();
      }
      if (requiresTrackSettingsRefresh) {
        this.applyTrackSettings();
      }
      this.notify();
    });
  }

  async destroy(): Promise<void> {
    this.bindings = null;
    this.stopResizeObserver();
    await this.enqueueLifecycle(async () => {
      await this.stopSession();
    });
    this.frameProcessorRuntime.dispose();
    unregisterCameraAgentSession(this.id);
  }

  async captureFrame(
    options: CameraAgentFrameCaptureOptions = {},
  ): Promise<Blob> {
    if (!this.bindings) {
      throw new Error("Camera session is not attached to any DOM bindings.");
    }

    const { format = "png", quality = 0.92, space = "view" } = options;
    if (space === "sensor") {
      await this.ensureSensorBufferFresh();
    }
    const sourceCanvas =
      space === "sensor"
        ? this.getCurrentSensorCanvas()
        : await this.renderCurrentViewToCanvas();
    return canvasToBlob(
      sourceCanvas,
      format === "jpeg" ? "image/jpeg" : "image/png",
      quality,
    );
  }

  async takePhoto(options: CameraPhotoOptions = {}): Promise<CameraPhotoResult> {
    if (!this.photoEnabled) {
      throw new Error("capture/pipeline-disabled");
    }

    await this.ensureSensorBufferFresh();
    const track = this.mediaStream?.getVideoTracks()[0];
    this.options.onShutter?.();

    let blob =
      track != null && this.options.previewMode !== "processed"
        ? await maybeCaptureTrackPhoto(track)
        : null;

    if (!blob) {
      const sourceCanvas = await this.capturePhotoCanvas();
      blob = await canvasToBlob(
        sourceCanvas,
        options.format === "png" ? "image/png" : "image/jpeg",
        clamp01(options.quality ?? 0.92),
      );
    }

    const uri = createUrlForBlob(blob);
    const canvas = await this.capturePhotoCanvas();
    const metadata: Record<string, unknown> = {
      previewMode: this.options.previewMode,
      deviceId: this.options.device?.id ?? null,
      virtual: this.virtualController != null || this.options.device?.isVirtual === true,
      processing: options.processing ?? this.options.processing ?? "auto",
      flash: options.flash ?? this.options.flash ?? "auto",
    };

    if (options.location) {
      const location = await getBestEffortLocation();
      if (location) {
        metadata.location = location;
      }
    }

    const analysis = this.computeAnalysis({
      histogram: true,
      clipping: true,
      fps: 0,
    });

    const result = {
      uri,
      width: canvas.width,
      height: canvas.height,
      rawUri: null,
      exif: options.exif ? { mimeType: blob.type } : undefined,
      metadata,
      provenance: buildCaptureProvenance({
        snapshot: this.getSnapshot(),
        sessionOptions: {
          flash: this.options.flash,
          zoom: this.options.zoom,
          processing: this.options.processing,
          format: this.options.format,
          intent: this.options.intent,
        },
        capturePath:
          this.options.previewMode === "processed"
            ? "processed-photo-pass"
            : "photo-pipeline",
        analysis,
        request: options,
        locationEmbedded: "location" in metadata,
        rawUri: null,
        }),
    } satisfies CameraPhotoResult;

    recordCameraSessionCapture(this.id, result);
    return result;
  }

  async takeBurst(options: CameraBurstOptions): Promise<CameraBurstResult> {
    const photos: CameraBurstResult["photos"] = [];
    const count = Math.max(1, Math.floor(options.count));
    const interval = Math.max(0, Math.floor(options.interval ?? 0));

    for (let index = 0; index < count; index += 1) {
      const photo = await this.takePhoto({
        format: options.format,
        quality: options.quality,
      });
      photos.push({
        uri: photo.uri,
        width: photo.width,
        height: photo.height,
        timestamp: Date.now(),
      });

      if (index < count - 1 && interval > 0) {
        await new Promise<void>((resolve) => {
          setTimeout(resolve, interval);
        });
      }
    }

    return {
      photos,
      provenance: buildCaptureProvenance({
        snapshot: this.getSnapshot(),
        sessionOptions: {
          flash: this.options.flash,
          zoom: this.options.zoom,
          processing: this.options.processing,
          format: this.options.format,
          intent: this.options.intent,
        },
        capturePath:
          this.options.previewMode === "processed"
            ? "processed-photo-pass"
            : "photo-pipeline",
        request: {
          processing: this.options.processing,
        },
      }),
    };
  }

  async takeSnapshot(
    options: CameraSnapshotOptions = {},
  ): Promise<CameraSnapshotResult> {
    await this.ensureSensorBufferFresh();
    const sourceCanvas =
      this.options.previewMode === "processed"
        ? this.outputCanvas
        : this.getCurrentSensorCanvas();
    const blob = await canvasToBlob(
      sourceCanvas,
      options.format === "png" ? "image/png" : "image/jpeg",
      clamp01(options.quality ?? 0.85),
    );

    const analysis = this.computeAnalysis({
      histogram: true,
      clipping: true,
      fps: 0,
    });

    const result = {
      uri: createUrlForBlob(blob),
      width: sourceCanvas.width,
      height: sourceCanvas.height,
      provenance: buildCaptureProvenance({
        snapshot: this.getSnapshot(),
        sessionOptions: {
          flash: this.options.flash,
          zoom: this.options.zoom,
          processing: this.options.processing,
          format: this.options.format,
          intent: this.options.intent,
        },
        capturePath: "snapshot-path-b",
        analysis,
        request: {
          processing: this.options.processing,
        },
        }),
    } satisfies CameraSnapshotResult;

    recordCameraSessionCapture(this.id, result);
    return result;
  }

  async startRecording(options: CameraRecordingOptions = {}): Promise<void> {
    if (!this.videoEnabled) {
      throw new Error("capture/pipeline-disabled");
    }
    if (this.recordingState !== "inactive") {
      throw new Error("capture/failed");
    }

    const recorder = await this.createRecorder(options);
    if (!recorder) {
      throw new Error("capture/codec-unsupported");
    }

    this.currentRecordingChunks = [];
    this.currentRecordingOptions = options;
    this.recordingBytesWritten = 0;
    this.recordingChunks = 0;
    this.recordingStartedAt = performance.now();
    this.recordingState = "recording";
    this.currentRecorder = recorder;
    this.discardNextRecording = false;

    recorder.ondataavailable = (event: BlobEvent) => {
      if (!event.data || event.data.size === 0) {
        return;
      }
      this.currentRecordingChunks.push(event.data);
      this.recordingBytesWritten += event.data.size;
      this.recordingChunks += 1;
      this.diagnostics.recordingBytesWritten = this.recordingBytesWritten;
      this.diagnostics.recordingChunks = this.recordingChunks;
      this.currentRecordingOptions?.onProgress?.({
        elapsedSeconds: (performance.now() - this.recordingStartedAt) / 1000,
        bytesWritten: this.recordingBytesWritten,
      });
    };

    recorder.onerror = () => {
      const error = makeCameraError(
        "capture/failed",
        "The browser recording pipeline failed.",
        true,
      );
      this.currentRecordingOptions?.onError?.(error);
      this.options.onError?.(error);
    };

    recorder.onstop = () => {
      const selectedRollingChunks =
        options.includeRetroactive && this.options.retroactiveBuffer
          ? this.selectRetroactiveChunks(this.options.retroactiveBuffer)
          : [];
      const blobs = [
        ...selectedRollingChunks.map((entry) => entry.blob),
        ...this.currentRecordingChunks,
      ];
      const size = blobs.reduce((total, blob) => total + blob.size, 0);
      const mimeType = recorder.mimeType || "video/webm";
      const blob = new Blob(blobs, { type: mimeType });
      const retroactiveSeconds =
        selectedRollingChunks.reduce((total, chunk) => total + chunk.durationMs, 0) / 1_000;
      const retroactiveAudioAvailable =
        options.audio === true
          ? options.includeRetroactive === true
            ? selectedRollingChunks.length > 0
              && selectedRollingChunks.every((chunk) => chunk.includesAudio)
            : false
          : undefined;
      const result: CameraVideoResult = {
        uri: createUrlForBlob(blob),
        duration: (performance.now() - this.recordingStartedAt) / 1000,
        size,
        retroactiveSeconds,
        retroactiveAudioAvailable,
        provenance: buildCaptureProvenance({
          snapshot: this.getSnapshot(),
          sessionOptions: {
            flash: this.options.flash,
            zoom: this.options.zoom,
            processing: this.options.processing,
            format: this.options.format,
            intent: this.options.intent,
          },
          capturePath:
            this.options.previewMode === "processed"
              ? "processed-photo-pass"
              : "photo-pipeline",
          request: {
            processing: this.options.processing,
            location: options.location,
          },
          locationEmbedded: false,
        }),
      };

      const finishedCallback = this.currentRecordingOptions?.onFinished;
      const shouldDiscard = this.discardNextRecording;
      this.recordingState = "inactive";
      this.currentRecorder = null;
      this.currentRecordingOptions = null;
      this.currentRecordingChunks = [];
      this.clearRecordingTimer();
      this.notify();

      if (!shouldDiscard) {
        finishedCallback?.(result);
      }
    };

    recorder.start(1000);
    this.startRecordingTimer();
    this.notify();
  }

  async stopRecording(): Promise<void> {
    if (this.currentRecorder && this.recordingState !== "inactive") {
      this.currentRecorder.requestData?.();
      this.currentRecorder.stop();
    }
  }

  async pauseRecording(): Promise<void> {
    if (this.currentRecorder && this.recordingState === "recording") {
      this.currentRecorder.pause();
      this.recordingState = "paused";
      this.notify();
    }
  }

  async resumeRecording(): Promise<void> {
    if (this.currentRecorder && this.recordingState === "paused") {
      this.currentRecorder.resume();
      this.recordingState = "recording";
      this.notify();
    }
  }

  async cancelRecording(): Promise<void> {
    if (this.currentRecorder && this.recordingState !== "inactive") {
      this.discardNextRecording = true;
      this.currentRecorder.stop();
    }
  }

  async focus(_point: CameraPoint): Promise<void> {
    // Browsers do not expose a portable, reliable focus-point API for the
    // preview stream. We intentionally keep this as a no-op that preserves the
    // public contract without lying about hardware support.
  }

  async setExposurePoint(_point: CameraPoint): Promise<void> {
    // Same rationale as focus(): the API exists, but web support is not
    // consistent enough to pretend this works uniformly.
  }

  async getScene(options: {
    features?: CameraSceneFeature[];
  } = {}): Promise<CameraSceneSnapshot> {
    await this.ensureSensorBufferFresh();

    const features = options.features ?? getCameraSceneFeatures();
    const analysis = this.computeAnalysis({
      histogram: features.includes("brightness"),
      clipping: features.includes("blur"),
      fps: 0,
    });
    const unavailableFeatures: CameraSceneSnapshot["unavailableFeatures"] = [];
    const objectsRequested = features.includes("objects");
    const needsBarcodeDetections = features.includes("barcodes") || objectsRequested;
    const needsTextDetections = features.includes("text") || objectsRequested;
    const needsFaceDetections = features.includes("faces") || objectsRequested;
    let objectSignalAvailable = false;
    const normalizeBounds = (bounds: DOMRectReadOnly) => ({
      x: bounds.x / Math.max(1, this.rawCanvas.width),
      y: bounds.y / Math.max(1, this.rawCanvas.height),
      width: bounds.width / Math.max(1, this.rawCanvas.width),
      height: bounds.height / Math.max(1, this.rawCanvas.height),
    });

    let barcodes: CameraSceneSnapshot["barcodes"];
    if (needsBarcodeDetections) {
      const detectorCtor = getBarcodeDetector();
      if (detectorCtor) {
        try {
          const detector = new detectorCtor();
          const codes = await detector.detect(this.rawCanvas);
          objectSignalAvailable = true;
          barcodes = codes.map((code) => {
            const bounds = code.boundingBox ?? new DOMRectReadOnly(0, 0, 0, 0);
            return {
              type: normalizeCodeType(code.format ?? "unknown"),
              data: code.rawValue ?? "",
              bounds: normalizeBounds(bounds),
            };
          });
        } catch {
          if (features.includes("barcodes")) {
            unavailableFeatures.push({
              feature: "barcodes",
              reason: "scene/ml-unavailable",
            });
          }
        }
      } else if (features.includes("barcodes")) {
        unavailableFeatures.push({
          feature: "barcodes",
          reason: "scene/ml-unavailable",
        });
      }
    }

    let text: CameraSceneSnapshot["text"];
    if (needsTextDetections) {
      const detectorCtor = getTextDetector();
      if (detectorCtor) {
        try {
          const detector = new detectorCtor();
          const detectedText = await detector.detect(this.rawCanvas);
          objectSignalAvailable = true;
          text = detectedText
            .map((entry) => {
              const bounds = entry.boundingBox ?? new DOMRectReadOnly(0, 0, 0, 0);
              return {
                value: entry.rawValue ?? "",
                bounds: normalizeBounds(bounds),
              };
            })
            .filter((entry) => entry.value.trim().length > 0);
        } catch {
          if (features.includes("text")) {
            unavailableFeatures.push({
              feature: "text",
              reason: "scene/ml-unavailable",
            });
          }
        }
      } else if (features.includes("text")) {
        unavailableFeatures.push({
          feature: "text",
          reason: "scene/ml-unavailable",
        });
      }
    }

    let faces: CameraSceneSnapshot["faces"];
    if (needsFaceDetections) {
      const detectorCtor = getFaceDetector();
      if (detectorCtor) {
        try {
          const detector = new detectorCtor({
            fastMode: true,
            maxDetectedFaces: 8,
          });
          const detectedFaces = await detector.detect(this.rawCanvas);
          objectSignalAvailable = true;
          faces = detectedFaces.map((entry) => {
            const bounds = entry.boundingBox ?? new DOMRectReadOnly(0, 0, 0, 0);
            return {
              bounds: normalizeBounds(bounds),
            };
          });
        } catch {
          if (features.includes("faces")) {
            unavailableFeatures.push({
              feature: "faces",
              reason: "scene/ml-unavailable",
            });
          }
        }
      } else if (features.includes("faces")) {
        unavailableFeatures.push({
          feature: "faces",
          reason: "scene/ml-unavailable",
        });
      }
    }

    let objects: CameraSceneSnapshot["objects"];
    if (objectsRequested) {
      if (objectSignalAvailable) {
        objects = deriveSceneObjectsFromSignals({
          barcodes,
          faces,
          text,
        });
      } else {
        unavailableFeatures.push({
          feature: "objects",
          reason: "scene/ml-unavailable",
        });
      }
    }

    return {
      frameId: this.frameCounter > 0 ? this.frameCounter : null,
      objects,
      text,
      barcodes,
      faces,
      brightness: features.includes("brightness")
        ? estimateBrightnessFromHistogram(analysis?.histogram)
        : undefined,
      blur: features.includes("blur") ? estimateBlurFromAnalysis(analysis) : undefined,
      dominantColors: features.includes("dominantColors")
        ? this.computeDominantColors()
        : undefined,
      unavailableFeatures:
        unavailableFeatures.length > 0 ? unavailableFeatures : undefined,
    };
  }

  async exportReplay(options: {
    seconds: number;
  }): Promise<CameraReplayExport> {
    const selectedChunks = this.selectRetroactiveChunks(options.seconds);
    if (selectedChunks.length === 0) {
      throw makeCameraError(
        "capture/no-buffer-data",
        "No retroactive buffer data is available for replay export.",
        true,
      );
    }

    const replayPayload = {
      version: 1,
      mimeType: this.rollingRecorder?.mimeType || this.currentRecorder?.mimeType || "video/webm",
      exportedAt: Date.now(),
      seconds: options.seconds,
      frameCount: Math.max(1, Math.round((options.seconds || 1) * 15)),
      chunks: await Promise.all(
        selectedChunks.map(async (chunk) => ({
          timestamp: chunk.timestamp,
          size: chunk.size,
          data: arrayBufferToBase64(await chunk.blob.arrayBuffer()),
        })),
      ),
    };

    const blob = new Blob([JSON.stringify(replayPayload)], {
      type: "application/json",
    });
    const uri = createUrlForBlob(blob);
    const startFrameId = Math.max(0, this.frameCounter - replayPayload.frameCount);
    const endFrameId = Math.max(startFrameId, this.frameCounter);

    return {
      uri,
      seconds: options.seconds,
      frameCount: replayPayload.frameCount,
      startFrameId,
      endFrameId,
    };
  }

  computeAnalysis(options: CameraAnalysisOptions): CameraAnalysisSnapshot | null {
    if (this.rawCanvas.width === 0 || this.rawCanvas.height === 0) {
      this.drawCurrentSensorFrame();
    }
    const canvas = this.getCurrentSensorCanvas();
    if (canvas.width === 0 || canvas.height === 0) {
      return null;
    }

    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) {
      return null;
    }

    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
    const r = new Array<number>(256).fill(0);
    const g = new Array<number>(256).fill(0);
    const b = new Array<number>(256).fill(0);
    const lum = new Array<number>(256).fill(0);
    let clippedR = 0;
    let clippedG = 0;
    let clippedB = 0;
    const pixelCount = imageData.data.length / 4;

    for (let index = 0; index < imageData.data.length; index += 4) {
      const red = imageData.data[index];
      const green = imageData.data[index + 1];
      const blue = imageData.data[index + 2];
      r[red] += 1;
      g[green] += 1;
      b[blue] += 1;
      const luma = Math.round(red * 0.299 + green * 0.587 + blue * 0.114);
      lum[luma] += 1;
      if (red >= 250) clippedR += 1;
      if (green >= 250) clippedG += 1;
      if (blue >= 250) clippedB += 1;
    }

    return {
      histogram: options.histogram
        ? {
            r,
            g,
            b,
            lum,
          }
        : undefined,
      clipping: options.clipping
        ? {
            r: pixelCount === 0 ? 0 : clippedR / pixelCount,
            g: pixelCount === 0 ? 0 : clippedG / pixelCount,
            b: pixelCount === 0 ? 0 : clippedB / pixelCount,
          }
        : undefined,
      fps: this.diagnostics.processorFps,
      frameId: this.frameCounter,
    };
  }

  private get photoEnabled(): boolean {
    return this.options.photo !== false;
  }

  private get videoEnabled(): boolean {
    return this.options.video === true || (this.options.retroactiveBuffer ?? 0) > 0;
  }

  private notify(): void {
    for (const subscriber of this.subscribers) {
      subscriber();
    }
    emitRegistryChange();
  }

  private getStreamSize(): { width: number; height: number } | null {
    if (this.rawCanvas.width > 0 && this.rawCanvas.height > 0) {
      return {
        width: this.rawCanvas.width,
        height: this.rawCanvas.height,
      };
    }
    if (this.bindings?.video.videoWidth && this.bindings.video.videoHeight) {
      return {
        width: this.bindings.video.videoWidth,
        height: this.bindings.video.videoHeight,
      };
    }
    return null;
  }

  private getRenderSize(): { width: number; height: number } | null {
    if (!this.bindings) {
      return null;
    }
    return {
      width: this.bindings.container.clientWidth,
      height: this.bindings.container.clientHeight,
    };
  }

  private computeDominantColors(): string[] {
    const canvas = this.getCurrentSensorCanvas();
    if (canvas.width === 0 || canvas.height === 0) {
      return [];
    }

    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) {
      return [];
    }

    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
    const buckets = new Map<string, number>();
    for (let index = 0; index < imageData.data.length; index += 16) {
      const red = imageData.data[index] ?? 0;
      const green = imageData.data[index + 1] ?? 0;
      const blue = imageData.data[index + 2] ?? 0;
      const bucket = `#${Math.round(red / 32)
        .toString(16)
        .padStart(2, "0")}${Math.round(green / 32)
        .toString(16)
        .padStart(2, "0")}${Math.round(blue / 32)
        .toString(16)
        .padStart(2, "0")}`;
      buckets.set(bucket, (buckets.get(bucket) ?? 0) + 1);
    }

    return [...buckets.entries()]
      .sort((left, right) => right[1] - left[1])
      .slice(0, 3)
      .map(([color]) => color);
  }

  private installResizeObserver(): void {
    if (!this.bindings || typeof ResizeObserver === "undefined") {
      return;
    }
    this.stopResizeObserver();
    this.resizeObserver = new ResizeObserver(() => {
      this.syncCanvasSizeToContainer();
    });
    this.resizeObserver.observe(this.bindings.container);
    this.syncCanvasSizeToContainer();
  }

  private stopResizeObserver(): void {
    this.resizeObserver?.disconnect();
    this.resizeObserver = null;
  }

  private syncCanvasSizeToContainer(): void {
    if (!this.bindings) {
      return;
    }
    const rect = this.bindings.container.getBoundingClientRect();
    const dpr = typeof window === "undefined" ? 1 : window.devicePixelRatio || 1;
    const width = Math.max(1, Math.round(rect.width * dpr));
    const height = Math.max(1, Math.round(rect.height * dpr));
    if (
      this.bindings.processedCanvas.width !== width ||
      this.bindings.processedCanvas.height !== height
    ) {
      this.bindings.processedCanvas.width = width;
      this.bindings.processedCanvas.height = height;
    }
  }

  private syncPresentationMode(): void {
    if (!this.bindings) {
      return;
    }

    const processed = this.options.previewMode === "processed";
    this.bindings.video.style.display = processed ? "none" : "block";
    this.bindings.processedCanvas.style.display = processed ? "block" : "none";
    this.bindings.video.style.width = "100%";
    this.bindings.video.style.height = "100%";
    this.bindings.video.style.objectFit =
      this.options.resizeMode === "stretch" ? "fill" : (this.options.resizeMode ?? "cover");
    this.bindings.video.style.transform = this.options.mirror ? "scaleX(-1)" : "";
    this.bindings.processedCanvas.style.width = "100%";
    this.bindings.processedCanvas.style.height = "100%";
  }

  private enqueueLifecycle(task: () => Promise<void>): Promise<void> {
    // Camera mount/update churn can rebind the preview element while a prior
    // start/stop is still awaiting getUserMedia() or video.play(). Serialize
    // those transitions so a stale preview start cannot race a newer restart.
    const nextTask = this.lifecycleTask
      .catch(() => {
        // The last lifecycle op already surfaced its own error through
        // controller state. Keep the queue moving for the latest request.
      })
      .then(task);
    this.lifecycleTask = nextTask.catch(() => {
      // Preserve the rejection for the originating caller but keep future
      // lifecycle work serializable.
    });
    return nextTask;
  }

  private async syncLifecycle(): Promise<void> {
    if (!this.bindings) {
      return;
    }

    this.syncPresentationMode();
    if (this.options.active === false) {
      await this.stopSession();
      return;
    }

    if (!this.started) {
      await this.startSession();
      return;
    }

    await this.syncFramePipeline();
    await this.syncRollingRecorderLifecycle();
  }

  private async restartSession(): Promise<void> {
    await this.stopSession();
    await this.startSession();
  }

  private async startSession(): Promise<void> {
    if (this.started || !this.bindings) {
      return;
    }

    try {
      const admissionError = getCameraSessionAdmissionError({
        snapshot: this.getSnapshot(),
        format: this.options.format ?? this.options.device?.formats[0] ?? null,
      });
      if (admissionError) {
        throw admissionError;
      }

      const stream = await this.createPreviewStream();
      this.mediaStream = stream;
      const video = this.bindings.video;
      video.srcObject = stream;
      video.muted = true;
      video.playsInline = true;
      try {
        await video.play();
      } catch (error) {
        if (!isTransientVideoPlayInterruption(error)) {
          throw error;
        }

        // If a newer lifecycle step already replaced this stream, treat the
        // interrupted play() as stale work instead of surfacing a false
        // device/configuration-failed error to the app.
        if (this.bindings?.video !== video || video.srcObject !== stream) {
          return;
        }
      }

      if (this.bindings?.video !== video || video.srcObject !== stream) {
        return;
      }
      this.started = true;
      this.initialized = true;
      this.lastError = null;
      this.options.onInitialized?.();
      this.syncCanvasSizeToContainer();
      await this.syncFramePipeline();
      this.applyTrackSettings();
      await this.syncRollingRecorderLifecycle();
      this.notify();
    } catch (error) {
      const cameraError = toPermissionDeniedError(error);
      this.lastError = cameraError;
      // RFC 0044 treats lack of camera permission as a placeholder state rather
      // than a mount error. Only unexpected runtime failures surface through
      // onError; prompt/denied states simply keep the preview dark.
      if (cameraError.code !== "permission/camera-denied") {
        this.options.onError?.(cameraError);
      }
      this.notify();
    }
  }

  private async stopSession(): Promise<void> {
    this.cancelFrameLoop();
    this.frameProcessorRuntime.dispose();
    this.processingBusy = false;
    this.hasProcessedPreviewFrame = false;
    this.pathBActive = false;
    this.stopRollingRecorder();
    this.clearRecordingTimer();
    if (this.currentRecorder && this.currentRecorder.state !== "inactive") {
      this.currentRecorder.stop();
    }
    this.currentRecorder = null;
    this.recordingState = "inactive";
    this.started = false;
    this.lastProcessorState = {
      frameId: null,
      timestamp: null,
      result: null,
    };

    if (this.bindings) {
      this.bindings.video.pause();
      this.bindings.video.srcObject = null;
      const context = this.bindings.processedCanvas.getContext("2d");
      context?.clearRect(
        0,
        0,
        this.bindings.processedCanvas.width,
        this.bindings.processedCanvas.height,
      );
    }

    if (this.audioStream) {
      for (const track of this.audioStream.getTracks()) {
        track.stop();
      }
      this.audioStream = null;
    }

    if (this.rollingAudioStream) {
      for (const track of this.rollingAudioStream.getTracks()) {
        track.stop();
      }
      this.rollingAudioStream = null;
    }

    if (this.mediaStream) {
      for (const track of this.mediaStream.getTracks()) {
        track.stop();
      }
      this.mediaStream = null;
    }

    if (this.virtualController) {
      this.virtualController.stop();
      this.virtualController = null;
    }

    this.notifyPathBState(false);
    this.notify();
  }

  private async createPreviewStream(): Promise<MediaStream> {
    const selectedDevice = this.options.device ?? (await this.selectDevice());

    if (!selectedDevice) {
      throw makeCameraError(
        "device/unavailable",
        "No camera device is available.",
        false,
      );
    }

    if (selectedDevice.isVirtual) {
      const controller = new VirtualCameraController(
        selectedDevice.id,
        getVirtualCameraConfig(selectedDevice.id),
      );
      this.virtualController = controller;
      this.diagnostics.virtualSourceType = controller.getSourceType();
      await controller.start();
      return controller.stream;
    }

    const permission = await getCameraPermissionDetails();
    if (permission.state !== "granted") {
      throw makeCameraError(
        "permission/camera-denied",
        permission.state === "prompt"
          ? "Camera access has not been granted yet."
          : "Camera access was denied.",
        false,
      );
    }

    const nav = getNavigator();
    if (!nav?.mediaDevices?.getUserMedia) {
      throw new Error("getUserMedia is unavailable");
    }

    const constraints = this.buildVideoConstraints(selectedDevice);
    const stream = await nav.mediaDevices.getUserMedia({
      video: constraints,
      audio: false,
    });
    this.options.device = selectedDevice;
    return stream;
  }

  private async selectDevice(): Promise<CameraDevice | null> {
    const devices = cachedDevices.length > 0 ? cachedDevices : await listCameraDevices();
    const requestedPosition = this.options.position ?? "back";
    const exactDeviceId = this.options.device?.id;
    if (exactDeviceId) {
      return devices.find((device) => device.id === exactDeviceId) ?? null;
    }

    const positionMatch = devices.find((device) => device.position === requestedPosition);
    if (positionMatch) {
      return positionMatch;
    }
    return devices[0] ?? null;
  }

  private buildVideoConstraints(selectedDevice: CameraDevice): MediaTrackConstraints {
    const format = this.options.format ?? selectedDevice.formats[1] ?? selectedDevice.formats[0];
    return {
      deviceId: selectedDevice.id ? { exact: selectedDevice.id } : undefined,
      facingMode:
        selectedDevice.position === "front"
          ? "user"
          : selectedDevice.position === "back"
            ? "environment"
            : undefined,
      width: format?.videoWidth ? { ideal: format.videoWidth } : undefined,
      height: format?.videoHeight ? { ideal: format.videoHeight } : undefined,
      frameRate: format?.maxFps ? { ideal: format.maxFps } : undefined,
    };
  }

  private applyTrackSettings(): void {
    const track = this.mediaStream?.getVideoTracks()[0] as MediaTrackWithCapabilities | undefined;
    if (!track?.getCapabilities || !track.applyConstraints) {
      return;
    }

    const capabilities = track.getCapabilities() as MediaTrackCapabilitiesLike;
    const zoom = this.options.zoom ?? 1;
    const nextConstraints: MediaTrackConstraints = {};

    if (capabilities.zoom && Number.isFinite(zoom)) {
      nextConstraints.advanced = [{ zoom } as MediaTrackConstraintSet];
    }

    if (this.options.torch && capabilities.torch) {
      nextConstraints.advanced = [
        ...(nextConstraints.advanced ?? []),
        { torch: true } as MediaTrackConstraintSet,
      ];
    }

    if (Object.keys(nextConstraints).length > 0) {
      void track.applyConstraints(nextConstraints).catch(() => {
        // Best-effort only. Web camera constraint support is highly fragmented.
      });
    }
  }

  private needsPathB(): boolean {
    return (
      this.options.previewMode === "processed" ||
      isCameraFrameProcessor(this.options.frameProcessor) ||
      !!this.options.codeScanner ||
      (this.options.retroactiveBuffer ?? 0) > 0
    );
  }

  private async syncFramePipeline(): Promise<void> {
    const shouldRunPathB = this.needsPathB();

    if (!shouldRunPathB) {
      this.cancelFrameLoop();
      this.frameProcessorRuntime.dispose();
      this.processingBusy = false;
      this.notifyPathBState(false);
      return;
    }

    if (isCameraFrameProcessor(this.options.frameProcessor)) {
      await this.frameProcessorRuntime.updateProcessor(this.options.frameProcessor);
    } else {
      this.frameProcessorRuntime.dispose();
    }

    if (!this.frameLoopToken) {
      this.diagnostics.pathBActivations += 1;
      this.notifyPathBState(true);
      this.scheduleNextFrame();
    }
  }

  private notifyPathBState(nextState: boolean): void {
    if (this.pathBActive === nextState) {
      return;
    }
    this.pathBActive = nextState;
    this.options.onStatusChange?.({
      code: nextState ? "session/path-b-activated" : "session/path-b-deactivated",
      message: nextState
        ? "The processing ring is active."
        : "The processing ring has been released.",
    });
  }

  private cancelFrameLoop(): void {
    if (!this.frameLoopToken || !this.bindings) {
      this.frameLoopToken = null;
      return;
    }

    if (this.frameLoopToken.kind === "video-frame-callback") {
      const video = this.bindings.video as HTMLVideoElement & {
        cancelVideoFrameCallback?: (id: number) => void;
      };
      video.cancelVideoFrameCallback?.(this.frameLoopToken.id);
    } else {
      cancelAnimationFrame(this.frameLoopToken.id);
    }
    this.frameLoopToken = null;
  }

  private scheduleNextFrame(): void {
    if (!this.bindings) {
      return;
    }

    const video = this.bindings.video as HTMLVideoElement & {
      requestVideoFrameCallback?: (
        callback: (time: number, metadata: VideoFrameCallbackMetadata) => void,
      ) => number;
    };

    if (typeof video.requestVideoFrameCallback === "function") {
      const id = video.requestVideoFrameCallback((_time, metadata) => {
        this.frameLoopToken = null;
        void this.handleFrame(metadata.expectedDisplayTime);
      });
      this.frameLoopToken = {
        kind: "video-frame-callback",
        id,
      };
      return;
    }

    const id = requestAnimationFrame((time) => {
      this.frameLoopToken = null;
      void this.handleFrame(time);
    });
    this.frameLoopToken = {
      kind: "raf",
      id,
    };
  }

  private async handleFrame(timestamp: number): Promise<void> {
    try {
      this.diagnostics.framesReceived += 1;
      this.diagnostics.lastFrameTimestamp = timestamp;
      this.frameCounter += 1;
      this.drawCurrentSensorFrame();
      await this.runCodeScannerIfNeeded(timestamp);
      await this.runFrameProcessorIfNeeded(timestamp);
      this.drawPreviewFromCurrentBuffer();
    } finally {
      if (this.needsPathB()) {
        this.scheduleNextFrame();
      }
      this.notify();
    }
  }

  private drawCurrentSensorFrame(): void {
    if (!this.bindings) {
      return;
    }

    const source = this.virtualController?.canvas ?? this.bindings.video;
    const sourceWidth =
      this.virtualController?.canvas.width || this.bindings.video.videoWidth || 0;
    const sourceHeight =
      this.virtualController?.canvas.height || this.bindings.video.videoHeight || 0;

    if (sourceWidth <= 0 || sourceHeight <= 0) {
      return;
    }

    if (this.rawCanvas.width !== sourceWidth || this.rawCanvas.height !== sourceHeight) {
      this.rawCanvas.width = sourceWidth;
      this.rawCanvas.height = sourceHeight;
      this.outputCanvas.width = sourceWidth;
      this.outputCanvas.height = sourceHeight;
      this.scratchCanvas.width = sourceWidth;
      this.scratchCanvas.height = sourceHeight;
      this.hasProcessedPreviewFrame = false;
    }

    this.rawContext.drawImage(source, 0, 0, sourceWidth, sourceHeight);

    // When processed preview is enabled at a lower target FPS than the source
    // stream, keep showing the most recent processed frame between processor
    // passes. Overwriting the output buffer with raw frames here causes the
    // preview to flicker between filtered and unfiltered images.
    const preserveProcessedPreviewFrame =
      this.options.previewMode === "processed"
      && isCameraFrameProcessor(this.options.frameProcessor)
      && this.hasProcessedPreviewFrame;
    if (!preserveProcessedPreviewFrame) {
      this.outputContext.drawImage(this.rawCanvas, 0, 0);
    }
  }

  private async runCodeScannerIfNeeded(timestamp: number): Promise<void> {
    const scanner = this.options.codeScanner;
    if (!scanner) {
      return;
    }

    const detectorCtor = getBarcodeDetector();
    if (!detectorCtor) {
      return;
    }

    const fps = Math.max(1, scanner.fps ?? 5);
    if (timestamp - this.lastCodeScanAt < 1000 / fps) {
      return;
    }

    this.lastCodeScanAt = timestamp;
    try {
      const detector = new detectorCtor({
        formats: scanner.types.map((type) => normalizeCodeType(type).replaceAll("-", "_")),
      });
      const codes = await detector.detect(this.rawCanvas);
      if (codes.length === 0) {
        return;
      }
      const renderSize = this.getRenderSize();
      const targetWidth = renderSize?.width ?? this.rawCanvas.width;
      const targetHeight = renderSize?.height ?? this.rawCanvas.height;
      const normalizedCodes = codes.map((code) => {
        const bounds = code.boundingBox ?? new DOMRectReadOnly(0, 0, 0, 0);
        const normalizedBounds = sensorRectToViewRect(
          {
            x: bounds.x,
            y: bounds.y,
            width: bounds.width,
            height: bounds.height,
          },
          this.rawCanvas.width,
          this.rawCanvas.height,
          targetWidth,
          targetHeight,
          this.options.resizeMode ?? "cover",
          this.options.mirror === true,
        );
        return {
          type: normalizeCodeType(code.format ?? "unknown"),
          data: code.rawValue ?? "",
          bounds: normalizedBounds,
          corners: (code.cornerPoints ?? []).map((point) => {
            const rect = sensorRectToViewRect(
              {
                x: point.x,
                y: point.y,
                width: 1,
                height: 1,
              },
              this.rawCanvas.width,
              this.rawCanvas.height,
              targetWidth,
              targetHeight,
              this.options.resizeMode ?? "cover",
              this.options.mirror === true,
            );
            return {
              x: rect.x,
              y: rect.y,
            };
          }),
        } satisfies CameraCodeScannerResult;
      });
      scanner.onScanned(normalizedCodes);
    } catch {
      // BarcodeDetector support varies enough across browsers that failed scans
      // should not poison the entire camera session.
    }
  }

  private async runFrameProcessorIfNeeded(timestamp: number): Promise<void> {
    const processor = this.options.frameProcessor;
    if (!isCameraFrameProcessor(processor)) {
      return;
    }

    if (this.processingBusy) {
      this.diagnostics.framesDropped += 1;
      const dropBudgetExceeded =
        this.diagnostics.framesReceived > 0 &&
        this.diagnostics.framesDropped / this.diagnostics.framesReceived > 0.5;
      if (dropBudgetExceeded) {
        this.options.onError?.(
          makeCameraError(
            "processor/overload",
            "The frame processor is dropping more than half of incoming frames.",
            true,
          ),
        );
      }
      return;
    }

    const minInterval = 1000 / Math.max(1, processor.fps);
    if (
      this.diagnostics.lastProcessorTimestamp != null &&
      timestamp - this.diagnostics.lastProcessorTimestamp < minInterval
    ) {
      return;
    }

    this.processingBusy = true;
    this.diagnostics.lastProcessorTimestamp = timestamp;

    try {
      const imageData = this.rawContext.getImageData(
        0,
        0,
        this.rawCanvas.width,
        this.rawCanvas.height,
      );
      const inputBuffer = rgbaToBgra(imageData.data);
      const renderSize = this.getRenderSize();
      const response = await this.frameProcessorRuntime.processFrame({
        inputBuffer,
        width: this.rawCanvas.width,
        height: this.rawCanvas.height,
        timestamp,
        previewMode: this.options.previewMode ?? "native",
        resizeMode: this.options.resizeMode ?? "cover",
        mirror: this.options.mirror === true,
        targetWidth: renderSize?.width ?? this.rawCanvas.width,
        targetHeight: renderSize?.height ?? this.rawCanvas.height,
        isCaptureFrame: false,
      });

      this.diagnostics.framesProcessed += 1;
      this.diagnostics.processorFps =
        this.diagnostics.lastProcessorTimestamp == null
          ? processor.fps
          : Math.round(
              1000 /
                Math.max(1, timestamp - (this.diagnostics.lastProcessorTimestamp ?? timestamp)),
            );

      if (response.outputBuffer) {
        const rgba = bgraToRgba(new Uint8Array(response.outputBuffer));
        const stableRgba = new Uint8ClampedArray(rgba.length);
        stableRgba.set(rgba);
        const processedImage = new ImageData(
          stableRgba,
          this.rawCanvas.width,
          this.rawCanvas.height,
        );
        this.outputContext.putImageData(processedImage, 0, 0);
        this.hasProcessedPreviewFrame = true;
      }

      if (response.result !== undefined) {
        this.lastProcessorState = {
          frameId: this.frameCounter,
          timestamp,
          result: response.result,
        };
        processor.onResult?.(response.result);
      }
    } catch (error) {
      const processorError = makeCameraError(
        "processor/failed",
        error instanceof Error ? error.message : "Frame processor failed.",
        true,
        error instanceof Error ? error : undefined,
      );
      this.options.onError?.(processorError);
      this.lastError = processorError;
    } finally {
      this.processingBusy = false;
    }
  }

  private drawPreviewFromCurrentBuffer(): void {
    if (!this.bindings || this.options.previewMode !== "processed") {
      return;
    }

    const context = this.bindings.processedCanvas.getContext("2d");
    if (!context) {
      return;
    }

    const source = this.outputCanvas.width > 0 ? this.outputCanvas : this.rawCanvas;
    drawSourceIntoTarget(
      context,
      source,
      source.width,
      source.height,
      this.bindings.processedCanvas.width,
      this.bindings.processedCanvas.height,
      this.options.resizeMode ?? "cover",
      this.options.mirror === true,
    );
  }

  private getCurrentSensorCanvas(): HTMLCanvasElement {
    return this.rawCanvas.width > 0 ? this.rawCanvas : this.outputCanvas;
  }

  private async renderCurrentViewToCanvas(): Promise<HTMLCanvasElement> {
    if (!this.bindings) {
      throw new Error("Camera bindings are unavailable.");
    }
    const renderCanvas = createBlankCanvas();
    const size = this.getRenderSize();
    renderCanvas.width = Math.max(1, size?.width ?? this.rawCanvas.width);
    renderCanvas.height = Math.max(1, size?.height ?? this.rawCanvas.height);
    const context = renderCanvas.getContext("2d");
    if (!context) {
      throw new Error("Failed to create view capture canvas.");
    }

    if (this.options.previewMode === "processed") {
      context.drawImage(
        this.bindings.processedCanvas,
        0,
        0,
        renderCanvas.width,
        renderCanvas.height,
      );
      return renderCanvas;
    }

    const source = this.virtualController?.canvas ?? this.bindings.video;
    const sourceWidth =
      this.virtualController?.canvas.width || this.bindings.video.videoWidth || 0;
    const sourceHeight =
      this.virtualController?.canvas.height || this.bindings.video.videoHeight || 0;

    drawSourceIntoTarget(
      context,
      source,
      sourceWidth,
      sourceHeight,
      renderCanvas.width,
      renderCanvas.height,
      this.options.resizeMode ?? "cover",
      this.options.mirror === true,
    );
    return renderCanvas;
  }

  private async capturePhotoCanvas(): Promise<HTMLCanvasElement> {
    if (this.options.previewMode !== "processed") {
      return this.getCurrentSensorCanvas();
    }
    return this.outputCanvas.width > 0 ? this.outputCanvas : this.getCurrentSensorCanvas();
  }

  private async ensureSensorBufferFresh(): Promise<void> {
    // Snapshots and still capture metadata need a current frame even when Path B
    // is cold. We opportunistically draw a single frame here instead of forcing
    // the whole processing loop to stay resident.
    if (this.rawCanvas.width > 0 && this.rawCanvas.height > 0) {
      return;
    }

    if (!this.started) {
      await this.startSession();
    }

    this.drawCurrentSensorFrame();
    if (this.rawCanvas.width > 0 && this.rawCanvas.height > 0) {
      this.frameCounter += 1;
    }
  }

  private async createRecorder(
    options: CameraRecordingOptions,
  ): Promise<MediaRecorderWithRequestData | null> {
    if (typeof MediaRecorder === "undefined") {
      return null;
    }

    const recordingSource =
      this.options.previewMode === "processed"
        ? this.bindings?.processedCanvas.captureStream(options.recordingFps ?? 30) ?? null
        : this.mediaStream?.clone() ?? null;
    if (!recordingSource) {
      return null;
    }

    if (options.audio) {
      const reusableRetroactiveAudio =
        this.options.retroactiveAudio === true
          ? this.rollingAudioStream?.clone() ?? null
          : null;
      if (reusableRetroactiveAudio && reusableRetroactiveAudio.getAudioTracks().length > 0) {
        this.audioStream = reusableRetroactiveAudio;
      } else {
        const nav = getNavigator();
        if (!nav?.mediaDevices?.getUserMedia) {
          throw new Error("Audio capture is unavailable.");
        }
        const audioPermission = await requestMicrophonePermission();
        if (audioPermission.state !== "granted") {
          throw new CapabilityDeniedError("device:microphone", "os_denied", true);
        }
        this.audioStream = await nav.mediaDevices.getUserMedia({
          audio: true,
          video: false,
        });
      }
      for (const track of this.audioStream.getAudioTracks()) {
        recordingSource.addTrack(track);
      }
    }

    const mimeType = pickRecordingMimeType(options.codec ?? "h264");
    if (!mimeType) {
      return null;
    }

    return new MediaRecorder(recordingSource, {
      mimeType,
    }) as MediaRecorderWithRequestData;
  }

  private startRecordingTimer(): void {
    this.clearRecordingTimer();
    this.recordingTimer = setInterval(() => {
      this.currentRecordingOptions?.onProgress?.({
        elapsedSeconds: (performance.now() - this.recordingStartedAt) / 1000,
        bytesWritten: this.recordingBytesWritten,
      });
    }, 1_000);
  }

  private clearRecordingTimer(): void {
    if (this.recordingTimer) {
      clearInterval(this.recordingTimer);
      this.recordingTimer = null;
    }
  }

  private async syncRollingRecorderLifecycle(): Promise<void> {
    const retroactiveSeconds = this.options.retroactiveBuffer ?? 0;
    if (retroactiveSeconds <= 0 || !this.started) {
      this.stopRollingRecorder();
      return;
    }

    const wantsAudio = this.options.retroactiveAudio === true;
    const usesProcessedPreview = this.options.previewMode === "processed";
    const needsRestart =
      this.rollingRecorder != null
      && (this.rollingRecorderHasAudio !== wantsAudio
        || this.rollingRecorderUsesProcessedPreview !== usesProcessedPreview);

    if (needsRestart) {
      this.stopRollingRecorder();
    }

    await this.ensureRollingRecorder();
  }

  private async ensureRollingRecorder(): Promise<void> {
    const retroactiveSeconds = this.options.retroactiveBuffer ?? 0;
    if (retroactiveSeconds <= 0 || typeof MediaRecorder === "undefined") {
      return;
    }
    if (this.rollingRecorder) {
      return;
    }

    const source =
      this.options.previewMode === "processed"
        ? this.bindings?.processedCanvas.captureStream(15) ?? null
        : this.mediaStream?.clone() ?? null;
    if (!source) {
      return;
    }

    let rollingAudioStream: MediaStream | null = null;
    let rollingRecorderHasAudio = false;
    if (this.options.retroactiveAudio === true) {
      rollingAudioStream = await this.ensureRetroactiveAudioStream();
      if (rollingAudioStream) {
        for (const track of rollingAudioStream.getAudioTracks()) {
          source.addTrack(track);
        }
        rollingRecorderHasAudio = rollingAudioStream.getAudioTracks().length > 0;
      }
    }

    const mimeType = pickRecordingMimeType("h264");
    if (!mimeType) {
      if (rollingAudioStream) {
        for (const track of rollingAudioStream.getTracks()) {
          track.stop();
        }
      }
      for (const track of source.getTracks()) {
        track.stop();
      }
      return;
    }

    const recorder = new MediaRecorder(source, { mimeType }) as MediaRecorderWithRequestData;
    this.rollingRecorderSource = source;
    this.rollingAudioStream = rollingAudioStream;
    this.rollingRecorderHasAudio = rollingRecorderHasAudio;
    this.rollingRecorderUsesProcessedPreview =
      this.options.previewMode === "processed";
    this.lastRollingChunkEndedAt = 0;
    recorder.ondataavailable = (event: BlobEvent) => {
      if (this.rollingRecorder !== recorder) {
        return;
      }
      if (!event.data || event.data.size === 0) {
        return;
      }
      const endedAt = Date.now();
      const durationMs =
        this.lastRollingChunkEndedAt > 0
          ? Math.max(0, endedAt - this.lastRollingChunkEndedAt)
          : 1_000;
      const startedAt = endedAt - durationMs;
      this.lastRollingChunkEndedAt = endedAt;
      this.rollingChunks.push({
        blob: event.data,
        timestamp: endedAt,
        startedAt,
        endedAt,
        durationMs,
        size: event.data.size,
        includesAudio: rollingRecorderHasAudio,
      });
      this.trimRollingChunks(retroactiveSeconds);
    };
    recorder.start(1_000);
    this.rollingRecorder = recorder;
  }

  private async ensureRetroactiveAudioStream(): Promise<MediaStream | null> {
    if (this.rollingAudioStream && this.rollingAudioStream.getAudioTracks().length > 0) {
      return this.rollingAudioStream;
    }

    const nav = getNavigator();
    if (!nav?.mediaDevices?.getUserMedia) {
      this.emitRetroactiveAudioUnavailable();
      return null;
    }

    const audioPermission = await requestMicrophonePermission();
    if (audioPermission.state !== "granted") {
      this.emitRetroactiveAudioUnavailable();
      return null;
    }

    try {
      const stream = await nav.mediaDevices.getUserMedia({
        audio: true,
        video: false,
      });
      this.reportedRetroactiveAudioUnavailable = false;
      return stream;
    } catch {
      this.emitRetroactiveAudioUnavailable();
      return null;
    }
  }

  private emitRetroactiveAudioUnavailable(): void {
    if (this.reportedRetroactiveAudioUnavailable) {
      return;
    }
    this.reportedRetroactiveAudioUnavailable = true;
    this.options.onError?.(
      makeCameraError(
        "capture/microphone-unavailable",
        "Retroactive audio requires microphone permission. Continuing with video-only pre-roll.",
        true,
      ),
    );
  }

  private stopRollingRecorder(): void {
    if (this.rollingRecorder && this.rollingRecorder.state !== "inactive") {
      this.rollingRecorder.stop();
    }
    this.rollingRecorder = null;
    if (this.rollingRecorderSource) {
      for (const track of this.rollingRecorderSource.getTracks()) {
        track.stop();
      }
      this.rollingRecorderSource = null;
    }
    if (this.rollingAudioStream) {
      for (const track of this.rollingAudioStream.getTracks()) {
        track.stop();
      }
      this.rollingAudioStream = null;
    }
    this.rollingRecorderHasAudio = false;
    this.rollingRecorderUsesProcessedPreview = false;
    this.lastRollingChunkEndedAt = 0;
    this.rollingChunks = [];
  }

  private trimRollingChunks(retroactiveSeconds: number): void {
    const cutoff = Date.now() - retroactiveSeconds * 1_000;
    this.rollingChunks = this.rollingChunks.filter((chunk) => chunk.timestamp >= cutoff);
  }

  private selectRetroactiveChunks(retroactiveSeconds: number): RollingChunk[] {
    const cutoff = Date.now() - retroactiveSeconds * 1_000;
    return this.rollingChunks.filter((chunk) => chunk.timestamp >= cutoff);
  }
}

export function createWebCameraSession(
  options: CameraSessionOptions = {},
): WebCameraSessionController {
  return new WebCameraSessionController(options);
}

export function chooseCameraDevice(
  devices: CameraDevice[],
  position: CameraPosition,
  preferredLenses: Array<CameraLens["type"]> = [],
): CameraDevice | null {
  const samePosition = devices.filter((device) => device.position === position);
  if (samePosition.length === 0) {
    return devices[0] ?? null;
  }

  if (preferredLenses.length === 0) {
    return samePosition[0] ?? null;
  }

  const scoreDevice = (device: CameraDevice): number => {
    let score = 0;
    for (const [index, lens] of preferredLenses.entries()) {
      if (device.lenses.some((candidate) => candidate.type === lens)) {
        score += (preferredLenses.length - index) * 10;
      }
    }
    return score;
  };

  return [...samePosition].sort((left, right) => scoreDevice(right) - scoreDevice(left))[0] ?? null;
}

type CameraFormatFilter = {
  fps?: number;
  videoAspectRatio?: number;
  photoResolution?: "max" | "min" | number;
};

export function chooseCameraFormat(
  device: CameraDevice | null,
  filters: CameraFormatFilter[] = [],
): CameraFormat | null {
  if (!device || device.formats.length === 0) {
    return null;
  }

  if (filters.length === 0) {
    return device.formats[0] ?? null;
  }

  let bestFormat: CameraFormat | null = null;
  let bestScore = -Infinity;

  for (const format of device.formats) {
    let score = 0;

    filters.forEach((filter, index) => {
      const weight = Math.pow(10, filters.length - index);

      if (filter.videoAspectRatio != null) {
        const ratio = format.videoWidth / format.videoHeight;
        score += weight * (1 - Math.abs(ratio - filter.videoAspectRatio));
      }

      if (filter.fps != null) {
        const bounded = Math.max(format.minFps, Math.min(format.maxFps, filter.fps));
        score += weight * (1 - Math.abs(bounded - filter.fps) / Math.max(filter.fps, 1));
      }

      if (filter.photoResolution != null) {
        const resolution = format.photoWidth * format.photoHeight;
        if (filter.photoResolution === "max") {
          score += weight * resolution;
        } else if (filter.photoResolution === "min") {
          score -= weight * resolution;
        } else {
          score += weight * (1 - Math.abs(resolution - filter.photoResolution) / Math.max(filter.photoResolution, 1));
        }
      }
    });

    if (score > bestScore) {
      bestScore = score;
      bestFormat = format;
    }
  }

  return bestFormat;
}
