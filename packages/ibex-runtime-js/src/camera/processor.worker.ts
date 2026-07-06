/**
 * Camera frame processor worker.
 *
 * The worker evaluates the user-supplied processor function source once and
 * then executes it for each frame with a minimal `Frame` facade that matches
 * the RFC shape closely enough for web camera labs and automated tests.
 */

type CameraPreviewMode = "native" | "processed";
type CameraResizeMode = "cover" | "contain" | "stretch";

interface FrameMessage {
  type: "frame";
  id: number;
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
}

let processorFn: ((frame: unknown) => unknown) | null = null;
let currentCallIndex = 0;
const fpsMemory = new Map<string, { timestamp: number; value: unknown }>();

function computeDrawRect(
  sourceWidth: number,
  sourceHeight: number,
  targetWidth: number,
  targetHeight: number,
  resizeMode: CameraResizeMode,
) {
  if (
    resizeMode === "stretch" ||
    sourceWidth <= 0 ||
    sourceHeight <= 0 ||
    targetWidth <= 0 ||
    targetHeight <= 0
  ) {
    return { x: 0, y: 0, width: targetWidth, height: targetHeight };
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

function sensorToViewRect(
  rect: { x: number; y: number; width: number; height: number },
  message: FrameMessage,
) {
  const drawRect = computeDrawRect(
    message.width,
    message.height,
    message.targetWidth,
    message.targetHeight,
    message.resizeMode,
  );
  const mapped = {
    x: drawRect.x + (rect.x / message.width) * drawRect.width,
    y: drawRect.y + (rect.y / message.height) * drawRect.height,
    width: (rect.width / message.width) * drawRect.width,
    height: (rect.height / message.height) * drawRect.height,
  };

  if (message.mirror) {
    mapped.x = message.targetWidth - (mapped.x + mapped.width);
  }

  return {
    x: mapped.x / message.targetWidth,
    y: mapped.y / message.targetHeight,
    width: mapped.width / message.targetWidth,
    height: mapped.height / message.targetHeight,
  };
}

function runAtTargetFps(targetFps: number, fn: () => unknown): unknown {
  const key = `${targetFps}:${currentCallIndex++}`;
  const last = fpsMemory.get(key);
  const frameBudget = 1000 / Math.max(1, targetFps);
  const now = Date.now();
  if (last && now - last.timestamp < frameBudget) {
    return last.value;
  }
  const value = fn();
  fpsMemory.set(key, { timestamp: now, value });
  return value;
}

function installRuntimeGlobals(): void {
  (globalThis as typeof globalThis & {
    runAtTargetFps?: typeof runAtTargetFps;
  }).runAtTargetFps = runAtTargetFps;
}

installRuntimeGlobals();

self.onmessage = (event: MessageEvent) => {
  const payload = event.data as
    | { type: "init"; source: string }
    | FrameMessage;

  if (payload.type === "init") {
    try {
      // We intentionally evaluate the source in the worker so that processor
      // execution stays off the main thread. The source comes from application
      // code running in the same bundle, not from remote input.
      processorFn = (0, eval)(`(${payload.source})`) as (frame: unknown) => unknown;
    } catch (error) {
      console.error("[CameraWorker] Failed to compile processor:", error);
      processorFn = null;
    }
    return;
  }

  if (!processorFn) {
    // The processor source failed to compile at init (processorFn stayed null).
    // Reply with an error so the main thread's pending request settles instead of
    // hanging forever — a hung request latches processingBusy and turns every
    // subsequent frame into an unbounded 'processor/overload' error. (ENG-22978)
    self.postMessage({
      type: "error",
      id: payload.id,
      message: "Frame processor is not initialized.",
    });
    return;
  }

  try {
    currentCallIndex = 0;
    const input = payload.inputBuffer;
    const writable =
      payload.previewMode === "processed" || payload.isCaptureFrame
        ? input.slice(0)
        : null;

    const frame = {
      width: payload.width,
      height: payload.height,
      timestamp: payload.timestamp,
      orientation: payload.width >= payload.height ? "landscape-left" : "portrait",
      isCaptureFrame: payload.isCaptureFrame,
      pixelFormat: "bgra",
      rawPixelFormat: "bgra",
      toArrayBuffer() {
        return input;
      },
      toWritableBuffer() {
        return writable;
      },
      sensorToView(rect: { x: number; y: number; width: number; height: number }) {
        return sensorToViewRect(rect, payload);
      },
      getDepthData() {
        return null;
      },
    };

    const result = processorFn(frame);
    self.postMessage(
      {
        type: "result",
        id: payload.id,
        result,
        outputBuffer: writable ?? undefined,
      },
      writable ? [writable] : [],
    );
  } catch (error) {
    self.postMessage({
      type: "error",
      id: payload.id,
      message: error instanceof Error ? error.message : String(error),
    });
  }
};
