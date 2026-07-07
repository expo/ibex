/**
 * Regression tests for the ENG-22978 web-camera audit (packages/ibex-runtime-js/src/camera).
 *
 * These exercise the pure JS buffer/lifecycle/state logic of the fixes. The
 * native camera bridge and a real browser media stack cannot run on CI, so the
 * DOM/media surface is mocked just enough to drive the affected code paths; each
 * test is written so it fails on the pre-fix behaviour and passes on the fix.
 */

import { beforeAll, expect, test } from "bun:test";

// ---------------------------------------------------------------------------
// Minimal browser/media mocks. Installed at module top-level so they exist
// before the (dynamically imported) camera module constructs any canvas.
// ---------------------------------------------------------------------------

class FakeTrack {
  stopped = false;
  readyState: "live" | "ended" = "live";
  constructor(public kind: "video" | "audio" = "video") {}
  stop() {
    this.stopped = true;
    this.readyState = "ended";
  }
  getSettings() {
    return {};
  }
  applyConstraints() {
    return Promise.resolve();
  }
  getCapabilities() {
    return {};
  }
}

class FakeMediaStream {
  lastClone: FakeMediaStream | null = null;
  constructor(public tracks: FakeTrack[] = [new FakeTrack("video")]) {}
  getTracks() {
    return this.tracks;
  }
  getVideoTracks() {
    return this.tracks.filter((t) => t.kind === "video");
  }
  getAudioTracks() {
    return this.tracks.filter((t) => t.kind === "audio");
  }
  addTrack(track: FakeTrack) {
    this.tracks.push(track);
  }
  clone() {
    const clone = new FakeMediaStream(this.tracks.map((t) => new FakeTrack(t.kind)));
    this.lastClone = clone;
    return clone;
  }
}

class FakeContext {
  drawImageCalls = 0;
  constructor(public canvas: FakeCanvas) {}
  drawImage(source: any) {
    this.drawImageCalls += 1;
    // Propagate the source's current luma so getImageData reflects freshness.
    if (typeof source?.currentLuma === "number") {
      this.canvas._luma = source.currentLuma;
    } else if (source instanceof FakeCanvas) {
      this.canvas._luma = source._luma;
    }
  }
  getImageData(_x: number, _y: number, w: number, h: number) {
    const width = Math.max(0, w);
    const height = Math.max(0, h);
    const data = new Uint8ClampedArray(width * height * 4);
    const luma = this.canvas._luma;
    for (let i = 0; i < data.length; i += 4) {
      data[i] = luma;
      data[i + 1] = luma;
      data[i + 2] = luma;
      data[i + 3] = 255;
    }
    return { data, width, height };
  }
  putImageData() {}
  clearRect() {}
  fillRect() {}
  fillText() {}
  beginPath() {}
  save() {}
  restore() {}
  translate() {}
  scale() {}
  rotate() {}
  measureText() {
    return { width: 0 };
  }
  set font(_v: string) {}
  get font() {
    return "";
  }
  set fillStyle(_v: string) {}
  get fillStyle() {
    return "";
  }
  set globalAlpha(_v: number) {}
}

class FakeCanvas {
  width = 300; // real browsers report a 300x150 default for a blank canvas
  height = 150;
  _luma = 0;
  _ctx: FakeContext | null = null;
  style: Record<string, unknown> = {};
  getContext() {
    if (!this._ctx) {
      this._ctx = new FakeContext(this);
    }
    return this._ctx;
  }
  captureStream() {
    return new FakeMediaStream([new FakeTrack("video")]);
  }
  toBlob(cb: (blob: Blob) => void) {
    cb(new Blob(["x"]));
  }
}

class FakeVideo {
  videoWidth = 64;
  videoHeight = 48;
  currentLuma = 0;
  srcObject: unknown = null;
  muted = false;
  playsInline = false;
  pause() {}
  play() {
    return Promise.resolve();
  }
}

class FakeMediaRecorder {
  static supported = true;
  static isTypeSupported() {
    return FakeMediaRecorder.supported;
  }
  state: "inactive" | "recording" | "paused" = "inactive";
  mimeType: string;
  ondataavailable: ((e: unknown) => void) | null = null;
  onerror: ((e: unknown) => void) | null = null;
  onstop: (() => void) | null = null;
  constructor(public stream: unknown, opts?: { mimeType?: string }) {
    this.mimeType = opts?.mimeType ?? "video/webm";
  }
  start() {
    this.state = "recording";
  }
  stop() {
    this.state = "inactive";
    this.onstop?.();
  }
  requestData() {}
  pause() {
    this.state = "paused";
  }
  resume() {
    this.state = "recording";
  }
}

// Synchronous, in-thread worker: on a frame message it echoes a result so the
// main thread's pending processFrame() promise settles deterministically.
class FakeWorker {
  onmessage: ((e: { data: unknown }) => void) | null = null;
  terminated = false;
  constructor(_url: unknown, _opts?: unknown) {}
  postMessage(message: any) {
    if (message?.type === "frame") {
      queueMicrotask(() => {
        this.onmessage?.({ data: { type: "result", id: message.id, result: "ok" } });
      });
    }
  }
  terminate() {
    this.terminated = true;
  }
}

const g = globalThis as any;
g.document = { createElement: () => new FakeCanvas() };
g.Worker = FakeWorker;
g.MediaRecorder = FakeMediaRecorder;
g.ImageData = class {
  constructor(public data: unknown, public width: number, public height: number) {}
};
g.requestAnimationFrame = (cb: (t: number) => void) => {
  void cb;
  return 1;
};
g.cancelAnimationFrame = () => {};

function makeBindings() {
  return {
    container: { clientWidth: 64, clientHeight: 48 },
    video: new FakeVideo(),
    processedCanvas: new FakeCanvas(),
  } as any;
}

let camera: typeof import("./index");

beforeAll(async () => {
  camera = await import("./index");
});

// ---------------------------------------------------------------------------
// Finding 3 — worker settles the pending request on a compile failure.
// ---------------------------------------------------------------------------

test("finding 3: worker replies with an error when the processor failed to compile", async () => {
  const posted: any[] = [];
  g.postMessage = (msg: any) => posted.push(msg);
  await import("./processor.worker.ts");
  const handler = g.onmessage as (e: { data: unknown }) => void;
  expect(typeof handler).toBe("function");

  // Source that throws in eval() -> processorFn stays null.
  handler({ data: { type: "init", source: "not valid javascript (((" } });
  posted.length = 0;

  handler({
    data: {
      type: "frame",
      id: 42,
      inputBuffer: new ArrayBuffer(16),
      width: 2,
      height: 2,
      timestamp: 0,
      previewMode: "native",
      resizeMode: "cover",
      mirror: false,
      targetWidth: 2,
      targetHeight: 2,
      isCaptureFrame: false,
    },
  });

  const reply = posted.find((m) => m?.type === "error" && m.id === 42);
  expect(reply).toBeTruthy();
});

test("finding 3: worker still processes frames once the processor compiles", async () => {
  const posted: any[] = [];
  g.postMessage = (msg: any) => posted.push(msg);
  await import("./processor.worker.ts");
  const handler = g.onmessage as (e: { data: unknown }) => void;

  handler({ data: { type: "init", source: "(frame) => ({ ok: frame.width })" } });
  posted.length = 0;

  handler({
    data: {
      type: "frame",
      id: 7,
      inputBuffer: new ArrayBuffer(16),
      width: 3,
      height: 2,
      timestamp: 0,
      previewMode: "native",
      resizeMode: "cover",
      mirror: false,
      targetWidth: 3,
      targetHeight: 2,
      isCaptureFrame: false,
    },
  });

  const reply = posted.find((m) => m?.type === "result" && m.id === 7);
  expect(reply).toBeTruthy();
  expect(reply.result).toEqual({ ok: 3 });
});

// ---------------------------------------------------------------------------
// Finding 1 — computeAnalysis reads a fresh sensor frame, not a stale buffer.
// ---------------------------------------------------------------------------

test("finding 1: computeAnalysis redraws a fresh frame in a non-Path-B session", async () => {
  const session = new camera.WebCameraSessionController({ previewMode: "native" });
  const bindings = makeBindings();
  (session as any).bindings = bindings;
  (session as any).started = true;

  // Prime the raw canvas with a bright frame (sets rawCanvas dimensions to 64x48,
  // which is exactly what used to latch the width>0 guard forever).
  bindings.video.currentLuma = 200;
  (session as any).drawCurrentSensorFrame();

  // Scene goes dark; a correct snapshot must reflect the *current* frame.
  bindings.video.currentLuma = 10;
  const analysis = await session.computeAnalysis({ histogram: true, clipping: true, fps: 0 });

  expect(analysis).not.toBeNull();
  const lum = analysis!.histogram!.lum;
  expect(lum[10]).toBeGreaterThan(0); // fresh (dark) frame
  expect(lum[200]).toBe(0); // not the stale bright buffer
});

// ---------------------------------------------------------------------------
// Finding 5 — processorFps reflects the real inter-frame delta, not 1000.
// ---------------------------------------------------------------------------

test("finding 5: processorFps is derived from the real frame delta", async () => {
  const processor = camera.createCameraFrameProcessor(() => "ok", { fps: 30 });
  const session = new camera.WebCameraSessionController({
    previewMode: "native",
    frameProcessor: processor,
  });
  (session as any).bindings = makeBindings();
  (session as any).started = true;
  await (session as any).frameProcessorRuntime.updateProcessor(processor);

  await (session as any).handleFrame(1000);
  expect((session as any).diagnostics.processorFps).toBe(30); // first frame: seed with fps

  await (session as any).handleFrame(1100); // 100ms later -> 10 fps
  expect((session as any).diagnostics.processorFps).toBe(10);
});

// ---------------------------------------------------------------------------
// Finding 2 — an in-flight frame does not resurrect the loop after stopSession.
// ---------------------------------------------------------------------------

test("finding 2: handleFrame after stopSession neither reschedules nor errors", async () => {
  const errors: unknown[] = [];
  const processor = camera.createCameraFrameProcessor(() => "ok", { fps: 30 });
  const session = new camera.WebCameraSessionController({
    previewMode: "native",
    frameProcessor: processor,
    onError: (e: unknown) => errors.push(e),
  });
  (session as any).bindings = makeBindings();
  (session as any).started = true;
  await (session as any).frameProcessorRuntime.updateProcessor(processor);

  // Loop is running (token set), then the session is stopped.
  (session as any).scheduleNextFrame();
  expect((session as any).frameLoopToken).not.toBeNull();
  await (session as any).stopSession();
  expect((session as any).frameLoopToken).toBeNull();

  // A frame that was already in flight resumes after teardown.
  await (session as any).handleFrame(2000);

  expect((session as any).frameLoopToken).toBeNull(); // no resurrection
  expect(errors).toHaveLength(0); // no processor/failed spam on a stopped session
});

// ---------------------------------------------------------------------------
// Finding 4 — cloned recorder tracks are released instead of leaking.
// ---------------------------------------------------------------------------

test("finding 4: codec-unsupported path stops the cloned camera tracks immediately", async () => {
  FakeMediaRecorder.supported = false;
  const session = new camera.WebCameraSessionController({ previewMode: "native", video: true });
  const preview = new FakeMediaStream([new FakeTrack("video")]);
  (session as any).mediaStream = preview;

  const recorder = await (session as any).createRecorder({});
  expect(recorder).toBeNull();
  expect(preview.lastClone).not.toBeNull();
  expect(preview.lastClone!.getTracks().every((t) => t.stopped)).toBe(true);
  // The live preview stream itself must stay untouched.
  expect(preview.getTracks().every((t) => t.stopped)).toBe(false);
  FakeMediaRecorder.supported = true;
});

test("finding 4: stopSession releases a lingering recorder source clone", async () => {
  const session = new camera.WebCameraSessionController({ previewMode: "native", video: true });
  const clone = new FakeMediaStream([new FakeTrack("video")]);
  (session as any).currentRecorderSource = clone;

  await (session as any).stopSession();

  expect(clone.getTracks().every((t) => t.stopped)).toBe(true);
  expect((session as any).currentRecorderSource).toBeNull();
});

test("finding 4: a full record/stop cycle stops the cloned camera tracks", async () => {
  FakeMediaRecorder.supported = true;
  const session = new camera.WebCameraSessionController({ previewMode: "native", video: true });
  (session as any).bindings = makeBindings();
  const preview = new FakeMediaStream([new FakeTrack("video")]);
  (session as any).mediaStream = preview;

  await session.startRecording({});
  const clone = preview.lastClone!;
  expect(clone).not.toBeNull();
  expect((session as any).currentRecorderSource).toBe(clone);
  expect(clone.getTracks().every((t) => t.stopped)).toBe(false);

  await session.stopRecording();

  expect(clone.getTracks().every((t) => t.stopped)).toBe(true);
  expect((session as any).currentRecorderSource).toBeNull();
  expect(preview.getTracks().every((t) => t.stopped)).toBe(false); // preview survives
});
