/**
 * Regression tests for the ENG-23139 web-camera audit (packages/ibex-runtime-js/src/camera).
 *
 * Round-3 lifecycle/leak findings on top of the ENG-22978 fixes: frame-loop
 * multiplication on reconfigure, cancelRecording leaking the recording via an
 * unrevoked object URL, concurrent session start leaking a live camera stream,
 * web maxDuration being ignored, the rolling retroactive buffer trimming to a
 * stale window, spurious processor/failed on live processor swaps, and the
 * recorder/worker edge latches. As in the ENG-22978 suite, the DOM/media
 * surface is mocked just enough to drive the affected code paths; each test is
 * written so it fails on the pre-fix behaviour and passes on the fix.
 */

import { beforeAll, expect, test } from "bun:test";

// ---------------------------------------------------------------------------
// Minimal browser/media mocks (module top-level so they exist before the
// dynamically imported camera module constructs any canvas).
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
  width = 300;
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
  static failStart = false;
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
    if (FakeMediaRecorder.failStart) {
      throw new Error("start failed");
    }
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

// Worker mock with a controllable reply mode: with autoReply on it echoes a
// result per frame (like the ENG-22978 suite); with it off, frames stay
// in flight so teardown/swap races can be driven deterministically.
class FakeWorker {
  static autoReply = true;
  static instances: FakeWorker[] = [];
  onmessage: ((e: { data: unknown }) => void) | null = null;
  onerror: ((e: { message?: string }) => void) | null = null;
  onmessageerror: (() => void) | null = null;
  terminated = false;
  constructor(_url: unknown, _opts?: unknown) {
    FakeWorker.instances.push(this);
  }
  postMessage(message: any, _transfer?: unknown[]) {
    if (message?.type === "frame" && FakeWorker.autoReply) {
      queueMicrotask(() => {
        this.onmessage?.({ data: { type: "result", id: message.id, result: "ok" } });
      });
    }
  }
  terminate() {
    this.terminated = true;
  }
}

// Controllable requestAnimationFrame queue: callbacks are held until the test
// fires them, so the number of live frame-loop chains is directly observable.
const rafCallbacks = new Map<number, (time: number) => void>();
let rafIdCounter = 0;

function fireNextRaf(time = performance.now()) {
  const next = rafCallbacks.entries().next();
  if (next.done) {
    throw new Error("no rAF callback pending");
  }
  const [id, callback] = next.value;
  rafCallbacks.delete(id);
  callback(time);
}

async function settle() {
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

const g = globalThis as any;
g.document = { createElement: () => new FakeCanvas() };
g.Worker = FakeWorker;
g.MediaRecorder = FakeMediaRecorder;
g.ImageData = class {
  constructor(public data: unknown, public width: number, public height: number) {}
};
g.requestAnimationFrame = (cb: (t: number) => void) => {
  rafIdCounter += 1;
  rafCallbacks.set(rafIdCounter, cb);
  return rafIdCounter;
};
g.cancelAnimationFrame = (id: number) => {
  rafCallbacks.delete(id);
};

// Counting object-URL stub: the camera module never revokes result URLs, so a
// URL minted for a discarded recording is a permanent leak (finding 2).
let objectUrlCalls = 0;
(URL as any).createObjectURL = (_blob: Blob) => {
  objectUrlCalls += 1;
  return `blob:fake-${objectUrlCalls}`;
};

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
// Finding: syncFramePipeline during an in-flight frame must not start a
// second self-perpetuating frame loop.
// ---------------------------------------------------------------------------

test("reconfigure during an in-flight frame does not multiply the frame loop", async () => {
  rafCallbacks.clear();
  const errors: unknown[] = [];
  const processor = camera.createCameraFrameProcessor(() => "ok", { fps: 1000 });
  const session = new camera.WebCameraSessionController({
    previewMode: "native",
    frameProcessor: processor,
    onError: (e: unknown) => errors.push(e),
  });
  (session as any).bindings = makeBindings();
  (session as any).started = true;
  await (session as any).frameProcessorRuntime.updateProcessor(processor);

  await (session as any).syncFramePipeline();
  expect(rafCallbacks.size).toBe(1); // one chain armed

  // A frame goes in flight (the schedule callback nulls the token before the
  // async handleFrame settles) ...
  fireNextRaf(1000);
  // ... and a lifecycle sync lands mid-frame, exactly like updateOptions with
  // a mirror/resizeMode/processor change does.
  const midFrameSync = (session as any).syncFramePipeline();
  await midFrameSync;
  await settle();

  // Exactly one chain must survive: the in-flight frame's continuation.
  // Pre-fix the mid-frame sync armed a second chain (2 pending callbacks).
  expect(rafCallbacks.size).toBe(1);

  // And it stays single across further rounds instead of compounding.
  fireNextRaf(2000);
  await settle();
  expect(rafCallbacks.size).toBe(1);

  expect(errors).toHaveLength(0);
  await (session as any).stopSession();
  expect(rafCallbacks.size).toBe(0); // stop kills the loop outright
});

// ---------------------------------------------------------------------------
// Finding: cancelRecording must not build (and leak) the recording result.
// ---------------------------------------------------------------------------

test("cancelRecording discards without minting an object URL for the recording", async () => {
  const finished: unknown[] = [];
  const session = new camera.WebCameraSessionController({ previewMode: "native", video: true });
  (session as any).bindings = makeBindings();
  const preview = new FakeMediaStream([new FakeTrack("video")]);
  (session as any).mediaStream = preview;

  try {
    await session.startRecording({ onFinished: (video: unknown) => finished.push(video) });
    (session as any).currentRecorder.ondataavailable({ data: new Blob(["recorded-chunk"]) });

    const urlsBefore = objectUrlCalls;
    await session.cancelRecording();

    expect(objectUrlCalls).toBe(urlsBefore); // no URL -> nothing pinned forever
    expect(finished).toHaveLength(0);
    expect((session as any).recordingState).toBe("inactive");
    expect((session as any).discardNextRecording).toBe(false);
    expect((session as any).currentRecordingChunks).toHaveLength(0);
    // A follow-up recording still completes and delivers a result.
    await session.startRecording({ onFinished: (video: unknown) => finished.push(video) });
    await session.stopRecording();
    expect(finished).toHaveLength(1);
  } finally {
    // A failed expect must not leave the progress interval running (it keeps
    // the bun process alive after the run).
    await (session as any).stopSession();
  }
});

// ---------------------------------------------------------------------------
// Finding: a capture-path session start must serialize with the lifecycle
// queue instead of racing a queued start and orphaning a live stream.
// ---------------------------------------------------------------------------

test("concurrent capture-path start does not open (and leak) a second camera stream", async () => {
  // The admission check counts every registered active session; drop the ones
  // accumulated by earlier tests in this process so this session stands alone.
  for (const snapshot of camera.listActiveCameraSessions()) {
    camera.unregisterCameraAgentSession(snapshot.id);
  }

  const session = new camera.WebCameraSessionController({ previewMode: "native" });
  (session as any).bindings = makeBindings();

  const createdStreams: FakeMediaStream[] = [];
  let createCalls = 0;
  (session as any).createPreviewStream = async () => {
    createCalls += 1;
    await new Promise<void>((resolve) => setTimeout(resolve, 5)); // getUserMedia latency
    const stream = new FakeMediaStream([new FakeTrack("video")]);
    createdStreams.push(stream);
    return stream;
  };

  // The attach()-queued start and a capture call racing it right after mount.
  const queuedStart = (session as any).enqueueLifecycle(() => (session as any).startSession());
  const captureStart = (session as any).ensureSensorBufferFresh();
  await Promise.all([queuedStart, captureStart]);

  expect((session as any).started).toBe(true);
  expect(createCalls).toBe(1); // pre-fix: 2 overlapping getUserMedia calls
  const liveStreams = createdStreams.filter((stream) =>
    stream.getTracks().some((track) => !track.stopped),
  );
  expect(liveStreams).toHaveLength(1); // pre-fix: the loser's stream stays live forever
  expect((session as any).mediaStream).toBe(liveStreams[0]);

  await (session as any).stopSession();
  expect(createdStreams.every((s) => s.getTracks().every((t) => t.stopped))).toBe(true);
});

// ---------------------------------------------------------------------------
// Finding: web recordings must honor maxDuration.
// ---------------------------------------------------------------------------

test("startRecording auto-stops after maxDuration on web", async () => {
  const finished: unknown[] = [];
  const session = new camera.WebCameraSessionController({ previewMode: "native", video: true });
  (session as any).bindings = makeBindings();
  (session as any).mediaStream = new FakeMediaStream([new FakeTrack("video")]);

  try {
    await session.startRecording({
      maxDuration: 0.03, // seconds
      onFinished: (video: unknown) => finished.push(video),
    });
    expect((session as any).recordingState).toBe("recording");

    await new Promise<void>((resolve) => setTimeout(resolve, 80));

    expect((session as any).recordingState).toBe("inactive"); // pre-fix: still recording
    expect(finished).toHaveLength(1);
    expect((session as any).maxDurationTimer).toBeNull();
  } finally {
    await (session as any).stopSession();
  }
});

test("manual stop before the deadline clears the maxDuration timer", async () => {
  const session = new camera.WebCameraSessionController({ previewMode: "native", video: true });
  (session as any).bindings = makeBindings();
  (session as any).mediaStream = new FakeMediaStream([new FakeTrack("video")]);

  try {
    await session.startRecording({ maxDuration: 5 });
    expect((session as any).maxDurationTimer).not.toBeNull();
    await session.stopRecording();
    expect((session as any).maxDurationTimer).toBeNull();
  } finally {
    await (session as any).stopSession();
  }
});

// ---------------------------------------------------------------------------
// Finding: the rolling retroactive buffer must trim against the live option.
// ---------------------------------------------------------------------------

test("raising retroactiveBuffer widens the rolling trim window without a restart", async () => {
  const session = new camera.WebCameraSessionController({
    previewMode: "native",
    retroactiveBuffer: 10,
  });
  (session as any).mediaStream = new FakeMediaStream([new FakeTrack("video")]);

  await (session as any).ensureRollingRecorder();
  const recorder = (session as any).rollingRecorder;
  expect(recorder).not.toBeNull();

  recorder.ondataavailable({ data: new Blob(["pre-roll"]) });
  expect((session as any).rollingChunks).toHaveLength(1);
  // Age the chunk to 20s: inside a 30s window, outside the original 10s one.
  (session as any).rollingChunks[0].timestamp = Date.now() - 20_000;

  (session as any).options.retroactiveBuffer = 30;
  recorder.ondataavailable({ data: new Blob(["fresh"]) });

  // Pre-fix the closure trimmed with the captured 10s and dropped the old chunk.
  expect((session as any).rollingChunks).toHaveLength(2);

  await (session as any).stopSession();
});

// ---------------------------------------------------------------------------
// Finding: a live processor swap/removal must not surface processor/failed
// for the superseded pipeline's in-flight frame.
// ---------------------------------------------------------------------------

test("swapping the frame processor mid-frame stays silent and leaves no lastError", async () => {
  rafCallbacks.clear();
  const errors: unknown[] = [];
  const processorA = camera.createCameraFrameProcessor(() => "a", { fps: 1000 });
  const processorB = camera.createCameraFrameProcessor(() => "b", { fps: 1000 });
  const session = new camera.WebCameraSessionController({
    previewMode: "native",
    frameProcessor: processorA,
    onError: (e: unknown) => errors.push(e),
  });
  (session as any).bindings = makeBindings();
  (session as any).started = true;
  await (session as any).frameProcessorRuntime.updateProcessor(processorA);

  FakeWorker.autoReply = false;
  try {
    const inFlightFrame = (session as any).handleFrame(1000);
    await settle(); // let the frame reach (and suspend inside) the worker await
    await (session as any).frameProcessorRuntime.updateProcessor(processorB); // rejects it
    await inFlightFrame;
  } finally {
    FakeWorker.autoReply = true;
  }

  expect(errors).toHaveLength(0); // pre-fix: processor/failed
  expect((session as any).lastError).toBeNull(); // pre-fix: 0.35 readiness penalty latched
  await (session as any).stopSession();
});

test("a clean frame clears a latched processor/failed lastError", async () => {
  rafCallbacks.clear();
  const processor = camera.createCameraFrameProcessor(() => "ok", { fps: 1000 });
  const session = new camera.WebCameraSessionController({
    previewMode: "native",
    frameProcessor: processor,
  });
  (session as any).bindings = makeBindings();
  (session as any).started = true;
  await (session as any).frameProcessorRuntime.updateProcessor(processor);

  (session as any).lastError = {
    code: "processor/failed",
    message: "earlier failure",
    recoverable: true,
  };

  await (session as any).handleFrame(1000);

  expect((session as any).lastError).toBeNull();
  await (session as any).stopSession();
});

// ---------------------------------------------------------------------------
// Finding (latches): recorder.start() throwing must roll the state back.
// ---------------------------------------------------------------------------

test("recorder.start() throwing rolls back recording state and releases the clone", async () => {
  const session = new camera.WebCameraSessionController({ previewMode: "native", video: true });
  (session as any).bindings = makeBindings();
  const preview = new FakeMediaStream([new FakeTrack("video")]);
  (session as any).mediaStream = preview;

  try {
    FakeMediaRecorder.failStart = true;
    try {
      await expect(session.startRecording({})).rejects.toThrow("start failed");
    } finally {
      FakeMediaRecorder.failStart = false;
    }

    expect((session as any).recordingState).toBe("inactive"); // pre-fix: latched "recording"
    expect((session as any).currentRecorder).toBeNull();
    expect(preview.lastClone!.getTracks().every((t) => t.stopped)).toBe(true);
    expect(preview.getTracks().every((t) => t.stopped)).toBe(false); // preview untouched

    // The controller is not wedged: the next recording works end to end.
    await session.startRecording({});
    expect((session as any).recordingState).toBe("recording");
    await session.stopRecording();
    expect((session as any).recordingState).toBe("inactive");
  } finally {
    await (session as any).stopSession();
  }
});

// ---------------------------------------------------------------------------
// Finding (latches): a worker that fails to load must settle pending requests.
// ---------------------------------------------------------------------------

test("worker.onerror rejects the pending frame with the real error and drops the worker", async () => {
  const processor = camera.createCameraFrameProcessor(() => "ok", { fps: 30 });
  const session = new camera.WebCameraSessionController({
    previewMode: "native",
    frameProcessor: processor,
  });
  const runtime = (session as any).frameProcessorRuntime;

  FakeWorker.autoReply = false;
  try {
    await runtime.updateProcessor(processor);
    const worker = FakeWorker.instances[FakeWorker.instances.length - 1]!;
    const pendingFrame = runtime.processFrame({
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
    });

    worker.onerror?.({ message: "script load failed" });

    // Pre-fix: no onerror handler -> this promise never settles and
    // processingBusy latches the processor dead.
    await expect(pendingFrame).rejects.toThrow(/script load failed/);
    expect(runtime.active).toBe(false);
    expect(worker.terminated).toBe(true);
  } finally {
    FakeWorker.autoReply = true;
  }
});

// ---------------------------------------------------------------------------
// Finding (latches): takePhoto must report the real photo dimensions for
// full-resolution ImageCapture photos, not the preview canvas size.
// ---------------------------------------------------------------------------

test("takePhoto reports the decoded blob dimensions for track photos", async () => {
  const previousImageCapture = g.ImageCapture;
  const previousCreateImageBitmap = g.createImageBitmap;
  g.ImageCapture = class {
    constructor(_track: unknown) {}
    takePhoto() {
      return Promise.resolve(new Blob(["full-res-photo"]));
    }
  };
  g.createImageBitmap = async (_blob: Blob) => ({
    width: 4032,
    height: 3024,
    close() {},
  });

  try {
    const session = new camera.WebCameraSessionController({ previewMode: "native" });
    (session as any).bindings = makeBindings();
    (session as any).started = true;
    (session as any).mediaStream = new FakeMediaStream([new FakeTrack("video")]);

    const photo = await session.takePhoto({});
    expect(photo.width).toBe(4032); // pre-fix: 64 (preview canvas width)
    expect(photo.height).toBe(3024);
  } finally {
    g.ImageCapture = previousImageCapture;
    g.createImageBitmap = previousCreateImageBitmap;
  }
});
