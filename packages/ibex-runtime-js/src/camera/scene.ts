export interface SceneRectLike {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface SceneBarcodeLike {
  type: string;
  data: string;
  bounds: SceneRectLike;
}

export interface SceneFaceLike {
  bounds: SceneRectLike;
}

export interface SceneTextLike {
  value: string;
  bounds: SceneRectLike;
}

export interface SceneObjectLike {
  label: string;
  bounds: SceneRectLike;
  confidence: number;
}

function clamp01(value: number): number {
  return Math.min(1, Math.max(0, value));
}

function clampSceneRect(rect: SceneRectLike): SceneRectLike {
  const x = clamp01(rect.x);
  const y = clamp01(rect.y);
  const right = clamp01(rect.x + Math.max(0, rect.width));
  const bottom = clamp01(rect.y + Math.max(0, rect.height));
  return {
    x,
    y,
    width: Math.max(0, right - x),
    height: Math.max(0, bottom - y),
  };
}

function sceneRectArea(rect: SceneRectLike): number {
  return Math.max(0, rect.width) * Math.max(0, rect.height);
}

function unionSceneRects(rects: SceneRectLike[]): SceneRectLike {
  const clamped = rects.map(clampSceneRect);
  const minX = Math.min(...clamped.map((rect) => rect.x));
  const minY = Math.min(...clamped.map((rect) => rect.y));
  const maxX = Math.max(...clamped.map((rect) => rect.x + rect.width));
  const maxY = Math.max(...clamped.map((rect) => rect.y + rect.height));
  return clampSceneRect({
    x: minX,
    y: minY,
    width: maxX - minX,
    height: maxY - minY,
  });
}

function sceneRectIntersectionArea(a: SceneRectLike, b: SceneRectLike): number {
  const left = Math.max(a.x, b.x);
  const top = Math.max(a.y, b.y);
  const right = Math.min(a.x + a.width, b.x + b.width);
  const bottom = Math.min(a.y + a.height, b.y + b.height);
  return Math.max(0, right - left) * Math.max(0, bottom - top);
}

function sceneRectIou(a: SceneRectLike, b: SceneRectLike): number {
  const intersection = sceneRectIntersectionArea(a, b);
  if (intersection === 0) {
    return 0;
  }
  const union = sceneRectArea(a) + sceneRectArea(b) - intersection;
  return union <= 0 ? 0 : intersection / union;
}

function sceneRectOverlapRatio(a: SceneRectLike, b: SceneRectLike): number {
  const intersection = sceneRectIntersectionArea(a, b);
  if (intersection === 0) {
    return 0;
  }
  const smallerArea = Math.min(sceneRectArea(a), sceneRectArea(b));
  return smallerArea <= 0 ? 0 : intersection / smallerArea;
}

function mergeSceneObjects(candidates: SceneObjectLike[]): SceneObjectLike[] {
  const merged: SceneObjectLike[] = [];
  // Normalize and sort first so downstream merges keep the highest-confidence
  // label/bounds pair when multiple detectors describe the same real-world
  // subject (for example OCR + rectangle detection both finding a document).
  const sorted = candidates
    .map((candidate) => ({
      ...candidate,
      bounds: clampSceneRect(candidate.bounds),
      confidence: clamp01(candidate.confidence),
    }))
    .filter((candidate) => sceneRectArea(candidate.bounds) > 0)
    .sort((left, right) => right.confidence - left.confidence);

  for (const candidate of sorted) {
    const existing = merged.find((entry) => {
      if (entry.label !== candidate.label) {
        return false;
      }
      return (
        sceneRectIou(entry.bounds, candidate.bounds) >= 0.4 ||
        sceneRectOverlapRatio(entry.bounds, candidate.bounds) >= 0.8
      );
    });
    if (existing) {
      existing.bounds = unionSceneRects([existing.bounds, candidate.bounds]);
      existing.confidence = Math.max(existing.confidence, candidate.confidence);
      continue;
    }
    merged.push(candidate);
  }

  return merged;
}

function buildDocumentCandidatesFromText(text: SceneTextLike[]): SceneObjectLike[] {
  const candidates = text.filter((entry) => entry.value.trim().length > 0);
  if (candidates.length === 0) {
    return [];
  }

  const rects = candidates.map((entry) => clampSceneRect(entry.bounds));
  const union = unionSceneRects(rects);
  const totalArea = rects.reduce((sum, rect) => sum + sceneRectArea(rect), 0);
  // Treat dense or large text blocks as a document-like region. Small, isolated
  // snippets stay labeled as plain text so agent consumers can distinguish a
  // button label from a full sheet of paper.
  const looksLikeDocument =
    candidates.length > 1 || union.width >= 0.35 || union.height >= 0.28 || totalArea >= 0.08;

  if (looksLikeDocument) {
    return [
      {
        label: "document",
        bounds: union,
        confidence: candidates.length > 1 ? 0.72 : 0.64,
      },
    ];
  }

  return candidates.map((entry) => ({
    label: "text",
    bounds: clampSceneRect(entry.bounds),
    confidence: 0.58,
  }));
}

export function deriveSceneObjectsFromSignals(input: {
  barcodes?: SceneBarcodeLike[] | null;
  faces?: SceneFaceLike[] | null;
  text?: SceneTextLike[] | null;
  documentBounds?: SceneRectLike[] | null;
}): SceneObjectLike[] {
  const candidates: SceneObjectLike[] = [];

  // The public `objects` surface is intentionally derived from the detector
  // signals we already have. That keeps the API useful on platforms that lack
  // a dedicated generic object detector while still reporting bounded subjects
  // like people, documents, and barcodes in a stable way.
  for (const barcode of input.barcodes ?? []) {
    candidates.push({
      label: "barcode",
      bounds: barcode.bounds,
      confidence: 0.94,
    });
  }

  for (const face of input.faces ?? []) {
    candidates.push({
      label: "person",
      bounds: face.bounds,
      confidence: 0.86,
    });
  }

  for (const bounds of input.documentBounds ?? []) {
    candidates.push({
      label: "document",
      bounds,
      confidence: 0.7,
    });
  }

  candidates.push(...buildDocumentCandidatesFromText(input.text ?? []));
  return mergeSceneObjects(candidates);
}
