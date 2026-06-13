const activeAnimationFrames = new Set<number>();
let lastAnimationActivityAt = 0;

function currentTimestamp(): number {
  return Date.now();
}

export function trackAnimationFrameRequested(id: number): void {
  activeAnimationFrames.add(id);
  lastAnimationActivityAt = currentTimestamp();
}

export function trackAnimationFrameCancelled(id: number): void {
  if (activeAnimationFrames.delete(id)) {
    lastAnimationActivityAt = currentTimestamp();
  }
}

export function trackAnimationFrameExecuted(ids: number[]): void {
  let changed = false;
  for (const id of ids) {
    changed = activeAnimationFrames.delete(id) || changed;
  }
  if (changed) {
    lastAnimationActivityAt = currentTimestamp();
  }
}

export function getAnimationTrackingState(): {
  activeCount: number;
  lastActivityAt: number;
} {
  return {
    activeCount: activeAnimationFrames.size,
    lastActivityAt: lastAnimationActivityAt,
  };
}
