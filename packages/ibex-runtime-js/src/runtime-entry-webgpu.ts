/**
 * Deferred WebGPU activation entry.
 *
 * This graph is embedded only by `webgpu-binding` builds and evaluated by the
 * owner-thread activation transaction. It deliberately installs no ordinary
 * runtime globals and carries no independently reachable native authority.
 */

import { installNativeGpuBridgeCapture } from './webgpu/runtime-internal';

// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam — native
// evaluates this trusted artifact only while all user/debugger ingress is
// excluded, then immediately consumes and proves this handoff absent.
installNativeGpuBridgeCapture(globalThis);
