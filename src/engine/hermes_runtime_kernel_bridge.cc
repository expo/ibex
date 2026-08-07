// Compile the app-host kernel bridge as its own static-archive member.
//
// @ref LLP 0003#app-host-kernel-bridge-is-a-separate-archive-member — standalone
// executables must not acquire the embedder's Rust-kernel symbols merely by
// using the ordinary dispatch and module-event callbacks.
#define IBEX_KERNEL_BRIDGE_OBJECT 1
#include "hermes_runtime_ios.cc"
