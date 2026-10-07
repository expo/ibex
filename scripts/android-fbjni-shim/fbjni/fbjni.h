// A stand-in for fbjni's header, for Hermes built into a native Android
// process with no JVM (Ibex's aarch64-linux-android bundle). Hermes's
// API/hermes/hermes.cpp includes <fbjni/fbjni.h> under __ANDROID__ only to
// attach its JSI finalizer thread to the JVM with facebook::jni::ThreadScope,
// because finalizers may release JNI references. An embedder whose JavaScript
// holds no JNI references has nothing to attach for, and a real ThreadScope
// throws where no JavaVM exists. This keeps the Hermes source unmodified.
#pragma once

namespace facebook {
namespace jni {

class ThreadScope {
 public:
  ThreadScope() = default;
  ThreadScope(const ThreadScope &) = delete;
  ThreadScope &operator=(const ThreadScope &) = delete;
};

} // namespace jni
} // namespace facebook
