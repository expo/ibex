import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "bun:test";
import {
  joinAndroidBridgeImplementationRefs,
  scanAndroidCppBridgeBindings,
  scanAndroidJavaBridgeSurfaces,
} from "./capsec-android-bridge-inventory.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);

describe("Android Java bridge inventory", () => {
  test("provider overloads fail instead of collapsing into one surface", () => {
    expect(() =>
      scanAndroidJavaBridgeSurfaces(
        `
          package dev.ibex.runtime;
          public final class IbexNetworking {
            public interface Provider {
              String acquire(String resource);
              String acquire(int resource);
            }
            public static void fetch(String url) {}
            private static native void nativeComplete(int id);
          }
        `,
        "synthetic.java",
      ),
    ).toThrow(/overloaded or duplicate Android bridge surface/);
  });
  test("is structural and excludes comments, literals, and nested overrides", () => {
    const rows = scanAndroidJavaBridgeSurfaces(
      `
        package dev.ibex.runtime;
        public final class IbexNetworking {
          // public static void fakeComment() {}
          private static final String FAKE = "public static void fakeString() {}";
          public interface Provider {
            String acquire(String resource) throws Exception;
          }
          public static void fetch(String url) {
            Runnable callback = new Runnable() {
              public void run() {}
            };
          }
          private static native void nativeComplete(int id);
        }
      `,
      "synthetic.java",
    );
    expect(rows.map((row) => row.name)).toEqual([
      "java:dev.ibex.runtime.IbexNetworking.Provider.acquire",
      "java:dev.ibex.runtime.IbexNetworking.fetch",
      "jni:dev.ibex.runtime.IbexNetworking.nativeComplete",
    ]);
    expect(
      rows.find((row) => row.name.endsWith(".Provider.acquire")).metadata
        .javaSignature,
    ).toEqual({
      parameters: [{ kind: "aggregate", type: "String" }],
      returnType: { kind: "aggregate", type: "String" },
    });
    expect(
      rows.find((row) => row.name.endsWith(".nativeComplete")).metadata
        .javaSignature,
    ).toEqual({
      parameters: [{ kind: "scalar", type: "int" }],
      returnType: { kind: "void", type: "void" },
    });
  });

  test("discovers the live public, provider, and JNI routes", () => {
    const sourcePath =
      "platform/android/java/dev/ibex/runtime/IbexNetworking.java";
    const rows = scanAndroidJavaBridgeSurfaces(
      fs.readFileSync(path.join(repoRoot, sourcePath), "utf8"),
      sourcePath,
    );
    expect(rows).toEqual(
      [...rows].sort((left, right) =>
        left.observedKey < right.observedKey
          ? -1
          : left.observedKey > right.observedKey
            ? 1
            : 0,
      ),
    );
    expect(rows.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "java:dev.ibex.runtime.IbexNetworking.CameraHostProvider.cameraHostCall",
        "java:dev.ibex.runtime.IbexNetworking.DialogHostProvider.dialog",
        "java:dev.ibex.runtime.IbexNetworking.fetch",
        "java:dev.ibex.runtime.IbexNetworking.connectWebSocket",
        "java:dev.ibex.runtime.IbexNetworking.dnsQuery",
        "java:dev.ibex.runtime.IbexNetworking.clipboardReadText",
        "java:dev.ibex.runtime.IbexNetworking.getCurrentLocation",
        "java:dev.ibex.runtime.IbexNetworking.notifyDeepLink",
        "jni:dev.ibex.runtime.IbexNetworking.nativeFetchDidComplete",
        "jni:dev.ibex.runtime.IbexNetworking.nativePlatformEventAvailable",
        "jni:dev.ibex.runtime.IbexNetworking.nativeAnimationFrame",
      ]),
    );
    expect(rows.some((row) => row.name.endsWith(".onResponse"))).toBe(false);
    expect(
      rows.filter(
        (row) => row.metadata.bridgeRole === "java-to-native-callback",
      ),
    ).toHaveLength(8);
    for (const row of rows) {
      expect(row.sourceRefs).toEqual([`${sourcePath}#${row.name}`]);
      expect(row.metadata.targetVariant).toBe("android");
    }
  });

  test("fails closed on overloads", () => {
    expect(() =>
      scanAndroidJavaBridgeSurfaces(
        `
          package dev.ibex.runtime;
          public final class IbexNetworking {
            public static void fetch(String url) {}
            public static void fetch(int id) {}
            private static native void nativeComplete();
          }
        `,
        "overload.java",
      ),
    ).toThrow(/overloaded or duplicate Android bridge surface/u);
  });

  test("joins every live JNI declaration and cached Java route to C++ evidence", () => {
    const javaPath =
      "platform/android/java/dev/ibex/runtime/IbexNetworking.java";
    const cppPath = "src/engine/native_android_networking.cc";
    const javaRows = scanAndroidJavaBridgeSurfaces(
      fs.readFileSync(path.join(repoRoot, javaPath), "utf8"),
      javaPath,
    );
    const bindings = scanAndroidCppBridgeBindings(
      fs.readFileSync(path.join(repoRoot, cppPath), "utf8"),
      cppPath,
    );
    const joined = joinAndroidBridgeImplementationRefs(
      javaRows,
      bindings,
      cppPath,
    );

    expect([...bindings.nativeCallbacks.keys()].sort()).toEqual([
      "nativeAnimationFrame",
      "nativeFetchDidComplete",
      "nativePlatformEventAvailable",
      "nativeWebSocketDidBytesSent",
      "nativeWebSocketDidClose",
      "nativeWebSocketDidError",
      "nativeWebSocketDidMessage",
      "nativeWebSocketDidOpen",
    ]);
    expect(bindings.staticMethods.has("fetch")).toBe(true);
    expect(bindings.staticMethods.has("cameraHostCall")).toBe(true);
    expect(
      joined.find((row) => row.name.endsWith(".nativeFetchDidComplete"))
        .sourceRefs,
    ).toEqual(
      expect.arrayContaining([
        `${cppPath}#jni-callback:nativeFetchDidComplete:android_fetch_did_complete`,
        `${javaPath}#jni:dev.ibex.runtime.IbexNetworking.nativeFetchDidComplete`,
      ]),
    );
    expect(
      joined.find((row) => row.name.endsWith(".fetch")).sourceRefs,
    ).toEqual(
      expect.arrayContaining([
        `${cppPath}#java-call:fetch:fetch`,
        `${javaPath}#java:dev.ibex.runtime.IbexNetworking.fetch`,
      ]),
    );
  });
});
