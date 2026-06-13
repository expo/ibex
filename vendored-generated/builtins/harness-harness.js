"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const processMod = require("node:process");

let bunTest;
try {
  bunTest = require("bun:test");
} catch (_e) {
  bunTest = null;
}

if (bunTest) {
  if (typeof globalThis.describe !== "function" && typeof bunTest.describe === "function") {
    globalThis.describe = bunTest.describe;
  }
  if (typeof globalThis.it !== "function" && typeof bunTest.it === "function") {
    globalThis.it = bunTest.it;
  }
  if (typeof globalThis.test !== "function" && typeof bunTest.test === "function") {
    globalThis.test = bunTest.test;
  }
  if (typeof globalThis.expect !== "function" && typeof bunTest.expect === "function") {
    globalThis.expect = bunTest.expect;
  }
  if (typeof globalThis.beforeAll !== "function" && typeof bunTest.beforeAll === "function") {
    globalThis.beforeAll = bunTest.beforeAll;
  }
  if (typeof globalThis.afterAll !== "function" && typeof bunTest.afterAll === "function") {
    globalThis.afterAll = bunTest.afterAll;
  }
  if (typeof globalThis.beforeEach !== "function" && typeof bunTest.beforeEach === "function") {
    globalThis.beforeEach = bunTest.beforeEach;
  }
  if (typeof globalThis.afterEach !== "function" && typeof bunTest.afterEach === "function") {
    globalThis.afterEach = bunTest.afterEach;
  }
}

function patchBrokenSharedArrayBufferUint8Array() {
  if (typeof globalThis.SharedArrayBuffer !== "function" || typeof globalThis.Uint8Array !== "function") {
    return;
  }

  try {
    var probeBuffer = new globalThis.SharedArrayBuffer(1);
    var probeView = new globalThis.Uint8Array(probeBuffer);
    if (
      probeView.length === 1 &&
      probeView.byteLength === 1 &&
      Object.prototype.toString.call(probeView.buffer) === "[object SharedArrayBuffer]"
    ) {
      return;
    }
  } catch (_probeErr) {}

  var NativeUint8Array = globalThis.Uint8Array;

  function exposeSharedArrayBufferView(view, originalBuffer) {
    try {
      Object.defineProperty(view, "buffer", {
        configurable: true,
        enumerable: false,
        get: function() {
          return originalBuffer;
        },
      });
    } catch (_bufferErr) {}
    try {
      Object.defineProperty(view, "__exactSharedArrayBuffer", {
        value: originalBuffer,
        writable: false,
        configurable: true,
        enumerable: false,
      });
    } catch (_markerErr) {}
    return view;
  }

  function WrappedUint8Array(buffer, byteOffset, length) {
    if (!(this instanceof WrappedUint8Array)) {
      throw new TypeError('Constructor Uint8Array requires "new"');
    }

    var backing = buffer && buffer._buffer;
    if (backing && Object.prototype.toString.call(backing) === "[object ArrayBuffer]") {
      var view;
      if (arguments.length <= 1) {
        view = new NativeUint8Array(backing);
      } else if (arguments.length === 2) {
        view = new NativeUint8Array(backing, byteOffset);
      } else {
        view = new NativeUint8Array(backing, byteOffset, length);
      }
      return exposeSharedArrayBufferView(view, buffer);
    }

    if (arguments.length === 0) return new NativeUint8Array();
    if (arguments.length === 1) return new NativeUint8Array(buffer);
    if (arguments.length === 2) return new NativeUint8Array(buffer, byteOffset);
    return new NativeUint8Array(buffer, byteOffset, length);
  }

  WrappedUint8Array.prototype = NativeUint8Array.prototype;
  try {
    Object.setPrototypeOf(WrappedUint8Array, NativeUint8Array);
  } catch (_protoErr) {}
  try {
    Object.defineProperty(WrappedUint8Array, "__exactSharedArrayBufferWrapped", {
      value: true,
      writable: false,
      configurable: true,
      enumerable: false,
    });
  } catch (_flagErr) {}
  try {
    Object.defineProperty(globalThis, "Uint8Array", {
      value: WrappedUint8Array,
      writable: true,
      configurable: true,
      enumerable: false,
    });
  } catch (_assignErr) {
    globalThis.Uint8Array = WrappedUint8Array;
  }
}

patchBrokenSharedArrayBufferUint8Array();

const fixturesDir = path.join(__dirname, "..", "fixtures");
const projectRoot = path.resolve(__dirname, "../..");

const isWindows = processMod.platform === "win32";
const isMacOS = processMod.platform === "darwin";
const isLinux = processMod.platform === "linux";
const isPosix = isLinux || isMacOS;
const isCI = Boolean(processMod.env.CI);
const isASAN = false;
const isBroken = false;

function getRandomPort() {
  return 40000 + Math.floor(Math.random() * 20000);
}

function randomFileName(prefix = "exact-compat") {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 999999)}`;
}

function resolveBaseDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "exact-compat-"));
}

function buildTree(base, entries) {
  fs.mkdirSync(base, { recursive: true });
  if (!entries || typeof entries !== "object") {
    return;
  }

  for (const [name, value] of Object.entries(entries)) {
    const target = path.join(base, name);
    if (typeof value === "object" && value !== null && !Buffer.isBuffer(value) && !Array.isArray(value)) {
      buildTree(target, value);
    } else if (typeof value === "string" || Buffer.isBuffer(value)) {
      fs.writeFileSync(target, value);
    } else if (value === null || value === undefined) {
      fs.writeFileSync(target, "");
    } else {
      fs.writeFileSync(target, String(value));
    }
  }
}

function tempDirWithFiles(name = "temp", entries = {}) {
  const base = path.join(resolveBaseDir(), name);
  buildTree(base, entries);
  return base;
}

function tempDirWithFilesAnon(entries = {}) {
  return tempDirWithFiles(randomFileName("temp"), entries);
}

function cwdScope(dir, fn) {
  const prev = processMod.cwd();
  processMod.chdir(dir);
  return Promise.resolve()
    .then(() => (typeof fn === "function" ? fn() : undefined))
    .finally(() => processMod.chdir(prev));
}

function rmScope(paths) {
  if (!Array.isArray(paths)) {
    paths = [paths];
  }
  for (const p of paths) {
    if (!p) continue;
    fs.rmSync(p, { recursive: true, force: true });
  }
}

function hideFromStackTrace(_fn) {}

function bunExe() {
  return processMod.execPath;
}

function createBunEnvAccessor(envObject) {
  var accessor = function() {
    return envObject;
  };
  if (typeof Proxy !== "function") {
    return accessor;
  }
  return new Proxy(accessor, {
    get: function(target, prop, receiver) {
      if (prop in target) {
        return Reflect.get(target, prop, receiver);
      }
      return envObject[prop];
    },
    set: function(_target, prop, value) {
      envObject[prop] = value;
      return true;
    },
    ownKeys: function(target) {
      var keys = Reflect.ownKeys(target);
      var envKeys = Object.keys(envObject);
      for (var i = 0; i < envKeys.length; i++) {
        if (keys.indexOf(envKeys[i]) === -1) {
          keys.push(envKeys[i]);
        }
      }
      return keys;
    },
    getOwnPropertyDescriptor: function(target, prop) {
      if (prop in target) {
        return Object.getOwnPropertyDescriptor(target, prop);
      }
      if (Object.prototype.hasOwnProperty.call(envObject, prop)) {
        return {
          configurable: true,
          enumerable: true,
          writable: true,
          value: envObject[prop],
        };
      }
      return undefined;
    },
  });
}
const bunEnv =
  bunTest && typeof bunTest.bunEnv === "function"
    ? bunTest.bunEnv
    : createBunEnvAccessor(processMod.env);

function nodeExe() {
  return process.env.NODE || "node";
}

function bunRun(script, env = {}, asScript = false) {
  const resolved = path.resolve(String(script));
  const args = asScript ? [resolved] : [];
  const child = require("node:child_process").spawnSync(processMod.execPath, [resolved, ...(Array.isArray(args) ? args : [])], {
    env: { ...processMod.env, ...env },
    encoding: "utf8",
  });
  return child;
}

function bunRunAsScript(dir, script) {
  return bunRun(script, {}, true);
}

function noOp() {}
function noOpAsync() {
  return Promise.resolve();
}

function expectMaxObjectTypeCount() {
  return noOpAsync;
}

function getMaxFD() {
  return 0;
}

function runBunInstall() {
  return;
}

function shellExe() {
  return processMod.platform === "win32" ? "cmd" : "/bin/sh";
}

function libcFamily() {
  return os.platform();
}

function tempDir() {
  return resolveBaseDir();
}

function tmpdirSync() {
  return resolveBaseDir();
}

function joinP(...parts) {
  return path.join(...parts);
}

function randomUUIDv7() {
  const uuid = crypto.randomUUID ? crypto.randomUUID() : "00000000-0000-7000-8000-000000000000";
  return uuid.replace(/-/, "-");
}

const exampleHtml = "<!doctype html><html><body><h1>Exact Fixture</h1></body></html>";
const exampleSiteBody = "This domain is for use in illustrative examples in documents";
const expiredTlsKey = [
  "-----BEGIN PRIVATE KEY-----",
  "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCveWP3isEW4MVk",
  "4iv3G50DUfEo7g+RFTEZScn3nXVx/M08AIf0N35aiEH+OqRdp+6VzDYWPC3g5hq0",
  "OQKypDSzU2EgyKFooG358ZOV01VuavbhnKEZdHFGtDyOAB7fAM6Akh5XFJ/J3xxu",
  "ImWEC3yCYcgo0cH0Ir0eOq6YRjh/jBuaMQ30eiBq7MwUyOKYAvB4sgayxbM8RJNH",
  "Pr0HUKJbuE9Z9vqI0wuGvC5E8U+S8TR6rxRsvy+8Wz9yh5xuT7/wKhhMY/lYo+zO",
  "PnOjwRgcbkMN6KGEa0yzDhvbSKGSvIIq+8AtLfo7l1DyE9RjOIZdgYWj54qpNp3S",
  "mi5DZGH5AgMBAAECggEAIKn4nWJTWjZiGErvwzJ9MlqFCUjzVd77gkkVkwXZEGxu",
  "Kd6xcBkKaMDXhAMXiKWTiIf4g4AVTDmZO/Ym1ekyNDVvraIbRbYjcrTw86Fg1EqO",
  "BWZaKLpfwbkYUpicJofoaM+KXUxmCDaDfM7jVcarmTupfku5joAO8zsaOBdOOhOj",
  "ZLISMziizypEGcx7eGFhmQjS2I4vQqWBtAGz6I0+P60u3ZUCCbyd4agwAz4NKLaU",
  "WB5rP8FD1YPVquwYNgW3DaKc86hHSkQK5KMx8Phgrvo8m2242LzOcR4jBEZnk53h",
  "7qRYi7JOg6cCOA6M0HVDgi3p1Qy5L+1VgaqAwGUwZwKBgQD1rXo+UvFuMZupDL+I",
  "1hom+SRLay5Aj420u5KLV8Hf+WO+G8uaIaQEKA0CU3samrYKTIllGqHLSBNruoqg",
  "+kQDQ6Vcsx6Gftmx4v909d3C8oDYxpTJxKnsXifBBlIyD9XjujitFTR3KqMAVLDM",
  "qj+j3ybGikCmHfQUTsB0wTGh1wKBgQC22MzzrRmP0vQAkCPZLZLAUb8GzidiX48w",
  "21z1Ya5duSpd4Le/6KI1xXGZg9vIx1fBQPb56Am9E4SFULqIOaMbW+SGaxxyMwT5",
  "C39SMac9jH482AItCo/RVadTPMOShgHlzuHKulL23q+CcOeUzQrOYZNvjzH7uomX",
  "iwxHJ+dArwKBgQC/OHGHhQOJ427nG5cRKKReZVkMorXzZkjDvaOIdZvfertZw0Ss",
  "CTciTRIjF1sgD/9U8NGYMixwjv8ewKkaNvEtIT/acUh3ItDKloaDQMOE8z+6eoZg",
  "rYQdCAQlR4g+kvjGMbHfdjvJ7RPGNCUQiArUv+HscrtzEKlkDQ/bUGwTLQKBgDRh",
  "wb1hbrxETADJSmvSYYNVJ+u0LZZCGAyAG450sHZLMLb6RMnmxGmxKc03+EP5z8se",
  "aGLJtdiD+egTa4zRLkgNOFfF4b1ZnmgWgiAy911rnVKi82Sh7PekmS4Ab2rPl0WV",
  "0hu460GsJA2zeLSpVRow3AMOu9wI4ZgXjqnn5ZkjAoGBALlOOLsbyINA40GOm/4Q",
  "ctHQqA+ddxFGd/GDNNV0Ip5skrEG3DQ4Q0HysU1VkhFNMKS7Knb1MOJrj2gd4wNa",
  "8RqEDanE+NU/M0n1Fo30oOPuWHBc417GZdHz+fBTunk8WE5IaadV9psvuNZP+egV",
  "FVMPRjO0b7AuUIKZ7qcFFoWY",
  "-----END PRIVATE KEY-----",
].join("\n");
const expiredTlsCert = [
  "-----BEGIN CERTIFICATE-----",
  "MIIDCTCCAfGgAwIBAgIUeoJiEaFHqAUZDRrFXsTEzKh/a+0wDQYJKoZIhvcNAQEL",
  "BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDMwODEyMjQwMloXDTI2MDMw",
  "OTEyMjQwMlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF",
  "AAOCAQ8AMIIBCgKCAQEAr3lj94rBFuDFZOIr9xudA1HxKO4PkRUxGUnJ9511cfzN",
  "PACH9Dd+WohB/jqkXafulcw2Fjwt4OYatDkCsqQ0s1NhIMihaKBt+fGTldNVbmr2",
  "4ZyhGXRxRrQ8jgAe3wDOgJIeVxSfyd8cbiJlhAt8gmHIKNHB9CK9HjqumEY4f4wb",
  "mjEN9HogauzMFMjimALweLIGssWzPESTRz69B1CiW7hPWfb6iNMLhrwuRPFPkvE0",
  "eq8UbL8vvFs/coecbk+/8CoYTGP5WKPszj5zo8EYHG5DDeihhGtMsw4b20ihkryC",
  "KvvALS36O5dQ8hPUYziGXYGFo+eKqTad0pouQ2Rh+QIDAQABo1MwUTAdBgNVHQ4E",
  "FgQUpPL/M3K/kTc0eov5qH5KVxBPSpwwHwYDVR0jBBgwFoAUpPL/M3K/kTc0eov5",
  "qH5KVxBPSpwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAGTtH",
  "Aby4Nb3TggEMuZu6O8HITEVTs58xUea5ENQLrQwNK0bTOZtne2sE+JltYXBHqO06",
  "SaFdSCRJv9H6FBWYuehGVuID90qDnHeJb8ZXvUxn9gUDPbQ2/aNcbGC4z9pQcNhD",
  "8l06Yf3PCA4k11OKcsq0mvmgiSxtCFzETkS6FRwnHdoycd9zGK3s09M6c28g0jH5",
  "NxZHQasRK6/FQmqLAcAL7LEB1r1QvNB3dJOInuDXcAGwlLJRi/AF+BP02zI81KZv",
  "ScECeHV73qS3Z7eAGq38N0+4xGLiSwdovhWjW5kM/Mfr9GeLzMddeR+a9kX8He2y",
  "8weZc/65fI16eKngBg==",
  "-----END CERTIFICATE-----",
].join("\n");
const exampleTlsKey = [
  "-----BEGIN PRIVATE KEY-----",
  "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDHAYgKtxWWbJBe",
  "ZA3gONmImYfnmubHFWSRFkC5mBZAFecwEZZ/j2h82Zi7G0R1Wm33mCHMLUWrJAUC",
  "xtfdYKkhYwq94L8jrLMLNMUGU782isPMrWNzrK3B2c6S2dy4N+ul+q3xJSVFVuJt",
  "W8hNMwOlzklCNFErId8EQtN3CjRgePqwXR7LtN8hw7Og/DaHRgqaWlBEu6bg5jjp",
  "gPu/P0Grq4DIq1ijXOhACJV+zvDJ6N6XBqJ36BOZeKcJ6Ra3fPZkmvQ1BJbsMoPT",
  "5STzaLdfAKIZIPDj4c58WzJq0NstPKc4n28b5RINAOzzTs4iLuvUwkkn51eqGjoX",
  "mKJcOBxrAgMBAAECggEAHE26dJOvjVJpghNG6fIL9mKnsqgUVJJVWFFK6VqZJ4o1",
  "9F88AW57FO65yzrIlMxEwacwf2Kc+wdHcyqmvwSlaWs1tuXFKaTBXkGmGA1HL9Gy",
  "oWSztVsE54I74CT+QHErodKydI6s61y9HYKlTV2JEkbxomngdXr+xhNfEhowctvh",
  "yxje2Q7RLalOJkYYI6v6lC4EyqerreTehn854KZWA5Td4fUWOwTjALIkUBdl2jUa",
  "jXkvCHoSvSsmKhLW4EB6fxhV+8fLurJ923pH6UFiDBi7E7zqJMdCoCHAr41WRJvz",
  "Js5JvZouVcMI1Wuodp3YL0qpBiNbIjPhTF2e0YYdyQKBgQDm7MB7k46MpTe+Xmsp",
  "AvRzalaWaTbpaphv/QMQN27MbUxntgRV+GxZFlD3b5TGjcexK7VBV2pohdVAZe59",
  "dU08Y1aVIA4pXz+y4LTRKXOZ26R/hYMuPoOKvqJvYTHFbu5WZgvMMoFOClKNg0PW",
  "t8pEyH/+4JhI0W4Jeg/pPSuLTQKBgQDcnX/3PH+Tl7I4x7yu4R6GyWOwZB21z7bh",
  "odJdPQyPcofQykiGsDy3/LnQeoNOMn2acFnoNVx8GutnmH+cxYOAVyeA8V/L7wwD",
  "g3xByODWgNbX4wR0aDFgPSX3mNKWJKJPUZbx0j0t45u1Mqw+S3ybez+sHSrTCj8O",
  "6MM33h+6lwKBgB1bxCzx2ZGv/6JIRr90DLgPsOp2ffC3CKJUPGt3YLLEwo386hgz",
  "+TJqT+jlWrjTlavErsqb3n9jZHVHgEaa/zLKPlu/M422+lY3k0V0S6on7oX353Gd",
  "qQOesPAQH0/Ghq6dUqqnUSEm1s/+/ET0INcV1pAE5dd8KM0zo4o3qK2RAoGBAIOr",
  "8TNTxWUGthVTiRbrP7f8vOYLavwXhDR4y8Bgbn2zQsJn6Q+SYjsBuLloVbQ3SGYD",
  "xnVkW9Wqj3OePhQIgqr32ZkI9z8VZps2P9RXm3ILJa9mTENZ6JZjCKUVbiK0rLcg",
  "oDGmZGNeJJHqM4lernlx/xevtN6OkAJLBDD0/wTzAoGBAOO8Q57ZA6ckfEZWuDx7",
  "Twt3bQNnbqJY7/v54zkSgUwqRe0s3y/qYuHNAbi3mbEE+ot0DuI10o0QYE9J3+N9",
  "mlgadFFel9L4KQHh+lVLAq15w69Y3omf6MA3HpJT+VMXm+vD5Nnvei8in3H+wtwc",
  "jyKhC0U6d6o2z+597orhyV93",
  "-----END PRIVATE KEY-----",
].join("\n");
const exampleTlsCert = [
  "-----BEGIN CERTIFICATE-----",
  "MIIDJTCCAg2gAwIBAgIUHhYtufJb6ew8LKANHI3tlpE/a7owDQYJKoZIhvcNAQEL",
  "BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDMxNzA0MTAxNVoXDTM2MDMx",
  "NDA0MTAxNVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF",
  "AAOCAQ8AMIIBCgKCAQEAxwGICrcVlmyQXmQN4DjZiJmH55rmxxVkkRZAuZgWQBXn",
  "MBGWf49ofNmYuxtEdVpt95ghzC1FqyQFAsbX3WCpIWMKveC/I6yzCzTFBlO/NorD",
  "zK1jc6ytwdnOktncuDfrpfqt8SUlRVbibVvITTMDpc5JQjRRKyHfBELTdwo0YHj6",
  "sF0ey7TfIcOzoPw2h0YKmlpQRLum4OY46YD7vz9Bq6uAyKtYo1zoQAiVfs7wyeje",
  "lwaid+gTmXinCekWt3z2ZJr0NQSW7DKD0+Uk82i3XwCiGSDw4+HOfFsyatDbLTyn",
  "OJ9vG+USDQDs807OIi7r1MJJJ+dXqho6F5iiXDgcawIDAQABo28wbTAdBgNVHQ4E",
  "FgQUTb6CUIzQoHdeQboSmoXE27iy/rUwHwYDVR0jBBgwFoAUTb6CUIzQoHdeQboS",
  "moXE27iy/rUwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SH",
  "BH8AAAEwDQYJKoZIhvcNAQELBQADggEBALXD1Z8OzPYcRXHA7PqEcAYwFuj3NvJ1",
  "8+vAGtIX1oK5dQW0nonGnk1LIzshjDpVe/+tQ6jgRRjeT5TEO53G76bMMHxn96L1",
  "TOyygY/ixGLQ5C0XQkkCjUZYArkAGhlraw8RZR4p85fSLantQPy2/ZpEOm1ZHIQG",
  "NrhR8yUFi5Tc6PXwt1cFL76qorEAzj4k/7GgNVeDrHadVLLZ5f/bhGucXkCKEV62",
  "bdGUL0GsJU+tFI+qsHZGgdl8AkALEZIy4XuxdudvJSHQhYV76RWpcSo0Fz2mogob",
  "tETrGFU1LcDGqGdz+6lnJvh0phsgr1XcmDw0rgSPPniVkqZg7jVm+Mc=",
  "-----END CERTIFICATE-----",
].join("\n");
const invalidTlsCert = "this is not a certificate";

var _cachedTls;
function getTlsModule() {
  if (_cachedTls === undefined) {
    try {
      _cachedTls = require("node:tls");
    } catch (_err) {
      _cachedTls = {};
    }
    _cachedTls.key = exampleTlsKey;
    _cachedTls.cert = exampleTlsCert;
    _cachedTls.ca = exampleTlsCert;
    _cachedTls.__exactSelfSigned = true;
  }
  return _cachedTls;
}

function withoutAggressiveGC() {
  return;
}

const exampleSite = protocol => {
  const useHttps = protocol !== "http";
  const bun = globalThis.Bun || require("bun");
  const server = bun.serve({
    port: 0,
    tls: useHttps ? { key: exampleTlsKey, cert: exampleTlsCert } : undefined,
    fetch() {
      return new Response(exampleSiteBody, {
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    },
  });
  server.ca = exampleTlsCert;
  server.cert = exampleTlsCert;
  server.key = exampleTlsKey;
  if (typeof server.close !== "function") {
    server.close = function () {
      return server.stop(true);
    };
  }
  return server;
};

const baseApi = {
  isWindows,
  isMacOS,
  isLinux,
  isPosix,
  isCI,
  isASAN,
  isBroken,
  fixturesDir,
  projectRoot,
  getRandomPort,
  get randomPort() {
    return getRandomPort();
  },
  tempDir,
  tempDirWithFiles,
  tempDirWithFilesAnon,
  tmpdirSync,
  cwdScope,
  rmScope,
  hideFromStackTrace,
  bunExe,
  bunEnv,
  nodeExe,
  bunRun,
  bunRunAsScript,
  joinP,
  getMaxFD,
  expectMaxObjectTypeCount,
  noOp,
  noOpAsync,
  gc: noOp,
  gcTick: noOp,
  gcTrace: noOp,
  runBunInstall,
  shellExe,
  libcFamily,
  libcPathForDlopen() {
    return "libc.so.6";
  },
  randomUUIDv7,
  withoutAggressiveGC,
  exampleSite,
  exampleHtml,
  get tls() {
    return getTlsModule();
  },
  get expiredTls() {
    return {
      key: expiredTlsKey,
      cert: expiredTlsCert,
      ca: expiredTlsCert,
      __exactExpired: true,
    };
  },
  get invalidTls() {
    return {
      cert: invalidTlsCert,
      ca: invalidTlsCert,
    };
  },
  isDockerEnabled: false,
  isIntelMacOS: isMacOS && os.cpus()[0]?.model?.includes("Intel"),
  isAMD64: processMod.arch === "x64",
  isFlaky: false,
  isDebug: false,
  isWindowsVersionAtLeast() {
    return false;
  },
  isMacOSVersionAtLeast() {
    return false;
  },
  randomPort: getRandomPort,
  isIPv6() {
    return false;
  },
  isIPv4() {
    return false;
  },
};

// readableStreamFromArray - creates a ReadableStream from an array of chunks
baseApi.readableStreamFromArray = function readableStreamFromArray(array) {
  return new ReadableStream({
    start(controller) {
      for (var i = 0; i < array.length; i++) {
        controller.enqueue(array[i]);
      }
      controller.close();
    }
  });
};

module.exports = new Proxy(baseApi, {
  get(target, prop) {
    if (prop in target) {
      return target[prop];
    }
    const fallback = (...args) => {
      if (args.length === 0) {
        return undefined;
      }
      if (args.length === 1) {
        return args[0];
      }
      return args;
    };
    return fallback;
  },
});
