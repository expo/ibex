// Test-only output executor. @ref LLP 0023#6-path-bearing-observables — the output-shape executor walks
// the exact loaded realm and reports raw values without consulting disposition
// policy. Unsupported fixture routes are explicit and block promotion.

use super::*;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::Write;

mod global_callable_batch {
    include!("capsec_global_callable_batch.test.rs");
}

mod native_freeze_batch {
    include!("capsec_native_freeze_output_batch.test.rs");
}

const EXECUTOR: &str = "ibex-public-surface-harness/output-shape-sweep-v3";
const BATCH_SCHEMA: &str = "ibex/capsec-output-shape-executor-batch/3";
const AUTHORED_BUILTIN_HARNESS: &str = include_str!("capsec_public_noncap_builtin_invocation.js");
const GLOBAL_ACCESSOR_HARNESS: &str = include_str!("capsec_global_accessor_get.js");
const AUTHORED_BUILTIN_TIMEOUT_MS: u64 = 1_000;

fn is_source_return_output(raw: &Value) -> bool {
    raw["kind"] == "return"
}

fn is_global_accessor_output(raw: &Value) -> bool {
    matches!(raw["kind"].as_str(), Some("return") | Some("throw"))
}

#[test]
fn return_output_routes_never_accept_inner_throws() {
    assert!(is_source_return_output(&json!({"kind": "return"})));
    assert!(!is_source_return_output(&json!({"kind": "throw"})));
    assert!(!is_source_return_output(&json!({"kind": "absent"})));
}

#[test]
fn global_accessor_routes_retain_actual_get_throws() {
    assert!(is_global_accessor_output(&json!({"kind": "return"})));
    assert!(is_global_accessor_output(&json!({"kind": "throw"})));
    assert!(!is_global_accessor_output(&json!({"kind": "absent"})));
}

const AUTHENTICATED_MODULE_INLINE_RECORD_SCRIPT: &str = r#"
function __ibexOutputShapeFirstStackSource(stack) {
  var lines = String(stack || '').split('\n');
  for (var index = 1; index < lines.length; index++) {
    var match = lines[index].match(/(?:\(|at\s+)([^()\s]+):\d+:\d+\)?$/);
    if (match) return match[1];
  }
}
var __ibexOutputShapeSource = __ibexOutputShapeFirstStackSource(
  new Error('output-shape-synthetic-source').stack
);
JSON.stringify({
  processArgv: process.argv,
  exactArgv: typeof Exact === 'undefined' ? undefined : Exact.argv,
  bunArgv: typeof Bun === 'undefined' ? undefined : Bun.argv,
  exactMain: typeof Exact === 'undefined' ? undefined : Exact.main,
  bunMain: typeof Bun === 'undefined' ? undefined : Bun.main,
  exactFile: typeof Exact === 'undefined' ? undefined : Exact.file('/project/output-shape.js'),
  bunFile: typeof Bun === 'undefined' ? undefined : Bun.file('/project/output-shape.js'),
  filename: typeof __filename === 'undefined' ? undefined : __filename,
  dirname: typeof __dirname === 'undefined' ? undefined : __dirname,
  importMeta: {
    url: import.meta.url,
    file: import.meta.file,
    filename: import.meta.filename,
    dirname: import.meta.dirname,
    dir: import.meta.dir,
    path: import.meta.path
  },
  sourceURL: __ibexOutputShapeSource,
  sourceMapSources: [__ibexOutputShapeSource]
});
"#;

const AUTHENTICATED_SCRIPT_INLINE_RECORD_SCRIPT: &str = r#"
function __ibexOutputShapeFirstStackSource(stack) {
  var lines = String(stack || '').split('\n');
  for (var index = 1; index < lines.length; index++) {
    var match = lines[index].match(/(?:\(|at\s+)([^()\s]+):\d+:\d+\)?$/);
    if (match) return match[1];
  }
}
var __ibexOutputShapeSource = __ibexOutputShapeFirstStackSource(
  new Error('output-shape-synthetic-source').stack
);
JSON.stringify({
  processArgv: process.argv,
  exactArgv: typeof Exact === 'undefined' ? undefined : Exact.argv,
  bunArgv: typeof Bun === 'undefined' ? undefined : Bun.argv,
  exactMain: typeof Exact === 'undefined' ? undefined : Exact.main,
  bunMain: typeof Bun === 'undefined' ? undefined : Bun.main,
  exactFile: typeof Exact === 'undefined' ? undefined : Exact.file('/project/output-shape.js'),
  bunFile: typeof Bun === 'undefined' ? undefined : Bun.file('/project/output-shape.js'),
  filename: typeof __filename === 'undefined' ? undefined : __filename,
  dirname: typeof __dirname === 'undefined' ? undefined : __dirname,
  sourceURL: __ibexOutputShapeSource,
  sourceMapSources: [__ibexOutputShapeSource]
});
"#;

const STRUCTURED_SWEEP_SCRIPT: &str = r#"
(function () {
  'use strict';
  var probes = __IBEX_OUTPUT_SHAPE_PROBES__;

  function valueShape(value) {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'array';
    return typeof value;
  }

  function jsonValue(value, shape) {
    if (shape === 'undefined' || shape === 'function' || shape === 'symbol') return null;
    if (shape === 'bigint') return String(value);
    if (shape === 'object' || shape === 'array') {
      try { return JSON.parse(JSON.stringify(value)); } catch (_) { return null; }
    }
    return value;
  }

  function returned(value) {
    var shape = valueShape(value);
    return { kind: 'return', rawValueShape: shape, value: jsonValue(value, shape), errorCode: null };
  }

  function absent() {
    return { kind: 'absent', rawValueShape: 'absent', value: null, errorCode: null };
  }

  function stableErrorCode(error) {
    if (error && typeof error.code === 'string' && error.code) return error.code;
    var message = String(error && error.message || error || '');
    if (/closed|not available|unsupported in armed/i.test(message)) return 'ERR_IBEX_CLOSED_SURFACE';
    if (/unmappable|outside.*namespace|cannot.*map/i.test(message)) return 'ERR_IBEX_UNMAPPABLE_LINK';
    return 'ERR_IBEX_UNCLASSIFIED_' + String(error && error.name || 'ERROR')
      .replace(/[^A-Za-z0-9]+/g, '_').toUpperCase();
  }

  function thrown(error) {
    return { kind: 'throw', rawValueShape: 'throw', value: null, errorCode: stableErrorCode(error) };
  }

  function thrownField(error, field) {
    var value = error && error[field];
    if (value === undefined) return thrown(error);
    var raw = returned(value);
    raw.kind = 'throw';
    raw.errorCode = stableErrorCode(error);
    return raw;
  }

  function fieldAt(record, path) {
    var components = path.split('.');
    var current = record;
    for (var index = 0; index < components.length; index++) {
      var component = components[index];
      var arrayProjection = /\[\]$/.test(component);
      var name = arrayProjection ? component.slice(0, -2) : component;
      current = name ? current && current[name] : current;
      if (arrayProjection && index + 1 < components.length) {
        var tail = components.slice(index + 1).join('.');
        return Array.isArray(current) ? current.map(function (item) { return fieldAt(item, tail); }) : undefined;
      }
    }
    return current;
  }

  function recordValue(record, output) {
    if (record === undefined) return undefined;
    if (output === '[[return]]' || output === 'array-items') return record;
    if (output.indexOf('field:') === 0) return fieldAt(record, output.slice(6));
    if (output.indexOf('index:') === 0) return record[Number(output.slice(6))];
    if (output.indexOf('callback:') === 0) return record;
    if (output.indexOf('stack-frame:') === 0) return record;
    throw new Error('unsupported loaded-realm record path ' + output);
  }

  function callbackValue(start) {
    return new Promise(function (resolve, reject) {
      start(function (error, value) { if (error) reject(error); else resolve(value); });
    });
  }

  function firstStackSource(stack) {
    var lines = String(stack || '').split('\n');
    for (var index = 1; index < lines.length; index++) {
      var match = lines[index].match(/(?:\(|at\s+)([^()\s]+):\d+:\d+\)?$/);
      if (match) return match[1];
    }
    return undefined;
  }

  function runtimeStackSource(stack) {
    var lines = String(stack || '').split('\n');
    for (var index = 1; index < lines.length; index++) {
      var match = lines[index].match(/(?:\(|at\s+)([^()\s]+):\d+:\d+\)?$/);
      if (match && /^(?:ibex:|node:|bun:)/.test(match[1])) return match[1];
    }
    return firstStackSource(stack);
  }

  function fixture(source) {
    var fs;
    switch (source.surfaceName) {
      case 'export:exact_process:execArgv':
        return require('exact:process').execArgv;
      case 'export:node_fs:default':
        fs = require('node:fs');
        fs.copyFileSync('/project/missing-output-shape.js', '/project/missing-output-shape-copy.js');
        return undefined;
      case 'export:node_fs:Dirent':
        fs = require('node:fs');
        return fs.readdirSync('/project', { withFileTypes: true }).filter(function (entry) {
          return String(entry.name) === 'output-shape.js';
        })[0];
      case 'export:node_fs:globSync':
        fs = require('node:fs');
        return source.returnVariant === 'absolute-pattern'
          ? fs.globSync('/project/*.js')
          : fs.globSync('*.js', { cwd: '/project' });
      case 'export:node_fs:glob':
        fs = require('node:fs');
        return callbackValue(function (done) {
          if (source.returnVariant === 'absolute-pattern') fs.glob('/project/*.js', done);
          else fs.glob('*.js', { cwd: '/project' }, done);
        });
      case 'export:node_fs_promises:FileHandle':
        return require('node:fs').promises.open('/project/output-shape.js', 'r').then(function (handle) {
          var result = { path: handle.path };
          return handle.close().then(function () { return result; });
        });
      case 'export:node_fs_promises:readlink':
        return require('node:fs').promises.readlink(
          source.returnVariant === 'mapped' ? '/project/mapped-link' : '/project/unmappable-link'
        );
      case 'export:node_fs:readlink':
        fs = require('node:fs');
        return callbackValue(function (done) {
          fs.readlink(
            source.returnVariant === 'mapped' ? '/project/mapped-link' : '/project/unmappable-link',
            done
          );
        });
      case 'export:node_fs:readlinkSync':
        return require('node:fs').readlinkSync(
          source.returnVariant === 'mapped' ? '/project/mapped-link' : '/project/unmappable-link'
        );
      case 'export:node_fs:ReadStream':
        fs = require('node:fs');
        var readStream = fs.createReadStream('/project/output-shape.js');
        var readRecord = { path: readStream.path };
        readStream.destroy();
        return readRecord;
      case 'export:node_fs:WriteStream':
        fs = require('node:fs');
        var writeStream = fs.createWriteStream('/project/output-shape-write.txt');
        var writeRecord = { path: writeStream.path };
        writeStream.destroy();
        return writeRecord;
      case 'export:node_fs:watch':
        fs = require('node:fs');
        return new Promise(function (resolve, reject) {
          var recursive = source.returnVariant === 'recursive';
          var target = recursive ? '/project/watch-tree/changed.txt' : '/project/watch-flat.txt';
          var watcher;
          var timeout = setTimeout(function () {
            if (watcher) watcher.close();
            var error = new Error('output-shape watcher did not observe its fixture mutation');
            error.code = 'ERR_IBEX_WATCH_TIMEOUT';
            reject(error);
          }, 1500);
          watcher = fs.watch('/project', { recursive: recursive, interval: 10 }, function (_event, filename) {
            clearTimeout(timeout);
            watcher.close();
            resolve(filename);
          });
          setTimeout(function () {
            try { fs.writeFileSync(target, String(Date.now())); } catch (error) {
              clearTimeout(timeout); watcher.close(); reject(error);
            }
          }, 75);
        });
      case 'export:node_os:userInfo':
        return require('node:os').userInfo();
      case 'export:node_path:posix':
        var posix = require('node:path').posix;
        return {
          relative: posix.relative('/project/a', '/project/b'),
          resolve: posix.resolve('/project/a', '../b')
        };
      case 'export:node_path:win32':
        var win32 = require('node:path').win32;
        return {
          relative: win32.relative('C:\\project\\a', 'C:\\project\\b'),
          resolve: win32.resolve('C:\\project\\a', '..\\b')
        };
      case 'global:Exact.file':
        return Exact.file('/project/output-shape.js');
      case 'global:Bun.file':
        return Bun.file('/project/output-shape.js');
      case 'global:process.execArgv':
        return process.execArgv;
      case 'global:require.resolve':
        return source.returnVariant === 'builtin'
          ? require.resolve('node:path')
          : require.resolve('./output-shape.js');
      case 'module-loader-install':
        if (source.sourceKind === 'runtime-owned') {
          try { require('node:path').resolve(Symbol('output-shape')); } catch (error) {
            return runtimeStackSource(error.stack);
          }
        }
        throw new Error('module-loader fixture requires authenticated source mode');
      case 'ex_host_vfs_bind_runtime':
      case 'ex_host_vfs_chdir':
      case 'ex_host_vfs_get_cwd':
      case 'ex_host_vfs_resolve_path':
      case 'ex_host_vfs_unbind_runtime':
        return globalThis[source.surfaceName];
      default:
        throw new Error('unknown loaded-realm output fixture ' + source.surfaceName);
    }
  }

  function observe(row) {
    var source = row.probe.sourceDescriptor;
    var operation;
    try { operation = fixture(source); } catch (error) { operation = Promise.reject(error); }
    return Promise.resolve(operation).then(function (record) {
      var value = recordValue(record, source.output);
      var raw = value === undefined ? absent() : returned(value);
      return {
        key: row.key,
        proof: {
          kind: 'loaded-engine-return-record',
          fixtureId: row.probe.fixtureId,
          sourceDescriptorDigest: row.probe.sourceDescriptorDigest,
          recordPath: row.probe.recordPath,
          rawValueShape: raw.rawValueShape
        },
        raw: raw
      };
    }, function (error) {
      var raw = source.output.indexOf('throw-field:') === 0
        ? thrownField(error, source.output.slice(12))
        : thrown(error);
      return {
        key: row.key,
        proof: {
          kind: 'loaded-engine-return-record',
          fixtureId: row.probe.fixtureId,
          sourceDescriptorDigest: row.probe.sourceDescriptorDigest,
          recordPath: row.probe.recordPath,
          rawValueShape: raw.rawValueShape
        },
        raw: raw
      };
    });
  }

  globalThis.__ibexOutputShapeStructuredBatch = null;
  Promise.all(probes.map(observe)).then(function (results) {
    globalThis.__ibexOutputShapeStructuredBatch = JSON.stringify(results);
  }, function (error) {
    globalThis.__ibexOutputShapeStructuredBatch = JSON.stringify({ fatal: stableErrorCode(error) });
  });
  return 'output-shape-structured-sweep-started';
})()
"#;

const DESCRIPTOR_SWEEP_SCRIPT: &str = r#"
(function () {
  'use strict';
  var probes = __IBEX_OUTPUT_SHAPE_PROBES__;

  function valueShape(value) {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'array';
    return typeof value;
  }

  function jsonValue(value, shape) {
    if (shape === 'undefined' || shape === 'function' || shape === 'symbol') return null;
    if (shape === 'bigint') return String(value);
    if (shape === 'object' || shape === 'array') {
      try { return JSON.parse(JSON.stringify(value)); } catch (_) { return null; }
    }
    return value;
  }

  function returned(value) {
    var shape = valueShape(value);
    return { kind: 'return', rawValueShape: shape, value: jsonValue(value, shape), errorCode: null };
  }

  function stableErrorCode(error) {
    if (error && typeof error.code === 'string' && error.code) return error.code;
    var message = String(error && error.message || error || '');
    if (/closed|not available|unsupported in armed/i.test(message)) return 'ERR_IBEX_CLOSED_SURFACE';
    if (/unmappable|outside.*namespace|cannot.*map/i.test(message)) return 'ERR_IBEX_UNMAPPABLE_LINK';
    var name = error && typeof error.name === 'string' && error.name ? error.name : 'Error';
    return 'ERR_IBEX_UNCLASSIFIED_' + name.replace(/[^A-Za-z0-9]+/g, '_').toUpperCase();
  }

  function thrown(error) {
    return { kind: 'throw', rawValueShape: 'throw', value: null, errorCode: stableErrorCode(error) };
  }

  function findDescriptor(owner, name) {
    var current = owner;
    while (current !== null && current !== undefined) {
      var descriptor = Object.getOwnPropertyDescriptor(current, name);
      if (descriptor) return { descriptor: descriptor, inherited: current !== owner };
      current = Object.getPrototypeOf(current);
    }
    return null;
  }

  function descriptorValueType(descriptor) {
    if (!descriptor) return 'unread';
    return Object.prototype.hasOwnProperty.call(descriptor, 'value')
      ? valueShape(descriptor.value)
      : 'unread';
  }

  function describe(found) {
    if (!found) {
      return {
        presence: 'absent', descriptorKind: 'absent', valueType: 'unread',
        enumerable: null, configurable: null, writable: null,
        hasGetter: null, hasSetter: null
      };
    }
    var descriptor = found.descriptor;
    var data = Object.prototype.hasOwnProperty.call(descriptor, 'value');
    return {
      presence: found.inherited ? 'inherited' : 'own',
      descriptorKind: data ? 'data' : 'accessor',
      valueType: descriptorValueType(descriptor),
      enumerable: !!descriptor.enumerable,
      configurable: !!descriptor.configurable,
      writable: data ? !!descriptor.writable : null,
      hasGetter: data ? false : typeof descriptor.get === 'function',
      hasSetter: data ? false : typeof descriptor.set === 'function'
    };
  }

  function dynamicMarker(name) {
    return /^\[\[dynamic-table:.*\]\]$/.test(name);
  }

  function readPath(owner, components) {
    var current = owner;
    var found = null;
    for (var index = 0; index < components.length; index++) {
      var component = components[index];
      if (dynamicMarker(component)) {
        return {
          owner: current,
          name: component,
          found: {
            descriptor: {
              value: current,
              enumerable: false,
              configurable: false,
              writable: false
            },
            inherited: true
          },
          value: current,
          syntheticDynamicTable: true
        };
      }
      found = findDescriptor(current, component);
      if (!found) return { owner: current, name: component, found: null, value: undefined };
      if (index + 1 < components.length) current = current[component];
    }
    var leaf = components[components.length - 1];
    var descriptor = found && found.descriptor;
    var value = descriptor && Object.prototype.hasOwnProperty.call(descriptor, 'value')
      ? descriptor.value
      : undefined;
    return { owner: current, name: leaf, found: found, value: value };
  }

  function builtinRoute(source) {
    var moduleValue;
    var lastError;
    for (var index = 0; index < source.moduleSpecifiers.length; index++) {
      try {
        moduleValue = require(source.moduleSpecifiers[index]);
        lastError = null;
        break;
      } catch (error) {
        lastError = error;
      }
    }
    if (lastError) throw lastError;
    if (source.kind === 'builtin-root') {
      return {
        owner: { value: moduleValue },
        name: 'value',
        found: {
          descriptor: {
            value: moduleValue,
            enumerable: true,
            configurable: false,
            writable: false
          },
          inherited: false
        },
        value: moduleValue
      };
    }
    var components = source.exportName.split('.');
    var prototypeRoute = source.exportIdioms.some(function (idiom) {
      return idiom.indexOf('prototype') >= 0;
    });
    if (prototypeRoute && components.length > 1) {
      var constructorValue = moduleValue[components.shift()];
      if (constructorValue == null || constructorValue.prototype == null) {
        return { owner: moduleValue, name: components[0], found: null, value: undefined };
      }
      return readPath(constructorValue.prototype, components);
    }
    return readPath(moduleValue, components);
  }

  function globalRoute(source) {
    if (source.memberName === null) return readPath(globalThis, [source.globalName]);
    var root = globalThis[source.globalName];
    var prototypeOnly = source.memberKinds.some(function (kind) {
      return kind.indexOf('prototype-') === 0;
    }) && source.memberKinds.every(function (kind) {
      return kind.indexOf('native-object-') !== 0;
    });
    var owner = prototypeOnly && root != null ? root.prototype : root;
    return readPath(owner, source.memberName.split('.'));
  }

  function runFixture(name) {
    if (name === 'open-project-directory-path') {
      var fs = require('node:fs');
      var directory = fs.opendirSync('/project');
      try { return directory.path; } finally { directory.closeSync(); }
    }
    throw new Error('unknown output-shape descriptor fixture ' + name);
  }

  function exercise(route, source) {
    var exercise = source.exercise;
    if (exercise.kind === 'descriptor') return route.value;
    if (exercise.kind === 'read') return route.owner[route.name];
    if (exercise.kind === 'fixture') return runFixture(exercise.fixture);
    var callable = route.owner[route.name];
    if (exercise.kind === 'construct') {
      return Reflect.construct(callable, exercise.arguments);
    }
    if (exercise.kind === 'call') {
      return callable.apply(route.owner, exercise.arguments);
    }
    throw new Error('unknown output-shape descriptor exercise ' + exercise.kind);
  }

  function observe(probe) {
    try {
      var source = probe.probe.sourceDescriptor;
      var route = source.kind === 'global-api' ? globalRoute(source) : builtinRoute(source);
      var descriptor = describe(route.found);
      if (!route.found) {
        return Promise.resolve({
          key: probe.key,
          proof: {
            kind: 'loaded-engine-descriptor',
            sourceDescriptorDigest: probe.probe.sourceDescriptorDigest,
            descriptor: descriptor
          },
          raw: { kind: 'absent', rawValueShape: 'absent', value: null, errorCode: null }
        });
      }
      var value = exercise(route, source);
      return Promise.resolve(value).then(function (settled) {
        return {
          key: probe.key,
          proof: {
            kind: 'loaded-engine-descriptor',
            sourceDescriptorDigest: probe.probe.sourceDescriptorDigest,
            descriptor: descriptor
          },
          raw: returned(settled)
        };
      }, function (error) {
        return {
          key: probe.key,
          proof: {
            kind: 'loaded-engine-descriptor',
            sourceDescriptorDigest: probe.probe.sourceDescriptorDigest,
            descriptor: descriptor
          },
          raw: thrown(error)
        };
      });
    } catch (error) {
      return Promise.resolve({
        key: probe.key,
        proof: {
          kind: 'loaded-engine-descriptor',
          sourceDescriptorDigest: probe.probe.sourceDescriptorDigest,
          descriptor: describe(null)
        },
        raw: thrown(error)
      });
    }
  }

  globalThis.__ibexOutputShapeDescriptorBatch = null;
  Promise.all(probes.map(observe)).then(function (results) {
    globalThis.__ibexOutputShapeDescriptorBatch = JSON.stringify(results);
  }, function (error) {
    globalThis.__ibexOutputShapeDescriptorBatch = JSON.stringify({ fatal: stableErrorCode(error) });
  });
  return 'output-shape-descriptor-sweep-started';
})()
"#;

fn read_plan(path: &std::path::Path) -> Value {
    let bytes = std::fs::read(path).expect("read output-shape sweep plan");
    let text = std::str::from_utf8(&bytes).expect("output-shape sweep plan must be UTF-8");
    let plan = capsec_semantics::strict_json::parse_strict(text)
        .expect("output-shape sweep plan must be strict JSON");
    assert_eq!(
        plan["outputShapeSweepPlanSchema"],
        "ibex/capsec-output-shape-sweep-plan/3"
    );
    assert_eq!(plan["profile"], "ibex/capsec/1");
    assert_eq!(plan["executor"], EXECUTOR);
    assert!(plan["target"].is_object());
    assert!(plan["rows"].is_array());
    plan
}

fn compiled_surface_ids() -> Vec<String> {
    let coverage: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/registry/coverage-edges.json"
    )))
    .expect("compiled coverage registry must be JSON");
    let ids = coverage["edges"]
        .as_array()
        .expect("compiled coverage registry must contain edges")
        .iter()
        .map(|edge| {
            edge["id"]
                .as_str()
                .expect("compiled coverage edge has no id")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    ids.into_iter().collect()
}

fn authored_builtin_unexercisable(row: &Value, reason: impl AsRef<str>) -> Value {
    json!({
        "key": row["key"].clone(),
        "reason": format!(
            "authored public builtin invocation {} was not an authenticated output observation: {}",
            row["probe"]["fixtureId"].as_str().unwrap_or("<missing>"),
            reason.as_ref()
        )
    })
}

fn return_record_result(row: &Value, raw: Value) -> Value {
    json!({
        "key": row["key"].clone(),
        "proof": {
            "kind": "loaded-engine-return-record",
            "fixtureId": row["probe"]["fixtureId"].clone(),
            "sourceDescriptorDigest": row["probe"]["sourceDescriptorDigest"].clone(),
            "recordPath": row["probe"]["recordPath"].clone(),
            "rawValueShape": raw["rawValueShape"].clone()
        },
        "raw": raw
    })
}

fn compiled_runtime_return_record_result(row: &Value, raw: Value) -> Value {
    json!({
        "key": row["key"].clone(),
        "proof": {
            "kind": "compiled-runtime-return-record",
            "fixtureId": row["probe"]["fixtureId"].clone(),
            "sourceDescriptorDigest": row["probe"]["sourceDescriptorDigest"].clone(),
            "recordPath": row["probe"]["recordPath"].clone(),
            "rawValueShape": raw["rawValueShape"].clone()
        },
        "raw": raw
    })
}

fn raw_string(value: String) -> Value {
    json!({
        "kind": "return",
        "rawValueShape": "string",
        "value": value,
        "errorCode": null
    })
}

unsafe fn take_vfs_output(data: *mut u8, len: u64) -> String {
    assert!(!data.is_null(), "successful VFS output must not be null");
    let bytes = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let value = std::str::from_utf8(bytes)
        .expect("VFS output must be UTF-8")
        .to_owned();
    crate::host::abi::ex_host_free_buffer(data, len);
    value
}

async fn private_vfs_results(engine: &HermesEngine, rows: &[Value]) -> Vec<Value> {
    if rows.is_empty() {
        return Vec::new();
    }
    let runtime = engine
        .ensure_runtime()
        .await
        .expect("load output-shape runtime for VFS ABI");
    let runtime_nonce = runtime
        .with_runtime(|raw| unsafe { ex_hermes_runtime_nonce(raw) })
        .expect("read output-shape runtime nonce");
    assert_ne!(runtime_nonce, 0);
    let module_ids = [0_u64];
    rows.iter()
        .map(|row| {
            let mut virtual_data = std::ptr::null_mut();
            let mut virtual_len = 0_u64;
            let mut errno = 0_i32;
            let surface = source_surface_name(row);
            let value = match surface {
                "ex_host_vfs_get_cwd" => {
                    let status = unsafe {
                        crate::host::abi::ex_host_vfs_get_cwd(
                            runtime_nonce,
                            0,
                            module_ids.as_ptr(),
                            module_ids.len(),
                            &mut virtual_data,
                            &mut virtual_len,
                            &mut errno,
                        )
                    };
                    assert_eq!(status, crate::host::abi::EX_HOST_VFS_RESULT_OK);
                    assert_eq!(errno, 0);
                    unsafe { take_vfs_output(virtual_data, virtual_len) }
                }
                "ex_host_vfs_chdir" => {
                    let input = b"/project";
                    let status = unsafe {
                        crate::host::abi::ex_host_vfs_chdir(
                            runtime_nonce,
                            0,
                            module_ids.as_ptr(),
                            module_ids.len(),
                            input.as_ptr(),
                            input.len() as u64,
                            &mut virtual_data,
                            &mut virtual_len,
                            &mut errno,
                        )
                    };
                    assert_eq!(status, crate::host::abi::EX_HOST_VFS_RESULT_OK);
                    assert_eq!(errno, 0);
                    unsafe { take_vfs_output(virtual_data, virtual_len) }
                }
                "ex_host_vfs_resolve_path" => {
                    let input = b"/project/output-shape.js";
                    let mut backing_data = std::ptr::null_mut();
                    let mut backing_len = 0_u64;
                    let status = unsafe {
                        crate::host::abi::ex_host_vfs_resolve_path(
                            runtime_nonce,
                            input.as_ptr(),
                            input.len() as u64,
                            &mut backing_data,
                            &mut backing_len,
                            &mut virtual_data,
                            &mut virtual_len,
                            &mut errno,
                        )
                    };
                    assert_eq!(status, crate::host::abi::EX_HOST_VFS_RESULT_OK);
                    assert_eq!(errno, 0);
                    let _private_backing = unsafe { take_vfs_output(backing_data, backing_len) };
                    unsafe { take_vfs_output(virtual_data, virtual_len) }
                }
                other => panic!("unsupported private VFS output fixture {other}"),
            };
            return_record_result(row, raw_string(value))
        })
        .collect()
}

async fn loaded_descriptor_results(
    engine: &HermesEngine,
    sweep: &mut AuthenticatedSweep,
    rows: &[Value],
) -> (Vec<Value>, Vec<Value>) {
    if rows.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let encoded = serde_json::to_string(rows).expect("serialize output-shape descriptor probes");
    let script = DESCRIPTOR_SWEEP_SCRIPT.replace("__IBEX_OUTPUT_SHAPE_PROBES__", &encoded);
    assert_eq!(
        sweep
            .eval_string(engine, &script)
            .await
            .expect("start output-shape descriptor sweep")
            .as_deref(),
        Some("output-shape-descriptor-sweep-started")
    );
    sweep
        .drive_event_loop(engine, "output-shape descriptor sweep")
        .await
        .expect("settle output-shape descriptor sweep");
    let encoded = sweep
        .eval_string(engine, "globalThis.__ibexOutputShapeDescriptorBatch")
        .await
        .expect("read output-shape descriptor sweep")
        .expect("output-shape descriptor sweep returned no result");
    let value: Value = serde_json::from_str(&encoded)
        .expect("output-shape descriptor sweep returned invalid JSON");
    assert!(
        value.get("fatal").is_none(),
        "descriptor sweep failed: {value}"
    );
    let results = value
        .as_array()
        .expect("output-shape descriptor sweep did not return an array")
        .clone();
    assert_eq!(results.len(), rows.len());
    let mut observed = Vec::new();
    let mut unexercisable = Vec::new();
    for (row, result) in rows.iter().zip(results) {
        let default_descriptor =
            row["probe"]["sourceDescriptor"]["exercise"]["kind"] == "descriptor";
        let descriptor = &result["proof"]["descriptor"];
        if default_descriptor
            && (descriptor["valueType"] == "function" || descriptor["descriptorKind"] == "accessor")
        {
            unexercisable.push(json!({
                "key": row["key"].clone(),
                "reason": "loaded descriptor reached a callable or accessor, but no bounded invocation/read fixture observes its output"
            }));
        } else {
            observed.push(result);
        }
    }
    assert_eq!(observed.len() + unexercisable.len(), rows.len());
    (observed, unexercisable)
}

fn authored_builtin_invocation(row: &Value) -> &Value {
    let source = &row["probe"]["sourceDescriptor"];
    assert_eq!(source["kind"], "authored-public-builtin-invocation");
    assert_eq!(row["probe"]["recordPath"], json!(["[[return]]"]));
    let invocation = &source["invocation"];
    assert!(matches!(
        invocation["kind"].as_str(),
        Some("builtin-export-read") | Some("builtin-export-call")
    ));
    assert_eq!(
        invocation["completion"],
        json!({
            "kind": "event-loop-quiescence",
            "timeoutMilliseconds": AUTHORED_BUILTIN_TIMEOUT_MS,
        })
    );
    invocation
}

fn authored_builtin_preload_script(module_specifier: &str) -> String {
    format!(
        "(function(){{require({});return 'ibex-capsec-builtin-preloaded';}})()",
        serde_json::to_string(module_specifier)
            .expect("serialize authored builtin module specifier")
    )
}

fn authored_builtin_invocation_script(row: &Value) -> String {
    let mut invocation = authored_builtin_invocation(row).clone();
    invocation
        .as_object_mut()
        .expect("authored builtin invocation must be an object")
        .insert("captureRawOutput".to_owned(), Value::Bool(true));
    format!(
        "JSON.stringify(({})({}))",
        AUTHORED_BUILTIN_HARNESS.trim(),
        serde_json::to_string(&invocation).expect("serialize authored builtin invocation")
    )
}

async fn authored_builtin_quiescence(
    engine: &HermesEngine,
    sweep: &mut AuthenticatedSweep,
) -> std::result::Result<(), String> {
    let completion = tokio::time::timeout(
        std::time::Duration::from_millis(AUTHORED_BUILTIN_TIMEOUT_MS),
        engine.drive_event_loop(),
    )
    .await;
    // Drain even on timeout/failure and before reading observer evidence.
    // @ref LLP 0025#11-delegated-obligations — OBL-UNIT-PUBLICATION
    // makes the bounded publication stream part of authenticated control.
    sweep
        .drain_publications(engine, "authored output-shape event-loop drive")
        .map_err(|error| format!("event-loop publication drain failed: {error:#}"))?;
    completion
        .map_err(|_| "event loop did not reach the authored one-second bound".to_owned())?
        .map_err(|error| format!("event-loop completion failed: {error:#}"))
}

async fn authored_builtin_results(
    engine: &HermesEngine,
    sweep: &mut AuthenticatedSweep,
    rows: &[Value],
) -> (Vec<Value>, Vec<Value>) {
    if rows.is_empty() {
        return (Vec::new(), Vec::new());
    }

    // Import initialization is a separate operation from the export output.
    // Preload each exact public module once, outside every invocation observer,
    // and require its deferred work to settle before any output is captured.
    let module_specifiers = rows
        .iter()
        .map(|row| {
            authored_builtin_invocation(row)["moduleSpecifier"]
                .as_str()
                .expect("authored builtin invocation has no module specifier")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    let mut preload_failures = std::collections::BTreeMap::new();
    for module_specifier in module_specifiers {
        let preload = match sweep
            .eval_string(engine, &authored_builtin_preload_script(&module_specifier))
            .await
        {
            Ok(Some(marker)) if marker == "ibex-capsec-builtin-preloaded" => {
                authored_builtin_quiescence(engine, sweep).await
            }
            Ok(value) => Err(format!("module preload returned {value:?}")),
            Err(error) => Err(format!("module preload failed: {error:#}")),
        };
        if let Err(error) = preload {
            preload_failures.insert(module_specifier, error);
        }
    }

    let mut observed = Vec::new();
    let mut unexercisable = Vec::new();
    for row in rows {
        let invocation = authored_builtin_invocation(row);
        let module_specifier = invocation["moduleSpecifier"]
            .as_str()
            .expect("authored builtin invocation has no module specifier");
        if let Some(error) = preload_failures.get(module_specifier) {
            unexercisable.push(authored_builtin_unexercisable(row, error));
            continue;
        }

        let fixture_id = row["probe"]["fixtureId"]
            .as_str()
            .expect("authored builtin route has no fixture ID");
        let observer_id = format!("output-shape:{fixture_id}");
        if !ibex_runtime::host::abi::begin_installed_conformance_observation(&observer_id) {
            unexercisable.push(authored_builtin_unexercisable(
                row,
                "the installed host refused the invocation observer",
            ));
            continue;
        }
        let execution = sweep
            .eval_string(engine, &authored_builtin_invocation_script(row))
            .await;
        let quiescence = authored_builtin_quiescence(engine, sweep).await;
        let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
        if !legacy.is_empty() || !typed.is_empty() {
            unexercisable.push(authored_builtin_unexercisable(
                row,
                format!(
                    "non-capability recipe reached {} legacy and {} typed decisions",
                    legacy.len(),
                    typed.len()
                ),
            ));
            continue;
        }
        if let Err(error) = quiescence {
            unexercisable.push(authored_builtin_unexercisable(row, error));
            continue;
        }
        let encoded = match execution {
            Ok(Some(encoded)) => encoded,
            Ok(None) => {
                unexercisable.push(authored_builtin_unexercisable(
                    row,
                    "loaded invocation returned no result",
                ));
                continue;
            }
            Err(error) => {
                unexercisable.push(authored_builtin_unexercisable(
                    row,
                    format!("loaded invocation failed before returning evidence: {error:#}"),
                ));
                continue;
            }
        };
        let result: Value = match serde_json::from_str(&encoded) {
            Ok(result) => result,
            Err(error) => {
                unexercisable.push(authored_builtin_unexercisable(
                    row,
                    format!("loaded invocation returned invalid JSON: {error}"),
                ));
                continue;
            }
        };
        if result["sourceOperationAttempted"] != true {
            unexercisable.push(authored_builtin_unexercisable(
                row,
                format!("harness never reached the authored operation: {result}"),
            ));
            continue;
        }
        if invocation["kind"] == "builtin-export-call"
            && result["bodyEntryProof"] != "normal-return-from-source-call"
            && result["kind"] != "throw"
        {
            unexercisable.push(authored_builtin_unexercisable(
                row,
                format!("call returned without loaded source-call proof: {result}"),
            ));
            continue;
        }
        if invocation["setup"]["kind"] == "zlib-owner" && result["cleanupPerformed"] != true {
            unexercisable.push(authored_builtin_unexercisable(
                row,
                format!("zlib recipe did not prove native cleanup: {result}"),
            ));
            continue;
        }
        let Some(raw) = result.get("rawOutput") else {
            unexercisable.push(authored_builtin_unexercisable(
                row,
                format!("loaded invocation returned no raw output: {result}"),
            ));
            continue;
        };
        if !is_source_return_output(raw) {
            unexercisable.push(authored_builtin_unexercisable(
                row,
                format!(
                    "loaded invocation produced {}, so the source [[return]] output was not exercised: {raw}",
                    raw["kind"].as_str().unwrap_or("an invalid outcome")
                ),
            ));
            continue;
        }
        observed.push(return_record_result(row, raw.clone()));
    }
    assert_eq!(observed.len() + unexercisable.len(), rows.len());
    (observed, unexercisable)
}

fn global_accessor_unexercisable(row: &Value, reason: impl AsRef<str>) -> Value {
    json!({
        "key": row["key"].clone(),
        "reason": format!(
            "authored global accessor Get {} was not an authenticated output observation: {}",
            row["probe"]["fixtureId"].as_str().unwrap_or("<missing>"),
            reason.as_ref()
        )
    })
}

fn global_accessor_invocation(row: &Value) -> &Value {
    let source = &row["probe"]["sourceDescriptor"];
    assert_eq!(source["kind"], "authored-global-accessor-get");
    assert_eq!(row["probe"]["recordPath"], json!(["[[return]]"]));
    let invocation = &source["invocation"];
    assert_eq!(
        invocation["invocationSchema"],
        "ibex/capsec-global-accessor-get-invocation/1"
    );
    assert_eq!(invocation["kind"], "global-accessor-get");
    assert_eq!(
        invocation["completion"],
        json!({
            "kind": "event-loop-quiescence",
            "timeoutMilliseconds": AUTHORED_BUILTIN_TIMEOUT_MS,
        })
    );
    invocation
}

fn global_accessor_invocation_script(row: &Value) -> String {
    format!(
        "JSON.stringify(({})({}))",
        GLOBAL_ACCESSOR_HARNESS.trim(),
        serde_json::to_string(global_accessor_invocation(row))
            .expect("serialize authored global accessor Get")
    )
}

fn global_accessor_requested_authority_matches(grant: &Value, observed: &Value) -> bool {
    if grant == observed {
        return true;
    }
    let Some(grant) = grant.as_object() else {
        return false;
    };
    let Some(observed) = observed.as_object() else {
        return false;
    };
    grant.len() == 2
        && observed.len() == 2
        && grant.get("kind") == Some(&json!("session-lifecycle"))
        && grant.get("operation") == Some(&json!("exit-code-get"))
        && observed.get("kind") == Some(&json!("session-lifecycle"))
        && observed.get("disposition") == Some(&json!("exit-code-get"))
}

#[test]
fn accessor_authority_maps_the_exit_code_get_route_without_output_policy_echo() {
    assert!(global_accessor_requested_authority_matches(
        &json!({"kind": "session-lifecycle", "operation": "exit-code-get"}),
        &json!({"kind": "session-lifecycle", "disposition": "exit-code-get"}),
    ));
    assert!(!global_accessor_requested_authority_matches(
        &json!({"kind": "session-lifecycle", "operation": "exit-code-get"}),
        &json!({"kind": "session-lifecycle", "disposition": "exit-code-set"}),
    ));
}

fn validate_global_accessor_typed_authority(
    invocation: &Value,
    observer_id: &str,
    typed_decisions: &Value,
) -> Result<(), String> {
    let decisions = typed_decisions
        .as_array()
        .ok_or_else(|| "typed accessor decision capture was not an array".to_owned())?;
    let grants = invocation["authority"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if decisions.is_empty() && grants.is_empty() {
        return Ok(());
    }
    if grants.is_empty() {
        return Err(format!(
            "{} typed decisions were observed without authored accessor authority: {}",
            decisions.len(),
            typed_decisions
        ));
    }

    let mut matched = vec![false; grants.len()];
    for decision in decisions {
        if decision["terminalBranchId"] != observer_id {
            return Err("typed accessor decision escaped its exact observer".to_owned());
        }
        if decision["evidence"]["outcome"] != "allow" {
            return Err("typed accessor decision was not an authenticated allow".to_owned());
        }
        let gates = decision["gates"]
            .as_array()
            .ok_or_else(|| "typed accessor decision gates were not an array".to_owned())?;
        if gates.is_empty()
            || gates.iter().any(|gate| {
                gate["targetCell"] != "complete"
                    || gate["definitionAndEdgePredicatesSatisfied"] != true
            })
        {
            return Err("typed accessor decision did not traverse complete gates".to_owned());
        }
        let effects = decision["decisionSet"]["effects"]
            .as_array()
            .ok_or_else(|| "typed accessor decision effects were not an array".to_owned())?;
        if effects.is_empty() {
            return Err("typed accessor decision carried no effects".to_owned());
        }
        for effect in effects {
            let Some(index) = grants.iter().position(|grant| {
                grant["kind"] == "typed-effect"
                    && grant["cap"] == effect["cap"]
                    && grant["resourceKind"] == effect["resource"]["kind"]
                    && global_accessor_requested_authority_matches(
                        &grant["requested"],
                        &effect["resource"]["requested"],
                    )
            }) else {
                return Err(format!(
                    "typed accessor effect was outside authored authority: {effect}"
                ));
            };
            matched[index] = true;
        }
    }
    if matched.iter().any(|matched| !matched) {
        return Err("authored accessor authority was broader than observed effects".to_owned());
    }
    Ok(())
}

async fn global_accessor_results(
    engine: &HermesEngine,
    sweep: &mut AuthenticatedSweep,
    rows: &[Value],
) -> (Vec<Value>, Vec<Value>) {
    let mut observed = Vec::new();
    let mut unexercisable = Vec::new();
    for row in rows {
        let invocation = global_accessor_invocation(row);
        let receiver = &invocation["receiver"];
        if receiver["kind"] == "unexercisable" {
            unexercisable.push(global_accessor_unexercisable(
                row,
                format!(
                    "{}: {}",
                    receiver["reasonCode"].as_str().unwrap_or("unspecified"),
                    receiver["reason"].as_str().unwrap_or("unspecified reason")
                ),
            ));
            continue;
        }

        let fixture_id = row["probe"]["fixtureId"]
            .as_str()
            .expect("global accessor Get route has no fixture ID");
        let observer_id = format!("output-shape:{fixture_id}");
        if !ibex_runtime::host::abi::begin_installed_conformance_observation(&observer_id) {
            unexercisable.push(global_accessor_unexercisable(
                row,
                "the installed host refused the Get observer",
            ));
            continue;
        }
        let execution = sweep
            .eval_string(engine, &global_accessor_invocation_script(row))
            .await;
        let quiescence = authored_builtin_quiescence(engine, sweep).await;
        let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
        let typed = serde_json::to_value(typed)
            .expect("serialize typed global accessor capability decisions");
        if !legacy.is_empty() {
            unexercisable.push(global_accessor_unexercisable(
                row,
                format!(
                    "Get or receiver setup reached {} legacy capability decisions",
                    legacy.len()
                ),
            ));
            continue;
        }
        if let Err(reason) =
            validate_global_accessor_typed_authority(invocation, &observer_id, &typed)
        {
            unexercisable.push(global_accessor_unexercisable(row, reason));
            continue;
        }
        if let Err(error) = quiescence {
            unexercisable.push(global_accessor_unexercisable(row, error));
            continue;
        }
        let encoded = match execution {
            Ok(Some(encoded)) => encoded,
            Ok(None) => {
                unexercisable.push(global_accessor_unexercisable(
                    row,
                    "loaded Get returned no result",
                ));
                continue;
            }
            Err(error) => {
                unexercisable.push(global_accessor_unexercisable(
                    row,
                    format!("loaded Get failed before returning evidence: {error:#}"),
                ));
                continue;
            }
        };
        let result: Value = match serde_json::from_str(&encoded) {
            Ok(result) => result,
            Err(error) => {
                unexercisable.push(global_accessor_unexercisable(
                    row,
                    format!("loaded Get returned invalid JSON: {error}"),
                ));
                continue;
            }
        };
        if result["sourceOperationAttempted"] != true {
            unexercisable.push(global_accessor_unexercisable(
                row,
                format!(
                    "{}: receiver setup never reached the source Get",
                    result["reasonCode"].as_str().unwrap_or("setup-failed")
                ),
            ));
            continue;
        }
        if !matches!(
            result["descriptorProof"]["descriptorKind"].as_str(),
            Some("data") | Some("accessor")
        ) {
            unexercisable.push(global_accessor_unexercisable(
                row,
                format!("source Get had no loaded property descriptor: {result}"),
            ));
            continue;
        }
        let Some(raw) = result.get("rawOutput") else {
            unexercisable.push(global_accessor_unexercisable(
                row,
                format!("loaded Get returned no raw output: {result}"),
            ));
            continue;
        };
        if !is_global_accessor_output(raw) {
            unexercisable.push(global_accessor_unexercisable(
                row,
                format!(
                    "loaded Get produced an invalid {} outcome: {raw}",
                    raw["kind"].as_str().unwrap_or("an invalid outcome")
                ),
            ));
            continue;
        }
        observed.push(return_record_result(row, raw.clone()));
    }
    assert_eq!(observed.len() + unexercisable.len(), rows.len());
    (observed, unexercisable)
}

fn source_surface_name(row: &Value) -> &str {
    row["probe"]["sourceDescriptor"]["surfaceName"]
        .as_str()
        .or_else(|| row["probe"]["sourceDescriptor"]["symbol"].as_str())
        .or_else(|| row["probe"]["sourceDescriptor"]["surfaceObservedKey"].as_str())
        .expect("structured output route has no source surface name")
}

fn is_safe_throw_metadata_surface(row: &Value) -> bool {
    row["key"]["alias"] == "ex_hermes_value_safe_throw_metadata"
}

fn is_authored_builtin_surface(row: &Value) -> bool {
    row["probe"]["sourceDescriptor"]["kind"] == "authored-public-builtin-invocation"
}

fn is_global_accessor_surface(row: &Value) -> bool {
    row["probe"]["sourceDescriptor"]["kind"] == "authored-global-accessor-get"
}

fn is_private_vfs_surface(row: &Value) -> bool {
    matches!(
        source_surface_name(row),
        "ex_host_vfs_get_cwd" | "ex_host_vfs_chdir" | "ex_host_vfs_resolve_path"
    )
}

fn is_resolver_surface(row: &Value) -> bool {
    matches!(
        source_surface_name(row),
        "__exactModuleResolve"
            | "__exactModuleResolveMeta"
            | "__exactNativeModuleResolve"
            | "__exactNativeModuleResolveMeta"
    )
}

fn is_generic_loaded_realm_surface(row: &Value) -> bool {
    matches!(
        source_surface_name(row),
        "export:exact_process:execArgv"
            | "export:node_fs:default"
            | "export:node_fs:Dirent"
            | "export:node_fs:glob"
            | "export:node_fs:globSync"
            | "export:node_fs_promises:FileHandle"
            | "export:node_fs_promises:readlink"
            | "export:node_fs:readlink"
            | "export:node_fs:readlinkSync"
            | "export:node_fs:ReadStream"
            | "export:node_fs:watch"
            | "export:node_fs:WriteStream"
            | "export:node_os:userInfo"
            | "export:node_path:posix"
            | "export:node_path:win32"
            | "global:Bun.file"
            | "global:Exact.file"
            | "global:process.execArgv"
            | "global:require.resolve"
            | "ex_host_vfs_bind_runtime"
            | "ex_host_vfs_chdir"
            | "ex_host_vfs_get_cwd"
            | "ex_host_vfs_resolve_path"
            | "ex_host_vfs_unbind_runtime"
    ) && row["key"]["mode"] != "private-native"
        || (source_surface_name(row) == "module-loader-install"
            && row["key"]["sourceKind"] == "runtime-owned")
}

fn resolver_unexercisable(row: &Value) -> Value {
    json!({
        "key": row["key"].clone(),
        "reason": format!(
            "resolver bridge {} is bootstrap-private and sealed before authenticated source ingress; diagnostic or pre-bootstrap bare evaluation is not execution evidence",
            source_surface_name(row)
        )
    })
}

async fn loaded_structured_results(
    engine: &HermesEngine,
    sweep: &mut AuthenticatedSweep,
    rows: &[Value],
) -> Vec<Value> {
    if rows.is_empty() {
        return Vec::new();
    }
    let encoded = serde_json::to_string(rows).expect("serialize output-shape loaded-realm probes");
    let script = STRUCTURED_SWEEP_SCRIPT.replace("__IBEX_OUTPUT_SHAPE_PROBES__", &encoded);
    assert_eq!(
        sweep
            .eval_string(engine, &script)
            .await
            .expect("start output-shape loaded-realm sweep")
            .as_deref(),
        Some("output-shape-structured-sweep-started")
    );
    sweep
        .drive_event_loop(engine, "output-shape loaded-realm sweep")
        .await
        .expect("settle output-shape loaded-realm sweep");
    let encoded = sweep
        .eval_string(engine, "globalThis.__ibexOutputShapeStructuredBatch")
        .await
        .expect("read output-shape loaded-realm sweep")
        .expect("output-shape loaded-realm sweep returned no result");
    let value: Value = serde_json::from_str(&encoded)
        .expect("output-shape loaded-realm sweep returned invalid JSON");
    assert!(
        value.get("fatal").is_none(),
        "structured sweep failed: {value}"
    );
    let results = value
        .as_array()
        .expect("output-shape loaded-realm sweep did not return an array")
        .clone();
    assert_eq!(results.len(), rows.len());
    results
}

struct AuthenticatedSweep {
    session: ibex_runtime::engine::evaluation::ArmedSessionToken,
    sequence: ibex_runtime::engine::evaluation::SubmissionSequence,
    publications: AuthenticatedPublicationTracker,
}

impl AuthenticatedSweep {
    fn new(host: &crate::host::Host) -> Self {
        let session = host
            .mint_armed_session_token()
            .expect("mint authenticated output-shape sweep session");
        let sequence = ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone())
            .expect("create authenticated output-shape sweep sequence");
        Self {
            session,
            sequence,
            publications: AuthenticatedPublicationTracker::default(),
        }
    }

    async fn eval_string(
        &mut self,
        engine: &HermesEngine,
        source: &str,
    ) -> anyhow::Result<Option<String>> {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};

        self.drain_publications(engine, "output-shape source before evaluation")?;
        let request = self
            .sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })?
            .authorize_inline()
            .bind_bytes(source.as_bytes().to_vec())
            .into_request()?;
        let evaluation = engine.evaluate_authenticated(&self.session, request).await;
        self.drain_publications(engine, "output-shape source after evaluation")?;
        let evaluation = evaluation.unwrap_or_else(|error| {
                let source_suffix = source
                    .chars()
                    .rev()
                    .take(800)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect::<String>();
                panic!(
                    "authenticated output-shape evaluator failed before producing a source outcome: {error:#}; source suffix: {source_suffix}"
                )
            });
        match evaluation {
            AuthenticatedEvaluation::Empty => Ok(None),
            AuthenticatedEvaluation::Value { display, receipt } => {
                let release = engine
                    .release_undisplayed_value(
                        receipt.expect("authenticated sweep value must retain a receipt"),
                    )
                    .await;
                self.drain_publications(engine, "output-shape value release")?;
                release?;
                anyhow::ensure!(
                    display.kind == AuthenticatedDisplayKind::String,
                    "authenticated output-shape sweep returned {:?}, expected a string",
                    display.kind
                );
                Ok(Some(serde_json::from_str(&display.text)?))
            }
            AuthenticatedEvaluation::Throw(thrown) => {
                anyhow::bail!("authenticated output-shape source threw: {thrown:?}")
            }
            AuthenticatedEvaluation::Cancelled => {
                anyhow::bail!("authenticated output-shape source was cancelled")
            }
            AuthenticatedEvaluation::Lifecycle(code) => {
                anyhow::bail!("authenticated output-shape source exited with lifecycle code {code}")
            }
        }
    }

    fn drain_publications(
        &mut self,
        engine: &HermesEngine,
        context: &str,
    ) -> anyhow::Result<()> {
        self.publications.drain(engine, context)
    }

    async fn drive_event_loop(
        &mut self,
        engine: &HermesEngine,
        context: &str,
    ) -> anyhow::Result<()> {
        let completion = engine.drive_event_loop().await;
        self.publications.drain(engine, context)?;
        completion
    }

    fn finish(&mut self, engine: &HermesEngine) -> anyhow::Result<()> {
        let context = "output-shape source batch completion";
        self.publications.drain(engine, context)?;
        self.publications.require_no_due_schedules(context)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_repl_survives_256_large_submissions() {
    if std::env::var_os("IBEX_CAPSEC_REPL_256_REPRO").is_none() {
        return;
    }

    let _lock = hermes_engine_test_lock().lock().await;
    let (host, digest) =
        build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |snapshot| {
            snapshot["entry"] = json!({
                "kind": "repl",
                "identity": "ibex:repl",
                "mode": "interactive"
            });
        });
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest))
        .expect("create authenticated 256-submission reproduction runtime");
    engine
        .load_runtime()
        .await
        .expect("load authenticated 256-submission reproduction runtime");
    let mut sweep = AuthenticatedSweep::new(&host);
    let source = format!("typeof ({})", AUTHORED_BUILTIN_HARNESS.trim());
    for ordinal in 1..=256 {
        let submission = format!("{source}\n/* authenticated submission {ordinal} */");
        assert_eq!(
            sweep
                .eval_string(&engine, &submission)
                .await
                .unwrap_or_else(|error| panic!(
                    "submission {ordinal} returned an outcome error: {error:#}"
                ))
                .as_deref(),
            Some("function"),
            "submission {ordinal}"
        );
    }
    sweep
        .finish(&engine)
        .expect("drain final authenticated 256-submission publications");
}

async fn decode_authenticated_record(
    engine: &HermesEngine,
    session: &ibex_runtime::engine::evaluation::ArmedSessionToken,
    request: SourceRequest,
    publications: &mut AuthenticatedPublicationTracker,
) -> Value {
    // Source-mode executors are controllers too: every authenticated boundary
    // must consume the bounded publication stream, including its error path.
    // @ref LLP 0025#11-delegated-obligations — OBL-UNIT-PUBLICATION
    publications
        .drain(engine, "output-shape file source before evaluation")
        .expect("drain output-shape file publications before evaluation");
    let evaluation = engine.evaluate_authenticated(session, request).await;
    publications
        .drain(engine, "output-shape file source after evaluation")
        .expect("drain output-shape file publications after evaluation");
    let evaluation = evaluation
        .expect("evaluate authenticated output-shape fixture");
    let AuthenticatedEvaluation::Value { display, receipt } = evaluation else {
        panic!("authenticated output-shape fixture returned no value: {evaluation:?}");
    };
    assert_eq!(display.kind, AuthenticatedDisplayKind::String);
    let encoded: String = serde_json::from_str(&display.text)
        .expect("authenticated output-shape fixture display must be a JSON string");
    let record = serde_json::from_str(&encoded)
        .expect("authenticated output-shape fixture returned invalid JSON");
    let release = engine
        .release_undisplayed_value(receipt.expect("authenticated fixture must retain a receipt"))
        .await;
    publications
        .drain(engine, "output-shape file source value release")
        .expect("drain output-shape file publications after value release");
    release
        .expect("release authenticated output-shape fixture value");
    record
}

async fn authenticated_file_record(
    engine: &HermesEngine,
    host: &crate::host::Host,
    entry_identity: &str,
    publications: &mut AuthenticatedPublicationTracker,
) -> Value {
    let vfs = host
        .virtual_file_system()
        .expect("create output-shape file VFS");
    let entry = vfs
        .resolve_root_file_url(entry_identity, None)
        .expect("resolve output-shape file entry");
    let session = host
        .mint_armed_session_token()
        .expect("mint output-shape file session");
    let mut sequence = ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone())
        .expect("create output-shape file submission sequence");
    let submission = sequence
        .mint_file(
            entry
                .logical_referrer()
                .expect("derive output-shape file logical referrer"),
            &["--output-shape-argument".to_owned()],
        )
        .expect("mint output-shape file submission");
    let request = host
        .authenticated_vfs_file_read(&vfs, entry, submission)
        .expect("read authenticated output-shape file")
        .into_capsule()
        .into_request()
        .expect("construct output-shape file request");
    let record = decode_authenticated_record(engine, &session, request, publications).await;
    let completion = engine.drive_authenticated_program_to_quiescence().await;
    publications
        .drain(engine, "output-shape file source event-loop drive")
        .expect("drain output-shape file publications after event-loop drive");
    completion
        .expect("drain output-shape file program");
    vfs.close();
    record
}

async fn evaluate_authenticated_inline(
    engine: &HermesEngine,
    host: &crate::host::Host,
    mode: &str,
    source: &[u8],
    publications: &mut AuthenticatedPublicationTracker,
) -> anyhow::Result<AuthenticatedEvaluation> {
    use capsec_semantics::model::{LogicalPath, LogicalRoot};

    let session = host.mint_armed_session_token()?;
    let mut sequence = ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone())?;
    let referrer = LogicalPath {
        root: LogicalRoot::Project,
        components: Vec::new(),
        host_bound: None,
    };
    let submission = match mode {
        "eval" => sequence.mint_eval(referrer),
        "program-stdin" => sequence.mint_stdin(referrer),
        "repl" => sequence.mint_repl(referrer),
        other => panic!("unsupported authenticated output-shape mode {other}"),
    }?;
    let request = submission
        .authorize_inline()
        .bind_bytes(source.to_vec())
        .into_request()?;
    publications.drain(
        engine,
        &format!("output-shape {mode} source before evaluation"),
    )?;
    let evaluation = engine.evaluate_authenticated(&session, request).await;
    publications.drain(
        engine,
        &format!("output-shape {mode} source after evaluation"),
    )?;
    evaluation
}

async fn authenticated_inline_record(
    engine: &HermesEngine,
    host: &crate::host::Host,
    mode: &str,
    publications: &mut AuthenticatedPublicationTracker,
) -> Value {
    let source = if mode == "program-stdin" {
        AUTHENTICATED_MODULE_INLINE_RECORD_SCRIPT
    } else {
        AUTHENTICATED_SCRIPT_INLINE_RECORD_SCRIPT
    };
    let evaluation =
        evaluate_authenticated_inline(engine, host, mode, source.as_bytes(), publications)
            .await
            .unwrap_or_else(|error| {
                panic!("evaluate authenticated output-shape {mode} inline record: {error:#}")
            });
    let AuthenticatedEvaluation::Value { display, receipt } = evaluation else {
        panic!("authenticated output-shape inline record returned no value: {evaluation:?}");
    };
    assert_eq!(display.kind, AuthenticatedDisplayKind::String);
    let encoded: String = serde_json::from_str(&display.text)
        .expect("authenticated output-shape inline display must be a JSON string");
    let record = serde_json::from_str(&encoded)
        .expect("authenticated output-shape inline record returned invalid JSON");
    let release = engine
        .release_undisplayed_value(
            receipt.expect("authenticated inline record must retain a receipt"),
        )
        .await;
    publications
        .drain(
            engine,
            &format!("output-shape {mode} source value release"),
        )
        .expect("drain authenticated output-shape inline value publications");
    release
        .expect("release authenticated output-shape inline record");
    record
}

async fn authenticated_script_import_meta_refusal(
    engine: &HermesEngine,
    host: &crate::host::Host,
    mode: &str,
    publications: &mut AuthenticatedPublicationTracker,
) -> Value {
    let error =
        evaluate_authenticated_inline(engine, host, mode, b"import.meta.url", publications)
            .await
            .expect_err("authenticated session script unexpectedly admitted import.meta");
    let reason = format!("{error:#}");
    assert_eq!(
        reason,
        "engine rejected the source request: import.meta is not allowed in a session script"
    );
    let error_code =
        ibex_runtime::engine::session_syntax::SyntaxFrontendError::ScriptImportMetaNotAllowed
            .code();
    assert_eq!(error_code, "IBEX_SCRIPT_IMPORT_META_NOT_ALLOWED");
    json!({
        "kind": "throw",
        "rawValueShape": "throw",
        "value": null,
        "errorCode": error_code
    })
}

fn raw_json_value(value: Value) -> Value {
    let shape = match &value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    };
    json!({
        "kind": "return",
        "rawValueShape": shape,
        "value": value,
        "errorCode": null
    })
}

fn cli_output_source(row: &Value) -> &Value {
    let source = &row["probe"]["sourceDescriptor"]["invocation"]["sourceDescriptor"];
    assert_eq!(source["kind"], "compiled-cli-surface");
    assert_eq!(row["probe"]["recordPath"], json!(["[[return]]"]));
    source
}

fn cli_source_ref(source: &Value) -> &str {
    source["sourceRefs"]
        .as_array()
        .and_then(|refs| refs.first())
        .and_then(Value::as_str)
        .expect("compiled CLI source has no source reference")
}

fn decode_cli_surface_component(component: &str) -> String {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = component.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = hex(bytes[index + 1]).expect("invalid CLI surface percent escape");
            let low = hex(bytes[index + 2]).expect("invalid CLI surface percent escape");
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).expect("CLI surface component is not UTF-8")
}

fn cli_surface_tail(surface_name: &str, marker: &str) -> String {
    decode_cli_surface_component(
        surface_name
            .rsplit_once(marker)
            .unwrap_or_else(|| panic!("CLI surface {surface_name} has no {marker} selector"))
            .1,
    )
}

fn clap_command_surface<'a>(
    snapshot: &'a crate::cli::tests::ClapManifestSnapshot,
    path: &str,
) -> &'a Value {
    snapshot
        .commands
        .iter()
        .find(|command| command["path"] == path)
        .unwrap_or_else(|| panic!("compiled Clap command {path} is absent"))
}

fn clap_argument_source_selector(source_ref: &str) -> Option<(&str, &str, &str)> {
    let body = source_ref.strip_prefix("runtime-surface.json#clapSurface.command:")?;
    if let Some((path, id)) = body.rsplit_once(":option:") {
        return Some((path, "options", id));
    }
    body.rsplit_once(":positional:")
        .map(|(path, id)| (path, "positionals", id))
}

fn clap_argument_surface<'a>(
    snapshot: &'a crate::cli::tests::ClapManifestSnapshot,
    source_ref: &str,
) -> &'a Value {
    let (path, collection, id) = clap_argument_source_selector(source_ref)
        .expect("compiled Clap argument source reference is malformed");
    clap_command_surface(snapshot, path)[collection]
        .as_array()
        .into_iter()
        .flatten()
        .find(|argument| argument["id"] == id)
        .unwrap_or_else(|| panic!("compiled Clap argument {id} on {path} is absent"))
}

fn clap_semantic_row<'a>(
    snapshot: &'a crate::cli::tests::ClapManifestSnapshot,
    collection: &str,
    command_path: &str,
    argument_id: &str,
) -> &'a Value {
    snapshot.semantic_relations[collection]
        .as_array()
        .into_iter()
        .flatten()
        .find(|row| row["commandPath"] == command_path && row["argumentId"] == argument_id)
        .unwrap_or_else(|| {
            panic!("compiled Clap semantic row {collection}:{command_path}:{argument_id} is absent")
        })
}

fn clap_output_value(snapshot: &crate::cli::tests::ClapManifestSnapshot, source: &Value) -> Value {
    let evidence_type = source["evidenceType"]
        .as_str()
        .expect("compiled CLI source has no evidence type");
    let surface_name = source["surfaceName"]
        .as_str()
        .expect("compiled CLI source has no surface name");
    let source_ref = cli_source_ref(source);
    match evidence_type {
        "cli-command-route" => {
            let path = source_ref
                .strip_prefix("runtime-surface.json#clapSurface.command:")
                .expect("compiled Clap command source reference is malformed");
            clap_command_surface(snapshot, path).clone()
        }
        "cli-option-route" | "cli-positional-route" => {
            clap_argument_surface(snapshot, source_ref).clone()
        }
        "cli-option-name" => {
            let argument = clap_argument_surface(snapshot, source_ref);
            let selected = cli_surface_tail(surface_name, ":");
            ["names", "visibleAliases", "hiddenAliases"]
                .into_iter()
                .flat_map(|field| {
                    argument[field]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                })
                .find(|name| *name == selected)
                .map(|name| Value::String(name.to_owned()))
                .unwrap_or_else(|| panic!("compiled Clap option name {selected} is absent"))
        }
        "cli-value-action" => {
            clap_argument_surface(snapshot, source_ref)["valueShape"]["action"].clone()
        }
        "cli-value-arity" => {
            let shape = &clap_argument_surface(snapshot, source_ref)["valueShape"];
            json!({
                "minValues": shape["minValues"].clone(),
                "maxValues": shape["maxValues"].clone(),
            })
        }
        "cli-value-name" => {
            let selected = cli_surface_tail(surface_name, ":value-name:");
            clap_argument_surface(snapshot, source_ref)["valueShape"]["valueNames"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .find(|value| *value == selected)
                .map(|value| Value::String(value.to_owned()))
                .unwrap_or_else(|| panic!("compiled Clap value name {selected} is absent"))
        }
        "cli-default-value" => {
            let selected = cli_surface_tail(surface_name, ":default:");
            clap_argument_surface(snapshot, source_ref)["valueShape"]["defaultValues"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .find(|value| *value == selected)
                .map(|value| Value::String(value.to_owned()))
                .unwrap_or_else(|| panic!("compiled Clap default value {selected} is absent"))
        }
        "cli-default-missing-value" => {
            let selected = cli_surface_tail(surface_name, ":default-missing:");
            clap_argument_surface(snapshot, source_ref)["valueShape"]["defaultMissingValues"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .find(|value| *value == selected)
                .map(|value| Value::String(value.to_owned()))
                .unwrap_or_else(|| {
                    panic!("compiled Clap default-missing value {selected} is absent")
                })
        }
        "cli-enum-value" => {
            let selected = cli_surface_tail(surface_name, ":enum:");
            clap_argument_surface(snapshot, source_ref)["valueShape"]["possibleValues"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|value| value["value"] == selected)
                .cloned()
                .unwrap_or_else(|| panic!("compiled Clap enum value {selected} is absent"))
        }
        "cli-enum-alias" => {
            let selector = surface_name
                .rsplit_once(":enum-alias:")
                .expect("compiled Clap enum alias selector is malformed")
                .1;
            let (canonical, alias) = selector
                .split_once(':')
                .expect("compiled Clap enum alias has no canonical value");
            let canonical = decode_cli_surface_component(canonical);
            let alias = decode_cli_surface_component(alias);
            clap_argument_surface(snapshot, source_ref)["valueShape"]["possibleValues"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|value| value["value"] == canonical)
                .and_then(|value| value["aliases"].as_array())
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .find(|value| *value == alias)
                .map(|value| Value::String(value.to_owned()))
                .unwrap_or_else(|| panic!("compiled Clap enum alias {alias} is absent"))
        }
        "cli-non-enumerated-parser" => {
            let body = source_ref
                .strip_prefix("runtime-surface.json#clapSurface.semanticRelations:parser:")
                .expect("compiled Clap parser source reference is malformed");
            let (head, parser_kind) = body
                .rsplit_once(':')
                .expect("compiled Clap parser has no parser kind");
            let (command_path, argument_id) = head
                .rsplit_once(':')
                .expect("compiled Clap parser has no argument ID");
            let row =
                clap_semantic_row(snapshot, "nonEnumeratedParsers", command_path, argument_id);
            assert_eq!(row["parserKind"], parser_kind);
            row.clone()
        }
        "cli-argument-conflict" => {
            let body = source_ref
                .strip_prefix(
                    "runtime-surface.json#clapSurface.semanticRelations:argument-conflict:",
                )
                .expect("compiled Clap conflict source reference is malformed");
            let (head, conflict_id) = body
                .rsplit_once(':')
                .expect("compiled Clap conflict has no peer argument");
            let (command_path, argument_id) = head
                .rsplit_once(':')
                .expect("compiled Clap conflict has no argument ID");
            clap_semantic_row(snapshot, "argumentConflicts", command_path, argument_id)
                ["conflictsWith"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .find(|value| *value == conflict_id)
                .map(|value| Value::String(value.to_owned()))
                .unwrap_or_else(|| panic!("compiled Clap conflict {conflict_id} is absent"))
        }
        other => panic!("unsupported compiled Clap evidence type {other}"),
    }
}

fn repl_keybinding_id(binding: &crate::repl_surface::KeybindingSpec) -> &'static str {
    use crate::repl_surface::KeybindingId;
    match binding.id {
        KeybindingId::Complete => "complete",
        KeybindingId::Interrupt => "interrupt",
        KeybindingId::Eof => "eof",
        KeybindingId::ReverseHistory => "reverse-history",
        KeybindingId::Suspend => "suspend",
    }
}

fn repl_output_value(source: &Value) -> Value {
    let evidence_type = source["evidenceType"]
        .as_str()
        .expect("compiled REPL source has no evidence type");
    let surface_name = source["surfaceName"]
        .as_str()
        .expect("compiled REPL source has no surface name");
    let source_ref = cli_source_ref(source);
    match evidence_type {
        "repl-command-route" => {
            let command_id = source_ref
                .strip_prefix("runtime-surface.json#replSurface.command:")
                .expect("compiled REPL command source reference is malformed");
            let command = crate::repl_surface::REPL_COMMANDS
                .iter()
                .find(|command| command.name.strip_prefix('.') == Some(command_id))
                .unwrap_or_else(|| panic!("compiled REPL command {command_id} is absent"));
            if surface_name.starts_with("repl-command-alias:") {
                let alias = cli_surface_tail(surface_name, ":");
                command
                    .aliases
                    .iter()
                    .copied()
                    .find(|candidate| *candidate == alias)
                    .map(|candidate| Value::String(candidate.to_owned()))
                    .unwrap_or_else(|| panic!("compiled REPL command alias {alias} is absent"))
            } else {
                Value::String(command.name.to_owned())
            }
        }
        "repl-command-recognition" => {
            use crate::repl_surface::CommandLine;
            match crate::repl_surface::classify_command_line(" \t.help  argument") {
                CommandLine::Known { command, argument } => json!({
                    "kind": "known",
                    "command": command.name,
                    "argument": argument,
                }),
                other => panic!("compiled REPL command recognizer returned {other:?}"),
            }
        }
        "repl-keybinding" => {
            let id = source_ref
                .strip_prefix("runtime-surface.json#keybindingSurface.binding:")
                .expect("compiled REPL keybinding source reference is malformed");
            let binding = crate::repl_surface::KEYBINDINGS
                .iter()
                .find(|binding| repl_keybinding_id(binding) == id)
                .unwrap_or_else(|| panic!("compiled REPL keybinding {id} is absent"));
            let resolved = crate::repl_surface::keybinding_for_bytes(binding.bytes)
                .expect("compiled REPL keybinding bytes do not resolve");
            assert_eq!(resolved.id, binding.id);
            json!({
                "id": repl_keybinding_id(binding),
                "display": binding.display,
                "bytes": binding.bytes,
                "action": format!("{:?}", binding.action),
                "countsAsEditorInput": binding.counts_as_editor_input,
                "help": binding.help,
            })
        }
        "repl-load-extension" => {
            let extension = source_ref
                .strip_prefix("runtime-surface.json#replSurface.loadExtension:")
                .expect("compiled REPL load-extension source reference is malformed");
            if extension == "default" {
                json!({
                    "extension": "default",
                    "disposition": format!(
                        "{:?}",
                        crate::repl_surface::classify_load_path("fixture.unknown")
                    ),
                    "errorCode": crate::repl_surface::LOAD_DEFAULT_ERROR_CODE,
                })
            } else {
                let route = crate::repl_surface::LOAD_EXTENSIONS
                    .iter()
                    .find(|route| route.extension == extension)
                    .unwrap_or_else(|| {
                        panic!("compiled REPL load extension {extension} is absent")
                    });
                assert_eq!(
                    crate::repl_surface::classify_load_path(&format!("fixture{extension}")),
                    route.disposition
                );
                json!({
                    "extension": route.extension,
                    "disposition": format!("{:?}", route.disposition),
                    "errorCode": route.error_code,
                })
            }
        }
        other => panic!("unsupported compiled REPL evidence type {other}"),
    }
}

fn clap_command_name_value(
    snapshot: &crate::cli::tests::ClapManifestSnapshot,
    source: &Value,
) -> Value {
    let name = source["surfaceName"]
        .as_str()
        .expect("compiled manifest command has no surface name");
    let path = format!("ibex {name}");
    let command = clap_command_surface(snapshot, &path);
    command["path"]
        .as_str()
        .and_then(|value| value.rsplit_once(' ').map(|(_, tail)| tail))
        .filter(|value| *value == name)
        .map(|value| Value::String(value.to_owned()))
        .unwrap_or_else(|| panic!("compiled Clap command name {name} is absent from {path}"))
}

fn namespace_command_name_value(source: &Value) -> Value {
    let name = source["surfaceName"]
        .as_str()
        .expect("compiled namespace command has no surface name");
    let source_ref = cli_source_ref(source);
    match source_ref {
        "runtime-surface.json#reservedCommands" => crate::RESERVED_RUNTIME_COMMANDS
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(actual_name, reason)| {
                json!({
                    "kind": "reserved-runtime",
                    "name": actual_name,
                    "reason": reason,
                })
            })
            .unwrap_or_else(|| panic!("reserved runtime command {name} is absent")),
        "runtime-surface.json#legacyProjectCommands" => crate::EXACT_PROJECT_COMMANDS
            .iter()
            .find(|candidate| **candidate == name)
            .map(|actual_name| {
                json!({
                    "kind": "exact-project",
                    "name": actual_name,
                })
            })
            .unwrap_or_else(|| panic!("legacy Exact project command {name} is absent")),
        other => panic!("unsupported namespace command source reference {other}"),
    }
}

fn product_ingress_route_observation(args: &[&str], stdin_is_tty: bool) -> Value {
    use clap::Parser as _;

    let cli = crate::cli::Cli::parse_from(args);
    let route = crate::terminal_session::selected_execution_route(&cli, stdin_is_tty)
        .expect("compiled product-ingress fixture selected no execution route");
    let owner = crate::authenticated_product_ingress(route)
        .expect("compiled product-ingress fixture selected no authenticated owner");
    json!({
        "entryKind": format!("{:?}", route.entry_kind),
        "mode": format!("{:?}", route.mode),
        "owner": owner.label(),
        "stdinIsTty": stdin_is_tty,
    })
}

fn product_ingress_output_value(source: &Value) -> Value {
    let surface_name = source["surfaceName"]
        .as_str()
        .expect("compiled product ingress has no surface name");
    let source_ref = cli_source_ref(source);
    match (surface_name, source_ref) {
        ("authenticated-one-shot-ingress", "src/bin/ibex/main.rs#eval_code") => {
            product_ingress_route_observation(&["ibex", "-e", "void 0"], false)
        }
        (
            "authenticated-direct-file-ingress",
            "src/bin/ibex/main.rs#run_file_with_execution_adapter",
        ) => product_ingress_route_observation(&["ibex", "app.ts"], false),
        ("authenticated-program-stdin-ingress", "src/bin/ibex/main.rs#run_stdin_program") => {
            product_ingress_route_observation(&["ibex"], false)
        }
        ("authenticated-repl-ingress", "src/bin/ibex/main.rs#start_repl") => {
            product_ingress_route_observation(&["ibex", "repl"], false)
        }
        ("implicit-no-file-dispatch", "src/bin/ibex/main.rs#run") => json!({
            "nonTty": product_ingress_route_observation(&["ibex"], false),
            "tty": product_ingress_route_observation(&["ibex"], true),
        }),
        other => panic!("unsupported compiled product-ingress route {other:?}"),
    }
}

fn compiled_cli_output_results(rows: &[Value]) -> Vec<Value> {
    let snapshot = crate::cli::tests::clap_manifest_snapshot();
    rows.iter()
        .map(|row| {
            let source = cli_output_source(row);
            let operation = row["probe"]["sourceDescriptor"]["invocation"]["operation"]["kind"]
                .as_str()
                .expect("compiled CLI operation has no kind");
            let value = match operation {
                "clap-surface-read" => clap_output_value(&snapshot, source),
                "clap-command-name-read" => clap_command_name_value(&snapshot, source),
                "namespace-command-name-read" => namespace_command_name_value(source),
                "product-ingress-route-read" => product_ingress_output_value(source),
                "repl-surface-read" => repl_output_value(source),
                other => panic!("unsupported compiled CLI operation {other}"),
            };
            compiled_runtime_return_record_result(row, raw_json_value(value))
        })
        .collect()
}

#[test]
fn compiled_cli_output_observes_authenticated_direct_file_route() {
    let source = json!({
        "surfaceName": "authenticated-direct-file-ingress",
        "sourceRefs": ["src/bin/ibex/main.rs#run_file_with_execution_adapter"],
    });
    assert_eq!(
        product_ingress_output_value(&source),
        json!({
            "entryKind": "File",
            "mode": "Program",
            "owner": "file-program",
            "stdinIsTty": false,
        })
    );
}

fn raw_absent() -> Value {
    json!({
        "kind": "absent",
        "rawValueShape": "absent",
        "value": null,
        "errorCode": null
    })
}

fn project_record_path(value: &Value, path: &str) -> Option<Value> {
    fn walk(value: &Value, components: &[&str]) -> Option<Value> {
        let Some((component, tail)) = components.split_first() else {
            return Some(value.clone());
        };
        let array_projection = component.ends_with("[]");
        let name = component.strip_suffix("[]").unwrap_or(component);
        let selected = if name.is_empty() {
            value
        } else {
            value.get(name)?
        };
        if array_projection && !tail.is_empty() {
            let values = selected
                .as_array()?
                .iter()
                .map(|item| walk(item, tail))
                .collect::<Option<Vec<_>>>()?;
            Some(Value::Array(values))
        } else {
            walk(selected, tail)
        }
    }
    let components = path.split('.').collect::<Vec<_>>();
    walk(value, &components)
}

fn authenticated_record_for_row<'a>(
    row: &Value,
    records: &'a std::collections::BTreeMap<String, Value>,
) -> &'a Value {
    let mode = row["key"]["mode"].as_str().expect("output mode");
    let selected = if mode != "all" {
        mode
    } else if row["key"]["sourceKind"] == "synthetic" {
        "eval"
    } else {
        "file"
    };
    records
        .get(selected)
        .unwrap_or_else(|| panic!("missing authenticated output-shape record for {selected}"))
}

fn authenticated_source_value(row: &Value, record: &Value) -> Option<Value> {
    let source = &row["probe"]["sourceDescriptor"];
    let surface = source["surfaceName"].as_str().expect("source surface name");
    let output = source["output"].as_str().expect("source output path");
    let alias = source["alias"].as_str().expect("source alias");
    let base = match surface {
        "__filename" => return record.get("filename").cloned(),
        "__dirname" => return record.get("dirname").cloned(),
        "global:process.argv" => record.get("processArgv")?,
        "global:Exact.argv" => record.get("exactArgv")?,
        "global:Bun.argv" => record.get("bunArgv")?,
        "global:Exact.main" => record.get("exactMain")?,
        "global:Bun.main" => record.get("bunMain")?,
        "module-loader-install" if output == "source-map:sourceURL" => {
            return record.get("sourceURL").cloned();
        }
        "module-loader-install" if output == "source-map:sources[]" => {
            return record.get("sourceMapSources").cloned();
        }
        "module-loader-install" if alias.starts_with("import.meta.") => record.get("importMeta")?,
        "module-loader-install" if alias.starts_with("module.__exactPackageRoot") => {
            if row["key"]["sourceKind"] == "package" {
                record.get("packageModule")?
            } else {
                record.get("projectModule")?
            }
        }
        "module-loader-install" if alias.starts_with("module.") => record.get("projectModule")?,
        other => panic!("unsupported authenticated output-shape surface {other}"),
    };
    if output == "[[return]]" || output == "array-items" {
        return Some(base.clone());
    }
    if let Some(path) = output.strip_prefix("field:") {
        return project_record_path(base, path);
    }
    if let Some(index) = output.strip_prefix("index:") {
        return base
            .as_array()
            .and_then(|values| values.get(index.parse::<usize>().ok()?))
            .cloned();
    }
    panic!("unsupported authenticated output record path {output}")
}

fn authenticated_source_result(
    row: &Value,
    records: &std::collections::BTreeMap<String, Value>,
) -> Value {
    let record = authenticated_record_for_row(row, records);
    if source_surface_name(row) == "module-loader-install" {
        let observation = match row["key"]["alias"].as_str() {
            Some("module.children") => record["projectModule"].get("childrenObservation"),
            Some("module.parent") => record["projectModule"].get("parentObservation"),
            _ => None,
        };
        if let Some(raw) = observation {
            return return_record_result(row, raw.clone());
        }
    }
    let raw = authenticated_source_value(row, record)
        .map(raw_json_value)
        .unwrap_or_else(raw_absent);
    return_record_result(row, raw)
}

fn is_authenticated_source_surface(row: &Value) -> bool {
    let surface = source_surface_name(row);
    matches!(
        surface,
        "__filename"
            | "__dirname"
            | "global:process.argv"
            | "global:Exact.argv"
            | "global:Bun.argv"
            | "global:Exact.main"
            | "global:Bun.main"
            | "module-loader-install"
    ) && !(surface == "module-loader-install" && row["key"]["sourceKind"] == "runtime-owned")
}

fn is_script_import_meta_surface(row: &Value) -> bool {
    source_surface_name(row) == "module-loader-install"
        && row["key"]["alias"] == "import.meta.url"
        && matches!(row["key"]["mode"].as_str(), Some("eval") | Some("repl"))
}

fn output_shape_path_components(path: &std::path::Path) -> Vec<Value> {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Prefix(prefix) => Some(json!({
                "encoding": "utf8",
                "value": prefix.as_os_str().to_string_lossy(),
            })),
            std::path::Component::Normal(value) => Some(json!({
                "encoding": "utf8",
                "value": value.to_str().expect("output-shape package path must be UTF-8"),
            })),
            std::path::Component::RootDir | std::path::Component::CurDir => None,
            std::path::Component::ParentDir => {
                panic!("output-shape package path must be canonical")
            }
        })
        .collect()
}

fn output_shape_object_identity(path: &std::path::Path) -> Value {
    let metadata = std::fs::metadata(path).expect("identify output-shape package root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        json!({
            "platform": if cfg!(any(target_os = "macos", target_os = "ios")) {
                "apple"
            } else if cfg!(target_os = "android") {
                "android"
            } else {
                "unix"
            },
            "volume": format!("dev:{}", metadata.dev()),
            "file": format!("ino:{}", metadata.ino()),
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        json!({
            "platform": "windows",
            "volume": format!("volume:{}", metadata.volume_serial_number().unwrap_or(0)),
            "file": format!("file:{}", metadata.file_index().unwrap_or(0)),
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        panic!("output-shape package object identity is unsupported on this target")
    }
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_output_shape_sweep_batch() {
    let Ok(plan_path) = std::env::var("IBEX_CAPSEC_OUTPUT_SHAPE_PLAN") else {
        eprintln!("IBEX_CAPSEC_OUTPUT_SHAPE_PLAN is unset; skipping output-shape sweep");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_OUTPUT_SHAPE_BATCH_OUTPUT")
        .expect("output-shape sweep requires an owned batch output path");
    let plan_path =
        std::fs::canonicalize(plan_path).expect("canonicalize output-shape sweep plan path");
    let plan = read_plan(&plan_path);
    let rows = plan["rows"]
        .as_array()
        .expect("output-shape sweep plan rows")
        .clone();

    let descriptor_rows = rows
        .iter()
        .filter(|row| row["probe"]["kind"] == "loaded-engine-descriptor")
        .cloned()
        .collect::<Vec<_>>();
    let compiled_runtime_rows = rows
        .iter()
        .filter(|row| row["probe"]["kind"] == "compiled-runtime-return-record")
        .cloned()
        .collect::<Vec<_>>();
    let structured_rows = rows
        .iter()
        .filter(|row| row["probe"]["kind"] == "loaded-engine-return-record")
        .collect::<Vec<_>>();
    assert_eq!(
        descriptor_rows.len() + compiled_runtime_rows.len() + structured_rows.len(),
        rows.len(),
        "every authenticated plan row must select exactly one supported probe family"
    );
    let plan_keys = rows
        .iter()
        .map(|row| serde_json::to_string(&row["key"]).expect("serialize plan key"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        plan_keys.len(),
        rows.len(),
        "authenticated plan must contain exactly one row per output key"
    );
    let compiled_ids = compiled_surface_ids();
    let plan_surface_ids = plan["surfaceAccountIds"]
        .as_array()
        .expect("v2 plan must bind every catalog surface account")
        .iter()
        .map(|surface_id| {
            surface_id
                .as_str()
                .expect("plan surface account has no stable ID")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        plan_surface_ids, compiled_ids,
        "catalog surface accounts and compiled coverage registry must join bidirectionally"
    );
    let compiled_runtime_observations = compiled_cli_output_results(&compiled_runtime_rows);
    assert_eq!(
        compiled_runtime_observations.len(),
        compiled_runtime_rows.len(),
        "compiled-runtime executor must observe every authored row"
    );

    let _lock = hermes_engine_test_lock().lock().await;
    let project = tempfile::tempdir().expect("create output-shape fixture project");
    let project_root =
        std::fs::canonicalize(project.path()).expect("canonicalize output-shape fixture project");
    std::fs::create_dir_all(project_root.join("node_modules/image-lib"))
        .expect("create output-shape package fixture");
    std::fs::create_dir_all(project_root.join("watch-tree"))
        .expect("create output-shape recursive-watch fixture");
    std::fs::write(
        project_root.join("entry.mjs"),
        r#"function firstStackSource(stack) {
  var lines = String(stack || '').split('\n');
  for (var index = 1; index < lines.length; index++) {
    var match = lines[index].match(/(?:\(|at\s+)([^()\s]+):\d+:\d+\)?$/);
    if (match) return match[1];
  }
}
var source = firstStackSource(new Error('output-shape-file-source').stack);
JSON.stringify({
  processArgv: process.argv,
  exactArgv: typeof Exact === 'undefined' ? undefined : Exact.argv,
  bunArgv: typeof Bun === 'undefined' ? undefined : Bun.argv,
  exactMain: typeof Exact === 'undefined' ? undefined : Exact.main,
  bunMain: typeof Bun === 'undefined' ? undefined : Bun.main,
  exactFile: typeof Exact === 'undefined' ? undefined : Exact.file('/project/output-shape.js'),
  bunFile: typeof Bun === 'undefined' ? undefined : Bun.file('/project/output-shape.js'),
  importMeta: {
    url: import.meta.url,
    file: import.meta.file,
    filename: import.meta.filename,
    dirname: import.meta.dirname,
    dir: import.meta.dir,
    path: import.meta.path
  },
  sourceURL: source,
  sourceMapSources: [source]
});
"#,
    )
    .expect("write output-shape entry fixture");
    std::fs::write(
        project_root.join("module-probe.cjs"),
        r#"function outputShapeObservation(read) {
  var value;
  try {
    value = read();
  } catch (error) {
    var message = String(error && error.message || error || '');
    var code = error && typeof error.code === 'string' && error.code
      ? error.code
      : (/closed|not available|unsupported in armed/i.test(message)
          ? 'ERR_IBEX_CLOSED_SURFACE'
          : 'ERR_IBEX_UNCLASSIFIED_' + String(error && error.name || 'ERROR')
              .replace(/[^A-Za-z0-9]+/g, '_').toUpperCase());
    return { kind: 'throw', rawValueShape: 'throw', value: null, errorCode: code };
  }
  var shape = value === null ? 'null' : (Array.isArray(value) ? 'array' : typeof value);
  var encoded = null;
  if (shape !== 'undefined' && shape !== 'function' && shape !== 'symbol') {
    try { encoded = JSON.parse(JSON.stringify(value)); } catch (_) {}
  }
  return {
    kind: 'return',
    rawValueShape: shape,
    value: encoded,
    errorCode: null
  };
}
var packageModule = require('image-lib');
var projectModule = {
  filename: __filename,
  dirname: __dirname,
  id: module.id,
  path: module.path,
  paths: module.paths,
  __exactPackageRoot: module.__exactPackageRoot,
  childrenObservation: outputShapeObservation(function () { return module.children; }),
  parentObservation: outputShapeObservation(function () { return module.parent; })
};
module.exports = JSON.stringify({
  projectModule: projectModule,
  packageModule: packageModule
});
"#,
    )
    .expect("write output-shape CommonJS module fixture");
    std::fs::write(
        project_root.join("output-shape.js"),
        "module.exports = 'shape';\n",
    )
    .expect("write output-shape file fixture");
    std::fs::write(
        project_root.join("node_modules/image-lib/package.json"),
        r#"{"name":"image-lib","version":"2.4.1","main":"index.js"}"#,
    )
    .expect("write output-shape package manifest");
    std::fs::write(
        project_root.join("node_modules/image-lib/index.js"),
        r#"globalThis.__ibexOutputShapePackageModule = {
  __exactPackageRoot: module.__exactPackageRoot
};
module.exports = globalThis.__ibexOutputShapePackageModule;
"#,
    )
    .expect("write output-shape package source");
    let package_root = project_root.join("node_modules/image-lib");
    let package_integrity = crate::module_loader::package_tree_integrity(&package_root)
        .expect("digest output-shape package fixture");
    let package_principal = json!({
        "kind": "package",
        "name": "image-lib",
        "integrity": package_integrity,
        "locator": "image-lib@2.4.1",
    });
    let package_components = output_shape_path_components(&package_root);
    let package_object = output_shape_object_identity(&package_root);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("output-shape.js", project_root.join("mapped-link"))
            .expect("create mapped output-shape symlink");
        std::os::unix::fs::symlink("/etc/passwd", project_root.join("unmappable-link"))
            .expect("create unmappable output-shape symlink");
    }

    let private_resolver_rows = rows
        .iter()
        .filter(|row| {
            row["probe"]["kind"] == "loaded-engine-return-record"
                && is_resolver_surface(row)
                && row["key"]["returnVariant"] == "private-compat"
        })
        .cloned()
        .collect::<Vec<_>>();
    let armed_resolver_rows = rows
        .iter()
        .filter(|row| {
            row["probe"]["kind"] == "loaded-engine-return-record"
                && is_resolver_surface(row)
                && row["key"]["returnVariant"] != "private-compat"
        })
        .cloned()
        .collect::<Vec<_>>();
    let loaded_realm_rows = rows
        .iter()
        .filter(|row| {
            row["probe"]["kind"] == "loaded-engine-return-record"
                && is_generic_loaded_realm_surface(row)
        })
        .cloned()
        .collect::<Vec<_>>();
    let private_vfs_rows = rows
        .iter()
        .filter(|row| {
            row["probe"]["kind"] == "loaded-engine-return-record"
                && is_private_vfs_surface(row)
                && row["key"]["mode"] == "private-native"
                && row["key"]["returnVariant"] == "success"
        })
        .cloned()
        .collect::<Vec<_>>();
    let authenticated_source_rows = rows
        .iter()
        .filter(|row| {
            row["probe"]["kind"] == "loaded-engine-return-record"
                && is_authenticated_source_surface(row)
        })
        .cloned()
        .collect::<Vec<_>>();
    let safe_throw_metadata_rows = rows
        .iter()
        .filter(|row| {
            row["probe"]["kind"] == "loaded-engine-return-record"
                && is_safe_throw_metadata_surface(row)
        })
        .cloned()
        .collect::<Vec<_>>();
    let authored_builtin_rows = rows
        .iter()
        .filter(|row| {
            row["probe"]["kind"] == "loaded-engine-return-record"
                && is_authored_builtin_surface(row)
        })
        .cloned()
        .collect::<Vec<_>>();
    let global_accessor_rows = rows
        .iter()
        .filter(|row| {
            row["probe"]["kind"] == "loaded-engine-return-record" && is_global_accessor_surface(row)
        })
        .cloned()
        .collect::<Vec<_>>();
    let global_callable_rows = rows
        .iter()
        .filter(|row| {
            row["probe"]["kind"] == "loaded-engine-return-record"
                && global_callable_batch::is_surface(row)
        })
        .cloned()
        .collect::<Vec<_>>();
    let native_freeze_rows = rows
        .iter()
        .filter(|row| {
            row["probe"]["kind"] == "loaded-engine-return-record"
                && native_freeze_batch::is_surface(row)
        })
        .cloned()
        .collect::<Vec<_>>();
    let closed_control_rows = rows
        .iter()
        .filter(|row| {
            row["probe"]["kind"] == "loaded-engine-return-record"
                && row["probe"]["sourceDescriptor"]["kind"] == "authored-closed-control-output"
        })
        .cloned()
        .collect::<Vec<_>>();
    let builtin_noncap_closed_rows = rows
        .iter()
        .filter(|row| super::capsec_builtin_noncap_closed_output_batch::is_surface(row))
        .cloned()
        .collect::<Vec<_>>();
    let builtin_effects_rows = rows
        .iter()
        .filter(|row| super::capsec_builtin_effects_output_batch::is_surface(row))
        .cloned()
        .collect::<Vec<_>>();
    let routed_structured_keys = private_resolver_rows
        .iter()
        .chain(&armed_resolver_rows)
        .chain(&loaded_realm_rows)
        .chain(&private_vfs_rows)
        .chain(&authenticated_source_rows)
        .chain(&safe_throw_metadata_rows)
        .chain(&authored_builtin_rows)
        .chain(&global_accessor_rows)
        .chain(&global_callable_rows)
        .chain(&native_freeze_rows)
        .chain(&closed_control_rows)
        .chain(&builtin_noncap_closed_rows)
        .chain(&builtin_effects_rows)
        .map(|row| serde_json::to_string(&row["key"]).expect("serialize routed key"))
        .collect::<BTreeSet<_>>();
    let expected_structured_keys = structured_rows
        .iter()
        .map(|row| serde_json::to_string(&row["key"]).expect("serialize structured key"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        routed_structured_keys.len(),
        private_resolver_rows.len()
            + armed_resolver_rows.len()
            + loaded_realm_rows.len()
            + private_vfs_rows.len()
            + authenticated_source_rows.len()
            + safe_throw_metadata_rows.len()
            + authored_builtin_rows.len()
            + global_accessor_rows.len()
            + global_callable_rows.len()
            + native_freeze_rows.len()
            + closed_control_rows.len()
            + builtin_noncap_closed_rows.len()
            + builtin_effects_rows.len(),
        "loaded-engine route families must not overlap"
    );
    assert_eq!(
        routed_structured_keys, expected_structured_keys,
        "loaded-engine route families must cover the structured plan exactly"
    );

    // Raw resolver bridges are reachable only while the trusted bootstrap is
    // constructing its private loader. Armed lockdown deletes them before
    // authenticated project source can execute, while the private-compat
    // branch exists only in an unarmed diagnostic runtime. Neither route is
    // authenticated output evidence, so retain every row as an explicit
    // residual instead of reopening the bare pre-bootstrap evaluator.
    // @ref LLP 0023#acceptance-criteria — resolver bridges are
    // unreachable from post-arming JavaScript.
    let resolver_unexercisable = private_resolver_rows
        .iter()
        .chain(&armed_resolver_rows)
        .map(resolver_unexercisable)
        .collect::<Vec<_>>();

    let module_specifiers = descriptor_rows
        .iter()
        .flat_map(|row| {
            row["probe"]["sourceDescriptor"]["moduleSpecifiers"]
                .as_array()
                .into_iter()
                .flatten()
        })
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .chain(authored_builtin_rows.iter().map(|row| {
            authored_builtin_invocation(row)["moduleSpecifier"]
                .as_str()
                .expect("authored builtin invocation has no module specifier")
                .to_owned()
        }))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    let (host, digest) = build_armed_test_host_custom(
        Some(&project_root),
        true,
        true,
        true,
        Vec::new(),
        None,
        |snapshot| {
            snapshot["bootstrapCompatibilityModes"] = json!(["bun"]);
            snapshot["principals"][0]["imports"]["builtins"] =
                Value::Array(module_specifiers.clone());
            snapshot["entry"] = json!({
                "kind": "repl",
                "identity": "ibex:repl",
                "mode": "interactive"
            });
        },
    );
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest))
        .expect("create exact output-shape Hermes runtime");
    let native_freeze_results = native_freeze_batch::results(&engine, &native_freeze_rows).await;
    engine
        .load_runtime()
        .await
        .expect("load exact output-shape runtime");
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before output-shape sweep");
    let mut authenticated_sweep = AuthenticatedSweep::new(&host);

    let (descriptor_results, descriptor_unexercisable) =
        loaded_descriptor_results(&engine, &mut authenticated_sweep, &descriptor_rows).await;
    let (authored_builtin_observations, authored_builtin_unexercisable) =
        authored_builtin_results(&engine, &mut authenticated_sweep, &authored_builtin_rows).await;
    let (global_accessor_observations, global_accessor_unexercisable) =
        global_accessor_results(&engine, &mut authenticated_sweep, &global_accessor_rows).await;
    let (global_callable_observations, global_callable_unexercisable) =
        global_callable_batch::results(&engine, &mut authenticated_sweep, &global_callable_rows)
            .await;
    let loaded_realm_results =
        loaded_structured_results(&engine, &mut authenticated_sweep, &loaded_realm_rows).await;
    let private_vfs_results = private_vfs_results(&engine, &private_vfs_rows).await;
    authenticated_sweep
        .finish(&engine)
        .expect("drain final authenticated output-shape publications");
    drop(authenticated_sweep);
    drop(engine);
    drop(_reset);

    let mut authenticated_records = std::collections::BTreeMap::new();
    let mut authenticated_import_meta_refusals = std::collections::BTreeMap::new();
    for mode in [
        "file",
        "commonjs-file",
        "eval-import-meta-refusal",
        "eval",
        "program-stdin",
        "repl-import-meta-refusal",
        "repl",
    ] {
        let source_mode = mode.strip_suffix("-import-meta-refusal").unwrap_or(mode);
        let (entry_kind, entry_identity, execution_mode) = match mode {
            "file" => ("file", "file:///project/entry.mjs", "program"),
            "commonjs-file" => ("file", "file:///project/module-probe.cjs", "program"),
            "eval" | "eval-import-meta-refusal" => ("eval", "ibex:eval", "one-shot"),
            "program-stdin" => ("stdin", "ibex:stdin", "program"),
            "repl" | "repl-import-meta-refusal" => ("repl", "ibex:repl", "interactive"),
            _ => unreachable!(),
        };
        let (mode_host, mode_digest) = build_armed_test_host_custom(
            Some(&project_root),
            true,
            true,
            true,
            Vec::new(),
            None,
            |snapshot| {
                snapshot["bootstrapCompatibilityModes"] = json!(["bun"]);
                snapshot["principals"][0]["imports"]["builtins"] =
                    Value::Array(module_specifiers.clone());
                snapshot["principals"][0]["imports"]["packages"] = json!(["image-lib@2.4.1"]);
                snapshot["principals"][1]["principal"] = package_principal.clone();
                snapshot["packageGraph"]["nodes"][0]["principal"] = package_principal.clone();
                snapshot["packageGraph"]["importEdges"][0]["imported"] = package_principal.clone();
                snapshot["rootBindings"][0] = json!({
                    "logicalRoot": "package",
                    "owner": package_principal.clone(),
                    "hostPath": {
                        "root": "absolute",
                        "components": package_components.clone(),
                        "hostBound": true,
                    },
                    "object": package_object.clone(),
                });
                snapshot["entry"] = json!({
                    "kind": entry_kind,
                    "identity": entry_identity,
                    "mode": execution_mode
                });
            },
        );
        assert_ne!(crate::host::abi::install_host(mode_host.clone()), 0);
        let reset = HostResetGuard;
        let mode_engine = HermesEngine::new_with_armed_snapshot(Some(&mode_digest))
            .expect("create authenticated output-shape mode runtime");
        mode_engine
            .load_runtime()
            .await
            .expect("load authenticated output-shape mode runtime");
        assert_eq!(
            HermesEngine::loaded_engine_identity()
                .expect("attest authenticated output-shape mode engine"),
            identity_before
        );
        let mut mode_publications = AuthenticatedPublicationTracker::default();
        if mode.ends_with("-import-meta-refusal") {
            let reason = authenticated_script_import_meta_refusal(
                &mode_engine,
                &mode_host,
                source_mode,
                &mut mode_publications,
            )
            .await;
            assert!(authenticated_import_meta_refusals
                .insert(source_mode.to_owned(), reason)
                .is_none());
        } else {
            let record = if entry_kind == "file" {
                authenticated_file_record(
                    &mode_engine,
                    &mode_host,
                    entry_identity,
                    &mut mode_publications,
                )
                .await
            } else {
                authenticated_inline_record(
                    &mode_engine,
                    &mode_host,
                    source_mode,
                    &mut mode_publications,
                )
                .await
            };
            authenticated_records.insert(mode.to_owned(), record);
        }
        let finish_context = format!("output-shape {mode} source-mode completion");
        mode_publications
            .drain(&mode_engine, &finish_context)
            .expect("drain final output-shape source-mode publications");
        mode_publications
            .require_no_due_schedules(&finish_context)
            .expect("finish output-shape source mode without due timers");
        drop(mode_publications);
        drop(mode_engine);
        drop(reset);
    }
    let commonjs_file_record = authenticated_records
        .remove("commonjs-file")
        .expect("authenticated CommonJS metadata record");
    let file_record = authenticated_records
        .get_mut("file")
        .and_then(Value::as_object_mut)
        .expect("authenticated ESM file record");
    file_record.insert(
        "projectModule".to_owned(),
        commonjs_file_record["projectModule"].clone(),
    );
    file_record.insert(
        "packageModule".to_owned(),
        commonjs_file_record["packageModule"].clone(),
    );
    file_record.insert(
        "filename".to_owned(),
        commonjs_file_record["projectModule"]["filename"].clone(),
    );
    file_record.insert(
        "dirname".to_owned(),
        commonjs_file_record["projectModule"]["dirname"].clone(),
    );
    let mut authenticated_source_results = authenticated_source_rows
        .iter()
        .filter(|row| !is_script_import_meta_surface(row))
        .map(|row| authenticated_source_result(row, &authenticated_records))
        .collect::<Vec<_>>();
    authenticated_source_results.extend(
        authenticated_source_rows
            .iter()
            .filter(|row| is_script_import_meta_surface(row))
            .map(|row| {
                let mode = match row["key"]["mode"].as_str() {
                    Some(mode @ ("eval" | "repl")) => mode,
                    other => panic!("unsupported script import.meta mode {other:?}"),
                };
                let raw = authenticated_import_meta_refusals
                    .get(mode)
                    .unwrap_or_else(|| {
                        panic!("missing authenticated import.meta refusal for {mode}")
                    });
                return_record_result(row, raw.clone())
            }),
    );
    let safe_throw_metadata_results = if safe_throw_metadata_rows.is_empty() {
        Vec::new()
    } else {
        for row in &safe_throw_metadata_rows {
            assert_eq!(row["probe"]["fixtureId"], "safe-throw-metadata");
            assert_eq!(row["probe"]["recordPath"], json!(["[[return]]"]));
            assert_eq!(
                row["probe"]["sourceDescriptor"]["kind"],
                "native-abi-fixture"
            );
            assert_eq!(
                row["probe"]["sourceDescriptor"]["symbol"],
                "ex_hermes_value_safe_throw_metadata"
            );
            assert_eq!(row["probe"]["sourceDescriptor"]["variant"], "rooted-error");
        }
        let (safe_host, safe_digest) = build_armed_test_host_custom(
            Some(&project_root),
            true,
            true,
            true,
            Vec::new(),
            None,
            |snapshot| {
                snapshot["bootstrapCompatibilityModes"] = json!(["bun"]);
                snapshot["entry"] = json!({
                    "kind": "repl",
                    "identity": "ibex:repl",
                    "mode": "interactive"
                });
            },
        );
        assert_ne!(crate::host::abi::install_host(safe_host.clone()), 0);
        let reset = HostResetGuard;
        let safe_engine = HermesEngine::new_with_armed_snapshot(Some(&safe_digest))
            .expect("create safe-throw-metadata output-shape runtime");
        safe_engine
            .load_runtime()
            .await
            .expect("load safe-throw-metadata output-shape runtime");
        assert_eq!(
            HermesEngine::loaded_engine_identity()
                .expect("attest safe-throw-metadata output-shape engine"),
            identity_before
        );
        let mut safe_publications = AuthenticatedPublicationTracker::default();
        safe_publications
            .drain(&safe_engine, "safe-throw metadata before execution")
            .expect("drain safe-throw publications before execution");
        let observation = loaded_engine_safe_throw_metadata_observation(
            &safe_engine,
            &safe_host,
            &mut safe_publications,
        )
        .await;
        let finish_context = "safe-throw metadata execution completion";
        safe_publications
            .drain(&safe_engine, finish_context)
            .expect("drain safe-throw publications after execution");
        safe_publications
            .require_no_due_schedules(finish_context)
            .expect("finish safe-throw execution without due timers");
        let results = safe_throw_metadata_rows
            .iter()
            .map(|row| return_record_result(row, raw_json_value(observation.clone())))
            .collect::<Vec<_>>();
        drop(safe_publications);
        drop(safe_engine);
        drop(reset);
        results
    };
    let (closed_control_observations, closed_control_unexercisable) =
        super::capsec_closed_control_output_batch::execute_closed_control_output_rows(
            &closed_control_rows,
        )
        .await;
    let (builtin_noncap_closed_observations, builtin_noncap_closed_unexercisable) =
        super::capsec_builtin_noncap_closed_output_batch::execute_builtin_noncap_closed_output_rows(
            &builtin_noncap_closed_rows,
        )
        .await;
    let (builtin_effects_observations, builtin_effects_unexercisable) =
        super::capsec_builtin_effects_output_batch::execute_builtin_effects_output_rows(
            &builtin_effects_rows,
        )
        .await;

    let compiled_runtime_by_key = compiled_runtime_observations
        .into_iter()
        .map(|result| {
            let key = serde_json::to_string(&result["key"])
                .expect("serialize compiled-runtime result key");
            (key, result)
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let expected_compiled_runtime_keys = compiled_runtime_rows
        .iter()
        .map(|row| serde_json::to_string(&row["key"]).expect("serialize compiled-runtime plan key"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        compiled_runtime_by_key
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        expected_compiled_runtime_keys,
        "compiled-runtime observations must join the authored plan exactly"
    );
    let descriptor_by_key = descriptor_results
        .into_iter()
        .map(|result| {
            let key =
                serde_json::to_string(&result["key"]).expect("serialize descriptor result key");
            (key, result)
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let descriptor_unexercisable_keys = descriptor_unexercisable
        .iter()
        .map(|result| {
            serde_json::to_string(&result["key"]).expect("serialize unexercisable descriptor key")
        })
        .collect::<BTreeSet<_>>();
    let structured_by_key = loaded_realm_results
        .into_iter()
        .chain(private_vfs_results)
        .chain(authenticated_source_results)
        .chain(safe_throw_metadata_results)
        .chain(authored_builtin_observations)
        .chain(global_accessor_observations)
        .chain(global_callable_observations)
        .chain(native_freeze_results)
        .chain(closed_control_observations)
        .chain(builtin_noncap_closed_observations)
        .chain(builtin_effects_observations)
        .map(|result| {
            let key =
                serde_json::to_string(&result["key"]).expect("serialize structured result key");
            (key, result)
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let structured_unexercisable_keys = resolver_unexercisable
        .iter()
        .chain(&authored_builtin_unexercisable)
        .chain(&global_accessor_unexercisable)
        .chain(&global_callable_unexercisable)
        .chain(&closed_control_unexercisable)
        .chain(&builtin_noncap_closed_unexercisable)
        .chain(&builtin_effects_unexercisable)
        .map(|result| {
            serde_json::to_string(&result["key"]).expect("serialize unexercisable structured key")
        })
        .collect::<BTreeSet<_>>();
    let structured_accounted_keys = structured_by_key
        .keys()
        .cloned()
        .chain(structured_unexercisable_keys.iter().cloned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        structured_accounted_keys, expected_structured_keys,
        "loaded-engine structured observations and explicit residuals must join the structured plan exactly"
    );
    let mut results = Vec::with_capacity(rows.len());
    let mut unexercisable = descriptor_unexercisable;
    unexercisable.extend(resolver_unexercisable);
    unexercisable.extend(authored_builtin_unexercisable);
    unexercisable.extend(global_accessor_unexercisable);
    unexercisable.extend(global_callable_unexercisable);
    unexercisable.extend(closed_control_unexercisable);
    unexercisable.extend(builtin_noncap_closed_unexercisable);
    unexercisable.extend(builtin_effects_unexercisable);
    for row in &rows {
        match row["probe"]["kind"].as_str() {
            Some("compiled-runtime-return-record") => {
                let key = serde_json::to_string(&row["key"])
                    .expect("serialize compiled-runtime plan key");
                results.push(
                    compiled_runtime_by_key
                        .get(&key)
                        .unwrap_or_else(|| panic!("compiled-runtime executor omitted {key}"))
                        .clone(),
                );
            }
            Some("loaded-engine-descriptor") => {
                let key =
                    serde_json::to_string(&row["key"]).expect("serialize descriptor plan key");
                if let Some(result) = descriptor_by_key.get(&key) {
                    results.push(result.clone());
                } else {
                    assert!(
                        descriptor_unexercisable_keys.contains(&key),
                        "descriptor executor omitted {key} without marking it unexercisable"
                    );
                }
            }
            Some("loaded-engine-return-record") => {
                let key =
                    serde_json::to_string(&row["key"]).expect("serialize structured plan key");
                if let Some(result) = structured_by_key.get(&key) {
                    results.push(result.clone());
                } else {
                    assert!(
                        structured_unexercisable_keys.contains(&key),
                        "structured executor omitted {key} without marking it unexercisable"
                    );
                }
            }
            other => panic!("unsupported output-shape probe kind {other:?}"),
        }
    }

    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes after output-shape sweep");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after output-shape sweep");

    let batch = json!({
        "outputShapeExecutorBatchSchema": BATCH_SCHEMA,
        "profile": "ibex/capsec/1",
        "executor": EXECUTOR,
        "sourceRevision": plan["sourceRevision"].clone(),
        "sourceTreeDigest": plan["sourceTreeDigest"].clone(),
        "target": plan["target"].clone(),
        "catalogKeyDigest": plan["catalogKeyDigest"].clone(),
        "sweepPlanDigest": plan["sweepPlanDigest"].clone(),
        "loadedEngineIdentity": serde_json::to_value(identity_before)
            .expect("serialize loaded engine identity"),
        "compiledRegistrarIds": compiled_ids,
        "results": results,
        "unexercisable": unexercisable,
    });
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .expect("create owned output-shape executor batch");
    serde_json::to_writer_pretty(&mut output, &batch)
        .expect("serialize output-shape executor batch");
    output
        .write_all(b"\n")
        .expect("finish output-shape executor batch");
    output.sync_all().expect("sync output-shape executor batch");
}
