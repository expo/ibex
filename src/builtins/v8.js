/* Try to get real memory stats from process.memoryUsage() if available */
function _getMemStats() {
  try {
    if (typeof process !== 'undefined' && typeof process.memoryUsage === 'function') {
      return process.memoryUsage();
    }
  } catch (e) {}
  return { rss: 0, heapTotal: 0, heapUsed: 0, external: 0, arrayBuffers: 0 };
}

module.exports = {
  getHeapStatistics: function() {
    var mem = _getMemStats();
    var heapTotal = mem.heapTotal || 0;
    var heapUsed = mem.heapUsed || 0;
    var external = mem.external || 0;
    /* Estimate heap limit as 4x current total (Hermes doesn't expose this directly) */
    var heapLimit = Math.max(heapTotal * 4, 256 * 1024 * 1024);
    return {
      total_heap_size: heapTotal,
      total_heap_size_executable: 0,
      total_physical_size: heapTotal,
      total_available_size: heapLimit - heapUsed,
      used_heap_size: heapUsed,
      heap_size_limit: heapLimit,
      malloced_memory: heapUsed,
      peak_malloced_memory: heapUsed,
      does_zap_garbage: 0,
      number_of_native_contexts: 1,
      number_of_detached_contexts: 0,
      total_global_handles_size: 8192,
      used_global_handles_size: 4096,
      external_memory: external
    };
  },
  getHeapSpaceStatistics: function() {
    var mem = _getMemStats();
    var heapTotal = mem.heapTotal || 0;
    var heapUsed = mem.heapUsed || 0;
    return [
      { space_name: 'new_space', space_size: Math.floor(heapTotal * 0.25), space_used_size: Math.floor(heapUsed * 0.2), space_available_size: Math.floor(heapTotal * 0.05), physical_space_size: Math.floor(heapTotal * 0.25) },
      { space_name: 'old_space', space_size: Math.floor(heapTotal * 0.6), space_used_size: Math.floor(heapUsed * 0.7), space_available_size: Math.floor(heapTotal * 0.1), physical_space_size: Math.floor(heapTotal * 0.6) },
      { space_name: 'code_space', space_size: Math.floor(heapTotal * 0.1), space_used_size: Math.floor(heapUsed * 0.05), space_available_size: Math.floor(heapTotal * 0.05), physical_space_size: Math.floor(heapTotal * 0.1) },
      { space_name: 'large_object_space', space_size: Math.floor(heapTotal * 0.05), space_used_size: Math.floor(heapUsed * 0.05), space_available_size: 0, physical_space_size: Math.floor(heapTotal * 0.05) }
    ];
  },
  getHeapSnapshot: function() {
    var Readable;
    try { Readable = require('stream').Readable; } catch(e) {}
    if (Readable) {
      var s = new Readable({ read: function() { this.push(null); } });
      return s;
    }
    return { read: function() { return null; } };
  },
  getHeapCodeStatistics: function() {
    var mem = _getMemStats();
    var heapUsed = mem.heapUsed || 0;
    return {
      code_and_metadata_size: Math.floor(heapUsed * 0.1),
      bytecode_and_metadata_size: Math.floor(heapUsed * 0.05),
      external_script_source_size: 0,
      cpu_profiler_metadata_size: 0
    };
  },
  setFlagsFromString: function(flags) {
    if (typeof flags !== 'string') {
      return;
    }
    var parts = flags.split(/\s+/);
    for (var i = 0; i < parts.length; i++) {
      if (parts[i] === '--allow-natives-syntax') {
        globalThis.__exactAllowNativesSyntax = true;
      }
    }
  },
  serialize: function(value) {
    var json = JSON.stringify(value);
    if (typeof Buffer !== 'undefined') return Buffer.from(json);
    return new TextEncoder().encode(json);
  },
  deserialize: function(buffer) {
    var str = typeof buffer === 'string' ? buffer :
      (typeof Buffer !== 'undefined' && Buffer.isBuffer(buffer)) ? buffer.toString() :
      new TextDecoder().decode(buffer);
    return JSON.parse(str);
  },
  cachedDataVersionTag: function() { return 0; },
  writeHeapSnapshot: function(filename) {
    /* In a real V8 environment this writes a heap snapshot file.
       We return a filename to maintain API compatibility. */
    if (!filename) {
      filename = 'Heap.' + Date.now() + '.heapsnapshot';
    }
    return filename;
  }
};
