// node:console module — re-exports the global console
var Console = function(stdout, stderr) {
  this._stdout = stdout;
  this._stderr = stderr;
  this._times = {};
  this._counts = {};
  this._groups = 0;
};
var _clearSequence = '\x1b[1;1H\x1b[0J';

function _clearTTY(stream) {
  if (!stream || stream.isTTY !== true || typeof stream.write !== 'function') {
    return;
  }
  stream.write(_clearSequence);
}
Console.prototype.log = function() { console.log.apply(console, arguments); };
Console.prototype.info = function() { console.info.apply(console, arguments); };
Console.prototype.warn = function() { console.warn.apply(console, arguments); };
Console.prototype.error = function() { console.error.apply(console, arguments); };
Console.prototype.debug = function() { console.debug.apply(console, arguments); };
Console.prototype.dir = function(obj) { console.dir(obj); };
Console.prototype.trace = function() { console.trace.apply(console, arguments); };
Console.prototype.assert = function(condition) {
  if (!condition) console.error.apply(console, ['Assertion failed:'].concat(Array.prototype.slice.call(arguments, 1)));
};
Console.prototype.time = function(label) {
  this._times[label || 'default'] = Date.now();
};
Console.prototype.timeEnd = function(label) {
  label = label || 'default';
  var start = this._times[label];
  if (start !== undefined) {
    console.log(label + ': ' + (Date.now() - start) + 'ms');
    delete this._times[label];
  }
};
Console.prototype.timeLog = function(label) {
  label = label || 'default';
  var start = this._times[label];
  if (start !== undefined) {
    var args = [label + ': ' + (Date.now() - start) + 'ms'];
    for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
    console.log.apply(console, args);
  }
};
Console.prototype.count = function(label) {
  label = label || 'default';
  this._counts[label] = (this._counts[label] || 0) + 1;
  console.log(label + ': ' + this._counts[label]);
};
Console.prototype.countReset = function(label) {
  label = label || 'default';
  this._counts[label] = 0;
};
Console.prototype.group = function() {
  this._groups++;
  if (arguments.length > 0) console.log.apply(console, arguments);
};
Console.prototype.groupEnd = function() {
  if (this._groups > 0) this._groups--;
};
Console.prototype.table = function(data) {
  console.log(data);
};
Console.prototype.clear = function() { _clearTTY(this._stdout); };

module.exports = console;
module.exports.Console = Console;
