(function() {
  var _times = {};
  var _counts = {};
  var _groupDepth = 0;
  var _origLog = console.log;
  var _origError = console.error;

  console.time = function(label) {
    _times[label || 'default'] = Date.now();
  };
  console.timeEnd = function(label) {
    label = label || 'default';
    var start = _times[label];
    if (start !== undefined) {
      _origLog.call(console, label + ': ' + (Date.now() - start) + 'ms');
      delete _times[label];
    }
  };
  console.timeLog = function(label) {
    label = label || 'default';
    var start = _times[label];
    if (start !== undefined) {
      var args = [label + ': ' + (Date.now() - start) + 'ms'];
      for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
      _origLog.apply(console, args);
    }
  };
  console.count = function(label) {
    label = label || 'default';
    _counts[label] = (_counts[label] || 0) + 1;
    _origLog.call(console, label + ': ' + _counts[label]);
  };
  console.countReset = function(label) {
    _counts[label || 'default'] = 0;
  };
  console.group = function() {
    _groupDepth++;
    if (arguments.length > 0) _origLog.apply(console, arguments);
  };
  console.groupCollapsed = console.group;
  console.groupEnd = function() {
    if (_groupDepth > 0) _groupDepth--;
  };
  console.table = function(data) {
    if (Array.isArray(data)) {
      _origLog.call(console, '(index) | Value');
      for (var i = 0; i < data.length; i++) {
        if (typeof data[i] === 'object' && data[i] !== null) {
          var keys = Object.keys(data[i]);
          var parts = [];
          for (var k = 0; k < keys.length; k++) parts.push(keys[k] + ': ' + data[i][keys[k]]);
          _origLog.call(console, i + '       | { ' + parts.join(', ') + ' }');
        } else {
          _origLog.call(console, i + '       | ' + data[i]);
        }
      }
    } else if (typeof data === 'object' && data !== null) {
      var objKeys = Object.keys(data);
      for (var j = 0; j < objKeys.length; j++) {
        _origLog.call(console, objKeys[j] + ': ' + data[objKeys[j]]);
      }
    } else {
      _origLog.call(console, data);
    }
  };
  console.assert = function(condition) {
    if (!condition) {
      var args = Array.prototype.slice.call(arguments, 1);
      if (args.length === 0) args = ['Assertion failed'];
      else args[0] = 'Assertion failed: ' + args[0];
      _origError.apply(console, args);
    }
  };
  console.clear = function() {};
})();
