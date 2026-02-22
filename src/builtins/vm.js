function Script(code, options) {
  this._code = code;
  this._options = options || {};
}
Script.prototype.runInThisContext = function(options) {
  // Use indirect eval to run in global scope
  return (0, eval)(this._code);
};
Script.prototype.runInNewContext = function(sandbox, options) {
  // Best-effort: run with sandbox properties as local vars
  var keys = sandbox ? Object.keys(sandbox) : [];
  var values = keys.map(function(k) { return sandbox[k]; });
  // Declare locals explicitly so Hermes doesn't reject undeclared references
  var varDecls = keys.length > 0 ? 'var ' + keys.join(',') + ';\n' : '';
  var assigns = '';
  for (var i = 0; i < keys.length; i++) {
    assigns += keys[i] + ' = arguments[' + i + '];\n';
  }
  var body = varDecls + assigns + 'return (' + this._code + ');\n';
  var fn = new Function(body);
  return fn.apply(null, values);
};

function createContext(sandbox) {
  return sandbox || {};
}

function runInThisContext(code, options) {
  return new Script(code, options).runInThisContext(options);
}

function runInNewContext(code, sandbox, options) {
  return new Script(code, options).runInNewContext(sandbox, options);
}

function compileFunction(code, params, options) {
  params = params || [];
  return new Function(params.join(','), code);
}

module.exports = {
  Script: Script,
  createContext: createContext,
  runInThisContext: runInThisContext,
  runInNewContext: runInNewContext,
  compileFunction: compileFunction,
  isContext: function(sandbox) { return typeof sandbox === 'object' && sandbox !== null; }
};
