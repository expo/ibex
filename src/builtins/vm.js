function Script(code, options) {
  this._code = code;
  this._options = options || {};
}

function unsupported(method) {
  var err = new Error(method + ' is not implemented in this runtime');
  err.code = 'ERR_METHOD_NOT_IMPLEMENTED';
  return err;
}

Script.prototype.runInThisContext = function(options) {
  // Use indirect eval to run in global scope
  return (0, eval)(this._code);
};
Script.prototype.runInNewContext = function(sandbox, options) {
  throw unsupported('vm.runInNewContext');
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
