function setTimeout$1(callback, delay) {
  var args = [];
  for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
  if (typeof globalThis.setTimeout !== "function") {
    throw new Error("setTimeout is not available");
  }
  return globalThis.setTimeout(function() {
    callback.apply(null, args);
  }, delay || 0);
}

function clearTimeout$1(handle) {
  if (typeof globalThis.clearTimeout === "function") {
    globalThis.clearTimeout(handle);
  }
}

function setInterval$1(callback, delay) {
  var args = [];
  for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
  if (typeof globalThis.setInterval !== "function") {
    throw new Error("setInterval is not available");
  }
  return globalThis.setInterval(function() {
    callback.apply(null, args);
  }, delay || 0);
}

function clearInterval$1(handle) {
  if (typeof globalThis.clearInterval === "function") {
    globalThis.clearInterval(handle);
  }
}

function setImmediate$1(callback) {
  var args = [];
  for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
  return setTimeout$1(function() {
    callback.apply(null, args);
  }, 0);
}

function clearImmediate$1(handle) {
  clearTimeout$1(handle);
}

module.exports = {
  setTimeout: setTimeout$1,
  clearTimeout: clearTimeout$1,
  setInterval: setInterval$1,
  clearInterval: clearInterval$1,
  setImmediate: setImmediate$1,
  clearImmediate: clearImmediate$1
};
