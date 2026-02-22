function delay(ms, value, options) {
  var delayMs = ms == null ? 0 : Number(ms);
  var resultValue = value === undefined ? undefined : value;
  return new Promise(function(resolve) {
    setTimeout(function() {
      resolve(resultValue);
    }, delayMs);
  });
}

function setImmediate$1(value) {
  return delay(0, value);
}

module.exports = {
  setTimeout: delay,
  setImmediate: setImmediate$1
};
