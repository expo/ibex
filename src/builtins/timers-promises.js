function delay(ms, value, options) {
  var delayMs = ms == null ? 0 : Number(ms);
  var resultValue = value === undefined ? undefined : value;
  var signal = options && options.signal;
  if (signal && signal.aborted) {
    return Promise.reject(signal.reason || new DOMException('The operation was aborted', 'AbortError'));
  }
  return new Promise(function(resolve, reject) {
    var timer = setTimeout(function() {
      resolve(resultValue);
    }, delayMs);
    if (signal) {
      signal.addEventListener('abort', function() {
        clearTimeout(timer);
        reject(signal.reason || new DOMException('The operation was aborted', 'AbortError'));
      }, { once: true });
    }
  });
}

function setImmediate$1(value, options) {
  return delay(0, value, options);
}

function setInterval$1(ms, value, options) {
  var delayMs = ms == null ? 0 : Number(ms);
  var signal = options && options.signal;

  return {
    [Symbol.asyncIterator]: function() {
      var done = false;
      var resolveNext = null;
      var timer = null;

      function schedule() {
        timer = setInterval(function() {
          if (resolveNext) {
            var resolve = resolveNext;
            resolveNext = null;
            resolve({ value: value === undefined ? undefined : value, done: false });
          }
        }, delayMs);
      }

      if (signal) {
        if (signal.aborted) {
          done = true;
        } else {
          signal.addEventListener('abort', function() {
            done = true;
            if (timer) clearInterval(timer);
            if (resolveNext) {
              var resolve = resolveNext;
              resolveNext = null;
              resolve({ value: undefined, done: true });
            }
          }, { once: true });
        }
      }

      if (!done) schedule();

      return {
        next: function() {
          if (done) return Promise.resolve({ value: undefined, done: true });
          return new Promise(function(resolve) {
            resolveNext = resolve;
          });
        },
        return: function() {
          done = true;
          if (timer) clearInterval(timer);
          return Promise.resolve({ value: undefined, done: true });
        }
      };
    }
  };
}

module.exports = {
  setTimeout: delay,
  setImmediate: setImmediate$1,
  setInterval: setInterval$1,
  scheduler: {
    wait: delay,
    yield: function() { return delay(0); }
  }
};
