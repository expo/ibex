var stream = require('node:stream');

function pipeline() {
  var args = [];
  for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
  // Prefer stream.promises.pipeline when available, and otherwise emulate promise mode
  if (typeof stream.pipeline === 'function') {
    if (typeof args[args.length - 1] === 'function') {
      return stream.pipeline.apply(stream, args);
    }
    if (stream.promises && typeof stream.promises.pipeline === 'function') {
      try {
        return stream.promises.pipeline.apply(stream.promises, args);
      } catch (err) {
        return Promise.reject(err);
      }
    }
    return new Promise(function(resolve, reject) {
      args.push(function(err) {
        if (err) {
          reject(err);
          return;
        }
        resolve();
      });
      try {
        stream.pipeline.apply(stream, args);
      } catch (err) {
        reject(err);
      }
    });
  }
  return Promise.reject(new Error('stream.pipeline is not available'));
}

function finished(streamLike, options) {
  if (typeof stream.finished === 'function') {
    return stream.finished(streamLike, options || {});
  }
  return Promise.reject(new Error('stream.finished is not available'));
}

module.exports = {
  pipeline: pipeline,
  finished: finished
};
