var stream = require('node:stream');

function pipeline() {
  var args = [];
  for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
  // stream.pipeline already returns a promise when no callback is given
  if (typeof stream.pipeline === 'function') {
    return stream.pipeline.apply(stream, args);
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
