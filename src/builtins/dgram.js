function createSocket(type, callback) {
  throw new Error('dgram.createSocket() is not yet supported in this runtime');
}

module.exports = {
  createSocket: createSocket,
  Socket: function() { throw new Error('dgram.Socket is not yet supported'); }
};
module.exports.default = module.exports;
