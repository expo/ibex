var EventEmitter = require('events');

function Domain() {
  EventEmitter.call(this);
  this.members = [];
}
Domain.prototype = Object.create(EventEmitter.prototype);
Domain.prototype.constructor = Domain;
Domain.prototype.add = function(emitter) { this.members.push(emitter); };
Domain.prototype.remove = function(emitter) {
  var idx = this.members.indexOf(emitter);
  if (idx !== -1) this.members.splice(idx, 1);
};
Domain.prototype.run = function(fn) {
  try { return fn(); }
  catch(e) { this.emit('error', e); }
};
Domain.prototype.bind = function(fn) {
  var self = this;
  return function() {
    try { return fn.apply(this, arguments); }
    catch(e) { self.emit('error', e); }
  };
};
Domain.prototype.intercept = function(fn) {
  var self = this;
  return function(err) {
    if (err) { self.emit('error', err); return; }
    var args = Array.prototype.slice.call(arguments, 1);
    try { return fn.apply(this, args); }
    catch(e) { self.emit('error', e); }
  };
};
Domain.prototype.enter = function() {};
Domain.prototype.exit = function() {};
Domain.prototype.dispose = function() { this.members = []; };

function create() { return new Domain(); }

module.exports = {
  Domain: Domain,
  create: create,
  createDomain: create
};
