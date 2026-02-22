var EventEmitter = require('events');

var cluster = Object.create(EventEmitter.prototype);
EventEmitter.call(cluster);

cluster.isMaster = true;
cluster.isPrimary = true;
cluster.isWorker = false;
cluster.workers = {};
cluster.settings = {};
cluster.SCHED_NONE = 1;
cluster.SCHED_RR = 2;
cluster.schedulingPolicy = 2;

cluster.setupMaster = function(settings) {
  if (settings) {
    for (var k in settings) {
      if (Object.prototype.hasOwnProperty.call(settings, k)) {
        cluster.settings[k] = settings[k];
      }
    }
  }
};
cluster.setupPrimary = cluster.setupMaster;

cluster.fork = function(env) {
  throw new Error('cluster.fork() is not supported in this runtime. Use child_process instead.');
};

cluster.disconnect = function(callback) {
  if (typeof callback === 'function') callback();
};

module.exports = cluster;
