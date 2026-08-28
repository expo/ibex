// MessageChannel / MessagePort.
//
// Present because it is load-bearing, not because the web platform defines it
// (LLP 0059 §7). React's server renderer builds one at module scope and uses
// it as its task-scheduling primitive:
//
//   var channel = new MessageChannel(), taskQueue = [];
//   channel.port1.onmessage = function () { taskQueue.shift()(); };
//   function scheduleWork(cb) { taskQueue.push(cb); channel.port2.postMessage(null); }
//
// So this is a scheduling primitive first and a communication one second. What
// matters is that delivery is a **task**, not a microtask: the idiom exists to
// yield to the event loop, and delivering on the microtask queue would starve
// exactly what the caller was trying to let through.
//
// Pure and ungated. Two ports that can only reach each other carry no
// authority — nothing here touches the network, the filesystem, or the
// environment.
//
// **Divergence: `postMessage` does not clone.** The real API structured-clones
// its argument, so the receiver cannot observe later mutation by the sender.
// This passes the reference. `structuredClone` is a v1 item that does not exist
// yet (LLP 0059 §3), and a fake clone would be worse than a stated one.
// Tracked in issues/20260828-messagechannel-does-not-clone.md.
//
// Out: `Worker` and cross-realm transfer (there is one realm), the `transfer`
// argument, `MessageEvent` beyond `.data`, and `port.addEventListener` — only
// the `onmessage` property form is supported, which is what the idiom uses.
(function (global) {
  "use strict";

  function MessagePort() {
    this.onmessage = null;
    // Set by MessageChannel; a port with no peer is not constructible here.
    this._peer = null;
    // Real ports queue messages until start() or onmessage is assigned.
    // Assigning onmessage implicitly starts, which is the only path used.
    this._started = false;
    this._closed = false;
    this._pending = [];
  }

  MessagePort.prototype.postMessage = function (data) {
    var peer = this._peer;
    if (peer === null || peer._closed) return;
    // A task, deliberately. setTimeout(0) is the runtime's task queue, so a
    // message and a timer are sequenced against each other in the order they
    // were enqueued (LLP 0058.000.000 §8) rather than jumping it.
    global.setTimeout(function () {
      peer._deliver(data);
    }, 0);
  };

  MessagePort.prototype._deliver = function (data) {
    if (this._closed) return;
    if (!this._started) {
      this._pending.push(data);
      return;
    }
    var handler = this.onmessage;
    if (typeof handler === "function") handler.call(this, { data: data });
  };

  MessagePort.prototype.start = function () {
    if (this._started || this._closed) return;
    this._started = true;
    var queued = this._pending;
    this._pending = [];
    for (var i = 0; i < queued.length; i++) this._deliver(queued[i]);
  };

  MessagePort.prototype.close = function () {
    this._closed = true;
    this._pending = [];
  };

  // Assigning onmessage starts the port, as the platform does. Without this,
  // a message posted before the handler is attached is never delivered — and
  // the scheduling idiom above attaches its handler after construction.
  Object.defineProperty(MessagePort.prototype, "onmessage", {
    get: function () {
      return this._onmessage || null;
    },
    set: function (handler) {
      this._onmessage = handler;
      if (handler !== null && handler !== undefined) this.start();
    },
    configurable: true,
  });

  function MessageChannel() {
    var port1 = new MessagePort();
    var port2 = new MessagePort();
    port1._peer = port2;
    port2._peer = port1;
    this.port1 = port1;
    this.port2 = port2;
  }

  global.MessageChannel = MessageChannel;
  global.MessagePort = MessagePort;
})(globalThis);
