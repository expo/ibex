package dev.ibex.runtime;

import java.util.ArrayDeque;

/**
 * Receive-side flow control shared by the Android OkHttp WebSocket callbacks.
 *
 * <p>This class deliberately has no Android or OkHttp dependencies. The app
 * bridge can therefore exercise the exact production queue state machine in a
 * host JVM test while the transport adapter remains in {@link IbexNetworking}.
 *
 * <p>@ref LLP 0003#websocket-bridge-threading-and-context-ownership — paused
 * receive delivery is FIFO, independently count/byte bounded, and terminates
 * with WebSocket close code 1009 rather than retaining an unbounded backlog.
 */
final class IbexWebSocketFlowController {
  interface Listener {
    void onMessage(byte[] bytes, boolean isText);

    void onError(String message);

    void onCloseRequested(int code, String reason);
  }

  private static final int RECEIVE_QUEUE_OVERFLOW_CODE = 1009;
  private static final String RECEIVE_QUEUE_OVERFLOW_REASON = "Receive queue overflow";

  private final int maxPendingMessages;
  private final long maxPendingBytes;
  private final Listener listener;
  private final ArrayDeque<Message> pending = new ArrayDeque<>();

  private long pendingBytes;
  private boolean closed;
  private boolean paused;
  private boolean draining;
  private boolean flowControlled;

  IbexWebSocketFlowController(
      int maxPendingMessages,
      long maxPendingBytes,
      Listener listener) {
    if (maxPendingMessages <= 0) {
      throw new IllegalArgumentException("maxPendingMessages must be positive");
    }
    if (maxPendingBytes <= 0) {
      throw new IllegalArgumentException("maxPendingBytes must be positive");
    }
    if (listener == null) {
      throw new NullPointerException("listener");
    }
    this.maxPendingMessages = maxPendingMessages;
    this.maxPendingBytes = maxPendingBytes;
    this.listener = listener;
  }

  void receive(byte[] bytes, boolean isText) {
    byte[] ownedBytes = bytes == null ? new byte[0] : bytes;
    Message message = new Message(ownedBytes, isText);
    boolean overflow = false;
    boolean deliver = false;
    synchronized (this) {
      if (closed) {
        return;
      }
      if (paused || draining) {
        boolean byteLimitExceeded =
            message.bytes.length > maxPendingBytes - pendingBytes;
        if (pending.size() >= maxPendingMessages || byteLimitExceeded) {
          closeAndClearLocked();
          overflow = true;
        } else {
          // The queue retains the already-owned message exactly once. Text and
          // ByteString conversion happens before this boundary in the adapter.
          pending.add(message);
          pendingBytes += message.bytes.length;
          return;
        }
      } else {
        deliver = true;
        if (flowControlled) {
          paused = true;
        }
      }
    }
    if (overflow) {
      try {
        listener.onError("WebSocket receive queue overflow");
      } finally {
        // Transport shutdown is the memory-safety boundary. Even a failing
        // error observer must not leave the remote peer feeding this socket.
        listener.onCloseRequested(
            RECEIVE_QUEUE_OVERFLOW_CODE,
            RECEIVE_QUEUE_OVERFLOW_REASON);
      }
    } else if (deliver) {
      listener.onMessage(message.bytes, message.isText);
    }
  }

  synchronized void pause() {
    if (!closed) {
      paused = true;
    }
  }

  void resume() {
    synchronized (this) {
      if (closed || draining) {
        return;
      }
      paused = false;
      draining = true;
    }
    for (;;) {
      Message message;
      synchronized (this) {
        if (closed) {
          draining = false;
          return;
        }
        message = pending.poll();
        if (message == null) {
          draining = false;
          return;
        }
        pendingBytes -= message.bytes.length;
        if (pendingBytes < 0) {
          throw new IllegalStateException("negative WebSocket pending-byte count");
        }
      }
      listener.onMessage(message.bytes, message.isText);
      synchronized (this) {
        if (closed) {
          draining = false;
          return;
        }
        // Honor both the native flow-control response and a concurrent,
        // explicit pause. The previous inline loop ignored an explicit pause
        // that arrived while a backlog was draining.
        if (paused || flowControlled) {
          paused = true;
          draining = false;
          return;
        }
      }
    }
  }

  synchronized void setFlowControlled(boolean enabled) {
    if (!closed) {
      flowControlled = enabled;
    }
  }

  synchronized boolean close() {
    return terminateLocked();
  }

  synchronized boolean transportClosed() {
    return terminateLocked();
  }

  synchronized boolean transportFailed() {
    return terminateLocked();
  }

  synchronized boolean isClosed() {
    return closed;
  }

  synchronized int pendingMessageCountForTest() {
    return pending.size();
  }

  synchronized long pendingByteCountForTest() {
    return pendingBytes;
  }

  private boolean terminateLocked() {
    if (closed) {
      return false;
    }
    closeAndClearLocked();
    return true;
  }

  private void closeAndClearLocked() {
    closed = true;
    paused = false;
    draining = false;
    pending.clear();
    pendingBytes = 0;
  }

  private static final class Message {
    final byte[] bytes;
    final boolean isText;

    Message(byte[] bytes, boolean isText) {
      this.bytes = bytes;
      this.isText = isText;
    }
  }
}
