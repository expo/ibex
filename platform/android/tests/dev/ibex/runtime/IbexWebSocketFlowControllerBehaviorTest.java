package dev.ibex.runtime;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Host-JVM behavioral coverage for the production Android WebSocket queue. */
public final class IbexWebSocketFlowControllerBehaviorTest {
  private IbexWebSocketFlowControllerBehaviorTest() {}

  public static void main(String[] args) {
    pausedTextAndBinaryMessagesDrainFifoWithoutCopies();
    textFloodExceedingTheCountBoundErrorsThenCloses();
    binaryFloodExceedingTheByteBoundErrorsThenCloses();
    repeatedFlowControlPauseResumeDrainsFairly();
    transportCloseAndErrorDiscardQueuedData();
    System.out.println("Android WebSocket flow-control behavioral tests: PASS");
  }

  private static void pausedTextAndBinaryMessagesDrainFifoWithoutCopies() {
    RecordingListener listener = new RecordingListener();
    IbexWebSocketFlowController controller = controller(4, 32, listener);
    byte[] text = "hello".getBytes(StandardCharsets.UTF_8);
    byte[] binary = new byte[] {0, 1, 2, 3};

    controller.pause();
    controller.receive(text, true);
    controller.receive(binary, false);

    equal(2, controller.pendingMessageCountForTest(), "paused message count");
    equal(9L, controller.pendingByteCountForTest(), "paused byte count");
    equal(0, listener.messages.size(), "paused delivery count");

    controller.resume();
    equal(2, listener.messages.size(), "resumed delivery count");
    same(text, listener.messages.get(0).bytes, "text array must not be copied again");
    same(binary, listener.messages.get(1).bytes, "binary array must not be copied again");
    check(listener.messages.get(0).isText, "first message should be text");
    check(!listener.messages.get(1).isText, "second message should be binary");
    equal(0, controller.pendingMessageCountForTest(), "drained message count");
    equal(0L, controller.pendingByteCountForTest(), "drained byte count");
  }

  private static void textFloodExceedingTheCountBoundErrorsThenCloses() {
    RecordingListener listener = new RecordingListener();
    IbexWebSocketFlowController controller = controller(2, 1024, listener);
    controller.pause();
    controller.receive(bytes("one"), true);
    controller.receive(bytes("two"), true);
    controller.receive(bytes("three"), true);

    equal(
        Arrays.asList("error:WebSocket receive queue overflow", "close:1009:Receive queue overflow"),
        listener.terminalEvents,
        "count overflow terminal sequence");
    check(controller.isClosed(), "count overflow must close the controller");
    equal(0, controller.pendingMessageCountForTest(), "count overflow clears queue");
    equal(0L, controller.pendingByteCountForTest(), "count overflow clears bytes");

    controller.receive(bytes("ignored"), true);
    controller.resume();
    equal(0, listener.messages.size(), "closed controller must ignore new frames");
    equal(2, listener.terminalEvents.size(), "overflow terminal events fire once");
  }

  private static void binaryFloodExceedingTheByteBoundErrorsThenCloses() {
    RecordingListener listener = new RecordingListener();
    IbexWebSocketFlowController controller = controller(16, 8, listener);
    controller.pause();
    controller.receive(new byte[] {0, 1, 2, 3, 4}, false);
    controller.receive(new byte[] {5, 6, 7, 8}, false);

    equal(
        Arrays.asList("error:WebSocket receive queue overflow", "close:1009:Receive queue overflow"),
        listener.terminalEvents,
        "byte overflow terminal sequence");
    check(controller.isClosed(), "byte overflow must close the controller");
    equal(0, controller.pendingMessageCountForTest(), "byte overflow clears queue");
    equal(0L, controller.pendingByteCountForTest(), "byte overflow clears bytes");
  }

  private static void repeatedFlowControlPauseResumeDrainsFairly() {
    RecordingListener listener = new RecordingListener();
    IbexWebSocketFlowController controller = controller(8, 1024, listener);
    controller.pause();
    controller.receive(bytes("a"), true);
    controller.receive(bytes("b"), true);
    controller.receive(bytes("c"), true);
    controller.receive(bytes("d"), true);
    controller.setFlowControlled(true);

    controller.resume();
    equal(Arrays.asList("a"), listener.messageStrings(), "first resume");
    controller.resume();
    equal(Arrays.asList("a", "b"), listener.messageStrings(), "second resume");
    controller.resume();
    equal(Arrays.asList("a", "b", "c"), listener.messageStrings(), "third resume");

    controller.setFlowControlled(false);
    controller.resume();
    equal(Arrays.asList("a", "b", "c", "d"), listener.messageStrings(), "final drain");
    equal(0, controller.pendingMessageCountForTest(), "fair drain leaves no messages");
    equal(0L, controller.pendingByteCountForTest(), "fair drain leaves no bytes");
  }

  private static void transportCloseAndErrorDiscardQueuedData() {
    RecordingListener closeListener = new RecordingListener();
    IbexWebSocketFlowController closed = controller(8, 1024, closeListener);
    closed.pause();
    closed.receive(bytes("queued-before-close"), true);
    check(closed.transportClosed(), "first transport close should transition state");
    check(!closed.transportClosed(), "second transport close should be idempotent");
    equal(0, closed.pendingMessageCountForTest(), "transport close clears messages");
    equal(0L, closed.pendingByteCountForTest(), "transport close clears bytes");

    RecordingListener errorListener = new RecordingListener();
    IbexWebSocketFlowController failed = controller(8, 1024, errorListener);
    failed.pause();
    failed.receive(new byte[] {1, 2, 3}, false);
    check(failed.transportFailed(), "first transport failure should transition state");
    check(!failed.transportFailed(), "second transport failure should be idempotent");
    equal(0, failed.pendingMessageCountForTest(), "transport failure clears messages");
    equal(0L, failed.pendingByteCountForTest(), "transport failure clears bytes");
  }

  private static IbexWebSocketFlowController controller(
      int maxMessages,
      long maxBytes,
      RecordingListener listener) {
    return new IbexWebSocketFlowController(maxMessages, maxBytes, listener);
  }

  private static byte[] bytes(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }

  private static void check(boolean condition, String message) {
    if (!condition) {
      throw new AssertionError(message);
    }
  }

  private static void same(Object expected, Object actual, String message) {
    if (expected != actual) {
      throw new AssertionError(message);
    }
  }

  private static void equal(Object expected, Object actual, String message) {
    if (!expected.equals(actual)) {
      throw new AssertionError(message + ": expected " + expected + ", got " + actual);
    }
  }

  private static final class ReceivedMessage {
    final byte[] bytes;
    final boolean isText;

    ReceivedMessage(byte[] bytes, boolean isText) {
      this.bytes = bytes;
      this.isText = isText;
    }
  }

  private static final class RecordingListener
      implements IbexWebSocketFlowController.Listener {
    final List<ReceivedMessage> messages = new ArrayList<>();
    final List<String> terminalEvents = new ArrayList<>();

    @Override
    public void onMessage(byte[] bytes, boolean isText) {
      messages.add(new ReceivedMessage(bytes, isText));
    }

    @Override
    public void onError(String message) {
      terminalEvents.add("error:" + message);
    }

    @Override
    public void onCloseRequested(int code, String reason) {
      terminalEvents.add("close:" + code + ":" + reason);
    }

    List<String> messageStrings() {
      List<String> values = new ArrayList<>();
      for (ReceivedMessage message : messages) {
        values.add(new String(message.bytes, StandardCharsets.UTF_8));
      }
      return values;
    }
  }
}
