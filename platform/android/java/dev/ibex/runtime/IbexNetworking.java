package dev.ibex.runtime;

import android.Manifest;
import android.app.Activity;
import android.app.Application;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ComponentCallbacks;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.net.DnsResolver;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.HandlerThread;
import android.os.LocaleList;
import android.provider.Settings;
import android.text.format.DateFormat;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.accessibility.AccessibilityManager;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;
import okio.BufferedSink;
import okio.ByteString;

/**
 * Android platform bridge for Ibex.
 *
 * Apps embedding Ibex should include this source in their Android source set,
 * depend on OkHttp, and call ex_android_initialize(JavaVM*, Context) from their
 * JNI startup code.
 */
public final class IbexNetworking {
  private static final String TAG = "IbexNetworking";
  private static final byte[] EMPTY_BYTES = new byte[0];
  private static final Executor DIRECT_EXECUTOR = new Executor() {
    @Override
    public void execute(Runnable command) {
      command.run();
    }
  };

  private static volatile Context applicationContext;
  private static volatile OkHttpClient client = new OkHttpClient.Builder()
      .followRedirects(false)
      .followSslRedirects(false)
      .build();
  private static volatile boolean componentCallbacksRegistered;
  private static volatile boolean lifecycleCallbacksRegistered;
  private static int manualStartedActivityCount;
  private static volatile String currentAppState = "unknown";
  private static volatile String initialUrl;

  private static final Map<Integer, Call> calls = new ConcurrentHashMap<>();
  private static final Map<Integer, WsEntry> webSockets = new ConcurrentHashMap<>();
  private static final ArrayDeque<String> platformEvents = new ArrayDeque<>();
  private static final Set<Activity> startedActivities =
      Collections.newSetFromMap(new WeakHashMap<Activity, Boolean>());

  private IbexNetworking() {}

  public static void initialize(Context context) {
    Context appContext = context == null ? null : context.getApplicationContext();
    applicationContext = appContext;
    captureInitialIntent(context);
    registerPlatformCallbacks(appContext);
    if (context instanceof Activity) {
      notifyActivityResumed((Activity) context);
    }
  }

  public static Context getApplicationContext() {
    return applicationContext;
  }

  public static void setClient(OkHttpClient okHttpClient) {
    if (okHttpClient == null) {
      throw new NullPointerException("okHttpClient == null");
    }
    client = okHttpClient.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .build();
  }

  public static String platformVersion() {
    return String.valueOf(Build.VERSION.SDK_INT);
  }

  public static String appState() {
    return currentAppState;
  }

  public static String initialURL() {
    return initialUrl == null ? "" : initialUrl;
  }

  public static String drainPlatformEvents() {
    StringBuilder builder = new StringBuilder();
    synchronized (platformEvents) {
      while (!platformEvents.isEmpty()) {
        if (builder.length() > 0) {
          builder.append('\n');
        }
        builder.append(platformEvents.removeFirst());
      }
    }
    return builder.toString();
  }

  public static void notifyActivityStarted(Activity activity) {
    captureInitialIntent(activity);
    int next;
    synchronized (IbexNetworking.class) {
      if (activity != null) {
        startedActivities.add(activity);
      } else {
        manualStartedActivityCount++;
      }
      next = startedActivityCountLocked();
    }
    if (next > 0) {
      updateAppState("active");
    }
  }

  public static void notifyActivityStopped(Activity activity) {
    synchronized (IbexNetworking.class) {
      if (activity != null) {
        startedActivities.remove(activity);
      } else {
        manualStartedActivityCount = Math.max(0, manualStartedActivityCount - 1);
      }
    }
    updateBackgroundIfIdle();
  }

  public static void notifyActivityResumed(Activity activity) {
    captureInitialIntent(activity);
    synchronized (IbexNetworking.class) {
      if (activity != null) {
        startedActivities.add(activity);
      } else if (startedActivityCountLocked() <= 0) {
        manualStartedActivityCount = 1;
      }
    }
    updateAppState("active");
  }

  public static void notifyActivityPaused(Activity activity) {
    if (activity == null) {
      updateBackgroundIfIdle();
    }
  }

  private static int startedActivityCountLocked() {
    return manualStartedActivityCount + startedActivities.size();
  }

  private static void updateBackgroundIfIdle() {
    synchronized (IbexNetworking.class) {
      if (startedActivityCountLocked() > 0) {
        return;
      }
    }
    updateAppState("background");
  }

  private static void notifyActivityDestroyed(Activity activity) {
    if (activity == null) {
      return;
    }
    boolean removed;
    synchronized (IbexNetworking.class) {
      removed = startedActivities.remove(activity);
    }
    if (removed) {
      updateBackgroundIfIdle();
    }
  }

  public static void notifyNewIntent(Intent intent) {
    recordIntent(intent, false);
  }

  public static void notifyDeepLink(String url) {
    if (url == null || url.isEmpty()) {
      return;
    }
    if (initialUrl == null) {
      initialUrl = url;
    }
    enqueuePlatformEvent("{\"type\":\"url\",\"url\":" + jsonString(url) + "}");
  }

  public static String[] localeTags() {
    Configuration configuration = currentConfiguration();
    ArrayList<String> tags = new ArrayList<>();
    LocaleList locales = configuration.getLocales();
    for (int i = 0; i < locales.size(); i++) {
      addLocaleTag(tags, locales.get(i));
    }
    if (tags.isEmpty()) {
      addLocaleTag(tags, Locale.getDefault());
    }
    return tags.toArray(new String[0]);
  }

  public static boolean uses24HourClock() {
    Context context = applicationContext;
    try {
      return context != null && DateFormat.is24HourFormat(context);
    } catch (RuntimeException ignored) {
      return false;
    }
  }

  public static float[] screenInfo() {
    Resources resources = currentResources();
    Configuration configuration = resources.getConfiguration();
    DisplayMetrics metrics = resources.getDisplayMetrics();
    float density = metrics.density > 0.0f ? metrics.density : 1.0f;
    float width = configuration.screenWidthDp > 0
        ? configuration.screenWidthDp
        : metrics.widthPixels / density;
    float height = configuration.screenHeightDp > 0
        ? configuration.screenHeightDp
        : metrics.heightPixels / density;
    float fontScale = configuration.fontScale > 0.0f ? configuration.fontScale : 1.0f;
    return new float[] {width, height, density, fontScale};
  }

  public static int[] accessibilityFlags() {
    Context context = applicationContext;
    Configuration configuration = currentConfiguration();
    boolean darkMode =
        (configuration.uiMode & Configuration.UI_MODE_NIGHT_MASK)
            == Configuration.UI_MODE_NIGHT_YES;
    boolean reducedMotion = false;
    boolean screenReader = false;
    boolean highContrast = false;
    if (context != null) {
      reducedMotion =
          animationScale(context, Settings.Global.ANIMATOR_DURATION_SCALE) == 0.0f
              || animationScale(context, Settings.Global.TRANSITION_ANIMATION_SCALE) == 0.0f
              || animationScale(context, Settings.Global.WINDOW_ANIMATION_SCALE) == 0.0f;
      AccessibilityManager accessibilityManager =
          (AccessibilityManager) context.getSystemService(Context.ACCESSIBILITY_SERVICE);
      if (accessibilityManager != null) {
        screenReader = accessibilityManager.isTouchExplorationEnabled();
        highContrast = isHighContrastTextEnabled(accessibilityManager);
      }
    }

    boolean boldText = false;
    if (Build.VERSION.SDK_INT >= 31) {
      boldText = configuration.fontWeightAdjustment > 0;
    }

    return new int[] {
      reducedMotion ? 1 : 0,
      boldText ? 1 : 0,
      highContrast ? 1 : 0,
      0,
      screenReader ? 1 : 0,
      darkMode ? 1 : 0,
      0,
      0
    };
  }

  public static String locationPermissionStatus() {
    Context context = applicationContext;
    if (context == null) {
      return "denied";
    }
    boolean hasFine = hasPermission(Manifest.permission.ACCESS_FINE_LOCATION);
    boolean hasCoarse = hasPermission(Manifest.permission.ACCESS_COARSE_LOCATION);
    if (!hasFine && !hasCoarse) {
      return "denied";
    }
    if (Build.VERSION.SDK_INT >= 29
        && hasPermission(Manifest.permission.ACCESS_BACKGROUND_LOCATION)) {
      return "authorizedAlways";
    }
    return "authorizedWhenInUse";
  }

  public static boolean isLocationServicesEnabled() {
    LocationManager locationManager = locationManager();
    if (locationManager == null) {
      return false;
    }
    try {
      if (Build.VERSION.SDK_INT >= 28) {
        return locationManager.isLocationEnabled();
      }
      return locationManager.isProviderEnabled(LocationManager.GPS_PROVIDER)
          || locationManager.isProviderEnabled(LocationManager.NETWORK_PROVIDER);
    } catch (RuntimeException ignored) {
      return false;
    }
  }

  public static double[] getCurrentLocation(String accuracy, int timeoutMs) throws Exception {
    if (!hasPermission(Manifest.permission.ACCESS_FINE_LOCATION)
        && !hasPermission(Manifest.permission.ACCESS_COARSE_LOCATION)) {
      throw new SecurityException("PERMISSION_DENIED: Android location permission denied");
    }

    LocationManager locationManager = locationManager();
    if (locationManager == null) {
      throw new IllegalStateException("POSITION_UNAVAILABLE: Android LocationManager is unavailable");
    }
    if (!isLocationServicesEnabled()) {
      throw new IllegalStateException("POSITION_UNAVAILABLE: Android location services are disabled");
    }

    String provider = chooseLocationProvider(locationManager, accuracy);
    if (provider == null) {
      Location lastKnown = bestLastKnownLocation(locationManager);
      if (lastKnown != null) {
        return locationToArray(lastKnown);
      }
      throw new IllegalStateException("POSITION_UNAVAILABLE: No enabled Android location provider");
    }

    int timeout = timeoutMs > 0 ? timeoutMs : 10000;
    Location current =
        Build.VERSION.SDK_INT >= 30
            ? getCurrentLocationApi30(locationManager, provider, timeout)
            : requestSingleLocation(locationManager, provider, timeout);
    if (current == null) {
      current = bestLastKnownLocation(locationManager);
    }
    if (current == null) {
      throw new IOException("POSITION_UNAVAILABLE: Android location provider returned no fix");
    }
    return locationToArray(current);
  }

  public static void fetch(
      final int requestId,
      String method,
      String url,
      String headersText,
      boolean decompress,
      byte[] body) {
    final String normalizedMethod = normalizeMethod(method);
    final Request.Builder builder;
    try {
      builder = new Request.Builder().url(url);
    } catch (RuntimeException error) {
      nativeFetchDidComplete(requestId, 0, error.getMessage(), "", EMPTY_BYTES);
      return;
    }

    boolean hasAcceptEncoding = false;
    Headers parsedHeaders = parseHeaders(headersText);
    for (int i = 0; i < parsedHeaders.size(); i++) {
      String name = parsedHeaders.name(i);
      if ("accept-encoding".equalsIgnoreCase(name)) {
        hasAcceptEncoding = true;
      }
      builder.addHeader(name, parsedHeaders.value(i));
    }
    if (!decompress && !hasAcceptEncoding) {
      builder.header("Accept-Encoding", "identity");
    }

    RequestBody requestBody = null;
    if (body != null) {
      requestBody = new ByteArrayRequestBody(body);
    } else if (requiresRequestBody(normalizedMethod)) {
      requestBody = new ByteArrayRequestBody(EMPTY_BYTES);
    }

    try {
      builder.method(normalizedMethod, requestBody);
    } catch (RuntimeException error) {
      nativeFetchDidComplete(requestId, 0, error.getMessage(), "", EMPTY_BYTES);
      return;
    }

    final Call call = client.newCall(builder.build());
    calls.put(requestId, call);
    call.enqueue(new Callback() {
      @Override
      public void onFailure(Call call, IOException error) {
        calls.remove(requestId);
        nativeFetchDidComplete(
            requestId,
            0,
            error == null ? "Network error" : error.getMessage(),
            "",
            EMPTY_BYTES);
      }

      @Override
      public void onResponse(Call call, Response response) {
        calls.remove(requestId);
        try (Response closeableResponse = response) {
          ResponseBody responseBody = closeableResponse.body();
          byte[] responseBytes = responseBody == null ? EMPTY_BYTES : responseBody.bytes();
          nativeFetchDidComplete(
              requestId,
              closeableResponse.code(),
              closeableResponse.message(),
              formatHeaders(closeableResponse.headers()),
              responseBytes == null ? EMPTY_BYTES : responseBytes);
        } catch (IOException error) {
          nativeFetchDidComplete(
              requestId,
              0,
              error.getMessage(),
              "",
              EMPTY_BYTES);
        }
      }
    });
  }

  public static void cancelFetch(int requestId) {
    Call call = calls.remove(requestId);
    if (call != null) {
      call.cancel();
    }
  }

  public static void connectWebSocket(final int wsId, String url, String protocols) {
    final WsEntry entry = new WsEntry(wsId);
    webSockets.put(wsId, entry);

    Request.Builder builder;
    try {
      builder = new Request.Builder().url(url);
    } catch (RuntimeException error) {
      webSockets.remove(wsId);
      nativeWebSocketDidError(wsId, error.getMessage());
      nativeWebSocketDidClose(wsId, 1006, "Invalid URL", false);
      return;
    }
    if (protocols != null && !protocols.isEmpty()) {
      builder.header("Sec-WebSocket-Protocol", protocols);
    }

    try {
      WebSocket socket = client.newWebSocket(builder.build(), new WebSocketListener() {
        @Override
        public void onOpen(WebSocket webSocket, Response response) {
          entry.socket = webSocket;
          nativeWebSocketDidOpen(
              wsId,
              response == null ? "" : valueOrEmpty(response.header("Sec-WebSocket-Protocol")),
              response == null ? "" : valueOrEmpty(response.header("Sec-WebSocket-Extensions")));
        }

        @Override
        public void onMessage(WebSocket webSocket, String text) {
          deliverOrQueue(entry, new WsMessage(
              text == null ? EMPTY_BYTES : text.getBytes(StandardCharsets.UTF_8),
              true));
        }

        @Override
        public void onMessage(WebSocket webSocket, ByteString bytes) {
          deliverOrQueue(entry, new WsMessage(bytes == null ? EMPTY_BYTES : bytes.toByteArray(), false));
        }

        @Override
        public void onClosing(WebSocket webSocket, int code, String reason) {
          webSocket.close(validCloseCode(code), reason);
        }

        @Override
        public void onClosed(WebSocket webSocket, int code, String reason) {
          webSockets.remove(wsId);
          nativeWebSocketDidClose(wsId, code, valueOrEmpty(reason), true);
        }

        @Override
        public void onFailure(WebSocket webSocket, Throwable error, Response response) {
          webSockets.remove(wsId);
          String message = error == null ? "WebSocket error" : error.getMessage();
          nativeWebSocketDidError(wsId, valueOrEmpty(message));
          nativeWebSocketDidClose(wsId, 1006, valueOrEmpty(message), false);
        }
      });
      entry.socket = socket;
    } catch (RuntimeException error) {
      webSockets.remove(wsId);
      nativeWebSocketDidError(wsId, error.getMessage());
      nativeWebSocketDidClose(wsId, 1006, "WebSocket connect failed", false);
    }
  }

  public static void sendWebSocket(int wsId, byte[] data, boolean isText) {
    WsEntry entry = webSockets.get(wsId);
    WebSocket socket = entry == null ? null : entry.socket;
    if (socket == null) {
      return;
    }
    byte[] bytes = data == null ? EMPTY_BYTES : data;
    boolean accepted = isText
        ? socket.send(new String(bytes, StandardCharsets.UTF_8))
        : socket.send(ByteString.of(bytes));
    if (accepted) {
      nativeWebSocketDidBytesSent(wsId, bytes.length);
    } else {
      nativeWebSocketDidError(wsId, "WebSocket send failed");
    }
  }

  public static void closeWebSocket(int wsId, int code, String reason) {
    WsEntry entry = webSockets.get(wsId);
    WebSocket socket = entry == null ? null : entry.socket;
    if (socket != null) {
      socket.close(validCloseCode(code), valueOrEmpty(reason));
    }
  }

  public static void pauseWebSocket(int wsId) {
    WsEntry entry = webSockets.get(wsId);
    if (entry == null) {
      return;
    }
    synchronized (entry) {
      entry.paused = true;
    }
  }

  public static void resumeWebSocket(int wsId) {
    WsEntry entry = webSockets.get(wsId);
    if (entry == null) {
      return;
    }
    for (;;) {
      WsMessage message;
      synchronized (entry) {
        entry.paused = false;
        message = entry.pending.poll();
        if (message == null) {
          return;
        }
        if (entry.flowControlled) {
          entry.paused = true;
        }
      }
      deliverMessage(entry.id, message);
      synchronized (entry) {
        if (entry.flowControlled) {
          return;
        }
      }
    }
  }

  public static void setWebSocketFlowControlled(int wsId, boolean enabled) {
    WsEntry entry = webSockets.get(wsId);
    if (entry == null) {
      return;
    }
    synchronized (entry) {
      entry.flowControlled = enabled;
    }
  }

  public static byte[] dnsQuery(String hostname, int qtype) throws Exception {
    if (Build.VERSION.SDK_INT < 29) {
      return null;
    }
    final DnsResult result = new DnsResult();
    final CountDownLatch latch = new CountDownLatch(1);
    CancellationSignal cancellationSignal = new CancellationSignal();
    DnsResolver.getInstance().rawQuery(
        null,
        hostname,
        DnsResolver.CLASS_IN,
        qtype,
        DnsResolver.FLAG_EMPTY,
        DIRECT_EXECUTOR,
        cancellationSignal,
        new DnsResolver.Callback<byte[]>() {
          @Override
          public void onAnswer(byte[] answer, int rcode) {
            result.answer = answer;
            result.rcode = rcode;
            latch.countDown();
          }

          @Override
          public void onError(DnsResolver.DnsException error) {
            result.error = error;
            latch.countDown();
          }
        });
    if (!latch.await(10, TimeUnit.SECONDS)) {
      cancellationSignal.cancel();
      throw new TimeoutException("Android DnsResolver query timed out");
    }
    if (result.error != null) {
      throw result.error;
    }
    if (result.rcode != 0) {
      throw new IOException("Android DnsResolver returned rcode " + result.rcode);
    }
    return result.answer == null ? EMPTY_BYTES : result.answer;
  }

  public static String clipboardReadText() {
    Context context = applicationContext;
    if (context == null) {
      return "";
    }
    ClipboardManager clipboard =
        (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
    if (clipboard == null || !clipboard.hasPrimaryClip()) {
      return "";
    }
    ClipData clip = clipboard.getPrimaryClip();
    if (clip == null || clip.getItemCount() == 0) {
      return "";
    }
    CharSequence text = clip.getItemAt(0).coerceToText(context);
    return text == null ? "" : text.toString();
  }

  public static void clipboardWriteText(String text) {
    Context context = applicationContext;
    if (context == null) {
      throw new IllegalStateException("IbexNetworking is not initialized with an Android Context");
    }
    ClipboardManager clipboard =
        (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
    if (clipboard == null) {
      throw new IllegalStateException("Android ClipboardManager is unavailable");
    }
    clipboard.setPrimaryClip(ClipData.newPlainText("Ibex", valueOrEmpty(text)));
  }

  private static void registerPlatformCallbacks(Context context) {
    if (context == null) {
      return;
    }
    // @ref LLP 0008#android-backend-matrix — Android window/navigator and
    // React Native compatibility state comes from platform lifecycle and
    // configuration callbacks instead of JS-side guesses.
    if (!componentCallbacksRegistered) {
      try {
        context.registerComponentCallbacks(new ComponentCallbacks() {
          @Override
          public void onConfigurationChanged(Configuration newConfig) {
            enqueuePlatformEvent("{\"type\":\"configuration\"}");
          }

          @Override
          public void onLowMemory() {
            enqueuePlatformEvent("{\"type\":\"memoryWarning\"}");
          }
        });
        componentCallbacksRegistered = true;
      } catch (RuntimeException ignored) {
        // Embedders can still call the public notify* hooks.
      }
    }

    if (!lifecycleCallbacksRegistered && context instanceof Application) {
      try {
        ((Application) context).registerActivityLifecycleCallbacks(
            new Application.ActivityLifecycleCallbacks() {
              @Override
              public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
                captureInitialIntent(activity);
              }

              @Override
              public void onActivityStarted(Activity activity) {
                notifyActivityStarted(activity);
              }

              @Override
              public void onActivityResumed(Activity activity) {
                notifyActivityResumed(activity);
              }

              @Override
              public void onActivityPaused(Activity activity) {
                notifyActivityPaused(activity);
              }

              @Override
              public void onActivityStopped(Activity activity) {
                notifyActivityStopped(activity);
              }

              @Override
              public void onActivitySaveInstanceState(Activity activity, Bundle outState) {}

              @Override
              public void onActivityDestroyed(Activity activity) {
                notifyActivityDestroyed(activity);
              }
            });
        lifecycleCallbacksRegistered = true;
      } catch (RuntimeException ignored) {
        // Embedders can still call the public notify* hooks.
      }
    }
  }

  private static void captureInitialIntent(Context context) {
    if (context instanceof Activity) {
      recordIntent(((Activity) context).getIntent(), true);
    }
  }

  private static void recordIntent(Intent intent, boolean initialOnly) {
    if (intent == null) {
      return;
    }
    String url = null;
    try {
      if (intent.getDataString() != null && !intent.getDataString().isEmpty()) {
        url = intent.getDataString();
      }
    } catch (RuntimeException ignored) {
      url = null;
    }
    if (url == null || url.isEmpty()) {
      return;
    }
    if (initialUrl == null) {
      initialUrl = url;
    }
    if (!initialOnly) {
      enqueuePlatformEvent("{\"type\":\"url\",\"url\":" + jsonString(url) + "}");
    }
  }

  private static void updateAppState(String state) {
    if (state == null || state.isEmpty() || state.equals(currentAppState)) {
      return;
    }
    currentAppState = state;
    enqueuePlatformEvent("{\"type\":\"appState\",\"state\":" + jsonString(state) + "}");
  }

  private static void enqueuePlatformEvent(String eventJson) {
    synchronized (platformEvents) {
      platformEvents.addLast(eventJson);
    }
    try {
      nativePlatformEventAvailable();
    } catch (UnsatisfiedLinkError ignored) {
      // Java-only test harnesses can still drain the queued events directly.
    }
  }

  private static Resources currentResources() {
    Context context = applicationContext;
    return context == null ? Resources.getSystem() : context.getResources();
  }

  private static Configuration currentConfiguration() {
    return currentResources().getConfiguration();
  }

  private static void addLocaleTag(ArrayList<String> tags, Locale locale) {
    if (locale == null) {
      return;
    }
    String tag = locale.toLanguageTag();
    if (tag != null && !tag.isEmpty() && !"und".equals(tag)) {
      tags.add(tag);
    }
  }

  private static float animationScale(Context context, String settingName) {
    try {
      return Settings.Global.getFloat(context.getContentResolver(), settingName, 1.0f);
    } catch (RuntimeException ignored) {
      return 1.0f;
    }
  }

  private static boolean isHighContrastTextEnabled(AccessibilityManager accessibilityManager) {
    try {
      Object result = AccessibilityManager.class
          .getMethod("isHighContrastTextEnabled")
          .invoke(accessibilityManager);
      return result instanceof Boolean && ((Boolean) result).booleanValue();
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      return false;
    }
  }

  private static boolean hasPermission(String permission) {
    Context context = applicationContext;
    if (context == null) {
      return false;
    }
    try {
      if (context.getApplicationInfo() == null
          || context.getApplicationInfo().uid != android.os.Process.myUid()) {
        return false;
      }
    } catch (RuntimeException ignored) {
      return false;
    }
    return context != null
        && context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED;
  }

  private static LocationManager locationManager() {
    Context context = applicationContext;
    return context == null
        ? null
        : (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
  }

  private static String chooseLocationProvider(LocationManager locationManager, String accuracy) {
    boolean highAccuracy = "best".equals(accuracy) || "nearestTenMeters".equals(accuracy);
    String first = highAccuracy ? LocationManager.GPS_PROVIDER : LocationManager.NETWORK_PROVIDER;
    String second = highAccuracy ? LocationManager.NETWORK_PROVIDER : LocationManager.GPS_PROVIDER;
    if (isProviderEnabled(locationManager, first)) {
      return first;
    }
    if (isProviderEnabled(locationManager, second)) {
      return second;
    }
    if (isProviderEnabled(locationManager, LocationManager.PASSIVE_PROVIDER)) {
      return LocationManager.PASSIVE_PROVIDER;
    }
    return null;
  }

  private static boolean isProviderEnabled(LocationManager locationManager, String provider) {
    try {
      return locationManager.isProviderEnabled(provider);
    } catch (RuntimeException ignored) {
      return false;
    }
  }

  private static Location getCurrentLocationApi30(
      LocationManager locationManager,
      String provider,
      int timeoutMs) throws Exception {
    final CountDownLatch latch = new CountDownLatch(1);
    final LocationResult result = new LocationResult();
    CancellationSignal cancellationSignal = new CancellationSignal();
    locationManager.getCurrentLocation(
        provider,
        cancellationSignal,
        DIRECT_EXECUTOR,
        new Consumer<Location>() {
          @Override
          public void accept(Location location) {
            result.location = location;
            latch.countDown();
          }
        });
    if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
      cancellationSignal.cancel();
      throw new TimeoutException("TIMEOUT: Android current location request timed out");
    }
    return result.location;
  }

  private static Location requestSingleLocation(
      LocationManager locationManager,
      String provider,
      int timeoutMs) throws Exception {
    final CountDownLatch latch = new CountDownLatch(1);
    final LocationResult result = new LocationResult();
    final HandlerThread thread = new HandlerThread("IbexLocation");
    thread.start();
    LocationListener listener = new LocationListener() {
      @Override
      public void onLocationChanged(Location location) {
        result.location = location;
        latch.countDown();
      }

      @Override
      public void onStatusChanged(String provider, int status, Bundle extras) {}

      @Override
      public void onProviderEnabled(String provider) {}

      @Override
      public void onProviderDisabled(String provider) {
        latch.countDown();
      }
    };
    try {
      locationManager.requestSingleUpdate(provider, listener, thread.getLooper());
      if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
        throw new TimeoutException("TIMEOUT: Android single location request timed out");
      }
      return result.location;
    } finally {
      locationManager.removeUpdates(listener);
      if (Build.VERSION.SDK_INT >= 18) {
        thread.quitSafely();
      } else {
        thread.quit();
      }
    }
  }

  private static Location bestLastKnownLocation(LocationManager locationManager) {
    Location best = null;
    String[] providers = new String[] {
      LocationManager.GPS_PROVIDER,
      LocationManager.NETWORK_PROVIDER,
      LocationManager.PASSIVE_PROVIDER
    };
    for (String provider : providers) {
      try {
        Location candidate = locationManager.getLastKnownLocation(provider);
        if (candidate != null
            && (best == null || candidate.getTime() > best.getTime())) {
          best = candidate;
        }
      } catch (RuntimeException ignored) {
        // Try the next provider.
      }
    }
    return best;
  }

  private static double[] locationToArray(Location location) {
    double altitude = location.hasAltitude() ? location.getAltitude() : Double.NaN;
    double verticalAccuracy = Double.NaN;
    if (Build.VERSION.SDK_INT >= 26 && location.hasVerticalAccuracy()) {
      verticalAccuracy = location.getVerticalAccuracyMeters();
    }
    return new double[] {
      location.getLatitude(),
      location.getLongitude(),
      altitude,
      location.hasAccuracy() ? location.getAccuracy() : Double.NaN,
      verticalAccuracy,
      location.getTime()
    };
  }

  private static Headers parseHeaders(String headersText) {
    Headers.Builder builder = new Headers.Builder();
    if (headersText == null || headersText.isEmpty()) {
      return builder.build();
    }
    String[] lines = headersText.split("\\r?\\n");
    for (String line : lines) {
      if (line == null || line.isEmpty()) {
        continue;
      }
      int colon = line.indexOf(':');
      if (colon <= 0) {
        continue;
      }
      String name = line.substring(0, colon).trim();
      String value = line.substring(colon + 1).trim();
      if (!name.isEmpty()) {
        try {
          builder.add(name, value);
        } catch (IllegalArgumentException ignored) {
          Log.w(TAG, "Ignoring invalid request header: " + name);
        }
      }
    }
    return builder.build();
  }

  private static String formatHeaders(Headers headers) {
    StringBuilder out = new StringBuilder();
    for (int i = 0; i < headers.size(); i++) {
      out.append(headers.name(i))
          .append(": ")
          .append(headers.value(i))
          .append("\r\n");
    }
    return out.toString();
  }

  private static String normalizeMethod(String method) {
    if (method == null || method.isEmpty()) {
      return "GET";
    }
    return method.toUpperCase(Locale.US);
  }

  private static boolean requiresRequestBody(String method) {
    return "POST".equals(method)
        || "PUT".equals(method)
        || "PATCH".equals(method)
        || "PROPPATCH".equals(method)
        || "REPORT".equals(method);
  }

  private static int validCloseCode(int code) {
    if (code == 1005 || code < 1000 || code >= 5000) {
      return 1000;
    }
    return code;
  }

  private static String valueOrEmpty(String value) {
    return value == null ? "" : value;
  }

  private static String jsonString(String value) {
    String text = value == null ? "" : value;
    StringBuilder builder = new StringBuilder(text.length() + 2);
    builder.append('"');
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      switch (c) {
        case '"':
          builder.append("\\\"");
          break;
        case '\\':
          builder.append("\\\\");
          break;
        case '\b':
          builder.append("\\b");
          break;
        case '\f':
          builder.append("\\f");
          break;
        case '\n':
          builder.append("\\n");
          break;
        case '\r':
          builder.append("\\r");
          break;
        case '\t':
          builder.append("\\t");
          break;
        default:
          if (c < 0x20) {
            builder.append(String.format(Locale.US, "\\u%04x", (int) c));
          } else {
            builder.append(c);
          }
      }
    }
    builder.append('"');
    return builder.toString();
  }

  private static void deliverOrQueue(WsEntry entry, WsMessage message) {
    synchronized (entry) {
      if (entry.paused) {
        entry.pending.add(message);
        return;
      }
      if (entry.flowControlled) {
        entry.paused = true;
      }
    }
    deliverMessage(entry.id, message);
  }

  private static void deliverMessage(int wsId, WsMessage message) {
    nativeWebSocketDidMessage(wsId, message.bytes, message.isText);
  }

  private static final class ByteArrayRequestBody extends RequestBody {
    private final byte[] data;

    ByteArrayRequestBody(byte[] data) {
      this.data = data == null ? EMPTY_BYTES : data;
    }

    @Override
    public MediaType contentType() {
      return null;
    }

    @Override
    public long contentLength() {
      return data.length;
    }

    @Override
    public void writeTo(BufferedSink sink) throws IOException {
      sink.write(data);
    }
  }

  private static final class WsEntry {
    final int id;
    final ArrayDeque<WsMessage> pending = new ArrayDeque<>();
    volatile WebSocket socket;
    boolean paused;
    boolean flowControlled;

    WsEntry(int id) {
      this.id = id;
    }
  }

  private static final class WsMessage {
    final byte[] bytes;
    final boolean isText;

    WsMessage(byte[] bytes, boolean isText) {
      this.bytes = bytes == null ? EMPTY_BYTES : bytes;
      this.isText = isText;
    }
  }

  private static final class DnsResult {
    byte[] answer;
    int rcode;
    Exception error;
  }

  private static final class LocationResult {
    Location location;
  }

  private static native void nativeFetchDidComplete(
      int requestId,
      int status,
      String statusText,
      String headers,
      byte[] body);

  private static native void nativeWebSocketDidOpen(
      int wsId,
      String protocol,
      String extensions);

  private static native void nativeWebSocketDidMessage(
      int wsId,
      byte[] data,
      boolean isText);

  private static native void nativeWebSocketDidClose(
      int wsId,
      int code,
      String reason,
      boolean wasClean);

  private static native void nativeWebSocketDidError(int wsId, String message);

  private static native void nativeWebSocketDidBytesSent(int wsId, long bytesSent);

  private static native void nativePlatformEventAvailable();
}
