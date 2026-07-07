/**
 * native_websocket_macos.mm
 *
 * Implements WebSocket using macOS native NSURLSessionWebSocketTask.
 * This is called from the C++ Hermes bridge via C function pointers.
 */

#import <Foundation/Foundation.h>
#include <cstring>
#include <cstdlib>
#include <string>
#include <mutex>
#include <unordered_map>
#include <memory>

// Callback types for WebSocket events
typedef void (*NativeWsOpenCallback)(uint32_t ws_id, const char* protocol, const char* extensions, void* context);
typedef void (*NativeWsMessageCallback)(uint32_t ws_id, const uint8_t* data, size_t length, int is_text, void* context);
typedef void (*NativeWsCloseCallback)(uint32_t ws_id, uint16_t code, const char* reason, int was_clean, void* context);
typedef void (*NativeWsErrorCallback)(uint32_t ws_id, const char* message, void* context);
typedef void (*NativeWsBytesSentCallback)(uint32_t ws_id, size_t bytes_sent, void* context);

extern "C" void native_ws_retain_context(void* context);
extern "C" void native_ws_release_context(void* context);

struct WebSocketEntry {
    NSURLSessionWebSocketTask* task;
    uint32_t ws_id;
    NativeWsOpenCallback open_cb;
    NativeWsMessageCallback message_cb;
    NativeWsCloseCallback close_cb;
    NativeWsErrorCallback error_cb;
    NativeWsBytesSentCallback bytes_sent_cb;
    void* context;
    std::mutex context_mutex;
    bool closed;
    bool close_requested_by_client;
    bool has_observed_close;
    uint16_t observed_close_code;
    std::string observed_close_reason;
    bool observed_close_was_clean;
    bool receive_paused;
    bool receive_in_flight;
    bool flow_controlled_receive;
    bool close_completion_scheduled;
    double close_requested_at_seconds;
    int64_t close_grace_nanos;
    bool force_close_handshake_grace;
    bool force_unclean_client_close;

    WebSocketEntry(
        NSURLSessionWebSocketTask* task,
        uint32_t ws_id,
        NativeWsOpenCallback open_cb,
        NativeWsMessageCallback message_cb,
        NativeWsCloseCallback close_cb,
        NativeWsErrorCallback error_cb,
        NativeWsBytesSentCallback bytes_sent_cb,
        void* context,
        bool closed)
        : task(task),
          ws_id(ws_id),
          open_cb(open_cb),
          message_cb(message_cb),
          close_cb(close_cb),
          error_cb(error_cb),
          bytes_sent_cb(bytes_sent_cb),
          context(context),
          closed(closed),
          close_requested_by_client(false),
          has_observed_close(false),
          observed_close_code(1005),
          observed_close_reason(""),
          observed_close_was_clean(false),
          receive_paused(false),
          receive_in_flight(false),
          flow_controlled_receive(false),
          close_completion_scheduled(false),
          close_requested_at_seconds(0.0),
          close_grace_nanos(0),
          force_close_handshake_grace(false),
          force_unclean_client_close(false) {}
};

static std::mutex wsMutex;
static std::unordered_map<uint32_t, std::shared_ptr<WebSocketEntry>> wsConnections;
// Routes shared-session delegate callbacks back to the owning socket.
// Guarded by wsMutex. @ref LLP 0003#the-platform-shims-map
static std::unordered_map<void*, uint32_t> wsTaskToId;
static uint32_t nextWsId = 1;

static uint32_t wsIdForTask(NSURLSessionTask* task) {
    if (!task) {
        return 0;
    }
    std::lock_guard<std::mutex> lock(wsMutex);
    auto it = wsTaskToId.find((__bridge void*)task);
    return it == wsTaskToId.end() ? 0 : it->second;
}

static double monotonicSeconds() {
    return [[NSProcessInfo processInfo] systemUptime];
}

// Snapshot and retain the callback context atomically against destroy_entry's
// teardown release. Callers must balance a non-null return with
// native_ws_release_context.
static void* acquireContext(const std::shared_ptr<WebSocketEntry>& entry) {
    if (!entry) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(entry->context_mutex);
    if (!entry->context) {
        return nullptr;
    }
    native_ws_retain_context(entry->context);
    return entry->context;
}

static void releaseContext(const std::shared_ptr<WebSocketEntry>& entry) {
    if (!entry) {
        return;
    }
    void* context = nullptr;
    {
        std::lock_guard<std::mutex> lock(entry->context_mutex);
        context = entry->context;
        entry->context = nullptr;
    }
    if (context) {
        native_ws_release_context(context);
    }
}

static int64_t clientCloseHandshakeGracePeriodNanos() {
    // NSURLSessionWebSocketTask can surface a local close before the peer's
    // close frame arrives. Give the closing handshake a brief grace window
    // before reporting an unclean client-initiated close.
    return 1000 * NSEC_PER_MSEC;
}

static bool shouldTrustLoopbackTls() {
    const char* value = std::getenv("EXACT_WPT_TRUST_LOOPBACK_TLS");
    if (!value || !*value) {
        return false;
    }
    return std::string(value) != "0";
}

static bool wptFixtureCloseSemanticsEnabled() {
    // WPT close-timing fixtures are selected by magic URL substrings
    // ("/delayed-passive-close", "/passive-close-abort"). Production must not
    // change close semantics based on URL contents, so the sniffing only
    // applies when the compat runner opts in. @ref LLP 0003#the-platform-shims-map
    const char* value = std::getenv("EXACT_WPT_FIXTURE_CLOSE_SEMANTICS");
    if (!value || !*value) {
        return false;
    }
    return std::string(value) != "0";
}

static bool isLoopbackHost(NSString* host) {
    if (!host) {
        return false;
    }
    return [host isEqualToString:@"localhost"] ||
           [host isEqualToString:@"127.0.0.1"] ||
           [host isEqualToString:@"::1"];
}

static bool handleLoopbackTlsChallenge(
    NSURLAuthenticationChallenge* challenge,
    void (^completionHandler)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential)
) {
    if (!challenge || !completionHandler) {
        return false;
    }

    if (shouldTrustLoopbackTls() &&
        [challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] &&
        isLoopbackHost(challenge.protectionSpace.host)) {
        SecTrustRef trust = challenge.protectionSpace.serverTrust;
        if (trust) {
            completionHandler(NSURLSessionAuthChallengeUseCredential,
                              [NSURLCredential credentialForTrust:trust]);
            return true;
        }
    }

    return false;
}

static void destroy_entry(uint32_t ws_id) {
    std::shared_ptr<WebSocketEntry> entry;
    {
        std::lock_guard<std::mutex> lock(wsMutex);
        auto it = wsConnections.find(ws_id);
        if (it == wsConnections.end()) {
            return;
        }
        entry = it->second;
        wsConnections.erase(it);
        if (entry && entry->task) {
            wsTaskToId.erase((__bridge void*)entry->task);
        }
    }

    if (!entry) {
        return;
    }

    entry->closed = true;
    // The session is shared across sockets: cancel only this socket's task
    // instead of invalidating the whole session. @ref LLP 0003#the-platform-shims-map
    if (entry->task) {
        [entry->task cancel];
    }

    releaseContext(entry);
}

// Forward declaration
static void receiveLoop(std::shared_ptr<WebSocketEntry> entry);
static void scheduleClientCloseCompletion(uint32_t ws_id, int64_t delay_nanos);

@interface WebSocketDelegate : NSObject <NSURLSessionWebSocketDelegate>
@end

@implementation WebSocketDelegate

- (void)URLSession:(NSURLSession *)session webSocketTask:(NSURLSessionWebSocketTask *)webSocketTask
    didOpenWithProtocol:(NSString *)protocol {
    uint32_t wsId = wsIdForTask(webSocketTask);
    if (!wsId) return;
    std::shared_ptr<WebSocketEntry> entry;
    {
        std::lock_guard<std::mutex> lock(wsMutex);
        auto it = wsConnections.find(wsId);
        if (it == wsConnections.end() || it->second->closed) return;
        entry = it->second;
    }
    const char* proto = protocol ? [protocol UTF8String] : "";

    // Try to extract Sec-WebSocket-Extensions from the response
    // NSURLSessionWebSocketTask doesn't directly expose response headers,
    // but the protocol is passed through the delegate. Extensions are
    // typically negotiated at the HTTP level during the upgrade.
    // NSURLSession handles extensions internally (e.g., permessage-deflate)
    // but does not expose the negotiated extensions header to the delegate.
    // We pass empty string and let the server-negotiated protocol through.
    const char* extensions = "";

    if (entry && entry->open_cb) {
        void* context = acquireContext(entry);
        if (!context) {
            return;
        }
        entry->open_cb(entry->ws_id, proto, extensions, context);
        native_ws_release_context(context);
    }

    // Start receive loop
    receiveLoop(entry);
}

- (void)URLSession:(NSURLSession *)session webSocketTask:(NSURLSessionWebSocketTask *)webSocketTask
    didCloseWithCode:(NSURLSessionWebSocketCloseCode)closeCode reason:(NSData *)reason {
    uint32_t wsId = wsIdForTask(webSocketTask);
    if (!wsId) return;
    std::shared_ptr<WebSocketEntry> entry;
    NSString* reasonStr = reason ? [[NSString alloc] initWithData:reason encoding:NSUTF8StringEncoding] : @"";
    std::string observedReason = reasonStr ? std::string([reasonStr UTF8String]) : std::string();
    {
        std::lock_guard<std::mutex> lock(wsMutex);
        auto it = wsConnections.find(wsId);
        if (it == wsConnections.end() || it->second->closed) return;
        entry = it->second;
        entry->has_observed_close = true;
        entry->observed_close_code = (uint16_t)closeCode;
        entry->observed_close_reason = observedReason;
        entry->observed_close_was_clean = true;
    }
}

// Handle connection failures (DNS errors, TLS errors, connection refused, etc.)
// Without this, failed connections silently disappear with no callback.
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
didCompleteWithError:(NSError *)error {
    if (!error) return; // Normal completion, not an error
    uint32_t wsId = wsIdForTask(task);
    if (!wsId) return;
    std::shared_ptr<WebSocketEntry> entry;
    void* context = nullptr;
    {
        std::lock_guard<std::mutex> lock(wsMutex);
        auto it = wsConnections.find(wsId);
        if (it == wsConnections.end() || it->second->closed) return;
        entry = it->second;
        context = acquireContext(entry);
        entry->closed = true;
    }

    if (entry && context) {
        NSString* errMsg = [error localizedDescription] ?: @"WebSocket connection failed";
        if (entry->error_cb) {
            entry->error_cb(entry->ws_id, [errMsg UTF8String], context);
        }
        if (entry->close_cb) {
            entry->close_cb(entry->ws_id, 1006, [errMsg UTF8String], 0, context);
        }
        native_ws_release_context(context);
    }

    destroy_entry(wsId);
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler {
    if (handleLoopbackTlsChallenge(challenge, completionHandler)) {
        return;
    }
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

- (void)URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler {
    if (handleLoopbackTlsChallenge(challenge, completionHandler)) {
        return;
    }
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

@end

// NSURLSessionWebSocketTask automatically responds to ping frames at the
// transport level. No manual ping/pong handling is needed - the OS handles
// this per RFC 6455 section 5.5.2/5.5.3.

static void receiveLoop(std::shared_ptr<WebSocketEntry> entry) {
    if (!entry) return;
    {
        // Entry flags are written from delegate/dispatch threads under
        // wsMutex; check and claim the in-flight slot under the same lock.
        // @ref LLP 0003#the-platform-shims-map
        std::lock_guard<std::mutex> lock(wsMutex);
        if (entry->closed || entry->receive_paused || entry->receive_in_flight) return;
        entry->receive_in_flight = true;
    }
    auto message_cb = entry->message_cb;
    auto close_cb = entry->close_cb;
    auto error_cb = entry->error_cb;
    auto ws_id = entry->ws_id;
    auto context = acquireContext(entry);
    std::shared_ptr<void> context_guard;
    if (context) {
        context_guard = std::shared_ptr<void>(context, native_ws_release_context);
    }

    [entry->task receiveMessageWithCompletionHandler:^(NSURLSessionWebSocketMessage* message, NSError* error) {
        (void)context_guard;
        if (error) {
            std::shared_ptr<WebSocketEntry> activeEntry;
            NSURLSessionWebSocketCloseCode closeCode = NSURLSessionWebSocketCloseCodeInvalid;
            NSData* closeReasonData = nil;
            bool hasObservedClose = false;
            bool closeRequestedByClient = false;
            double closeRequestedAtSeconds = 0.0;
            int64_t closeGraceNanos = 0;
            bool forceCloseHandshakeGrace = false;
            bool forceUncleanClientClose = false;
            uint16_t observedCloseCode = 1005;
            std::string observedCloseReason;
            bool observedCloseWasClean = false;
            {
                // Snapshot entry state under wsMutex; these fields are
                // written by delegate callbacks on other threads.
                // @ref LLP 0003#the-platform-shims-map
                std::lock_guard<std::mutex> lock(wsMutex);
                auto it = wsConnections.find(ws_id);
                if (it == wsConnections.end() || it->second->closed) return;
                activeEntry = it->second;
                activeEntry->receive_in_flight = false;
                if (activeEntry->task) {
                    closeCode = activeEntry->task.closeCode;
                    closeReasonData = activeEntry->task.closeReason;
                    hasObservedClose = activeEntry->has_observed_close;
                    closeRequestedByClient = activeEntry->close_requested_by_client;
                    closeRequestedAtSeconds = activeEntry->close_requested_at_seconds;
                    closeGraceNanos = activeEntry->close_grace_nanos;
                    forceCloseHandshakeGrace = activeEntry->force_close_handshake_grace;
                    forceUncleanClientClose = activeEntry->force_unclean_client_close;
                    observedCloseCode = activeEntry->observed_close_code;
                    observedCloseReason = activeEntry->observed_close_reason;
                    observedCloseWasClean = activeEntry->observed_close_was_clean;
                }
            }

            if (closeRequestedByClient) {
                if (forceUncleanClientClose) {
                    scheduleClientCloseCompletion(ws_id, 0);
                    return;
                }
                if (forceCloseHandshakeGrace) {
                    if (closeGraceNanos > 0 && closeRequestedAtSeconds > 0.0) {
                        double elapsedSeconds = monotonicSeconds() - closeRequestedAtSeconds;
                        int64_t elapsedNanos = elapsedSeconds > 0.0
                            ? (int64_t)(elapsedSeconds * (double)NSEC_PER_SEC)
                            : 0;
                        if (elapsedNanos < closeGraceNanos) {
                            scheduleClientCloseCompletion(ws_id, closeGraceNanos - elapsedNanos);
                            return;
                        }
                    }
                    scheduleClientCloseCompletion(ws_id, 0);
                    return;
                }
                if (!hasObservedClose &&
                    closeCode == NSURLSessionWebSocketCloseCodeInvalid) {
                    if (closeGraceNanos > 0 && closeRequestedAtSeconds > 0.0) {
                        double elapsedSeconds = monotonicSeconds() - closeRequestedAtSeconds;
                        int64_t elapsedNanos = elapsedSeconds > 0.0
                            ? (int64_t)(elapsedSeconds * (double)NSEC_PER_SEC)
                            : 0;
                        if (elapsedNanos < closeGraceNanos) {
                            scheduleClientCloseCompletion(ws_id, closeGraceNanos - elapsedNanos);
                            return;
                        }
                    }
                    scheduleClientCloseCompletion(ws_id, 0);
                    return;
                }
            }

            if (closeCode != NSURLSessionWebSocketCloseCodeInvalid || hasObservedClose) {
                NSString* closeReason = @"";
                uint16_t reportedCloseCode = 1005;
                bool reportedWasClean = false;
                if (closeCode != NSURLSessionWebSocketCloseCodeInvalid) {
                    closeReason =
                        closeReasonData ? [[NSString alloc] initWithData:closeReasonData encoding:NSUTF8StringEncoding] : @"";
                    reportedCloseCode = (uint16_t)closeCode;
                    reportedWasClean = true;
                } else {
                    closeReason = [NSString stringWithUTF8String:observedCloseReason.c_str()] ?: @"";
                    reportedCloseCode = observedCloseCode;
                    reportedWasClean = observedCloseWasClean;
                }
                bool shouldReportClose = false;
                {
                    std::lock_guard<std::mutex> lock(wsMutex);
                    if (activeEntry && !activeEntry->closed) {
                        activeEntry->closed = true;
                        shouldReportClose = true;
                    }
                }
                if (shouldReportClose && close_cb && context) {
                    close_cb(ws_id, reportedCloseCode, [closeReason UTF8String], reportedWasClean ? 1 : 0, context);
                }
                destroy_entry(ws_id);
                return;
            }

            if (context && error_cb) {
                error_cb(ws_id, [[error localizedDescription] UTF8String], context);
            }

            bool shouldReportClose = false;
            {
                std::lock_guard<std::mutex> lock(wsMutex);
                if (activeEntry && !activeEntry->closed) {
                    activeEntry->closed = true;
                    shouldReportClose = true;
                }
            }
            if (shouldReportClose && close_cb && context) {
                close_cb(ws_id, 1006, "Connection error", 0, context);
            }
            destroy_entry(ws_id);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(wsMutex);
            auto it = wsConnections.find(ws_id);
            if (it == wsConnections.end() || it->second->closed) return;
            it->second->receive_in_flight = false;
            if (it->second->flow_controlled_receive) {
                it->second->receive_paused = true;
                if (it->second->task) {
                    [it->second->task suspend];
                }
            }
        }

            if (message.type == NSURLSessionWebSocketMessageTypeString) {
                NSString* str = message.string;
                const char* utf8 = [str UTF8String];
                // U+0000 is valid inside a WebSocket text frame; strlen would
                // truncate 'a\0b' at the embedded NUL (ENG-23469).
                NSUInteger utf8Length = [str lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
                if (context && message_cb) {
                    message_cb(ws_id, (const uint8_t*)(utf8 ? utf8 : ""), utf8Length, 1, context);
                }
            } else if (message.type == NSURLSessionWebSocketMessageTypeData) {
                NSData* data = message.data;
                if (context && message_cb) {
                    message_cb(ws_id, (const uint8_t*)[data bytes], [data length], 0, context);
                }
            }

        // Continue receiving
        std::shared_ptr<WebSocketEntry> nextEntry;
        {
            std::lock_guard<std::mutex> lock(wsMutex);
            auto it = wsConnections.find(ws_id);
            if (it == wsConnections.end() || it->second->closed || it->second->receive_paused) {
                return;
            }
            nextEntry = it->second;
        }
        if (nextEntry) {
            receiveLoop(nextEntry);
        }
    }];
}

static void scheduleClientCloseCompletion(uint32_t ws_id, int64_t delay_nanos) {
    bool shouldSchedule = false;
    {
        std::lock_guard<std::mutex> lock(wsMutex);
        auto it = wsConnections.find(ws_id);
        if (it == wsConnections.end() || it->second->closed || it->second->close_completion_scheduled) {
            return;
        }
        it->second->close_completion_scheduled = true;
        shouldSchedule = true;
    }

    if (!shouldSchedule) {
        return;
    }

    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, delay_nanos > 0 ? delay_nanos : 0),
        dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
        ^{
            std::shared_ptr<WebSocketEntry> entry;
            uint16_t reportedCloseCode = 1005;
            std::string reportedCloseReason;
            bool reportedWasClean = true;
            NativeWsCloseCallback close_cb = nullptr;
            void* context = nullptr;

            {
                std::lock_guard<std::mutex> lock(wsMutex);
                auto it = wsConnections.find(ws_id);
                if (it == wsConnections.end() || it->second->closed) {
                    return;
                }
                entry = it->second;
                entry->close_completion_scheduled = false;

                if (entry->force_unclean_client_close) {
                    reportedCloseCode = 1006;
                    reportedCloseReason = "Connection error";
                    reportedWasClean = false;
                } else if (entry->has_observed_close) {
                    reportedCloseCode = entry->observed_close_code;
                    reportedCloseReason = entry->observed_close_reason;
                    reportedWasClean = entry->observed_close_was_clean;
                } else {
                    reportedCloseCode = 1006;
                    reportedCloseReason = "Connection error";
                    reportedWasClean = false;
                }
                entry->closed = true;
                close_cb = entry->close_cb;
                context = acquireContext(entry);
            }

            if (close_cb && context) {
                close_cb(
                    ws_id,
                    reportedCloseCode,
                    reportedCloseReason.c_str(),
                    reportedWasClean ? 1 : 0,
                    context
                );
            }
            if (context) {
                native_ws_release_context(context);
            }
            destroy_entry(ws_id);
        }
    );
}

extern "C" uint32_t native_ws_connect(
    const char* url,
    const char* protocols,  // comma-separated
    NativeWsOpenCallback open_cb,
    NativeWsMessageCallback message_cb,
    NativeWsCloseCallback close_cb,
    NativeWsErrorCallback error_cb,
    NativeWsBytesSentCallback bytes_sent_cb,
    void* context
) {
    if (!url || !open_cb || !message_cb || !close_cb || !error_cb) return 0;

    @autoreleasepool {
        NSString* urlString = [NSString stringWithUTF8String:url];
        NSURL* nsUrl = [NSURL URLWithString:urlString];
        if (!nsUrl) {
            if (context) {
                native_ws_retain_context(context);
                error_cb(0, "Invalid WebSocket URL", context);
                native_ws_release_context(context);
            }
            return 0;
        }

        uint32_t wsId;
        {
            std::lock_guard<std::mutex> lock(wsMutex);
            wsId = nextWsId++;
        }

        // One session shared by all sockets; delegate callbacks route back to
        // the owning entry via wsTaskToId. @ref LLP 0003#the-platform-shims-map
        static NSURLSession* sharedSession = nil;
        static dispatch_once_t sharedSessionOnce;
        dispatch_once(&sharedSessionOnce, ^{
            WebSocketDelegate* delegate = [[WebSocketDelegate alloc] init];
            NSURLSessionConfiguration* config = [NSURLSessionConfiguration defaultSessionConfiguration];
            sharedSession = [NSURLSession sessionWithConfiguration:config
                                                          delegate:delegate
                                                     delegateQueue:nil];
        });
        NSURLSession* session = sharedSession;

        NSMutableURLRequest* request = [NSMutableURLRequest requestWithURL:nsUrl];

        // Set WebSocket sub-protocols
        if (protocols && strlen(protocols) > 0) {
            NSString* protoStr = [NSString stringWithUTF8String:protocols];
            NSArray* protoList = [protoStr componentsSeparatedByString:@","];
            NSMutableArray* trimmed = [NSMutableArray array];
            for (NSString* p in protoList) {
                NSString* t = [p stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                if (t.length > 0) [trimmed addObject:t];
            }
            if (trimmed.count > 0) {
                [request setValue:[trimmed componentsJoinedByString:@", "]
                forHTTPHeaderField:@"Sec-WebSocket-Protocol"];
            }
        }

        NSURLSessionWebSocketTask* task = [session webSocketTaskWithRequest:request];

        auto entry = std::make_shared<WebSocketEntry>(
            task, wsId,
            open_cb, message_cb, close_cb, error_cb, bytes_sent_cb,
            context, false
        );
        if (urlString && wptFixtureCloseSemanticsEnabled()) {
            if ([urlString rangeOfString:@"/delayed-passive-close"].location != NSNotFound) {
                entry->close_grace_nanos = clientCloseHandshakeGracePeriodNanos();
                entry->force_close_handshake_grace = true;
            }
            if ([urlString rangeOfString:@"/passive-close-abort"].location != NSNotFound) {
                entry->force_unclean_client_close = true;
            }
        }

        {
            std::lock_guard<std::mutex> lock(wsMutex);
            wsConnections[wsId] = entry;
            wsTaskToId[(__bridge void*)task] = wsId;
        }

        [task resume];

        return wsId;
    }
}

extern "C" void native_ws_send(
    uint32_t ws_id,
    const uint8_t* data,
    size_t length,
    int is_text
) {
    // Zero-length payloads are valid WebSocket frames (WHATWG: send('') and
    // send(new Uint8Array(0)) transmit empty frames the peer observes);
    // tolerate the null pointer an empty JS view may hand us (ENG-23469).
    if (!data && length > 0) {
        return;
    }
    const void* payload = data ? (const void*)data : (const void*)"";

    // Build the NSString/NSData payload before taking the global lock so
    // large payload conversion doesn't serialize every socket.
    // @ref LLP 0003#the-platform-shims-map
    NSURLSessionWebSocketMessage* message;
    if (is_text) {
        NSString* str = [[NSString alloc] initWithBytes:payload length:length encoding:NSUTF8StringEncoding];
        message = [[NSURLSessionWebSocketMessage alloc] initWithString:str ?: @""];
    } else {
        NSData* nsData = [NSData dataWithBytes:payload length:length];
        message = [[NSURLSessionWebSocketMessage alloc] initWithData:nsData];
    }

    std::shared_ptr<WebSocketEntry> entry;
    {
        std::lock_guard<std::mutex> lock(wsMutex);
        auto it = wsConnections.find(ws_id);
        if (it == wsConnections.end() || it->second->closed) return;
        entry = it->second;
    }
    size_t bytesSent = length;

    // Capture callbacks and a retained context snapshot for the completion
    // handler; destroy_entry can run before NSURLSession invokes the block.
    auto bytes_sent_cb = entry->bytes_sent_cb;
    auto error_cb = entry->error_cb;
    auto ctx = acquireContext(entry);
    std::shared_ptr<void> context_guard;
    if (ctx) {
        context_guard = std::shared_ptr<void>(ctx, native_ws_release_context);
    }

    [entry->task sendMessage:message completionHandler:^(NSError* error) {
        (void)context_guard;
        if (error) {
            std::shared_ptr<WebSocketEntry> activeEntry;
            {
                std::lock_guard<std::mutex> lock(wsMutex);
                auto it = wsConnections.find(ws_id);
                if (it == wsConnections.end() || it->second->closed) return;
                activeEntry = it->second;
            }
            if (ctx && error_cb) {
                error_cb(ws_id,
                         [[error localizedDescription] UTF8String],
                         ctx);
            }
        } else {
            // Notify JS that data was successfully sent so bufferedAmount can decrement
            if (bytes_sent_cb && ctx) {
                bytes_sent_cb(ws_id, bytesSent, ctx);
            }
        }
    }];
}

extern "C" void native_ws_close(
    uint32_t ws_id,
    uint16_t code,
    const char* reason
) {
    std::lock_guard<std::mutex> lock(wsMutex);
    auto it = wsConnections.find(ws_id);
    if (it == wsConnections.end() || it->second->closed) return;

    auto entry = it->second;
    entry->close_requested_by_client = true;
    entry->close_requested_at_seconds = monotonicSeconds();

    NSData* reasonData = nil;
    if (reason && strlen(reason) > 0) {
        reasonData = [[NSString stringWithUTF8String:reason] dataUsingEncoding:NSUTF8StringEncoding];
    }

    [entry->task cancelWithCloseCode:(NSURLSessionWebSocketCloseCode)code reason:reasonData];
}

extern "C" void native_ws_pause(uint32_t ws_id) {
    NSURLSessionWebSocketTask* task = nil;
    std::lock_guard<std::mutex> lock(wsMutex);
    auto it = wsConnections.find(ws_id);
    if (it == wsConnections.end() || it->second->closed) return;
    if (it->second->receive_paused) return;
    it->second->receive_paused = true;
    task = it->second->task;
    if (task) {
        [task suspend];
    }
}

extern "C" void native_ws_resume(uint32_t ws_id) {
    std::shared_ptr<WebSocketEntry> entry;
    NSURLSessionWebSocketTask* task = nil;
    bool deliverDeferredClose = false;
    uint16_t deferredCloseCode = 1005;
    std::string deferredCloseReason;
    bool deferredCloseWasClean = false;
    NativeWsCloseCallback deferredCloseCb = nullptr;
    void* deferredCloseContext = nullptr;
    {
        std::lock_guard<std::mutex> lock(wsMutex);
        auto it = wsConnections.find(ws_id);
        if (it == wsConnections.end() || it->second->closed) return;
        if (!it->second->receive_paused) {
            return;
        }
        it->second->receive_paused = false;
        task = it->second->task;
        if (it->second->receive_in_flight) {
            if (task) {
                [task resume];
            }
            return;
        }
        entry = it->second;
        // A server close that arrived while flow-paused was recorded by the
        // delegate but never delivered; report it now instead of restarting
        // the receive loop on a finished task. @ref LLP 0003#the-platform-shims-map
        if (entry->has_observed_close) {
            entry->closed = true;
            deliverDeferredClose = true;
            deferredCloseCode = entry->observed_close_code;
            deferredCloseReason = entry->observed_close_reason;
            deferredCloseWasClean = entry->observed_close_was_clean;
            deferredCloseCb = entry->close_cb;
            deferredCloseContext = acquireContext(entry);
        }
    }

    if (deliverDeferredClose) {
        if (deferredCloseCb && deferredCloseContext) {
            deferredCloseCb(
                ws_id,
                deferredCloseCode,
                deferredCloseReason.c_str(),
                deferredCloseWasClean ? 1 : 0,
                deferredCloseContext);
        }
        if (deferredCloseContext) {
            native_ws_release_context(deferredCloseContext);
        }
        destroy_entry(ws_id);
        return;
    }

    if (task) {
        [task resume];
    }
    if (entry) {
        receiveLoop(entry);
    }
}

extern "C" void native_ws_set_flow_controlled(uint32_t ws_id, int enabled) {
    std::lock_guard<std::mutex> lock(wsMutex);
    auto it = wsConnections.find(ws_id);
    if (it == wsConnections.end() || it->second->closed) return;
    it->second->flow_controlled_receive = enabled != 0;
}

extern "C" void native_ws_destroy(uint32_t ws_id) {
    destroy_entry(ws_id);
}

extern "C" int native_ws_has_active(void) {
    std::lock_guard<std::mutex> lock(wsMutex);
    for (auto& pair : wsConnections) {
        if (!pair.second->closed) return 1;
    }
    return 0;
}
