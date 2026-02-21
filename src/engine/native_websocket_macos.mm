/**
 * native_websocket_macos.mm
 *
 * Implements WebSocket using macOS native NSURLSessionWebSocketTask.
 * This is called from the C++ Hermes bridge via C function pointers.
 */

#import <Foundation/Foundation.h>
#include <cstring>
#include <string>
#include <mutex>
#include <unordered_map>

// Callback types for WebSocket events
typedef void (*NativeWsOpenCallback)(uint32_t ws_id, const char* protocol, const char* extensions, void* context);
typedef void (*NativeWsMessageCallback)(uint32_t ws_id, const uint8_t* data, size_t length, int is_text, void* context);
typedef void (*NativeWsCloseCallback)(uint32_t ws_id, uint16_t code, const char* reason, int was_clean, void* context);
typedef void (*NativeWsErrorCallback)(uint32_t ws_id, const char* message, void* context);
typedef void (*NativeWsBytesSentCallback)(uint32_t ws_id, size_t bytes_sent, void* context);

struct WebSocketEntry {
    NSURLSessionWebSocketTask* task;
    NSURLSession* session;
    uint32_t ws_id;
    NativeWsOpenCallback open_cb;
    NativeWsMessageCallback message_cb;
    NativeWsCloseCallback close_cb;
    NativeWsErrorCallback error_cb;
    NativeWsBytesSentCallback bytes_sent_cb;
    void* context;
    bool closed;
};

static std::mutex wsMutex;
static std::unordered_map<uint32_t, WebSocketEntry*> wsConnections;
static uint32_t nextWsId = 1;

// Forward declaration
static void receiveLoop(WebSocketEntry* entry);

@interface WebSocketDelegate : NSObject <NSURLSessionWebSocketDelegate>
@property (nonatomic, assign) uint32_t wsId;
@end

@implementation WebSocketDelegate

- (void)URLSession:(NSURLSession *)session webSocketTask:(NSURLSessionWebSocketTask *)webSocketTask
    didOpenWithProtocol:(NSString *)protocol {
    std::lock_guard<std::mutex> lock(wsMutex);
    auto it = wsConnections.find(self.wsId);
    if (it == wsConnections.end() || it->second->closed) return;

    auto* entry = it->second;
    const char* proto = protocol ? [protocol UTF8String] : "";

    // Try to extract Sec-WebSocket-Extensions from the response
    // NSURLSessionWebSocketTask doesn't directly expose response headers,
    // but the protocol is passed through the delegate. Extensions are
    // typically negotiated at the HTTP level during the upgrade.
    // NSURLSession handles extensions internally (e.g., permessage-deflate)
    // but does not expose the negotiated extensions header to the delegate.
    // We pass empty string and let the server-negotiated protocol through.
    const char* extensions = "";

    entry->open_cb(entry->ws_id, proto, extensions, entry->context);

    // Start receive loop
    receiveLoop(entry);
}

- (void)URLSession:(NSURLSession *)session webSocketTask:(NSURLSessionWebSocketTask *)webSocketTask
    didCloseWithCode:(NSURLSessionWebSocketCloseCode)closeCode reason:(NSData *)reason {
    std::lock_guard<std::mutex> lock(wsMutex);
    auto it = wsConnections.find(self.wsId);
    if (it == wsConnections.end() || it->second->closed) return;

    auto* entry = it->second;
    entry->closed = true;

    NSString* reasonStr = reason ? [[NSString alloc] initWithData:reason encoding:NSUTF8StringEncoding] : @"";
    entry->close_cb(entry->ws_id, (uint16_t)closeCode, [reasonStr UTF8String], 1, entry->context);
}

@end

// NSURLSessionWebSocketTask automatically responds to ping frames at the
// transport level. No manual ping/pong handling is needed - the OS handles
// this per RFC 6455 section 5.5.2/5.5.3.

static void receiveLoop(WebSocketEntry* entry) {
    if (entry->closed) return;

    [entry->task receiveMessageWithCompletionHandler:^(NSURLSessionWebSocketMessage* message, NSError* error) {
        if (error) {
            std::lock_guard<std::mutex> lock(wsMutex);
            auto it = wsConnections.find(entry->ws_id);
            if (it == wsConnections.end() || it->second->closed) return;

            entry->error_cb(entry->ws_id, [[error localizedDescription] UTF8String], entry->context);

            if (!entry->closed) {
                entry->closed = true;
                entry->close_cb(entry->ws_id, 1006, "Connection error", 0, entry->context);
            }
            return;
        }

        {
            std::lock_guard<std::mutex> lock(wsMutex);
            auto it = wsConnections.find(entry->ws_id);
            if (it == wsConnections.end() || it->second->closed) return;
        }

        if (message.type == NSURLSessionWebSocketMessageTypeString) {
            NSString* str = message.string;
            const char* utf8 = [str UTF8String];
            entry->message_cb(entry->ws_id, (const uint8_t*)utf8, strlen(utf8), 1, entry->context);
        } else if (message.type == NSURLSessionWebSocketMessageTypeData) {
            NSData* data = message.data;
            entry->message_cb(entry->ws_id, (const uint8_t*)[data bytes], [data length], 0, entry->context);
        }

        // Continue receiving
        receiveLoop(entry);
    }];
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
            error_cb(0, "Invalid WebSocket URL", context);
            return 0;
        }

        uint32_t wsId;
        {
            std::lock_guard<std::mutex> lock(wsMutex);
            wsId = nextWsId++;
        }

        WebSocketDelegate* delegate = [[WebSocketDelegate alloc] init];
        delegate.wsId = wsId;

        NSURLSessionConfiguration* config = [NSURLSessionConfiguration defaultSessionConfiguration];
        NSURLSession* session = [NSURLSession sessionWithConfiguration:config
                                                              delegate:delegate
                                                         delegateQueue:nil];

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

        auto* entry = new WebSocketEntry{
            task, session, wsId,
            open_cb, message_cb, close_cb, error_cb, bytes_sent_cb,
            context, false
        };

        {
            std::lock_guard<std::mutex> lock(wsMutex);
            wsConnections[wsId] = entry;
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
    std::lock_guard<std::mutex> lock(wsMutex);
    auto it = wsConnections.find(ws_id);
    if (it == wsConnections.end() || it->second->closed) return;

    auto* entry = it->second;
    size_t bytesSent = length;

    NSURLSessionWebSocketMessage* message;
    if (is_text) {
        NSString* str = [[NSString alloc] initWithBytes:data length:length encoding:NSUTF8StringEncoding];
        message = [[NSURLSessionWebSocketMessage alloc] initWithString:str ?: @""];
    } else {
        NSData* nsData = [NSData dataWithBytes:data length:length];
        message = [[NSURLSessionWebSocketMessage alloc] initWithData:nsData];
    }

    // Capture bytes_sent_cb and ws_id for completion handler
    auto bytes_sent_cb = entry->bytes_sent_cb;
    auto ctx = entry->context;

    [entry->task sendMessage:message completionHandler:^(NSError* error) {
        if (error) {
            std::lock_guard<std::mutex> lock(wsMutex);
            auto it = wsConnections.find(ws_id);
            if (it == wsConnections.end() || it->second->closed) return;
            it->second->error_cb(ws_id, [[error localizedDescription] UTF8String], it->second->context);
        } else {
            // Notify JS that data was successfully sent so bufferedAmount can decrement
            if (bytes_sent_cb) {
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

    auto* entry = it->second;

    NSData* reasonData = nil;
    if (reason && strlen(reason) > 0) {
        reasonData = [[NSString stringWithUTF8String:reason] dataUsingEncoding:NSUTF8StringEncoding];
    }

    [entry->task cancelWithCloseCode:(NSURLSessionWebSocketCloseCode)code reason:reasonData];
}

extern "C" void native_ws_destroy(uint32_t ws_id) {
    std::lock_guard<std::mutex> lock(wsMutex);
    auto it = wsConnections.find(ws_id);
    if (it == wsConnections.end()) return;

    auto* entry = it->second;
    entry->closed = true;
    [entry->session invalidateAndCancel];
    wsConnections.erase(it);
    delete entry;
}

extern "C" int native_ws_has_active(void) {
    std::lock_guard<std::mutex> lock(wsMutex);
    for (auto& pair : wsConnections) {
        if (!pair.second->closed) return 1;
    }
    return 0;
}
