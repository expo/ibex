/**
 * native_fetch_macos.mm
 *
 * Implements HTTP fetch using macOS native NSURLSession.
 * This is called from the C++ Hermes bridge via C function pointers.
 *
 * Cookie handling is done in the JS layer (CookieJar). This native layer is
 * a stateless HTTP pipe: it sends whatever headers JS provides and returns
 * raw response headers (including multiple Set-Cookie lines) without any
 * implicit cookie storage.
 */

#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

// C callback type matching the one defined in hermes_runtime.cc
typedef void (*NativeFetchResponseCallback)(
    uint32_t request_id,
    int status,
    const char* status_text,
    const char* headers,
    const uint8_t* body,
    size_t body_length,
    void* context
);

// =============================================================================
// Set-Cookie header splitting
// =============================================================================

/**
 * Split a collapsed Set-Cookie header value into individual cookie strings.
 *
 * NSHTTPURLResponse.allHeaderFields is an NSDictionary which collapses
 * duplicate Set-Cookie headers into a single comma-separated string.
 * However, cookie values can contain commas in the Expires attribute
 * (e.g. "Expires=Thu, 01 Jan 2025 00:00:00 GMT"). We must split only
 * on commas that separate distinct cookies, not commas inside Expires dates.
 *
 * Strategy: split on ", " (comma-space) but only when the token after the
 * comma looks like a new cookie (contains '=' before any ';').
 */
static NSArray<NSString*>* splitSetCookieHeaderValue(NSString* headerValue) {
    if (!headerValue || headerValue.length == 0) {
        return @[];
    }

    NSMutableArray<NSString*>* cookies = [NSMutableArray array];
    NSMutableString* current = [NSMutableString string];
    NSArray<NSString*>* parts = [headerValue componentsSeparatedByString:@", "];

    for (NSUInteger i = 0; i < parts.count; i++) {
        NSString* part = parts[i];
        if (current.length == 0) {
            [current appendString:part];
        } else {
            // Check if this part looks like a new cookie (has name=value before any ;)
            // A new cookie starts with a token that contains '=' (the name=value pair).
            // Expires date fragments like "01 Jan 2025 00:00:00 GMT" don't contain '='.
            NSRange eqRange = [part rangeOfString:@"="];
            NSRange semiRange = [part rangeOfString:@";"];

            bool looksLikeNewCookie = false;
            if (eqRange.location != NSNotFound) {
                // '=' exists - it's a new cookie if '=' comes before any ';'
                if (semiRange.location == NSNotFound || eqRange.location < semiRange.location) {
                    looksLikeNewCookie = true;
                }
            }

            if (looksLikeNewCookie) {
                // Commit the current cookie and start a new one
                [cookies addObject:[current copy]];
                [current setString:part];
            } else {
                // This is a continuation (e.g. Expires date), rejoin with ", "
                [current appendFormat:@", %@", part];
            }
        }
    }

    if (current.length > 0) {
        [cookies addObject:[current copy]];
    }

    return cookies;
}

/**
 * Append response headers to the output buffer in "Key: Value\r\n" format.
 *
 * For Set-Cookie, we use the CFNetwork-level API to get individual header
 * values, falling back to splitting the collapsed NSDictionary value.
 */
static void appendResponseHeaders(NSHTTPURLResponse* response, std::string& out) {
    NSDictionary* responseHeaders = response.allHeaderFields;
    NSString* setCookieValue = nil;

    for (NSString* key in responseHeaders) {
        NSString* lowerKey = [key lowercaseString];
        if ([lowerKey isEqualToString:@"set-cookie"]) {
            // Defer Set-Cookie handling
            setCookieValue = responseHeaders[key];
            continue;
        }
        NSString* value = responseHeaders[key];
        out += std::string(key.UTF8String) + ": " + std::string(value.UTF8String) + "\r\n";
    }

    // Handle Set-Cookie separately: split collapsed value into individual cookies
    if (setCookieValue) {
        NSArray<NSString*>* cookies = splitSetCookieHeaderValue(setCookieValue);
        for (NSString* cookie in cookies) {
            out += "Set-Cookie: " + std::string(cookie.UTF8String) + "\r\n";
        }
    }
}

// =============================================================================
// NSURLSession delegate for per-request state
// =============================================================================

@interface FetchSessionDelegate : NSObject <NSURLSessionDataDelegate, NSURLSessionTaskDelegate>
@end

@implementation FetchSessionDelegate

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    // Allow the response to proceed
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
    didReceiveData:(NSData *)data {
    // Data chunks are handled in the completion handler path
    // (we still use semaphore-based synchronous completion below)
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didCompleteWithError:(NSError *)error {
    // Completion handled by the dataTask completion handler
}

// Intercept redirects: return nil to prevent auto-follow.
// This lets the JS layer handle redirect logic (method changes,
// cookie storage per-hop, header stripping, redirect modes).
- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
        newRequest:(NSURLRequest *)request
 completionHandler:(void (^)(NSURLRequest * _Nullable))completionHandler {
    // Return nil to prevent auto-follow — let JS handle redirects
    completionHandler(nil);
}

@end

// Shared URLSession instance — ephemeral config with cookies disabled
static NSURLSession* sharedSession = nil;
static FetchSessionDelegate* sharedDelegate = nil;
static std::mutex fetchTasksMutex;
static NSMutableDictionary<NSNumber*, NSURLSessionTask*>* fetchTasks = nil;

static NSURLSession* getSession() {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedDelegate = [FetchSessionDelegate new];

        NSURLSessionConfiguration* config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        config.timeoutIntervalForRequest = 30;
        config.timeoutIntervalForResource = 300;

        // Disable all implicit cookie handling — cookies are managed by the JS CookieJar
        config.HTTPCookieAcceptPolicy = NSHTTPCookieAcceptPolicyNever;
        config.HTTPCookieStorage = nil;
        config.HTTPShouldSetCookies = NO;

        sharedSession = [NSURLSession sessionWithConfiguration:config
                                                     delegate:sharedDelegate
                                                delegateQueue:nil];
    });
    return sharedSession;
}

static NSMutableDictionary<NSNumber*, NSURLSessionTask*>* getFetchTasks() {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        fetchTasks = [NSMutableDictionary new];
    });
    return fetchTasks;
}

extern "C" void native_fetch_perform(
    uint32_t request_id,
    const char* method,
    const char* url,
    const char* headers,
    const uint8_t* body,
    size_t body_length,
    NativeFetchResponseCallback response_callback,
    void* context
) {
    if (!method || !url || !response_callback) return;

    @autoreleasepool {
        NSString* urlString = [NSString stringWithUTF8String:url];
        NSURL* nsUrl = [NSURL URLWithString:urlString];
        if (!nsUrl) {
            response_callback(request_id, 0, "Invalid URL", nullptr, nullptr, 0, context);
            return;
        }

        NSMutableURLRequest* request = [NSMutableURLRequest requestWithURL:nsUrl];
        request.HTTPMethod = [NSString stringWithUTF8String:method];

        // Parse headers from "Key: Value\r\n" format
        if (headers) {
            NSString* headersStr = [NSString stringWithUTF8String:headers];
            NSArray* lines = [headersStr componentsSeparatedByString:@"\r\n"];
            for (NSString* line in lines) {
                NSRange colonRange = [line rangeOfString:@":"];
                if (colonRange.location != NSNotFound) {
                    NSString* key = [[line substringToIndex:colonRange.location]
                        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                    NSString* value = [[line substringFromIndex:colonRange.location + 1]
                        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                    [request setValue:value forHTTPHeaderField:key];
                }
            }
        }

        // Set body
        if (body && body_length > 0) {
            request.HTTPBody = [NSData dataWithBytes:body length:body_length];
        }

        NSURLSessionDataTask* task = [getSession() dataTaskWithRequest:request
            completionHandler:^(NSData* data, NSURLResponse* response, NSError* error) {
                NSNumber* requestKey = [NSNumber numberWithUnsignedInt:request_id];
                {
                    std::lock_guard<std::mutex> lock(fetchTasksMutex);
                    [getFetchTasks() removeObjectForKey:requestKey];
                }
                if (error) {
                    std::string message = error.localizedDescription
                        ? std::string(error.localizedDescription.UTF8String)
                        : std::string("Network error");
                    response_callback(
                        request_id,
                        0,
                        message.c_str(),
                        nullptr,
                        nullptr,
                        0,
                        context
                    );
                    return;
                }
                if (!response || ![response isKindOfClass:[NSHTTPURLResponse class]]) {
                    response_callback(
                        request_id,
                        0,
                        "No HTTP response",
                        nullptr,
                        nullptr,
                        0,
                        context
                    );
                    return;
                }

                auto* httpResponse = (NSHTTPURLResponse*)response;
                int status = (int)httpResponse.statusCode;
                std::string statusText = "Unknown";

                NSString* localizedStatusText =
                    [NSHTTPURLResponse localizedStringForStatusCode:httpResponse.statusCode];
                if (localizedStatusText) {
                    statusText = std::string(localizedStatusText.UTF8String);
                }

                // Use appendResponseHeaders to correctly handle Set-Cookie multiplicity
                std::string headerText;
                appendResponseHeaders(httpResponse, headerText);

                std::vector<uint8_t> responseBody;
                if (data && data.length > 0) {
                    responseBody.resize((size_t)data.length);
                    memcpy(responseBody.data(), data.bytes, (size_t)data.length);
                }

                const char* headerPtr = headerText.empty() ? nullptr : headerText.c_str();
                const uint8_t* bodyPtr = responseBody.empty() ? nullptr : responseBody.data();
                response_callback(
                    request_id,
                    status,
                    statusText.c_str(),
                    headerPtr,
                    bodyPtr,
                    responseBody.size(),
                    context
                );
            }];
        NSNumber* requestKey = [NSNumber numberWithUnsignedInt:request_id];
        {
            std::lock_guard<std::mutex> lock(fetchTasksMutex);
            [getFetchTasks() setObject:task forKey:requestKey];
        }
        [task resume];
    }
}

extern "C" void native_fetch_cancel(uint32_t request_id) {
    @autoreleasepool {
        NSNumber* requestKey = [NSNumber numberWithUnsignedInt:request_id];
        NSURLSessionTask* task = nil;
        {
            std::lock_guard<std::mutex> lock(fetchTasksMutex);
            task = [getFetchTasks() objectForKey:requestKey];
            [getFetchTasks() removeObjectForKey:requestKey];
        }
        if (task) {
            [task cancel];
        }
    }
}
