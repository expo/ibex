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
#include <string>
#include <vector>
#include <mutex>

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

// Per-request state used by the delegate
struct FetchRequestState {
    int status = 0;
    std::string status_text;
    std::string headers;
    std::string error_text;
    std::vector<uint8_t> body;
    bool completed = false;
    dispatch_semaphore_t semaphore;
};

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

@end

// Shared URLSession instance — ephemeral config with cookies disabled
static NSURLSession* sharedSession = nil;
static FetchSessionDelegate* sharedDelegate = nil;

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

        // Use a semaphore to make this synchronous from the caller's perspective
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        struct FetchResult {
            int status = 0;
            std::string status_text;
            std::string headers;
            std::string error_text;
            std::vector<uint8_t> body;
            bool completed = false;
        };
        __block FetchResult result;

        NSURLSessionDataTask* task = [getSession() dataTaskWithRequest:request
            completionHandler:^(NSData* data, NSURLResponse* response, NSError* error) {
                result.completed = true;
                if (error) {
                    const char* msg = error.localizedDescription.UTF8String;
                    result.error_text = msg ? msg : "Network error";
                    dispatch_semaphore_signal(sem);
                    return;
                }
                if (!response || ![response isKindOfClass:[NSHTTPURLResponse class]]) {
                    result.error_text = "No HTTP response";
                    dispatch_semaphore_signal(sem);
                    return;
                }

                auto* httpResponse = (NSHTTPURLResponse*)response;
                result.status = (int)httpResponse.statusCode;

                NSString* statusText =
                    [NSHTTPURLResponse localizedStringForStatusCode:httpResponse.statusCode];
                if (statusText) {
                    result.status_text = std::string(statusText.UTF8String);
                } else {
                    result.status_text = std::string("Unknown");
                }

                // Use appendResponseHeaders to correctly handle Set-Cookie multiplicity
                appendResponseHeaders(httpResponse, result.headers);

                if (data && data.length > 0) {
                    result.body.resize((size_t)data.length);
                    memcpy(result.body.data(), data.bytes, (size_t)data.length);
                }
                dispatch_semaphore_signal(sem);
            }];
        [task resume];

        // Wait for completion
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

        if (!result.completed || result.status == 0) {
            response_callback(request_id, 0,
                result.error_text.empty() ? "No HTTP response" : result.error_text.c_str(),
                nullptr, nullptr, 0, context);
            return;
        }

        const char* statusText = result.status_text.c_str();
        const char* headersText = result.headers.empty() ? nullptr : result.headers.c_str();
        const uint8_t* bodyPtr = result.body.empty() ? nullptr : result.body.data();
        size_t bodyLen = result.body.size();

        response_callback(
            request_id,
            result.status,
            statusText,
            headersText,
            bodyPtr,
            bodyLen,
            context
        );
    }
}
