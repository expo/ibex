/**
 * native_fetch_macos.mm
 *
 * Implements HTTP fetch using macOS native NSURLSession.
 * This is called from the C++ Hermes bridge via C function pointers.
 */

#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#include <cstring>
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

// Shared URLSession instance
static NSURLSession* sharedSession = nil;

static NSURLSession* getSession() {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSURLSessionConfiguration* config = [NSURLSessionConfiguration defaultSessionConfiguration];
        config.timeoutIntervalForRequest = 30;
        config.timeoutIntervalForResource = 300;
        sharedSession = [NSURLSession sessionWithConfiguration:config];
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
        // but still use NSURLSession's native networking stack.
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

                NSDictionary* responseHeaders = httpResponse.allHeaderFields;
                for (NSString* key in responseHeaders) {
                    NSString* value = responseHeaders[key];
                    result.headers +=
                        std::string(key.UTF8String) + ": " + std::string(value.UTF8String) + "\r\n";
                }
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
