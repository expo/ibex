/**
 * native_fetch_macos.mm
 *
 * Implements HTTP fetch using macOS native NSURLSession.
 * This is called from the C++ Hermes bridge via C function pointers.
 */

#import <Foundation/Foundation.h>
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
        // but still use NSURLSession's native networking stack
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);

        __block NSData* responseData = nil;
        __block NSHTTPURLResponse* httpResponse = nil;
        __block NSError* responseError = nil;

        NSURLSessionDataTask* task = [getSession() dataTaskWithRequest:request
            completionHandler:^(NSData* data, NSURLResponse* response, NSError* error) {
                responseData = data;
                if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
                    httpResponse = (NSHTTPURLResponse*)response;
                }
                responseError = error;
                dispatch_semaphore_signal(sem);
            }];
        [task resume];

        // Wait for completion
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

        if (responseError) {
            std::string errorMsg = std::string(responseError.localizedDescription.UTF8String);
            response_callback(request_id, 0, errorMsg.c_str(), nullptr, nullptr, 0, context);
            return;
        }

        if (!httpResponse) {
            response_callback(request_id, 0, "No HTTP response", nullptr, nullptr, 0, context);
            return;
        }

        // Build status text
        NSString* statusText = [NSHTTPURLResponse localizedStringForStatusCode:httpResponse.statusCode];
        std::string statusTextStr(statusText.UTF8String);

        // Build headers string in "Key: Value\r\n" format
        std::string headersStr;
        NSDictionary* responseHeaders = httpResponse.allHeaderFields;
        for (NSString* key in responseHeaders) {
            NSString* value = responseHeaders[key];
            headersStr += std::string(key.UTF8String) + ": " + std::string(value.UTF8String) + "\r\n";
        }

        int statusCode = (int)httpResponse.statusCode;
        const uint8_t* bodyPtr = responseData ? (const uint8_t*)responseData.bytes : nullptr;
        size_t bodyLen = responseData ? responseData.length : 0;

        response_callback(
            request_id,
            statusCode,
            statusTextStr.c_str(),
            headersStr.empty() ? nullptr : headersStr.c_str(),
            bodyPtr,
            bodyLen,
            context
        );
    }
}
