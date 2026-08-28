// NSURLSession behind the Transport trait: the platform half of LLP 0057 §3.
//
// What this buys, none of which Rust should reimplement: TLS with the system
// certificate store, system and per-network proxy configuration, VPN
// awareness, HTTP/2 and /3, and connection pooling.
//
// THE CRITICAL DETAIL: NSURLSession follows redirects by default, and it must
// not. Redirect policy is Rust's (LLP 0059.000 §3.5), and — far more
// importantly — Rust re-checks the net.fetch grant on every hop. If the
// platform followed redirects internally, a grant for a.example would silently
// deliver a response from b.example, reintroducing exactly the redirect
// laundering the semantics layer exists to prevent. The delegate below refuses
// every redirect by completing with nil, so the 3xx comes back to Rust to
// decide on.
//
// @ref LLP 0057#3-the-boundary — the platform executes; it does not decide

#import <Foundation/Foundation.h>

#include <cstdlib>
#include <cstring>
#include <string>

namespace {

char *dup_utf8(NSString *value) {
  if (value == nil) {
    return nullptr;
  }
  const char *raw = [value UTF8String];
  if (raw == nullptr) {
    return nullptr;
  }
  size_t len = std::strlen(raw);
  char *out = static_cast<char *>(std::malloc(len + 1));
  if (out != nullptr) {
    std::memcpy(out, raw, len + 1);
  }
  return out;
}

} // namespace

/// Refuses redirects so Rust keeps redirect policy and the per-hop capability
/// check. Nothing else is overridden — the rest of NSURLSession's behaviour is
/// exactly what we want from the platform.
@interface Ibex2NoRedirect : NSObject <NSURLSessionTaskDelegate>
@end

@implementation Ibex2NoRedirect
- (void)URLSession:(NSURLSession *)session
                          task:(NSURLSessionTask *)task
    willPerformHTTPRedirection:(NSHTTPURLResponse *)response
                    newRequest:(NSURLRequest *)request
             completionHandler:(void (^)(NSURLRequest *))completionHandler {
  // nil means "do not follow"; the 3xx is delivered to us instead.
  completionHandler(nil);
}
@end

extern "C" {

/// Perform one request. Blocking, because it is called on a worker thread that
/// exists precisely so the JavaScript thread does not have to wait.
///
/// Headers cross as a newline-delimited `name: value` block. That is a
/// serialization, and it is fine here: LLP 0059.000 §1.1 governs the
/// JavaScript boundary, not Rust's call into the platform, and a header set is
/// small metadata rather than a payload. Bodies cross as raw bytes.
int ibex2_darwin_http_send(const char *method, const char *url,
                           const char *header_block, const unsigned char *body,
                           size_t body_len, int *out_status,
                           char **out_headers, unsigned char **out_body,
                           size_t *out_body_len, char **out_error) {
  @autoreleasepool {
    *out_status = 0;
    *out_headers = nullptr;
    *out_body = nullptr;
    *out_body_len = 0;
    *out_error = nullptr;

    NSString *urlString = [NSString stringWithUTF8String:url];
    NSURL *nsurl = [NSURL URLWithString:urlString];
    if (nsurl == nil) {
      *out_error = dup_utf8(@"TypeError: Failed to fetch — invalid URL");
      return 1;
    }

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:nsurl];
    request.HTTPMethod = [NSString stringWithUTF8String:method];

    if (header_block != nullptr) {
      NSString *block = [NSString stringWithUTF8String:header_block];
      for (NSString *line in [block componentsSeparatedByString:@"\n"]) {
        NSRange colon = [line rangeOfString:@": "];
        if (colon.location == NSNotFound) {
          continue;
        }
        NSString *name = [line substringToIndex:colon.location];
        NSString *value = [line substringFromIndex:colon.location + colon.length];
        [request setValue:value forHTTPHeaderField:name];
      }
    }
    if (body != nullptr && body_len > 0) {
      request.HTTPBody = [NSData dataWithBytes:body length:body_len];
    }

    // Ephemeral: no shared cookie jar and no disk cache. v1 has no credentials
    // or cache modes (LLP 0059.000 §3.5), so inheriting process-wide cookie
    // state would be ambient authority arriving through the back door.
    NSURLSessionConfiguration *config =
        [NSURLSessionConfiguration ephemeralSessionConfiguration];
    Ibex2NoRedirect *delegate = [[Ibex2NoRedirect alloc] init];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config
                                                         delegate:delegate
                                                    delegateQueue:nil];

    __block NSData *resultData = nil;
    __block NSHTTPURLResponse *resultResponse = nil;
    __block NSError *resultError = nil;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);

    NSURLSessionDataTask *task = [session
        dataTaskWithRequest:request
          completionHandler:^(NSData *data, NSURLResponse *response,
                              NSError *error) {
            resultData = data;
            resultResponse = [response isKindOfClass:[NSHTTPURLResponse class]]
                                 ? (NSHTTPURLResponse *)response
                                 : nil;
            resultError = error;
            dispatch_semaphore_signal(done);
          }];
    [task resume];
    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
    [session finishTasksAndInvalidate];

    if (resultError != nil && resultResponse == nil) {
      NSString *message = [NSString
          stringWithFormat:@"TypeError: Failed to fetch — %@",
                           resultError.localizedDescription];
      *out_error = dup_utf8(message);
      return 1;
    }
    if (resultResponse == nil) {
      *out_error = dup_utf8(@"TypeError: Failed to fetch — no response");
      return 1;
    }

    *out_status = static_cast<int>(resultResponse.statusCode);

    NSMutableString *headers = [NSMutableString string];
    [resultResponse.allHeaderFields
        enumerateKeysAndObjectsUsingBlock:^(id key, id value, BOOL *) {
          [headers appendFormat:@"%@: %@\n", key, value];
        }];
    *out_headers = dup_utf8(headers);

    if (resultData != nil && resultData.length > 0) {
      unsigned char *bytes =
          static_cast<unsigned char *>(std::malloc(resultData.length));
      if (bytes == nullptr) {
        *out_error = dup_utf8(@"TypeError: Failed to fetch — out of memory");
        return 1;
      }
      std::memcpy(bytes, resultData.bytes, resultData.length);
      *out_body = bytes;
      *out_body_len = resultData.length;
    }
    return 0;
  }
}

void ibex2_darwin_free(void *value) { std::free(value); }

} // extern "C"
