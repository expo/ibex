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

/// One in-flight request: what came back, and the ceiling it may not pass.
///
/// Every field is written on the session's delegate queue — which is serial,
/// so the callbacks below need no lock among themselves — and read by the
/// calling thread only after `done` is signalled, which is the happens-before
/// edge that makes the handoff safe.
@interface Ibex2Exchange : NSObject
@property(nonatomic, assign) NSUInteger limit;
@property(nonatomic, strong) NSMutableData *body;
@property(nonatomic, strong) NSHTTPURLResponse *response;
@property(nonatomic, strong) NSString *failure;
@property(nonatomic, assign) BOOL finished;
@property(nonatomic, strong) dispatch_semaphore_t done;
@end

@implementation Ibex2Exchange
- (instancetype)initWithLimit:(NSUInteger)limit {
  if ((self = [super init])) {
    _limit = limit;
    _body = [NSMutableData data];
    _done = dispatch_semaphore_create(0);
  }
  return self;
}

/// First finish wins, and nothing after it may touch the exchange. A refusal
/// and the cancellation error it causes both arrive here; the refusal is the
/// one the caller should see.
- (void)finishWith:(NSString *)failure {
  if (self.finished) {
    return;
  }
  if (failure != nil) {
    self.failure = failure;
  }
  self.finished = YES;
  dispatch_semaphore_signal(self.done);
}
@end

/// Refuses redirects so Rust keeps redirect policy and the per-hop capability
/// check, and holds each in-flight request to the byte ceiling it was given.
///
/// **The ceiling is why the body arrives through delegate callbacks instead of
/// a completion handler.** `dataTaskWithRequest:completionHandler:` hands over
/// one `NSData` that is already fully buffered: by the time it can be measured
/// the memory has been spent, which is the whole of what the ceiling exists to
/// prevent. `didReceiveData:` is the rung where a response can still be
/// refused, so that is the rung the limit is enforced at.
@interface Ibex2NoRedirect : NSObject <NSURLSessionDataDelegate>
/// taskIdentifier -> whether that task rode an already-open connection.
@property(nonatomic, strong) NSMutableDictionary<NSNumber *, NSNumber *> *reused;
/// taskIdentifier -> the in-flight exchange, entered before `resume`.
@property(nonatomic, strong)
    NSMutableDictionary<NSNumber *, Ibex2Exchange *> *exchanges;
@property(nonatomic, strong) NSLock *lock;
@end

@implementation Ibex2NoRedirect
- (instancetype)init {
  if ((self = [super init])) {
    _reused = [NSMutableDictionary dictionary];
    _exchanges = [NSMutableDictionary dictionary];
    _lock = [[NSLock alloc] init];
  }
  return self;
}

/// Registered from the calling thread before the task is resumed, so no
/// callback can arrive for a task the delegate does not yet know about.
- (void)track:(Ibex2Exchange *)exchange for:(NSUInteger)identifier {
  [self.lock lock];
  self.exchanges[@(identifier)] = exchange;
  [self.lock unlock];
}

- (Ibex2Exchange *)exchangeFor:(NSUInteger)identifier {
  [self.lock lock];
  Ibex2Exchange *exchange = self.exchanges[@(identifier)];
  [self.lock unlock];
  return exchange;
}

- (void)forget:(NSUInteger)identifier {
  [self.lock lock];
  [self.exchanges removeObjectForKey:@(identifier)];
  [self.lock unlock];
}

/// A declared length already over the ceiling is refused before the body is
/// read at all — `NSURLSessionResponseCancel` means the bytes never come.
- (void)URLSession:(NSURLSession *)session
              dataTask:(NSURLSessionDataTask *)dataTask
    didReceiveResponse:(NSURLResponse *)response
     completionHandler:
         (void (^)(NSURLSessionResponseDisposition))completionHandler {
  Ibex2Exchange *exchange = [self exchangeFor:dataTask.taskIdentifier];
  if (exchange == nil) {
    completionHandler(NSURLSessionResponseAllow);
    return;
  }
  if (![response isKindOfClass:[NSHTTPURLResponse class]]) {
    [exchange finishWith:@"TypeError: Failed to fetch — no response"];
    completionHandler(NSURLSessionResponseCancel);
    return;
  }
  exchange.response = (NSHTTPURLResponse *)response;
  if (response.expectedContentLength != NSURLResponseUnknownLength &&
      response.expectedContentLength > (long long)exchange.limit) {
    [exchange
        finishWith:[NSString stringWithFormat:
                                 @"TypeError: Failed to fetch — response "
                                 @"exceeded the %lu-byte limit",
                                 (unsigned long)exchange.limit]];
    completionHandler(NSURLSessionResponseCancel);
    return;
  }
  completionHandler(NSURLSessionResponseAllow);
}

/// And again on what actually arrives: Content-Length is the peer's claim, and
/// a chunked response makes no claim at all. Cancelling here stops the
/// transfer rather than merely declining to keep the rest of it.
- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
    didReceiveData:(NSData *)data {
  Ibex2Exchange *exchange = [self exchangeFor:dataTask.taskIdentifier];
  if (exchange == nil || exchange.finished) {
    return;
  }
  if (exchange.body.length + data.length > exchange.limit) {
    [exchange
        finishWith:[NSString stringWithFormat:
                                 @"TypeError: Failed to fetch — response "
                                 @"exceeded the %lu-byte limit",
                                 (unsigned long)exchange.limit]];
    [dataTask cancel];
    return;
  }
  [exchange.body appendData:data];
}

- (void)URLSession:(NSURLSession *)session
                    task:(NSURLSessionTask *)task
    didCompleteWithError:(NSError *)error {
  Ibex2Exchange *exchange = [self exchangeFor:task.taskIdentifier];
  if (exchange == nil) {
    return;
  }
  if (error != nil && !exchange.finished) {
    [exchange finishWith:[NSString stringWithFormat:
                                       @"TypeError: Failed to fetch — %@",
                                       error.localizedDescription]];
    return;
  }
  if (exchange.response == nil && !exchange.finished) {
    [exchange finishWith:@"TypeError: Failed to fetch — no response"];
    return;
  }
  [exchange finishWith:nil];
}

/// Records whether the connection was reused, so "the pool works" can be
/// asserted directly instead of inferred from a latency threshold. Timing
/// cannot tell a pooled request from a fast handshake, and picking a
/// millisecond number to separate them makes the test fail when the network
/// is slow rather than when the pool is broken.
- (void)URLSession:(NSURLSession *)session
                          task:(NSURLSessionTask *)task
    didFinishCollectingMetrics:(NSURLSessionTaskMetrics *)metrics {
  NSURLSessionTaskTransactionMetrics *last = metrics.transactionMetrics.lastObject;
  if (last == nil) {
    return;
  }
  [self.lock lock];
  self.reused[@(task.taskIdentifier)] = @(last.reusedConnection);
  [self.lock unlock];
}

/// Take the recorded flag, or -1 if metrics never arrived.
- (int)takeReusedFor:(NSUInteger)identifier {
  [self.lock lock];
  NSNumber *value = self.reused[@(identifier)];
  [self.reused removeObjectForKey:@(identifier)];
  [self.lock unlock];
  if (value == nil) {
    return -1;
  }
  return [value boolValue] ? 1 : 0;
}
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

/// Create the session a runtime performs all of its requests through.
///
/// **One session per runtime, not one per request.** Ephemeral is deliberate
/// and stays: no shared cookie jar and no disk cache, because v1 has no
/// credentials or cache modes (LLP 0059.000 §3.5) and inheriting process-wide
/// cookie state would be ambient authority arriving through the back door.
/// Per-*request* was the accident. A session owns the connection pool, so
/// building a new one each time threw away every pooled connection and paid a
/// full TLS handshake on every call — ~80ms each, measured.
///
/// Scoping it to the runtime rather than the process keeps the isolation the
/// ephemeral configuration is there for: two runtimes still share no cookie,
/// cache, or connection state.
///
/// @ref LLP 0057#3-the-boundary — pooling is the platform's job, and this is
/// what lets it do it
void *ibex2_darwin_session_create(void) {
  @autoreleasepool {
    NSURLSessionConfiguration *config =
        [NSURLSessionConfiguration ephemeralSessionConfiguration];

    // Ephemeral means "not on disk", NOT "no state". Apple still gives the
    // session a private in-memory cookie jar and URL cache, and sharing one
    // session across a runtime is exactly what makes them live long enough to
    // matter — with a session per request they were destroyed each time.
    //
    // Cookies are ambient authority the grant check cannot see: `net.fetch` is
    // granted per *origin*, while cookies are RFC 6265 *domain*-scoped, so a
    // module granted evil.example.com could set a cookie for example.com that
    // the platform then attaches to another module's request to
    // app.example.com. v1 has no credentials mode (LLP 0059.000 §3.5), so the
    // correct number of cookies is zero. Ibex 1 already did this
    // (src/engine/native_fetch_macos.mm).
    config.HTTPCookieAcceptPolicy = NSHTTPCookieAcceptPolicyNever;
    config.HTTPCookieStorage = nil;
    config.HTTPShouldSetCookies = NO;

    // The response cache goes for the same reason and one more: v1 has no
    // cache mode either, so a cached response is a result Rust's semantics
    // layer never decided to serve. It also keeps "did the connection get
    // reused" answerable — a URL cache answers a repeat request without any
    // connection at all, which would make the transport look fast for the
    // wrong reason.
    config.URLCache = nil;
    config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;

    // Stateless, so one instance serves every task on this session.
    Ibex2NoRedirect *delegate = [[Ibex2NoRedirect alloc] init];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config
                                                         delegate:delegate
                                                    delegateQueue:nil];
    return (__bridge_retained void *)session;
  }
}

/// Report whether a session kept a cookie jar or a response cache.
///
/// Exists so `the_session_keeps_no_cookies_and_no_cache` can assert the
/// property instead of trusting the comment above it — the previous version of
/// that comment claimed "no cookie jar, no disk cache" while the session had
/// both in memory.
void ibex2_darwin_session_has_state(void *handle, int *out_cookies,
                                    int *out_cache) {
  *out_cookies = 0;
  *out_cache = 0;
  if (handle == nullptr) {
    return;
  }
  @autoreleasepool {
    NSURLSession *session = (__bridge NSURLSession *)handle;
    NSURLSessionConfiguration *config = session.configuration;
    *out_cookies = (config.HTTPCookieStorage != nil ||
                    config.HTTPShouldSetCookies ||
                    config.HTTPCookieAcceptPolicy !=
                        NSHTTPCookieAcceptPolicyNever)
                       ? 1
                       : 0;
    *out_cache = (config.URLCache != nil) ? 1 : 0;
  }
}

/// Release a session. `finishTasksAndInvalidate` rather than
/// `invalidateAndCancel`: a runtime is torn down after its tasks are drained,
/// and cancelling in-flight work here would race the drive loop's own teardown.
void ibex2_darwin_session_destroy(void *handle) {
  if (handle == nullptr) {
    return;
  }
  @autoreleasepool {
    NSURLSession *session = (__bridge_transfer NSURLSession *)handle;
    [session finishTasksAndInvalidate];
  }
}

/// Perform one request on `session`. Blocking, because it is called on a worker
/// thread that exists precisely so the JavaScript thread does not have to wait.
///
/// Headers cross as a newline-delimited `name: value` block. That is a
/// serialization, and it is fine here: LLP 0059.000 §1.1 governs the
/// JavaScript boundary, not Rust's call into the platform, and a header set is
/// small metadata rather than a payload. Bodies cross as raw bytes.
int ibex2_darwin_http_send(void *session_handle, const char *method,
                           const char *url,
                           const char *header_block, const unsigned char *body,
                           size_t body_len, size_t max_body, int *out_status,
                           char **out_headers, unsigned char **out_body,
                           size_t *out_body_len, char **out_error,
                           int *out_reused) {
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

    if (out_reused != nullptr) {
      *out_reused = -1;
    }
    // The runtime's session, created once. See ibex2_darwin_session_create.
    NSURLSession *session = (__bridge NSURLSession *)session_handle;
    if (session == nil) {
      *out_error = dup_utf8(@"TypeError: Failed to fetch — no session");
      return 1;
    }

    if (![session.delegate isKindOfClass:[Ibex2NoRedirect class]]) {
      *out_error = dup_utf8(@"TypeError: Failed to fetch — no session delegate");
      return 1;
    }
    Ibex2NoRedirect *delegate = (Ibex2NoRedirect *)session.delegate;

    // The exchange is registered before `resume`, never after: a cached or
    // failed-fast response can call back before this thread reaches the wait.
    Ibex2Exchange *exchange = [[Ibex2Exchange alloc] initWithLimit:max_body];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request];
    NSUInteger identifier = task.taskIdentifier;
    [delegate track:exchange for:identifier];
    [task resume];
    dispatch_semaphore_wait(exchange.done, DISPATCH_TIME_FOREVER);
    if (out_reused != nullptr) {
      *out_reused = [delegate takeReusedFor:identifier];
    }
    [delegate forget:identifier];
    // No finishTasksAndInvalidate here: the session outlives the request and
    // is released by ibex2_darwin_session_destroy when the runtime goes away.

    if (exchange.failure != nil) {
      *out_error = dup_utf8(exchange.failure);
      return 1;
    }
    NSHTTPURLResponse *resultResponse = exchange.response;
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

    NSData *resultData = exchange.body;
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
