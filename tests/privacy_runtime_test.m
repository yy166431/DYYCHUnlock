#define DPS_TESTING 1
#import "../src/PrivacyShield.m"
#include <assert.h>

static NSUInteger originalCalls;
static NSUInteger clockOriginalCalls;
static id lastClockAddress;
static id lastClockCompletion;
static BOOL clockSawAllowedRequest;
static atomic_uint fixtureRequests;
static atomic_uint unexpectedFixtureRequests;
static NSString *const clockAddress = @"http://configured-author.invalid:8080/wx/get_time";

@interface potpiutoideidcs : NSObject
+ (NSString *)logUrl;
+ (void)plxmnqazxcvbnm:(id)action data:(id)data callback:(void (^)(NSDictionary *))callback;
@end
@implementation potpiutoideidcs
+ (NSString *)logUrl { return @"configured-author.invalid:8080"; }
+ (void)plxmnqazxcvbnm:(id)action data:(id)data callback:(void (^)(NSDictionary *))callback {
    ++originalCalls;
}
@end

@interface WCTools : NSObject
+ (void)requestServerTime:(id)address com:(id)completion;
@end
@implementation WCTools
+ (void)requestServerTime:(id)address com:(id)completion {
    assert(self == WCTools.class);
    assert(_cmd == @selector(requestServerTime:com:));
    ++clockOriginalCalls;
    lastClockAddress = address;
    lastClockCompletion = completion;
    NSURL *url = [address isKindOfClass:NSString.class] ? [NSURL URLWithString:address] : nil;
    clockSawAllowedRequest = url && DPSAllowedRequest([NSURLRequest requestWithURL:url]);
}
@end

@interface SupabaseClient : NSObject
- (void)performRequest:(id)request completion:(void (^)(id,NSError *))completion;
@end
@implementation SupabaseClient
- (void)performRequest:(id)request completion:(void (^)(id,NSError *))completion { ++originalCalls; }
@end

@interface LCPaasClient : NSObject
- (void)performRequest:(id)request validator:(id)validator success:(id)success
                failure:(void (^)(id,id,NSError *))failure wait:(BOOL)wait;
@end
@implementation LCPaasClient
- (void)performRequest:(id)request validator:(id)validator success:(id)success
                failure:(void (^)(id,id,NSError *))failure wait:(BOOL)wait { ++originalCalls; }
@end

static NSData *FixtureData(void) {
    // Synthetic transport fixture; this does not assert the live server's schema.
    return [@"{\"fixture_time_ms\":1760000000123}" dataUsingEncoding:NSUTF8StringEncoding];
}

@interface DPSFixtureProtocol : NSURLProtocol
@end
@implementation DPSFixtureProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)request { return YES; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
- (void)startLoading {
    atomic_fetch_add(&fixtureRequests, 1);
    if (![self.request.URL.absoluteString isEqualToString:clockAddress] ||
        ![self.request.HTTPMethod isEqualToString:@"GET"] || self.request.HTTPBody.length ||
        self.request.HTTPBodyStream) {
        atomic_fetch_add(&unexpectedFixtureRequests, 1);
        [self.client URLProtocol:self didFailWithError:
            [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorResourceUnavailable userInfo:nil]];
        return;
    }
    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL
        statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{@"Content-Type": @"application/json"}];
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [self.client URLProtocol:self didLoadData:FixtureData()];
    [self.client URLProtocolDidFinishLoading:self];
}
- (void)stopLoading {}
@end

static void WaitFor(BOOL (^predicate)(void)) {
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:5];
    while (!predicate() && deadline.timeIntervalSinceNow > 0)
        [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    assert(predicate());
}

static NSURLSession *FixtureSession(BOOL privateSession) {
    NSURLSessionConfiguration *configuration = NSURLSessionConfiguration.ephemeralSessionConfiguration;
    // Every request is consumed in memory; the fixture never opens a connection.
    configuration.protocolClasses = @[DPSFixtureProtocol.class];
    configuration.URLCache = nil;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration
        delegate:nil delegateQueue:NSOperationQueue.mainQueue];
    DPSPrepareSession(session, privateSession);
    return session;
}

static void AssertDeniedTask(NSURLSession *session, NSURLRequest *request) {
    unsigned before = atomic_load(&fixtureRequests);
    __block NSUInteger callbacks = 0;
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            assert(error != nil);
            ++callbacks;
        }];
    assert([task.originalRequest.URL.scheme isEqualToString:@"dyyy-privacy-denied"]);
    [task resume];
    WaitFor(^BOOL { return callbacks == 1; });
    assert(atomic_load(&fixtureRequests) == before);
}

static void AssertTimeTask(NSURLSession *session, NSURLRequest *request) {
    unsigned before = atomic_load(&fixtureRequests);
    __block NSUInteger callbacks = 0;
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            assert(!error);
            assert([(NSHTTPURLResponse *)response statusCode] == 200);
            assert([data isEqualToData:FixtureData()]);
            ++callbacks;
        }];
    assert([task.originalRequest.URL isEqual:request.URL]);
    assert([task.currentRequest.URL isEqual:request.URL]);
    assert(![objc_getAssociatedObject(task, &gPrivateTaskKey) boolValue]);
    [task resume];
    WaitFor(^BOOL { return callbacks == 1; });
    assert(atomic_load(&fixtureRequests) == before + 1);
}

static void AssertDeniedUploads(NSURLSession *session, NSURLRequest *request) {
    assert([request.HTTPMethod isEqualToString:@"GET"]);
    assert(!request.HTTPBody && !request.HTTPBodyStream);
    unsigned before = atomic_load(&fixtureRequests);
    NSData *payload = [@"fixture-upload-payload" dataUsingEncoding:NSUTF8StringEncoding];
    NSString *filename = [@"dyyy-privacy-test-" stringByAppendingString:NSUUID.UUID.UUIDString];
    NSURL *fileURL = [NSURL fileURLWithPath:[NSTemporaryDirectory() stringByAppendingPathComponent:filename]];
    NSError *fileError = nil;
    BOOL wroteFile = [payload writeToURL:fileURL options:NSDataWritingAtomic error:&fileError];
    assert(wroteFile && !fileError);
    __block NSUInteger callbacks = 0;
    void (^completion)(NSData *, NSURLResponse *, NSError *) =
        ^(NSData *data, NSURLResponse *response, NSError *error) {
            assert(error != nil);
            ++callbacks;
        };
    // fromData/fromFile payloads are separate API arguments, absent from HTTPBody.
    NSArray<NSURLSessionUploadTask *> *tasks = @[
        [session uploadTaskWithRequest:request fromData:payload],
        [session uploadTaskWithRequest:request fromFile:fileURL],
        [session uploadTaskWithRequest:request fromData:payload completionHandler:completion],
        [session uploadTaskWithRequest:request fromFile:fileURL completionHandler:completion],
        [session uploadTaskWithStreamedRequest:request]
    ];
    for (NSURLSessionUploadTask *task in tasks) {
        assert([task.originalRequest.URL.scheme isEqualToString:@"dyyy-privacy-denied"]);
        assert([objc_getAssociatedObject(task, &gPrivateTaskKey) boolValue]);
        [task resume];
    }
    WaitFor(^BOOL {
        if (callbacks != 2) return NO;
        for (NSURLSessionUploadTask *task in tasks)
            if (task.state != NSURLSessionTaskStateCompleted) return NO;
        return YES;
    });
    assert(atomic_load(&fixtureRequests) == before);
    BOOL removedFile = [NSFileManager.defaultManager removeItemAtURL:fileURL error:&fileError];
    assert(removedFile && !fileError);
}

static void AssertClockForwarded(id address, id completion) {
    NSUInteger before = clockOriginalCalls;
    [WCTools requestServerTime:address com:completion];
    assert(clockOriginalCalls == before + 1);
    assert(lastClockAddress == address);
    assert(lastClockCompletion == completion);
}

int main(void) {
    @autoreleasepool {
        gLock = [NSObject new];
        gInstalled = [NSMutableSet new];
        gLearnedHosts = [NSMutableSet new];
        gTimeURLs = [NSMutableSet new];
        Method clockMethod = class_getClassMethod(WCTools.class, @selector(requestServerTime:com:));
        IMP originalClock = method_getImplementation(clockMethod);
        DPSInstall();
        IMP observedClock = method_getImplementation(clockMethod);
        assert(observedClock != originalClock);
        NSUInteger installed = gInstalled.count;
        DPSInstall();
        assert(installed == gInstalled.count);
        assert(method_getImplementation(clockMethod) == observedClock);
        __block NSUInteger callbacks = 0;
        [potpiutoideidcs plxmnqazxcvbnm:@"dy_order_create_maybe_suc" data:@{}
            callback:^(NSDictionary *result) { assert([result[@"code"] intValue] == -999); ++callbacks; }];
        [[SupabaseClient new] performRequest:nil completion:^(id result,NSError *error) {
            assert(!result && error.code == NSURLErrorCancelled); ++callbacks;
        }];
        __block BOOL synchronousCallback = NO;
        [[LCPaasClient new] performRequest:nil validator:nil success:nil
            failure:^(id response,id result,NSError *error) {
                assert(!response && !result && error.code == NSURLErrorCancelled);
                synchronousCallback = YES;
            } wait:YES];
        assert(synchronousCallback);
        WaitFor(^BOOL { return callbacks == 2; });
        assert(originalCalls == 0);
        assert([[potpiutoideidcs logUrl] isEqualToString:@"configured-author.invalid:8080"]);

        NSURLSession *session = FixtureSession(NO);
        NSURLSession *privateSession = FixtureSession(YES);
        NSURLRequest *timeRequest = [NSURLRequest requestWithURL:[NSURL URLWithString:clockAddress]];
        assert(gTimeURLs.count == 0);
        assert(DPSDeniedURL(timeRequest.URL));
        assert(!DPSAllowedRequest(timeRequest));
        AssertDeniedTask(session, timeRequest);
        AssertDeniedTask(privateSession, timeRequest);

        // The observer must learn before invoking the original clock entry, and
        // preserve both arguments. It must never execute the callback itself.
        __block NSUInteger clockCallbacks = 0;
        id completion = [^{ ++clockCallbacks; } copy];
        AssertClockForwarded(clockAddress, completion);
        assert(clockSawAllowedRequest);
        assert(clockCallbacks == 0);
        assert(gTimeURLs.count == 1);
        assert(DPSAllowedRequest(timeRequest));
        assert(!DPSDeniedRequest(session, timeRequest));
        assert(!DPSDeniedRequest(privateSession, timeRequest));
        assert(DPSAllowedRequest([NSURLRequest requestWithURL:
            [NSURL URLWithString:@"HTTP://CONFIGURED-AUTHOR.INVALID:8080/wx/get_time"]]));
        DPSInstall();
        assert(method_getImplementation(clockMethod) == observedClock);
        AssertClockForwarded(clockAddress, completion);
        assert(gTimeURLs.count == 1 && clockCallbacks == 0);

        // Syntactically similar input at the observer never broadens the route.
        NSArray<NSString *> *invalidAddresses = @[
            @"http://configured-author.invalid:8080/WX/GET_TIME",
            @"http://configured-author.invalid:8080/wx/get_time/",
            @"http://configured-author.invalid:8080/wx/get_time/extra",
            @"http://configured-author.invalid:8080/wx/get_times",
            @"http://configured-author.invalid:8080/wx/%67et_time",
            @"http://configured-author.invalid:8080/wx%2Fget_time",
            @"http://configured-author.invalid:8080/wx/get_time?ts=123",
            @"http://configured-author.invalid:8080/wx/get_time?",
            @"http://configured-author.invalid:8080/wx/get_time#fragment",
            @"http://configured-author.invalid:8080/wx/get_time#",
            @"http://user:password@configured-author.invalid:8080/wx/get_time",
            @"ftp://configured-author.invalid:8080/wx/get_time",
            @"dyyy-privacy-denied://configured-author.invalid:8080/wx/get_time",
            @"http://configured-author.invalid:8080/wx/receive_data_dy",
            @"https://api.leancloud.cn/1.1/date"
        ];
        for (NSString *address in invalidAddresses) {
            NSURL *url = [NSURL URLWithString:address];
            assert(url && DPSTimeURLKey(url) == nil);
            AssertClockForwarded(address, completion);
            assert(!clockSawAllowedRequest);
            assert(gTimeURLs.count == 1);
            NSURLRequest *request = [NSURLRequest requestWithURL:url];
            assert(!DPSAllowedRequest(request));
            assert(DPSDeniedRequest(privateSession, request));
        }
        AssertClockForwarded(nil, completion);
        AssertClockForwarded([NSURL URLWithString:clockAddress], completion);
        AssertClockForwarded([NSObject new], nil);
        assert(gTimeURLs.count == 1 && clockCallbacks == 0);
        assert(!DPSAllowedRequest(nil));
        assert(!DPSAllowedRequest((id)[NSObject new]));

        // The endpoint is scoped to its observed origin, not only its path.
        for (NSString *address in @[
                @"https://configured-author.invalid:8080/wx/get_time",
                @"http://configured-author.invalid:8081/wx/get_time",
                @"http://unobserved.invalid:8080/wx/get_time"]) {
            NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:address]];
            assert(DPSTimeURLKey(request.URL) != nil);
            assert(!DPSAllowedRequest(request));
            AssertDeniedTask(privateSession, request);
        }
        for (NSString *method in @[@"POST", @"PUT", @"PATCH", @"DELETE", @"HEAD"]) {
            NSMutableURLRequest *request = [timeRequest mutableCopy];
            request.HTTPMethod = method;
            assert(!DPSAllowedRequest(request));
            AssertDeniedTask(session, request);
        }
        NSMutableURLRequest *bodyRequest = [timeRequest mutableCopy];
        bodyRequest.HTTPBody = [@"fixture-sensitive-payload" dataUsingEncoding:NSUTF8StringEncoding];
        assert(!DPSAllowedRequest(bodyRequest));
        AssertDeniedTask(privateSession, bodyRequest);
        NSMutableURLRequest *streamRequest = [timeRequest mutableCopy];
        streamRequest.HTTPBodyStream = [NSInputStream inputStreamWithData:[NSData data]];
        assert(!DPSAllowedRequest(streamRequest));
        AssertDeniedTask(privateSession, streamRequest);

        // Actual task creation and resume must both preserve the clock exception.
        AssertTimeTask(session, timeRequest);
        AssertTimeTask(privateSession, timeRequest);
        NSMutableURLRequest *reportRequest = [NSMutableURLRequest requestWithURL:
            [NSURL URLWithString:@"http://configured-author.invalid:8080/wx/receive_data_dy"]];
        reportRequest.HTTPMethod = @"POST";
        reportRequest.HTTPBody = [@"fixture-report" dataUsingEncoding:NSUTF8StringEncoding];
        AssertDeniedTask(session, reportRequest);
        AssertDeniedTask(privateSession, reportRequest);
        NSMutableURLRequest *operateRequest = [reportRequest mutableCopy];
        operateRequest.URL = [NSURL URLWithString:@"http://configured-author.invalid:8080/operate"];
        AssertDeniedTask(privateSession, operateRequest);
        AssertDeniedUploads(session, timeRequest);
        AssertDeniedUploads(privateSession, timeRequest);
        assert([objc_getAssociatedObject(privateSession, &gPrivateSessionKey) boolValue]);

        // A URL-level time exception must not reopen the LeanCloud source hook.
        NSURLRequest *leanCloudRequest = [NSURLRequest requestWithURL:
            [NSURL URLWithString:@"https://api.leancloud.cn/1.1/date"]];
        AssertDeniedTask(session, leanCloudRequest);
        for (NSURLRequest *request in @[leanCloudRequest, timeRequest]) {
            __block NSUInteger failures = 0;
            [[LCPaasClient new] performRequest:request validator:nil success:nil
                failure:^(id response, id result, NSError *error) {
                    assert(!response && !result && error.code == NSURLErrorCancelled);
                    ++failures;
                } wait:YES];
            assert(failures == 1 && originalCalls == 0);
        }

        // A previously denied task stays denied, even when its URL is a clock URL.
        unsigned beforeResumeChecks = atomic_load(&fixtureRequests);
        __block NSUInteger taggedCallbacks = 0;
        NSURLSessionDataTask *tagged = [privateSession dataTaskWithRequest:timeRequest
            completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                assert(error != nil); ++taggedCallbacks;
            }];
        assert([tagged.originalRequest.URL isEqual:timeRequest.URL]);
        DPSPrepareTask(tagged, YES);
        [tagged resume];
        WaitFor(^BOOL { return taggedCallbacks == 1; });
        assert(atomic_load(&fixtureRequests) == beforeResumeChecks);

        // Host discovery after task creation must still be enforced at resume.
        NSURL *lateURL = [NSURL URLWithString:@"https://late-author.invalid/report"];
        __block NSUInteger lateCallbacks = 0;
        NSURLSessionDataTask *late = [session dataTaskWithURL:lateURL
            completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                assert(error != nil); ++lateCallbacks;
            }];
        assert([late.originalRequest.URL isEqual:lateURL]);
        assert(![objc_getAssociatedObject(late, &gPrivateTaskKey) boolValue]);
        DPSLearnURL(lateURL);
        [late resume];
        WaitFor(^BOOL { return lateCallbacks == 1; });
        assert(atomic_load(&fixtureRequests) == beforeResumeChecks);

        // An upload created before host discovery has no denied tag. Learning
        // its URL as a clock endpoint must not grant its external body a bypass.
        NSString *lateClockAddress = @"http://late-clock.invalid/wx/get_time";
        NSURLRequest *lateClockRequest = [NSURLRequest requestWithURL:[NSURL URLWithString:lateClockAddress]];
        __block NSUInteger lateUploadCallbacks = 0;
        NSURLSessionUploadTask *lateUpload = [session uploadTaskWithRequest:lateClockRequest
            fromData:[@"fixture-external-body" dataUsingEncoding:NSUTF8StringEncoding]
            completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                assert(error != nil); ++lateUploadCallbacks;
            }];
        assert([lateUpload.originalRequest.URL isEqual:lateClockRequest.URL]);
        assert(![objc_getAssociatedObject(lateUpload, &gPrivateTaskKey) boolValue]);
        AssertClockForwarded(lateClockAddress, completion);
        assert(DPSAllowedRequest(lateClockRequest));
        DPSLearnURL(lateClockRequest.URL);
        [lateUpload resume];
        WaitFor(^BOOL { return lateUploadCallbacks == 1; });
        assert(atomic_load(&fixtureRequests) == beforeResumeChecks);

        NSURLRequest *privateRequest = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://api.day.app/redacted"]];
        NSURLSessionDataTask *denied = [session dataTaskWithRequest:privateRequest
            completionHandler:^(NSData *data,NSURLResponse *response,NSError *error) {
                assert(error != nil); ++callbacks;
            }];
        assert([denied.originalRequest.URL.scheme isEqualToString:@"dyyy-privacy-denied"]);
        [denied resume];
        WaitFor(^BOOL { return callbacks == 3; });
        NSURL *businessURL = [NSURL URLWithString:@"https://www.douyin.com/operate"];
        NSURLSessionDataTask *allowed = [session dataTaskWithURL:businessURL];
        assert([allowed.originalRequest.URL isEqual:businessURL]);
        [allowed cancel];
        NSURLSessionDataTask *custom = [privateSession dataTaskWithURL:[NSURL URLWithString:@"https://custom.invalid/random"]];
        assert([custom.originalRequest.URL.scheme isEqualToString:@"dyyy-privacy-denied"]);
        [custom cancel];
        [session invalidateAndCancel];
        [privateSession invalidateAndCancel];
        assert(atomic_load(&fixtureRequests) == 2);
        assert(atomic_load(&unexpectedFixtureRequests) == 0);
        assert(originalCalls == 0 && clockCallbacks == 0);
        NSLog(@"Privacy runtime tests passed; permitted clock tasks completed using an in-memory protocol fixture");
    }
    return 0;
}
