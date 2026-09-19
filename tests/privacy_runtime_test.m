#define DPS_TESTING 1
#import "../src/PrivacyShield.m"
#include <assert.h>

static NSUInteger originalCalls;
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

static void WaitFor(BOOL (^predicate)(void)) {
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:5];
    while (!predicate() && deadline.timeIntervalSinceNow > 0)
        [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    assert(predicate());
}

int main(void) {
    @autoreleasepool {
        gLock = [NSObject new];
        gInstalled = [NSMutableSet new];
        gLearnedHosts = [NSMutableSet new];
        DPSInstall();
        NSUInteger installed = gInstalled.count;
        DPSInstall();
        assert(installed == gInstalled.count);
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
        // The learned author host is blocked, but the time-sync path is allowlisted
        // so calibration survives; other paths on the same host stay denied.
        assert(!DPSDeniedURL([NSURL URLWithString:@"http://configured-author.invalid:8080/wx/get_time"]));
        assert(!DPSDeniedURL([NSURL URLWithString:@"http://configured-author.invalid:8080/wx/get_time?ts=123"]));
        assert(DPSDeniedURL([NSURL URLWithString:@"http://configured-author.invalid:8080/wx/receive_data_dy"]));
        NSURLSession *session = [NSURLSession sessionWithConfiguration:NSURLSessionConfiguration.ephemeralSessionConfiguration];
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
        NSURLSession *privateSession = [NSURLSession sessionWithConfiguration:NSURLSessionConfiguration.ephemeralSessionConfiguration];
        DPSPrepareSession(privateSession,YES);
        NSURLSessionDataTask *custom = [privateSession dataTaskWithURL:[NSURL URLWithString:@"https://custom.invalid/random"]];
        assert([custom.originalRequest.URL.scheme isEqualToString:@"dyyy-privacy-denied"]);
        [custom cancel];
        [session invalidateAndCancel];
        [privateSession invalidateAndCancel];
        NSLog(@"Privacy runtime tests passed; no permitted task was resumed");
    }
    return 0;
}
