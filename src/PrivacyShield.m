// Privacy layer for sample SHA256 447792aa...44c9bc69.
// Does not change activation flags or ticket-platform request handling.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <execinfo.h>
#import <stdatomic.h>
#import "PrivacyPolicy.h"

static atomic_uintptr_t gTargetBase;
static atomic_bool gKnownBuild;
static NSMutableSet<NSString *> *gLearnedHosts;
static NSMutableSet<NSValue *> *gInstalled;
static NSObject *gLock;
static char gPrivateSessionKey;
static atomic_ulong gDenied;
static _Thread_local BOOL gCheckingStack;
static char gPrivateTaskKey;
static atomic_bool gInstallScheduled;
static void DPSInstall(void);
static void DPSPrepareSession(id session, BOOL privateSession);
static void DPSPrepareTask(id task, BOOL denied);

static NSError *DPSError(void) {
    return [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCancelled
                          userInfo:@{NSLocalizedDescriptionKey: @"Plugin telemetry disabled locally"}];
}

static void DPSCount(void) {
    unsigned long n = atomic_fetch_add_explicit(&gDenied, 1, memory_order_relaxed) + 1;
    if (n == 1 || (n & (n - 1)) == 0)
        NSLog(@"[DYYYPrivacy] blocked operations=%lu", n);
}

static BOOL DPSOwnClass(Class cls) {
    const char *image = cls ? class_getImageName(cls) : NULL;
    Class gate = objc_getClass("potpiutoideidcs");
    const char *target = gate ? class_getImageName(gate) : NULL;
    return image && target && !strcmp(image, target);
}

static void DPSIdentify(void) {
    Class cls = objc_getClass("potpiutoideidcs");
    if (!cls) return;
    const char *path = class_getImageName(cls);
    static const uint8_t expected[16] = {
        0x79,0xae,0x6b,0x44,0x7f,0xe2,0x3c,0x31,
        0x97,0x65,0x09,0xed,0x0c,0x83,0xc2,0x98
    };
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char *name = _dyld_get_image_name(i);
        if (!path || !name || strcmp(name, path)) continue;
        const struct mach_header *header = _dyld_get_image_header(i);
        if (header->magic != MH_MAGIC_64) return;
        BOOL known = NO;
        const uint8_t *p = (const uint8_t *)header + sizeof(struct mach_header_64);
        for (uint32_t c = 0; c < header->ncmds; ++c) {
            const struct load_command *lc = (const void *)p;
            if (lc->cmd == LC_UUID)
                known = !memcmp(((const struct uuid_command *)lc)->uuid, expected, 16);
            p += lc->cmdsize;
        }
        atomic_store(&gKnownBuild, known);
        atomic_store(&gTargetBase, (uintptr_t)header);
        return;
    }
}

static BOOL DPSAuthorStack(void) {
    uintptr_t base = atomic_load(&gTargetBase);
    if (gCheckingStack || !base) return NO;
    gCheckingStack = YES;
    void *frames[48];
    int count = backtrace(frames, 48);
    BOOL found = NO;
    // These are author-network components, not the host's request proxy.
    static const uintptr_t ranges[][2] = {
        {0x35608c,0x3bb440}, {0x4bdac8,0x4c61c8},
        {0x9263d4,0x92e000}, {0xd2c4d4,0xd336a8},
        {0xeb2a6c,0xf308c0}, {0x1007bd8,0x100cac4},
        {0x10ae9ec,0x10c1088}, {0xc7a638,0xc96d00},
        {0x11cdb28,0x12437d4}
    };
    for (int i = 0; i < count && !found; ++i) {
        Dl_info info = {0};
        if (!dladdr(frames[i], &info) || (uintptr_t)info.dli_fbase != base) continue;
        uintptr_t rva = (uintptr_t)frames[i] - base;
        if (atomic_load(&gKnownBuild)) {
            for (size_t r = 0; r < sizeof(ranges) / sizeof(ranges[0]); ++r)
                if (rva >= ranges[r][0] && rva < ranges[r][1]) found = YES;
        }
        const char *s = info.dli_sname;
        if (s && (strstr(s, "[SupabaseClient ") || strstr(s, "[WPLeanCloudHandler ") ||
                  strstr(s, "[potpiutoideidcs ") || strstr(s, "[WPDDReporter ") ||
                  strstr(s, "[SRWebSocketHelper ") || strstr(s, "[LCPaasClient ") ||
                  strstr(s, "[LCRouter ") || strstr(s, "[LCURLSessionManager ") ||
                  strstr(s, "[LCFileTaskManager ") || strstr(s, "[WPCheckVersionTool ") ||
                  strstr(s, "pp60f925ab47ed:"))) found = YES;
    }
    gCheckingStack = NO;
    return found;
}

static void DPSLearnURL(id value) {
    NSURL *url = [value isKindOfClass:NSURL.class] ? value :
        ([value isKindOfClass:NSString.class] ? [NSURL URLWithString:value] : nil);
    if (!url.host.length && [value isKindOfClass:NSString.class] &&
        ![value hasPrefix:@"/"] && ![value containsString:@"://"])
        url = [NSURL URLWithString:[@"http://" stringByAppendingString:value]];
    NSString *host = url.host.lowercaseString;
    if (!host.length) return;
    @synchronized(gLock) { [gLearnedHosts addObject:host]; }
}

static BOOL DPSAllowedURL(NSURL *url) {
    // Path-only match; query/fragment ignored so timestamped requests still pass.
    return url && DPSAllowedPath(url.path.UTF8String);
}

static BOOL DPSDeniedURL(NSURL *url) {
    if (DPSAllowedURL(url)) return NO;
    NSString *host = url.host.lowercaseString;
    if (DPSKnownHost(host.UTF8String)) return YES;
    @synchronized(gLock) { return host && [gLearnedHosts containsObject:host]; }
}

static BOOL DPSDeniedRequest(id session, NSURLRequest *request) {
    if ([request.URL.scheme isEqualToString:@"dyyy-privacy-denied"]) return YES;
    // Allowlisted paths bypass URL, private-session and author-stack denial so the
    // plugin's own time-sync request is never cancelled.
    if (DPSAllowedURL(request.URL)) return NO;
    return DPSDeniedURL(request.URL) ||
        [objc_getAssociatedObject(session, &gPrivateSessionKey) boolValue] || DPSAuthorStack();
}

static NSURLRequest *DPSSanitizedRequest(void) {
    // Unsupported scheme fails locally, preserving a real task and its completion contract.
    return [NSURLRequest requestWithURL:[NSURL URLWithString:@"dyyy-privacy-denied://local/"]];
}

static const char *DPSType(const char *type) {
    while (type && *type && strchr("rnNoORV", *type)) ++type;
    return type;
}

static BOOL DPSMethodMatches(Method method, const char *layout) {
    if (!method || method_getNumberOfArguments(method) != strlen(layout) + 2) return NO;
    char result[32] = {0};
    method_getReturnType(method, result, sizeof(result));
    if (*DPSType(result) != 'v') return NO;
    for (unsigned i = 0; i < strlen(layout); ++i) {
        char arg[128] = {0};
        method_getArgumentType(method, i + 2, arg, sizeof(arg));
        char t = *DPSType(arg);
        if (layout[i] == '@' && t != '@') return NO;
        if (layout[i] == 'B' && t != 'B' && t != 'c') return NO;
        if (layout[i] == 'q' && t != 'q' && t != 'Q') return NO;
    }
    return YES;
}

static void DPSInstallSource(const char *name, BOOL meta, const char *selector,
                             const char *layout, id replacement) {
    Class cls = objc_getClass(name);
    if (!DPSOwnClass(cls)) return;
    Method method = meta ? class_getClassMethod(cls, sel_registerName(selector)) :
                           class_getInstanceMethod(cls, sel_registerName(selector));
    if (!method) return;
    NSValue *key = [NSValue valueWithPointer:method];
    if ([gInstalled containsObject:key]) return;
    if (!DPSMethodMatches(method, layout)) {
        NSLog(@"[DYYYPrivacy] ABI mismatch: %s %s", name, selector);
        return;
    }
    method_setImplementation(method, imp_implementationWithBlock(replacement));
    [gInstalled addObject:key];
    NSLog(@"[DYYYPrivacy] installed: %s %s", name, selector);
}

static void DPSObjectPair(id block, id value, NSError *error) {
    if (!block) return;
    void (^callback)(id, NSError *) = [block copy];
    dispatch_async(dispatch_get_main_queue(), ^{ callback(value, error); });
}

static void DPSSources(void) {
    id none = ^(id self) { DPSCount(); };
    id one = ^(id self, id value) { DPSCount(); };
    id two = ^(id self, id a, id b) { DPSCount(); };
    DPSInstallSource("WPLeanCloudHandler", YES,
        "LeanCloud_saveDataWithClassName:whereKey:whereObj:data:", "@@@@",
        ^(id self, id a, id b, id c, id d) { DPSCount(); });
    DPSInstallSource("WPLeanCloudHandler", YES,
        "LeanCloud_saveDataWithClassName:whereKey:whereObj:data:block:", "@@@@@",
        ^(id self, id a, id b, id c, id d, id block) {
            DPSCount();
            if (block) { void (^cb)(BOOL,id) = [block copy];
                dispatch_async(dispatch_get_main_queue(), ^{ cb(NO, @[]); }); }
        });
    DPSInstallSource("WPLeanCloudHandler", YES,
        "LeanCloud_saveDataWithClassName:whereKey:whereObj:data:limit:block:", "@@@@q@",
        ^(id self, id a, id b, id c, id d, NSInteger limit, id block) {
            DPSCount();
            if (block) { void (^cb)(BOOL,id) = [block copy];
                dispatch_async(dispatch_get_main_queue(), ^{ cb(NO, @[]); }); }
        });
    DPSInstallSource("potpiutoideidcs", YES, "plxmnqazxcvbnm:data:callback:", "@@@",
        ^(id self, id action, id data, id block) {
            DPSCount();
            if (block) { void (^cb)(NSDictionary *) = [block copy];
                dispatch_async(dispatch_get_main_queue(), ^{
                    cb(@{@"code": @(-999), @"data": @{}, @"message": @"telemetry disabled"});
                }); }
        });
    DPSInstallSource("potpiutoideidcs", YES, "mnxbvczqwpalsdf:data:withFilters:completion:", "@@@@",
        ^(id self, id table, id data, id filters, id block) {
            DPSCount(); DPSObjectPair(block, nil, DPSError());
        });
    for (NSString *selector in @[@"plxqzmnwfdsajkl:", @"qplxmnzwdfasdjhk:",
                                 @"plxmfsdasdfgh:", @"qazxswedcplmnb:"])
        DPSInstallSource("potpiutoideidcs", YES, selector.UTF8String, "@", one);
    DPSInstallSource("pytpiutoideidcs", NO, "pp60f925ab47ed:", "@", one);
    DPSInstallSource("potpiutoideidcs", YES, "qwzxmnplasdjhfg:key:payUrl:", "@@@",
        ^(id self, id a, id b, id c) { DPSCount(); });
    DPSInstallSource("potpiutoideidcs", YES, "plxqwmnzxcasdfg:url:", "@@", two);
    DPSInstallSource("potpiutoideidcs", YES, "qazxmnplkwertyu:ignore:d:", "@BB",
        ^(id self, id a, BOOL ignore, BOOL d) { DPSCount(); });
    for (NSString *selector in @[@"sendWaitObj:", @"justSendWaitObj:",
             @"reportObj:", @"reportImpObj:", @"reportImpObj_MT4:"])
        DPSInstallSource("WPDDReporter", YES, selector.UTF8String, "@", one);
    DPSInstallSource("WPDDReporter", YES, "reportObj:ddToken:", "@@", two);
    DPSInstallSource("WPDDReporter", YES, "sendNow", "", none);
    for (NSString *selector in @[@"startTimer", @"startWebsocket", @"attemptReconnect"])
        DPSInstallSource("SRWebSocketHelper", NO, selector.UTF8String, "", none);
    DPSInstallSource("SRWebSocketHelper", NO, "sendMessage:", "@", one);
    DPSInstallSource("SRWebSocketHelper", NO, "action:", "@", one);
    // The only external constructor references to this SocketRocket class are in its helper.
    DPSInstallSource("SRWebSocket", NO, "open", "", none);
    DPSInstallSource("SRWebSocket", NO, "_writeData:", "@", one);
    DPSInstallSource("WPCheckVersionTool", NO, "checkVersionFromFir", "", none);
    DPSInstallSource("WPCheckVersionTool", NO, "checkVersionFromAppStore", "", none);
    DPSInstallSource("SupabaseClient", NO, "performRequest:completion:", "@@",
        ^(id self, id request, id block) { DPSCount(); DPSObjectPair(block, nil, DPSError()); });
    for (NSString *selector in @[@"signInWithEmail:password:completion:",
                                  @"signUpWithEmail:password:completion:"])
        DPSInstallSource("SupabaseClient", NO, selector.UTF8String, "@@@",
            ^(id self, id email, id password, id block) { DPSCount(); DPSObjectPair(block,nil,DPSError()); });
    DPSInstallSource("LCPaasClient", NO, "handleAllArchivedRequests", "", none);
    DPSInstallSource("LCPaasClient", NO,
        "performRequest:validator:success:failure:wait:", "@@@@B",
        ^(id self, id request, id validator, id success, id failure, BOOL wait) {
            DPSCount();
            if (!failure) return;
            void (^cb)(id,id,NSError *) = [failure copy];
            void (^finish)(void) = ^{ cb(nil,nil,DPSError()); };
            if (wait) finish();
            else dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT,0),finish);
        });
}

static BOOL DPSSubclass(Class cls, Class parent) {
    for (Class c = cls; c; c = class_getSuperclass(c)) if (c == parent) return YES;
    return NO;
}

static void DPSTransportMethod(Class cls, Method method) {
    NSValue *key = [NSValue valueWithPointer:method];
    if ([gInstalled containsObject:key]) return;
    SEL sel = method_getName(method);
    NSString *name = NSStringFromSelector(sel);
    IMP original = method_getImplementation(method);
    id replacement = nil;
    BOOL urlArgument = [name containsString:@"WithURL:"];
    NSArray *oneArg = @[@"dataTaskWithRequest:", @"dataTaskWithURL:",
                         @"downloadTaskWithRequest:", @"downloadTaskWithURL:",
                         @"uploadTaskWithStreamedRequest:"];
    NSArray *twoArgs = @[@"dataTaskWithRequest:completionHandler:", @"dataTaskWithURL:completionHandler:",
        @"downloadTaskWithRequest:completionHandler:", @"downloadTaskWithURL:completionHandler:",
        @"uploadTaskWithRequest:fromData:", @"uploadTaskWithRequest:fromFile:"];
    NSArray *threeArgs = @[@"uploadTaskWithRequest:fromData:completionHandler:",
                            @"uploadTaskWithRequest:fromFile:completionHandler:"];
    if ([oneArg containsObject:name]) {
        replacement = ^id(id self, id a) {
            NSURLRequest *request = urlArgument ? [NSURLRequest requestWithURL:a] : a;
            BOOL denied = DPSDeniedRequest(self, request);
            if (denied) { DPSCount(); a = urlArgument ? DPSSanitizedRequest().URL : DPSSanitizedRequest(); }
            id task = ((id(*)(id,SEL,id))original)(self,sel,a);
            DPSPrepareTask(task,denied);
            return task;
        };
    } else if ([twoArgs containsObject:name]) {
        BOOL payload = [name hasPrefix:@"uploadTask"];
        BOOL file = [name containsString:@"fromFile:"];
        replacement = ^id(id self, id a, id b) {
            NSURLRequest *request = urlArgument ? [NSURLRequest requestWithURL:a] : a;
            BOOL denied = DPSDeniedRequest(self, request);
            if (denied) {
                DPSCount(); a = urlArgument ? DPSSanitizedRequest().URL : DPSSanitizedRequest();
                if (payload) b = file ? [NSURL fileURLWithPath:@"/dev/null"] : [NSData data];
            }
            id task = ((id(*)(id,SEL,id,id))original)(self,sel,a,b);
            DPSPrepareTask(task,denied);
            return task;
        };
    } else if ([threeArgs containsObject:name]) {
        BOOL file = [name containsString:@"fromFile:"];
        replacement = ^id(id self, id a, id b, id c) {
            BOOL denied = DPSDeniedRequest(self,a);
            if (denied) {
                DPSCount(); a = DPSSanitizedRequest();
                b = file ? [NSURL fileURLWithPath:@"/dev/null"] : [NSData data];
            }
            id task = ((id(*)(id,SEL,id,id,id))original)(self,sel,a,b,c);
            DPSPrepareTask(task,denied);
            return task;
        };
    } else if ([name isEqualToString:@"downloadTaskWithResumeData:"]) {
        replacement = ^id(id self,id data) {
            id task = ((id(*)(id,SEL,id))original)(self,sel,data);
            DPSPrepareTask(task,DPSDeniedRequest(self,[task originalRequest]));
            return task;
        };
    } else if ([name isEqualToString:@"downloadTaskWithResumeData:completionHandler:"]) {
        replacement = ^id(id self,id data,id completion) {
            id task = ((id(*)(id,SEL,id,id))original)(self,sel,data,completion);
            DPSPrepareTask(task,DPSDeniedRequest(self,[task originalRequest]));
            return task;
        };
    }
    if (replacement) {
        method_setImplementation(method, imp_implementationWithBlock(replacement));
        [gInstalled addObject:key];
    }
}

static void DPSConnections(void) {
    Class cls = NSURLConnection.class;
    SEL sel = @selector(sendAsynchronousRequest:queue:completionHandler:);
    Method m = class_getClassMethod(cls,sel);
    NSValue *key = [NSValue valueWithPointer:m];
    if (m && ![gInstalled containsObject:key]) {
        IMP original = method_getImplementation(m);
        id replacement = ^(id self, NSURLRequest *request, NSOperationQueue *queue, id block) {
            if (!DPSDeniedRequest(nil,request)) {
                ((void(*)(id,SEL,id,id,id))original)(self,sel,request,queue,block); return;
            }
            DPSCount();
            if (block) { void (^cb)(NSURLResponse *,NSData *,NSError *) = [block copy];
                [(queue ?: NSOperationQueue.mainQueue) addOperationWithBlock:^{ cb(nil,nil,DPSError()); }]; }
        };
        method_setImplementation(m,imp_implementationWithBlock(replacement)); [gInstalled addObject:key];
    }
    sel = @selector(sendSynchronousRequest:returningResponse:error:);
    m = class_getClassMethod(cls,sel); key = [NSValue valueWithPointer:m];
    if (m && ![gInstalled containsObject:key]) {
        IMP original = method_getImplementation(m);
        SEL syncSel = sel;
        id replacement = ^id(id self, NSURLRequest *request, NSURLResponse *__autoreleasing *response,
                              NSError *__autoreleasing *error) {
            if (!DPSDeniedRequest(nil,request))
                return ((id(*)(id,SEL,id,NSURLResponse *__autoreleasing *,NSError *__autoreleasing *))original)(self,syncSel,request,response,error);
            DPSCount(); if (response) *response = nil; if (error) *error = DPSError(); return nil;
        };
        method_setImplementation(m,imp_implementationWithBlock(replacement)); [gInstalled addObject:key];
    }
}

static void DPSPrepareSession(id session, BOOL privateSession) {
    if (!session) return;
    @synchronized(gLock) {
        if (privateSession) objc_setAssociatedObject(session,&gPrivateSessionKey,@YES,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        for (Class cls = object_getClass(session); DPSSubclass(cls,NSURLSession.class); cls = class_getSuperclass(cls)) {
        unsigned n = 0;
        Method *methods = class_copyMethodList(cls, &n);
        for (unsigned j = 0; j < n; ++j) DPSTransportMethod(cls,methods[j]);
        free(methods);
        }
    }
}

static void DPSPrepareTask(id task, BOOL denied) {
    if (!task) return;
    @synchronized(gLock) {
        if (denied) objc_setAssociatedObject(task,&gPrivateTaskKey,@YES,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        for (Class cls = object_getClass(task); DPSSubclass(cls,NSURLSessionTask.class); cls = class_getSuperclass(cls)) {
            unsigned count = 0;
            Method *methods = class_copyMethodList(cls,&count);
            for (unsigned i = 0; i < count; ++i) {
                Method method = methods[i];
                SEL selector = method_getName(method);
                if (selector != @selector(resume)) continue;
                NSValue *key = [NSValue valueWithPointer:method];
                if ([gInstalled containsObject:key]) continue;
                IMP original = method_getImplementation(method);
                id replacement = ^(NSURLSessionTask *self) {
                    if ([objc_getAssociatedObject(self,&gPrivateTaskKey) boolValue] ||
                        DPSDeniedURL(self.originalRequest.URL) || DPSDeniedURL(self.currentRequest.URL)) {
                        DPSCount();
                        [self cancel];
                    }
                    ((void(*)(id,SEL))original)(self,selector);
                };
                method_setImplementation(method,imp_implementationWithBlock(replacement));
                [gInstalled addObject:key];
            }
            free(methods);
        }
    }
}

static void DPSSessionFactories(void) {
    Class cls = NSURLSession.class;
    for (NSString *name in @[@"sharedSession", @"sessionWithConfiguration:",
                             @"sessionWithConfiguration:delegate:delegateQueue:"]) {
        SEL sel = NSSelectorFromString(name);
        Method method = class_getClassMethod(cls,sel);
        if (!method) continue;
        NSValue *key = [NSValue valueWithPointer:method];
        if ([gInstalled containsObject:key]) continue;
        IMP original = method_getImplementation(method);
        id replacement;
        if ([name isEqualToString:@"sharedSession"]) {
            replacement = ^id(id self) {
                id session = ((id(*)(id,SEL))original)(self,sel);
                DPSPrepareSession(session,NO);
                return session;
            };
        } else if ([name isEqualToString:@"sessionWithConfiguration:"]) {
            replacement = ^id(id self,id config) {
                BOOL owned = DPSAuthorStack();
                id session = ((id(*)(id,SEL,id))original)(self,sel,config);
                DPSPrepareSession(session,owned);
                return session;
            };
        } else {
            replacement = ^id(id self,id config,id delegate,id queue) {
                BOOL owned = DPSAuthorStack();
                id session = ((id(*)(id,SEL,id,id,id))original)(self,sel,config,delegate,queue);
                DPSPrepareSession(session,owned);
                return session;
            };
        }
        method_setImplementation(method,imp_implementationWithBlock(replacement));
        [gInstalled addObject:key];
    }
}

static void DPSConfigureObservers(void) {
    Class gate = objc_getClass("potpiutoideidcs");
    SEL hostSelector = sel_registerName("logUrl");
    Method hostMethod = class_getClassMethod(gate,hostSelector);
    NSValue *hostKey = [NSValue valueWithPointer:hostMethod];
    char returnType[32] = {0};
    if (hostMethod) method_getReturnType(hostMethod,returnType,sizeof(returnType));
    if (DPSOwnClass(gate) && hostMethod && ![gInstalled containsObject:hostKey] &&
        method_getNumberOfArguments(hostMethod) == 2 && *DPSType(returnType) == '@') {
        IMP original = method_getImplementation(hostMethod);
        id replacement = ^id(id self) {
            id authority = ((id(*)(id,SEL))original)(self,hostSelector);
            DPSLearnURL(authority);
            return authority;
        };
        method_setImplementation(hostMethod,imp_implementationWithBlock(replacement));
        [gInstalled addObject:hostKey];
    }
    Class cls = objc_getClass("SupabaseClient");
    if (!DPSOwnClass(cls)) return;
    SEL sel = sel_registerName("configureWithURL:apiKey:");
    Method m = class_getInstanceMethod(cls,sel);
    NSValue *key = [NSValue valueWithPointer:m];
    if (m && ![gInstalled containsObject:key] && DPSMethodMatches(m,"@@")) {
        IMP original = method_getImplementation(m);
        id replacement = ^(id self,id url,id apiKey) {
            DPSLearnURL(url);
            ((void(*)(id,SEL,id,id))original)(self,sel,url,apiKey);
            SEL sessionSel = sel_registerName("session");
            if ([self respondsToSelector:sessionSel]) {
                id session = ((id(*)(id,SEL))objc_msgSend)(self,sessionSel);
                if (session) objc_setAssociatedObject(session,&gPrivateSessionKey,@YES,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            }
        };
        method_setImplementation(m,imp_implementationWithBlock(replacement)); [gInstalled addObject:key];
    }
}

static void DPSInstall(void) {
    @synchronized(gLock) {
        DPSIdentify();
        DPSSources();
        DPSConfigureObservers();
        DPSConnections();
        DPSSessionFactories();
        DPSPrepareSession(NSURLSession.sharedSession,NO);
    }
}

static void DPSImageAdded(const struct mach_header *header, intptr_t slide) {
    // The dyld callback must not realize Objective-C classes while the loader holds its locks.
    if (atomic_exchange(&gInstallScheduled,true)) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        atomic_store(&gInstallScheduled,false);
        DPSInstall();
    });
}

@interface DYYYPrivacyBootstrap : NSObject @end
@implementation DYYYPrivacyBootstrap
+ (void)load {
#ifndef DPS_TESTING
    @autoreleasepool {
        gLock = [NSObject new];
        gInstalled = [NSMutableSet new];
        gLearnedHosts = [NSMutableSet new];
        DPSInstall();
        _dyld_register_func_for_add_image(DPSImageAdded);
        dispatch_async(dispatch_get_main_queue(), ^{
            // Discover Foundation's concrete session class before a request is made.
            (void)NSURLSession.sharedSession;
            DPSInstall();
        });
        NSLog(@"[DYYYPrivacy] privacy layer loaded; device validation required");
    }
#endif
}
@end
