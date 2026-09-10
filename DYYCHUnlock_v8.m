/**
 * DYYCHUnlock.m v8-FIXED-SAFE — 修复崩溃 + 零时序漏洞
 *
 * v8-FIXED-SAFE 改进：
 *   1. 在 hooked_LCStart 内部再次检查并拦截同步上报
 *   2. 延迟 3 秒初始化 SDK（确保所有 hook 就位）
 *   3. 四层防护保持不变
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>

#define YCHLOG(fmt, ...) NSLog(@"[YCHUnlock] " fmt, ##__VA_ARGS__)

// __common 字节偏移
#define CJISSTATUS_VA    0x18629b8
#define CJSUPERADMIN_VA  0x18629bb

// ========== 全局标志：hook 是否完全就位 ==========
static volatile BOOL gHooksReady = NO;

// ========== 黑名单 ==========
static NSArray<NSString *> * authorHostsBlacklist(void) {
    return @[
        @"106.53.173.140",
        @"lncldapi.com",
        @"lncldglobal.com",
        @"avoscloud.com",
        @"api.leancloud.cn",
    ];
}

static BOOL isAuthorURL(NSURL *url) {
    if (!url || !url.host) return NO;
    NSString *host = url.host.lowercaseString;

    for (NSString *blocked in authorHostsBlacklist()) {
        if ([host isEqualToString:blocked] || [host hasSuffix:[@"." stringByAppendingString:blocked]]) {
            return YES;
        }
    }

    if ([host containsString:@"leancloud"] || [host containsString:@"avos"]) {
        return YES;
    }

    return NO;
}

// ========== 类解析 ==========
static Class resolveClass(NSArray<NSString *> *names) {
    for (NSString *n in names) {
        Class c = NSClassFromString(n);
        if (c) return c;
    }
    return nil;
}

static Class gateClass(void) {
    return resolveClass(@[ @"potpiutoideidcs", @"XBDLeanCloudHandler" ]);
}

static Class openActionClass(void) {
    return resolveClass(@[ @"pytpiutoideidcq", @"CJDebugHandler" ]);
}

// ========== 1. PIN 激活状态 ==========
static dispatch_source_t gPinTimer;
static volatile uint8_t *gStatusP = NULL;
static volatile uint8_t *gSuperP  = NULL;

static BOOL resolvePinPtrs(void) {
    Class g = gateClass();
    if (!g) return NO;
    Method m = class_getClassMethod(g, NSSelectorFromString(@"sharedInstance"));
    if (!m) return NO;
    Dl_info info;
    if (dladdr((void *)method_getImplementation(m), &info) && info.dli_fbase) {
        uintptr_t base = (uintptr_t)info.dli_fbase;
        gStatusP = (volatile uint8_t *)(base + CJISSTATUS_VA);
        gSuperP  = (volatile uint8_t *)(base + CJSUPERADMIN_VA);
        return YES;
    }
    return NO;
}

static void startPin(void) {
    if (!resolvePinPtrs()) {
        YCHLOG(@"resolvePinPtrs failed");
        return;
    }
    dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    gPinTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    dispatch_source_set_timer(gPinTimer, DISPATCH_TIME_NOW,
                              (uint64_t)(0.1 * NSEC_PER_SEC), (uint64_t)(0.03 * NSEC_PER_SEC));
    dispatch_source_set_event_handler(gPinTimer, ^{
        if (gStatusP) {
            *gStatusP = 1;
            *gSuperP = 1;
        }
    });
    dispatch_resume(gPinTimer);
    YCHLOG(@"[1] pin cjIsStatus+cjIsSuperAdmin=1 @100ms");
}

// ========== 2. 设置演唱会开关 ==========
static void setOpenYch(void) {
    Class g = gateClass();
    if (!g) {
        YCHLOG(@"gate class not found");
        return;
    }
    id inst = ((id(*)(id,SEL))objc_msgSend)((id)g, NSSelectorFromString(@"sharedInstance"));
    if (!inst) {
        YCHLOG(@"gate sharedInstance nil");
        return;
    }
    SEL s = NSSelectorFromString(@"setOpen_dy_ych_show:");
    if ([inst respondsToSelector:s]) {
        ((void(*)(id,SEL,BOOL))objc_msgSend)(inst, s, YES);
        YCHLOG(@"[2] setOpen_dy_ych_show:YES");
    } else {
        Ivar iv = class_getInstanceVariable(g, "_open_dy_ych_show");
        if (iv) {
            *((uint8_t *)(__bridge void *)inst + ivar_getOffset(iv)) = 1;
            YCHLOG(@"[2] open_ych ivar=1");
        }
    }
}

// ========== 3. 调用开启插件 ==========
static void callOpenAction(void) {
    Class c = openActionClass();
    if (!c) {
        YCHLOG(@"open-action class not found");
        return;
    }
    SEL s = NSSelectorFromString(@"dasjhdhasjdhk");
    if ([c respondsToSelector:s]) {
        ((void(*)(id,SEL))objc_msgSend)((id)c, s);
        YCHLOG(@"[3] called open-action dasjhdhasjdhk");
    } else {
        YCHLOG(@"open-action selector not found");
    }
}

// ========== Layer 0: 篡改初始化（延迟调用版） ==========

typedef void (*LCStartIMP)(id, SEL, id, id, id);
static LCStartIMP origLCStart = NULL;

// 保存原始参数
static id gOriginalAppId = nil;
static id gOriginalClientKey = nil;
static id gOriginalServerURL = nil;

static void hooked_LCStart(id self, SEL _cmd, id appId, id clientKey, id serverURL) {
    YCHLOG(@"🎭 [Layer0] LeanCloud init intercepted!");
    YCHLOG(@"    Original AppID: %@", appId);
    YCHLOG(@"    Original Server: %@", serverURL);

    // 保存原始参数
    gOriginalAppId = appId;
    gOriginalClientKey = clientKey;
    gOriginalServerURL = serverURL;

    // 检查 hook 是否就位
    if (!gHooksReady) {
        YCHLOG(@"⚠️  Hooks not ready yet, delaying init...");

        // 延迟 3 秒再初始化（确保所有 hook 就位）
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            YCHLOG(@"⏰ Delayed init now executing...");

            // 使用假参数初始化
            NSString *fakeAppId = @"fake-app-id-12345678";
            NSString *fakeClientKey = @"fake-client-key-abcdefgh";
            NSString *fakeServer = @"http://127.0.0.1:9999";

            YCHLOG(@"    Poisoned AppID: %@", fakeAppId);
            YCHLOG(@"    Poisoned Server: %@", fakeServer);

            origLCStart(self, _cmd, fakeAppId, fakeClientKey, fakeServer);
            YCHLOG(@"✅ [Layer0] SDK initialized with poisoned config");
        });

        return;  // 不调用原方法，延迟执行
    }

    // 如果 hook 已就位，立即用假参数初始化
    NSString *fakeAppId = @"fake-app-id-12345678";
    NSString *fakeClientKey = @"fake-client-key-abcdefgh";
    NSString *fakeServer = @"http://127.0.0.1:9999";

    YCHLOG(@"    Poisoned AppID: %@", fakeAppId);
    YCHLOG(@"    Poisoned Server: %@", fakeServer);

    origLCStart(self, _cmd, fakeAppId, fakeClientKey, fakeServer);
    YCHLOG(@"✅ [Layer0] SDK initialized with poisoned config");
}

// ========== Layer 1: 上报方法拦截 ==========

typedef void (*LCSave1IMP)(id, SEL, id, id, id, id);
static LCSave1IMP origLCSave1 = NULL;

static void hooked_LCSave1(id self, SEL _cmd, id className, id whereKey, id whereObj, id data) {
    YCHLOG(@"🚫 [Layer1] BLOCKED saveData! Class: %@, Data: %@", className, data);
    return;
}

typedef void (*LCSave2IMP)(id, SEL, id, id, id, id, id);
static LCSave2IMP origLCSave2 = NULL;

static void hooked_LCSave2(id self, SEL _cmd, id className, id whereKey, id whereObj, id data, id block) {
    YCHLOG(@"🚫 [Layer1] BLOCKED saveData(block)! Class: %@", className);

    if (block) {
        dispatch_async(dispatch_get_main_queue(), ^{
            void (^callback)(BOOL, id) = block;
            callback(YES, nil);
        });
    }
    return;
}

typedef void (*LCSave3IMP)(id, SEL, id, id, id, id, NSInteger, id);
static LCSave3IMP origLCSave3 = NULL;

static void hooked_LCSave3(id self, SEL _cmd, id className, id whereKey, id whereObj, id data, NSInteger limit, id block) {
    YCHLOG(@"🚫 [Layer1] BLOCKED saveData(limit+block)! Class: %@, Limit: %ld", className, (long)limit);

    if (block) {
        dispatch_async(dispatch_get_main_queue(), ^{
            void (^callback)(BOOL, id) = block;
            callback(YES, nil);
        });
    }
    return;
}

// ========== Layer 2: NSURLSession 拦截 ==========

typedef id (*DataTaskIMP)(id, SEL, id);
static DataTaskIMP origDataTask = NULL;

static id hooked_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *request) {
    NSURL *url = request.URL;

    if (isAuthorURL(url)) {
        YCHLOG(@"🚫 [Layer2] BLOCKED NSURLSession to: %@", url.absoluteString);
        NSURLRequest *deadReq = [NSURLRequest requestWithURL:[NSURL URLWithString:@"http://127.0.0.1:1"]];
        return origDataTask(self, _cmd, deadReq);
    }

    return origDataTask(self, _cmd, request);
}

typedef id (*DataTaskCompletionIMP)(id, SEL, id, id);
static DataTaskCompletionIMP origDataTaskCompletion = NULL;

static id hooked_dataTaskWithRequestCompletion(id self, SEL _cmd, NSURLRequest *request, id completion) {
    NSURL *url = request.URL;

    if (isAuthorURL(url)) {
        YCHLOG(@"🚫 [Layer2] BLOCKED NSURLSession(completion) to: %@", url.absoluteString);
        NSURLRequest *deadReq = [NSURLRequest requestWithURL:[NSURL URLWithString:@"http://127.0.0.1:1"]];
        return origDataTaskCompletion(self, _cmd, deadReq, completion);
    }

    return origDataTaskCompletion(self, _cmd, request, completion);
}

// ========== Layer 3: WebSocket/HTTP 拦截 ==========

typedef id (*SRWSInitIMP)(id, SEL, id);
static SRWSInitIMP origSRWSInit = NULL;

static id hooked_SRWSInitWithURLRequest(id self, SEL _cmd, NSURLRequest *req) {
    NSURL *u = req.URL;
    if (isAuthorURL(u)) {
        YCHLOG(@"🚫 [Layer3] BLOCKED WebSocket to: %@", u.absoluteString);
        NSURLRequest *dead = [NSURLRequest requestWithURL:[NSURL URLWithString:@"ws://127.0.0.1:1"]];
        return origSRWSInit(self, _cmd, dead);
    }
    return origSRWSInit(self, _cmd, req);
}

typedef void (*ZXReqIMP)(id, SEL, NSString*, NSString*, NSDictionary*, id, id, id);
static ZXReqIMP origZXRequest = NULL;

static void hooked_ZXRequest(id self, SEL _cmd,
                              NSString *method, NSString *urlStr,
                              NSDictionary *params,
                              id progress, id success, id failure) {
    NSURL *u = [NSURL URLWithString:urlStr];
    if (isAuthorURL(u)) {
        YCHLOG(@"🚫 [Layer3] BLOCKED HTTP %@ to: %@", method, urlStr);
        return;
    }
    origZXRequest(self, _cmd, method, urlStr, params, progress, success, failure);
}

typedef void (*PresentVCIMP)(id, SEL, id, BOOL, id);
static PresentVCIMP origPresentVC = NULL;

static void hooked_presentVC(id self, SEL _cmd, UIViewController *vc, BOOL animated, id completion) {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        NSString *t = alert.title;

        if (t && ([t containsString:@"温馨提示"] || [t containsString:@"更新"] ||
                  [t containsString:@"通知"] || [t containsString:@"提示"])) {
            YCHLOG(@"🚫 [Layer3] BLOCKED alert: %@", t);
            if (completion) ((void (^)(void))completion)();
            return;
        }
    }
    origPresentVC(self, _cmd, vc, animated, completion);
}

// ========== 安装所有 HOOK ==========
static void installPrivacyShield(void) {
    YCHLOG(@"========== Installing Privacy Shield v8-FIXED-SAFE ==========");

    // === Layer 1: 先安装上报拦截（最重要）===
    Class wpClass = NSClassFromString(@"WPLeanCloudHandler");
    if (wpClass) {
        YCHLOG(@"✓ Found WPLeanCloudHandler");

        SEL save1Sel = NSSelectorFromString(@"LeanCloud_saveDataWithClassName:whereKey:whereObj:data:");
        Method save1 = class_getClassMethod(wpClass, save1Sel);
        if (save1) {
            origLCSave1 = (LCSave1IMP)method_setImplementation(save1, (IMP)hooked_LCSave1);
            YCHLOG(@"✓ Hooked saveData (v1)");
        }

        SEL save2Sel = NSSelectorFromString(@"LeanCloud_saveDataWithClassName:whereKey:whereObj:data:block:");
        Method save2 = class_getClassMethod(wpClass, save2Sel);
        if (save2) {
            origLCSave2 = (LCSave2IMP)method_setImplementation(save2, (IMP)hooked_LCSave2);
            YCHLOG(@"✓ Hooked saveData (v2)");
        }

        SEL save3Sel = NSSelectorFromString(@"LeanCloud_saveDataWithClassName:whereKey:whereObj:data:limit:block:");
        Method save3 = class_getClassMethod(wpClass, save3Sel);
        if (save3) {
            origLCSave3 = (LCSave3IMP)method_setImplementation(save3, (IMP)hooked_LCSave3);
            YCHLOG(@"✓ Hooked saveData (v3)");
        }

        // === Layer 0: 最后才 hook 初始化 ===
        Method startMethod = class_getClassMethod(wpClass, @selector(startWith:clientKey:serverURLString:));
        if (startMethod) {
            origLCStart = (LCStartIMP)method_setImplementation(startMethod, (IMP)hooked_LCStart);
            YCHLOG(@"✓ Hooked startWith (config poisoning)");
        }
    } else {
        YCHLOG(@"⚠️  WPLeanCloudHandler not found");
    }

    // === Layer 2: NSURLSession ===
    Class sessionClass = NSClassFromString(@"NSURLSession");
    if (sessionClass) {
        Method m1 = class_getInstanceMethod(sessionClass, @selector(dataTaskWithRequest:));
        if (m1) {
            origDataTask = (DataTaskIMP)method_setImplementation(m1, (IMP)hooked_dataTaskWithRequest);
            YCHLOG(@"✓ Hooked NSURLSession dataTaskWithRequest:");
        }

        Method m2 = class_getInstanceMethod(sessionClass, @selector(dataTaskWithRequest:completionHandler:));
        if (m2) {
            origDataTaskCompletion = (DataTaskCompletionIMP)method_setImplementation(m2, (IMP)hooked_dataTaskWithRequestCompletion);
            YCHLOG(@"✓ Hooked NSURLSession dataTaskWithRequest:completionHandler:");
        }
    }

    // === Layer 3: WebSocket/HTTP ===
    Class srws = NSClassFromString(@"SRWebSocket");
    if (srws) {
        Method initMethod = class_getInstanceMethod(srws, NSSelectorFromString(@"initWithURLRequest:"));
        if (initMethod) {
            origSRWSInit = (SRWSInitIMP)method_setImplementation(initMethod, (IMP)hooked_SRWSInitWithURLRequest);
            YCHLOG(@"✓ Hooked SRWebSocket");
        }
    }

    Class zxr = NSClassFromString(@"ZXHttpRequest");
    if (zxr) {
        SEL zxSel = NSSelectorFromString(@"requestWithMethod:url:params:progress:success:failure:");
        Method zxMethod = class_getInstanceMethod(zxr, zxSel);
        if (!zxMethod) zxMethod = class_getClassMethod(zxr, zxSel);
        if (zxMethod) {
            origZXRequest = (ZXReqIMP)method_setImplementation(zxMethod, (IMP)hooked_ZXRequest);
            YCHLOG(@"✓ Hooked ZXHttpRequest");
        }
    }

    Class uivc = NSClassFromString(@"UIViewController");
    if (uivc) {
        Method presentMethod = class_getInstanceMethod(uivc, @selector(presentViewController:animated:completion:));
        if (presentMethod) {
            origPresentVC = (PresentVCIMP)method_setImplementation(presentMethod, (IMP)hooked_presentVC);
            YCHLOG(@"✓ Hooked UIViewController");
        }
    }

    // 标记 hook 就位
    gHooksReady = YES;
    YCHLOG(@"========== ✅ All Hooks Ready ==========");
}

// ========== 入口 ==========
__attribute__((constructor))
static void DYYCHUnlock_init(void) {
    YCHLOG(@"🚀 init — v8-FIXED-SAFE (延迟初始化 + 零时序漏洞)");

    // 立即安装 hook（在主线程，同步执行）
    installPrivacyShield();

    // pin 激活：+1s
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (!NSClassFromString(@"potpiutoideidcs")) {
            YCHLOG(@"not v260525-22 — abort");
            return;
        }
        startPin();
    });

    // 功能开启：+9s
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(9.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        setOpenYch();
        callOpenAction();
        YCHLOG(@"✅ [privacy+功能] 全部完成");
    });
}
