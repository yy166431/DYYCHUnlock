/**
 * DYYCHUnlock.m v8 — ULTIMATE Privacy Shield（彻底断连版）
 *
 * v8 修复：彻底阻断作者的 LeanCloud 数据上报
 *   问题根源：v7 只拦截了 106.53.173.140，但作者的数据通过 LeanCloud SDK
 *            直接发送到 lncldapi.com / lncldglobal.com，完全绕过了拦截！
 *
 * v8 新增防护（三层拦截）：
 *   Layer 1: HOOK WPLeanCloudHandler 所有上报方法（阻断源头）
 *   Layer 2: HOOK LeanCloud SDK 初始化（让SDK根本连不上服务器）
 *   Layer 3: HOOK NSURLSession 底层（拦截所有 lncld*.com 域名）
 *
 * 原有功能保留：
 *   1. pin cjIsStatus + cjIsSuperAdmin = 1（保激活）
 *   2. setOpen_dy_ych_show:YES（演唱会闸）
 *   3. 调 dasjhdhasjdhk（开启全功能）
 *   4. 拦截 106.53.173.140 的 WS/HTTP
 *   5. 拦截作者弹窗
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

// ========== 黑名单：作者的所有数据收集端点 ==========
static NSArray<NSString *> * authorHostsBlacklist(void) {
    return @[
        @"106.53.173.140",        // 作者服务器 IP
        @"lncldapi.com",          // LeanCloud API 域名
        @"lncldglobal.com",       // LeanCloud 全球域名
        @"avoscloud.com",         // LeanCloud 旧域名
        @"api.leancloud.cn",      // LeanCloud CN API
    ];
}

static BOOL isAuthorURL(NSURL *url) {
    if (!url || !url.host) return NO;
    NSString *host = url.host.lowercaseString;

    for (NSString *blocked in authorHostsBlacklist()) {
        // 精确匹配或子域名匹配
        if ([host isEqualToString:blocked] || [host hasSuffix:[@"." stringByAppendingString:blocked]]) {
            return YES;
        }
    }

    // 额外检查：任何包含 "leancloud" 或 "avos" 的域名
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

// ========== 4. Privacy Shield - Layer 1: HOOK WPLeanCloudHandler ==========

// HOOK: +[WPLeanCloudHandler startWith:clientKey:serverURLString:]
// 阻止 LeanCloud SDK 初始化
typedef void (*LCStartIMP)(id, SEL, id, id, id);
static LCStartIMP origLCStart = NULL;

static void hooked_LCStart(id self, SEL _cmd, id appId, id clientKey, id serverURL) {
    YCHLOG(@"🚫 [Layer1] BLOCKED LeanCloud init! AppID: %@, URL: %@", appId, serverURL);
    // 不调用原方法，SDK 根本初始化不了
    return;
}

// HOOK: +[WPLeanCloudHandler LeanCloud_saveDataWithClassName:whereKey:whereObj:data:]
typedef void (*LCSave1IMP)(id, SEL, id, id, id, id);
static LCSave1IMP origLCSave1 = NULL;

static void hooked_LCSave1(id self, SEL _cmd, id className, id whereKey, id whereObj, id data) {
    YCHLOG(@"🚫 [Layer1] BLOCKED LeanCloud saveData! Class: %@, Data: %@", className, data);
    return;
}

// HOOK: +[WPLeanCloudHandler LeanCloud_saveDataWithClassName:whereKey:whereObj:data:block:]
typedef void (*LCSave2IMP)(id, SEL, id, id, id, id, id);
static LCSave2IMP origLCSave2 = NULL;

static void hooked_LCSave2(id self, SEL _cmd, id className, id whereKey, id whereObj, id data, id block) {
    YCHLOG(@"🚫 [Layer1] BLOCKED LeanCloud saveData(block)! Class: %@, Data: %@", className, data);

    // 伪造成功回调，让插件以为上报成功了
    if (block) {
        dispatch_async(dispatch_get_main_queue(), ^{
            void (^callback)(BOOL, id) = block;
            callback(YES, nil);  // 伪造成功
        });
    }
    return;
}

// HOOK: +[WPLeanCloudHandler LeanCloud_saveDataWithClassName:whereKey:whereObj:data:limit:block:]
typedef void (*LCSave3IMP)(id, SEL, id, id, id, id, NSInteger, id);
static LCSave3IMP origLCSave3 = NULL;

static void hooked_LCSave3(id self, SEL _cmd, id className, id whereKey, id whereObj, id data, NSInteger limit, id block) {
    YCHLOG(@"🚫 [Layer1] BLOCKED LeanCloud saveData(limit+block)! Class: %@, Limit: %ld", className, (long)limit);

    if (block) {
        dispatch_async(dispatch_get_main_queue(), ^{
            void (^callback)(BOOL, id) = block;
            callback(YES, nil);
        });
    }
    return;
}

// ========== Layer 2: HOOK LeanCloud SDK 底层网络类 ==========

// HOOK NSURLSession 的 dataTaskWithRequest (LeanCloud SDK 用这个发请求)
typedef id (*DataTaskIMP)(id, SEL, id);
static DataTaskIMP origDataTask = NULL;

static id hooked_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *request) {
    NSURL *url = request.URL;

    if (isAuthorURL(url)) {
        YCHLOG(@"🚫 [Layer2] BLOCKED NSURLSession request to: %@", url.absoluteString);

        // 返回一个假的 task，但不会真正发送
        // 创建一个指向无效地址的请求
        NSURLRequest *deadReq = [NSURLRequest requestWithURL:[NSURL URLWithString:@"http://127.0.0.1:1"]];
        return origDataTask(self, _cmd, deadReq);
    }

    return origDataTask(self, _cmd, request);
}

// ========== Layer 3: 原有的 WS/HTTP 拦截（保留） ==========

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

// 拦截作者弹窗
typedef void (*PresentVCIMP)(id, SEL, id, BOOL, id);
static PresentVCIMP origPresentVC = NULL;

static void hooked_presentVC(id self, SEL _cmd, UIViewController *vc, BOOL animated, id completion) {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        NSString *t = alert.title;
        NSString *msg = alert.message;

        // 拦截作者的所有公告（更严格的匹配）
        if (t && ([ t containsString:@"温馨提示"] || [t containsString:@"更新"] ||
                  [t containsString:@"通知"] || [t containsString:@"提示"])) {
            YCHLOG(@"🚫 [Layer3] BLOCKED author alert: %@ — %@", t, msg);
            if (completion) ((void (^)(void))completion)();
            return;
        }
    }
    origPresentVC(self, _cmd, vc, animated, completion);
}

// ========== 安装所有 HOOK ==========
static void installUltimatePrivacyShield(void) {
    YCHLOG(@"========== Installing ULTIMATE Privacy Shield ==========");

    // === Layer 1: WPLeanCloudHandler ===
    Class wpClass = NSClassFromString(@"WPLeanCloudHandler");
    if (wpClass) {
        YCHLOG(@"✓ Found WPLeanCloudHandler");

        // HOOK startWith (初始化)
        Method startMethod = class_getClassMethod(wpClass, @selector(startWith:clientKey:serverURLString:));
        if (startMethod) {
            origLCStart = (LCStartIMP)method_setImplementation(startMethod, (IMP)hooked_LCStart);
            YCHLOG(@"✓ Hooked startWith:clientKey:serverURLString:");
        }

        // HOOK saveData 方法1
        SEL save1Sel = NSSelectorFromString(@"LeanCloud_saveDataWithClassName:whereKey:whereObj:data:");
        Method save1 = class_getClassMethod(wpClass, save1Sel);
        if (save1) {
            origLCSave1 = (LCSave1IMP)method_setImplementation(save1, (IMP)hooked_LCSave1);
            YCHLOG(@"✓ Hooked LeanCloud_saveData (variant 1)");
        }

        // HOOK saveData 方法2
        SEL save2Sel = NSSelectorFromString(@"LeanCloud_saveDataWithClassName:whereKey:whereObj:data:block:");
        Method save2 = class_getClassMethod(wpClass, save2Sel);
        if (save2) {
            origLCSave2 = (LCSave2IMP)method_setImplementation(save2, (IMP)hooked_LCSave2);
            YCHLOG(@"✓ Hooked LeanCloud_saveData (variant 2)");
        }

        // HOOK saveData 方法3
        SEL save3Sel = NSSelectorFromString(@"LeanCloud_saveDataWithClassName:whereKey:whereObj:data:limit:block:");
        Method save3 = class_getClassMethod(wpClass, save3Sel);
        if (save3) {
            origLCSave3 = (LCSave3IMP)method_setImplementation(save3, (IMP)hooked_LCSave3);
            YCHLOG(@"✓ Hooked LeanCloud_saveData (variant 3)");
        }
    } else {
        YCHLOG(@"⚠️  WPLeanCloudHandler not found (may be OK if not loaded yet)");
    }

    // === Layer 2: NSURLSession ===
    Class sessionClass = NSClassFromString(@"NSURLSession");
    if (sessionClass) {
        Method dataTaskMethod = class_getInstanceMethod(sessionClass, @selector(dataTaskWithRequest:));
        if (dataTaskMethod) {
            origDataTask = (DataTaskIMP)method_setImplementation(dataTaskMethod, (IMP)hooked_dataTaskWithRequest);
            YCHLOG(@"✓ Hooked NSURLSession dataTaskWithRequest:");
        }
    }

    // === Layer 3: 原有拦截 ===
    // SRWebSocket
    Class srws = NSClassFromString(@"SRWebSocket");
    if (srws) {
        Method initMethod = class_getInstanceMethod(srws, NSSelectorFromString(@"initWithURLRequest:"));
        if (initMethod) {
            origSRWSInit = (SRWSInitIMP)method_setImplementation(initMethod, (IMP)hooked_SRWSInitWithURLRequest);
            YCHLOG(@"✓ Hooked SRWebSocket initWithURLRequest:");
        }
    }

    // ZXHttpRequest
    Class zxr = NSClassFromString(@"ZXHttpRequest");
    if (zxr) {
        SEL zxSel = NSSelectorFromString(@"requestWithMethod:url:params:progress:success:failure:");
        Method zxMethod = class_getInstanceMethod(zxr, zxSel);
        if (!zxMethod) zxMethod = class_getClassMethod(zxr, zxSel);
        if (zxMethod) {
            origZXRequest = (ZXReqIMP)method_setImplementation(zxMethod, (IMP)hooked_ZXRequest);
            YCHLOG(@"✓ Hooked ZXHttpRequest requestWithMethod:");
        }
    }

    // UIViewController (拦截弹窗)
    Class uivc = NSClassFromString(@"UIViewController");
    if (uivc) {
        Method presentMethod = class_getInstanceMethod(uivc, @selector(presentViewController:animated:completion:));
        if (presentMethod) {
            origPresentVC = (PresentVCIMP)method_setImplementation(presentMethod, (IMP)hooked_presentVC);
            YCHLOG(@"✓ Hooked UIViewController presentViewController:");
        }
    }

    YCHLOG(@"========== Privacy Shield Installation Complete ==========");
}

// ========== 入口 ==========
__attribute__((constructor))
static void DYYCHUnlock_init(void) {
    YCHLOG(@"🚀 init — v8.0 ULTIMATE (三层拦截 + 彻底断 LeanCloud)");

    // 立即安装 Privacy Shield（尽早拦截）
    dispatch_async(dispatch_get_main_queue(), ^{
        installUltimatePrivacyShield();
    });

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
