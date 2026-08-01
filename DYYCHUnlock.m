/**
 * DYYCHUnlock.m v7 — 纯固化版（v260525-22）+ Privacy Shield
 *
 * 把 dyunlock_clean.py 验证通过的三样固化进原生 dylib，脱离电脑/frida：
 *   1. 持续 pin cjIsStatus(0x18629b8)=1 + cjIsSuperAdmin(0x18629bb)=1（保激活，不降级序列号）
 *   2. setOpen_dy_ych_show:YES（演唱会闸）
 *   3. 调 +[pytpiutoideidcq dasjhdhasjdhk]（无参类方法 = 点"开启插件" → 直播间菜单+状态栏+演唱会全功能）
 *
 * v7 新增 Privacy Shield：
 *   - hook -[SRWebSocket open]：拦截到作者后端 106.53.173.140 的 WS 连接，静默丢弃
 *   - hook -[ZXHttpRequest requestWithMethod:url:params:progress:success:failure:]：
 *     拦截到作者后端的 HTTP 上报，直接回调 success(nil) 不发出去
 *   - 目的：作者后端收不到任何使用数据、购票记录、激活信息
 *
 * 设备：iPhone 12 / iOS 14.8.1 / arm64（牛磺酸 + TrollStore）。注入：本 dylib + libswiftMetal_patched.dylib。
 *
 * 安全做法：
 *   - 绝不 hook WCTools.addBtn（带 CGRect by-value，会崩）——clean.py 实证不补 addSubview 也全功能
 *   - pin 定时器只写两个字节；base 用 dladdr 一次性解析（不在 dyld 加载期遍历镜像）
 *   - 全部放进 +9s 延迟块（等作者 AWESpriter/类注册完，对齐 clean.py 的 +9s 时机）
 *   - Privacy Shield 在 +3s 时装（SRWebSocket 类必须已注册，但尽早拦首次连接）
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>

#define YCHLOG(fmt, ...) NSLog(@"[YCHUnlock] " fmt, ##__VA_ARGS__)

// __common 字节偏移（file VA，preferred base 0）—— v260525-22
#define CJISSTATUS_VA    0x18629b8
#define CJSUPERADMIN_VA  0x18629bb

// 多版本类名 fallback（新混淆名在前，旧明文名兜底）
static Class resolveClass(NSArray<NSString *> *names) {
    for (NSString *n in names) { Class c = NSClassFromString(n); if (c) return c; }
    return nil;
}
static Class gateClass(void) {        // XBDLeanCloudHandler / 持 open_dy_ych_show
    return resolveClass(@[ @"potpiutoideidcs", @"XBDLeanCloudHandler" ]);
}
static Class openActionClass(void) {  // CJDebugHandler 系 / 持 dasjhdhasjdhk(开启动作)
    return resolveClass(@[ @"pytpiutoideidcq", @"CJDebugHandler" ]);
}

// ---- 1. 持续 pin ----
static dispatch_source_t gPinTimer;
static volatile uint8_t *gStatusP = NULL;
static volatile uint8_t *gSuperP  = NULL;

// 用 dladdr 拿 libswiftMetal_patched 运行时基址（安全，不遍历 dyld 镜像）
static BOOL resolvePinPtrs(void) {
    Class g = gateClass();
    if (!g) return NO;
    Method m = class_getClassMethod(g, NSSelectorFromString(@"sharedInstance"));
    if (!m) return NO;
    Dl_info info;
    if (dladdr((void *)method_getImplementation(m), &info) && info.dli_fbase) {
        uintptr_t base = (uintptr_t)info.dli_fbase;   // preferred base 0 → base+fileVA
        gStatusP = (volatile uint8_t *)(base + CJISSTATUS_VA);
        gSuperP  = (volatile uint8_t *)(base + CJSUPERADMIN_VA);
        return YES;
    }
    return NO;
}

static void startPin(void) {
    if (!resolvePinPtrs()) { YCHLOG(@"resolvePinPtrs failed"); return; }
    dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    gPinTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    dispatch_source_set_timer(gPinTimer, DISPATCH_TIME_NOW,
                              (uint64_t)(0.1 * NSEC_PER_SEC), (uint64_t)(0.03 * NSEC_PER_SEC));
    dispatch_source_set_event_handler(gPinTimer, ^{
        if (gStatusP) { *gStatusP = 1; *gSuperP = 1; }
    });
    dispatch_resume(gPinTimer);
    YCHLOG(@"[1] pin cjIsStatus+cjIsSuperAdmin=1 @100ms");
}

// ---- 2. setOpen_dy_ych_show:YES ----
static void setOpenYch(void) {
    Class g = gateClass();
    if (!g) { YCHLOG(@"gate class not found"); return; }
    id inst = ((id(*)(id,SEL))objc_msgSend)((id)g, NSSelectorFromString(@"sharedInstance"));
    if (!inst) { YCHLOG(@"gate sharedInstance nil"); return; }
    SEL s = NSSelectorFromString(@"setOpen_dy_ych_show:");
    if ([inst respondsToSelector:s]) {
        ((void(*)(id,SEL,BOOL))objc_msgSend)(inst, s, YES);
        YCHLOG(@"[2] setOpen_dy_ych_show:YES");
    } else {
        // 兜底：直接写 ivar offset 9
        Ivar iv = class_getInstanceVariable(g, "_open_dy_ych_show");
        if (iv) { *((uint8_t *)(__bridge void *)inst + ivar_getOffset(iv)) = 1; YCHLOG(@"[2] open_ych ivar=1"); }
    }
}

// ---- 3. 调开启插件 action（无参类方法）----
static void callOpenAction(void) {
    Class c = openActionClass();
    if (!c) { YCHLOG(@"open-action class not found"); return; }
    SEL s = NSSelectorFromString(@"dasjhdhasjdhk");
    if ([c respondsToSelector:s]) {
        ((void(*)(id,SEL))objc_msgSend)((id)c, s);
        YCHLOG(@"[3] called open-action dasjhdhasjdhk");
    } else {
        YCHLOG(@"open-action selector not found on %s", class_getName(c));
    }
}

// ---- 4. Privacy Shield — 断作者后端通信 ----

// 作者后端 IP；插件通过 SRWebSocket + ZXHttpRequest 上报使用数据/购票记录到这里
static NSString * const kAuthorBackendHost = @"106.53.173.140";

static BOOL isAuthorURL(NSURL *url) {
    if (!url) return NO;
    NSString *h = url.host;
    if (!h) return NO;
    return [h isEqualToString:kAuthorBackendHost];
}

// -[SRWebSocket initWithURLRequest:] hook：在 WS 对象创建时就把 URL 换成死地址
// 比 -open 更早，不管 open 什么时候调都不会连到作者服务器
typedef id (*SRWSInitIMP)(id, SEL, id);
static SRWSInitIMP origSRWSInit = NULL;
static id hooked_SRWSInitWithURLRequest(id self, SEL _cmd, NSURLRequest *req) {
    NSURL *u = req.URL;
    if (isAuthorURL(u)) {
        YCHLOG(@"[privacy] redirect WS init → dead addr (orig: %@)", u.absoluteString);
        // 把 URL 换成本机拒绝端口，open 会立刻 fail 且不会重连到作者服务器
        NSURLRequest *dead = [NSURLRequest requestWithURL:
                              [NSURL URLWithString:@"ws://127.0.0.1:1"]];
        return origSRWSInit(self, _cmd, dead);
    }
    return origSRWSInit(self, _cmd, req);
}

// ZXHttpRequest 上报拦截
typedef void (*ZXReqIMP)(id, SEL, NSString*, NSString*, NSDictionary*, id, id, id);
static ZXReqIMP origZXRequest = NULL;
static void hooked_ZXRequest(id self, SEL _cmd,
                              NSString *method, NSString *urlStr,
                              NSDictionary *params,
                              id progress, id success, id failure) {
    NSURL *u = [NSURL URLWithString:urlStr];
    if (isAuthorURL(u)) {
        YCHLOG(@"[privacy] dropped HTTP %@ → %@", method, urlStr);
        return;
    }
    origZXRequest(self, _cmd, method, urlStr, params, progress, success, failure);
}

// -[UIViewController presentViewController:animated:completion:] 拦截
// 拦截作者的"温馨提示"公告弹窗（服务器公告/升级提示）
typedef void (*PresentVCIMP)(id, SEL, id, BOOL, id);
static PresentVCIMP origPresentVC = NULL;
static void hooked_presentVC(id self, SEL _cmd, UIViewController *vc, BOOL animated, id completion) {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        NSString *t = alert.title;
        // 拦截作者的服务器公告弹窗（"温馨提示"/"更新"标题）
        if ([t isEqualToString:@"温馨提示"] || [t isEqualToString:@"更新"] || t == nil) {
            // 检查 message 是否是作者公告特征（避免误杀其他 alert）
            NSString *msg = alert.message;
            if (msg && ([msg containsString:@"升级"] || [msg containsString:@"更新"] ||
                        [msg containsString:@"请升级"] || [msg containsString:@"最新版"])) {
                YCHLOG(@"[privacy] suppressed author alert: %@ — %@", t, msg);
                if (completion) ((void (^)(void))completion)();
                return;
            }
        }
    }
    origPresentVC(self, _cmd, vc, animated, completion);
}

static void installPrivacyShield(void) {
    // --- SRWebSocket -initWithURLRequest: ---
    // 在 WS 对象创建时换 URL，比 -open 更早，彻底断连
    Class srws = NSClassFromString(@"SRWebSocket");
    if (srws) {
        SEL initSel = NSSelectorFromString(@"initWithURLRequest:");
        Method m = class_getInstanceMethod(srws, initSel);
        if (m) {
            origSRWSInit = (SRWSInitIMP)method_setImplementation(m, (IMP)hooked_SRWSInitWithURLRequest);
            YCHLOG(@"[privacy] SRWebSocket -initWithURLRequest: hooked");
        } else {
            YCHLOG(@"[privacy] SRWebSocket -initWithURLRequest: NOT FOUND");
        }
    } else {
        YCHLOG(@"[privacy] SRWebSocket class NOT FOUND");
    }

    // --- ZXHttpRequest -requestWithMethod:url:params:progress:success:failure: ---
    Class zxr = NSClassFromString(@"ZXHttpRequest");
    if (zxr) {
        SEL zxSel = NSSelectorFromString(@"requestWithMethod:url:params:progress:success:failure:");
        Method m2 = class_getInstanceMethod(zxr, zxSel);
        if (m2) {
            origZXRequest = (ZXReqIMP)method_setImplementation(m2, (IMP)hooked_ZXRequest);
            YCHLOG(@"[privacy] ZXHttpRequest -requestWithMethod: hooked");
        } else {
            YCHLOG(@"[privacy] ZXHttpRequest selector not found — trying class method");
            Method m3 = class_getClassMethod(zxr, zxSel);
            if (m3) {
                origZXRequest = (ZXReqIMP)method_setImplementation(m3, (IMP)hooked_ZXRequest);
                YCHLOG(@"[privacy] ZXHttpRequest +requestWithMethod: hooked (class method)");
            } else {
                YCHLOG(@"[privacy] ZXHttpRequest hook FAILED — selector not found");
            }
        }
    } else {
        YCHLOG(@"[privacy] ZXHttpRequest class NOT FOUND");
    }
    // --- UIViewController -presentViewController:animated:completion: (suppress author alert) ---
    Class uivc = NSClassFromString(@"UIViewController");
    if (uivc) {
        SEL pressSel = NSSelectorFromString(@"presentViewController:animated:completion:");
        Method m4 = class_getInstanceMethod(uivc, pressSel);
        if (m4) {
            origPresentVC = (PresentVCIMP)method_setImplementation(m4, (IMP)hooked_presentVC);
            YCHLOG(@"[privacy] UIViewController -presentVC: hooked (suppress author alerts)");
        }
    }
}

__attribute__((constructor))
static void DYYCHUnlock_init(void) {
    YCHLOG(@"init — v7.3 (固化三件套 + Privacy Shield 早注入)");

    // Privacy Shield：立即派发到主队列（dyld 加载完后首个 runloop tick 执行）
    // 比 WS 首次 connect 更早，彻底断连作者后端
    dispatch_async(dispatch_get_main_queue(), ^{
        installPrivacyShield();
    });

    // pin 激活：+1s 起，等类注册完
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (!NSClassFromString(@"potpiutoideidcs")) {
            YCHLOG(@"not v260525-22 (no potpiutoideidcs) — abort");
            return;
        }
        startPin();
    });

    // setOpen + 开启动作：+9s
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(9.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        setOpenYch();
        callOpenAction();
        YCHLOG(@"[privacy+ych] all done");
    });
}
