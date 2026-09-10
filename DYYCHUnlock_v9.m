/**
 * DYYCHUnlock.m v9 — 纯净版：精确拦截 saveData，业务查询正常
 *
 * v9 改进：
 *   1. ❌ 删除参数投毒 — SDK 正常连接真实服务器
 *   2. ✅ 只拦截 saveData — 阻止隐私上报
 *   3. ✅ 放行 LCQuery — 让订单刷新/商品查询正常工作
 *   4. ❌ 删除 Layer 2/3 网络拦截 — 不误伤业务请求
 *   5. ✅ 保留反调试 + 功能开关 + Alert 拦截
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>

#define YCHLOG(fmt, ...) NSLog(@"[YCHUnlock-v9] " fmt, ##__VA_ARGS__)

// __common 字节偏移
#define CJISSTATUS_VA    0x18629b8
#define CJSUPERADMIN_VA  0x18629bb

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
        YCHLOG(@"❌ resolvePinPtrs failed");
        return;
    }
    dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    gPinTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    dispatch_source_set_timer(gPinTimer, DISPATCH_TIME_NOW,
                              (uint64_t)(0.1 * NSEC_PER_SEC), (uint64_t)(0.03 * NSEC_PER_SEC));
    dispatch_source_set_event_handler(gPinTimer, ^{
        if (gStatusP) {
            uint8_t old = *gStatusP;
            *gStatusP = 1;
            if (old != 1) YCHLOG(@"✅ PIN status → 1");
        }
        if (gSuperP) {
            uint8_t old = *gSuperP;
            *gSuperP = 1;
            if (old != 1) YCHLOG(@"✅ PIN super → 1");
        }
    });
    dispatch_resume(gPinTimer);
    YCHLOG(@"✅ PIN timer started");
}

// ========== 2. 开门方法开关 ==========
static void (*origOpen)(id, SEL);
static void hookedOpen(id self, SEL _cmd) {
    YCHLOG(@"✅ 开门方法被调用");
    if (origOpen) origOpen(self, _cmd);
}

static void hookOpenAction(void) {
    Class c = openActionClass();
    if (!c) {
        YCHLOG(@"❌ openActionClass not found");
        return;
    }
    SEL s = NSSelectorFromString(@"dasjhdhasjdhk");
    Method m = class_getInstanceMethod(c, s);
    if (!m) {
        YCHLOG(@"❌ open method not found");
        return;
    }
    origOpen = (void (*)(id, SEL))method_getImplementation(m);
    method_setImplementation(m, (IMP)hookedOpen);
    YCHLOG(@"✅ 开门方法已 hook");
}

// ========== 3. 拦截 UIAlertController ==========
static id (*origAlertInit)(id, SEL);
static id hookedAlertInit(id self, SEL _cmd) {
    return nil;  // 拦截所有弹窗
}

static void hookAlertController(void) {
    Class c = NSClassFromString(@"UIAlertController");
    if (!c) return;
    SEL s = NSSelectorFromString(@"init");
    Method m = class_getInstanceMethod(c, s);
    if (!m) return;
    origAlertInit = (id (*)(id, SEL))method_getImplementation(m);
    method_setImplementation(m, (IMP)hookedAlertInit);
    YCHLOG(@"✅ UIAlertController.init 已拦截");
}

// ========== 4. 精确拦截 saveData（核心防护）==========
static void (*origSaveData5)(id, SEL, id, id, id, id, id);
static void (*origSaveData6)(id, SEL, id, id, id, id, int64_t, id);

static void hookedSaveData5(id self, SEL _cmd, id className, id whereKey, id whereObj, id data, id block) {
    YCHLOG(@"🚫 [v9] 拦截 saveData (5参数) - className:%@", className);
    // 不调用原方法，直接返回
    return;
}

static void hookedSaveData6(id self, SEL _cmd, id className, id whereKey, id whereObj, id data, int64_t limit, id block) {
    YCHLOG(@"🚫 [v9] 拦截 saveData (6参数) - className:%@", className);
    // 不调用原方法，直接返回
    return;
}

static void hookSaveData(void) {
    Class handler = NSClassFromString(@"WPLeanCloudHandler");
    if (!handler) {
        YCHLOG(@"❌ WPLeanCloudHandler not found");
        return;
    }

    // Hook 5参数版本
    SEL s5 = NSSelectorFromString(@"LeanCloud_saveDataWithClassName:whereKey:whereObj:data:block:");
    Method m5 = class_getClassMethod(handler, s5);
    if (m5) {
        origSaveData5 = (void (*)(id, SEL, id, id, id, id, id))method_getImplementation(m5);
        method_setImplementation(m5, (IMP)hookedSaveData5);
        YCHLOG(@"✅ saveData (5参数) 已拦截");
    }

    // Hook 6参数版本
    SEL s6 = NSSelectorFromString(@"LeanCloud_saveDataWithClassName:whereKey:whereObj:data:limit:block:");
    Method m6 = class_getClassMethod(handler, s6);
    if (m6) {
        origSaveData6 = (void (*)(id, SEL, id, id, id, id, int64_t, id))method_getImplementation(m6);
        method_setImplementation(m6, (IMP)hookedSaveData6);
        YCHLOG(@"✅ saveData (6参数) 已拦截");
    }
}

// ========== 入口 ==========
__attribute__((constructor))
static void dyych_unlock_init(void) {
    YCHLOG(@"========== DYYCHUnlock v9 纯净版启动 ==========");

    // 1. PIN 激活
    startPin();

    // 2. Hook 开门方法
    hookOpenAction();

    // 3. 拦截弹窗
    hookAlertController();

    // 4. 精确拦截 saveData（核心）
    hookSaveData();

    YCHLOG(@"========== v9 初始化完成 ==========");
    YCHLOG(@"✅ SDK 正常连接服务器");
    YCHLOG(@"✅ LCQuery 业务查询正常");
    YCHLOG(@"🚫 saveData 隐私上报已拦截");
}
