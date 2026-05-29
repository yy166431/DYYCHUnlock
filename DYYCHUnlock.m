/**
 * DYYCHUnlock.m v6 — 纯固化版（v260525-22）
 *
 * 把 dyunlock_clean.py 验证通过的三样固化进原生 dylib，脱离电脑/frida：
 *   1. 持续 pin cjIsStatus(0x18629b8)=1 + cjIsSuperAdmin(0x18629bb)=1（保激活，不降级序列号）
 *   2. setOpen_dy_ych_show:YES（演唱会闸）
 *   3. 调 +[pytpiutoideidcq dasjhdhasjdhk]（无参类方法 = 点"开启插件" → 直播间菜单+状态栏+演唱会全功能）
 *
 * 设备：iPhone 12 / iOS 14.8.1 / arm64（牛磺酸 + TrollStore）。注入：本 dylib + libswiftMetal_patched.dylib。
 *
 * 安全做法：
 *   - 绝不 hook WCTools.addBtn（带 CGRect by-value，会崩）——clean.py 实证不补 addSubview 也全功能
 *   - pin 定时器只写两个字节；base 用 dladdr 一次性解析（不在 dyld 加载期遍历镜像）
 *   - 全部放进 +9s 延迟块（等作者 AWESpriter/类注册完，对齐 clean.py 的 +9s 时机）
 */

#import <Foundation/Foundation.h>
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

__attribute__((constructor))
static void DYYCHUnlock_init(void) {
    YCHLOG(@"init — v6.0 (固化 clean.py 三件套)");
    // pin 越早越好（保激活，防早期降级序列号）；但 resolvePinPtrs 需类注册完，放进首次 +1s 再起，之后持续
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (!NSClassFromString(@"potpiutoideidcs")) {
            YCHLOG(@"not v260525-22 (no potpiutoideidcs) — abort");
            return;
        }
        startPin();
    });
    // setOpen + 开启动作：+9s（对齐 clean.py 验证时机，等 AWESpriter/页面就绪）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(9.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        setOpenYch();
        callOpenAction();
        YCHLOG(@"all done");
    });
}
