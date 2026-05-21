/**
 * DYYCHUnlock.m v2 — 抖音演唱会助手全功能解锁 dylib
 *
 * 通过 TrollFools 注入抖音（配合 libswiftMetal_patched.dylib），实现：
 * 1. Fake WS — hook wsUrl getter 返回假 URL + hook SRWebSocket delegate 回调
 * 2. Gate 解锁 — _open_dy_ych_show = 1
 * 3. addBtn fix — 补 addSubview
 * 4. AWENetworkRequest hook — 触发 req_finish 建演唱会菜单
 *
 * 编译：GitHub Actions (macOS-14 + xcrun iphoneos clang arm64)
 */

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

#pragma mark - Logging

#define YCHLOG(fmt, ...) NSLog(@"[YCHUnlock] " fmt, ##__VA_ARGS__)

#pragma mark - Forward declarations

static void setupFakeWS(void);
static void setupGateUnlock(void);
static void setupAddBtnFix(void);
static void setupNetworkHook(void);

#pragma mark - Constructor

__attribute__((constructor))
static void DYYCHUnlock_init(void) {
    YCHLOG(@"init — v2.0");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        setupGateUnlock();
        setupAddBtnFix();
        setupNetworkHook();
        setupFakeWS();
        YCHLOG(@"all hooks installed");
    });
}

#pragma mark - Swizzle Helper

static void swizzleInstanceMethod(Class cls, SEL orig, SEL replacement) {
    Method origMethod = class_getInstanceMethod(cls, orig);
    Method replMethod = class_getInstanceMethod(cls, replacement);
    if (origMethod && replMethod) {
        method_exchangeImplementations(origMethod, replMethod);
    }
}

#pragma mark - 1. Fake WS (safe approach)

static IMP orig_wsUrl_IMP = NULL;

static id hook_wsUrl(id self, SEL _cmd) {
    return @"ws://127.0.0.1:18888/dy";
}

static void setupFakeWS(void) {
    // Hook wsUrl getter on SRWebSocketHelper to return non-nil URL
    // This prevents "广播消息订阅地址未配置" error
    Class SRWSHelper = NSClassFromString(@"SRWebSocketHelper");
    if (!SRWSHelper) { YCHLOG(@"SRWebSocketHelper not found"); return; }

    SEL wsUrlSel = NSSelectorFromString(@"wsUrl");
    Method m = class_getInstanceMethod(SRWSHelper, wsUrlSel);
    if (m) {
        orig_wsUrl_IMP = method_setImplementation(m, (IMP)hook_wsUrl);
        YCHLOG(@"wsUrl hook installed (returns fake URL)");
    }

    // Also force-create a WS instance and set it on the helper
    // so isConnected checks pass
    id helper = ((id(*)(id,SEL))objc_msgSend)((id)SRWSHelper,
                    NSSelectorFromString(@"sharedInstance"));
    if (!helper) return;

    Class SRWebSocket = NSClassFromString(@"SRWebSocket");
    if (!SRWebSocket) return;

    // Create SRWebSocket with fake URL
    NSURL *url = [NSURL URLWithString:@"ws://127.0.0.1:18888/dy"];
    id ws = ((id(*)(id,SEL))objc_msgSend)((id)SRWebSocket,
                NSSelectorFromString(@"alloc"));
    ws = ((id(*)(id,SEL,id))objc_msgSend)(ws,
                NSSelectorFromString(@"initWithURL:"), url);
    if (!ws) return;

    // Retain heavily
    for (int i = 0; i < 10; i++) {
        ((void(*)(id,SEL))objc_msgSend)(ws, NSSelectorFromString(@"retain"));
    }

    // Set delegate + webSocket on helper
    ((void(*)(id,SEL,id))objc_msgSend)(ws,
        NSSelectorFromString(@"setDelegate:"), helper);
    ((void(*)(id,SEL,id))objc_msgSend)(helper,
        NSSelectorFromString(@"setWebSocket:"), ws);

    // Force readyState = SR_OPEN (1) to pass connection checks
    Ivar readyStateIvar = class_getInstanceVariable(SRWebSocket, "_readyState");
    if (readyStateIvar) {
        ptrdiff_t off = ivar_getOffset(readyStateIvar);
        *((int *)((uint8_t *)(__bridge void *)ws + off)) = 1; // SR_OPEN
        YCHLOG(@"readyState forced to OPEN");
    }

    // Also hook readyState getter as fallback
    SEL rsSel = NSSelectorFromString(@"readyState");
    Method rsMethod = class_getInstanceMethod(SRWebSocket, rsSel);
    if (rsMethod) {
        method_setImplementation(rsMethod, imp_implementationWithBlock(^long(id self_) {
            return 1; // SR_OPEN
        }));
        YCHLOG(@"readyState getter hooked → always OPEN");
    }

    // Don't call open — just having a non-nil webSocket suppresses errors
    YCHLOG(@"Fake WS instance set on helper");
}

#pragma mark - 2. Gate Unlock (_open_dy_ych_show = 1)

static void setupGateUnlock(void) {
    Class XBD = NSClassFromString(@"XBDLeanCloudHandler");
    if (!XBD) { YCHLOG(@"XBDLeanCloudHandler not found"); return; }

    SEL sharedSel = NSSelectorFromString(@"sharedInstance");
    id xbd = ((id(*)(id,SEL))objc_msgSend)((id)XBD, sharedSel);
    if (!xbd) { YCHLOG(@"XBD sharedInstance nil"); return; }

    Ivar ivar = class_getInstanceVariable(XBD, "_open_dy_ych_show");
    if (ivar) {
        ptrdiff_t offset = ivar_getOffset(ivar);
        uint8_t *ptr = (uint8_t *)(__bridge void *)xbd + offset;
        *ptr = 1;
        YCHLOG(@"_open_dy_ych_show = 1 (offset %td)", offset);
    } else {
        uint8_t *ptr = (uint8_t *)(__bridge void *)xbd + 9;
        *ptr = 1;
        YCHLOG(@"_open_dy_ych_show = 1 (hardcoded offset 9)");
    }
}

#pragma mark - 3. addBtn fix (补 addSubview)

static IMP orig_addBtnWithView_IMP = NULL;

static id hook_addBtnWithView(id self, SEL _cmd, id view, id text,
                              CGRect frame, id callback) {
    id btn = ((id(*)(id,SEL,id,id,CGRect,id))orig_addBtnWithView_IMP)(
        self, _cmd, view, text, frame, callback);
    if (view && btn) {
        ((void(*)(id,SEL,id))objc_msgSend)(view,
            NSSelectorFromString(@"addSubview:"), btn);
    }
    return btn;
}

static void setupAddBtnFix(void) {
    Class WCTools = NSClassFromString(@"WCTools");
    if (!WCTools) { YCHLOG(@"WCTools not found"); return; }

    SEL sel = NSSelectorFromString(@"addBtnWithView:text:frame:CallBack:");
    Method m = class_getClassMethod(WCTools, sel);
    if (!m) { YCHLOG(@"addBtnWithView not found"); return; }

    orig_addBtnWithView_IMP = method_getImplementation(m);
    method_setImplementation(m, (IMP)hook_addBtnWithView);
    YCHLOG(@"addBtn fix installed");
}

#pragma mark - 4. AWENetworkRequest hook → trigger req_finish

@interface NSObject (YCHNetHook)
- (void)ych_netHook:(id)block
              method:(id)method
              params:(id)params
                 res:(id)res
                 err:(id)err
              netReq:(id)netReq;
@end

@implementation NSObject (YCHNetHook)

- (void)ych_netHook:(id)block
              method:(id)method
              params:(id)params
                 res:(id)res
                 err:(id)err
              netReq:(id)netReq {
    // Call original (swizzled — this calls the author's real impl)
    [self ych_netHook:block method:method params:params
                  res:res err:err netReq:netReq];

    // Safety checks
    if (!params || !res) return;
    if (![res isKindOfClass:[NSDictionary class]]) return;
    if (![params isKindOfClass:[NSDictionary class]]) return;

    NSDictionary *resDict = (NSDictionary *)res;
    NSDictionary *paramsDict = (NSDictionary *)params;

    BOOL hasProductId = (paramsDict[@"product_id"] != nil);
    BOOL hasBuyLimit = (resDict[@"buy_limit"] != nil);
    BOOL hasProductData = (resDict[@"ProductSerializationData"] != nil);

    if (!hasProductId && !hasBuyLimit && !hasProductData) return;

    Class DYYCHHelper = NSClassFromString(@"DYYCHHelper");
    id helper = ((id(*)(id,SEL))objc_msgSend)((id)DYYCHHelper,
                    NSSelectorFromString(@"sharedInstance"));
    if (!helper) return;

    @try {
        if (hasProductData) {
            SEL sel = NSSelectorFromString(
                @"req_finish_YCH_product_info_WithParams:res:");
            ((void(*)(id,SEL,id,id))objc_msgSend)(helper, sel, params, res);
        } else if (hasBuyLimit) {
            SEL s1 = NSSelectorFromString(
                @"req_finish_YCH_get_show_sku_info_WithParams:res:");
            SEL s2 = NSSelectorFromString(
                @"req_finish_YCH_dito_prepare_page_init_WithParams:res:");
            ((void(*)(id,SEL,id,id))objc_msgSend)(helper, s1, params, res);
            ((void(*)(id,SEL,id,id))objc_msgSend)(helper, s2, params, res);
        } else {
            SEL sel = NSSelectorFromString(
                @"req_finish_YCH_product_info_WithParams:res:");
            ((void(*)(id,SEL,id,id))objc_msgSend)(helper, sel, params, res);
        }
    } @catch (NSException *e) {
        YCHLOG(@"req_finish exception: %@", e.reason);
    }
}

@end

static void setupNetworkHook(void) {
    Class DYYCHHelper = NSClassFromString(@"DYYCHHelper");
    if (!DYYCHHelper) { YCHLOG(@"DYYCHHelper not found"); return; }

    SEL orig = NSSelectorFromString(
        @"AWENetworkRequest_setCompletionBlock:method:params:res:err:netReq:");
    SEL hook = @selector(ych_netHook:method:params:res:err:netReq:);

    Method origMethod = class_getInstanceMethod(DYYCHHelper, orig);
    if (!origMethod) { YCHLOG(@"AWENetworkRequest method not found"); return; }

    // Add our hook method to DYYCHHelper, then swizzle
    Method hookMethod = class_getInstanceMethod([NSObject class], hook);
    if (!hookMethod) { YCHLOG(@"hook method not found"); return; }

    BOOL added = class_addMethod(DYYCHHelper, hook,
                                 method_getImplementation(hookMethod),
                                 method_getTypeEncoding(hookMethod));
    if (added) {
        swizzleInstanceMethod(DYYCHHelper, orig, hook);
        YCHLOG(@"network hook installed");
    } else {
        YCHLOG(@"failed to add hook method");
    }
}
