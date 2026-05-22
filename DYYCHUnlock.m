/**
 * DYYCHUnlock.m v3 — iOS 16 arm64e 兼容版
 *
 * 修复：hook #4 改用 method_setImplementation 避免往 DYYCHHelper 添加新 selector
 *       AWESpriter _hooks 枚举不到多余方法 → 不再 PAC trap
 *       延迟 8s 等 AWESpriter _hooks block 跑完再装
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
    YCHLOG(@"init — v3.0 (iOS16-compat)");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        YCHLOG(@"installing hooks (8s delay)...");
        setupGateUnlock();
        setupAddBtnFix();
        setupNetworkHook();
        setupFakeWS();
        YCHLOG(@"all hooks installed");
    });
}

#pragma mark - 1. Fake WS

static IMP orig_wsUrl_IMP = NULL;

static id hook_wsUrl(id self, SEL _cmd) {
    return @"ws://127.0.0.1:18888/dy";
}

static void setupFakeWS(void) {
    Class SRWSHelper = NSClassFromString(@"SRWebSocketHelper");
    if (!SRWSHelper) { YCHLOG(@"SRWebSocketHelper not found"); return; }

    SEL wsUrlSel = NSSelectorFromString(@"wsUrl");
    Method m = class_getInstanceMethod(SRWSHelper, wsUrlSel);
    if (m) {
        orig_wsUrl_IMP = method_setImplementation(m, (IMP)hook_wsUrl);
        YCHLOG(@"wsUrl hook installed");
    }

    id helper = ((id(*)(id,SEL))objc_msgSend)((id)SRWSHelper,
                    NSSelectorFromString(@"sharedInstance"));
    if (!helper) return;

    Class SRWebSocket = NSClassFromString(@"SRWebSocket");
    if (!SRWebSocket) return;

    NSURL *url = [NSURL URLWithString:@"ws://127.0.0.1:18888/dy"];
    id ws = ((id(*)(id,SEL))objc_msgSend)((id)SRWebSocket,
                NSSelectorFromString(@"alloc"));
    ws = ((id(*)(id,SEL,id))objc_msgSend)(ws,
                NSSelectorFromString(@"initWithURL:"), url);
    if (!ws) return;

    ((void(*)(id,SEL,id))objc_msgSend)(ws,
        NSSelectorFromString(@"setDelegate:"), helper);
    ((void(*)(id,SEL,id))objc_msgSend)(helper,
        NSSelectorFromString(@"setWebSocket:"), ws);

    Ivar readyStateIvar = class_getInstanceVariable(SRWebSocket, "_readyState");
    if (readyStateIvar) {
        ptrdiff_t off = ivar_getOffset(readyStateIvar);
        *((int *)((uint8_t *)(__bridge void *)ws + off)) = 1;
    }

    SEL rsSel = NSSelectorFromString(@"readyState");
    Method rsMethod = class_getInstanceMethod(SRWebSocket, rsSel);
    if (rsMethod) {
        method_setImplementation(rsMethod, imp_implementationWithBlock(^long(id s) {
            return 1;
        }));
    }
    YCHLOG(@"Fake WS ready");
}

#pragma mark - 2. Gate Unlock

static void setupGateUnlock(void) {
    Class XBD = NSClassFromString(@"XBDLeanCloudHandler");
    if (!XBD) { YCHLOG(@"XBDLeanCloudHandler not found"); return; }

    id xbd = ((id(*)(id,SEL))objc_msgSend)((id)XBD,
                NSSelectorFromString(@"sharedInstance"));
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

#pragma mark - 3. addBtn fix

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

#pragma mark - 4. AWENetworkRequest hook (method_setImplementation — no new selector added)

static IMP orig_netReq_IMP = NULL;

static void hook_netReq(id self, SEL _cmd, id block, id method,
                        id params, id res, id err, id netReq) {
    // Call original author IMP first
    ((void(*)(id,SEL,id,id,id,id,id,id))orig_netReq_IMP)(
        self, _cmd, block, method, params, res, err, netReq);

    if (!params || !res) return;
    if (![res isKindOfClass:[NSDictionary class]]) return;
    if (![params isKindOfClass:[NSDictionary class]]) return;

    NSDictionary *resDict = (NSDictionary *)res;
    NSDictionary *paramsDict = (NSDictionary *)params;

    BOOL hasProductId = (paramsDict[@"product_id"] != nil);
    BOOL hasBuyLimit = (resDict[@"buy_limit"] != nil);
    BOOL hasProductData = (resDict[@"ProductSerializationData"] != nil);

    if (!hasProductId && !hasBuyLimit && !hasProductData) return;

    Class DYCH = NSClassFromString(@"DYYCHHelper");
    id helper = ((id(*)(id,SEL))objc_msgSend)((id)DYCH,
                    NSSelectorFromString(@"sharedInstance"));
    if (!helper) return;

    @try {
        if (hasProductData) {
            SEL s = NSSelectorFromString(
                @"req_finish_YCH_product_info_WithParams:res:");
            ((void(*)(id,SEL,id,id))objc_msgSend)(helper, s, params, res);
        } else if (hasBuyLimit) {
            SEL s1 = NSSelectorFromString(
                @"req_finish_YCH_get_show_sku_info_WithParams:res:");
            SEL s2 = NSSelectorFromString(
                @"req_finish_YCH_dito_prepare_page_init_WithParams:res:");
            ((void(*)(id,SEL,id,id))objc_msgSend)(helper, s1, params, res);
            ((void(*)(id,SEL,id,id))objc_msgSend)(helper, s2, params, res);
        } else {
            SEL s = NSSelectorFromString(
                @"req_finish_YCH_product_info_WithParams:res:");
            ((void(*)(id,SEL,id,id))objc_msgSend)(helper, s, params, res);
        }
    } @catch (NSException *e) {
        YCHLOG(@"req_finish exception: %@", e.reason);
    }
}

static void setupNetworkHook(void) {
    Class DYYCHHelper = NSClassFromString(@"DYYCHHelper");
    if (!DYYCHHelper) { YCHLOG(@"DYYCHHelper not found"); return; }

    SEL orig = NSSelectorFromString(
        @"AWENetworkRequest_setCompletionBlock:method:params:res:err:netReq:");
    Method m = class_getInstanceMethod(DYYCHHelper, orig);
    if (!m) { YCHLOG(@"AWENetworkRequest method not found"); return; }

    orig_netReq_IMP = method_setImplementation(m, (IMP)hook_netReq);
    YCHLOG(@"network hook installed (setIMP, no new selector)");
}
