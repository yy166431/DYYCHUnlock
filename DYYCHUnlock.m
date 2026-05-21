/**
 * DYYCHUnlock.m — 抖音演唱会助手全功能解锁 dylib
 *
 * 通过 TrollFools 注入抖音，实现：
 * 1. Fake WS（hook SRWebSocket，本地回 heartbeat_ack，无需 PC）
 * 2. Gate 解锁（_open_dy_ych_show = 1）
 * 3. addBtn fix（补 addSubview）
 * 4. AWENetworkRequest hook → 触发 req_finish 建演唱会菜单
 *
 * 编译：GitHub Actions (macOS-14 + xcrun iphoneos clang arm64)
 * 注入名：libDYYCHUnlock.dylib
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
    YCHLOG(@"init — v1.0");

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        setupFakeWS();
        setupGateUnlock();
        setupAddBtnFix();
        setupNetworkHook();
        YCHLOG(@"all hooks installed");
    });
}

#pragma mark - Swizzle Helpers

static void swizzleInstanceMethod(Class cls, SEL orig, SEL replacement) {
    Method origMethod = class_getInstanceMethod(cls, orig);
    Method replMethod = class_getInstanceMethod(cls, replacement);
    if (origMethod && replMethod) {
        method_exchangeImplementations(origMethod, replMethod);
    }
}

static void swizzleClassMethod(Class cls, SEL orig, SEL replacement) {
    Class meta = object_getClass(cls);
    Method origMethod = class_getInstanceMethod(meta, orig);
    Method replMethod = class_getInstanceMethod(meta, replacement);
    if (origMethod && replMethod) {
        method_exchangeImplementations(origMethod, replMethod);
    }
}

#pragma mark - 1. Fake WS (hook SRWebSocket)

@interface NSObject (YCHFakeWS)
- (void)ych_open;
- (void)ych_send:(id)msg;
@end

@implementation NSObject (YCHFakeWS)

- (void)ych_open {
    YCHLOG(@"SRWebSocket.open intercepted — faking didOpen");
    // Call original (connects to localhost, will fail — that's fine)
    // Don't call original, just fake the delegate callback
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        SEL delegateSel = NSSelectorFromString(@"delegate");
        id delegate = ((id(*)(id,SEL))objc_msgSend)(self, delegateSel);
        if (delegate) {
            SEL didOpen = NSSelectorFromString(@"webSocket:didOpen:");
            if ([delegate respondsToSelector:didOpen]) {
                ((void(*)(id,SEL,id,id))objc_msgSend)(delegate, didOpen, self, nil);
                YCHLOG(@"  → didOpen fired");
            }
        }
    });
}

- (void)ych_send:(id)msg {
    YCHLOG(@"SRWebSocket.send intercepted");
    // Parse message, reply with ack
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        SEL delegateSel = NSSelectorFromString(@"delegate");
        id delegate = ((id(*)(id,SEL))objc_msgSend)(self, delegateSel);
        if (!delegate) return;

        // Build heartbeat_ack response
        NSString *msgStr = nil;
        if ([msg isKindOfClass:[NSString class]]) {
            msgStr = msg;
        }

        NSString *reply = nil;
        if (msgStr && [msgStr containsString:@"heartbeat"]) {
            reply = @"{\"action\":\"heartbeat_ack\",\"data\":{}}";
        } else {
            reply = @"{\"action\":\"ack\",\"data\":{\"status\":1}}";
        }

        SEL didRecv = NSSelectorFromString(@"webSocket:didReceiveMessage:");
        if ([delegate respondsToSelector:didRecv]) {
            ((void(*)(id,SEL,id,id))objc_msgSend)(delegate, didRecv, self, reply);
        }
    });
}

@end

static void setupFakeWS(void) {
    Class SRWebSocket = NSClassFromString(@"SRWebSocket");
    if (!SRWebSocket) { YCHLOG(@"SRWebSocket not found"); return; }

    swizzleInstanceMethod(SRWebSocket,
                          NSSelectorFromString(@"open"),
                          @selector(ych_open));
    swizzleInstanceMethod(SRWebSocket,
                          NSSelectorFromString(@"send:"),
                          @selector(ych_send:));
    YCHLOG(@"Fake WS installed");
}

#pragma mark - 2. Gate Unlock (_open_dy_ych_show = 1)

static void setupGateUnlock(void) {
    Class XBD = NSClassFromString(@"XBDLeanCloudHandler");
    if (!XBD) { YCHLOG(@"XBDLeanCloudHandler not found"); return; }

    SEL sharedSel = NSSelectorFromString(@"sharedInstance");
    id xbd = ((id(*)(id,SEL))objc_msgSend)((id)XBD, sharedSel);
    if (!xbd) { YCHLOG(@"XBD sharedInstance nil"); return; }

    // ivar _open_dy_ych_show at offset 9, type BOOL (uint8_t)
    Ivar ivar = class_getInstanceVariable(XBD, "_open_dy_ych_show");
    if (ivar) {
        ptrdiff_t offset = ivar_getOffset(ivar);
        uint8_t *ptr = (uint8_t *)(__bridge void *)xbd + offset;
        *ptr = 1;
        YCHLOG(@"_open_dy_ych_show = 1 (offset %td)", offset);
    } else {
        // Fallback: try offset 9 directly
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
        SEL addSub = NSSelectorFromString(@"addSubview:");
        ((void(*)(id,SEL,id))objc_msgSend)(view, addSub, btn);
    }
    return btn;
}

static void setupAddBtnFix(void) {
    Class WCTools = NSClassFromString(@"WCTools");
    if (!WCTools) { YCHLOG(@"WCTools not found"); return; }

    SEL sel = NSSelectorFromString(@"addBtnWithView:text:frame:CallBack:");
    Method m = class_getClassMethod(WCTools, sel);
    if (!m) { YCHLOG(@"addBtnWithView method not found"); return; }

    orig_addBtnWithView_IMP = method_getImplementation(m);
    method_setImplementation(m, (IMP)hook_addBtnWithView);
    YCHLOG(@"addBtn fix installed");
}

#pragma mark - 4. AWENetworkRequest hook → trigger req_finish

@interface NSObject (YCHNetHook)
- (void)ych_AWENetworkRequest_setCompletionBlock:(id)block
                                          method:(id)method
                                          params:(id)params
                                             res:(id)res
                                             err:(id)err
                                          netReq:(id)netReq;
@end

@implementation NSObject (YCHNetHook)

- (void)ych_AWENetworkRequest_setCompletionBlock:(id)block
                                          method:(id)method
                                          params:(id)params
                                             res:(id)res
                                             err:(id)err
                                          netReq:(id)netReq {
    // Call original first
    [self ych_AWENetworkRequest_setCompletionBlock:block
                                           method:method
                                           params:params
                                              res:res
                                              err:err
                                           netReq:netReq];

    // Check if this is a YCH-related response
    if (!params || !res) return;
    if (![res isKindOfClass:[NSDictionary class]]) return;
    NSDictionary *resDict = (NSDictionary *)res;
    NSDictionary *paramsDict = nil;
    if ([params isKindOfClass:[NSDictionary class]]) {
        paramsDict = (NSDictionary *)params;
    }

    BOOL hasProductId = paramsDict && paramsDict[@"product_id"] != nil;
    BOOL hasBuyLimit = resDict[@"buy_limit"] != nil;
    BOOL hasProductData = resDict[@"ProductSerializationData"] != nil;

    if (!hasProductId && !hasBuyLimit && !hasProductData) return;

    Class DYYCHHelper = NSClassFromString(@"DYYCHHelper");
    SEL sharedSel = NSSelectorFromString(@"sharedInstance");
    id helper = ((id(*)(id,SEL))objc_msgSend)((id)DYYCHHelper, sharedSel);
    if (!helper) return;

    if (hasProductData) {
        SEL sel = NSSelectorFromString(@"req_finish_YCH_product_info_WithParams:res:");
        ((void(*)(id,SEL,id,id))objc_msgSend)(helper, sel, params, res);
        YCHLOG(@"→ product_info triggered");
    } else if (hasBuyLimit) {
        SEL selSku = NSSelectorFromString(@"req_finish_YCH_get_show_sku_info_WithParams:res:");
        ((void(*)(id,SEL,id,id))objc_msgSend)(helper, selSku, params, res);
        SEL selDito = NSSelectorFromString(@"req_finish_YCH_dito_prepare_page_init_WithParams:res:");
        ((void(*)(id,SEL,id,id))objc_msgSend)(helper, selDito, params, res);
        YCHLOG(@"→ sku_info + dito_prepare triggered");
    } else if (hasProductId) {
        SEL sel = NSSelectorFromString(@"req_finish_YCH_product_info_WithParams:res:");
        ((void(*)(id,SEL,id,id))objc_msgSend)(helper, sel, params, res);
        YCHLOG(@"→ product_info (generic) triggered");
    }
}

@end

static void setupNetworkHook(void) {
    Class DYYCHHelper = NSClassFromString(@"DYYCHHelper");
    if (!DYYCHHelper) { YCHLOG(@"DYYCHHelper not found"); return; }

    SEL orig = NSSelectorFromString(@"AWENetworkRequest_setCompletionBlock:method:params:res:err:netReq:");
    SEL hook = @selector(ych_AWENetworkRequest_setCompletionBlock:method:params:res:err:netReq:);

    Method origMethod = class_getInstanceMethod(DYYCHHelper, orig);
    if (!origMethod) { YCHLOG(@"AWENetworkRequest method not found"); return; }

    // Add our method to DYYCHHelper class, then swizzle
    Method hookMethod = class_getInstanceMethod([NSObject class], hook);
    BOOL added = class_addMethod(DYYCHHelper, hook,
                                 method_getImplementation(hookMethod),
                                 method_getTypeEncoding(hookMethod));
    if (added) {
        swizzleInstanceMethod(DYYCHHelper, orig, hook);
        YCHLOG(@"AWENetworkRequest hook installed");
    } else {
        YCHLOG(@"Failed to add hook method to DYYCHHelper");
    }
}
