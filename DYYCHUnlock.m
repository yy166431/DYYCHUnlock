/**
 * DYYCHUnlock.m v4 — v260525-22 兼容（多版本名字 fallback）
 *
 * 目标设备：iPhone 12 / iOS 14.8.1 / arm64（牛磺酸 + TrollStore）
 *
 * v4 改动：作者在 v260513-22 起对核心 helper 类做了类名混淆（selector 混淆
 *          种子在 v260513-22 与 v260525-22 之间复用），工具类/属性名仍明文。
 *          本版用「候选名表」解析类与 selector：先试新版混淆名，再回退旧版明文名，
 *          因此同一个 dylib 同时适配 v260512-21 / v260513-22 / v260525-22。
 *
 * 沿用 v3 的 iOS 16 安全做法（虽然当前目标是 iOS14，保持兼容）：
 *   - 全程 method_setImplementation，绝不 class_addMethod 加新 selector（PAC trap）
 *   - constructor 延迟 8s 等作者 AWESpriter _hooks 链跑完再装
 */

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

#pragma mark - Logging

#define YCHLOG(fmt, ...) NSLog(@"[YCHUnlock] " fmt, ##__VA_ARGS__)

#pragma mark - 多版本名字解析

// 候选类名：新混淆名在前，旧明文名兜底
static Class resolveClass(NSArray<NSString *> *candidates) {
    for (NSString *name in candidates) {
        Class c = NSClassFromString(name);
        if (c) return c;
    }
    return nil;
}

// 候选 selector：返回目标类上第一个存在的 selector（含其 Method）
// isClassMethod=YES 查类方法，否则实例方法
static SEL resolveSelector(Class cls, NSArray<NSString *> *candidates,
                           BOOL isClassMethod, Method *outMethod) {
    for (NSString *name in candidates) {
        SEL s = NSSelectorFromString(name);
        Method m = isClassMethod ? class_getClassMethod(cls, s)
                                  : class_getInstanceMethod(cls, s);
        if (m) { if (outMethod) *outMethod = m; return s; }
    }
    if (outMethod) *outMethod = NULL;
    return NULL;
}

// gate 持有类（XBDLeanCloudHandler）—— v260525-22: potpiutoideidcs
static Class gateClass(void) {
    return resolveClass(@[ @"potpiutoideidcs", @"XBDLeanCloudHandler" ]);
}

// 演唱会 helper（DYYCHHelper）—— v260525-22: pytpiutoldeidcs
static Class ychHelperClass(void) {
    return resolveClass(@[ @"pytpiutoldeidcs", @"DYYCHHelper" ]);
}

// 网络 swizzle selector（AWENetworkRequest_setCompletionBlock:...）
static NSArray<NSString *> *netHookSelCandidates(void) {
    return @[ @"kxmnqplasdfghy:method:params:res:err:netReq:",
              @"AWENetworkRequest_setCompletionBlock:method:params:res:err:netReq:" ];
}

// req_finish 回调（参数均为 :params: :res: 两参）
static NSArray<NSString *> *reqProductInfoCandidates(void) {
    return @[ @"kxmnqplasdfghe:res:",
              @"req_finish_YCH_product_info_WithParams:res:" ];
}
static NSArray<NSString *> *reqSkuInfoCandidates(void) {
    return @[ @"plxmnzqwasdfgc:res:",
              @"req_finish_YCH_get_show_sku_info_WithParams:res:" ];
}
static NSArray<NSString *> *reqPrepareInitCandidates(void) {
    return @[ @"bvnzxqmplasdfgd:res:",
              @"req_finish_YCH_dito_prepare_page_init_WithParams:res:" ];
}

// 在目标类上对第一个存在的 selector 发 (params,res) 两参消息
static void callReqFinish(id helper, NSArray<NSString *> *candidates,
                          id params, id res) {
    Class cls = object_getClass(helper);
    Method m = NULL;
    SEL s = resolveSelector(cls, candidates, NO, &m);
    if (s) {
        ((void(*)(id,SEL,id,id))objc_msgSend)(helper, s, params, res);
    }
}

#pragma mark - Forward declarations

static void setupFakeWS(void);
static void setupGateUnlock(void);
static void setupAddBtnFix(void);
static void setupNetworkHook(void);

#pragma mark - Constructor

__attribute__((constructor))
static void DYYCHUnlock_init(void) {
    YCHLOG(@"init — v4.0 (v260525-22 compat, multi-version)");
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

    // wsUrl getter（旧版有；新版无 wsUrl 时 m==NULL，安全跳过）
    Method m = NULL;
    SEL wsUrlSel = resolveSelector(SRWSHelper, @[ @"wsUrl" ], NO, &m);
    if (wsUrlSel && m) {
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
    Class XBD = gateClass();
    if (!XBD) { YCHLOG(@"gate class not found"); return; }
    YCHLOG(@"gate class = %s", class_getName(XBD));

    id xbd = ((id(*)(id,SEL))objc_msgSend)((id)XBD,
                NSSelectorFromString(@"sharedInstance"));
    if (!xbd) { YCHLOG(@"gate sharedInstance nil"); return; }

    Ivar ivar = class_getInstanceVariable(XBD, "_open_dy_ych_show");
    if (ivar) {
        ptrdiff_t offset = ivar_getOffset(ivar);
        uint8_t *ptr = (uint8_t *)(__bridge void *)xbd + offset;
        *ptr = 1;
        YCHLOG(@"_open_dy_ych_show = 1 (offset %td)", offset);
    } else {
        // 走 setter 兜底（属性名 open_dy_ych_show 明文保留）
        SEL setSel = NSSelectorFromString(@"setOpen_dy_ych_show:");
        if ([xbd respondsToSelector:setSel]) {
            ((void(*)(id,SEL,BOOL))objc_msgSend)(xbd, setSel, YES);
            YCHLOG(@"_open_dy_ych_show = 1 (via setter)");
        } else {
            uint8_t *ptr = (uint8_t *)(__bridge void *)xbd + 9;
            *ptr = 1;
            YCHLOG(@"_open_dy_ych_show = 1 (hardcoded offset 9)");
        }
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

#pragma mark - 4. 网络 swizzle hook（method_setImplementation，不加新 selector）

static IMP orig_netReq_IMP = NULL;

static void hook_netReq(id self, SEL _cmd, id block, id method,
                        id params, id res, id err, id netReq) {
    // 先调作者原 IMP
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

    Class DYCH = ychHelperClass();
    if (!DYCH) return;
    id helper = ((id(*)(id,SEL))objc_msgSend)((id)DYCH,
                    NSSelectorFromString(@"sharedInstance"));
    if (!helper) return;

    @try {
        if (hasProductData) {
            callReqFinish(helper, reqProductInfoCandidates(), params, res);
        } else if (hasBuyLimit) {
            callReqFinish(helper, reqSkuInfoCandidates(),     params, res);
            callReqFinish(helper, reqPrepareInitCandidates(), params, res);
        } else {
            callReqFinish(helper, reqProductInfoCandidates(), params, res);
        }
    } @catch (NSException *e) {
        YCHLOG(@"req_finish exception: %@", e.reason);
    }
}

static void setupNetworkHook(void) {
    Class DYYCHHelper = ychHelperClass();
    if (!DYYCHHelper) { YCHLOG(@"YCH helper class not found"); return; }
    YCHLOG(@"YCH helper class = %s", class_getName(DYYCHHelper));

    Method m = NULL;
    SEL orig = resolveSelector(DYYCHHelper, netHookSelCandidates(), NO, &m);
    if (!orig || !m) { YCHLOG(@"network hook selector not found"); return; }

    orig_netReq_IMP = method_setImplementation(m, (IMP)hook_netReq);
    YCHLOG(@"network hook installed: %@ (setIMP)", NSStringFromSelector(orig));
}
