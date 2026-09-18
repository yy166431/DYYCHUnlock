// Compatibility behavior retained from the supplied working v8 hook.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <mach-o/loader.h>
#include <string.h>

static dispatch_source_t gPinTimer;
static volatile uint8_t *gStatus;
static volatile uint8_t *gSuper;

static BOOL DYUMatchesImage(const void *base) {
    if (!base) return NO;
    const struct mach_header_64 *header = base;
    if (header->magic != MH_MAGIC_64) return NO;
    static const uint8_t expected[16] = {
        0x79,0xae,0x6b,0x44,0x7f,0xe2,0x3c,0x31,
        0x97,0x65,0x09,0xed,0x0c,0x83,0xc2,0x98
    };
    const uint8_t *p = (const uint8_t *)base + sizeof(*header);
    const uint8_t *end = p + header->sizeofcmds;
    for (uint32_t i = 0; i < header->ncmds && p + sizeof(struct load_command) <= end; ++i) {
        const struct load_command *lc = (const void *)p;
        if (lc->cmdsize < sizeof(*lc) || p + lc->cmdsize > end) return NO;
        if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command))
            return !memcmp(((const struct uuid_command *)lc)->uuid,expected,16);
        p += lc->cmdsize;
    }
    return NO;
}

static void DYUStart(void) {
    Class gate = objc_getClass("potpiutoideidcs");
    Method shared = class_getClassMethod(gate,sel_registerName("sharedInstance"));
    Dl_info info = {0};
    if (!shared || !dladdr((void *)method_getImplementation(shared),&info) ||
        !DYUMatchesImage(info.dli_fbase)) {
        NSLog(@"[DYYCHUnlock] unsupported plugin build; compatibility hooks skipped");
        return;
    }
    gStatus = (volatile uint8_t *)((uintptr_t)info.dli_fbase + 0x18629b8);
    gSuper = (volatile uint8_t *)((uintptr_t)info.dli_fbase + 0x18629bb);
    gPinTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,
                                      dispatch_get_global_queue(QOS_CLASS_UTILITY,0));
    dispatch_source_set_timer(gPinTimer,DISPATCH_TIME_NOW,NSEC_PER_SEC/10,NSEC_PER_SEC*3/100);
    dispatch_source_set_event_handler(gPinTimer, ^{ *gStatus = 1; *gSuper = 1; });
    dispatch_resume(gPinTimer);
}

static void DYUOpen(void) {
    if (!gStatus) return;
    Class gate = objc_getClass("potpiutoideidcs");
    id instance = ((id(*)(id,SEL))objc_msgSend)(gate,sel_registerName("sharedInstance"));
    SEL selector = sel_registerName("setOpen_dy_ych_show:");
    if ([instance respondsToSelector:selector])
        ((void(*)(id,SEL,BOOL))objc_msgSend)(instance,selector,YES);
    else {
        Ivar ivar = class_getInstanceVariable(gate,"_open_dy_ych_show");
        if (ivar && instance) *((uint8_t *)(__bridge void *)instance + ivar_getOffset(ivar)) = 1;
    }
    Class action = objc_getClass("pytpiutoideidcq");
    selector = sel_registerName("dasjhdhasjdhk");
    if ([action respondsToSelector:selector]) ((void(*)(id,SEL))objc_msgSend)(action,selector);
}

__attribute__((constructor)) static void DYUInitialize(void) {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,NSEC_PER_SEC),dispatch_get_main_queue(),^{ DYUStart(); });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,9*NSEC_PER_SEC),dispatch_get_main_queue(),^{ DYUOpen(); });
    }
}
