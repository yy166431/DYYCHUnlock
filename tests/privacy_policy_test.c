#include "../src/PrivacyPolicy.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    const char *blocked[] = {
        "106.53.173.140", "WHCUYCXU.LC-CN-N1-SHARED.COM.",
        "vv7izmce.lc-cn-n1-shared.com", "app-router.com", "x.lncld.net",
        "project.supabase.co", "api.day.app", "m1.apifoxmock.com", "api.bq04.com"
    };
    const char *allowed[] = {
        NULL, "", "api.amemv.com", "www.douyin.com", "tos.bytegecko.com",
        "supabase.co.attacker.invalid", "notsupabase.co", "api.day.app.invalid",
        "106.53.173.140.invalid", "www.apple.com", "example.invalid"
    };
    for (size_t i = 0; i < sizeof(blocked)/sizeof(blocked[0]); ++i) assert(DPSKnownHost(blocked[i]));
    for (size_t i = 0; i < sizeof(allowed)/sizeof(allowed[0]); ++i) assert(!DPSKnownHost(allowed[i]));
    puts("privacy domain boundary tests passed");
    return 0;
}
