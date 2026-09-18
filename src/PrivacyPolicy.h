#ifndef DYYY_PRIVACY_POLICY_H
#define DYYY_PRIVACY_POLICY_H
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>

static bool DPSHostIs(const char *host, const char *domain) {
    if (!host || !domain) return false;
    size_t h = strlen(host), d = strlen(domain);
    while (h && host[h - 1] == '.') --h;
    if (h < d) return false;
    for (size_t i = 0; i < d; ++i)
        if (tolower((unsigned char)host[h - d + i]) != tolower((unsigned char)domain[i])) return false;
    return h == d || host[h - d - 1] == '.';
}

static bool DPSKnownHost(const char *host) {
    static const char *domains[] = {
        "106.53.173.140", "lncldapi.com", "lncldglobal.com", "lncld.net",
        "avoscloud.com", "leancloud.cn", "lc-cn-n1-shared.com",
        "app-router.com", "supabase.co", "supabase.in", "api.day.app",
        "m1.apifoxmock.com", "api.bq04.com"
    };
    for (size_t i = 0; i < sizeof(domains) / sizeof(domains[0]); ++i)
        if (DPSHostIs(host, domains[i])) return true;
    return false;
}

#endif
