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

// Path-level allowlist. These endpoints stay reachable even when their host is
// otherwise blocked, because a core (non-telemetry) feature depends on them.
// Server time sync (/wx/get_time) drives order-grab timing; blocking it forces a
// local-clock fallback that drifts and misses orders. Matched case-insensitively
// against the URL path only, query string excluded.
static bool DPSPathEquals(const char *a, const char *b) {
    if (!a || !b) return false;
    size_t i = 0;
    for (; a[i] && b[i]; ++i)
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return false;
    return a[i] == b[i];
}

static bool DPSAllowedPath(const char *path) {
    if (!path) return false;
    static const char *paths[] = {
        "/wx/get_time"
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i)
        if (DPSPathEquals(path, paths[i])) return true;
    return false;
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
