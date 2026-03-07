/* ============================================================================
 * pkg_resolver.h - 包名解析头文件
 * ============================================================================ */

#ifndef _PKG_RESOLVER_H_
#define _PKG_RESOLVER_H_

#include "svc_tracer.h"

/* 包名缓存条目 */
struct pkg_cache_entry {
    unsigned int uid;                   /* Android UID */
    char pkg_name[MAX_PKG_LEN];        /* 包名 */
    unsigned long long timestamp_ns;    /* 缓存时间戳 (纳秒) */
    int valid;                          /* 条目是否有效 */
};

/* 公共接口 (在 svc_tracer.h 中声明) */

#endif /* _PKG_RESOLVER_H_ */
