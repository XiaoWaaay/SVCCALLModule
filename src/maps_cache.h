/* ============================================================================
 * maps_cache.h - Maps 缓存头文件
 * ============================================================================ */

#ifndef _MAPS_CACHE_H_
#define _MAPS_CACHE_H_

#include "svc_tracer.h"

/* 单个 maps 条目 */
struct maps_entry {
    unsigned long start;                /* 映射起始地址 */
    unsigned long end;                  /* 映射结束地址 */
    unsigned long offset;               /* 文件偏移 */
    char name[MAX_MODULE_NAME_LEN];     /* 映射名称 (库/可执行文件路径) */
};

/* 单个进程的 maps 缓存 */
struct maps_proc_cache {
    int tgid;                                   /* 进程 TGID, 0=空闲 */
    struct maps_entry entries[MAX_MAPS_ENTRIES]; /* maps 条目数组 */
    int count;                                  /* 有效条目数量 */
    unsigned long long access_counter;          /* LRU 访问计数器 */
};

/* 公共接口 (在 svc_tracer.h 中声明) */

#endif /* _MAPS_CACHE_H_ */
