/* ============================================================================
 * pkg_resolver.c - Android 包名解析实现
 * ============================================================================
 * 版本: 3.0.0
 * 描述: UID 与 Android 包名之间的双向解析
 *       - 带 TTL 的缓存 (64条目, 60秒过期)
 *       - 通过读取 /data/system/packages.list 解析
 *       - Android UID 规则: app UID = 10000 + app_id
 * ============================================================================ */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <kpmalloc.h>
#include "svc_tracer.h"
#include "pkg_resolver.h"

/* --------------------------------------------------------------------------
 * 包名缓存
 * -------------------------------------------------------------------------- */
static struct pkg_cache_entry g_pkg_cache[MAX_PKG_CACHE];
static spinlock_t g_pkg_lock;

/* Android packages.list 路径 */
#define PACKAGES_LIST_PATH "/data/system/packages.list"

/* --------------------------------------------------------------------------
 * cache_find_by_uid - 通过 UID 查找缓存
 * -------------------------------------------------------------------------- */
static struct pkg_cache_entry *cache_find_by_uid(unsigned int uid)
{
    int i;
    unsigned long long now = 0;

    if (kfunc_ktime_get_ns)
        now = kfunc_ktime_get_ns();

    for (i = 0; i < MAX_PKG_CACHE; i++) {
        if (g_pkg_cache[i].valid && g_pkg_cache[i].uid == uid) {
            /* 检查 TTL */
            if (now > 0 && g_pkg_cache[i].timestamp_ns > 0 &&
                (now - g_pkg_cache[i].timestamp_ns) > PKG_CACHE_TTL_NS) {
                /* 过期, 标记无效 */
                g_pkg_cache[i].valid = 0;
                return NULL;
            }
            return &g_pkg_cache[i];
        }
    }
    return NULL;
}

/* --------------------------------------------------------------------------
 * cache_find_by_pkg - 通过包名查找缓存
 * -------------------------------------------------------------------------- */
static struct pkg_cache_entry *cache_find_by_pkg(const char *pkg)
{
    int i;
    unsigned long long now = 0;

    if (kfunc_ktime_get_ns)
        now = kfunc_ktime_get_ns();

    for (i = 0; i < MAX_PKG_CACHE; i++) {
        if (g_pkg_cache[i].valid &&
            strncmp(g_pkg_cache[i].pkg_name, pkg, MAX_PKG_LEN) == 0) {
            if (now > 0 && g_pkg_cache[i].timestamp_ns > 0 &&
                (now - g_pkg_cache[i].timestamp_ns) > PKG_CACHE_TTL_NS) {
                g_pkg_cache[i].valid = 0;
                return NULL;
            }
            return &g_pkg_cache[i];
        }
    }
    return NULL;
}

/* --------------------------------------------------------------------------
 * cache_insert - 插入缓存条目
 * -------------------------------------------------------------------------- */
static void cache_insert(unsigned int uid, const char *pkg)
{
    int i;
    int oldest_idx = 0;
    unsigned long long oldest_ts = 0xFFFFFFFFFFFFFFFFull;

    /* 查找空闲或最旧的条目 */
    for (i = 0; i < MAX_PKG_CACHE; i++) {
        if (!g_pkg_cache[i].valid) {
            oldest_idx = i;
            break;
        }
        if (g_pkg_cache[i].timestamp_ns < oldest_ts) {
            oldest_ts = g_pkg_cache[i].timestamp_ns;
            oldest_idx = i;
        }
    }

    g_pkg_cache[oldest_idx].uid = uid;
    strncpy(g_pkg_cache[oldest_idx].pkg_name, pkg, MAX_PKG_LEN - 1);
    g_pkg_cache[oldest_idx].pkg_name[MAX_PKG_LEN - 1] = '\0';
    g_pkg_cache[oldest_idx].valid = 1;

    if (kfunc_ktime_get_ns)
        g_pkg_cache[oldest_idx].timestamp_ns = kfunc_ktime_get_ns();
}

/* --------------------------------------------------------------------------
 * parse_packages_for_uid - 从 packages.list 查找 UID 对应的包名
 * --------------------------------------------------------------------------
 * 格式: package_name uid debug_flag data_dir ...
 * 例如: com.example.app 10123 0 /data/user/0/com.example.app ...
 * -------------------------------------------------------------------------- */
static int parse_packages_for_uid(unsigned int target_uid,
                                   char *pkg_out, int pkg_len)
{
    void *filp;
    char *buf;
    int buf_size = 32 * 1024;
    int found = 0;

    if (!kfunc_filp_open || !kfunc_filp_close)
        return -1;

    buf = (char *)kp_malloc(buf_size);
    if (!buf) return -1;

    filp = kfunc_filp_open(PACKAGES_LIST_PATH, 0, 0);
    if (!filp || (unsigned long)filp >= (unsigned long)(-4096)) {
        kp_free(buf);
        return -1;
    }

    /*
     * 注意: 从内核读取文件内容需要 kernel_read
     * 在 KPM 环境中, 使用已解析的符号或用户空间辅助
     * 简化: 此处提供框架, 实际部署需完善文件读取逻辑
     */

    kfunc_filp_close(filp, NULL);
    kp_free(buf);

    return found ? 0 : -1;
}

/* --------------------------------------------------------------------------
 * parse_packages_for_pkg - 从 packages.list 查找包名对应的 UID
 * -------------------------------------------------------------------------- */
static int parse_packages_for_pkg(const char *target_pkg)
{
    void *filp;
    char *buf;
    int buf_size = 32 * 1024;
    int uid = -1;

    if (!kfunc_filp_open || !kfunc_filp_close)
        return -1;

    buf = (char *)kp_malloc(buf_size);
    if (!buf) return -1;

    filp = kfunc_filp_open(PACKAGES_LIST_PATH, 0, 0);
    if (!filp || (unsigned long)filp >= (unsigned long)(-4096)) {
        kp_free(buf);
        return -1;
    }

    /* 简化: 从文件中查找包名对应行并解析 UID */

    kfunc_filp_close(filp, NULL);
    kp_free(buf);

    return uid;
}

/* ============================================================================
 * 公共接口实现
 * ============================================================================ */

int pkg_resolver_init(void)
{
    spin_lock_init(&g_pkg_lock);
    memset(g_pkg_cache, 0, sizeof(g_pkg_cache));
    pr_info("[svc-tracer] pkg_resolver: initialized, cache=%d, ttl=%llus\n",
            MAX_PKG_CACHE, PKG_CACHE_TTL_NS / 1000000000ULL);
    return 0;
}

int pkg_resolve_uid_to_pkg(unsigned int uid, char *pkg_out, int pkg_len)
{
    unsigned long flags;
    struct pkg_cache_entry *entry;

    if (!pkg_out || pkg_len <= 0)
        return -1;

    pkg_out[0] = '\0';

    flags = spin_lock_irqsave(&g_pkg_lock);

    /* 先查缓存 */
    entry = cache_find_by_uid(uid);
    if (entry) {
        strncpy(pkg_out, entry->pkg_name, pkg_len - 1);
        pkg_out[pkg_len - 1] = '\0';
        spin_unlock_irqrestore(&g_pkg_lock, flags);
        return 0;
    }

    spin_unlock_irqrestore(&g_pkg_lock, flags);

    /* 缓存未命中, 从文件解析 */
    if (parse_packages_for_uid(uid, pkg_out, pkg_len) == 0) {
        /* 插入缓存 */
        flags = spin_lock_irqsave(&g_pkg_lock);
        cache_insert(uid, pkg_out);
        spin_unlock_irqrestore(&g_pkg_lock, flags);
        return 0;
    }

    return -1;
}

int pkg_resolve_pkg_to_uid(const char *pkg_name)
{
    unsigned long flags;
    struct pkg_cache_entry *entry;
    int uid;

    if (!pkg_name || strlen(pkg_name) == 0)
        return -1;

    flags = spin_lock_irqsave(&g_pkg_lock);

    /* 先查缓存 */
    entry = cache_find_by_pkg(pkg_name);
    if (entry) {
        uid = entry->uid;
        spin_unlock_irqrestore(&g_pkg_lock, flags);
        return uid;
    }

    spin_unlock_irqrestore(&g_pkg_lock, flags);

    /* 缓存未命中, 从文件解析 */
    uid = parse_packages_for_pkg(pkg_name);
    if (uid >= 0) {
        flags = spin_lock_irqsave(&g_pkg_lock);
        cache_insert((unsigned int)uid, pkg_name);
        spin_unlock_irqrestore(&g_pkg_lock, flags);
    }

    return uid;
}
