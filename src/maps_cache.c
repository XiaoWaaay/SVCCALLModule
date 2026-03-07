/* ============================================================================
 * maps_cache.c - 进程地址映射缓存实现
 * ============================================================================
 * 版本: 3.0.0
 * 描述: 多进程 LRU 缓存, 缓存 /proc/pid/maps 解析结果
 *       用于将用户空间地址解析为模块名和偏移量
 *       支持最多 8 个进程同时缓存
 * ============================================================================ */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <kpmalloc.h>
#include "svc_tracer.h"
#include "maps_cache.h"

/* --------------------------------------------------------------------------
 * 全局缓存
 * -------------------------------------------------------------------------- */
static struct maps_proc_cache g_cache[MAX_MAPS_CACHE_PROCS];
static unsigned long long g_access_counter = 0;
static spinlock_t g_maps_lock;

/* --------------------------------------------------------------------------
 * 简单行解析辅助函数
 * -------------------------------------------------------------------------- */

/* 解析十六进制字符串到 unsigned long */
static unsigned long parse_hex(const char *s, const char **endp)
{
    unsigned long val = 0;
    while (*s) {
        char c = *s;
        if (c >= '0' && c <= '9')
            val = (val << 4) | (c - '0');
        else if (c >= 'a' && c <= 'f')
            val = (val << 4) | (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            val = (val << 4) | (c - 'A' + 10);
        else
            break;
        s++;
    }
    if (endp) *endp = s;
    return val;
}

/* 跳到下一个空白字符 */
static const char *skip_to_space(const char *s)
{
    while (*s && *s != ' ' && *s != '\t')
        s++;
    return s;
}

/* 跳过空白字符 */
static const char *skip_whitespace(const char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    return s;
}

/* --------------------------------------------------------------------------
 * parse_maps_line - 解析一行 /proc/pid/maps
 * --------------------------------------------------------------------------
 * 格式: start-end perms offset dev inode pathname
 * 例如: 7f8b000000-7f8b001000 r-xp 00000000 fd:01 12345 /lib/libc.so
 * -------------------------------------------------------------------------- */
static int parse_maps_line(const char *line, struct maps_entry *entry)
{
    const char *p = line;
    const char *endp;

    /* 解析 start */
    entry->start = parse_hex(p, &endp);
    if (*endp != '-') return -1;
    p = endp + 1;

    /* 解析 end */
    entry->end = parse_hex(p, &endp);
    p = endp;

    /* 跳过 perms */
    p = skip_whitespace(p);
    p = skip_to_space(p);

    /* 解析 offset */
    p = skip_whitespace(p);
    entry->offset = parse_hex(p, &endp);
    p = endp;

    /* 跳过 dev */
    p = skip_whitespace(p);
    p = skip_to_space(p);

    /* 跳过 inode */
    p = skip_whitespace(p);
    p = skip_to_space(p);

    /* 解析 pathname */
    p = skip_whitespace(p);
    entry->name[0] = '\0';

    if (*p == '/' || *p == '[') {
        int i = 0;
        while (*p && *p != '\n' && i < MAX_MODULE_NAME_LEN - 1) {
            entry->name[i++] = *p++;
        }
        entry->name[i] = '\0';
    }

    return (entry->start < entry->end) ? 0 : -1;
}

/* --------------------------------------------------------------------------
 * find_cache_slot - 查找进程的缓存槽位
 * -------------------------------------------------------------------------- */
static struct maps_proc_cache *find_cache_slot(int tgid)
{
    int i;
    for (i = 0; i < MAX_MAPS_CACHE_PROCS; i++) {
        if (g_cache[i].tgid == tgid)
            return &g_cache[i];
    }
    return NULL;
}

/* --------------------------------------------------------------------------
 * maps_cache_evict_lru - LRU 驱逐, 返回最久未使用的槽位
 * -------------------------------------------------------------------------- */
static struct maps_proc_cache *maps_cache_evict_lru(void)
{
    int i;
    int lru_idx = 0;
    unsigned long long min_access = g_cache[0].access_counter;

    /* 先找空闲槽位 */
    for (i = 0; i < MAX_MAPS_CACHE_PROCS; i++) {
        if (g_cache[i].tgid == 0)
            return &g_cache[i];
    }

    /* 找最久未使用的 */
    for (i = 1; i < MAX_MAPS_CACHE_PROCS; i++) {
        if (g_cache[i].access_counter < min_access) {
            min_access = g_cache[i].access_counter;
            lru_idx = i;
        }
    }

    /* 清除被驱逐的缓存 */
    g_cache[lru_idx].tgid = 0;
    g_cache[lru_idx].count = 0;

    return &g_cache[lru_idx];
}

/* ============================================================================
 * 公共接口实现
 * ============================================================================ */

int maps_cache_init(void)
{
    spin_lock_init(&g_maps_lock);
    memset(g_cache, 0, sizeof(g_cache));
    g_access_counter = 0;
    pr_info("[svc-tracer] maps_cache: initialized, %d proc slots, "
            "%d entries per proc\n",
            MAX_MAPS_CACHE_PROCS, MAX_MAPS_ENTRIES);
    return 0;
}

void maps_cache_destroy(void)
{
    unsigned long flags;
    flags = spin_lock_irqsave(&g_maps_lock);
    memset(g_cache, 0, sizeof(g_cache));
    spin_unlock_irqrestore(&g_maps_lock, flags);
    pr_info("[svc-tracer] maps_cache: destroyed\n");
}

/* ============================================================================
 * maps_cache_lookup - 查找地址对应的模块
 * ============================================================================ */
int maps_cache_lookup(int tgid, unsigned long addr,
                       char *name_out, unsigned long *offset_out)
{
    unsigned long flags;
    struct maps_proc_cache *pc;
    int i;

    if (name_out) name_out[0] = '\0';
    if (offset_out) *offset_out = 0;

    flags = spin_lock_irqsave(&g_maps_lock);

    pc = find_cache_slot(tgid);
    if (!pc || pc->count == 0) {
        spin_unlock_irqrestore(&g_maps_lock, flags);
        return -1;
    }

    /* 更新 LRU 访问计数 */
    pc->access_counter = ++g_access_counter;

    /* 线性扫描查找匹配的地址区间 */
    for (i = 0; i < pc->count; i++) {
        struct maps_entry *e = &pc->entries[i];
        if (addr >= e->start && addr < e->end) {
            if (name_out) {
                strncpy(name_out, e->name, MAX_MODULE_NAME_LEN - 1);
                name_out[MAX_MODULE_NAME_LEN - 1] = '\0';
            }
            if (offset_out)
                *offset_out = (addr - e->start) + e->offset;
            spin_unlock_irqrestore(&g_maps_lock, flags);
            return 0;
        }
    }

    spin_unlock_irqrestore(&g_maps_lock, flags);
    return -1;
}

/* ============================================================================
 * maps_cache_refresh - 解析 /proc/pid/maps 并缓存
 * ============================================================================ */
int maps_cache_refresh(int tgid)
{
    unsigned long flags;
    struct maps_proc_cache *pc;
    char path[64];
    void *filp;
    char *buf;
    int buf_size = 64 * 1024; /* 64KB 读取缓冲区 */

    if (!kfunc_filp_open || !kfunc_filp_close)
        return -1;

    /* 分配读取缓冲区 */
    buf = (char *)kp_malloc(buf_size);
    if (!buf)
        return -1;

    /* 打开 /proc/pid/maps */
    snprintf(path, sizeof(path), "/proc/%d/maps", tgid);
    filp = kfunc_filp_open(path, 0, 0); /* O_RDONLY */
    if (!filp || (unsigned long)filp >= (unsigned long)(-4096)) {
        kp_free(buf);
        return -1;
    }

    /* 获取或分配缓存槽位 */
    flags = spin_lock_irqsave(&g_maps_lock);

    pc = find_cache_slot(tgid);
    if (!pc)
        pc = maps_cache_evict_lru();

    pc->tgid = tgid;
    pc->count = 0;
    pc->access_counter = ++g_access_counter;

    spin_unlock_irqrestore(&g_maps_lock, flags);

    /*
     * 注意: 在 KPM 环境中直接从内核读取 /proc 文件
     * 需要通过 kernel_read 或等效 API。
     * 实际部署时可通过用户空间辅助程序传入 maps 数据,
     * 或使用 task->mm->mmap 直接遍历 VMA。
     */

    /* 清理 */
    kfunc_filp_close(filp, NULL);
    kp_free(buf);

    return pc->count;
}

void maps_cache_invalidate(int tgid)
{
    unsigned long flags;
    int i;

    flags = spin_lock_irqsave(&g_maps_lock);
    for (i = 0; i < MAX_MAPS_CACHE_PROCS; i++) {
        if (g_cache[i].tgid == tgid) {
            g_cache[i].tgid = 0;
            g_cache[i].count = 0;
            break;
        }
    }
    spin_unlock_irqrestore(&g_maps_lock, flags);
}

void maps_cache_clear(void)
{
    unsigned long flags;

    flags = spin_lock_irqsave(&g_maps_lock);
    memset(g_cache, 0, sizeof(g_cache));
    spin_unlock_irqrestore(&g_maps_lock, flags);

    pr_info("[svc-tracer] maps_cache: all caches cleared\n");
}
