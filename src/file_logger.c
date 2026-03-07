/* ============================================================================
 * file_logger.c - 文件日志实现
 * ============================================================================
 * 版本: 3.0.0
 * 描述: 将事件以 JSON Lines 格式写入文件
 *       支持文件大小轮转 (10MB)
 *       使用 spinlock 保护并发写入
 * ============================================================================ */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include "svc_tracer.h"
#include "file_logger.h"

/* --------------------------------------------------------------------------
 * 内部状态
 * -------------------------------------------------------------------------- */
static void *g_filp = NULL;            /* 文件指针 (struct file *) */
static long long g_file_pos = 0;       /* 当前写入位置 */
static long long g_file_size = 0;      /* 当前文件大小估算 */
static int g_enabled = 0;              /* 启用状态 */
static char g_path[MAX_PATH_LEN] = "/sdcard/Download/svc_tracer.log";
static spinlock_t g_flock;             /* 文件写入锁 */

/* --------------------------------------------------------------------------
 * open_log_file - 打开日志文件
 * -------------------------------------------------------------------------- */
static int open_log_file(void)
{
    if (!kfunc_filp_open)
        return -1;

    if (g_filp)
        return 0; /* 已打开 */

    /* O_WRONLY | O_CREAT | O_APPEND = 0x441 */
    g_filp = kfunc_filp_open(g_path, 0x441, 0644);
    if (!g_filp || (unsigned long)g_filp >= (unsigned long)(-4096)) {
        pr_err("[svc-tracer] file_logger: failed to open %s\n", g_path);
        g_filp = NULL;
        return -1;
    }

    g_file_pos = 0;
    g_file_size = 0;
    return 0;
}

/* --------------------------------------------------------------------------
 * close_log_file - 关闭日志文件
 * -------------------------------------------------------------------------- */
static void close_log_file(void)
{
    if (g_filp && kfunc_filp_close) {
        kfunc_filp_close(g_filp, NULL);
        g_filp = NULL;
    }
    g_file_pos = 0;
    g_file_size = 0;
}

/* --------------------------------------------------------------------------
 * rotate_if_needed - 检查并执行文件轮转
 * -------------------------------------------------------------------------- */
static void rotate_if_needed(void)
{
    if (g_file_size >= FILE_LOG_MAX_SIZE) {
        close_log_file();
        /*
         * 简单轮转: 关闭后以 O_TRUNC 重新打开
         * 生产环境可增加备份文件逻辑
         */
        if (kfunc_filp_open) {
            /* O_WRONLY | O_CREAT | O_TRUNC = 0x241 */
            g_filp = kfunc_filp_open(g_path, 0x241, 0644);
            if (!g_filp || (unsigned long)g_filp >= (unsigned long)(-4096)) {
                g_filp = NULL;
                pr_warn("[svc-tracer] file_logger: rotate failed\n");
                return;
            }
        }
        g_file_pos = 0;
        g_file_size = 0;
        pr_info("[svc-tracer] file_logger: rotated\n");
    }
}

/* ============================================================================
 * 公共接口实现
 * ============================================================================ */

int file_logger_init(void)
{
    spin_lock_init(&g_flock);
    g_filp = NULL;
    g_file_pos = 0;
    g_file_size = 0;
    g_enabled = 0;

    pr_info("[svc-tracer] file_logger: initialized, path=%s\n", g_path);
    return 0;
}

void file_logger_close(void)
{
    unsigned long flags;

    flags = spin_lock_irqsave(&g_flock);
    g_enabled = 0;
    close_log_file();
    spin_unlock_irqrestore(&g_flock, flags);

    pr_info("[svc-tracer] file_logger: closed\n");
}

void file_logger_enable(void)
{
    unsigned long flags;

    flags = spin_lock_irqsave(&g_flock);
    if (!g_filp) {
        if (open_log_file() != 0) {
            spin_unlock_irqrestore(&g_flock, flags);
            pr_err("[svc-tracer] file_logger: enable failed\n");
            return;
        }
    }
    g_enabled = 1;
    spin_unlock_irqrestore(&g_flock, flags);

    pr_info("[svc-tracer] file_logger: enabled\n");
}

void file_logger_disable(void)
{
    unsigned long flags;

    flags = spin_lock_irqsave(&g_flock);
    g_enabled = 0;
    spin_unlock_irqrestore(&g_flock, flags);

    pr_info("[svc-tracer] file_logger: disabled\n");
}

/* ============================================================================
 * file_logger_write_event - 将事件以 JSON Line 格式写入文件
 * ============================================================================ */
int file_logger_write_event(const struct svc_event *event)
{
    unsigned long flags;
    char line[1024];
    int len;
    long written;

    if (!g_enabled || !g_filp || !event)
        return -1;

    if (!kfunc_kernel_write)
        return -1;

    /* 格式化为 JSON Line */
    len = snprintf(line, sizeof(line),
        "{\"ts\":%llu,\"pid\":%d,\"tid\":%d,\"uid\":%u,"
        "\"comm\":\"%s\",\"nr\":%d,\"name\":\"%s\","
        "\"ret\":%ld,\"cat\":%d,\"antidebug\":%d,"
        "\"pc\":\"0x%lx\",\"lr\":\"0x%lx\","
        "\"module\":\"%s\",\"offset\":\"0x%lx\","
        "\"detail\":\"%s\"}\n",
        event->timestamp_ns, event->pid, event->tid, event->uid,
        event->comm, event->syscall_nr,
        get_syscall_name(event->syscall_nr),
        event->retval, event->category, event->is_antidebug,
        event->caller_pc, event->caller_lr,
        event->caller_module, event->caller_offset,
        event->detail);

    if (len <= 0 || len >= (int)sizeof(line))
        return -1;

    flags = spin_lock_irqsave(&g_flock);

    if (!g_filp || !g_enabled) {
        spin_unlock_irqrestore(&g_flock, flags);
        return -1;
    }

    /* 轮转检查 */
    rotate_if_needed();

    if (!g_filp) {
        spin_unlock_irqrestore(&g_flock, flags);
        return -1;
    }

    /* 写入文件 */
    written = kfunc_kernel_write(g_filp, line, len, &g_file_pos);

    if (written > 0) {
        g_file_size += written;
    }

    spin_unlock_irqrestore(&g_flock, flags);

    return (written > 0) ? 0 : -1;
}

int file_logger_set_path(const char *path)
{
    unsigned long flags;

    if (!path || strlen(path) == 0 || strlen(path) >= MAX_PATH_LEN)
        return -1;

    flags = spin_lock_irqsave(&g_flock);

    /* 关闭当前文件 */
    close_log_file();

    /* 设置新路径 */
    memset(g_path, 0, MAX_PATH_LEN);
    strncpy(g_path, path, MAX_PATH_LEN - 1);

    /* 如果已启用, 重新打开 */
    if (g_enabled) {
        open_log_file();
    }

    spin_unlock_irqrestore(&g_flock, flags);

    pr_info("[svc-tracer] file_logger: path set to %s\n", g_path);
    return 0;
}

int file_logger_truncate(void)
{
    unsigned long flags;

    flags = spin_lock_irqsave(&g_flock);

    close_log_file();

    /* 以 O_TRUNC 重新打开 */
    if (kfunc_filp_open) {
        g_filp = kfunc_filp_open(g_path, 0x241, 0644);
        if (!g_filp || (unsigned long)g_filp >= (unsigned long)(-4096)) {
            g_filp = NULL;
            spin_unlock_irqrestore(&g_flock, flags);
            return -1;
        }
    }
    g_file_pos = 0;
    g_file_size = 0;

    spin_unlock_irqrestore(&g_flock, flags);

    pr_info("[svc-tracer] file_logger: truncated\n");
    return 0;
}

void file_logger_flush(void)
{
    /* 内核文件写入通常不需要显式 flush */
    /* 预留接口用于未来扩展 */
}
