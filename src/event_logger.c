/* ============================================================================
 * event_logger.c - 环形事件缓冲区实现
 * ============================================================================
 * 版本: 3.0.0
 * 描述: 固定容量环形缓冲区, 存储捕获的 syscall 事件
 *       满时覆盖最旧的事件 (不丢弃新事件)
 *       使用 spinlock + irqsave 保护并发访问
 * ============================================================================ */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <kpmalloc.h>
#include "svc_tracer.h"

/* --------------------------------------------------------------------------
 * 环形缓冲区结构
 * -------------------------------------------------------------------------- */
static struct svc_event *g_buffer = NULL;   /* 事件数组 */
static int g_head = 0;                     /* 写入位置 (下一个写入的索引) */
static int g_tail = 0;                     /* 读取位置 (下一个读取的索引) */
static int g_count = 0;                    /* 当前缓冲区中事件数量 */
static unsigned long long g_total = 0;     /* 历史总写入数 */
static unsigned long long g_dropped = 0;   /* 丢弃数 (被覆盖的事件) */

/* spinlock 保护 */
static spinlock_t g_lock;

/* ============================================================================
 * event_logger_init - 初始化缓冲区
 * ============================================================================ */
int event_logger_init(void)
{
    unsigned long alloc_size = sizeof(struct svc_event) * EVENT_BUFFER_CAPACITY;

    g_buffer = (struct svc_event *)kp_malloc(alloc_size);
    if (!g_buffer) {
        pr_err("[svc-tracer] event_logger: failed to allocate %lu bytes\n",
               alloc_size);
        return -1;
    }

    memset(g_buffer, 0, alloc_size);
    spin_lock_init(&g_lock);

    g_head = 0;
    g_tail = 0;
    g_count = 0;
    g_total = 0;
    g_dropped = 0;

    pr_info("[svc-tracer] event_logger: initialized, capacity=%d, "
            "event_size=%lu, total=%lu bytes\n",
            EVENT_BUFFER_CAPACITY,
            (unsigned long)sizeof(struct svc_event), alloc_size);
    return 0;
}

/* ============================================================================
 * event_logger_destroy - 销毁缓冲区
 * ============================================================================ */
void event_logger_destroy(void)
{
    unsigned long flags;

    flags = spin_lock_irqsave(&g_lock);
    if (g_buffer) {
        kp_free(g_buffer);
        g_buffer = NULL;
    }
    g_head = 0;
    g_tail = 0;
    g_count = 0;
    spin_unlock_irqrestore(&g_lock, flags);

    pr_info("[svc-tracer] event_logger: destroyed, total=%llu, dropped=%llu\n",
            g_total, g_dropped);
}

/* ============================================================================
 * event_logger_write - 写入一个事件
 * ============================================================================
 * 满时覆盖最旧事件 (移动 tail)
 * 返回: 0 成功, -1 缓冲区未初始化
 * ============================================================================ */
int event_logger_write(const struct svc_event *event)
{
    unsigned long flags;

    if (!g_buffer || !event)
        return -1;

    flags = spin_lock_irqsave(&g_lock);

    /* 复制事件到 head 位置 */
    memcpy(&g_buffer[g_head], event, sizeof(struct svc_event));

    /* 前进 head */
    g_head = (g_head + 1) % EVENT_BUFFER_CAPACITY;

    if (g_count < EVENT_BUFFER_CAPACITY) {
        /* 未满: 增加计数 */
        g_count++;
    } else {
        /* 已满: tail 也前进 (覆盖最旧事件) */
        g_tail = (g_tail + 1) % EVENT_BUFFER_CAPACITY;
        g_dropped++;
    }

    g_total++;

    spin_unlock_irqrestore(&g_lock, flags);
    return 0;
}

/* ============================================================================
 * event_logger_read - 读取一个事件 (从 tail)
 * ============================================================================
 * 返回: 0 成功, -1 缓冲区空或未初始化
 * ============================================================================ */
int event_logger_read(struct svc_event *out)
{
    unsigned long flags;

    if (!g_buffer || !out)
        return -1;

    flags = spin_lock_irqsave(&g_lock);

    if (g_count == 0) {
        spin_unlock_irqrestore(&g_lock, flags);
        return -1;
    }

    memcpy(out, &g_buffer[g_tail], sizeof(struct svc_event));
    g_tail = (g_tail + 1) % EVENT_BUFFER_CAPACITY;
    g_count--;

    spin_unlock_irqrestore(&g_lock, flags);
    return 0;
}

/* ============================================================================
 * event_logger_read_batch - 批量读取事件
 * ============================================================================
 * 返回: 实际读取的事件数量
 * ============================================================================ */
int event_logger_read_batch(struct svc_event *out, int max_count)
{
    unsigned long flags;
    int read_count = 0;

    if (!g_buffer || !out || max_count <= 0)
        return 0;

    flags = spin_lock_irqsave(&g_lock);

    while (read_count < max_count && g_count > 0) {
        memcpy(&out[read_count], &g_buffer[g_tail], sizeof(struct svc_event));
        g_tail = (g_tail + 1) % EVENT_BUFFER_CAPACITY;
        g_count--;
        read_count++;
    }

    spin_unlock_irqrestore(&g_lock, flags);
    return read_count;
}

/* ============================================================================
 * event_logger_clear - 清空缓冲区
 * ============================================================================ */
void event_logger_clear(void)
{
    unsigned long flags;

    flags = spin_lock_irqsave(&g_lock);
    g_head = 0;
    g_tail = 0;
    g_count = 0;
    spin_unlock_irqrestore(&g_lock, flags);

    pr_info("[svc-tracer] event_logger: cleared\n");
}

/* ============================================================================
 * 查询接口
 * ============================================================================ */

int event_logger_pending(void)
{
    return g_count;
}

unsigned long long event_logger_dropped(void)
{
    return g_dropped;
}

void event_logger_get_stats(int *pending, unsigned long long *total,
                            unsigned long long *dropped)
{
    unsigned long flags;

    flags = spin_lock_irqsave(&g_lock);
    if (pending)  *pending  = g_count;
    if (total)    *total    = g_total;
    if (dropped)  *dropped  = g_dropped;
    spin_unlock_irqrestore(&g_lock, flags);
}
