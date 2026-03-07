/* ============================================================================
 * main.c - SVCModule KPM 入口文件
 * ============================================================================
 * 版本: 3.0.0
 * 描述: KPM 模块入口, 包含 init/control/exit 函数
 *       kpm_control0 提供完整的用户空间命令交互接口
 * ============================================================================ */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <kpmalloc.h>
#include "svc_tracer.h"

/* KPM 模块元信息 */
KPM_NAME("svc-tracer");
KPM_VERSION(SVC_TRACER_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("svc-tracer team");
KPM_DESCRIPTION("ARM64 syscall tracer with anti-debug detection for KernelPatch");

/* ---- 辅助宏: 安全 snprintf 到用户空间输出缓冲区 ---- */
#define OUT_MSG(fmt, ...) \
    do { \
        if (out_msg && outlen > 0) { \
            snprintf(out_msg, outlen, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

/* ---- 辅助函数: 字符串比较 ---- */
static int str_starts_with(const char *str, const char *prefix)
{
    int len = strlen(prefix);
    return (strncmp(str, prefix, len) == 0);
}

/* ---- 辅助函数: 跳过前导空格 ---- */
static const char *skip_spaces_local(const char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    return s;
}

/* ---- 辅助函数: 简单 atoi ---- */
static int simple_atoi(const char *s)
{
    int val = 0;
    int neg = 0;

    if (*s == '-') {
        neg = 1;
        s++;
    }
    while (*s >= '0' && *s <= '9') {
        val = val * 10 + (*s - '0');
        s++;
    }
    return neg ? -val : val;
}

/* ============================================================================
 * kpm_init - 模块初始化入口
 * ============================================================================
 * 由 KernelPatch 在加载模块时调用。
 * 参数: args - 用户提供的初始化参数字符串 (可为 NULL)
 * 返回: 0 成功, 负值失败
 * ============================================================================ */
static long kpm_init(const char *args, const char *__user reserved, void *__user outbuf)
{
    int ret;

    pr_info("[svc-tracer] initializing v%s\n", SVC_TRACER_VERSION);

    /* 1. 初始化符号解析器 (最先, 其他模块依赖内核符号) */
    ret = symbol_resolver_init();
    if (ret < 0) {
        pr_err("[svc-tracer] symbol_resolver_init failed: %d\n", ret);
        return ret;
    }

    /* 2. 初始化事件日志缓冲区 */
    ret = event_logger_init();
    if (ret < 0) {
        pr_err("[svc-tracer] event_logger_init failed: %d\n", ret);
        return ret;
    }

    /* 3. 初始化调用者解析器 */
    ret = caller_resolver_init();
    if (ret < 0) {
        pr_err("[svc-tracer] caller_resolver_init failed: %d\n", ret);
        goto fail_caller;
    }

    /* 4. 初始化 maps 缓存 */
    ret = maps_cache_init();
    if (ret < 0) {
        pr_err("[svc-tracer] maps_cache_init failed: %d\n", ret);
        goto fail_maps;
    }

    /* 5. 初始化包名解析器 */
    ret = pkg_resolver_init();
    if (ret < 0) {
        pr_err("[svc-tracer] pkg_resolver_init failed: %d\n", ret);
        goto fail_pkg;
    }

    /* 6. 初始化 syscall 监控器 (初始化默认配置) */
    ret = syscall_monitor_init();
    if (ret < 0) {
        pr_err("[svc-tracer] syscall_monitor_init failed: %d\n", ret);
        goto fail_monitor;
    }

    /* 7. 初始化 hook 引擎 (不安装 hook, 等待用户命令) */
    ret = hook_engine_init();
    if (ret < 0) {
        pr_err("[svc-tracer] hook_engine_init failed: %d\n", ret);
        goto fail_hook;
    }

    /* 8. 初始化文件日志 */
    ret = file_logger_init();
    if (ret < 0) {
        pr_err("[svc-tracer] file_logger_init failed (non-fatal): %d\n", ret);
        /* 文件日志失败不影响核心功能 */
    }

    /* 9. 解析初始化参数 (可选) */
    if (args && strlen(args) > 0) {
        pr_info("[svc-tracer] init args: %s\n", args);
        /* 预留: 未来可在此解析初始化参数 */
    }

    pr_info("[svc-tracer] initialized successfully\n");
    return 0;

fail_hook:
fail_monitor:
fail_pkg:
    maps_cache_destroy();
fail_maps:
fail_caller:
    event_logger_destroy();
    return ret;
}

/* ============================================================================
 * kpm_control0 - 模块控制接口
 * ============================================================================
 * 由用户空间通过 KernelPatch 的 ctl 接口调用。
 * 参数:
 *   args    - 用户命令字符串
 *   out_msg - 输出缓冲区 (用户空间地址)
 *   outlen  - 输出缓冲区长度
 * 返回: 0 成功, 负值错误
 * ============================================================================ */
static long kpm_control0(const char *args, char *__user out_msg, int outlen)
{
    const char *cmd;
    if (!args || strlen(args) == 0) {
        OUT_MSG("{\"error\":\"empty command\"}");
        return -1;
    }

    cmd = skip_spaces_local(args);

    /* ================================================================
     * status - 返回当前状态
     * ================================================================ */
    if (strcmp(cmd, "status") == 0) {
        int pending = event_logger_pending();
        OUT_MSG("{\"status\":\"ok\",\"version\":\"%s\","
                "\"running\":%d,\"pid_count\":%d,"
                "\"filter_uid\":%d,\"filter_pkg\":\"%s\","
                "\"filter_comm\":\"%s\","
                "\"category_mask\":%d,\"syscall_filter_count\":%d,"
                "\"pending_events\":%d,\"hooks\":%d,"
                "\"capture_args\":%d,\"capture_caller\":%d,"
                "\"capture_bt\":%d,\"capture_retval\":%d,"
                "\"detect_antidebug\":%d,"
                "\"file_log\":%d}",
                SVC_TRACER_VERSION,
                g_config.running, g_config.pid_count,
                g_config.filter_uid, g_config.filter_pkg,
                g_config.filter_comm,
                g_config.category_mask, g_config.filtered_syscall_count,
                pending, hook_get_count(),
                g_config.capture_args, g_config.capture_caller,
                g_config.capture_backtrace, g_config.capture_retval,
                g_config.detect_antidebug,
                g_config.file_log_enabled);
        return 0;
    }

    /* ================================================================
     * start - 开始监控
     * ================================================================ */
    if (strcmp(cmd, "start") == 0) {
        g_config.running = 1;
        OUT_MSG("{\"status\":\"ok\",\"message\":\"monitor started\"}");
        return 0;
    }

    /* ================================================================
     * stop - 停止监控
     * ================================================================ */
    if (strcmp(cmd, "stop") == 0) {
        g_config.running = 0;
        OUT_MSG("{\"status\":\"ok\",\"message\":\"monitor stopped\"}");
        return 0;
    }

    /* ================================================================
     * clear - 清空事件缓冲区
     * ================================================================ */
    if (strcmp(cmd, "clear") == 0) {
        event_logger_clear();
        OUT_MSG("{\"status\":\"ok\",\"message\":\"events cleared\"}");
        return 0;
    }

    /* ================================================================
     * stats - 返回统计信息
     * ================================================================ */
    if (strcmp(cmd, "stats") == 0) {
        OUT_MSG("{\"status\":\"ok\",\"total\":%llu,\"dropped\":%llu,"
                "\"filtered\":%llu,\"antidebug\":%llu,"
                "\"file_writes\":%llu,\"file_errors\":%llu,"
                "\"hooks\":%llu}",
                g_stats.total_events, g_stats.dropped_events,
                g_stats.filtered_events, g_stats.antidebug_events,
                g_stats.file_log_writes, g_stats.file_log_errors,
                g_stats.hook_count);
        return 0;
    }

    /* ================================================================
     * hooks - 安装 hook
     *   hooks slim   : 安装预定义的常用 hook
     *   hooks all    : 安装 0-512 全量 hook
     *   hooks range N: 安装 0-N hook
     * ================================================================ */
    if (str_starts_with(cmd, "hooks")) {
        cmd = skip_spaces_local(cmd + 5);
        if (strcmp(cmd, "slim") == 0) {
            int count = hook_install_slim();
            OUT_MSG("{\"status\":\"ok\",\"hooks_installed\":%d}", count);
            return 0;
        }
        if (strcmp(cmd, "all") == 0) {
            int count = hook_install_all();
            OUT_MSG("{\"status\":\"ok\",\"hooks_installed\":%d}", count);
            return 0;
        }
        if (str_starts_with(cmd, "range")) {
            cmd = skip_spaces_local(cmd + 5);
            int max = simple_atoi(cmd);
            int count = hook_install_range(max);
            OUT_MSG("{\"status\":\"ok\",\"hooks_installed\":%d}", count);
            return 0;
        }
        OUT_MSG("{\"error\":\"invalid hooks command\"}");
        return -1;
    }

    /* ================================================================
     * config - 配置项设置
     *   示例: config uid 10086
     * ================================================================ */
    if (str_starts_with(cmd, "config")) {
        cmd = skip_spaces_local(cmd + 6);

        if (str_starts_with(cmd, "uid")) {
            cmd = skip_spaces_local(cmd + 3);
            g_config.filter_uid = simple_atoi(cmd);
            OUT_MSG("{\"status\":\"ok\",\"uid\":%d}", g_config.filter_uid);
            return 0;
        }

        if (str_starts_with(cmd, "pkg")) {
            cmd = skip_spaces_local(cmd + 3);
            strncpy(g_config.filter_pkg, cmd, MAX_PKG_LEN - 1);
            g_config.filter_pkg[MAX_PKG_LEN - 1] = '\0';
            OUT_MSG("{\"status\":\"ok\",\"pkg\":\"%s\"}", g_config.filter_pkg);
            return 0;
        }

        if (str_starts_with(cmd, "comm")) {
            cmd = skip_spaces_local(cmd + 4);
            strncpy(g_config.filter_comm, cmd, MAX_COMM_LEN - 1);
            g_config.filter_comm[MAX_COMM_LEN - 1] = '\0';
            OUT_MSG("{\"status\":\"ok\",\"comm\":\"%s\"}", g_config.filter_comm);
            return 0;
        }

        if (str_starts_with(cmd, "cat")) {
            cmd = skip_spaces_local(cmd + 3);
            g_config.category_mask = (unsigned char)simple_atoi(cmd);
            OUT_MSG("{\"status\":\"ok\",\"category_mask\":%d}", g_config.category_mask);
            return 0;
        }

        if (str_starts_with(cmd, "capture_args")) {
            cmd = skip_spaces_local(cmd + 12);
            g_config.capture_args = simple_atoi(cmd) ? 1 : 0;
            OUT_MSG("{\"status\":\"ok\",\"capture_args\":%d}", g_config.capture_args);
            return 0;
        }

        if (str_starts_with(cmd, "capture_caller")) {
            cmd = skip_spaces_local(cmd + 14);
            g_config.capture_caller = simple_atoi(cmd) ? 1 : 0;
            OUT_MSG("{\"status\":\"ok\",\"capture_caller\":%d}", g_config.capture_caller);
            return 0;
        }

        if (str_starts_with(cmd, "capture_bt")) {
            cmd = skip_spaces_local(cmd + 10);
            g_config.capture_backtrace = simple_atoi(cmd) ? 1 : 0;
            OUT_MSG("{\"status\":\"ok\",\"capture_bt\":%d}", g_config.capture_backtrace);
            return 0;
        }

        if (str_starts_with(cmd, "capture_retval")) {
            cmd = skip_spaces_local(cmd + 14);
            g_config.capture_retval = simple_atoi(cmd) ? 1 : 0;
            OUT_MSG("{\"status\":\"ok\",\"capture_retval\":%d}", g_config.capture_retval);
            return 0;
        }

        if (str_starts_with(cmd, "antidebug")) {
            cmd = skip_spaces_local(cmd + 9);
            g_config.detect_antidebug = simple_atoi(cmd) ? 1 : 0;
            OUT_MSG("{\"status\":\"ok\",\"antidebug\":%d}", g_config.detect_antidebug);
            return 0;
        }

        if (str_starts_with(cmd, "file_log")) {
            cmd = skip_spaces_local(cmd + 8);
            g_config.file_log_enabled = simple_atoi(cmd) ? 1 : 0;
            if (g_config.file_log_enabled)
                file_logger_enable();
            else
                file_logger_disable();
            OUT_MSG("{\"status\":\"ok\",\"file_log\":%d}", g_config.file_log_enabled);
            return 0;
        }

        if (str_starts_with(cmd, "file_path")) {
            cmd = skip_spaces_local(cmd + 9);
            file_logger_set_path(cmd);
            OUT_MSG("{\"status\":\"ok\",\"file_path\":\"%s\"}", cmd);
            return 0;
        }

        OUT_MSG("{\"error\":\"invalid config command\"}");
        return -1;
    }

    /* ================================================================
     * read - 读取事件
     * ================================================================ */
    if (str_starts_with(cmd, "read")) {
        int max_count = 1;
        struct svc_event *events;
        int count, i;

        cmd = skip_spaces_local(cmd + 4);
        if (*cmd) {
            max_count = simple_atoi(cmd);
            if (max_count <= 0 || max_count > 100)
                max_count = 1;
        }

        events = (struct svc_event *)kp_malloc(sizeof(struct svc_event) * max_count);
        if (!events) {
            OUT_MSG("{\"error\":\"alloc failed\"}");
            return -1;
        }

        count = event_logger_read_batch(events, max_count);
        if (count <= 0) {
            kp_free(events);
            OUT_MSG("{\"status\":\"ok\",\"events\":[]}");
            return 0;
        }

        if (g_config.json_output) {
            int pos = 0;
            pos += snprintf(out_msg + pos, outlen - pos, "{\"status\":\"ok\",\"events\":[");
            for (i = 0; i < count; i++) {
                struct svc_event *e = &events[i];
                pos += snprintf(out_msg + pos, outlen - pos,
                    "{\"ts\":%llu,\"pid\":%d,\"tid\":%d,\"uid\":%u,"
                    "\"comm\":\"%s\",\"nr\":%d,\"name\":\"%s\","
                    "\"ret\":%ld,\"cat\":%d,\"antidebug\":%d,"
                    "\"pc\":\"0x%lx\",\"lr\":\"0x%lx\","
                    "\"module\":\"%s\",\"offset\":\"0x%lx\","
                    "\"detail\":\"%s\"}%s",
                    e->timestamp_ns, e->pid, e->tid, e->uid,
                    e->comm, e->syscall_nr, get_syscall_name(e->syscall_nr),
                    e->retval, e->category, e->is_antidebug,
                    e->caller_pc, e->caller_lr,
                    e->caller_module, e->caller_offset,
                    e->detail,
                    (i == count - 1) ? "" : ",");
                if (pos >= outlen - 128)
                    break;
            }
            snprintf(out_msg + pos, outlen - pos, "]}");
        } else {
            int pos = 0;
            pos += snprintf(out_msg + pos, outlen - pos, "count=%d\n", count);
            for (i = 0; i < count; i++) {
                struct svc_event *e = &events[i];
                pos += snprintf(out_msg + pos, outlen - pos,
                    "[%d] ts=%llu pid=%d tid=%d uid=%u comm=%s nr=%d ret=%ld\n",
                    i, e->timestamp_ns, e->pid, e->tid, e->uid,
                    e->comm, e->syscall_nr, e->retval);
                if (pos >= outlen - 128)
                    break;
            }
        }

        kp_free(events);
        return 0;
    }

    OUT_MSG("{\"error\":\"unknown command\"}");
    return -1;
}

/* ============================================================================
 * kpm_exit - 模块卸载入口
 * ============================================================================ */
static long kpm_exit(void *reserved)
{
    (void)reserved;
    hook_engine_destroy();
    file_logger_close();
    maps_cache_destroy();
    event_logger_destroy();
    pr_info("[svc-tracer] exited\n");
    return 0;
}

/* --------------------------------------------------------------------------
 * KPM 入口注册
 * -------------------------------------------------------------------------- */
KPM_INIT(kpm_init);
KPM_CTL0(kpm_control0);
KPM_EXIT(kpm_exit);
