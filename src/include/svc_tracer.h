/* ============================================================================
 * svc_tracer.h - SVCModule 主头文件
 * ============================================================================
 * 版本: 3.0.0
 * 描述: 定义所有公共结构体、宏常量、模块间接口声明
 * ============================================================================ */

#ifndef _SVC_TRACER_H_
#define _SVC_TRACER_H_

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>

/* --------------------------------------------------------------------------
 * 版本信息
 * -------------------------------------------------------------------------- */
#define SVC_TRACER_VERSION "3.0.0"

/* --------------------------------------------------------------------------
 * 容量与限制常量
 * -------------------------------------------------------------------------- */
#define EVENT_BUFFER_CAPACITY   4096    /* 环形事件缓冲区容量 */
#define MAX_MONITORED_PIDS      32      /* 最大监控 PID 数量 */
#define MAX_BACKTRACE_DEPTH     16      /* 最大回溯深度 */
#define MAX_FILTERED_SYSCALLS   128     /* 最大过滤 syscall 数量 */
#define MAX_MAPS_CACHE_PROCS    8       /* maps 缓存最大进程数 */
#define MAX_MAPS_ENTRIES        512     /* 单进程 maps 最大条目数 */
#define MAX_PKG_CACHE           64      /* 包名缓存最大条目数 */
#define PKG_CACHE_TTL_NS        (60ULL * 1000000000ULL) /* 包名缓存 TTL: 60秒 */

/* --------------------------------------------------------------------------
 * 字符串缓冲区大小
 * -------------------------------------------------------------------------- */
#define MAX_DETAIL_LEN          512     /* 事件详情字符串最大长度 */
#define MAX_COMM_LEN            16      /* 进程 comm 最大长度 */
#define MAX_PKG_LEN             128     /* 包名最大长度 */
#define MAX_PATH_LEN            256     /* 路径最大长度 */
#define MAX_MODULE_NAME_LEN     128     /* 模块名最大长度 */

/* --------------------------------------------------------------------------
 * Syscall 类别掩码
 * -------------------------------------------------------------------------- */
#define SC_CAT_FILE     0x01    /* 文件操作: openat, close, read, write 等 */
#define SC_CAT_NET      0x02    /* 网络操作: socket, connect, bind 等 */
#define SC_CAT_MEM      0x04    /* 内存操作: mmap, munmap, mprotect 等 */
#define SC_CAT_PROC     0x08    /* 进程操作: execve, clone, exit_group 等 */
#define SC_CAT_IPC      0x10    /* IPC 操作: epoll, eventfd 等 */
#define SC_CAT_SIGNAL   0x20    /* 信号操作: rt_sigaction, kill, tgkill 等 */
#define SC_CAT_ANTIDEBUG 0x40   /* 反调试行为: ptrace, 特殊文件访问等 */
#define SC_CAT_ALL      0xFF    /* 所有类别 */

/* --------------------------------------------------------------------------
 * svc_event - 系统调用事件结构体
 * --------------------------------------------------------------------------
 * 每次捕获到的系统调用事件信息，存入环形缓冲区。
 * -------------------------------------------------------------------------- */
struct svc_event {
    /* 时间戳 (纳秒, ktime_get_ns) */
    unsigned long long timestamp_ns;

    /* 进程信息 */
    int pid;                            /* 进程 PID (tgid) */
    int tid;                            /* 线程 TID (pid) */
    unsigned int uid;                   /* 用户 UID */
    char comm[MAX_COMM_LEN];            /* 进程名 */

    /* 系统调用信息 */
    int syscall_nr;                     /* 系统调用号 */
    unsigned long args[6];              /* 系统调用参数 (最多6个) */
    long retval;                        /* 返回值 */
    unsigned char category;             /* 类别掩码 (SC_CAT_xxx) */
    unsigned char is_antidebug;         /* 是否触发反调试检测 */

    /* 调用者信息 */
    unsigned long caller_pc;            /* 调用者 PC */
    unsigned long caller_lr;            /* 调用者 LR */
    char caller_module[MAX_MODULE_NAME_LEN]; /* 调用者所在模块 */
    unsigned long caller_offset;        /* 模块内偏移 */

    /* 回溯栈 */
    unsigned long backtrace[MAX_BACKTRACE_DEPTH]; /* 回溯地址数组 */
    int backtrace_depth;                /* 实际回溯深度 (最大16) */

    /* 详情字符串 (格式化后的参数描述) */
    char detail[MAX_DETAIL_LEN];
};

/* --------------------------------------------------------------------------
 * tracer_config - 全局配置结构体
 * -------------------------------------------------------------------------- */
struct tracer_config {
    /* 运行状态 */
    int running;                        /* 1=运行中, 0=停止 */

    /* PID 过滤 */
    int monitored_pids[MAX_MONITORED_PIDS]; /* 监控的 PID 列表 */
    int pid_count;                      /* 当前监控 PID 数量 */

    /* UID 过滤 */
    int filter_uid;                     /* UID 过滤值, -1 表示不过滤 */

    /* 包名过滤 */
    char filter_pkg[MAX_PKG_LEN];       /* 包名过滤, 空串表示不过滤 */

    /* comm 过滤 */
    char filter_comm[MAX_COMM_LEN];     /* comm 过滤, 空串表示不过滤 */

    /* Syscall 类别过滤 */
    unsigned char category_mask;        /* 类别掩码, SC_CAT_ALL 表示全部 */

    /* Syscall 号过滤 */
    int filtered_syscalls[MAX_FILTERED_SYSCALLS]; /* 过滤的 syscall 号列表 */
    int filtered_syscall_count;         /* 过滤的 syscall 数量 */

    /* 功能开关 */
    int capture_args;                   /* 捕获参数详情 */
    int capture_caller;                 /* 捕获调用者信息 */
    int capture_backtrace;              /* 捕获回溯栈 */
    int capture_retval;                 /* 捕获返回值 */
    int detect_antidebug;               /* 反调试检测 */
    int json_output;                    /* JSON 格式输出 (ctl0 响应) */

    /* 文件日志 */
    int file_log_enabled;               /* 文件日志开关 */
    char file_log_path[MAX_PATH_LEN];   /* 文件日志路径 */
};

/* --------------------------------------------------------------------------
 * tracer_stats - 运行时统计结构体
 * -------------------------------------------------------------------------- */
struct tracer_stats {
    unsigned long long total_events;        /* 总事件数 */
    unsigned long long dropped_events;      /* 丢弃事件数 (缓冲区满时覆盖) */
    unsigned long long antidebug_events;    /* 反调试事件数 */
    unsigned long long filtered_events;     /* 被过滤掉的事件数 */
    unsigned long long file_log_writes;     /* 文件日志写入次数 */
    unsigned long long file_log_errors;     /* 文件日志写入错误次数 */
    unsigned long long hook_count;          /* 已安装的 hook 数量 */
};

/* --------------------------------------------------------------------------
 * 模块接口声明: symbol_resolver
 * -------------------------------------------------------------------------- */
int symbol_resolver_init(void);

/* 解析后的内核符号函数指针 */
extern unsigned long long (*kfunc_ktime_get_ns)(void);
extern unsigned long (*kfunc_copy_from_user)(void *to, const void __user *from,
                                              unsigned long n);
extern void *(*kfunc_filp_open)(const char *filename, int flags, unsigned short mode);
extern int (*kfunc_filp_close)(void *filp, void *id);
extern long (*kfunc_kernel_write)(void *filp, const void *buf,
                                   unsigned long count, long long *pos);

/* --------------------------------------------------------------------------
 * 模块接口声明: event_logger
 * -------------------------------------------------------------------------- */
int event_logger_init(void);
void event_logger_destroy(void);
int event_logger_write(const struct svc_event *event);
int event_logger_read(struct svc_event *out);
int event_logger_read_batch(struct svc_event *out, int max_count);
void event_logger_clear(void);
int event_logger_pending(void);
unsigned long long event_logger_dropped(void);
void event_logger_get_stats(int *pending, unsigned long long *total,
                            unsigned long long *dropped);

/* --------------------------------------------------------------------------
 * 模块接口声明: caller_resolver
 * -------------------------------------------------------------------------- */
int caller_resolver_init(void);
void caller_resolve(unsigned long *pc_out, unsigned long *lr_out,
                     char *module_out, unsigned long *offset_out);
int caller_backtrace(unsigned long *bt_out, int max_depth);

/* --------------------------------------------------------------------------
 * 模块接口声明: maps_cache
 * -------------------------------------------------------------------------- */
int maps_cache_init(void);
void maps_cache_destroy(void);
int maps_cache_lookup(int tgid, unsigned long addr,
                       char *name_out, unsigned long *offset_out);
int maps_cache_refresh(int tgid);
void maps_cache_invalidate(int tgid);
void maps_cache_clear(void);

/* --------------------------------------------------------------------------
 * 模块接口声明: pkg_resolver
 * -------------------------------------------------------------------------- */
int pkg_resolver_init(void);
int pkg_resolve_uid_to_pkg(unsigned int uid, char *pkg_out, int pkg_len);
int pkg_resolve_pkg_to_uid(const char *pkg_name);

/* --------------------------------------------------------------------------
 * 模块接口声明: syscall_monitor
 * -------------------------------------------------------------------------- */
int syscall_monitor_init(void);
void syscall_monitor_on_syscall(int nr, unsigned long *args,
                                long retval, int narg);
const char *get_syscall_name(int nr);
unsigned char get_syscall_category(int nr);

/* --------------------------------------------------------------------------
 * 模块接口声明: hook_engine
 * -------------------------------------------------------------------------- */
int hook_engine_init(void);
void hook_engine_destroy(void);
int hook_install_slim(void);
int hook_install_all(void);
int hook_install_range(int max_nr);
int hook_get_count(void);

/* --------------------------------------------------------------------------
 * 模块接口声明: file_logger
 * -------------------------------------------------------------------------- */
int file_logger_init(void);
void file_logger_close(void);
void file_logger_enable(void);
void file_logger_disable(void);
int file_logger_write_event(const struct svc_event *event);
int file_logger_set_path(const char *path);
int file_logger_truncate(void);
void file_logger_flush(void);

/* --------------------------------------------------------------------------
 * 全局变量
 * -------------------------------------------------------------------------- */
extern struct tracer_config g_config;
extern struct tracer_stats g_stats;

#endif /* _SVC_TRACER_H_ */
