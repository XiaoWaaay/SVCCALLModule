/* ============================================================================
 * syscall_monitor.c - Syscall 监控核心实现
 * ============================================================================
 * 版本: 3.0.0
 * 描述: 系统调用事件处理核心逻辑
 *       - 多级进程过滤 (PID -> UID -> comm -> package)
 *       - Syscall 类别分类
 *       - 反调试行为检测
 *       - 参数解析与事件构建
 * ============================================================================ */

#include <compiler.h>
#include <ktypes.h>
#include <stdint.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include "svc_tracer.h"

/* --------------------------------------------------------------------------
 * 全局配置与统计 (其他模块通过 extern 引用)
 * -------------------------------------------------------------------------- */
struct tracer_config g_config = {
    .running             = 0,
    .pid_count           = 0,
    .filter_uid          = -1,
    .filter_pkg          = {0},
    .filter_comm         = {0},
    .category_mask       = SC_CAT_ALL,
    .filtered_syscall_count = 0,
    .capture_args        = 1,
    .capture_caller      = 1,
    .capture_backtrace   = 0,
    .capture_retval      = 1,
    .detect_antidebug    = 1,
    .json_output         = 1,
    .file_log_enabled    = 0,
    .file_log_path       = "/sdcard/Download/svc_tracer.log",
};

struct tracer_stats g_stats = {0};

/* --------------------------------------------------------------------------
 * syscall 号定义 (与 hook_engine.c 一致)
 * -------------------------------------------------------------------------- */
#define __NR_eventfd2       19
#define __NR_epoll_create1  20
#define __NR_epoll_ctl      21
#define __NR_dup            23
#define __NR_dup3           24
#define __NR_ioctl          29
#define __NR_mkdirat        34
#define __NR_unlinkat       35
#define __NR_faccessat      48
#define __NR_openat         56
#define __NR_close          57
#define __NR_pipe2          59
#define __NR_lseek          62
#define __NR_read           63
#define __NR_write          64
#define __NR_readv          65
#define __NR_writev         66
#define __NR_readlinkat     78
#define __NR_fstat          80
#define __NR_exit_group     94
#define __NR_ptrace         117
#define __NR_kill           129
#define __NR_tgkill         131
#define __NR_rt_sigaction   134
#define __NR_setpgid        154
#define __NR_prctl          167
#define __NR_getpid         172
#define __NR_getuid         174
#define __NR_socket         198
#define __NR_bind           200
#define __NR_listen         201
#define __NR_connect        203
#define __NR_getsockname    204
#define __NR_sendto         206
#define __NR_recvfrom       207
#define __NR_setsockopt     208
#define __NR_munmap         215
#define __NR_mremap         216
#define __NR_clone          220
#define __NR_execve         221
#define __NR_mmap           222
#define __NR_mprotect       226
#define __NR_madvise        233
#define __NR_accept4        242
#define __NR_wait4          260
#define __NR_renameat2      276

/* prctl 选项常量 */
#define PR_SET_DUMPABLE     4

/* 信号常量 */
#define SIGTRAP             5

/* --------------------------------------------------------------------------
 * get_syscall_name - 获取 syscall 名称
 * -------------------------------------------------------------------------- */
const char *get_syscall_name(int nr)
{
    switch (nr) {
    case __NR_openat:       return "openat";
    case __NR_close:        return "close";
    case __NR_read:         return "read";
    case __NR_write:        return "write";
    case __NR_readv:        return "readv";
    case __NR_writev:       return "writev";
    case __NR_lseek:        return "lseek";
    case __NR_fstat:        return "fstat";
    case __NR_ioctl:        return "ioctl";
    case __NR_dup:          return "dup";
    case __NR_dup3:         return "dup3";
    case __NR_pipe2:        return "pipe2";
    case __NR_readlinkat:   return "readlinkat";
    case __NR_faccessat:    return "faccessat";
    case __NR_unlinkat:     return "unlinkat";
    case __NR_mkdirat:      return "mkdirat";
    case __NR_renameat2:    return "renameat2";
    case __NR_execve:       return "execve";
    case __NR_clone:        return "clone";
    case __NR_wait4:        return "wait4";
    case __NR_exit_group:   return "exit_group";
    case __NR_getpid:       return "getpid";
    case __NR_getuid:       return "getuid";
    case __NR_prctl:        return "prctl";
    case __NR_setpgid:      return "setpgid";
    case __NR_mmap:         return "mmap";
    case __NR_munmap:       return "munmap";
    case __NR_mprotect:     return "mprotect";
    case __NR_madvise:      return "madvise";
    case __NR_mremap:       return "mremap";
    case __NR_socket:       return "socket";
    case __NR_connect:      return "connect";
    case __NR_bind:         return "bind";
    case __NR_listen:       return "listen";
    case __NR_accept4:      return "accept4";
    case __NR_sendto:       return "sendto";
    case __NR_recvfrom:     return "recvfrom";
    case __NR_setsockopt:   return "setsockopt";
    case __NR_getsockname:  return "getsockname";
    case __NR_ptrace:       return "ptrace";
    case __NR_rt_sigaction: return "rt_sigaction";
    case __NR_kill:         return "kill";
    case __NR_tgkill:       return "tgkill";
    case __NR_epoll_create1: return "epoll_create1";
    case __NR_epoll_ctl:    return "epoll_ctl";
    case __NR_eventfd2:     return "eventfd2";
    default:                return "unknown";
    }
}

/* --------------------------------------------------------------------------
 * get_syscall_category - 获取 syscall 类别掩码
 * -------------------------------------------------------------------------- */
unsigned char get_syscall_category(int nr)
{
    switch (nr) {
    /* 文件操作 */
    case __NR_openat: case __NR_close: case __NR_read: case __NR_write:
    case __NR_readv: case __NR_writev: case __NR_lseek: case __NR_fstat:
    case __NR_ioctl: case __NR_dup: case __NR_dup3: case __NR_pipe2:
    case __NR_readlinkat: case __NR_faccessat: case __NR_unlinkat:
    case __NR_mkdirat: case __NR_renameat2:
        return SC_CAT_FILE;

    /* 进程操作 */
    case __NR_execve: case __NR_clone: case __NR_wait4:
    case __NR_exit_group: case __NR_getpid: case __NR_getuid:
    case __NR_prctl: case __NR_setpgid:
        return SC_CAT_PROC;

    /* 内存操作 */
    case __NR_mmap: case __NR_munmap: case __NR_mprotect:
    case __NR_madvise: case __NR_mremap:
        return SC_CAT_MEM;

    /* 网络操作 */
    case __NR_socket: case __NR_connect: case __NR_bind:
    case __NR_listen: case __NR_accept4: case __NR_sendto:
    case __NR_recvfrom: case __NR_setsockopt: case __NR_getsockname:
        return SC_CAT_NET;

    /* 信号操作 */
    case __NR_rt_sigaction: case __NR_kill: case __NR_tgkill:
        return SC_CAT_SIGNAL;

    /* 反调试 */
    case __NR_ptrace:
        return SC_CAT_ANTIDEBUG;

    /* IPC */
    case __NR_epoll_create1: case __NR_epoll_ctl: case __NR_eventfd2:
        return SC_CAT_IPC;

    default:
        return 0;
    }
}

static inline int task_get_pid(struct task_struct *task)
{
    return *(int *)((uintptr_t)task + task_struct_offset.pid_offset);
}

static inline int task_get_tgid(struct task_struct *task)
{
    return *(int *)((uintptr_t)task + task_struct_offset.tgid_offset);
}

static inline unsigned int task_get_uid(struct task_struct *task)
{
    const struct cred *cred = *(const struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    const kuid_t *uid = (const kuid_t *)((uintptr_t)cred + cred_offset.uid_offset);
    return uid->val;
}

/* --------------------------------------------------------------------------
 * should_monitor - 多级过滤判断
 * --------------------------------------------------------------------------
 * 过滤优先级: PID列表 -> UID -> comm -> package
 * 返回: 1=应该监控, 0=应该跳过
 * -------------------------------------------------------------------------- */
static int should_monitor(int tgid, unsigned int uid, const char *comm)
{
    int i;

    /* 1. PID 列表过滤 (如果设置了 PID 列表, 只监控列表中的进程) */
    if (g_config.pid_count > 0) {
        int found = 0;
        for (i = 0; i < g_config.pid_count; i++) {
            if (g_config.monitored_pids[i] == tgid) {
                found = 1;
                break;
            }
        }
        if (!found)
            return 0;
    }

    /* 2. UID 过滤 */
    if (g_config.filter_uid >= 0) {
        if ((int)uid != g_config.filter_uid)
            return 0;
    }

    /* 3. comm 过滤 */
    if (g_config.filter_comm[0] != '\0') {
        if (strncmp(comm, g_config.filter_comm, MAX_COMM_LEN) != 0)
            return 0;
    }

    /* 4. 包名过滤 (通过 UID 间接过滤) */
    if (g_config.filter_pkg[0] != '\0' && g_config.filter_uid < 0) {
        /*
         * 包名过滤但未设置 UID:
         * 尝试解析当前 UID 对应的包名进行匹配
         */
        char pkg_buf[MAX_PKG_LEN];
        if (pkg_resolve_uid_to_pkg(uid, pkg_buf, MAX_PKG_LEN) == 0) {
            if (strncmp(pkg_buf, g_config.filter_pkg, MAX_PKG_LEN) != 0)
                return 0;
        } else {
            /* 无法解析包名, 跳过 */
            return 0;
        }
    }

    return 1;
}

/* --------------------------------------------------------------------------
 * is_antidebug_behavior - 反调试行为检测
 * --------------------------------------------------------------------------
 * 检测以下行为模式:
 * 1. ptrace 调用 (直接反调试)
 * 2. 访问 /proc/self/status, maps, mem, wchan, task, fd
 * 3. 检测 frida, magisk, su 字符串
 * 4. prctl PR_SET_DUMPABLE 0
 * 5. rt_sigaction SIGTRAP
 * 6. openat 访问 /proc/self/fd (遍历文件描述符)
 * -------------------------------------------------------------------------- */
static int is_antidebug_behavior(int nr, unsigned long *args)
{
    /* ptrace 调用 */
    if (nr == __NR_ptrace)
        return 1;

    /* prctl PR_SET_DUMPABLE 0 */
    if (nr == __NR_prctl) {
        if (args[0] == PR_SET_DUMPABLE && args[1] == 0)
            return 1;
    }

    /* rt_sigaction SIGTRAP */
    if (nr == __NR_rt_sigaction) {
        if ((int)args[0] == SIGTRAP)
            return 1;
    }

    /* 文件访问类反调试检测 */
    if (nr == __NR_openat || nr == __NR_faccessat || nr == __NR_readlinkat) {
        /*
         * args[1] 是路径指针 (用户空间地址)
         * 安全读取路径字符串进行检查
         */
        char path_buf[256];
        unsigned long path_addr = args[1];

        if (path_addr == 0)
            return 0;

        /* 安全读取用户空间字符串 */
        memset(path_buf, 0, sizeof(path_buf));
        if (kfunc_copy_from_user && kfunc_copy_from_user(
                path_buf, (const void __user *)path_addr, 255) != 0) {
            return 0; /* 读取失败,不判定 */
        }
        path_buf[255] = '\0';

        /* /proc/self/ 相关检测 */
        if (strstr(path_buf, "/proc/self/status") ||
            strstr(path_buf, "/proc/self/maps") ||
            strstr(path_buf, "/proc/self/mem") ||
            strstr(path_buf, "/proc/self/wchan") ||
            strstr(path_buf, "/proc/self/task") ||
            strstr(path_buf, "/proc/self/fd")) {
            return 1;
        }

        /* frida 检测 */
        if (strstr(path_buf, "frida") ||
            strstr(path_buf, "linjector") ||
            strstr(path_buf, "gadget")) {
            return 1;
        }

        /* magisk / su 检测 */
        if (strstr(path_buf, "magisk") ||
            strstr(path_buf, "/su") ||
            strstr(path_buf, "/sbin/su") ||
            strstr(path_buf, "supersu")) {
            return 1;
        }
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * safe_strncpy_from_user - 安全读取用户空间字符串
 * -------------------------------------------------------------------------- */
static int safe_strncpy_from_user(char *dst, unsigned long user_addr, int maxlen)
{
    if (user_addr == 0 || maxlen <= 0) {
        dst[0] = '\0';
        return 0;
    }

    memset(dst, 0, maxlen);
    if (kfunc_copy_from_user &&
        kfunc_copy_from_user(dst, (const void __user *)user_addr, maxlen - 1) != 0) {
        dst[0] = '\0';
        return -1;
    }
    dst[maxlen - 1] = '\0';
    return strlen(dst);
}

/* --------------------------------------------------------------------------
 * parse_args - 为各系统调用解析参数到 detail 字符串
 * -------------------------------------------------------------------------- */
static void parse_args(int nr, unsigned long *args, long retval,
                        char *detail, int detail_len)
{
    char path_buf[128];

    detail[0] = '\0';

    switch (nr) {
    /* === 文件操作 === */
    case __NR_openat:
        safe_strncpy_from_user(path_buf, args[1], sizeof(path_buf));
        snprintf(detail, detail_len,
                 "dirfd=%ld path=\"%s\" flags=0x%lx mode=0%lo",
                 (long)args[0], path_buf, args[2], args[3]);
        break;

    case __NR_close:
        snprintf(detail, detail_len, "fd=%ld", (long)args[0]);
        break;

    case __NR_read:
        snprintf(detail, detail_len, "fd=%ld buf=0x%lx count=%lu",
                 (long)args[0], args[1], args[2]);
        break;

    case __NR_write:
        snprintf(detail, detail_len, "fd=%ld buf=0x%lx count=%lu",
                 (long)args[0], args[1], args[2]);
        break;

    case __NR_readv:
        snprintf(detail, detail_len, "fd=%ld iov=0x%lx iovcnt=%lu",
                 (long)args[0], args[1], args[2]);
        break;

    case __NR_writev:
        snprintf(detail, detail_len, "fd=%ld iov=0x%lx iovcnt=%lu",
                 (long)args[0], args[1], args[2]);
        break;

    case __NR_lseek:
        snprintf(detail, detail_len, "fd=%ld offset=%ld whence=%ld",
                 (long)args[0], (long)args[1], (long)args[2]);
        break;

    case __NR_fstat:
        snprintf(detail, detail_len, "fd=%ld statbuf=0x%lx",
                 (long)args[0], args[1]);
        break;

    case __NR_ioctl:
        snprintf(detail, detail_len, "fd=%ld cmd=0x%lx arg=0x%lx",
                 (long)args[0], args[1], args[2]);
        break;

    case __NR_dup:
        snprintf(detail, detail_len, "oldfd=%ld", (long)args[0]);
        break;

    case __NR_dup3:
        snprintf(detail, detail_len, "oldfd=%ld newfd=%ld flags=0x%lx",
                 (long)args[0], (long)args[1], args[2]);
        break;

    case __NR_pipe2:
        snprintf(detail, detail_len, "pipefd=0x%lx flags=0x%lx",
                 args[0], args[1]);
        break;

    case __NR_readlinkat:
        safe_strncpy_from_user(path_buf, args[1], sizeof(path_buf));
        snprintf(detail, detail_len, "dirfd=%ld path=\"%s\" bufsiz=%lu",
                 (long)args[0], path_buf, args[3]);
        break;

    case __NR_faccessat:
        safe_strncpy_from_user(path_buf, args[1], sizeof(path_buf));
        snprintf(detail, detail_len, "dirfd=%ld path=\"%s\" mode=%ld",
                 (long)args[0], path_buf, (long)args[2]);
        break;

    case __NR_unlinkat:
        safe_strncpy_from_user(path_buf, args[1], sizeof(path_buf));
        snprintf(detail, detail_len, "dirfd=%ld path=\"%s\" flags=0x%lx",
                 (long)args[0], path_buf, args[2]);
        break;

    case __NR_mkdirat:
        safe_strncpy_from_user(path_buf, args[1], sizeof(path_buf));
        snprintf(detail, detail_len, "dirfd=%ld path=\"%s\" mode=0%lo",
                 (long)args[0], path_buf, args[2]);
        break;

    case __NR_renameat2:
        safe_strncpy_from_user(path_buf, args[1], sizeof(path_buf));
        snprintf(detail, detail_len,
                 "olddirfd=%ld oldpath=\"%s\" newdirfd=%ld flags=0x%lx",
                 (long)args[0], path_buf, (long)args[2], args[4]);
        break;

    /* === 进程操作 === */
    case __NR_execve:
        safe_strncpy_from_user(path_buf, args[0], sizeof(path_buf));
        snprintf(detail, detail_len,
                 "filename=\"%s\" argv=0x%lx envp=0x%lx",
                 path_buf, args[1], args[2]);
        break;

    case __NR_clone:
        snprintf(detail, detail_len,
                 "flags=0x%lx stack=0x%lx ptid=0x%lx tls=0x%lx ctid=0x%lx",
                 args[0], args[1], args[2], args[3], args[4]);
        break;

    case __NR_wait4:
        snprintf(detail, detail_len,
                 "pid=%ld stat_addr=0x%lx options=0x%lx rusage=0x%lx",
                 (long)args[0], args[1], args[2], args[3]);
        break;

    case __NR_exit_group:
        snprintf(detail, detail_len, "status=%ld", (long)args[0]);
        break;

    case __NR_prctl:
        snprintf(detail, detail_len,
                 "option=%ld arg2=0x%lx arg3=0x%lx arg4=0x%lx arg5=0x%lx",
                 (long)args[0], args[1], args[2], args[3], args[4]);
        break;

    case __NR_setpgid:
        snprintf(detail, detail_len, "pid=%ld pgid=%ld",
                 (long)args[0], (long)args[1]);
        break;

    case __NR_getpid:
    case __NR_getuid:
        snprintf(detail, detail_len, "ret=%ld", retval);
        break;

    /* === 内存操作 === */
    case __NR_mmap:
        snprintf(detail, detail_len,
                 "addr=0x%lx len=%lu prot=0x%lx flags=0x%lx fd=%ld off=0x%lx",
                 args[0], args[1], args[2], args[3], (long)args[4], args[5]);
        break;

    case __NR_munmap:
        snprintf(detail, detail_len, "addr=0x%lx len=%lu",
                 args[0], args[1]);
        break;

    case __NR_mprotect:
        snprintf(detail, detail_len, "addr=0x%lx len=%lu prot=0x%lx",
                 args[0], args[1], args[2]);
        break;

    case __NR_madvise:
        snprintf(detail, detail_len, "addr=0x%lx len=%lu advice=%ld",
                 args[0], args[1], (long)args[2]);
        break;

    case __NR_mremap:
        snprintf(detail, detail_len,
                 "old_addr=0x%lx old_size=%lu new_size=%lu flags=0x%lx new_addr=0x%lx",
                 args[0], args[1], args[2], args[3], args[4]);
        break;

    /* === 网络操作 === */
    case __NR_socket:
        snprintf(detail, detail_len, "domain=%ld type=%ld protocol=%ld",
                 (long)args[0], (long)args[1], (long)args[2]);
        break;

    case __NR_connect:
        snprintf(detail, detail_len, "sockfd=%ld addr=0x%lx addrlen=%lu",
                 (long)args[0], args[1], args[2]);
        break;

    case __NR_bind:
        snprintf(detail, detail_len, "sockfd=%ld addr=0x%lx addrlen=%lu",
                 (long)args[0], args[1], args[2]);
        break;

    case __NR_listen:
        snprintf(detail, detail_len, "sockfd=%ld backlog=%ld",
                 (long)args[0], (long)args[1]);
        break;

    case __NR_accept4:
        snprintf(detail, detail_len,
                 "sockfd=%ld addr=0x%lx addrlen=0x%lx flags=0x%lx",
                 (long)args[0], args[1], args[2], args[3]);
        break;

    case __NR_sendto:
        snprintf(detail, detail_len,
                 "sockfd=%ld buf=0x%lx len=%lu flags=0x%lx dest=0x%lx addrlen=%lu",
                 (long)args[0], args[1], args[2], args[3], args[4], args[5]);
        break;

    case __NR_recvfrom:
        snprintf(detail, detail_len,
                 "sockfd=%ld buf=0x%lx len=%lu flags=0x%lx src=0x%lx addrlen=0x%lx",
                 (long)args[0], args[1], args[2], args[3], args[4], args[5]);
        break;

    case __NR_setsockopt:
        snprintf(detail, detail_len,
                 "sockfd=%ld level=%ld optname=%ld optval=0x%lx optlen=%lu",
                 (long)args[0], (long)args[1], (long)args[2], args[3], args[4]);
        break;

    case __NR_getsockname:
        snprintf(detail, detail_len, "sockfd=%ld addr=0x%lx addrlen=0x%lx",
                 (long)args[0], args[1], args[2]);
        break;

    /* === 信号/调试操作 === */
    case __NR_ptrace:
        snprintf(detail, detail_len,
                 "request=%ld pid=%ld addr=0x%lx data=0x%lx",
                 (long)args[0], (long)args[1], args[2], args[3]);
        break;

    case __NR_rt_sigaction:
        snprintf(detail, detail_len,
                 "signum=%ld act=0x%lx oldact=0x%lx sigsetsize=%lu",
                 (long)args[0], args[1], args[2], args[3]);
        break;

    case __NR_kill:
        snprintf(detail, detail_len, "pid=%ld sig=%ld",
                 (long)args[0], (long)args[1]);
        break;

    case __NR_tgkill:
        snprintf(detail, detail_len, "tgid=%ld tid=%ld sig=%ld",
                 (long)args[0], (long)args[1], (long)args[2]);
        break;

    /* === IPC 操作 === */
    case __NR_epoll_create1:
        snprintf(detail, detail_len, "flags=0x%lx", args[0]);
        break;

    case __NR_epoll_ctl:
        snprintf(detail, detail_len, "epfd=%ld op=%ld fd=%ld event=0x%lx",
                 (long)args[0], (long)args[1], (long)args[2], args[3]);
        break;

    case __NR_eventfd2:
        snprintf(detail, detail_len, "initval=%lu flags=0x%lx",
                 args[0], args[1]);
        break;

    default:
        snprintf(detail, detail_len, "arg0=0x%lx arg1=0x%lx arg2=0x%lx",
                 args[0], args[1], args[2]);
        break;
    }
}

/* ============================================================================
 * syscall_monitor_init - 初始化监控器
 * ============================================================================ */
int syscall_monitor_init(void)
{
    /* 配置已在声明时初始化, 此处清零统计 */
    memset(&g_stats, 0, sizeof(g_stats));
    pr_info("[svc-tracer] syscall monitor initialized\n");
    return 0;
}

/* ============================================================================
 * syscall_monitor_on_syscall - 主入口, 由 hook 回调调用
 * ============================================================================
 * 参数:
 *   nr     - 系统调用号
 *   args   - 系统调用参数数组 (6个元素)
 *   retval - 返回值
 *   narg   - 实际参数数量
 * ============================================================================ */
void syscall_monitor_on_syscall(int nr, unsigned long *args,
                                 long retval, int narg)
{
    struct svc_event event;
    int tgid, tid;
    unsigned int uid;
    unsigned char cat;

    /* 检查运行状态 */
    if (!g_config.running)
        return;

    /* 获取当前进程信息 */
    tgid = task_get_tgid(current);
    tid = task_get_pid(current);

    /* 获取 UID: 通过 current->cred->uid.val */
    uid = task_get_uid(current);

    /* 获取 syscall 类别 */
    cat = get_syscall_category(nr);

    /* 类别过滤 */
    if (cat != 0 && !(cat & g_config.category_mask)) {
        g_stats.filtered_events++;
        return;
    }

    /* Syscall 号过滤 (如果设置了过滤列表, 只监控列表中的 syscall) */
    if (g_config.filtered_syscall_count > 0) {
        int i, found = 0;
        for (i = 0; i < g_config.filtered_syscall_count; i++) {
            if (g_config.filtered_syscalls[i] == nr) {
                found = 1;
                break;
            }
        }
        if (!found) {
            g_stats.filtered_events++;
            return;
        }
    }

    /* 多级进程过滤 */
    if (!should_monitor(tgid, uid, get_task_comm(current))) {
        g_stats.filtered_events++;
        return;
    }

    /* 构建事件 */
    memset(&event, 0, sizeof(event));

    /* 时间戳 */
    if (kfunc_ktime_get_ns)
        event.timestamp_ns = kfunc_ktime_get_ns();

    /* 进程信息 */
    event.pid = tgid;
    event.tid = tid;
    event.uid = uid;
    strncpy(event.comm, get_task_comm(current), MAX_COMM_LEN - 1);

    /* 系统调用信息 */
    event.syscall_nr = nr;
    if (args) {
        int i;
        for (i = 0; i < 6 && i < narg; i++)
            event.args[i] = args[i];
    }
    event.category = cat;

    /* 返回值 */
    if (g_config.capture_retval)
        event.retval = retval;

    /* 反调试检测 */
    if (g_config.detect_antidebug) {
        event.is_antidebug = is_antidebug_behavior(nr, args);
        if (event.is_antidebug)
            g_stats.antidebug_events++;
    }

    /* 调用者信息 */
    if (g_config.capture_caller) {
        caller_resolve(&event.caller_pc, &event.caller_lr,
                        event.caller_module, &event.caller_offset);

        /* 如果模块名为空, 尝试从 maps 缓存查询 */
        if (event.caller_module[0] == '\0' && event.caller_pc != 0) {
            maps_cache_lookup(tgid, event.caller_pc,
                              event.caller_module, &event.caller_offset);
        }
    }

    /* 回溯栈 */
    if (g_config.capture_backtrace) {
        event.backtrace_depth = caller_backtrace(
            event.backtrace, MAX_BACKTRACE_DEPTH);
    }

    /* 参数解析 */
    if (g_config.capture_args) {
        parse_args(nr, args, retval, event.detail, MAX_DETAIL_LEN);
    }

    /* 写入环形缓冲区 */
    g_stats.total_events++;
    if (event_logger_write(&event) < 0) {
        g_stats.dropped_events++;
    }

    /* 文件日志 */
    if (g_config.file_log_enabled) {
        if (file_logger_write_event(&event) == 0) {
            g_stats.file_log_writes++;
        } else {
            g_stats.file_log_errors++;
        }
    }
}
