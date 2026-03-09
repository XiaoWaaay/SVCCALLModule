/* svc_monitor.c — v8.0 Always-On SVC Monitor KPM
 *
 * Architecture:
 *   - Module load → hook all tier1 syscalls → always monitoring
 *   - APP only controls: which UID, which NRs to log, pause/resume
 *   - Bitmap-based NR filter + UID filter, lock-free
 *
 * Official KPM API used:
 *   - inline_hook_syscalln(nr, narg, before, after, udata)
 *   - inline_unhook_syscalln(nr, before, after)
 *   - fp_hook_syscalln / fp_unhook_syscalln (fallback)
 *   - syscall_argn(fargs, n) / set_syscall_argn(fargs, n, val)
 *   - current_uid() from kputils.h
 *   - current from asm/current.h
 *   - compat_copy_to_user / compat_strncpy_from_user
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("svc_monitor");
KPM_VERSION("8.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("SVC Monitor Team");
KPM_DESCRIPTION("Always-on ARM64 SVC syscall monitor with filter control");

/* ================================================================
 * Constants
 * ================================================================ */
#define MAX_EVENTS      512
#define MAX_NR          320
#define BITMAP_LONGS    (MAX_NR / 64 + 1)
#define OUTPUT_PATH     "/data/local/tmp/svc_out.json"
#define DESC_BUF_SIZE   256
#define PATH_BUF_SIZE   256

/* ================================================================
 * Syscall name table (ARM64, 0-291)
 * ================================================================ */
static const char *syscall_names[] = {
    [0]="io_setup",[1]="io_destroy",[2]="io_submit",[3]="io_cancel",
    [4]="io_getevents",[5]="setxattr",[6]="lsetxattr",[7]="fsetxattr",
    [8]="getxattr",[9]="lgetxattr",[10]="fgetxattr",[11]="listxattr",
    [12]="llistxattr",[13]="flistxattr",[14]="removexattr",
    [15]="lremovexattr",[16]="fremovexattr",[17]="getcwd",
    [18]="lookup_dcookie",[19]="eventfd2",[20]="epoll_create1",
    [21]="epoll_ctl",[22]="epoll_pwait",[23]="dup",[24]="dup3",
    [25]="fcntl",[26]="inotify_init1",[27]="inotify_add_watch",
    [28]="inotify_rm_watch",[29]="ioctl",[30]="ioprio_set",
    [31]="ioprio_get",[32]="flock",[33]="mknodat",[34]="mkdirat",
    [35]="unlinkat",[36]="symlinkat",[37]="linkat",[38]="renameat",
    [39]="umount2",[40]="mount",[41]="pivot_root",
    [42]="nfsservctl",[43]="statfs",[44]="fstatfs",[45]="truncate",
    [46]="ftruncate",[47]="fallocate",[48]="faccessat",
    [49]="chdir",[50]="fchdir",[51]="chroot",[52]="fchmod",
    [53]="fchmodat",[54]="fchownat",[55]="fchown",
    [56]="openat",[57]="close",[58]="vhangup",
    [59]="pipe2",[60]="quotactl",[61]="getdents64",
    [62]="lseek",[63]="read",[64]="write",[65]="readv",
    [66]="writev",[67]="pread64",[68]="pwrite64",
    [69]="preadv",[70]="pwritev",[71]="sendfile",
    [72]="pselect6",[73]="ppoll",[74]="signalfd4",
    [75]="vmsplice",[76]="splice",[77]="tee",
    [78]="readlinkat",[79]="newfstatat",[80]="fstat",
    [81]="sync",[82]="fsync",[83]="fdatasync",
    [84]="sync_file_range",[85]="timerfd_create",
    [86]="timerfd_settime",[87]="timerfd_gettime",
    [88]="utimensat",[89]="acct",[90]="capget",
    [91]="capset",[92]="personality",[93]="exit",
    [94]="exit_group",[95]="waitid",[96]="set_tid_address",
    [97]="unshare",[98]="futex",[99]="set_robust_list",
    [100]="get_robust_list",[101]="nanosleep",
    [102]="getitimer",[103]="setitimer",[104]="kexec_load",
    [105]="init_module",[106]="delete_module",
    [107]="timer_create",[108]="timer_gettime",
    [109]="timer_getoverrun",[110]="timer_settime",
    [111]="timer_delete",[112]="clock_settime",
    [113]="clock_gettime",[114]="clock_getres",
    [115]="clock_nanosleep",[116]="syslog",
    [117]="ptrace",[118]="sched_setparam",
    [119]="sched_setscheduler",[120]="sched_getscheduler",
    [121]="sched_getparam",[122]="sched_setaffinity",
    [123]="sched_getaffinity",[124]="sched_yield",
    [125]="sched_get_priority_max",[126]="sched_get_priority_min",
    [127]="sched_rr_get_interval",[128]="restart_syscall",
    [129]="kill",[130]="tkill",[131]="tgkill",
    [132]="sigaltstack",[133]="rt_sigsuspend",
    [134]="rt_sigaction",[135]="rt_sigprocmask",
    [136]="rt_sigpending",[137]="rt_sigtimedwait",
    [138]="rt_sigqueueinfo",[139]="rt_sigreturn",
    [140]="setpriority",[141]="getpriority",
    [142]="reboot",[143]="setregid",[144]="setgid",
    [145]="setreuid",[146]="setuid",[147]="setresuid",
    [148]="getresuid",[149]="setresgid",[150]="getresgid",
    [151]="setfsuid",[152]="setfsgid",[153]="times",
    [154]="setpgid",[155]="getpgid",[156]="getsid",
    [157]="setsid",[158]="getgroups",[159]="setgroups",
    [160]="uname",[161]="sethostname",[162]="setdomainname",
    [163]="getrlimit",[164]="setrlimit",[165]="getrusage",
    [166]="umask",[167]="prctl",[168]="getcpu",
    [169]="gettimeofday",[170]="settimeofday",[171]="adjtimex",
    [172]="getpid",[173]="getppid",[174]="getuid",
    [175]="geteuid",[176]="getgid",[177]="getegid",
    [178]="gettid",[179]="sysinfo",[180]="mq_open",
    [181]="mq_unlink",[182]="mq_timedsend",
    [183]="mq_timedreceive",[184]="mq_notify",
    [185]="mq_getsetattr",[186]="msgget",[187]="msgctl",
    [188]="msgrcv",[189]="msgsnd",[190]="semget",
    [191]="semctl",[192]="semtimedop",[193]="semop",
    [194]="shmget",[195]="shmctl",[196]="shmat",
    [197]="shmdt",[198]="socket",[199]="socketpair",
    [200]="bind",[201]="listen",[202]="accept",
    [203]="connect",[204]="getsockname",[205]="getpeername",
    [206]="sendto",[207]="recvfrom",[208]="setsockopt",
    [209]="getsockopt",[210]="shutdown",[211]="sendmsg",
    [212]="recvmsg",[213]="readahead",[214]="brk",
    [215]="munmap",[216]="mremap",[217]="add_key",
    [218]="request_key",[219]="keyctl",[220]="clone",
    [221]="execve",[222]="mmap",[223]="fadvise64",
    [224]="swapon",[225]="swapoff",[226]="mprotect",
    [227]="msync",[228]="mlock",[229]="munlock",
    [230]="mlockall",[231]="munlockall",[232]="mincore",
    [233]="madvise",[234]="remap_file_pages",
    [235]="mbind",[236]="get_mempolicy",[237]="set_mempolicy",
    [238]="migrate_pages",[239]="move_pages",
    [240]="rt_tgsigqueueinfo",[241]="perf_event_open",
    [242]="accept4",[243]="recvmmsg",[244]="arch_specific_syscall",
    [260]="wait4",[261]="prlimit64",[262]="fanotify_init",
    [263]="fanotify_mark",[264]="name_to_handle_at",
    [265]="open_by_handle_at",[266]="clock_adjtime",
    [267]="syncfs",[268]="setns",[269]="sendmmsg",
    [270]="process_vm_readv",[271]="process_vm_writev",
    [272]="kcmp",[273]="finit_module",[274]="sched_setattr",
    [275]="sched_getattr",[276]="renameat2",
    [277]="seccomp",[278]="getrandom",[279]="memfd_create",
    [280]="bpf",[281]="execveat",[282]="userfaultfd",
    [283]="membarrier",[284]="mlock2",[285]="copy_file_range",
    [286]="preadv2",[287]="pwritev2",[288]="pkey_mprotect",
    [289]="pkey_alloc",[290]="pkey_free",[291]="statx",
};
#define SYSCALL_NAMES_COUNT (sizeof(syscall_names)/sizeof(syscall_names[0]))

static const char *get_syscall_name(int nr) {
    if (nr >= 0 && nr < (int)SYSCALL_NAMES_COUNT && syscall_names[nr])
        return syscall_names[nr];
    return "unknown";
}

/* ================================================================
 * Bitmap operations (for NR filter, MAX_NR=320, 5 longs)
 * ================================================================ */
static inline void bitmap_set(volatile unsigned long *bm, int bit) {
    if (bit >= 0 && bit < MAX_NR)
        bm[bit / 64] |= (1UL << (bit % 64));
}

static inline void bitmap_clear(volatile unsigned long *bm, int bit) {
    if (bit >= 0 && bit < MAX_NR)
        bm[bit / 64] &= ~(1UL << (bit % 64));
}

static inline int bitmap_test(volatile unsigned long *bm, int bit) {
    if (bit < 0 || bit >= MAX_NR) return 0;
    return (bm[bit / 64] >> (bit % 64)) & 1;
}

/* ================================================================
 * Global filter state (volatile for lock-free read)
 * ================================================================ */
static volatile int g_enabled = 0;                  /* 0=paused, 1=running */
static volatile int g_target_uid = -1;              /* -1=all, >=0=specific */
static volatile unsigned long g_nr_bitmap[BITMAP_LONGS];  /* which NRs to log */
static volatile int g_hooks_installed = 0;          /* how many hooks active */
static volatile int g_tier2_loaded = 0;             /* tier2 extension */

/* ================================================================
 * Event ring buffer
 * ================================================================ */
typedef struct {
    int nr;
    int pid;
    int uid;
    char comm[16];
    unsigned long a0, a1, a2, a3, a4, a5;
    char desc[DESC_BUF_SIZE];
} svc_event_t;

static svc_event_t g_events[MAX_EVENTS];
static volatile int g_ev_head = 0;    /* write position */
static volatile int g_ev_count = 0;   /* total events ever */

static void store_event(int nr, unsigned long a0, unsigned long a1,
                        unsigned long a2, unsigned long a3,
                        unsigned long a4, unsigned long a5,
                        const char *desc)
{
    int idx = g_ev_head;
    svc_event_t *ev = &g_events[idx];

    ev->nr = nr;
    ev->a0 = a0; ev->a1 = a1; ev->a2 = a2;
    ev->a3 = a3; ev->a4 = a4; ev->a5 = a5;

    /* Get PID and comm from current task */
    struct task_struct *task = current;
    ev->pid = task ? *(int *)((unsigned long)task + 0) : 0;
    /* Use a safer approach: just get uid via official API */
    ev->uid = (int)current_uid();

    /* Copy comm name from task->comm offset - use a simple default */
    if (task) {
        /* task_struct comm is typically at a known offset, but for safety
         * just copy a default; the desc field carries the real info */
        int i;
        const char *p = (const char *)((unsigned long)task + 2560); /* approx comm offset */
        for (i = 0; i < 15 && p[i]; i++)
            ev->comm[i] = p[i];
        ev->comm[i] = '\0';
    } else {
        ev->comm[0] = '?'; ev->comm[1] = '\0';
    }

    /* Copy desc */
    if (desc) {
        int i;
        for (i = 0; i < DESC_BUF_SIZE - 1 && desc[i]; i++)
            ev->desc[i] = desc[i];
        ev->desc[i] = '\0';
    } else {
        ev->desc[0] = '\0';
    }

    /* Advance ring buffer */
    g_ev_head = (idx + 1) % MAX_EVENTS;
    g_ev_count++;
}

/* ================================================================
 * Argument description helpers
 * ================================================================ */

/* Safe user string copy using official API */
static void safe_copy_user_str(char *dst, unsigned long uptr, int maxlen) {
    if (!uptr || uptr > 0x7ffffffffff0UL) {
        dst[0] = '\0';
        return;
    }
    long ret = compat_strncpy_from_user(dst, (const char __user *)uptr, maxlen);
    if (ret < 0) {
        dst[0] = '?'; dst[1] = '\0';
    }
}

/* Build description for well-known syscalls */
static void describe_args(int nr, unsigned long a0, unsigned long a1,
                          unsigned long a2, unsigned long a3,
                          unsigned long a4, unsigned long a5,
                          char *desc, int dlen)
{
    char pathbuf[PATH_BUF_SIZE];
    int n = 0;
    desc[0] = '\0';

    switch (nr) {
    case 56: /* openat */
        safe_copy_user_str(pathbuf, a1, sizeof(pathbuf));
        n = snprintf(desc, dlen, "dirfd=%d path=\"%s\" flags=0x%lx mode=0%lo",
                     (int)a0, pathbuf, a2, a3);
        break;
    case 57: /* close */
        n = snprintf(desc, dlen, "fd=%d", (int)a0);
        break;
    case 48: /* faccessat */
        safe_copy_user_str(pathbuf, a1, sizeof(pathbuf));
        n = snprintf(desc, dlen, "dirfd=%d path=\"%s\" mode=%d",
                     (int)a0, pathbuf, (int)a2);
        break;
    case 35: /* unlinkat */
        safe_copy_user_str(pathbuf, a1, sizeof(pathbuf));
        n = snprintf(desc, dlen, "dirfd=%d path=\"%s\" flags=0x%lx",
                     (int)a0, pathbuf, a2);
        break;
    case 78: /* readlinkat */
        safe_copy_user_str(pathbuf, a1, sizeof(pathbuf));
        n = snprintf(desc, dlen, "dirfd=%d path=\"%s\" bufsiz=%d",
                     (int)a0, pathbuf, (int)a3);
        break;
    case 63: /* read */
        n = snprintf(desc, dlen, "fd=%d buf=0x%lx count=%lu",
                     (int)a0, a1, a2);
        break;
    case 64: /* write */
        n = snprintf(desc, dlen, "fd=%d buf=0x%lx count=%lu",
                     (int)a0, a1, a2);
        break;
    case 221: /* execve */
        safe_copy_user_str(pathbuf, a0, sizeof(pathbuf));
        n = snprintf(desc, dlen, "filename=\"%s\"", pathbuf);
        break;
    case 281: /* execveat */
        safe_copy_user_str(pathbuf, a1, sizeof(pathbuf));
        n = snprintf(desc, dlen, "dirfd=%d filename=\"%s\" flags=0x%lx",
                     (int)a0, pathbuf, a4);
        break;
    case 220: /* clone */
        n = snprintf(desc, dlen, "flags=0x%lx stack=0x%lx", a0, a1);
        break;
    case 93: /* exit */
        n = snprintf(desc, dlen, "status=%d", (int)a0);
        break;
    case 94: /* exit_group */
        n = snprintf(desc, dlen, "status=%d", (int)a0);
        break;
    case 222: /* mmap */
        n = snprintf(desc, dlen, "addr=0x%lx len=%lu prot=0x%lx flags=0x%lx fd=%d off=0x%lx",
                     a0, a1, a2, a3, (int)a4, a5);
        break;
    case 226: /* mprotect */
        n = snprintf(desc, dlen, "addr=0x%lx len=%lu prot=0x%lx", a0, a1, a2);
        break;
    case 215: /* munmap */
        n = snprintf(desc, dlen, "addr=0x%lx len=%lu", a0, a1);
        break;
    case 214: /* brk */
        n = snprintf(desc, dlen, "addr=0x%lx", a0);
        break;
    case 198: /* socket */
        n = snprintf(desc, dlen, "domain=%d type=%d protocol=%d",
                     (int)a0, (int)a1, (int)a2);
        break;
    case 200: /* bind */
        n = snprintf(desc, dlen, "sockfd=%d addr=0x%lx addrlen=%d",
                     (int)a0, a1, (int)a2);
        break;
    case 203: /* connect */
        n = snprintf(desc, dlen, "sockfd=%d addr=0x%lx addrlen=%d",
                     (int)a0, a1, (int)a2);
        break;
    case 206: /* sendto */
        n = snprintf(desc, dlen, "sockfd=%d buf=0x%lx len=%lu flags=0x%lx",
                     (int)a0, a1, a2, a3);
        break;
    case 207: /* recvfrom */
        n = snprintf(desc, dlen, "sockfd=%d buf=0x%lx len=%lu flags=0x%lx",
                     (int)a0, a1, a2, a3);
        break;
    case 117: /* ptrace */
        n = snprintf(desc, dlen, "request=%ld pid=%d addr=0x%lx data=0x%lx",
                     (long)a0, (int)a1, a2, a3);
        break;
    case 167: /* prctl */
        n = snprintf(desc, dlen, "option=%d arg2=0x%lx arg3=0x%lx",
                     (int)a0, a1, a2);
        break;
    case 129: /* kill */
        n = snprintf(desc, dlen, "pid=%d sig=%d", (int)a0, (int)a1);
        break;
    case 131: /* tgkill */
        n = snprintf(desc, dlen, "tgid=%d tid=%d sig=%d",
                     (int)a0, (int)a1, (int)a2);
        break;
    case 134: /* rt_sigaction */
        n = snprintf(desc, dlen, "sig=%d act=0x%lx oact=0x%lx",
                     (int)a0, a1, a2);
        break;
    case 277: /* seccomp */
        n = snprintf(desc, dlen, "op=%d flags=0x%lx", (int)a0, a1);
        break;
    case 280: /* bpf */
        n = snprintf(desc, dlen, "cmd=%d attr=0x%lx size=%d",
                     (int)a0, a1, (int)a2);
        break;
    case 279: /* memfd_create */
        safe_copy_user_str(pathbuf, a0, sizeof(pathbuf));
        n = snprintf(desc, dlen, "name=\"%s\" flags=0x%lx", pathbuf, a1);
        break;
    case 29: /* ioctl */
        n = snprintf(desc, dlen, "fd=%d cmd=0x%lx arg=0x%lx",
                     (int)a0, a1, a2);
        break;
    case 40: /* mount */
        safe_copy_user_str(pathbuf, a1, sizeof(pathbuf));
        n = snprintf(desc, dlen, "target=\"%s\" flags=0x%lx", pathbuf, a3);
        break;
    case 146: /* setuid */
        n = snprintf(desc, dlen, "uid=%d", (int)a0);
        break;
    case 144: /* setgid */
        n = snprintf(desc, dlen, "gid=%d", (int)a0);
        break;
    case 105: /* init_module */
        n = snprintf(desc, dlen, "module_image=0x%lx len=%lu", a0, a1);
        break;
    case 273: /* finit_module */
        n = snprintf(desc, dlen, "fd=%d flags=0x%lx", (int)a0, a2);
        break;
    case 97: /* unshare */
        n = snprintf(desc, dlen, "flags=0x%lx", a0);
        break;
    case 268: /* setns */
        n = snprintf(desc, dlen, "fd=%d nstype=0x%lx", (int)a0, a1);
        break;
    default:
        n = snprintf(desc, dlen, "a0=0x%lx a1=0x%lx a2=0x%lx",
                     a0, a1, a2);
        break;
    }
    (void)n;
}

/* ================================================================
 * Generic hook callback (before only)
 * One callback for ALL syscalls, NR passed via udata.
 * ================================================================ */
static void before_generic(hook_fargs4_t *args, void *udata)
{
    int nr = (int)(unsigned long)udata;
    int uid;
    char desc[DESC_BUF_SIZE];
    unsigned long a0, a1, a2, a3, a4, a5;

    /* Fast rejection path */
    if (!g_enabled) return;
    if (!bitmap_test(g_nr_bitmap, nr)) return;

    uid = (int)current_uid();
    if (g_target_uid >= 0 && uid != g_target_uid) return;

    /* Read syscall arguments via official API */
    a0 = syscall_argn(args, 0);
    a1 = syscall_argn(args, 1);
    a2 = syscall_argn(args, 2);
    a3 = syscall_argn(args, 3);
    a4 = syscall_argn(args, 4);
    a5 = syscall_argn(args, 5);

    /* Build argument description */
    describe_args(nr, a0, a1, a2, a3, a4, a5, desc, sizeof(desc));

    /* Store event */
    store_event(nr, a0, a1, a2, a3, a4, a5, desc);
}

/* ================================================================
 * Hook management — track which NRs are hooked
 * ================================================================ */

/* Hook record: which NRs are hooked and with which method */
#define HOOK_INLINE 1
#define HOOK_FP     2

typedef struct {
    int nr;
    int narg;
    int method;   /* HOOK_INLINE or HOOK_FP */
    int active;   /* 1 if currently hooked */
} hook_record_t;

/* Tier 1: ~44 high-value syscalls, hooked on module load */
static hook_record_t tier1_hooks[] = {
    /* File operations */
    { 56, 4, 0, 0 },  /* openat */
    { 57, 1, 0, 0 },  /* close */
    { 48, 4, 0, 0 },  /* faccessat */
    { 35, 3, 0, 0 },  /* unlinkat */
    { 78, 4, 0, 0 },  /* readlinkat */
    { 61, 3, 0, 0 },  /* getdents64 */
    { 63, 3, 0, 0 },  /* read */
    { 64, 3, 0, 0 },  /* write */
    { 79, 4, 0, 0 },  /* newfstatat */
    { 291, 4, 0, 0 }, /* statx */
    { 276, 4, 0, 0 }, /* renameat2 */
    { 34, 3, 0, 0 },  /* mkdirat */

    /* Process management */
    { 220, 4, 0, 0 }, /* clone */
    { 221, 3, 0, 0 }, /* execve */
    { 281, 4, 0, 0 }, /* execveat */
    { 93,  1, 0, 0 }, /* exit */
    { 94,  1, 0, 0 }, /* exit_group */
    { 260, 4, 0, 0 }, /* wait4 */
    { 167, 4, 0, 0 }, /* prctl */
    { 117, 4, 0, 0 }, /* ptrace */

    /* Memory management */
    { 222, 4, 0, 0 }, /* mmap (uses 6 args but hook_fargs4_t works; use syscall_argn) */
    { 226, 3, 0, 0 }, /* mprotect */
    { 215, 2, 0, 0 }, /* munmap */
    { 214, 1, 0, 0 }, /* brk */
    { 233, 3, 0, 0 }, /* madvise */
    { 279, 2, 0, 0 }, /* memfd_create */

    /* Network */
    { 198, 3, 0, 0 }, /* socket */
    { 200, 3, 0, 0 }, /* bind */
    { 201, 2, 0, 0 }, /* listen */
    { 203, 3, 0, 0 }, /* connect */
    { 202, 3, 0, 0 }, /* accept */
    { 242, 4, 0, 0 }, /* accept4 */
    { 206, 4, 0, 0 }, /* sendto (6 args, same note as mmap) */
    { 207, 4, 0, 0 }, /* recvfrom (6 args) */

    /* Signals & Security */
    { 129, 2, 0, 0 }, /* kill */
    { 131, 3, 0, 0 }, /* tgkill */
    { 134, 3, 0, 0 }, /* rt_sigaction */
    { 277, 3, 0, 0 }, /* seccomp */
    { 268, 2, 0, 0 }, /* setns */
    { 97,  1, 0, 0 }, /* unshare */
    { 280, 3, 0, 0 }, /* bpf */
    { 270, 4, 0, 0 }, /* process_vm_readv (6 args) */
    { 271, 4, 0, 0 }, /* process_vm_writev (6 args) */
};
#define TIER1_COUNT (sizeof(tier1_hooks)/sizeof(tier1_hooks[0]))

/* Tier 2: ~20 extra syscalls, loaded on demand */
static hook_record_t tier2_hooks[] = {
    { 29,  3, 0, 0 },  /* ioctl */
    { 62,  3, 0, 0 },  /* lseek */
    { 65,  3, 0, 0 },  /* readv */
    { 66,  3, 0, 0 },  /* writev */
    { 25,  3, 0, 0 },  /* fcntl */
    { 71,  4, 0, 0 },  /* sendfile */
    { 211, 3, 0, 0 },  /* sendmsg */
    { 212, 3, 0, 0 },  /* recvmsg */
    { 208, 4, 0, 0 },  /* setsockopt (5 args) */
    { 209, 4, 0, 0 },  /* getsockopt (5 args) */
    { 40,  4, 0, 0 },  /* mount (5 args) */
    { 39,  2, 0, 0 },  /* umount2 */
    { 261, 4, 0, 0 },  /* prlimit64 */
    { 90,  2, 0, 0 },  /* capget */
    { 91,  2, 0, 0 },  /* capset */
    { 146, 1, 0, 0 },  /* setuid */
    { 144, 1, 0, 0 },  /* setgid */
    { 273, 3, 0, 0 },  /* finit_module */
    { 105, 3, 0, 0 },  /* init_module */
    { 106, 2, 0, 0 },  /* delete_module */
};
#define TIER2_COUNT (sizeof(tier2_hooks)/sizeof(tier2_hooks[0]))

/* Install a single hook: try inline first, fallback to fp */
static int install_hook(hook_record_t *h)
{
    hook_err_t err;

    if (h->active) return 0; /* already hooked */

    /* Try inline hook first */
    err = inline_hook_syscalln(h->nr, h->narg, before_generic, 0,
                               (void *)(unsigned long)h->nr);
    if (err == HOOK_NO_ERR) {
        h->method = HOOK_INLINE;
        h->active = 1;
        g_hooks_installed++;
        return 0;
    }

    /* Fallback to function pointer hook */
    err = fp_hook_syscalln(h->nr, h->narg, before_generic, 0,
                           (void *)(unsigned long)h->nr);
    if (err == HOOK_NO_ERR) {
        h->method = HOOK_FP;
        h->active = 1;
        g_hooks_installed++;
        return 0;
    }

    pr_err("svc_monitor: failed to hook NR %d, err=%d\n", h->nr, err);
    return -1;
}

/* Remove a single hook */
static void remove_hook(hook_record_t *h)
{
    if (!h->active) return;

    if (h->method == HOOK_INLINE) {
        inline_unhook_syscalln(h->nr, before_generic, 0);
    } else if (h->method == HOOK_FP) {
        fp_unhook_syscalln(h->nr, before_generic, 0);
    }
    h->active = 0;
    h->method = 0;
    if (g_hooks_installed > 0) g_hooks_installed--;
}

/* Install all tier1 hooks */
static int install_tier1(void)
{
    int i, ok = 0;
    for (i = 0; i < (int)TIER1_COUNT; i++) {
        if (install_hook(&tier1_hooks[i]) == 0) ok++;
    }
    pr_info("svc_monitor: tier1 installed %d/%d hooks\n", ok, (int)TIER1_COUNT);
    return ok;
}

/* Remove all tier1 hooks */
static void remove_tier1(void)
{
    int i;
    for (i = 0; i < (int)TIER1_COUNT; i++) {
        remove_hook(&tier1_hooks[i]);
    }
}

/* Install all tier2 hooks */
static int install_tier2(void)
{
    int i, ok = 0;
    for (i = 0; i < (int)TIER2_COUNT; i++) {
        if (install_hook(&tier2_hooks[i]) == 0) ok++;
    }
    g_tier2_loaded = 1;
    pr_info("svc_monitor: tier2 installed %d/%d hooks\n", ok, (int)TIER2_COUNT);
    return ok;
}

/* Remove all tier2 hooks */
static void remove_tier2(void)
{
    int i;
    for (i = 0; i < (int)TIER2_COUNT; i++) {
        remove_hook(&tier2_hooks[i]);
    }
    g_tier2_loaded = 0;
}

/* ================================================================
 * Presets — each sets a predefined group of NRs in the bitmap
 * ================================================================ */
static void apply_preset(const char *name)
{
    int i;
    /* Clear bitmap first */
    for (i = 0; i < BITMAP_LONGS; i++)
        g_nr_bitmap[i] = 0;

    if (!strcmp(name, "re_basic")) {
        int nrs[] = {56,63,64,222,226,167,117,220,221,281,203};
        for (i = 0; i < (int)(sizeof(nrs)/sizeof(nrs[0])); i++)
            bitmap_set(g_nr_bitmap, nrs[i]);
    } else if (!strcmp(name, "re_full")) {
        int nrs[] = {56,57,63,64,222,226,215,214,233,279,167,117,
                     220,221,281,93,94,203,198,280,129,131,277,134};
        for (i = 0; i < (int)(sizeof(nrs)/sizeof(nrs[0])); i++)
            bitmap_set(g_nr_bitmap, nrs[i]);
    } else if (!strcmp(name, "file")) {
        int nrs[] = {56,57,48,35,78,61,63,64,79,291,276,34};
        for (i = 0; i < (int)(sizeof(nrs)/sizeof(nrs[0])); i++)
            bitmap_set(g_nr_bitmap, nrs[i]);
    } else if (!strcmp(name, "net")) {
        int nrs[] = {198,200,201,203,202,242,206,207,208,209,211,212};
        for (i = 0; i < (int)(sizeof(nrs)/sizeof(nrs[0])); i++)
            bitmap_set(g_nr_bitmap, nrs[i]);
    } else if (!strcmp(name, "proc")) {
        int nrs[] = {220,221,281,93,94,260,129,131,117,167};
        for (i = 0; i < (int)(sizeof(nrs)/sizeof(nrs[0])); i++)
            bitmap_set(g_nr_bitmap, nrs[i]);
    } else if (!strcmp(name, "mem")) {
        int nrs[] = {222,226,215,214,233,279,270,271};
        for (i = 0; i < (int)(sizeof(nrs)/sizeof(nrs[0])); i++)
            bitmap_set(g_nr_bitmap, nrs[i]);
    } else if (!strcmp(name, "security")) {
        int nrs[] = {117,167,277,268,97,280,146,144,90,91,105,273,106};
        for (i = 0; i < (int)(sizeof(nrs)/sizeof(nrs[0])); i++)
            bitmap_set(g_nr_bitmap, nrs[i]);
    } else if (!strcmp(name, "all")) {
        /* Enable all hooked NRs */
        for (i = 0; i < (int)TIER1_COUNT; i++)
            if (tier1_hooks[i].active) bitmap_set(g_nr_bitmap, tier1_hooks[i].nr);
        for (i = 0; i < (int)TIER2_COUNT; i++)
            if (tier2_hooks[i].active) bitmap_set(g_nr_bitmap, tier2_hooks[i].nr);
    }
}

/* ================================================================
 * Simple integer parser (no stdlib)
 * ================================================================ */
static int parse_int(const char *s, int *consumed)
{
    int neg = 0, val = 0, c = 0;
    if (*s == '-') { neg = 1; s++; c++; }
    while (*s >= '0' && *s <= '9') {
        val = val * 10 + (*s - '0');
        s++; c++;
    }
    if (consumed) *consumed = c;
    return neg ? -val : val;
}

/* ================================================================
 * JSON output via file (kernel file write)
 * ================================================================ */

/* Simple kernel file write using raw_syscall */
static int write_output_file(const char *data, int len)
{
    long fd;
    /* Use raw_syscall to open, write, close the output file */
    /* openat(AT_FDCWD, path, O_WRONLY|O_CREAT|O_TRUNC, 0644) */
    fd = raw_syscall4(__NR_openat, -100, (long)OUTPUT_PATH,
                      0x241 /* O_WRONLY|O_CREAT|O_TRUNC */, 0644);
    if (fd < 0) return -1;

    raw_syscall3(__NR_write, fd, (long)data, len);
    raw_syscall1(__NR_close, fd);
    return 0;
}

/* Buffer for building JSON output */
static char g_outbuf[65536];

/* ================================================================
 * Escape a string for JSON output
 * ================================================================ */
static int json_escape(char *dst, int dstlen, const char *src)
{
    int i = 0;
    while (*src && i < dstlen - 2) {
        if (*src == '"' || *src == '\\') {
            dst[i++] = '\\';
            if (i >= dstlen - 1) break;
        }
        if (*src == '\n') {
            dst[i++] = '\\'; if (i >= dstlen - 1) break;
            dst[i++] = 'n';
        } else if (*src == '\r') {
            dst[i++] = '\\'; if (i >= dstlen - 1) break;
            dst[i++] = 'r';
        } else if (*src == '\t') {
            dst[i++] = '\\'; if (i >= dstlen - 1) break;
            dst[i++] = 't';
        } else {
            dst[i++] = *src;
        }
        src++;
    }
    dst[i] = '\0';
    return i;
}

/* ================================================================
 * CTL0 command handler
 * ================================================================ */
static long svc_ctl0(const char *args, char *__user out_msg, int outlen)
{
    int n = 0;
    char *buf = g_outbuf;
    int blen = sizeof(g_outbuf);
    char esc[DESC_BUF_SIZE];

    /* ---- status ---- */
    if (!strcmp(args, "status")) {
        int nr_logging = 0, i;
        for (i = 0; i < MAX_NR; i++) {
            if (bitmap_test(g_nr_bitmap, i)) nr_logging++;
        }
        n = snprintf(buf, blen,
            "{\"ok\":true,\"version\":\"8.0.0\",\"enabled\":%s,"
            "\"target_uid\":%d,\"hooks_installed\":%d,"
            "\"nrs_logging\":%d,\"events_total\":%d,"
            "\"events_buffered\":%d,\"tier2\":%s,"
            "\"logging_nrs\":[",
            g_enabled ? "true" : "false",
            g_target_uid, g_hooks_installed,
            nr_logging, g_ev_count,
            g_ev_count < MAX_EVENTS ? g_ev_count : MAX_EVENTS,
            g_tier2_loaded ? "true" : "false");

        /* List active logging NRs */
        int first = 1;
        for (i = 0; i < MAX_NR; i++) {
            if (bitmap_test(g_nr_bitmap, i)) {
                if (!first) n += snprintf(buf + n, blen - n, ",");
                n += snprintf(buf + n, blen - n, "%d", i);
                first = 0;
            }
        }
        n += snprintf(buf + n, blen - n, "],\"hooks\":[");

        /* List installed hooks */
        first = 1;
        for (i = 0; i < (int)TIER1_COUNT; i++) {
            if (tier1_hooks[i].active) {
                if (!first) n += snprintf(buf + n, blen - n, ",");
                n += snprintf(buf + n, blen - n, "{\"nr\":%d,\"name\":\"%s\",\"method\":\"%s\"}",
                    tier1_hooks[i].nr, get_syscall_name(tier1_hooks[i].nr),
                    tier1_hooks[i].method == HOOK_INLINE ? "inline" : "fp");
                first = 0;
            }
        }
        for (i = 0; i < (int)TIER2_COUNT; i++) {
            if (tier2_hooks[i].active) {
                if (!first) n += snprintf(buf + n, blen - n, ",");
                n += snprintf(buf + n, blen - n, "{\"nr\":%d,\"name\":\"%s\",\"method\":\"%s\"}",
                    tier2_hooks[i].nr, get_syscall_name(tier2_hooks[i].nr),
                    tier2_hooks[i].method == HOOK_INLINE ? "inline" : "fp");
                first = 0;
            }
        }
        n += snprintf(buf + n, blen - n, "]}");
    }

    /* ---- uid <n> ---- */
    else if (!strncmp(args, "uid ", 4)) {
        g_target_uid = parse_int(args + 4, 0);
        n = snprintf(buf, blen, "{\"ok\":true,\"target_uid\":%d}", g_target_uid);
    }

    /* ---- enable ---- (enable monitoring / start) */
    else if (!strcmp(args, "enable") || !strcmp(args, "resume") || !strcmp(args, "start")) {
        g_enabled = 1;
        n = snprintf(buf, blen, "{\"ok\":true,\"enabled\":true}");
    }

    /* ---- disable ---- (pause monitoring) */
    else if (!strcmp(args, "disable") || !strcmp(args, "pause") || !strcmp(args, "stop")) {
        g_enabled = 0;
        n = snprintf(buf, blen, "{\"ok\":true,\"enabled\":false}");
    }

    /* ---- enable_nr <n> ---- */
    else if (!strncmp(args, "enable_nr ", 10)) {
        int nr = parse_int(args + 10, 0);
        bitmap_set(g_nr_bitmap, nr);
        n = snprintf(buf, blen, "{\"ok\":true,\"enabled_nr\":%d}", nr);
    }

    /* ---- disable_nr <n> ---- */
    else if (!strncmp(args, "disable_nr ", 11)) {
        int nr = parse_int(args + 11, 0);
        bitmap_clear(g_nr_bitmap, nr);
        n = snprintf(buf, blen, "{\"ok\":true,\"disabled_nr\":%d}", nr);
    }

    /* ---- set_nrs <n1>,<n2>,... ---- */
    else if (!strncmp(args, "set_nrs ", 8)) {
        int i;
        const char *p = args + 8;
        int cnt = 0;
        /* Clear bitmap */
        for (i = 0; i < BITMAP_LONGS; i++)
            g_nr_bitmap[i] = 0;
        /* Parse comma-separated NRs */
        while (*p) {
            while (*p == ' ' || *p == ',') p++;
            if (*p == '\0') break;
            int consumed = 0;
            int nr = parse_int(p, &consumed);
            if (consumed > 0) {
                bitmap_set(g_nr_bitmap, nr);
                cnt++;
                p += consumed;
            } else {
                p++;
            }
        }
        n = snprintf(buf, blen, "{\"ok\":true,\"set_nrs_count\":%d}", cnt);
    }

    /* ---- enable_all ---- */
    else if (!strcmp(args, "enable_all")) {
        int i;
        for (i = 0; i < (int)TIER1_COUNT; i++)
            if (tier1_hooks[i].active) bitmap_set(g_nr_bitmap, tier1_hooks[i].nr);
        for (i = 0; i < (int)TIER2_COUNT; i++)
            if (tier2_hooks[i].active) bitmap_set(g_nr_bitmap, tier2_hooks[i].nr);
        n = snprintf(buf, blen, "{\"ok\":true}");
    }

    /* ---- disable_all ---- */
    else if (!strcmp(args, "disable_all")) {
        int i;
        for (i = 0; i < BITMAP_LONGS; i++)
            g_nr_bitmap[i] = 0;
        n = snprintf(buf, blen, "{\"ok\":true}");
    }

    /* ---- preset <name> ---- */
    else if (!strncmp(args, "preset ", 7)) {
        apply_preset(args + 7);
        n = snprintf(buf, blen, "{\"ok\":true,\"preset\":\"%s\"}", args + 7);
    }

    /* ---- tier2 on/off ---- */
    else if (!strcmp(args, "tier2 on")) {
        if (!g_tier2_loaded) {
            install_tier2();
        }
        n = snprintf(buf, blen, "{\"ok\":true,\"tier2\":true}");
    }
    else if (!strcmp(args, "tier2 off")) {
        if (g_tier2_loaded) {
            remove_tier2();
        }
        n = snprintf(buf, blen, "{\"ok\":true,\"tier2\":false}");
    }

    /* ---- drain <max> ---- */
    else if (!strncmp(args, "drain ", 6) || !strcmp(args, "drain")) {
        int max = 50;
        if (!strncmp(args, "drain ", 6)) max = parse_int(args + 6, 0);
        if (max <= 0) max = 50;
        if (max > MAX_EVENTS) max = MAX_EVENTS;

        int avail = g_ev_count < MAX_EVENTS ? g_ev_count : MAX_EVENTS;
        int count = avail < max ? avail : max;
        int start;

        n = snprintf(buf, blen, "{\"ok\":true,\"count\":%d,\"total\":%d,\"events\":[", count, g_ev_count);

        if (count > 0) {
            start = (g_ev_head - avail + MAX_EVENTS) % MAX_EVENTS;
            /* Only return the most recent 'count' events */
            int skip = avail - count;
            start = (start + skip) % MAX_EVENTS;

            int i;
            for (i = 0; i < count && n < blen - 512; i++) {
                int idx = (start + i) % MAX_EVENTS;
                svc_event_t *ev = &g_events[idx];
                json_escape(esc, sizeof(esc), ev->desc);

                if (i > 0) n += snprintf(buf + n, blen - n, ",");
                n += snprintf(buf + n, blen - n,
                    "{\"nr\":%d,\"name\":\"%s\",\"pid\":%d,\"uid\":%d,"
                    "\"comm\":\"%s\",\"a0\":%lu,\"a1\":%lu,\"a2\":%lu,"
                    "\"a3\":%lu,\"a4\":%lu,\"a5\":%lu,\"desc\":\"%s\"}",
                    ev->nr, get_syscall_name(ev->nr), ev->pid, ev->uid,
                    ev->comm, ev->a0, ev->a1, ev->a2,
                    ev->a3, ev->a4, ev->a5, esc);
            }
        }
        n += snprintf(buf + n, blen - n, "]}");

        /* Clear events after drain */
        g_ev_head = 0;
        g_ev_count = 0;
    }

    /* ---- events (alias for drain 50) ---- */
    else if (!strcmp(args, "events")) {
        /* Redirect to drain logic with max=50 */
        return svc_ctl0("drain 50", out_msg, outlen);
    }

    /* ---- clear ---- */
    else if (!strcmp(args, "clear")) {
        g_ev_head = 0;
        g_ev_count = 0;
        n = snprintf(buf, blen, "{\"ok\":true,\"cleared\":true}");
    }

    /* ---- unknown command ---- */
    else {
        n = snprintf(buf, blen, "{\"ok\":false,\"error\":\"unknown command: %s\"}", args);
    }

    /* Write to output file */
    if (n > 0) {
        write_output_file(buf, n);
    }

    /* Also copy to out_msg if possible */
    if (out_msg && outlen > 0) {
        int copy = n < outlen - 1 ? n : outlen - 1;
        if (copy > 0) {
            compat_copy_to_user(out_msg, buf, copy);
        }
    }

    return 0;
}

/* ================================================================
 * Module init — install tier1 hooks, set default NR filter
 * ================================================================ */
static long svc_init(const char *args, const char *event, void *__user reserved)
{
    int ok;

    pr_info("svc_monitor: v8.0 init, always-on architecture\n");

    /* Clear state */
    memset((void *)g_nr_bitmap, 0, sizeof(g_nr_bitmap));
    g_ev_head = 0;
    g_ev_count = 0;
    g_enabled = 0;          /* Start paused, APP sends "enable" when ready */
    g_target_uid = -1;
    g_hooks_installed = 0;
    g_tier2_loaded = 0;

    /* Install tier1 hooks */
    ok = install_tier1();
    if (ok == 0) {
        pr_err("svc_monitor: failed to install any hooks!\n");
        return -1;
    }

    /* Set default logging NRs (逆向基础 preset) */
    apply_preset("re_basic");

    pr_info("svc_monitor: init complete, %d hooks installed, waiting for enable command\n", ok);
    return 0;
}

/* ================================================================
 * Module exit — remove all hooks
 * ================================================================ */
static long svc_exit(void *__user reserved)
{
    pr_info("svc_monitor: exit, removing all hooks\n");

    g_enabled = 0;

    /* Remove tier2 if loaded */
    if (g_tier2_loaded) {
        remove_tier2();
    }

    /* Remove tier1 */
    remove_tier1();

    pr_info("svc_monitor: all hooks removed, exit complete\n");
    return 0;
}

KPM_INIT(svc_init);
KPM_CTL0(svc_ctl0);
KPM_EXIT(svc_exit);
