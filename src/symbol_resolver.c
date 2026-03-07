/* ============================================================================
 * symbol_resolver.c - 内核符号运行时解析
 * ============================================================================
 * 版本: 3.0.0
 * 描述: 使用 KernelPatch 提供的 kallsyms_lookup_name 在运行时
 *       解析需要的内核函数地址, 存入全局函数指针供其他模块使用
 *
 * 解析的符号:
 *   - ktime_get_ns          : 高精度时间戳
 *   - __arch_copy_from_user : 安全读取用户空间内存
 *   - filp_open             : 打开文件
 *   - filp_close            : 关闭文件
 *   - kernel_write          : 内核空间写文件
 * ============================================================================ */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include "svc_tracer.h"

/* --------------------------------------------------------------------------
 * 全局函数指针 (其他模块通过 extern 引用)
 * -------------------------------------------------------------------------- */

/* ktime_get_ns: 返回纳秒级时间戳 */
unsigned long long (*kfunc_ktime_get_ns)(void) = NULL;

/* __arch_copy_from_user: 安全读取用户空间内存
 * 返回: 未能复制的字节数 (0=成功) */
unsigned long (*kfunc_copy_from_user)(void *to, const void __user *from,
                                      unsigned long n) = NULL;

/* filp_open: 打开内核文件
 * 返回: struct file* 或 ERR_PTR */
void *(*kfunc_filp_open)(const char *filename, int flags,
                          unsigned short mode) = NULL;

/* filp_close: 关闭内核文件 */
int (*kfunc_filp_close)(void *filp, void *id) = NULL;

/* kernel_write: 从内核空间写文件
 * 返回: 写入的字节数或负值错误码 */
long (*kfunc_kernel_write)(void *filp, const void *buf,
                            unsigned long count, long long *pos) = NULL;

/* ============================================================================
 * symbol_resolver_init - 解析所有需要的内核符号
 * ============================================================================
 * 使用 KernelPatch 提供的 kallsyms_lookup_name 函数
 * 该函数在 KPM 环境中全局可用
 *
 * 返回: 0 成功 (关键符号全部解析)
 *       -1 失败 (关键符号缺失)
 * ============================================================================ */
int symbol_resolver_init(void)
{
    int critical_ok = 1;

    pr_info("[svc-tracer] symbol_resolver: resolving kernel symbols...\n");

    /* ktime_get_ns - 用于时间戳 */
    kfunc_ktime_get_ns = (typeof(kfunc_ktime_get_ns))
        kallsyms_lookup_name("ktime_get_ns");
    if (kfunc_ktime_get_ns) {
        pr_info("[svc-tracer]   ktime_get_ns = %px\n",
                (void *)kfunc_ktime_get_ns);
    } else {
        pr_warn("[svc-tracer]   ktime_get_ns: NOT FOUND (non-critical)\n");
    }

    /* __arch_copy_from_user - 关键符号, 用于安全读取用户空间内存 */
    kfunc_copy_from_user = (typeof(kfunc_copy_from_user))
        kallsyms_lookup_name("__arch_copy_from_user");
    if (!kfunc_copy_from_user) {
        /* 备选: _copy_from_user */
        kfunc_copy_from_user = (typeof(kfunc_copy_from_user))
            kallsyms_lookup_name("_copy_from_user");
    }
    if (!kfunc_copy_from_user) {
        /* 备选: raw_copy_from_user */
        kfunc_copy_from_user = (typeof(kfunc_copy_from_user))
            kallsyms_lookup_name("raw_copy_from_user");
    }
    if (kfunc_copy_from_user) {
        pr_info("[svc-tracer]   copy_from_user = %px\n",
                (void *)kfunc_copy_from_user);
    } else {
        pr_err("[svc-tracer]   copy_from_user: NOT FOUND (CRITICAL)\n");
        critical_ok = 0;
    }

    /* filp_open - 用于文件日志和 maps/packages 读取 */
    kfunc_filp_open = (typeof(kfunc_filp_open))
        kallsyms_lookup_name("filp_open");
    if (kfunc_filp_open) {
        pr_info("[svc-tracer]   filp_open = %px\n",
                (void *)kfunc_filp_open);
    } else {
        pr_warn("[svc-tracer]   filp_open: NOT FOUND (file logging disabled)\n");
    }

    /* filp_close - 用于文件日志 */
    kfunc_filp_close = (typeof(kfunc_filp_close))
        kallsyms_lookup_name("filp_close");
    if (kfunc_filp_close) {
        pr_info("[svc-tracer]   filp_close = %px\n",
                (void *)kfunc_filp_close);
    } else {
        pr_warn("[svc-tracer]   filp_close: NOT FOUND\n");
    }

    /* kernel_write - 用于文件日志 */
    kfunc_kernel_write = (typeof(kfunc_kernel_write))
        kallsyms_lookup_name("kernel_write");
    if (!kfunc_kernel_write) {
        /* 备选: __kernel_write */
        kfunc_kernel_write = (typeof(kfunc_kernel_write))
            kallsyms_lookup_name("__kernel_write");
    }
    if (kfunc_kernel_write) {
        pr_info("[svc-tracer]   kernel_write = %px\n",
                (void *)kfunc_kernel_write);
    } else {
        pr_warn("[svc-tracer]   kernel_write: NOT FOUND (file logging disabled)\n");
    }

    /* 总结 */
    pr_info("[svc-tracer] symbol_resolver: done, critical=%s\n",
            critical_ok ? "OK" : "MISSING");

    return critical_ok ? 0 : -1;
}
