/* ============================================================================
 * caller_resolver.c - ARM64 调用者解析实现
 * ============================================================================
 * 版本: 3.0.0
 * 描述: 解析系统调用的用户空间调用者信息
 *       - 从 pt_regs 获取 PC 和 LR
 *       - ARM64 Frame Pointer chain 回溯
 *       - PAC (Pointer Authentication Code) 标签清除
 *       - 安全的用户空间内存读取
 * ============================================================================ */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <asm/processor.h>
#include <linux/sched.h>
#include "svc_tracer.h"

/* --------------------------------------------------------------------------
 * ARM64 PAC 掩码
 * --------------------------------------------------------------------------
 * PAC 使用地址高位存储签名, 需要清除这些位以获得真实地址
 * 用户空间地址通常在 [0, 0x0000FFFFFFFFFFFF] 范围内
 * -------------------------------------------------------------------------- */
#define PAC_MASK 0x0000FFFFFFFFFFFFul

static inline unsigned long strip_pac(unsigned long addr)
{
    return addr & PAC_MASK;
}

/* --------------------------------------------------------------------------
 * 用户空间地址范围检查
 * -------------------------------------------------------------------------- */
#define USER_ADDR_MAX  0x0000FFFFFFFFFFFFul

static inline int is_user_addr(unsigned long addr)
{
    return (addr > 0 && addr <= USER_ADDR_MAX);
}

/* --------------------------------------------------------------------------
 * safe_read_ulong - 安全读取用户空间 unsigned long 值
 * -------------------------------------------------------------------------- */
static int safe_read_ulong(unsigned long user_addr, unsigned long *out)
{
    if (!is_user_addr(user_addr) || !out)
        return -1;

    if (!kfunc_copy_from_user)
        return -1;

    if (kfunc_copy_from_user(out, (const void __user *)user_addr,
                              sizeof(unsigned long)) != 0) {
        return -1;
    }
    return 0;
}

/* ============================================================================
 * caller_resolver_init - 初始化
 * ============================================================================ */
int caller_resolver_init(void)
{
    pr_info("[svc-tracer] caller_resolver: initialized\n");
    return 0;
}

/* ============================================================================
 * caller_resolve - 获取调用者 PC、LR、模块名、偏移量
 * ============================================================================
 * 从当前线程的 pt_regs 获取 PC 和 LR (用户空间寄存器)
 * 模块名和偏移量通过 maps_cache 在调用侧查询
 * ============================================================================ */
void caller_resolve(unsigned long *pc_out, unsigned long *lr_out,
                     char *module_out, unsigned long *offset_out)
{
    struct pt_regs *regs;
    unsigned long pc = 0, lr = 0;

    /* 初始化输出 */
    if (pc_out) *pc_out = 0;
    if (lr_out) *lr_out = 0;
    if (module_out) module_out[0] = '\0';
    if (offset_out) *offset_out = 0;

    /*
     * 获取用户空间寄存器:
     * 在 syscall 上下文中, current 的 pt_regs 在内核栈顶部
     * 通过 task_pt_regs(current) 获取
     */
    regs = task_pt_regs(current);

    if (!regs)
        return;

    /* PC: 用户空间的 ELR_EL1 (异常返回地址) */
    pc = strip_pac(regs->pc);
    /* LR: 用户空间的 X30 */
    lr = strip_pac(regs->regs[30]);

    if (pc_out) *pc_out = pc;
    if (lr_out) *lr_out = lr;

    /* 模块信息通过 maps_cache 在调用侧查询 */
}

/* ============================================================================
 * caller_backtrace - ARM64 Frame Pointer chain 回溯
 * ============================================================================
 * ARM64 FP chain 结构 (AAPCS64):
 *   FP (X29) -> [saved_FP | saved_LR]
 *                    |
 *                    v
 *                [saved_FP | saved_LR]
 *                    |
 *                   ...
 *
 * 每个栈帧: FP 指向 [上一个FP (8字节), 返回地址 (8字节)]
 *
 * 安全措施:
 * - 地址有效性检查 (用户空间范围)
 * - PAC 标签清除
 * - 最大深度限制 (MAX_BACKTRACE_DEPTH = 16)
 * - 检测循环 (FP 不递增则停止)
 *
 * 返回: 实际回溯深度
 * ============================================================================ */
int caller_backtrace(unsigned long *bt_out, int max_depth)
{
    struct pt_regs *regs;
    unsigned long fp, prev_fp;
    unsigned long frame[2]; /* [saved_fp, saved_lr] */
    int depth = 0;

    if (!bt_out || max_depth <= 0)
        return 0;

    if (max_depth > MAX_BACKTRACE_DEPTH)
        max_depth = MAX_BACKTRACE_DEPTH;

    /* 获取 pt_regs */
    regs = task_pt_regs(current);
    if (!regs)
        return 0;

    /* 第一层: PC */
    bt_out[depth++] = strip_pac(regs->pc);
    if (depth >= max_depth)
        return depth;

    /* 第二层: LR (X30) */
    bt_out[depth++] = strip_pac(regs->regs[30]);
    if (depth >= max_depth)
        return depth;

    /* 从 FP (X29) 开始遍历 frame chain */
    fp = strip_pac(regs->regs[29]);
    prev_fp = 0;

    while (depth < max_depth && is_user_addr(fp)) {
        /* 对齐检查: FP 必须 16 字节对齐 */
        if (fp & 0xF)
            break;

        /* 防止循环: FP 必须递增 */
        if (prev_fp != 0 && fp <= prev_fp)
            break;

        /* 读取栈帧: [saved_fp, saved_lr] */
        if (safe_read_ulong(fp, &frame[0]) != 0)
            break;
        if (safe_read_ulong(fp + 8, &frame[1]) != 0)
            break;

        /* saved_lr 是返回地址 */
        unsigned long ret_addr = strip_pac(frame[1]);
        if (!is_user_addr(ret_addr))
            break;

        bt_out[depth++] = ret_addr;

        /* 移动到上一个栈帧 */
        prev_fp = fp;
        fp = strip_pac(frame[0]);
    }

    return depth;
}
