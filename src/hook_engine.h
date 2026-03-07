/* ============================================================================
 * hook_engine.h - Hook 引擎头文件
 * ============================================================================
 * 描述: 系统调用 hook 安装与管理接口
 * ============================================================================ */

#ifndef _HOOK_ENGINE_H_
#define _HOOK_ENGINE_H_

/* 系统调用 hook 定义结构体 */
struct syscall_hook_def {
    int nr;             /* ARM64 系统调用号 (__NR_xxx) */
    int narg;           /* 参数数量 (0-6) */
    const char *name;   /* 系统调用名称 (用于日志) */
    unsigned char cat;  /* 类别 (SC_CAT_xxx) */
};

/* 公共接口 (在 svc_tracer.h 中声明) */
/* int hook_engine_init(void);       */
/* void hook_engine_destroy(void);   */
/* int hook_install_slim(void);      */
/* int hook_install_all(void);       */
/* int hook_install_range(int max);  */
/* int hook_get_count(void);         */

#endif /* _HOOK_ENGINE_H_ */
