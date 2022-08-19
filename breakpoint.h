#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#include <stdio.h>
#include <uthash.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/user.h>

#include "proc_ptrace.h"

#define MAX_DEPTH 16

#define SHOW_FUNC_NAME 1
#define SHOW_BACKTRACE 2
#define BREAK_ON_RETURN 4
#define MAX_INFO_LEN 128

/*
 * so_name: The path show in /proc/<pid>/maps
 * api_offset: The offset in the library
 *
 * Example:
 *   readelf -s ./victim | grep foo --> 0x1258
 *
 * When execute foo in victim, expect run foo in libmax.so first
 *
 * breakpoints:
 *  - so_name: /home/lnx/mycode/infect/victim
 *    api_offset: 0x1258
 *    api_name: foo
 *  - so_name: ...
 *    ...
 *
 */

struct addr_key_ {
    pid_t tid;
    long addr;
} __attribute__((packed));

typedef struct breakpoint_info_ {
    /* api_name for display purpose, also used as key */
    char *api_name;
    struct addr_key_ sys_addr;

    long orig_code;
    /* If this is return, it is dynamic, should be removed automatically when hitten */
    bool is_return;
    int debug_flag;

    /* so_name is so libaray, if not specified, it is self */
    char *so_name;
    long api_offset;

    UT_hash_handle sys_addr_hdl;
    UT_hash_handle api_name_hdl;
    UT_hash_handle pending_hdl;
} breakpoint_info_t;

int read_breakpoint_config (const char *cfg_file);
void relocate_breakpoint_addr (int pid);
void display_all_breakpoints (void);

int breakpoint_main_loop (int traced);
void configure_breakpoint (pid_t pid, struct breakpoint_info_ *bp);
void restore_all_bp (pid_t target_pid);
struct bp_info_* update_api_address (pid_t pid, const char *api_name);
struct bp_info_* get_entry_breakpoint (long rip);
int commit_breakpoint (pid_t tid, long addr);
int get_tid_cnt (struct traced_process_ *proc);
struct breakpoint_info_* get_breakpoint_via_addr (pid_t pid, long addr);
int enable_breakpoint_via_name (char *name);
int request_pending_breakpoint (char *name, int flag);
void disable_all_breakpoints (pid_t target_pid);
int remote_backtrace (struct traced_process_ *proc, int tid, long trace_ip[MAX_DEPTH]);
void breakpoint_exit_loop (void);
int load_active_breakpoints (FILE *bfp, pid_t pid);
void load_api_addr_info (FILE *fp, pid_t pid);
typedef int (*api_callback_fn)(pid_t tid, struct breakpoint_info_ *bp,
                               struct user_regs_struct *regs);
int regist_api_hook (api_callback_fn fn);
#endif
