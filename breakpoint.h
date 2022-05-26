#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#include <uthash.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/user.h>

#include "proc_ptrace.h"

#define MAX_DEPTH 16

#define SHOW_FUNC_NAME 1
#define SHOW_BACKTRACE 2
#define SHOW_FLOW 4
/*
 * host_file: The path show in /proc/<pid>/maps
 * host_offset: The offset in the library
 *
 * Example:
 *   readelf -s ./victim | grep foo --> 0x1258
 *
 * When execute foo in victim, expect run foo in libmax.so first
 *
 * breakpoints:
 *  - host_file: /home/lnx/mycode/infect/victim
 *    host_offset: 0x1258
 *    func_name: foo
 *  - host_file: ...
 *    ...
 *
 */

struct addr_key_ {
    pid_t tid;
    long addr;
} __attribute__((packed));

typedef struct breakpoint_info_ {
    /* func_name for display purpose, also used as key */
    char *func_name;
    struct addr_key_ sys_addr;

    int func_size;
    long orig_code;
    /* If this is return, it is dynamic, should be removed automatically when hitten */
    bool is_return;
    int debug_flag;

    /* host_file is so libaray, if not specified, it is self */
    char *host_file;
    long host_offset;

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
void load_breakpoint_set (pid_t pid, const char *bp_fn);
int remote_backtrace (struct traced_process_ *proc, int tid, long trace_ip[MAX_DEPTH]);
void breakpoint_exit_loop (void);

typedef int (*api_callback_fn)(pid_t tid, struct breakpoint_info_ *bp,
                               struct user_regs_struct *regs);
int regist_api_hook (api_callback_fn fn);
#endif
