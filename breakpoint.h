#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#include <stdio.h>
#include <uthash.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/user.h>

#include <libunwind.h>
#include <libunwind-ptrace.h>

#define PLUGIN_NAME "ibut_plugin.so"

/* If there is a recursive call, the depth will be deep */
#define MAX_DEPTH 64
#define MAX_HOOK_FN_LEN 64

#define SHOW_API_NAME 1
#define SHOW_BACKTRACE 2
#define GENERATE_CORE 4
#define INVOKE_USER_HOOK 8

#define MAX_INFO_LEN 128

typedef struct api_info_ {
    char *api_name;
    long api_offset;

    UT_hash_handle off_hdl;
    UT_hash_handle hh;
} api_info_t;

typedef struct breakpoint_info_ {
    char *api_name;

    long sys_addr;
    long orig_code;
    bool is_return;
    int debug_flag;

    size_t expected_life;
    size_t hit_cnt;

    UT_hash_handle hh ;
} breakpoint_info_t;

typedef struct pending_breakpoint_ {
    char *api_name;
    bool enable;
    int debug_flag;

    UT_hash_handle hh;
} pending_breakpoint_t;

typedef enum {
    RUNNING,
    TRAPPED,
    STOPPED
} thread_state_e;

struct thread_info_ {
    int tid;
    thread_state_e state;
    struct breakpoint_info_ *active_bp;

    UT_hash_handle hh;
};

typedef enum {
    WAIT_FOR_BP,
    WAIT_FOR_STOP,
    WAIT_FOR_STEP
} proc_state_e;

struct traced_process_ {
    /* tgid of this process, AKA main process id */
    pid_t tgid;
    struct proc_addr_info_ *addr_info;
    proc_state_e state;
    struct thread_info_ *thread_set;

    void *ui;
    unw_cursor_t unw_c;
    unw_addr_space_t addr_space;

    /* If this is main, link to global list */
    UT_hash_handle hh;
};

void breakpoint_exit_loop (void);
int load_api_addr_info (const char *sym_file, pid_t pid);
int load_active_breakpoints (const char *breakpoint_file);
int breakpoint_main_loop (pid_t target_pid);
void ptrace_getdata (pid_t child, long addr, char *str, int len);

typedef int (*user_hook_fn)(long, long, long, long, long, long);
#endif
