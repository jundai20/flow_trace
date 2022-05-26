#ifndef PROC_PTRACE_H
#define PROC_PTRACE_H

#include <uthash.h>
#include <sys/types.h>

#include <libunwind.h>
#include <libunwind-ptrace.h>

struct thread_info_ {
    int tid;
    int status;

    UT_hash_handle hh;
};

struct traced_process_ {
    /* tgid of this process, AKA main process id */
    pid_t tgid;

    struct thread_info_ *active_thread;
    struct thread_info_ *thread_set;

    void *ui;
    unw_cursor_t unw_c;
    unw_addr_space_t addr_space;

    /* If this is main, link to global list */
    UT_hash_handle hh;
};

int control_process(pid_t proc_id, const char *msg);
void sigint_handler(int sig_type);

int attach_process (pid_t target_pid);
int detach_process (pid_t target_pid);

struct traced_process_* create_traced_proc (pid_t target_pid);
pid_t continue_process (struct traced_process_ *proc);
void step_process (struct traced_process_ *proc, pid_t tid);

long examine_api (pid_t pid, long return_rip, long addr_start, long addr_end);
void ptrace_getdata (pid_t child, long addr, char *str, int len);
void ptrace_putdata (pid_t child, long addr, char *str, int len);
#endif
