#include "proc_ptrace.h"
#include "breakpoint.h"

#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/user.h>
#include <wait.h>
#include <sys/signal.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <endian.h>
#include <uthash.h>
#include <assert.h>
#include <stdbool.h>
#include <dirent.h>
#include <uthash.h>

static uint8_t break_instr[] = {0xcc};
#define SZ 8
#define PC 16

static int debug_process;
static struct traced_process_ *proc_ary;

void ptrace_getdata (pid_t child, long addr, char *str, int len)
{
    char *laddr;
    int i, j, long_size = sizeof(long);
    union u {
        long val;
        char chars[long_size];
    } data;

    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA,
                          child, addr + i * 8, //i * 4
                          NULL);
        memcpy(laddr, data.chars, j);
    }
    str[len] = '\0';
}

void ptrace_putdata (pid_t child, long addr, char *str, int len)
{
    char *laddr;
    int i, j, long_size = sizeof(long);
    union u {
        long val;
        char chars[long_size];
    } data;

    i = 0;
    j = len / long_size;
    laddr = str;
    while (i < j) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child, addr + i * long_size, data.val);
        ++i;
        laddr += long_size;
    }

    j = len % long_size;
    if (j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child, addr + i * long_size, data.val);
    }
}


int get_lwp_list (struct traced_process_ *proc)
{
    char dirname[64];
    DIR *dir;
    struct dirent *ent;
    struct thread_info_ *lwp;

    snprintf(dirname, sizeof dirname, "/proc/%d/task/", (int)proc->tgid);
    dir = opendir(dirname);
    if (!dir) {
        return -1;
    }
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.')
            continue;
        lwp = calloc(1, sizeof(struct thread_info_));
        assert(lwp);
        lwp->tid = atoi(ent->d_name);
        HASH_ADD_INT(proc->thread_set, tid, lwp);
    }

    closedir(dir);
    return 0;
}

struct traced_process_* create_traced_proc (pid_t target_pid)
{
    struct traced_process_ *proc;

    proc = calloc(1, sizeof(struct traced_process_));
    assert(proc);
    proc->tgid = target_pid;
    get_lwp_list(proc);
    HASH_ADD_INT(proc_ary, tgid, proc);
    return proc;
}

int attach_process (pid_t pid)
{
    struct traced_process_* proc;
    struct thread_info_ *cur, *tmp;

    HASH_FIND_INT(proc_ary, &pid, proc);
    if (!proc) {
        return -1;
    }
    HASH_ITER(hh, proc->thread_set, cur, tmp) {
        if (ptrace(PTRACE_ATTACH, cur->tid, NULL, NULL) < 0) {
            perror("ptrace()");
            return -1;
        }
        if (waitpid(cur->tid, &cur->status, __WALL) < 0) {
            perror("waitpid");
            return -1;
        }
        /* If want to monitor dynamic threads, uncomment following */
        //ptrace(PTRACE_SETOPTIONS, cur->tid, NULL, PTRACE_O_TRACECLONE);
        if (debug_process) {
            printf("attached to process %d\n", (int)cur->tid);
        }
    }
    proc->active_thread = proc->thread_set;
    proc->addr_space = unw_create_addr_space(&_UPT_accessors, 0);
    unw_set_caching_policy(proc->addr_space, UNW_CACHE_GLOBAL);
    proc->ui = _UPT_create(pid);

    return 0;
}

int detach_process (pid_t target_pid)
{
    struct traced_process_ *proc;
    struct thread_info_ *cur, *tmp;

    HASH_FIND_INT(proc_ary, &target_pid, proc);

    HASH_ITER(hh, proc->thread_set, cur, tmp) {
        ptrace(PTRACE_DETACH, cur->tid, NULL, NULL);
    }
    return 0;
}

bool is_clone_event(int status)
{
    return (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)));
}

bool check_exit (struct traced_process_ *proc)
{
    struct thread_info_ *active_thread = proc->active_thread;

    if (HASH_COUNT(proc->thread_set) && WIFEXITED(active_thread->status)) {
        HASH_DELETE(hh, proc->thread_set, active_thread);
        proc->active_thread = NULL;
        return true;
    }
    return false;
}

void check_sigtrap (struct traced_process_ *proc)
{
    siginfo_t info;
    struct thread_info_ *active_thread = proc->active_thread;

    ptrace(PTRACE_GETSIGINFO, active_thread->tid, NULL, &info);
    if (info.si_code == SI_KERNEL && info.si_signo == SIGTRAP) {
        /* Workaround, if both active and other thread hit breakpoint,
         * force non-active trap again.
         * So we must not break at instructions which has side effect * e.g. var++
         * This is a kludge, most of time, it is not a problem user knows it :)
         */
        size_t pc = ptrace(PTRACE_PEEKUSER, active_thread->tid, SZ * PC, NULL);
        pc -= sizeof(break_instr);
        ptrace(PTRACE_POKEUSER, active_thread->tid, SZ * PC, pc);
        return;
    }
}

bool check_sigstop (struct traced_process_ *proc)
{
    siginfo_t info;

    ptrace(PTRACE_GETSIGINFO, proc->active_thread->tid, NULL, &info);
    if (info.si_code == SI_TKILL && info.si_signo == SIGSTOP) {
        ptrace(PTRACE_CONT, proc->active_thread->tid, NULL, NULL);
        return true;
    }
    return false;
}

bool check_clone (struct traced_process_ *proc)
{
    size_t newtid;
    int stat;
    struct thread_info_ *new_thread;

    if (is_clone_event(proc->active_thread->status)) {
        ptrace(PTRACE_GETEVENTMSG, proc->active_thread->tid, NULL, (long)&newtid);
        if (waitpid(newtid, &stat, __WALL) > 0) {
            new_thread = calloc(1, sizeof(struct thread_info_));
            new_thread->tid = newtid;
            HASH_ADD_INT(proc->thread_set, tid, new_thread);

            ptrace(PTRACE_CONT, newtid, NULL, NULL);
        }
        ptrace(PTRACE_CONT, proc->active_thread->tid, NULL, NULL);
        return true;
    }
    return false;
}

void set_curr_thread (struct traced_process_ *proc, pid_t tid)
{
    struct thread_info_ *act;

    HASH_FIND_INT(proc->thread_set, &tid, act);
    if (act) {
        proc->active_thread = act;
    }
}

void stop_threads (struct traced_process_ *proc)
{
    struct thread_info_ *saved_active, *cur, *tmp;

    saved_active = proc->active_thread;
    HASH_ITER(hh, proc->thread_set, cur, tmp) {
        if (cur == saved_active) {
            continue;
        }
        do {
            proc->active_thread = cur;
            if (syscall(SYS_tgkill, proc->tgid, cur->tid, SIGSTOP) == -1) {
                printf("Failed to stop thread %d\n", cur->tid);
            }
            waitpid(cur->tid, &cur->status, __WALL);
            check_exit(proc);
            check_sigtrap(proc);
        } while (check_clone(proc));
    }
    proc->active_thread = saved_active;
}

pid_t continue_process (struct traced_process_ *proc)
{
    struct thread_info_ *cur, *tmp;
    int stat;
    pid_t tid;

    if (debug_process) {
        printf("\n\n-------------- continue process ----------------\n");
    }
    HASH_ITER(hh, proc->thread_set, cur, tmp) {
        ptrace(PTRACE_CONT, cur->tid, NULL, NULL);
    }

    do {
        tid = waitpid(-1, &stat, __WALL);
        HASH_FIND_INT(proc->thread_set, &tid, cur);
        if (!cur) {
            printf("Stopped because found strange pid = %d\n", tid);
            continue;
        }
        set_curr_thread(proc, tid);
        assert(proc->active_thread);
        proc->active_thread->status = stat;
    } while (check_exit(proc) || check_sigstop(proc) || check_clone(proc));
    if (debug_process) {
        printf("%s continue tid %d, stop sig = %d\n", __FUNCTION__, (int)tid, WSTOPSIG(stat));
    }
    if (WIFSTOPPED(stat)) {
        stop_threads(proc);
    }
    if (WIFSTOPPED(stat) && WSTOPSIG(stat) == SIGTRAP) {
        if (debug_process) {
            printf("%s detect SIGTRAP on %d\n", __FUNCTION__, (int)tid);
        }
        return tid;
    } else if (WIFSTOPPED(stat)) {
        if (debug_process) {
            printf("tid %d stopped by = %d\n", tid, WSTOPSIG(stat));
        }
    }
    if (WIFEXITED(stat)) {
        printf("tid %d exited, exit = %d\n", tid, WEXITSTATUS(stat));
        //TODO
    }
    if (WIFSIGNALED(stat)) {
        printf("tid %d terminated, term = %d\n", tid, WTERMSIG(stat));
        //TODO
    }

    if (debug_process) {
        printf("%s Invalid stop SIG %d on tid %d\n", __FUNCTION__, WSTOPSIG(stat), tid);
    }
    return -1;
}

void step_process (struct traced_process_ *proc, pid_t tid)
{
    struct thread_info_ *curr;

    HASH_FIND_INT(proc->thread_set, &tid, curr);
    proc->active_thread = curr;
    ptrace(PTRACE_SINGLESTEP, curr->tid, NULL, NULL);
}

#define CALLSTACK_DEPTH 30

typedef struct breakpoint {
    unsigned long vaddr;
    long orig_code;
} breakpoint_t;

typedef struct calldata {
    unsigned long vaddr;
    unsigned long retaddr;
    breakpoint_t breakpoint;
} calldata_t;

typedef struct callstack {
    calldata_t *calldata;
    unsigned int depth;
} callstack_t;

static void callstack_set_breakpoint (pid_t pid, callstack_t *callstack)
{
    long orig = ptrace(PTRACE_PEEKTEXT, pid, callstack->calldata[callstack->depth].retaddr);
    long trap;

    trap = (orig & ~0xff) | 0xcc;

    ptrace(PTRACE_POKETEXT, pid, callstack->calldata[callstack->depth].retaddr, trap);
    callstack->calldata[callstack->depth].breakpoint.orig_code = orig;
    callstack->calldata[callstack->depth].breakpoint.vaddr = callstack->calldata[callstack->depth].retaddr;

}

void callstack_remove_breakpoint (pid_t pid, callstack_t *callstack)
{
    ptrace(PTRACE_POKETEXT, pid, callstack->calldata[callstack->depth].retaddr, callstack->calldata[callstack->depth].breakpoint.orig_code);
}

/*
 * Simple array implementation of stack
 * to keep track of function depth and return values
 */

void callstack_init(callstack_t *callstack)
{
    callstack->calldata = (calldata_t *)calloc(CALLSTACK_DEPTH, sizeof(calldata_t));
    callstack->depth = -1; // 0 is first element

}

void callstack_push (pid_t pid, callstack_t *callstack, calldata_t *calldata)
{
    memcpy(&callstack->calldata[++callstack->depth], calldata, sizeof(calldata_t));
    callstack_set_breakpoint(pid, callstack);
}

calldata_t * callstack_pop (pid_t pid, callstack_t *callstack)
{
    if (callstack->depth == -1)
        return NULL;

    callstack_remove_breakpoint(pid, callstack);
    return (&callstack->calldata[callstack->depth--]);
}

/* View the top of the stack without popping */
calldata_t * callstack_peek(callstack_t *callstack)
{
    if (callstack->depth == -1)
        return NULL;

    return &callstack->calldata[callstack->depth];

}

long examine_api (pid_t pid, long return_addr, long addr_start, long addr_end)
{
    int status;
    struct user_regs_struct pt_reg;
    char buf[16];
    long vaddr, eip;
    unsigned int offset;
    bool step_over = false;

    callstack_t callstack;
    calldata_t calldata;
    calldata_t *calldp;

    printf("----- Enter Function(%lx) ----------\n", addr_start);
    /*
     * Initiate our call frame stack
     */
    callstack_init(&callstack);
    for (;;) {
        if (step_over) {
            ptrace(PTRACE_CONT, pid, NULL, NULL);
        } else {
            ptrace (PTRACE_SINGLESTEP, pid, NULL, NULL);
            step_over = false;
        }
        wait (&status);

        ptrace (PTRACE_GETREGS, pid, NULL, &pt_reg);
        eip = pt_reg.rip;
        if (eip == return_addr) {
            printf("----- Exit Function(%lx) ----------\n", addr_start);
            return pt_reg.rax;
        }
        ptrace_getdata(pid, eip, buf, sizeof(buf));
        if (buf[0] == 0xcc) {
            calldp = callstack_peek(&callstack);
            if (calldp != NULL) {
                if (calldp->retaddr == eip) {
                    calldp = callstack_pop(pid, &callstack);
                }
            }
        } else if (buf[0] == 0xe8) {
            offset = buf[1] + (buf[2] << 8) + (buf[3] << 16) + (buf[4] << 24);
            vaddr = eip + offset + 5;
            printf("---------------call->%lx----------------\n", vaddr);
            calldata.vaddr = vaddr;
            calldata.retaddr = eip + 5;
            callstack_push(pid, &callstack, &calldata);
            if (vaddr < addr_start || vaddr > addr_end) {
                step_over = true;
            }
        } else if (eip < addr_end && eip > addr_start) {
            printf(">%lx(%ld)\n", eip, eip - addr_start);
        }
    }
}
