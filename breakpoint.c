#include <stdio.h>
#include <ctype.h>
#include <sys/ptrace.h>
#include <sys/types.h>
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
#include <libunwind.h>
#include <libunwind-ptrace.h>

#include "breakpoint.h"
#include "func_addr.h"
#include "spy.h"
#include "arch.h"
#include "log.h"

static bool exit_flag;
static int debug_bp_verbose;
/* global unique address: process id + virtual address */
static struct breakpoint_info_ *sys_addr_set;
/* configured function name must be global unique */
static struct breakpoint_info_ *api_name_set;
/* pending breakpoint, set it when stopped */
static struct breakpoint_info_ *pending_set;


#define MAX_HOOK 8
static api_callback_fn api_hook[MAX_HOOK];

int regist_api_hook (api_callback_fn fn)
{
    static int cnt = 0;

    if ((cnt + 1) > MAX_HOOK) {
        return -1;
    }
    api_hook[cnt] = fn;
    cnt++;
    return 0;
}

struct breakpoint_info_* get_breakpoint_via_addr (pid_t pid, long addr)
{
    struct breakpoint_info_ *bp;
    struct addr_key_ key;

    key.tid = pid;
    key.addr = addr;
    HASH_FIND(sys_addr_hdl, sys_addr_set, &key, sizeof(struct addr_key_), bp);
    return bp;
}

/* key is api_name, so make sure API name is global (multi processes) unique */
void configure_breakpoint (pid_t pid, struct breakpoint_info_ *bp)
{
    struct breakpoint_info_* new_bp, *prev_bp;
    long host_so_base, addr;

    host_so_base = soname_to_addr(pid, bp->host_file);
    addr = host_so_base + bp->host_offset;
    if (get_breakpoint_via_addr(pid, addr)) {
        return;
    }

    prev_bp = get_breakpoint_via_addr(pid, host_so_base + bp->host_offset);
    if (prev_bp) {
        printf("Error: duplicate breakpoints %s and %s\n", bp->func_name, prev_bp->func_name);
        assert(0);
    }
    new_bp = calloc(1, sizeof(struct breakpoint_info_));
    new_bp->func_name = strdup(bp->func_name);
    new_bp->func_size = bp->func_size;
    new_bp->sys_addr.tid = pid;
    new_bp->sys_addr.addr = host_so_base + bp->host_offset;
    new_bp->debug_flag = bp->debug_flag;
    new_bp->host_file = bp->host_file?strdup(bp->host_file):NULL;
    new_bp->host_offset = bp->host_offset;
    /* Note, the macro will use get func_name[0] address, donot use func_name */
    HASH_ADD(api_name_hdl, api_name_set, func_name[0], strlen(bp->func_name), new_bp);
    HASH_ADD(sys_addr_hdl, sys_addr_set, sys_addr, sizeof(struct addr_key_), new_bp);
    if (bp->debug_flag) {
        request_pending_breakpoint(bp->func_name, bp->debug_flag);
    }
}

/* really enable the breakpoint */
int set_breakpoint (pid_t tid, long addr)
{
    struct breakpoint_info_* bp;
    long data;

    bp = get_breakpoint_via_addr(tid, addr);
    if (!bp) {
        return -1;
    }
    bp->orig_code = ptrace(PTRACE_PEEKTEXT, tid, (void*)addr, 0);
    data = bp->orig_code;
    memcpy((void *)&data, break_instr, sizeof(break_instr));
    if (ptrace(PTRACE_POKETEXT, tid, addr, data) < 0) {
        return -1;
    }
    return 0;
}

/* Request to enable this breakpoint when this debugger can (attached/stopped) */
int request_pending_breakpoint (char *name, int debug_flag)
{
    struct breakpoint_info_* bp;

    if (name[0] == '#') {
        return -1;
    }
    HASH_FIND(api_name_hdl, api_name_set, name, strlen(name), bp);
    if (!bp) {
        //printf("Error: API %s not configured, skip\n", name);
        return -1;
    }
    bp->debug_flag = debug_flag;
    HASH_ADD(pending_hdl, pending_set, func_name[0], strlen(name), bp);
    return 0;
}

int enable_pending_breakpoints (struct traced_process_ *proc)
{
    struct breakpoint_info_ *bp, *tmp;
    long data;
    int inserted_cnt = 0;

    HASH_ITER(pending_hdl, pending_set, bp, tmp) {
        bp->orig_code = ptrace(PTRACE_PEEKTEXT, bp->sys_addr.tid, (void*)bp->sys_addr.addr, 0);
        data = bp->orig_code;
        memcpy((void *)&data, break_instr, sizeof(break_instr));
        if (ptrace(PTRACE_POKETEXT, bp->sys_addr.tid, bp->sys_addr.addr, data) < 0) {
            printf("Warning: fail to break %s, skipped\n", bp->func_name);
            continue;
        }
        if (bp->debug_flag == 0) {
            /* from extra added breakpoint file */
            bp->debug_flag = 1;
        }
        inserted_cnt++;
    }
    HASH_CLEAR(pending_hdl, pending_set);
    printf("Inserted %d breakpoints successfully\n", inserted_cnt);
    return inserted_cnt;
}

/* remove breakpoint from memory, but we never remove breakpoints from database */
int remove_breakpoint (pid_t tgid, long addr)
{
    struct breakpoint_info_* bp;

    bp = get_breakpoint_via_addr(tgid, addr);
    if (!bp || bp->orig_code == 0) {
        return -1;
    }
    if (ptrace(PTRACE_POKETEXT, tgid, bp->sys_addr.addr, bp->orig_code) < 0) {
        return -1;
    }
    HASH_DELETE(sys_addr_hdl, sys_addr_set, bp);
    return 0;
}

void disable_all_breakpoints (pid_t target_pid)
{
    int cnt = 0;
    struct breakpoint_info_ *bp, *tmp_bp;

    HASH_ITER(sys_addr_hdl, sys_addr_set, bp, tmp_bp) {
        if (bp->orig_code == 0) {
            continue;
        }
        if (ptrace(PTRACE_POKETEXT,
                   bp->sys_addr.tid, bp->sys_addr.addr, bp->orig_code) < 0) {
            printf("Restore breakpoint %s failed\n", bp->func_name);
        }
        if (debug_bp_verbose) {
            printf("Disable %s %d %lx\n", bp->func_name, bp->sys_addr.tid, bp->sys_addr.addr);
        }
        cnt++;
    }
    printf("All (%d) breakpoints disabled\n", cnt);
}

int remote_backtrace (struct traced_process_ *proc, int tid, long trace_ip[MAX_DEPTH])
{
    unw_word_t ip, sp;
    int depth = 0, ret;

    if ((ret = unw_init_remote(&proc->unw_c, proc->addr_space, proc->ui)) < 0) {
        fprintf(stderr, "unw_init_remote failed (ret=%d).\n", ret);
        return 0;
    }
    do {
        if ((ret = unw_get_reg(&proc->unw_c, UNW_REG_IP, &ip)) < 0 ||
                (ret = unw_get_reg(&proc->unw_c, UNW_REG_SP, &sp)) < 0) {
            fprintf(stderr, "unw_get_reg failed (ret=%d).\n", ret);
            break;
        }
        trace_ip[depth] = ip;
        if (depth++ > MAX_DEPTH) {
            break;
        }
    } while (unw_step(&proc->unw_c) > 0);

    return depth;
}

void print_callinfo (struct traced_process_ *proc, struct breakpoint_info_ *active_bp, int tid, bool is_return)
{
    int depth, i = 0, j;
    long trace_ip[MAX_DEPTH];

    /* FIXME: To accelerate avoid stuck, sacrifice API info accuracy, better idea? */
    depth = remote_backtrace(proc, tid, trace_ip);
    if (is_return == false && (active_bp->debug_flag & SHOW_BACKTRACE)) {
        display_backtrace(tid, depth, &trace_ip[0]);
    }
    if (strncmp(active_bp->func_name, "__be_", strlen("__be_")) == 0) {
        i = strlen("__be_");
    }
    j = is_return?1:0;
    output_message("[%d]%*s%s%s\n", depth + j, depth*4, " ", is_return?"    <-":"->", &active_bp->func_name[i]);
}

#ifndef __arm__
void run_shadow_api (int pid, long shadow_abs_addr, struct user_regs_struct *regs)
{
    struct user_regs_struct orig_code_regs;
    struct user_regs_struct execute_regs;
    long orig_code_retaddr;
    int status;

    memcpy(&orig_code_regs, regs, sizeof(struct user_regs_struct));
    memcpy(&execute_regs, regs, sizeof(struct user_regs_struct));
    execute_regs.rip = shadow_abs_addr;
    /* Set an invalid 0xdeafbeef, It is as return address */
    orig_code_retaddr = ptrace(PTRACE_PEEKTEXT, pid, execute_regs.rsp, 0);
    ptrace(PTRACE_POKETEXT, pid, (void*)execute_regs.rsp, 0xdeadbeef);
    if (ptrace(PTRACE_SETREGS, pid, NULL, &execute_regs)) {
        perror("Fail to setreg when execute: ");
        goto bailout;
    }
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        perror("Fail to contiune inserted code when execute: ");
        goto bailout;
    }
    /* 0xdeadbeef will stop traced process to here, SIGSEGV*/
    waitpid(pid, &status, 0);
    /* Recover*/
    if (ptrace(PTRACE_SETREGS, pid, NULL, &orig_code_regs) ) {
        perror("Fail to recover after execute: ");
        goto bailout;
    }
    ptrace(PTRACE_POKETEXT, pid, (void*)orig_code_regs.rsp, orig_code_retaddr);

bailout:
    /* TODO error handling & cleanup */
    return;
}
#endif

int insert_breakpoint_for_return (struct breakpoint_info_ *func_bp,
                                  pid_t tid, struct user_regs_struct *regs)
{
    long return_addr, data;
    struct breakpoint_info_* ret_bp;
#ifdef __arm__
    return_addr = ptrace(PTRACE_PEEKTEXT, tid, regs->sp, 0);
#else
    return_addr = ptrace(PTRACE_PEEKTEXT, tid, regs->rsp, 0);
#endif
    ret_bp = get_breakpoint_via_addr(tid, return_addr);
    if (ret_bp) {
        /* already tracked */
        return 0;
    }
    if (addr_in_range(tid, return_addr) == false) {
        assert(0);
        return 0;
    }
    ret_bp = calloc(1, sizeof(struct breakpoint_info_));
    assert(ret_bp);
    ret_bp->func_name = strdup(func_bp->func_name);
    ret_bp->sys_addr.addr = return_addr;
    ret_bp->sys_addr.tid = tid;
    ret_bp->orig_code = ptrace(PTRACE_PEEKTEXT, tid, return_addr, 0);
    data = ret_bp->orig_code;
    memcpy(&data, break_instr, sizeof(break_instr));
    if (ptrace(PTRACE_POKETEXT, tid, (void*)return_addr, data) < 0) {
        printf("Fatal, can not insert func return breakpoint @ %lx\n", ret_bp->sys_addr.addr);
        free(ret_bp);
        disable_all_breakpoints(tid);
        return -1;
    }
    ret_bp->is_return = true;
    if (debug_bp_verbose) {
        printf("%s:%d:%s, inserted breakpoint for %s return @ %lx\n",
               __FILE__, __LINE__, __FUNCTION__,
               func_bp->func_name, return_addr);
    }
    HASH_ADD(sys_addr_hdl, sys_addr_set, sys_addr, sizeof(struct addr_key_), ret_bp);
    return 0;
}

int step_over_lwp (struct traced_process_ *proc, pid_t tid)
{
    int i, depth, status;
    long trace_ip[MAX_DEPTH], addr;
    struct breakpoint_info_* bp;
    struct user_regs_struct regs;
#ifdef __arm__
    ptrace(PTRACE_GETREGSET, tid, NULL, &regs);
    addr = regs.pc - sizeof(break_instr);
#else
    ptrace(PTRACE_GETREGS, tid, NULL, &regs);
    addr = regs.rip - sizeof(break_instr);
#endif
    bp = get_breakpoint_via_addr (proc->tgid, addr);
    if (!bp) {
        /* This can be a watch triggered trap */
        printf("Triggered by unknown bp\n");
        depth = remote_backtrace(proc, tid, trace_ip);
        display_backtrace(tid, depth, &trace_ip[0]);
        return 0;
    }
    for (i = 0; i < MAX_HOOK; i++) {
        if (!api_hook[i]) {
            break;
        }
        api_hook[i](tid, bp, &regs);
    }
    if (bp->is_return == false
            && ((bp->debug_flag & SHOW_FLOW) == 0)) {
        insert_breakpoint_for_return(bp, proc->tgid, &regs);
    }
    if (ptrace(PTRACE_POKETEXT, proc->tgid, bp->sys_addr.addr, bp->orig_code) < 0) {
        printf("Fail to restore code\n");
        return -1;
    }
#ifdef __arm__
    regs.pc = addr;
    if (ptrace(PTRACE_SETREGSET, tid, NULL, &regs)) {
#else
    regs.rip = addr;
    if (ptrace(PTRACE_SETREGS, tid, NULL, &regs)) {
#endif
        printf("Fail to set args\n");
        return -1;
    }
    if (ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL) < 0) {
        printf("Fail to singalstep\n");
        return -1;
    }
    waitpid(tid, &status, __WALL);
    if (bp->debug_flag & SHOW_FLOW) {
        long return_addr;

        printf("Monitor API %s\n", bp->func_name);
#ifdef __arm__
        return_addr = ptrace(PTRACE_PEEKTEXT, tid, regs.sp, 0);
#else
        return_addr = ptrace(PTRACE_PEEKTEXT, tid, regs.rsp, 0);
#endif
        examine_api(tid, return_addr,
                    bp->sys_addr.addr,
                    bp->sys_addr.addr + bp->sys_addr.addr + bp->func_size);
    }

    if (bp->is_return == false) {
        set_breakpoint(proc->tgid, addr);
    } else {
        remove_breakpoint(proc->tgid, addr);
    }
    if (bp->debug_flag) {
        print_callinfo(proc, bp, tid, bp->is_return);
    }

    return 0;
}

/*TODO: move it to common utility file*/
static char *trim (char *str)
{
    char *p = str;
    char *p1;
    if(p) {
        p1 = p + strlen(str) - 1;
        while(*p && isspace(*p)) p++;
        while(p1 > p && isspace(*p1)) *p1-- = 0;
    }
    return p;
}

void load_breakpoint_set (pid_t pid, const char *bp_file)
{
    char *line = NULL, *api_name;
    size_t nread, len;
    int cnt = 0;
    FILE *bfp;

    printf("Loading extra watch API list from %s for pid %d\n", bp_file, pid);
    bfp = fopen(bp_file, "r");
    if (bfp) {
        while ((nread = getline(&line, &len, bfp)) != -1) {
            api_name = trim(line);
            if (request_pending_breakpoint(api_name, 1) == 0) {
                cnt++;
            }
            if (cnt%100 == 0) {
                printf("!");
            }
        }
        free(line);
        fclose(bfp);
        printf("\nIn total requesting %d breakpoints\n", cnt);
    }
}

int breakpoint_main_loop (pid_t target_pid)
{
    pid_t tid;
    int status;
    struct traced_process_ *proc;

    proc = create_traced_proc(target_pid);
    if ((status = attach_process(target_pid)) < 0) {
        printf("Insert BP: Fail to attach process %d\n", target_pid);
        return -1;
    }
    if (enable_pending_breakpoints (proc) == 0) {
        printf("No breakpoint inserted, exit.\n");
        return -1;
    }
    printf("------------ ready ------------\n");
    do {
        /* breakpoint operation use target_pid/tgid, process operation use lwp/tid */
        tid = continue_process(proc);
        if (tid == -1) {
            continue;
        }
        if (step_over_lwp(proc, tid) < 0) {
            break;
        }
    } while(exit_flag == false);

    disable_all_breakpoints(target_pid);
    detach_process(target_pid);
    return -1;
}

void breakpoint_exit_loop (void)
{
    exit_flag = true;
}
