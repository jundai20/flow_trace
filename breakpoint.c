#define _GNU_SOURCE
#include <stdio.h>
#include <link.h>
#include <dlfcn.h>
#include <elf.h>

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
#include <sys/syscall.h>

#include "breakpoint.h"
#include "func_addr.h"
#include "ibut.h"
#include "log.h"
#include "arch.h"
#include "generate_core.h"
#include "watchdog.h"


#define SIMULARITY_FILE "simularity_log.txt"

#define BP_ERR 1
#define BP_WARNING 2
#define BP_NOTE 3
#define BP_VERBOSE 3

int debug_bp;

static bool exit_flag;
static void *plugin_handle;
static pid_t cur_pid;
static int core_fn_cnt;

gen_coredump_cb coredump_callback;

static struct api_info_ *api_db;
static struct api_info_ *offset_db;

static struct breakpoint_info_ *active_bp_db;
static struct pending_breakpoint_ *pending_db;
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

static pid_t mywaitpid(pid_t pid, int *wstatus, int options)
{
    pid_t rc;

    do {
        errno = 0;
        rc = waitpid(pid, wstatus, options);
        if ( rc != -1 ) {
            break;
        }
    } while(errno == EINTR);

    return rc;
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

static struct traced_process_* create_traced_proc (pid_t target_pid)
{
    struct traced_process_ *proc;

    //printf("Reading process %d VM areas\n", target_pid);
    proc = calloc(1, sizeof(struct traced_process_));
    assert(proc);
    proc->tgid = target_pid;
    get_lwp_list(proc);
    proc->addr_info = get_proc_addrinfo(target_pid);
    HASH_ADD_INT(proc_ary, tgid, proc);
    //printf("Target process inforamation ready\n");
    return proc;
}

struct traced_process_* get_traced_proc (pid_t pid)
{
    struct traced_process_ *proc;

    HASH_FIND_INT(proc_ary, &pid, proc);
    if (!proc) {
        proc = create_traced_proc(pid);
    }

    return proc;
}

int attach_process (pid_t pid)
{
    struct traced_process_* proc;
    struct thread_info_ *cur, *tmp;
    int status, sig;
    pid_t tid;

    HASH_FIND_INT(proc_ary, &pid, proc);
    if (!proc) {
        return -1;
    }
    HASH_ITER(hh, proc->thread_set, cur, tmp) {
        if (ptrace(PTRACE_ATTACH, cur->tid, NULL, NULL) < 0) {
            perror("ptrace()");
            return -1;
        }
        tid = mywaitpid(cur->tid, &status, __WALL);
        if (tid == -1) {
            continue;
        }
        sig = WSTOPSIG(status);
        if (debug_bp) {
            printf("    process %d got signal %d\n", cur->tid, sig);
        }
        while(!WIFSTOPPED(status) || sig != SIGSTOP) {
            /* Seems that tracer monitor instead of hooked signal */
            //syscall(SYS_tgkill, proc->tgid, cur->tid, sig);
            tid = mywaitpid(cur->tid, &status, __WALL);
            sig = WSTOPSIG(status);
        }
        /* If want to monitor dynamic threads, uncomment following */
        //ptrace(PTRACE_SETOPTIONS, cur->tid, NULL, PTRACE_O_TRACECLONE);
        if (debug_bp) {
            printf("    attached to process %d\n", (int)cur->tid);
        }
    }

    return 0;
}

int detach_process (pid_t target_pid)
{
    struct traced_process_ *proc;
    struct thread_info_ *cur, *tmp;

    HASH_FIND_INT(proc_ary, &target_pid, proc);
    HASH_ITER(hh, proc->thread_set, cur, tmp) {
        ptrace(PTRACE_DETACH, cur->tid, NULL, NULL);
        printf("Detached thread %d\n", cur->tid);
    }
    return 0;
}

struct thread_info_* tg_get_thread (struct traced_process_ *proc, pid_t tid)
{
    struct thread_info_ *cur, *tmp;

    HASH_ITER(hh, proc->thread_set, cur, tmp) {
        if (cur->tid == tid) {
            return cur;
        }
    }
    return NULL;
}

void ptrace_cont_all (struct traced_process_ *proc)
{
    struct thread_info_ *cur, *tmp;

    HASH_ITER(hh, proc->thread_set, cur, tmp) {
        ptrace(PTRACE_CONT, cur->tid, NULL, NULL);
        cur->state = RUNNING;
    }
}

static long get_api_abs_addr (pid_t pid, struct api_info_ *api)
{
    long so_baseaddr, addr, i;
    char so_name[MAX_INFO_LEN] = {0};

    if (!api) {
        return 0;
    }
    for (i = 0; i < strlen(api->api_name); i++) {
        if (api->api_name[i] == ':') {
            break;
        }
        so_name[i] = api->api_name[i];
    }
    so_baseaddr = soname_to_addr(pid, so_name);
    if (so_baseaddr == 0) {
        if (debug_bp) {
            printf("Warning: fail to locate base address for %s@%s\n", api->api_name, so_name);
        }
        return 0;
    }
    addr = so_baseaddr + api->api_offset;

    return addr;
}

/* Since this API read orig code, don't invoke this API when .text is changed */
static int insert_breakpoint_to_target (pid_t pid, struct breakpoint_info_ *active_bp)
{
    long data;

    active_bp->orig_code = ptrace(PTRACE_PEEKTEXT, pid, (void*)active_bp->sys_addr, 0);
    data = active_bp->orig_code;
    assert(data);
    memcpy((void *)&data, break_instr, sizeof(break_instr));
    if (ptrace(PTRACE_POKETEXT, pid, active_bp->sys_addr, data) < 0) {
        return -1;
    }
    return 0;
}

static int enable_pending_breakpoint (pid_t pid, struct pending_breakpoint_ *pending_bp)
{
    struct api_info_ *api;
    long sys_addr;
    struct breakpoint_info_ *active_bp;

    HASH_FIND_STR(api_db, pending_bp->api_name, api);
    sys_addr = get_api_abs_addr(pid, api);
    if (!sys_addr) {
        if (debug_bp) {
            printf("API [%s] offset unknown, skipped\n", pending_bp->api_name);
        }
        return -1;
    }
    HASH_FIND(hh, active_bp_db, &sys_addr, sizeof(long), active_bp);
    /* add permanent breakpoint */
    active_bp = malloc(sizeof(struct breakpoint_info_));
    assert(active_bp);
    active_bp->api_name = strdup(pending_bp->api_name);
    active_bp->sys_addr = sys_addr;
    active_bp->debug_flag = pending_bp->debug_flag;
    active_bp->expected_life = 0;
    active_bp->hit_cnt = 0;
    if (insert_breakpoint_to_target(pid, active_bp)) {
        if (debug_bp) {
            printf("API [%s] insert to target failed, skipped\n", pending_bp->api_name);
        }
        free(active_bp->api_name);
        free(active_bp);
        return -1;
    }
    HASH_ADD(hh, active_bp_db, sys_addr, sizeof(long), active_bp);
    if (debug_bp > BP_ERR) {
        printf("Inserted breakpoint [%s]@[%lx], flag = 0x%x\n", pending_bp->api_name, sys_addr, active_bp->debug_flag);
    }
    return 0;
}

static int enable_pending_breakpoints (pid_t pid)
{
    struct pending_breakpoint_ *bp, *tmp;
    int inserted_cnt = 0, rc;

    HASH_ITER(hh, pending_db, bp, tmp) {
        rc = enable_pending_breakpoint(pid, bp);;;;
        if (rc == 0) {
            inserted_cnt++;
        }
    }
    HASH_ITER(hh, pending_db, bp, tmp) {
        HASH_DEL(pending_db, bp);
        free(bp->api_name);
        free(bp);
    }
    return inserted_cnt;
}

static bool disable_all_breakpoints (pid_t pid)
{
    int cnt = 0;
    struct breakpoint_info_ *bp, *tmp_bp;

    HASH_ITER(hh, active_bp_db, bp, tmp_bp) {
        if (ptrace(PTRACE_POKETEXT, pid, bp->sys_addr, bp->orig_code) < 0) {
            printf("Restore breakpoint %s failed\n", bp->api_name);
            return false;
        }
        if (debug_bp > BP_ERR) {
            printf("Disabled %s %d %lx\n", bp->api_name, pid, bp->sys_addr);
        }
        cnt++;
    }
    HASH_ITER(hh, active_bp_db, bp, tmp_bp) {
        HASH_DEL(active_bp_db, bp);
        free(bp->api_name);
        free(bp);
    }
    printf("All (%d) breakpoints disabled\n", cnt);
    return true;
}

int remote_backtrace (struct traced_process_ *proc, long trace_ip[MAX_DEPTH])
{
    unw_word_t ip;
    int depth = 0, ret;

    if (!proc->addr_space) {
        proc->addr_space = unw_create_addr_space(&_UPT_accessors, 0);
        unw_set_caching_policy(proc->addr_space, UNW_CACHE_GLOBAL);
        proc->ui = _UPT_create(proc->tgid);
    }
    if ((ret = unw_init_remote(&proc->unw_c, proc->addr_space, proc->ui)) < 0) {
        fprintf(stderr, "unw_init_remote failed (ret=%d).\n", ret);
        return 0;
    }
    do {
        if ((ret = unw_get_reg(&proc->unw_c, UNW_REG_IP, &ip)) < 0) {
            fprintf(stderr, "unw_get_reg failed (ret=%d).\n", ret);
            break;
        }
        trace_ip[depth] = ip;
        if (depth++ >= MAX_DEPTH) {
            break;
        }
    } while (unw_step(&proc->unw_c) > 0);

    return depth;
}

static void print_callinfo (struct traced_process_ *proc,
                            struct breakpoint_info_ *active_bp,
                            int tid,
                            bool is_return)
{
    int depth, i = 0, j;
    long trace_ip[MAX_DEPTH];

    if ((active_bp->debug_flag & SHOW_API_NAME)  == 0) {
        return;
    }

    depth = remote_backtrace(proc, trace_ip);
    if (is_return == false && (active_bp->debug_flag & SHOW_BACKTRACE)) {
        display_backtrace(proc->tgid, depth, &trace_ip[0]);
    }
    if (strncmp(active_bp->api_name, "self:", strlen("self:")) == 0) {
        i = strlen("self:");
    }

    j = is_return?1:0;
    output_message("[%d]%*s%s%s\n", depth + j, depth*4, " ",
                   is_return?"    <-":"->", &active_bp->api_name[i]);
}

int insert_breakpoint_for_return (struct breakpoint_info_ *func_bp,
                                  pid_t pid, struct user_regs_struct *regs)
{
    long return_addr, data;
    struct breakpoint_info_* ret_bp;

#ifdef __arm__
    return_addr = regs->regs[30];
#else
    return_addr = ptrace(PTRACE_PEEKTEXT, pid, regs->rsp, 0);
#endif

    HASH_FIND(hh, active_bp_db, &return_addr, sizeof(long), ret_bp);
    if (ret_bp) {
        /* already tracked */
        return 0;
    }
    if (debug_bp) {
        printf("Try to insert proc %d, function %lx, return_addr = %lx\n",
               pid, func_bp->sys_addr, return_addr);
    }
    ret_bp = calloc(1, sizeof(struct breakpoint_info_));
    assert(ret_bp);
    ret_bp->api_name = strdup(func_bp->api_name);
    ret_bp->sys_addr = return_addr;
    ret_bp->is_return = true;
    ret_bp->debug_flag = func_bp->debug_flag;
    ret_bp->expected_life = 1;
    ret_bp->orig_code = ptrace(PTRACE_PEEKTEXT, pid, return_addr, 0);
    data = ret_bp->orig_code;
    memcpy(&data, break_instr, sizeof(break_instr));
    if (ptrace(PTRACE_POKETEXT, pid, (void*)return_addr, data) < 0) {
        printf("Fatal, can not insert func return breakpoint @ %lx\n", ret_bp->sys_addr);
        free(ret_bp);
        disable_all_breakpoints(pid);
        return -1;
    }
    if (debug_bp) {
        printf("%s:%d:%s, inserted breakpoint for %s return @ %lx\n",
               __FILE__, __LINE__, __FUNCTION__,
               func_bp->api_name, return_addr);
    }
    HASH_ADD(hh, active_bp_db, sys_addr, sizeof(long), ret_bp);
    return 0;
}

void breakpoint_exit_loop (void)
{
    exit_flag = true;
}

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

int insert_one_pending_breakpoint (char *api_name, int debug_flag, bool enable)
{
    struct pending_breakpoint_ *bp;
    struct api_info_ *api;

    if (debug_bp > BP_NOTE) {
        printf("Request breakpoint on %s, flag: %d\n", api_name, debug_flag);
    }
    HASH_FIND_STR(api_db, api_name, api);
    if (!api) {
        if (debug_bp) {
            printf("Fail to insert %s, offset unknown\n", api_name);
        }
        return -1;
    }
    HASH_FIND_STR(pending_db, api_name, bp);
    if (bp) {
        return 0;
    }
    bp = malloc(sizeof(struct pending_breakpoint_));
    assert(bp);

    bp->api_name = strdup(api_name);
    bp->debug_flag = debug_flag;
    bp->enable = enable;
    HASH_ADD_STR(pending_db, api_name, bp);
    return 0;
}

int load_api_addr_info (const char *sym_file, pid_t pid)
{
    char *line = NULL, *api_info;
    char offset_buf[128] = {0}, api_name[128] = {0};
    FILE *cfg_fp;
    size_t nread, len;
    struct api_info_ *api;
    int rc;

    cfg_fp = fopen(sym_file, "rb");
    if (!cfg_fp) {
        return -1;
    }

    while ((nread = getline(&line, &len, cfg_fp)) != -1) {
        api_info = trim(line);
        if (api_info[0] == '#') {
            continue;
        }
        memset(offset_buf, 0, sizeof(offset_buf));
        memset(api_name, 0, sizeof(api_name));
        rc = sscanf(api_info, "%127s %127s\n", api_name, offset_buf);
        if (rc == 2) {
            api = malloc(sizeof(api_info_t));
            assert(api);
            memset(api, 0, sizeof(struct api_info_));
            api->api_name = strdup(api_name);
            api->api_offset = strtoul(offset_buf, NULL, 16);
            HASH_ADD_STR(api_db, api_name, api);

            if (strncmp(api_name, "self:", strlen("self:")) == 0) {
                HASH_ADD(off_hdl, offset_db, api_offset, sizeof(long), api);
            }
            if (debug_bp > BP_VERBOSE) {
                printf("Loaded API info (%s:%lx) to DB\n", api->api_name, api->api_offset);
            }
        } else if (debug_bp > BP_VERBOSE) {
            printf("Invalid API info line (%s) skipped\n", api_info);
            continue;
        }
    }

    free(line);
    fclose(cfg_fp);
    if (debug_bp) {
        printf("Inserted %d APIs in to API info DB\n", HASH_COUNT(api_db));
    }
    return 0;
}
///////////////////////////////////////////////////////////////////////////////
void stop_other_threads (struct traced_process_ *proc, pid_t exclude_tid)
{
    struct thread_info_ *cur, *tmp;
    int sig, status;
    pid_t tid;

    HASH_ITER(hh, proc->thread_set, cur, tmp) {
        if (cur->state == TRAPPED) {
            continue;
        }

        syscall(SYS_tgkill, proc->tgid, cur->tid, SIGSTOP);
        while (1) {
            tid = mywaitpid(cur->tid, &status, __WALL);
            sig = WSTOPSIG(status);
            if (tid == -1 || !WIFSTOPPED(status)) {
                continue;
            }

            if (sig == SIGSTOP) {
                if (debug_bp) {
                    printf("Process %d stopped\n", tid);
                }
                cur->state = STOPPED;
                return;
            } else if (sig == SIGTRAP) {
                if (debug_bp) {
                    printf("Process %d trapped\n", tid);
                }
                cur->state = TRAPPED;
                break;
            }
        }
    }
}

pid_t wait_trap (struct traced_process_ *proc)
{
    struct thread_info_ *cur;
    int stat, sig;
    pid_t tid;

    tid = mywaitpid(-1, &stat, __WALL);
    HASH_FIND_INT(proc->thread_set, &tid, cur);
    if (!cur) {
        return -1;
    }
    sig = WSTOPSIG(stat);
    if (WIFSTOPPED(stat) && (sig == SIGTRAP || sig == SIGSEGV || sig == SIGILL)) {
        /* If another thread hit breakpoint or stopped again now,
         * without mywaitpid(to hook signal), the unhandled signal may kill proc
         * To avoid crash, has to stop all threads.
         */
        cur->state = TRAPPED;
        stop_other_threads(proc, tid);
        if (debug_bp) {
            printf("All processes except %d stopped\n", tid);
        }
        return tid;
    }

    /* return means, goback to wait since this API will be invoked again soon */
    return -1;
}

void invoke_user_hook (pid_t tid, struct breakpoint_info_ *bp, struct user_regs_struct *regs)
{
    char *error, func_name[MAX_HOOK_FN_LEN] = {0}, *real_name;
    void *hook_fn;

    if (!plugin_handle) {
        return;
    }
    cur_pid = tid;
    real_name = strstr(bp->api_name, ":");
    if (!real_name) {
        return;
    }
    real_name++;
    if (bp->is_return) {
        snprintf(func_name, MAX_HOOK_FN_LEN, "exit_%s", real_name);
        hook_fn = dlsym(plugin_handle, func_name);
    } else {
        snprintf(func_name, MAX_HOOK_FN_LEN, "enter_%s", real_name);
        hook_fn = dlsym(plugin_handle, func_name);
    }
    if (!hook_fn || (error = dlerror()) != NULL) {
        return;
    }
#ifdef __arm__
    ((user_hook_fn)hook_fn)(regs->regs[0], regs->regs[1], regs->regs[2], regs->regs[3], regs->regs[4], regs->regs[5]);
#else
    ((user_hook_fn)hook_fn)(regs->rdi, regs->rsi, regs->rdx, regs->rcx, regs->r8, regs->r9);
#endif
}

static int step_over_lwp (struct traced_process_ *proc, pid_t pid)
{
    int i, depth, status;
    long trace_ip[MAX_DEPTH], addr;
    struct breakpoint_info_* bp;
    struct user_regs_struct regs;

#ifdef __arm__
    struct iovec io_vec;

    io_vec.iov_base = &regs;
    io_vec.iov_len = sizeof(struct user_regs_struct);
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io_vec);
    addr = regs.pc;
#else
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    addr = regs.rip - sizeof(break_instr);
#endif

    HASH_FIND(hh, active_bp_db, &addr, sizeof(long), bp);
    if (!bp) {
        /* This can be a watch triggered trap */
        depth = remote_backtrace(proc, trace_ip);
        printf("Triggered by unknown bp, pc addr = %lx: ", addr);
        for (i = 0; i < depth; i++) {
            printf("[%lx]", trace_ip[i]);
        }
        printf("\n");
        return -1;
    }
    bp->hit_cnt++;
    if (coredump_callback && (bp->debug_flag & GENERATE_CORE)) {
        char cfn[32] = {0};

        bp->debug_flag &= ~GENERATE_CORE;
        sprintf(cfn, "%08d.core", core_fn_cnt);
        coredump_callback(cfn, proc);
        core_fn_cnt++;
    }

if (bp->debug_flag & INVOKE_USER_HOOK) {
    invoke_user_hook(pid, bp, &regs);
}
if (bp->is_return == false) {
    insert_breakpoint_for_return(bp, proc->tgid, &regs);
}
if (ptrace(PTRACE_POKETEXT, proc->tgid, bp->sys_addr, bp->orig_code) < 0) {
    printf("Fail to restore code\n");
    return -1;
}

#ifdef __arm__
regs.pc = addr;
if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &io_vec)) {
    printf("Fail to set args, error = %s\n", strerror(errno));
    return -1;
}
#else
regs.rip = addr;
if (ptrace(PTRACE_SETREGS, pid, NULL, &regs)) {
    printf("Fail to set args\n");
    return -1;
}
#endif

if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
    printf("Fail to singalstep\n");
    return -1;
}
pid = mywaitpid(pid, &status, __WALL);
while(pid == -1 || !WIFSTOPPED(status)) {
    pid = mywaitpid(pid, &status, __WALL);
}
if (bp->debug_flag) {
    print_callinfo(proc, bp, pid, bp->is_return);
}
if (((bp->expected_life == 0) || (bp->expected_life < bp->hit_cnt))
        && exit_flag == false) {
    insert_breakpoint_to_target(pid, bp);
} else {
    HASH_DEL(active_bp_db, bp);
    free(bp->api_name);
    free(bp);
}

return 0;
}

static void similarity_data (void)
{
    FILE *sim_fp;

    struct breakpoint_info_ *bp, *tmp_bp;

    sim_fp = fopen(SIMULARITY_FILE, "w");
    assert(sim_fp);

    HASH_ITER(hh, active_bp_db, bp, tmp_bp) {
        fprintf(sim_fp, "%s %ld\n", bp->api_name, bp->hit_cnt);
    }
    fclose(sim_fp);
}

int get_name_callback (struct dl_phdr_info *info, size_t size, void *data)
{
    const char * libname = (const char *)data;

    if (strstr(info->dlpi_name, libname)) {
        for (int j = 0; j < info->dlpi_phnum; j++) {
            if (info->dlpi_phdr[j].p_type == PT_DYNAMIC) {
                Elf64_Sym * symtab = NULL;
                char * strtab = NULL;
                int symentries = 0;
                Elf64_Dyn* dyn = (Elf64_Dyn *)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
                for (int k = 0; k < info->dlpi_phdr[j].p_memsz / sizeof(Elf64_Dyn); ++k) {
                    if (dyn[k].d_tag == DT_SYMTAB) {
                        symtab = (Elf64_Sym *)dyn[k].d_un.d_ptr;
                    }
                    if (dyn[k].d_tag == DT_STRTAB) {
                        strtab = (char*)dyn[k].d_un.d_ptr;
                    }
                    if (dyn[k].d_tag == DT_SYMENT) {
                        symentries = dyn[k].d_un.d_val;
                    }
                }

                int size = strtab - (char *)symtab;
                for (int k = 0; k < size / symentries; ++k) {
                    Elf64_Sym* sym = &symtab[k];
                    char* str = &strtab[sym->st_name];
                    char api_name[MAX_HOOK_FN_LEN] = {0};

                    if (debug_bp) {
                        printf("Found pulgin API %s\n", str);
                    }
                    if (strncmp(str, "enter_", strlen("enter_")) == 0) {
                        snprintf(api_name, MAX_HOOK_FN_LEN, "self:%s", &str[strlen("enter_")]);
                        insert_one_pending_breakpoint(api_name, INVOKE_USER_HOOK|SHOW_API_NAME, true);
                    } else if (strncmp(str, "exit_", strlen("exit_")) == 0) {
                        snprintf(api_name, MAX_HOOK_FN_LEN, "self:%s", &str[strlen("exit_")]);
                        insert_one_pending_breakpoint(api_name, INVOKE_USER_HOOK|SHOW_API_NAME, true);
                    } else if (debug_bp > BP_WARNING) {
                        printf("API %s in plugin is skiped, API name not started [enter_*|exit_*] )\n", api_name);
                    }
                }
                break;
            }
        }
    }
    return 0;
}

void load_plugin_apis (void)
{
    char plugin_so_path[PATH_MAX], cwd[PATH_MAX - sizeof(PLUGIN_NAME) - 1];

    if(getcwd(cwd, sizeof(cwd)) != NULL) {
        sprintf(plugin_so_path, "%s/%s", cwd, PLUGIN_NAME);
        plugin_handle = dlopen(plugin_so_path, RTLD_NOW);
        if (plugin_handle) {
#ifdef __arm__
#else
            dl_iterate_phdr(get_name_callback, PLUGIN_NAME);
#endif
        } else {
            printf("Fail to open plugin so %s, error: %s\n", plugin_so_path, dlerror());
        }
    }
}

/* Return how many API under monitoring */
int load_active_breakpoints (const char *breakpoint_file)
{
    ssize_t nread;
    size_t len;
    int rc,  debug_flag, bp_cnt;
    char *line = NULL, *bp_cfg, api_name[MAX_INFO_LEN], flag_str[MAX_INFO_LEN];
    FILE *bfp;

    load_plugin_apis();
    bfp = fopen(breakpoint_file, "rb");
    if (!bfp) {
        return 0;
    }
    while ((nread = getline(&line, &len, bfp)) != -1) {
        bp_cfg = trim(line);

        memset(api_name, 0, sizeof(api_name));
        memset(flag_str, 0, sizeof(flag_str));
        rc = sscanf(bp_cfg, "%s %s\n", api_name, flag_str);
        debug_flag = 0;
        if (rc > 1) {
            debug_flag = strtoul(flag_str, NULL, 16);
        }
        insert_one_pending_breakpoint(api_name, debug_flag|SHOW_API_NAME, true);
    }
    free(line);
    fclose(bfp);

    bp_cnt = HASH_COUNT(pending_db);
    if (bp_cnt == 0) {
        printf("No breakpoint defined, exit\n");
        return 0;
    }

    printf("\nIn total requested %d pending breakpoints\n", bp_cnt);
    return 0;
}

static pid_t debug_pid;

void watchdog_exit (void)
{
    disable_all_breakpoints(debug_pid);
    detach_process(debug_pid);

    raise(SIGABRT);
}

int breakpoint_main_loop (pid_t target_pid)
{
    pid_t tid;
    int status, rc;
    struct traced_process_ *proc;
    struct thread_info_ *cur, *tmp;

    proc = get_traced_proc(target_pid);
    if ((status = attach_process(target_pid)) < 0) {
        printf("Insert BP: Fail to attach process %d\n", target_pid);
        return -1;
    }
    rc = enable_pending_breakpoints(target_pid);
    printf("Enabled [%d]  breakpoints, [%d] in active db\n", rc, HASH_COUNT(active_bp_db));

    debug_pid = target_pid;
    start_watchdog(watchdog_exit);

    do {
        if (HASH_COUNT(active_bp_db) == 0) {
            break;
        }
        feed_dog();
        ptrace_cont_all(proc);
        /* breakpoint operation use target_pid/tgid, process operation use lwp/tid */
        tid = wait_trap(proc);
        if (tid == -1) {
            continue;
        }
        HASH_ITER(hh, proc->thread_set, cur, tmp) {
            if (cur->state == TRAPPED) {
                rc = step_over_lwp(proc, tid);
                if (rc == -1) {
                    break;
                }
            }
        }
    } while(exit_flag == false);

    disable_all_breakpoints(target_pid);
    detach_process(target_pid);
    similarity_data();
    return 0;
}

int tool_version (void)
{
    return 1;
}

char* tool_addr_to_api_name (long addr)
{
    struct api_info_ *bp;
    long offset;

    if (!addr) {
        return NULL;
    }
    offset = addr - self_base_addr(cur_pid);
    HASH_FIND(off_hdl, offset_db, &offset, sizeof(long), bp);
    if (bp && strncmp(bp->api_name, "self:", strlen("self:")) == 0) {
        return &bp->api_name[strlen("self:")];
    } else if (bp) {
        return &bp->api_name[0];
    }
    return NULL;
}

void tool_getdata (long addr, char *str, int len)
{
    ptrace_getdata(cur_pid, addr, str, len);
}

int tool_break_on (char *api_name, int debug_flag)
{
    return insert_one_pending_breakpoint(api_name, debug_flag, true);
}
