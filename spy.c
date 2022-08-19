#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <sched.h>

#include "log.h"
#include "spy.h"
#include "proc_ptrace.h"
#include "func_addr.h"
#include "breakpoint.h"
#include "special_api.h"

typedef struct cmd_param_ {
    int target_pid;
    long dlopen_fn, dlsym_fn, exe_fn;
    char *so_name;
} cmd_param_t;

#define SYM_FILE "api_list.txt"
#define BP_FILE "bp_list.txt"

void sigint_handler(int num)
{
    breakpoint_exit_loop();
}

void show_usage (char *app)
{
    printf("This tool support following functions:\n");
    printf("    -p target process id\n");
    printf("    -g generate function description\n");
    printf("    -o output log\n");
}

/* inject so, then run this application again because proc map will be changed. */
int main(int argc, char **argv)
{
    char ch, *log_file = NULL;
    cmd_param_t req;
    FILE *cfg_fp, *bp_fp;

    struct sched_param param;
    int pid_num = 0;
    bool gen_cfg = false;

    param.sched_priority = 99;
    sched_setscheduler(pid_num, SCHED_FIFO, &param);

    setbuf(stdout, NULL);
    //printf("Welcome to kludge debugger, compiled @ %s:%s\n", __DATE__, __TIME__);
    memset(&req, 0, sizeof(req));
    while ((ch = getopt(argc, argv, "p:o:gh")) != -1) {
        switch (ch) {
        case 'p':
            req.target_pid = strtoul(optarg, 0, 10);
            break;
        case 'o':
            log_file = strdup(optarg);
            break;
        case 'g':
            gen_cfg = true;
            break;
        case 'h':
            show_usage(argv[0]);
            return 0;
        default:
            break;
        }
    }
    if (req.target_pid == 0) {
        printf("Please specify process id. e.g. %s -p 1122\n", argv[0]);
        return -1;
    }
    if (kill(req.target_pid, 0)) {
        printf("Invalid process id %d, process died?\n", req.target_pid);
        return -1;
    }
    if (gen_cfg) {
        generate_func_description(req.target_pid, SYM_FILE);
        printf("Check generated API description file %s, please\n", SYM_FILE);
        return 0;
    }

    cfg_fp = fopen(SYM_FILE, "rb");
    if (!cfg_fp) {
        printf("Fatal: can not open function decription file %s\n", SYM_FILE);
        printf("       You may want to run: '%s -g -p %d'\n", argv[0], req.target_pid);
        return -1;
    }
    load_api_addr_info(cfg_fp, req.target_pid);
    bp_fp = fopen(BP_FILE, "rb");
    if (!bp_fp) {
        printf("Fatal: can not open breakpoints decription file %s\n", BP_FILE);
        return -1;
    }
    if (load_active_breakpoints(bp_fp, req.target_pid) < 0) {
        printf("Fatal: breakpoint not valid\n");
        return -1;
    }

    printf("Initializing, be patient please...\n");
    log_subsys_init(log_file);
    signal(SIGINT, sigint_handler);
    regist_api_hook(display_callback_function);
    breakpoint_main_loop(req.target_pid);
}
