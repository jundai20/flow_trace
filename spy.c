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
#include "yparse_bp.h"
#include "func_addr.h"
#include "breakpoint.h"
#include "special_api.h"

typedef struct cmd_param_ {
    int target_pid;
    long dlopen_fn, dlsym_fn, exe_fn;
    char *so_name;
} cmd_param_t;

/* Following default file names should be the same as names in generate_bp.py */
#define SYM_FILE "func_info.txt"
void sigint_handler(int num)
{
    breakpoint_exit_loop();
}

void show_usage (char *app)
{
    printf("This tool support following functions:\n");
    printf("    -p target process id, by default, it is IOSd\n");
    printf("    -b additional breakpoint file\n");
    printf("    -c input function description file\n");
    printf("    -g generate function description\n");
    printf("    -o output log\n");
}

/* inject so, then run this application again because proc map will be changed. */
int main(int argc, char **argv)
{
    char ch, *cfg_file = NULL, *breakpoint_file = NULL, *output_file = NULL;
    cmd_param_t req;
    FILE *cfg_fp;

    struct sched_param param;
    int pid_num = 0;
    bool gen_cfg = false;

    param.sched_priority = 99;
    sched_setscheduler(pid_num, SCHED_FIFO, &param);

    setbuf(stdout, NULL);
    printf("Welcome to kludge debugger, compiled @ %s:%s\n", __DATE__, __TIME__);
    memset(&req, 0, sizeof(req));
    while ((ch = getopt(argc, argv, "p:s:e:b:c:o:atgh")) != -1) {
        switch (ch) {
        case 'p':
            req.target_pid = strtoul(optarg, 0, 10);
            break;
        case 'o':
            output_file = strdup(optarg);
            break;
        case 'b':
            breakpoint_file = strdup(optarg);
            break;
        case 'c':
            cfg_file = strdup(optarg);
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
    printf("pid = %d\n", req.target_pid);

    if (gen_cfg) {
        if (output_file == NULL) {
            printf("Please specify output file name.\ne.g. %s -g -o test.txt -p 1122\n", argv[0]);
            return -1;
        }
        generate_func_description(req.target_pid, output_file);
        return 0;
    }

    if (log_subsys_init(output_file)) {
        printf("Warning: can't start logging subsystem\n");
    }
    signal(SIGINT, sigint_handler);
    if (req.target_pid == 0) {
        printf("Detecting default process to mointor...");
    }
    if (kill(req.target_pid, 0)) {
        printf("Invalid process id %d, process died?\n", req.target_pid);
        return -1;
    }
    printf("Initializing, be patient please...\n");
    cfg_file = cfg_file?cfg_file:SYM_FILE;
    cfg_fp = fopen(cfg_file, "rb");
    if (!cfg_fp) {
        printf("Fatal: can not open function decription file %s\n", cfg_file);
        printf("       you can generate it under workspace or auto generate it by '%s -g -o xxx'\n", argv[0]);
        return -1;
    }
    parse_breakpoint_config(cfg_fp, req.target_pid, configure_breakpoint);
    if(breakpoint_file) {
        /* If you want to monitor a few more additional APIs manually */
        load_breakpoint_set(req.target_pid, breakpoint_file);
    }

    regist_api_hook(display_callback_function);
    breakpoint_main_loop(req.target_pid);
}
