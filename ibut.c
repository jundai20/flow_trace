#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <sched.h>

#include "log.h"
#include "ibut.h"
#include "func_addr.h"
#include "breakpoint.h"
#include "generate_core.h"

typedef struct cmd_param_ {
    int target_pid;
    long dlopen_fn, dlsym_fn, exe_fn;
    char *so_name;
} cmd_param_t;

#define SYM_FILE "api_list.txt"
#define BP_FILE "bp_list.txt"
#define ALT_STACK_SIZE (64*1024)

extern int debug_bp;

void sigint_handler (int signum, siginfo_t *si, void* arg)
{
    breakpoint_exit_loop();
}

static void register_sigaltstack ()
{
    stack_t newSS, oldSS;

    newSS.ss_sp = malloc(ALT_STACK_SIZE);
    newSS.ss_size = ALT_STACK_SIZE;
    newSS.ss_flags = 0;
    sigaltstack(&newSS, &oldSS);
}

void show_usage (char *app)
{
    printf("This tool support following functions:\n");
    printf("    -p target process id\n");
    printf("    -b breakpoint list\n");
    printf("    -s api offset description file\n");
    printf("    -o output log\n");
}

static void setup_signal_handlers ()
{
    struct sigaction action;

    register_sigaltstack();
    action.sa_sigaction = &sigint_handler;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_ONESHOT;
    sigaction(SIGINT, &action, NULL);
}

/* inject so, then run this application again because proc map will be changed. */
int main(int argc, char **argv)
{
    char *log_file = NULL;
    const char *sym_file = SYM_FILE, *breakpoint_file = BP_FILE;
    cmd_param_t req;
    int ch;

    setbuf(stdout, NULL);
    printf("Welcome to kludge debugger, compiled @ %s:%s\n", __DATE__, __TIME__);
    setup_signal_handlers();

    memset(&req, 0, sizeof(req));
    while ((ch = getopt(argc, argv, "p:b:o:s:v:h")) != -1) {
        switch (ch) {
        case 'p':
            req.target_pid = strtoul(optarg, 0, 10);
            break;
        case 'o':
            log_file = strdup(optarg);
            break;
        case 's':
            sym_file = strdup(optarg);
            break;
        case 'b':
            breakpoint_file = strdup(optarg);
            break;
        case 'h':
            show_usage(argv[0]);
            return 0;
        case 'v':
            debug_bp = atoi(optarg);
            break;
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
    if (access(sym_file, F_OK) != F_OK) {
        printf("Symbol file not available, generate symbol automatically?\n");
        generate_func_description(req.target_pid, sym_file, breakpoint_file);
    }

    printf("Initializing, be patient please...\n");
    if (load_api_addr_info(sym_file, req.target_pid) != 0) {
        printf("Fatal: can not open function decription file %s\n", SYM_FILE);
        printf("       You may want to run: '%s -g -p %d'\n", argv[0], req.target_pid);
        return -1;
    }
    log_subsys_init(log_file);
    coredump_callback = generate_coredump;
    load_active_breakpoints(breakpoint_file);
    breakpoint_main_loop(req.target_pid);
}
