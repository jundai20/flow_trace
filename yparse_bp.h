#ifndef YPARSE_BP_H

#include <stdio.h>
#include <sys/types.h>
#include "breakpoint.h"

typedef void (*iter_func_fn)(pid_t pid, struct breakpoint_info_ *bp);
int parse_breakpoint_config (FILE *cfg_fp, pid_t pid, iter_func_fn callback);
#endif
