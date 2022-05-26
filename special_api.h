#ifndef SPECIAL_API_H
#define SPECIAL_API_H

#include "breakpoint.h"
int display_callback_function (pid_t tid, struct breakpoint_info_ *bp,
                               struct user_regs_struct *regs);

#endif
