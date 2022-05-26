#include "special_api.h"

#include <stdio.h>
#include <sys/user.h>

char* addr_to_api_name (pid_t tid, long addr)
{
    struct breakpoint_info_ *bp;

    if (!addr) {
        return NULL;
    }
    bp = get_breakpoint_via_addr(tid, addr);
    if (bp && strncmp(bp->func_name, "__be_", strlen("__be_")) == 0) {
        return &bp->func_name[strlen("__be_")];
    }
    return NULL;
}

int display_callback_function (pid_t tid, struct breakpoint_info_ *bp, struct user_regs_struct *regs)
{
    long param1;
    char *callback;

    param1 = regs->rdi&0x7fffffffffffffff;
    if (bp->is_return ||
        strncmp(bp->func_name, "__be_insert_slowest_cmd", strlen("__be_insert_slowest_cmd"))) {
        return -1;
    }

    callback = addr_to_api_name(tid, param1);
    printf("Callback : %s\n", callback?callback:"NULL");
    return 0;
}
