#include "special_api.h"

#include <stdio.h>
#include <sys/user.h>

#define SPECIAL_API "__be_insert_slowest_cmd"

char* addr_to_api_name (pid_t tid, long addr)
{
    struct breakpoint_info_ *bp;

    if (!addr) {
        return NULL;
    }
    bp = get_breakpoint_via_addr(tid, addr);
    if (bp && strncmp(bp->api_name, "__be_", strlen("__be_")) == 0) {
        return &bp->api_name[strlen("__be_")];
    }
    return NULL;
}

int display_callback_function (pid_t tid, struct breakpoint_info_ *bp, struct user_regs_struct *regs)
{
    long param1;
    char *callback;

    param1 = regs->rdi&0x7fffffffffffffff;
    if (bp->is_return ||
            strncmp(bp->api_name, SPECIAL_API, strlen(SPECIAL_API))) {
        return -1;
    }

    /* Assume your API's parameter is callback function pointer, we want to convert it back to API name */
    callback = addr_to_api_name(tid, param1);
    printf("Callback : %s\n", callback?callback:"NULL");
    return 0;
}
