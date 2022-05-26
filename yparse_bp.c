#include "yparse_bp.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <yaml.h>
#include <uthash.h>
#include <assert.h>
#include "breakpoint.h"

typedef enum {
    CFG_INVALID,
    HOST_FILE,
    HOST_OFFSET,
    SHADOW_FILE,
    SHADOW_OFFSET,
    FUNC_NAME,
    FUNC_SIZE,
    DEBUG_FLAG,
    PROC_QUEUE,
    PROC_NAME
} bp_cfg_item_e;

bool good_bp_candidate (struct breakpoint_info_ *bp)
{
    if (bp->func_name == NULL
            || bp->func_size == 0
            || bp->host_offset == 0) {
        return false;
    }

    return true;
}

/*
 * breakpointset
 *  - host_file: /home/lnx/mycode/infect/victim
 *    host_offset: 0x1258
 *    shadow_file: /home/lnx/mycode/infect/libmax.so
 *    enter_shadow_offset: 0x1119
*/

int parse_breakpoint_config (FILE *file, pid_t pid, iter_func_fn callback)
{
    yaml_parser_t parser;
    yaml_token_t token;
    int done = 0;
    struct breakpoint_info_ bp, *cur_bp = &bp;
    char *scalar_value;
    bp_cfg_item_e item = CFG_INVALID;
    char *proc_name = NULL;

    assert(yaml_parser_initialize(&parser));
    yaml_parser_set_input_file(&parser, file);

    while (!done) {
        if (!yaml_parser_scan(&parser, &token)) {
            break;
        }

        if (token.type == YAML_SCALAR_TOKEN) {
            scalar_value = (char*)token.data.scalar.value;
            switch (item) {
            case HOST_FILE:
                cur_bp->host_file = strdup(scalar_value);
                break;
            case HOST_OFFSET:
                cur_bp->host_offset = strtoul(scalar_value, NULL, 16);
                break;
            case FUNC_NAME:
                cur_bp->func_name = strdup(scalar_value);
                break;
            case FUNC_SIZE:
                cur_bp->func_size = strtoul(scalar_value, NULL, 10);
                break;
            case DEBUG_FLAG:
                cur_bp->debug_flag = strtoul(scalar_value, NULL, 16);
                break;
            default:
                item = CFG_INVALID;
                break;
            }
        }

        switch(token.type) {
        case YAML_BLOCK_END_TOKEN:
            if (good_bp_candidate(cur_bp)&& callback) {
                callback(pid, cur_bp);
            }
            memset(cur_bp, 0, sizeof(struct breakpoint_info_));
            break;
        case YAML_BLOCK_ENTRY_TOKEN:
            memset(cur_bp, 0, sizeof(struct breakpoint_info_));
            free(proc_name);
            proc_name = NULL;
            break;
        case YAML_FLOW_ENTRY_TOKEN:
            printf("Get YAML_FLOW_ENTRY_TOKEN\n");
            break;
        case YAML_SCALAR_TOKEN:
            scalar_value = (char*)token.data.scalar.value;
            //printf(" YAML_SCALAR_TOKEN %s\n", scalar_value);
            if (strncmp(scalar_value, "proc_hdr", strlen("proc_hdr")) == 0) {
                item = PROC_QUEUE;
            } else if (strncmp(scalar_value, "proc_name", strlen("proc_name")) == 0) {
                item = PROC_NAME;
            } else if (strncmp(scalar_value, "host_file", strlen("host_file")) == 0) {
                item = HOST_FILE;
            } else if (strncmp(scalar_value, "host_offset", strlen("host_offset")) == 0) {
                item = HOST_OFFSET;
            } else if (strncmp(scalar_value, "shadow_file", strlen("shadow_file")) == 0) {
                item = SHADOW_FILE;
            } else if (strncmp(scalar_value, "shadow_offset", strlen("shadow_offset"))==0) {
                item = SHADOW_OFFSET;
            } else if (strncmp(scalar_value, "func_name", strlen("func_name")) == 0) {
                item = FUNC_NAME;
            } else if (strncmp(scalar_value, "func_size", strlen("func_size")) == 0) {
                item = FUNC_SIZE;
            } else if (strncmp(scalar_value, "debug_flag", strlen("debug_flag")) == 0) {
                item = DEBUG_FLAG;
            } else {
                item = CFG_INVALID;
            }
            break;
        default:
            break;
        }
        done = (token.type == YAML_STREAM_END_TOKEN);
        yaml_token_delete(&token);
    }
    yaml_parser_delete(&parser);
    return 0;
}

#if 0
static char test_cfg_buf[] = \
                             "breakpoints:\n"
                             " - host_offset: 0000000009955d30\n"
                             "   func_name: func_to_so\n"
                             "   host_file: test.so\n"
                             "   func_size: 1428\n"

void check_breakpoint (pid_t pid, struct breakpoint_info_ *bp)
{
    assert(pid == 0x55aa);
    printf("API: %s host: %s offset: %lx, size = %d\n",
           bp->func_name,
           bp->host_file?bp->host_file:"NULL",
           bp->host_offset,
           bp->func_size);
}

int main()
{
    FILE *fd = fmemopen(test_cfg_buf, strlen(test_cfg_buf), "r");
    parse_breakpoint_config (fd, 0x55aa, check_breakpoint);
}
#endif
