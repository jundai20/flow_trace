#ifndef TOOL_FUNC_H
#define TOOL_FUNC_H

#define SHOW_API_NAME 1
#define SHOW_BACKTRACE 2
#define GENERATE_CORE 4
#define INVOKE_USER_HOOK 8

int tool_version (void);
void tool_getdata (long addr, char *str, int len);
void output_message(const char *format, ...);
char* tool_addr_to_api_name (long addr);
int tool_break_on (char *api_name, int debug_flag, int enable);
#endif
