#ifndef FUNC_ADDR_H
#define FUNC_ADDR_H
#include <sys/types.h>
#include <stdbool.h>
#include <uthash.h>

typedef struct so_load_info_ {
    /* Key is so_name */
    char *so_name;
    long addr_start;
    long addr_end;

    size_t st_size;
    char *full_path;

    UT_hash_handle hh;
} so_load_info;

int find_target_pid (const char *app);
long get_dlopen_addr (pid_t pid);
long get_dlsym_addr (pid_t pid);
void display_backtrace (pid_t pid, int cnt, long *bt);
long soname_to_addr (pid_t pid, const char *so_name);
long self_base_addr (int pid);
bool addr_in_range (pid_t pid, long addr);
struct proc_addr_info_* get_proc_addrinfo (pid_t pid);
struct so_load_info_* get_so_info (pid_t pid, const char *so_name);

typedef void (*so_iter_fn) (so_load_info *lib, void *ctx);
void iterator_library (pid_t pid, so_iter_fn fn,void *ctx);

int get_api_addr (pid_t pid, const char *api_name, long *addr_start, long *addr_end);
void generate_func_description (pid_t pid, char *cfg_file);
#endif
