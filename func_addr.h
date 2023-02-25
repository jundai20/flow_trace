#ifndef FUNC_ADDR_H
#define FUNC_ADDR_H
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <uthash.h>

#define MAX_PATH_LEN 256

typedef struct so_load_info_ {
    /* Key is so_name */
    char *so_name;
    long addr_start;
    long addr_end;

    size_t st_size;
    char *full_path;

    UT_hash_handle hh;
} so_load_info;


struct vm_zone_ {
    struct vm_zone_ *next;

    char *path;
    uint32_t p_flags;
    long addr_start;
    long addr_end;

    long p_filesz;
};

struct share_mem_zone_ {
    struct share_mem_zone_ *next;

    char *name;
    long addr_start;
    long addr_end;
};

typedef struct api_addr_info_ {
    char *so_name;
    char *func_name;

    long offset;
    long addr_start;
    long addr_end;


    UT_hash_handle hh;
} api_addr_info_t;

struct proc_so_ {
    char *proc_basename;
    char *full_path;
    long base_addr;

    UT_hash_handle hh;
};

struct proc_addr_info_ {
    /* Key is pid */
    pid_t pid;

    char *self_name;
    char *full_name;
    long addr_start, addr_end;
    long exe_start, exe_end;
    int vm_cnt;

    bool sym_loaded;

    /* Duplicate name not supported to simplify logic */
    struct api_addr_info_ *api_set;
    struct proc_so_ *lib_set;
    struct share_mem_zone_ *shmem_hdr;
    struct vm_zone_ *vm_hdr;

    struct so_load_info_ *vm_zone;
    char *trace_key;

    UT_hash_handle hh;
};

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
int get_self_api_addr (pid_t pid, const char *api_name, long *addr_start, long *addr_end);
int get_so_api_addr (pid_t pid, const char *lib_name, const char *api_name, long *addr_start);

void generate_func_description (pid_t pid, const char *cfg_file, const char *breakpoint_file);
#endif
