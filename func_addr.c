#include "func_addr.h"

#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/resource.h>
#include <uthash.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <elf.h>
#include <sys/mman.h>
#include <limits.h>
#include <libgen.h>

#include "pmparser.h"

static struct proc_addr_info_ *proc_addr_set;

static char* pid_to_exec_file (int pid)
{
    char *name1, *name2, *proc_self_name;

    name1 = (char*)malloc (MAX_PATH_LEN);
    name2 = (char*)malloc (MAX_PATH_LEN);
    memset (name1, 0, MAX_PATH_LEN);
    memset (name2, 0, MAX_PATH_LEN);

    sprintf (name1, "/proc/%d/exe", pid);
    if (readlink (name1, name2, MAX_PATH_LEN) > 0) {
        proc_self_name = name2;
    } else {
        proc_self_name = name1;
    }
    return proc_self_name;
}

static char* file_base_name (char const *path)
{
    char *s = strrchr(path, '/');

    if (s) {
        return strdup((const char*)s+1);
    } else {
        return strdup((const char*)path);
    }
}

static void append_vm_info (struct proc_addr_info_ *proc, procmaps_struct *cur_map)
{
    struct vm_zone_ *vm_info, *tmp_vm = proc->vm_hdr;

    vm_info = calloc(1, sizeof(struct vm_zone_));
    assert(vm_info);
    vm_info->path = strdup(cur_map->pathname);
    assert(vm_info->path);
    vm_info->addr_start = (long)cur_map->addr_start;
    vm_info->addr_end = (long)cur_map->addr_end;
    if (cur_map->is_r) {
        vm_info->p_flags |= 0x04;
    }
    if (cur_map->is_w) {
        vm_info->p_flags |= 0x02;
    }
    if (cur_map->is_x) {
        vm_info->p_flags |= 0x01;
    }

    if (tmp_vm) {
        while (tmp_vm->next) {
            tmp_vm = tmp_vm->next;
        }
        tmp_vm->next = vm_info;
    } else {
        proc->vm_hdr = vm_info;
    }
}

static void append_so_info (struct proc_addr_info_ *proc, procmaps_struct *cur_map)
{
    so_load_info *so_info, *prev_info;
    struct proc_so_ *lib;
    char *so_name = file_base_name(cur_map->pathname);

    HASH_FIND_STR(proc->vm_zone, so_name, prev_info);
    if (prev_info) {
        return;
    }

    so_info = calloc(1, sizeof(so_load_info));
    assert(so_info);
    so_info->addr_start = (long)cur_map->addr_start;
    so_info->addr_end = (long)cur_map->addr_end;
    so_info->so_name = so_name;
    so_info->full_path = strdup(cur_map->pathname);
    //printf("VM area %s\n    %lx-%lx, perm = %s\n", so_info->full_path, so_info->addr_start, so_info->addr_end, cur_map->perm);
    HASH_ADD_STR(proc->vm_zone, so_name, so_info);
    if (strstr(so_name, ".so")
            && strncmp("ld-", so_name, strlen("ld-"))
            && strncmp("linux-vdso", so_name, strlen("linux-vdso"))) {
        HASH_FIND_STR(proc->lib_set, cur_map->pathname, lib);
        if (!lib) {
            lib = malloc(sizeof(struct proc_so_));
            lib->full_path = strdup(cur_map->pathname);
            lib->proc_basename = basename(lib->full_path);
            lib->base_addr = so_info->addr_start;
            HASH_ADD_STR(proc->lib_set, proc_basename, lib);
        }
    }
}

static void save_self_exe_offset (struct proc_addr_info_ *proc, procmaps_struct *cur_map)
{
    char *so_name = file_base_name(cur_map->pathname);

    if (strncmp(proc->self_name, so_name, strlen(proc->self_name)) == 0) {
        if (proc->addr_start == 0) {
            proc->addr_start = (long)cur_map->addr_start;
            proc->addr_end = (long)cur_map->addr_end;
        }
        if (proc->exe_start == 0 && cur_map->is_x) {
            proc->exe_start = (long)cur_map->addr_start;
            proc->exe_end = (long)cur_map->addr_end;
        }
    }
}

static int read_memory_regions (struct proc_addr_info_ *proc)
{
    procmaps_iterator* maps;
    procmaps_struct *cur_map;

    proc->full_name = pid_to_exec_file(proc->pid);
    proc->self_name = basename(proc->full_name);

    maps  = pmparser_parse(proc->pid, &proc->vm_cnt);
    assert(maps);
    while( (cur_map = pmparser_next(maps)) != NULL) {
        //pmparser_print(cur_map, 0);
        save_self_exe_offset(proc, cur_map);
        append_so_info(proc, cur_map);
        append_vm_info(proc, cur_map);
    }
    pmparser_free(maps);

    return 0;
}

static void get_process_environment (struct proc_addr_info_ *proc)
{
    int fd;
    char filename[24];
    char environment[8192];
    size_t length;
    char* next_var;

    /* Generate the name of the environ file for the process. */
    snprintf (filename, sizeof (filename), "/proc/%d/environ", (int) proc->pid);

    /* Read the contents of the file. */
    fd = open (filename, O_RDONLY);
    length = read (fd, environment, sizeof (environment));
    close (fd);
    environment[length] = 0;
    /* Loop over variables. Variables are separated by NULs. */
    next_var = environment;
    while (next_var < environment + length) {
        //printf ("%s\n", next_var);
        if (strncmp(next_var, "TRACEKEY", strlen("TRACEKEY")) == 0) {
            proc->trace_key = strdup(next_var);
            return;
        }
        next_var += strlen (next_var) + 1;
    }
}

struct proc_addr_info_* get_proc_addrinfo (pid_t pid)
{
    struct proc_addr_info_ *proc;

    HASH_FIND_INT(proc_addr_set, &pid, proc);
    if (!proc) {
        proc = calloc(1, sizeof(struct proc_addr_info_));
        assert(proc);
        proc->pid = pid;
        get_process_environment(proc);
        read_memory_regions(proc);
        HASH_ADD_INT(proc_addr_set, pid, proc);
    }

    return proc;
}

static so_load_info* get_addr_lib (pid_t pid, unsigned long address)
{
    so_load_info *cur_lib, *tmp;
    struct proc_addr_info_ *proc;

    proc = get_proc_addrinfo(pid);
    HASH_ITER(hh, proc->vm_zone, cur_lib, tmp) {
        if (cur_lib->addr_start < address && cur_lib->addr_end > address) {
            return cur_lib;
        }
    }
    return NULL;
}

int find_target_pid (const char* app)
{
    FILE *fp;
    char cmd_str[32] = {0};
    char pid_str[32] = {0};
    int pid;

    sprintf(cmd_str, "pidof %s", app);
    fp = popen(cmd_str, "r");
    if (!fp) {
        perror("Fail to find default process: ");
        return 0;
    }
    if (fgets(pid_str, sizeof(pid_str), fp) == NULL) {
        return 0;
    }
    pid = strtoul(pid_str, 0, 10);
    pclose(fp);

    //printf("The [%s] pid = %d\n", app, (int)pid);
    return pid;
}

long self_base_addr (int pid)
{
    struct proc_addr_info_ *proc;

    proc = get_proc_addrinfo(pid);
    assert(proc);
    return proc->addr_start;
}

bool addr_in_range (pid_t pid, long addr)
{
    struct proc_addr_info_ *proc;

    proc = get_proc_addrinfo(pid);
    assert(proc);
    if (addr < proc->exe_start || addr > proc->exe_end) {
        //printf("addr [%lx] not in scope %lx - %lx\n", addr, proc->exe_start, proc->exe_end);
    }
    return ((addr > proc->exe_start) && (addr < proc->exe_end));
}

long soname_to_addr (pid_t pid, const char *target_so)
{
    so_load_info *cur_lib;
    struct proc_addr_info_ *proc;

    if (pid == 0) {
        return 0;
    }
    proc = get_proc_addrinfo(pid);
    assert(proc);
    if (!target_so || strncmp(target_so, "self", strlen("self")) == 0) {
        return self_base_addr(pid);
    }
    HASH_FIND_STR(proc->vm_zone, target_so, cur_lib);
    if (!cur_lib) {
        return 0;
    }
    return cur_lib->addr_start;
}

struct so_load_info_* get_so_info (pid_t pid, const char *so_name)
{
    so_load_info *cur_lib;
    struct proc_addr_info_ *proc;

    proc = get_proc_addrinfo(pid);
    if (!proc) {
        return NULL;
    }
    HASH_FIND_STR(proc->vm_zone, so_name, cur_lib);
    return cur_lib;
}

void display_backtrace (pid_t pid, int cnt, long *bt)
{
    int i;
    so_load_info *lib;
    struct proc_addr_info_ *proc;

    HASH_FIND_INT(proc_addr_set, &pid, proc);
    if (!proc) {
        return;
    }
    printf("%*s%s", cnt*2, " ", proc->trace_key?proc->trace_key:"backtrace: ");
    for (i = 0; i < cnt; i++) {
        lib = get_addr_lib(pid, bt[i]);
        if (proc->trace_key && lib) {
            printf(" :%lx+%lx", lib->addr_start, bt[i] - lib->addr_start);
        } else if (lib) {
            printf(" :[%s]%lx+%lx", lib->so_name, lib->addr_start, bt[i] - lib->addr_start);
        } else {
            printf(" :%lx", bt[i]);
        }
    }
    printf("\n");
}

struct elf64 {
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdr;
    Elf64_Sym  *sym;

    char *StringTable;
    char *SymStringTable;
};

struct syms {
    char *name;
    unsigned long value;
};

struct handle {
    char *path;
    uint8_t *map;
    struct elf64 *elf64;
};

/* Store api address information into process global api_set table, lib used to provide addr info */
static void save_symbol (struct proc_addr_info_ *proc, char *api_name,
                         struct proc_so_ *lib, Elf64_Sym  *symtab64, bool self)
{
    struct api_addr_info_ *api;

    if (symtab64->st_value == 0) {
        return;
    }
    api = malloc(sizeof(struct api_addr_info_));
    if (self) {
        api->so_name = strdup("self");
        api->func_name = strdup(api_name);
    } else {
        api->so_name = basename(lib->full_path);
    }
    api->func_name = malloc(strlen(api->so_name) + 1 + strlen(api_name) + 1);
    strcpy(api->func_name, api->so_name);
    strcat(api->func_name, ":");
    strcat(api->func_name, api_name);

    api->addr_start = lib->base_addr + symtab64->st_value;
    api->addr_end = api->addr_start + symtab64->st_size;
    api->offset = symtab64->st_value;
    HASH_ADD_STR(proc->api_set, func_name, api);
}

static int map_elf64 (struct proc_addr_info_ *proc, size_t *len, struct handle *h)
{
    int fd;
    struct stat st;

    if ((fd = open(h->path, O_RDONLY)) < 0) {
        fprintf(stderr, "Unable to open %s: %s\n", h->path, strerror(errno));
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return -1;
    }
    h->map = (uint8_t *)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (h->map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    h->elf64->ehdr = (Elf64_Ehdr *)h->map;
    h->elf64->shdr = (Elf64_Shdr *)(h->map + h->elf64->ehdr->e_shoff);
    h->elf64->StringTable = (char *)&h->map[h->elf64->shdr[h->elf64->ehdr->e_shstrndx].sh_offset];
    *len = st.st_size;

    return 0;
}

static int parse_symbols (struct proc_addr_info_ *proc, struct proc_so_ *lib, struct handle *h, bool self)
{
    unsigned int i, j;
    char *SymStrTable;
    Elf64_Ehdr *ehdr64;
    Elf64_Shdr *shdr64;
    Elf64_Sym  *symtab64;
    int st_type;
    char *name;

    ehdr64 = h->elf64->ehdr;
    shdr64 = h->elf64->shdr;
    for (i = 0; i < ehdr64->e_shnum; i++) {
        if (shdr64[i].sh_type == SHT_SYMTAB || shdr64[i].sh_type == SHT_DYNSYM) {
            SymStrTable = (char *)&h->map[shdr64[shdr64[i].sh_link].sh_offset];
            symtab64 = (Elf64_Sym *)&h->map[shdr64[i].sh_offset];
            for (j = 0; j < shdr64[i].sh_size / sizeof(Elf64_Sym); j++, symtab64++) {
                st_type = ELF64_ST_TYPE(symtab64->st_info);
                if (st_type != STT_FUNC) {
                    continue;
                }
                switch(shdr64[i].sh_type) {
                case SHT_SYMTAB:
                    name = &SymStrTable[symtab64->st_name];
                    save_symbol(proc, name, lib, symtab64, self);
                    break;
                case SHT_DYNSYM:
                    name = &SymStrTable[symtab64->st_name];
                    save_symbol(proc, name, lib, symtab64, self);
                    break;
                }
            }
        }
    }

    return 0;
}

/* Parse a library or application itself, store API information to lib */
static int read_elf_symbols (struct proc_addr_info_ *proc, struct proc_so_ *lib, bool self)
{
    struct handle elf_info;
    size_t len;
    char *file_name = lib->full_path;

    memset(&elf_info, 0, sizeof(elf_info));
    elf_info.elf64 = malloc(sizeof(struct elf64));
    elf_info.path = file_name;
    if (map_elf64(proc, &len, &elf_info)) {
        printf("Error: can not map %s to elf64\n", file_name);
        return -1;
    }
    parse_symbols(proc, lib, &elf_info, self);
    munmap(elf_info.map, len);
    free(elf_info.elf64);

    return 0;
}

/* It is expensive */
static void read_application_symbols (pid_t pid)
{
    struct proc_so_ *lib, *tmp, dummy_lib;
    struct proc_addr_info_ *proc;

    proc = get_proc_addrinfo(pid);
    memset(&dummy_lib, 0, sizeof(struct proc_so_));
    dummy_lib.full_path = proc->full_name;
    dummy_lib.base_addr = self_base_addr(pid);
    read_elf_symbols(proc, &dummy_lib, true);

    HASH_ITER(hh, proc->lib_set, lib, tmp) {
        read_elf_symbols(proc, lib, false);
    }
}

int get_self_api_addr (pid_t pid, const char *api_name, long *addr_start, long* addr_end)
{
    struct proc_addr_info_ *proc;
    struct api_addr_info_ *api;

    assert(pid);
    assert(api_name);
    assert(addr_start);

    proc = get_proc_addrinfo(pid);
    if (!proc) {
        return -1;
    }
    if (proc->sym_loaded == false) {
        read_application_symbols(pid);
        proc->sym_loaded = true;
    }

    HASH_FIND_STR(proc->api_set, api_name, api);
    if (!api) {
        return -1;
    }

    *addr_start = api->addr_start;
    if (addr_end) {
        *addr_end = api->addr_end;
    }
    return 0;
}

#define MAX_API_FULL_PATH_LEN 128

int get_so_api_addr (pid_t pid, const char *so_name, const char *api_name, long *addr_start)
{
    struct proc_addr_info_ *proc;
    struct proc_so_ *lib;
    char full_name[MAX_API_FULL_PATH_LEN] = {0};
    struct api_addr_info_ *api;

    proc = get_proc_addrinfo(pid);
    if (!proc) {
        return -1;
    }

    HASH_FIND_STR(proc->lib_set, so_name, lib);
    if (!lib) {
        return -2;
    }

    if (proc->sym_loaded == false) {
        read_application_symbols(pid);
        proc->sym_loaded = true;
    }

    sprintf(full_name, "%s:%s", so_name, api_name);
    HASH_FIND_STR(proc->api_set, full_name, api);
    if (!api) {
        return -3;
    }

    *addr_start = api->addr_start;
    return 0;
}

const char *noice_prefix[] = {
    "_",
    "register_tm_clones",
    "deregister_tm_clones",
    "frame_dummy",
    "completed"
};

void generate_func_description (pid_t pid, const char *info_file, const char *breakpoint_file)
{
    struct proc_addr_info_ *proc;
    struct api_addr_info_ *api, *tmp;
    FILE *info_fp, *bp_fp;
    int i;

    read_application_symbols(pid);
    proc = get_proc_addrinfo(pid);
    if (!proc) {
        return;
    }

    if ((bp_fp = fopen(breakpoint_file, "w")) == NULL) {
        printf("Error: can not open %s for write\n", breakpoint_file);
        return;
    }
    if ((info_fp = fopen(info_file, "w")) == NULL) {
        printf("Error: can not open %s for write\n", info_file);
        return;
    }

    HASH_ITER(hh, proc->api_set, api, tmp) {
        for (i = 0; i < sizeof(noice_prefix)/sizeof(char*); i++) {
            if (strncmp(noice_prefix[i], api->func_name, strlen(noice_prefix[i])) == 0) {
                break;
            }
        }
        if (i < sizeof(noice_prefix)/sizeof(char*)) {
            continue;
        }
        if (strncmp(api->so_name, "self", strlen("self")) == 0) {
            fprintf(info_fp, "%s %lx\n", api->func_name, api->offset);
            fprintf(bp_fp, "%s\n", api->func_name);
        } else {
            fprintf(info_fp, "%s %lx\n", api->func_name, api->offset);
        }
    }
    fclose(info_fp);
    fclose(bp_fp);
}
