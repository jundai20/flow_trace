#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/reg.h>
#include <stdarg.h>
#include <assert.h>
#include <sys/uio.h>
#include <uthash.h>

#include "breakpoint.h"
#include "pmparser.h"
#include "elf_core.h"
#include "func_addr.h"

#define UCORE_S_STR     1       /* slurp string */
#define UCORE_S_BIN     2       /* slurp binary */

static char ucore_pbuf[4096];
static const size_t ucore_plen = sizeof (ucore_pbuf);
char auxv_data_buf[512];
size_t auxv_data_len;
////////////////////////////////////////////////////////////////////////////////
#define P2ROUNDUP(x, a)         (-(-(x) & -(__typeof__(x))(a)))
#define U_MICROSEC      1000000ULL

int __attribute__ ((format(printf, 2, 3)))
ucore_error(int err, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);

    return (err);
}

ssize_t ucore_note_size(const char *name, size_t dlen)
{
    return (sizeof (Elf64_Nhdr) +
            P2ROUNDUP(strlen(name) + 1, sizeof (int32_t)) +
            P2ROUNDUP(dlen, sizeof (int32_t)));
}

ssize_t ucore_note_dump(int fd, off_t off, Elf64_Word type, const char *name, const void *data, size_t dlen)
{
    ssize_t nlen = ucore_note_size(name, 0);
    Elf64_Nhdr *note = alloca(nlen);

    struct iovec iov[2];
    int ioc = 0;

    if (dlen == (size_t)-1)
        return (-1); /* propagate caller's error */

    bzero(note, nlen);
    bcopy(name, note + 1, strlen(name));

    note->n_namesz = strlen(name) + 1;
    note->n_descsz = dlen;
    note->n_type = type;

    iov[ioc].iov_base = note;
    iov[ioc++].iov_len = nlen;

    iov[ioc].iov_base = (void *)data;
    iov[ioc++].iov_len = dlen;

    return (pwritev(fd, iov, ioc, off));
}

ssize_t __attribute__ ((format(printf, 4, 5)))
ucore_slurp(int mode, char *buf, size_t len, const char *fmt, ...)
{
    char path[PATH_MAX];
    va_list ap;
    ssize_t rlen;
    int fd;

    if (buf == NULL)
        return (ucore_error(ENOMEM, "failed to alloc buf"));

    va_start(ap, fmt);
    (void) vsnprintf(path, sizeof (path), fmt, ap);
    va_end(ap);

    if ((fd = open(path, O_RDONLY)) == -1)
        return (ucore_error(errno, "failed to open %s", path));

    rlen = read(fd, buf, len);
    if (rlen > 0 && mode == UCORE_S_STR && buf[rlen - 1] == '\n')
        buf[--rlen] = '\0';

    (void) close(fd);
    return (rlen);
}

int __attribute__ ((format(printf, 3, 4)))
ucore_parse(int (*func)(size_t, char *[], void *), void *farg, const char *fmt, ...)
{
    char path[PATH_MAX];
    va_list ap;

    int fd, err = 0;
    int line = 1;

    const char delims[] = " \f\n\r\t\v";
    char *eol, *eob, *rpos, *wpos;
    ssize_t len = 0;

    va_start(ap, fmt);
    (void) vsnprintf(path, sizeof (path), fmt, ap);
    va_end(ap);

    if ((fd = open(path, O_RDONLY)) == -1)
        return (ucore_error(errno, "failed to parse %s", path));

    eob = ucore_pbuf + ucore_plen - 1;
    rpos = wpos = ucore_pbuf;
    *wpos = '\0';

    do {
        char *argv[48] = { 0 };
        size_t argc = 0;
        char *p, *q;

        if ((eol = strchr(rpos, '\n')) != NULL) {
            *eol++ = '\0';
        } else {
            (void) memmove(ucore_pbuf, rpos, wpos - rpos);
            wpos -= rpos - ucore_pbuf;
            rpos = ucore_pbuf;

            if ((len = read(fd, wpos, eob - wpos)) < 0)
                break;

            wpos += len;
            *wpos = '\0';

            if (len > 0)
                continue;	/* retry EOL search */
        }

        for (p = strtok_r(rpos, delims, &q); p != NULL &&
                argc < sizeof (argv) / sizeof (argv[0]);
                p = strtok_r(NULL, delims, &q))
            argv[argc++] = p;

        if (argc != 0 && func(argc, argv, farg) != 0) {
            (void) ucore_error(errno,
                               "error at line %d of %s", line, path);

            if (errno == EPIPE || errno == EBADF)
                break; /* slave exited; abort the parse */
        }

        rpos = eol;
        line++;
    } while (rpos != NULL);

    if (len == -1)
        err = ucore_error(errno, "failed to parse %s", path);

    (void) close(fd);
    return (err);
}

////////////////////////////////////////////////////////////////////////////////
static int nt_prpsinfo_stat(size_t argc, char *argv[], void *data)
{
    struct elf_prpsinfo *p = data;
    const char states[] = "RSDTZW";

    const char *sp;
    char sname;
    long nicev;

    (void) sscanf(argv[2], "%c", &sname);
    sp = strchr(states, sname);
    (void) sscanf(argv[18], "%ld", &nicev);

    p->pr_state = sp ? (char)(sp - states) : -1;
    p->pr_sname = sname;
    p->pr_zomb = sname == 'Z';
    p->pr_nice = (char)nicev;

    (void) sscanf(argv[8], "%lu", &p->pr_flag);
    (void) sscanf(argv[0], "%d", &p->pr_pid);
    (void) sscanf(argv[3], "%d", &p->pr_ppid);
    (void) sscanf(argv[4], "%d", &p->pr_pgrp);
    (void) sscanf(argv[5], "%d", &p->pr_sid);

    return (0);
}

static int
nt_prpsinfo_uids(size_t argc, char *argv[], void *data)
{
    struct elf_prpsinfo *p = data;

    if (argc >= 5 && strcmp(argv[0], "Uid:") == 0)
        (void) sscanf(argv[1], sizeof (p->pr_uid) == 2 ? "%hd" : "%d",
                      &p->pr_uid);
    else if (argc >= 5 && strcmp(argv[1], "Gid:") == 0)
        (void) sscanf(argv[1], sizeof (p->pr_gid) == 2 ? "%hd" : "%d",
                      &p->pr_gid);

    return (0);
}

ssize_t nt_prpsinfo_dump(int fd, off_t off, int pid)
{
    struct elf_prpsinfo p;
    ssize_t i, len;

    bzero(&p, sizeof (p));
    (void) ucore_parse(nt_prpsinfo_stat, &p, "/proc/%d/stat", pid);
    (void) ucore_parse(nt_prpsinfo_uids, &p, "/proc/%d/status", pid);
    (void) ucore_slurp(UCORE_S_STR, p.pr_fname, sizeof (p.pr_fname), "/proc/%d/comm", pid);

    len = ucore_slurp(UCORE_S_BIN, p.pr_psargs, sizeof (p.pr_psargs) - 1, "/proc/%d/cmdline", pid);
    for (i = 0; i < len; i++)
        if (p.pr_psargs[i] == '\0')
            p.pr_psargs[i] = ' ';

    return (ucore_note_dump(fd, off, NT_PRPSINFO, "CORE", &p, sizeof (p)));
}

static int nt_prstatus_stat(size_t argc, char *argv[], void *data)
{
    struct elf_prstatus *p = data;

    (void) sscanf(argv[0], "%d", &p->pr_pid);
    (void) sscanf(argv[3], "%d", &p->pr_ppid);
    (void) sscanf(argv[4], "%d", &p->pr_pgrp);
    (void) sscanf(argv[5], "%d", &p->pr_sid);
    return (0);
}

ssize_t nt_prstatus_dump (int fd, off_t off, pid_t pid, pid_t tid,
                          struct user_regs_struct *regs)
{
    struct elf_prstatus p;

    bzero(&p, sizeof (p));
    (void) ucore_parse(nt_prstatus_stat, &p, "/proc/%d/task/%d/stat", pid, tid);

    if (ptrace(PTRACE_GETREGS, tid, NULL, &p.pr_reg) != 0)
        (void) ucore_error(errno, "failed to get gregs for %d", tid);

    memcpy(&p.pr_reg, regs, sizeof(struct user_regs_struct));
    return (ucore_note_dump(fd, off, NT_PRSTATUS, "CORE", &p, sizeof (p)));
}

void fill_elf_note_payload (int wfd, struct traced_process_ *proc, Elf64_Phdr *note_phdr)
{
    struct thread_info_ *cur, *tmp;
    struct user_regs_struct regs;
    unsigned long cur_offset, prstatus_len;

    cur_offset = note_phdr->p_offset;
    HASH_ITER(hh, proc->thread_set, cur, tmp) {
        ptrace(PTRACE_GETREGS, cur->tid, NULL, &regs);
        nt_prstatus_dump(wfd, cur_offset, proc->tgid, cur->tid, &regs);
        prstatus_len = ucore_note_size("CORE", sizeof(struct elf_prstatus));
        cur_offset += prstatus_len;
        if (cur->tid == proc->tgid) {
            nt_prpsinfo_dump(wfd, cur_offset, proc->tgid);
            cur_offset += ucore_note_size("CORE", sizeof(struct elf_prpsinfo));
        }
    }
    cur_offset += ucore_note_dump(wfd, cur_offset, NT_AUXV, "CORE", auxv_data_buf, auxv_data_len);
    cur_offset = P2ROUNDUP(cur_offset, sizeof(int));
}

void fill_elf_note (int wfd, Elf64_Phdr *phdr, struct traced_process_ *proc, int vm_cnt, loff_t phdr_offset)
{
    int note_size, thread_cnt;

    thread_cnt = HASH_COUNT(proc->thread_set);
    note_size = ucore_note_size("CORE", sizeof(struct elf_prstatus))*thread_cnt;
    note_size += ucore_note_size("CORE", sizeof(struct elf_prpsinfo));
    assert(auxv_data_len);
    note_size += ucore_note_size("CORE", auxv_data_len);

    memset(phdr, 0, sizeof(Elf64_Phdr));
    phdr->p_type = PT_NOTE;
    phdr->p_offset = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr)*(1 + vm_cnt);
    phdr->p_filesz = note_size;

    pwrite(wfd, phdr, sizeof(Elf64_Phdr), phdr_offset);
    fill_elf_note_payload(wfd, proc, phdr);
}
////////////////////////////////////////////////////////////////////////////////
void fill_elf_header(int wfd, int segs)
{
    Elf64_Ehdr ehdr;

    memset(&ehdr, 0, sizeof(ehdr));
    memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
    ehdr.e_ident[EI_CLASS] = ELF_CLASS;
    ehdr.e_ident[EI_DATA] = ELF_DATA;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_ident[EI_OSABI] = ELF_OSABI;

    ehdr.e_type = ET_CORE;
    ehdr.e_machine = EM_X86_64;
    ehdr.e_version = EV_CURRENT;
    ehdr.e_phoff = sizeof(Elf64_Ehdr);
    ehdr.e_flags = 0;
    ehdr.e_ehsize = sizeof(Elf64_Ehdr);
    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phnum = segs;

    pwrite(wfd, &ehdr, sizeof(ehdr), 0);
}
////////////////////////////////////////////////////////////////////////////////
void read_auxv_info (pid_t pid)
{
    int fd, i;
    char auxv_fn[64] = {0};
    ssize_t len;

    auxv_data_len = 0;
    sprintf(auxv_fn, "/proc/%d/auxv", pid);
    fd = open(auxv_fn, O_RDONLY);
    assert(fd != -1);

    while (1) {
        len = pread(fd, &auxv_data_buf[auxv_data_len], sizeof(long)*2, auxv_data_len);
        if (len == 0) {
            close(fd);
            break;
        }
        for (i = 0; i < 16; i++) {
            if (auxv_data_buf[auxv_data_len + i] == 0) {
                break;
            }
        }
        if (i == 16) {
            auxv_data_len += 16;
            close(fd);
            break;
        }
        auxv_data_len += 16;
        assert(auxv_data_len < 512);
    }
}
////////////////////////////////////////////////////////////////////////////////
int generate_coredump (char *core_fn, struct traced_process_ *proc)
{
    int wfd, vm_cnt;
    loff_t hdr_offset, max_ps = 0, prev_tail;
    Elf64_Phdr cur_phdr;
    struct vm_zone_ *vm;
    char *vm_buf = NULL;

    wfd = open(core_fn, O_CREAT | O_RDWR | O_TRUNC, 0666);
    assert(wfd != -1);

    vm_cnt = proc->addr_info->vm_cnt;
    fill_elf_header(wfd, vm_cnt + 1);

    read_auxv_info(proc->tgid);
    fill_elf_note(wfd, &cur_phdr, proc, vm_cnt, sizeof(Elf64_Ehdr));
    hdr_offset = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);
    prev_tail = cur_phdr.p_offset + cur_phdr.p_filesz;
    /* Fill in Porgram headers for VM, header 0 is note */
    for (vm = proc->addr_info->vm_hdr; vm; vm = vm->next) {
        /* Payload = previous phdr.offset + phdr.offset */
        prev_tail = P2ROUNDUP(prev_tail, 4096);
        if ((vm->p_flags & P_FLAG_E) == 0 && (vm->p_flags & P_FLAG_R)) {
            vm->p_filesz = vm->addr_end - vm->addr_start;
        } else {
            vm->p_filesz = 0;
        }
        //printf("%s:%d prev_off = %lx, vm size = %lx\n", __FILE__, __LINE__, prev_tail, vm->p_filesz);
        memset(&cur_phdr, 0, sizeof(Elf64_Phdr));
        cur_phdr.p_type = PT_LOAD;
        cur_phdr.p_offset = prev_tail;
        cur_phdr.p_vaddr = vm->addr_start;
        cur_phdr.p_paddr = 0;
        cur_phdr.p_filesz = vm->p_filesz;
        cur_phdr.p_memsz = vm->addr_end - vm->addr_start;
        cur_phdr.p_flags = vm->p_flags;
        cur_phdr.p_align = 4096;
        pwrite(wfd, &cur_phdr, sizeof(Elf64_Phdr), hdr_offset);

        if (vm->p_filesz) {
            if (vm->p_filesz > max_ps) {
                max_ps = vm->p_filesz;
                vm_buf = realloc(vm_buf, max_ps);
                assert(vm_buf);
            }
            ptrace_getdata(proc->tgid, vm->addr_start, vm_buf, vm->p_filesz);
            pwrite(wfd, vm_buf, vm->p_filesz, prev_tail);
            prev_tail += vm->p_filesz;
        }
        hdr_offset += sizeof(Elf64_Phdr);
    }
    free(vm_buf);
    close(wfd);
    return 0;
}
