#ifndef ELF_CORE_H
#define ELF_CORE_H

#ifndef EI_NIDENT
#define EI_NIDENT	16
#endif
#include <sys/user.h>

#define P_FLAG_R 4
#define P_FLAG_W 2
#define P_FLAG_E 1

typedef char __s8;
typedef unsigned char __u8;
typedef  short __s16;
typedef unsigned short __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long __s64;
typedef unsigned long __u64;
typedef __u64	Elf64_Addr;
typedef __u16	Elf64_Half;
typedef __s16	Elf64_SHalf;
typedef __u64	Elf64_Off;
typedef __s32	Elf64_Sword;
typedef __u32	Elf64_Word;
typedef __u64	Elf64_Xword;
typedef __s64	Elf64_Sxword;

#if 0
struct user_regs_struct {
    unsigned long	r15;
    unsigned long	r14;
    unsigned long	r13;
    unsigned long	r12;
    unsigned long	bp;
    unsigned long	bx;
    unsigned long	r11;
    unsigned long	r10;
    unsigned long	r9;
    unsigned long	r8;
    unsigned long	ax;
    unsigned long	cx;
    unsigned long	dx;
    unsigned long	si;
    unsigned long	di;
    unsigned long	orig_ax;
    unsigned long	ip;
    unsigned long	cs;
    unsigned long	flags;
    unsigned long	sp;
    unsigned long	ss;
    unsigned long	fs_base;
    unsigned long	gs_base;
    unsigned long	ds;
    unsigned long	es;
    unsigned long	fs;
    unsigned long	gs;
};
#endif
///////////////////////////////////////////////////////////////////////////////
#define	ELFCLASS64	2
#define ELFDATA2LSB	1
#define EM_X86_64	62	/* AMD x86-64 */
///////////////////////////////////////////////////////////////////////////////

#define	ELFMAG		"\177ELF"
#define	SELFMAG		4
#define ELF_CLASS	ELFCLASS64
#define ELF_DATA	ELFDATA2LSB
#define EV_CURRENT	1
#define ELF_ARCH	EM_X86_64
#define ELFOSABI_NONE	0
#define ELF_OSABI ELFOSABI_NONE
#define ET_CORE   4

#define	EI_CLASS	4
#define	EI_DATA		5
#define	EI_VERSION	6
#define	EI_OSABI	7

#if 0
typedef struct elf64_hdr {
    unsigned char	e_ident[EI_NIDENT];	/* ELF "magic number" */
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;		/* Entry point virtual address */
    Elf64_Off e_phoff;		/* Program header table file offset */
    Elf64_Off e_shoff;		/* Section header table file offset */
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
} Elf64_Ehdr;
#endif

#define PT_LOAD    1
#define PT_NOTE    4
#if 0
typedef struct elf64_phdr {
    Elf64_Word p_type;
    Elf64_Word p_flags;
    Elf64_Off p_offset;		/* Segment file offset */
    Elf64_Addr p_vaddr;		/* Segment virtual address */
    Elf64_Addr p_paddr;		/* Segment physical address */
    Elf64_Xword p_filesz;		/* Segment size in file */
    Elf64_Xword p_memsz;		/* Segment size in memory */
    Elf64_Xword p_align;		/* Segment alignment, file & memory */
} Elf64_Phdr;
#endif
////////////////////////// For note ///////////////////////////////////////////

#define NT_PRSTATUS	1
#define NT_PRPSINFO	3
#define NT_FILE         0x46494c45

#if 0
typedef struct elf64_note {
    Elf64_Word n_namesz;	/* Name size */
    Elf64_Word n_descsz;	/* Content size */
    Elf64_Word n_type;	/* Content type */
} Elf64_Nhdr;
#endif
struct elf_siginfo {
    int si_signo;
    int si_code;
    int si_errno;
};

typedef unsigned long elf_greg_t;
#define ELF_NGREG (sizeof(struct user_regs_struct) / sizeof(elf_greg_t))
typedef elf_greg_t elf_gregset_t[ELF_NGREG];

typedef long		__kernel_long_t;
struct __kernel_old_timeval {
    __kernel_long_t tv_sec;
    __kernel_long_t tv_usec;
};

struct elf_prstatus {
    struct elf_siginfo pr_info;	/* Info associated with signal */
    short	pr_cursig;		/* Current signal */
    unsigned long pr_sigpend;	/* Set of pending signals */
    unsigned long pr_sighold;	/* Set of held signals */
    pid_t	pr_pid;
    pid_t	pr_ppid;
    pid_t	pr_pgrp;
    pid_t	pr_sid;
    struct __kernel_old_timeval pr_utime;	/* User time */
    struct __kernel_old_timeval pr_stime;	/* System time */
    struct __kernel_old_timeval pr_cutime;	/* Cumulative user time */
    struct __kernel_old_timeval pr_cstime;	/* Cumulative system time */

    elf_gregset_t pr_reg;	/* GP registers */
    int pr_fpvalid;		/* True if math co-processor being used.  */
};
#define ELF_PRARGSZ 80

struct elf_prpsinfo {
    char pr_state;
    char pr_sname;
    char pr_zomb;
    char pr_nice;
    unsigned long int pr_flag;
    unsigned int pr_uid;
    unsigned int pr_gid;
    int pr_pid, pr_ppid, pr_pgrp, pr_sid;
    char pr_fname[16];
    char pr_psargs[ELF_PRARGSZ];
};


/*
 * Format of NT_FILE note:
 *
 * long count     -- how many files are mapped
 * long page_size -- units for file_ofs
 * array of [COUNT] elements of
 *   long start
 *   long end
 *   long file_ofs
 * followed by COUNT filenames in ASCII: "FILE1" NUL "FILE2" NUL...
 */

#define NT_PRFPREG	2
struct user_i387_struct {
    unsigned short	cwd;
    unsigned short	swd;
    unsigned short	twd;	/* Note this is not the same as
				   the 32bit/x87/FSAVE twd */
    unsigned short	fop;
    __u64	rip;
    __u64	rdp;
    __u32	mxcsr;
    __u32	mxcsr_mask;
    __u32	st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
    __u32	xmm_space[64];	/* 16*16 bytes for each XMM-reg = 256 bytes */
    __u32	padding[24];
};

#define NT_X86_XSTATE	0x202		/* x86 extended state using xsave */

#endif
