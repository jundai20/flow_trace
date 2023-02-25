#ifndef API_TRACER_ARCH_H
#define API_TRACER_ARCH_H

#include <stdint.h>

#ifdef __x86_64__
#define user_pt_regs user_regs_struct
static uint8_t break_instr[] = {0xcc};
#define SZ 8
#define PC 16
#endif

#ifdef __arm__
/* arm le */
//static uint8_t break_instr[] = {0xf0, 0x01, 0xf0, 0xe7};
/* arm64 le */
static uint8_t break_instr[] = {0xd4, 0x20, 0x00, 0x00};
#endif

#endif

