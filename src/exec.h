#ifndef EXEC_H
#define EXEC_H

#include <stdint.h>

#include "gadgets.h"

#define MEMORY_SIZE             0x00300000

//
// We need 64k alignment due to arithmetic tables.
//

#define STRICTEST_ALIGNMENT     0x10000

enum BF_SYSCALL_NUMBERS
{
    BF_EXIT     = 128,
    BF_OPEN     = 129,
    BF_CLOSE    = 130,
    BF_READ     = 131,
    BF_WRITE    = 132,

    NUMBER_OF_SYSCALLS
};

typedef struct _SYSCALL_MEMORY {
    uint8_t do_syscall;
    uint32_t syscall_no;
    uint32_t arg0;
    uint32_t arg1;
    uint32_t arg2;
    uint32_t arg3;
    uint32_t arg4;
    uint32_t scratch;
} SYSCALL_MEMORY, *PSYSCALL_MEMORY;

typedef struct _IO_MEMORY {
    uint8_t input_status;
    uint8_t input;

    uint8_t output_status;
    uint8_t output;
} IO_MEMORY, *PIO_MEMORY;

typedef struct _SYS_IO_MEMORY_BASE {
    SYSCALL_MEMORY  syscall_memory;
    IO_MEMORY       io_memory;
} SYS_IO_MEMORY_BASE, *PSYS_IO_MEMORY_BASE;

extern void                 *physical_memory;
extern bf_t                 *g_bf;

extern SYS_IO_MEMORY_BASE   *sys_io_base;
extern SYSCALL_MEMORY       *syscall_memory;
extern IO_MEMORY            *io_memory;

void
eval(
    struct control_block *cb
    );

/* This is only for virtual addresses pointing to in
 * [g_bf, g_bf + MEMORY_SIZE). */
static inline uintptr_t virtual_to_bus(void *p)
{
    return (void *)p - (void *)g_bf;
}

static inline void *bus_to_virtual(uintptr_t addr)
{
    return (char *)g_bf + addr;
}

#endif // EXEC_H
