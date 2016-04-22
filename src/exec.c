#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include "exec.h"

//
// Hold our state
//

void                *physical_memory;
bf_t                *g_bf;
SYS_IO_MEMORY_BASE  *sys_io_base;
SYSCALL_MEMORY      *syscall_memory;
IO_MEMORY           *io_memory;

struct bf_t;
void
eval(
    cb_t cb
    )
{
    void *src, *dst, *next;

    for (; virtual_to_bus(cb) != QUIT; cb = (cb_t)next)
    {
        next = bus_to_virtual(cb->next);
        dst  = bus_to_virtual(cb->destination);
        src  = bus_to_virtual(cb->source);

#if DEBUG
        void *data = bus_to_virtual(cb->data);
        printf("\nsource:\t\t%p (%08x) -> %p\n", src, cb->source, (src) ? *(void **)src : 0);
        printf("destination:\t%p (%08x) -> %p\n", dst, cb->destination, (dst) ? *(void **)dst : 0);
        printf("size:\t\t%08x\n", cb->size);
        printf("data:\t\t%p (%08x) -> %p\n", data, virtual_to_bus(data), (data) ? *(void**)data : 0);
        printf("next:\t\t%p (%08x)\n\n", next, cb->next);
#endif

        memcpy(dst, src, cb->size);

        if (syscall_memory->do_syscall)
        {
            long ret;
#if DEBUG
            printf("syscall number:\t%08x\n", syscall_memory->syscall_no);
            printf("syscall arg0:\t%08x\n", syscall_memory->arg0);
            printf("syscall arg1:\t%08x\n", syscall_memory->arg1);
            printf("syscall arg2:\t%08x\n", syscall_memory->arg2);
            printf("syscall arg3:\t%08x\n", syscall_memory->arg3);
            printf("syscall arg4:\t%08x\n", syscall_memory->arg4);
            printf("syscall scratch:\t%08x\n", syscall_memory->scratch);
#endif
            ret = syscall(
                syscall_memory->syscall_no,
                syscall_memory->arg0,
                syscall_memory->arg1,
                syscall_memory->arg2,
                syscall_memory->arg3,
                syscall_memory->arg4
            );
            memset(syscall_memory, 0, sizeof(*syscall_memory));
            syscall_memory->scratch = ret;
        }
        else if (io_memory->input_status)
        {
            io_memory->input_status = 0;
            io_memory->input = getchar();
        }
        else if (io_memory->output_status)
        {
            io_memory->output_status = 0;
            putchar(io_memory->output);
        }
    }
}
