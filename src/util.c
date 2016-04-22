#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <errno.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/user.h>

#include "exec.h"
#include "util.h"

void *
get_aligned(
    void *base,
    size_t base_size,
    long alignment,
    size_t minimum_size
    )
{
    long base_address, aligned_address, difference;
    void *new_base;

    base_address = (long)base;
    aligned_address = base_address & ~(alignment - 1);

    //
    // Ensure our aligned address is not less than the base address.
    //

    while (aligned_address < base_address)
    {
        aligned_address += alignment;
    }

    difference = aligned_address - base_address;

    if (difference > base_size)
    {
        //
        // We don't have enough space to even find the proper alignment.
        //

        warnx(
            "Mapped region is not large enough to contain desired alignment: %08lx > %08lx+%x\n",
            aligned_address,
            base_address,
            base_size
        );

        return NULL;
    }
    else if (base_size - difference < minimum_size)
    {
        //
        // We found an alignment but it doesn't leave us with enough space for
        // our purposes.
        //

        warnx(
            "Aligning leaves less than desired size: %x-(%08lx-%08lx) < %x\n",
            base_size,
            aligned_address,
            base_address,
            minimum_size
        );

        return NULL;
    }

    //
    // We found the proper alignment. Rejoice.
    //

    new_base = (void *)aligned_address;

    return new_base;
}

void *
allocate_memory(
    void
    )
{
    uint8_t *p;

    p = mmap(
            NULL,
            MEMORY_SIZE,
            PROT_READ|PROT_WRITE,
            MAP_ANONYMOUS|MAP_PRIVATE,
            -1,
            0
        );
    if (p == MAP_FAILED)
    {
        err(1, "mmap setup 0");
    }
    physical_memory = p;

    g_bf = get_aligned(physical_memory, MEMORY_SIZE, STRICTEST_ALIGNMENT, sizeof(*g_bf));
    if (g_bf == NULL)
    {
        errx(1, "alignment");
    }

    p = mmap(
            NULL,
            PAGE_ROUND_UP(sizeof(*sys_io_base)),
            PROT_READ|PROT_WRITE,
            MAP_ANONYMOUS|MAP_PRIVATE,
            -1,
            0
        );
    if (p == MAP_FAILED)
    {
        err(1, "mmap setup 1");
    }
    sys_io_base     = (SYS_IO_MEMORY_BASE *)p;
    syscall_memory  = &sys_io_base->syscall_memory;
    io_memory       = &sys_io_base->io_memory;

    memset(syscall_memory, 0, sizeof(*syscall_memory));
    memset(io_memory, 0, sizeof(*io_memory));

    return (void *)g_bf;
}

void
cleanup_memory(
    void
    )
{
    uint32_t status;

    status = munmap(sys_io_base, PAGE_ROUND_UP(sizeof(*sys_io_base)));
    if (status != 0)
    {
        err(1, "munmap cleanup 0");
    }
    io_memory = NULL;

    status = munmap(physical_memory, MEMORY_SIZE);
    if (status != 0)
    {
        err(1, "munmap cleanup 1");
    }
    physical_memory = NULL;
}

void
asciify(
    unsigned char *ascii,
    int byte_len
    )
{
    int i;

    for (i = 0; i < byte_len; ++i) {
        if ((ascii[i] < 0x20) || (ascii[i] > 0x7e))
            ascii[i] = '.';
    }
}

void
enhex(
    unsigned char *hexed,
    int hex_size,
    unsigned char *buf,
    int buf_len
    )
{
    int i;

    for (i = 0; i < buf_len; ++i) {
        char tmp[4];
        char *space = (i == 0) ? "" : " ";
        snprintf(tmp, sizeof(tmp), "%s%02x", space, buf[i]);
        strncat((char *)hexed, tmp, hex_size);
    }
}

int
all_zero(
    unsigned char *buf,
    int len
    )
{
    int i, isNonZero = 0;
    for (i = 0; i < len; ++i) {
        isNonZero |= buf[i];
    }
    return !isNonZero;
}

void
hexdump(
    char *desc,
    void *addr,
    int len
    )
{
#define BYTE_LEN        (16)
// each byte is two characters (00-FF), plus the whitespace inbetween (BYTE_LEN
// - 1 spaces)
#define BYTE_LEN_HEXED  (BYTE_LEN*2 + BYTE_LEN - 1)

    int i, isZero, beenZero, byte_len, hex_len;
    unsigned char bytes[BYTE_LEN+1], hexed[BYTE_LEN_HEXED+1];
    unsigned char *pc = (unsigned char*)addr;

    if (desc != NULL) {
        printf("%s:\n", desc);
    }

    beenZero = 0;
    for (i = 0; i < len; i += byte_len) {
        hex_len = BYTE_LEN_HEXED;
        byte_len = MIN(BYTE_LEN, len - i);

        hexed[0] = '\0';
        memcpy(bytes, &pc[i], byte_len);
        isZero = all_zero(bytes, byte_len);
        enhex(hexed, hex_len, bytes, byte_len);
        asciify(bytes, byte_len);

        if (!isZero) {
            beenZero = 0;
        }

        if (!beenZero) {
            hexed[hex_len] = '\0';
            bytes[byte_len] = '\0';
            printf("%04x  %-*s  %*s\n", i, hex_len, hexed, byte_len, bytes);

            if (isZero) {
                beenZero = 1;
                printf("*\n");
            }
        }
    }
    printf("%04x\n", i);
}
