#ifndef UTIL_H
#define UTIL_H

#define ARRAY_SIZE(array) (sizeof(array)/sizeof(array[0]))

#define MIN(a, b)   (((a) < (b)) ? (a) : (b))
#define MAX(a, b)   (((a) < (b)) ? (b) : (a))

#define PAGE_ROUND_UP(x)    ( (((ulong)(x)) + PAGE_SIZE-1)  & (~(PAGE_SIZE-1)) )

void
hexdump(
    char *desc,
    void *addr,
    int len
    );

void *
allocate_memory(
    void
    );

void
cleanup_memory(
    void
    );

#endif // UTIL_H
