#ifndef GADGETS_H
#define GADGETS_H

#include "exec.h"

#define QUIT (-1)

//
// Offsets into the conditional table.
//

enum
{
    INC_4_INDEX         = 0x00,
    //
    // These two values are implicitly used
    //
    // INC_4_INDEX_1       =  0x01,
    // INC_4_INDEX_2       =  0x02,

    DEC_4_INDEX         = 0x03,
    //
    // These two values are implicitly used
    //
    // DEC_4_INDEX_1       = 0x04,
    // DEC_4_INDEX_2       = 0x05,

    LCOND_INDEX         = 0x06,
    LCOND_LC_INDEX_0    = 0x07,
    LCOND_LC_INDEX_1    = 0x08,
    LCOND_LC_INDEX_2    = 0x09,
    LCOND_LC_INDEX_3    = 0x0a,

    RCOND_INDEX         = 0x0b,
    RCOND_LC_INDEX_0    = 0x0c,
    RCOND_LC_INDEX_1    = 0x0d,
    RCOND_LC_INDEX_2    = 0x0e,
    RCOND_LC_INDEX_3    = 0x0f,

    COND_INDEX          = 0x10,

    MAXIMUM_CONDITION_INDEX_ENUM_VALUE
};

//
// points to gadgets located in bf_t
//

typedef struct
{
    union {
        struct {
            uint32_t quit;
            uint32_t nop;
            uint32_t inc;
            uint32_t dec;
            uint32_t right;
            uint32_t left;
            uint32_t lcond;
            uint32_t rcond;
            uint32_t input;
            uint32_t output;

            uint32_t syscall_dispatch;
        };

        // Pad to 0x100 boundary
        uint8_t PAD[0x100];
    };
} insn_table_t;

//
// points to syscall gadgets located in bf_t
//

typedef struct
{
    union {
        struct {
            uint32_t quit;
            uint32_t nop;
            uint32_t exit;
            uint32_t open;
            uint32_t close;
            uint32_t read;
            uint32_t write;
        };

        // Pad to 0x100 boundary
        uint8_t PAD[0x100];
    };
} syscall_table_t;

typedef struct
{
    union {
        struct {
            uint32_t keep_scanning;
            uint32_t left_bracket;
            uint32_t right_bracket;
            uint32_t quit;
        };

        // Pad to 0x100 boundary
        uint8_t PAD[0x100];
    };
} scan_table_t;

typedef struct
{
    union {
        struct {
            uint32_t False[0x40];   // 0x100 bytes
            uint32_t True [0x40];   // 0x100 bytes
        };

        uint32_t Test[0x80];        // 0x200 bytes
    };
} cond_table_t;

typedef struct
{
    uint8_t addition[0x100][0x100];
} arithmetic_tables_t;

struct control_block
{
    uint32_t source;        // source address
    uint32_t destination;   // destination address
    uint32_t size;          // transfer length
    uint32_t data;          // rip-relative data storage
    uint32_t next;          // next control block address;
};
typedef struct control_block *cb_t;

typedef struct _bf_t
{
    //
    // Tables: these must be aligned to 64k-byte boundaries.
    //

    arithmetic_tables_t arithmetic_tables;

    //
    // Tables: these must be aligned to 256-byte boundaries.
    //

    uint8_t dispatch_table[0x100];
    uint8_t inc_table[0x100];
    uint8_t dec_table[0x100];
    uint8_t boolean_inc_table[0x100];
    uint8_t boolean_dec_table[0x100];
    uint8_t bracket_table[0x100];
    uint8_t eq_table[0x100];
    uint8_t msb_set[0x100];
    cond_table_t conditional_table;
    insn_table_t insn_table;
    scan_table_t scanleft_table;
    scan_table_t scanright_table;

    uint8_t syscall_dispatch_table[0x100];
    syscall_table_t syscall_table;


    //
    // Instructions
    //

    cb_t next_cb;
    struct control_block instructions[0x10000];

    //
    // Data
    //

    uint8_t program[0x100000];
    uint8_t tape[0x10000];

    uint32_t pc;
    uint32_t lc;
    uint32_t head;
    uint32_t scratch0, scratch1, scratch2, scratch3, scratch4, scratch5;

    size_t program_size;
    uint32_t tape_start;
    uint32_t tape_end;

    //
    // System call number data
    //

    uint32_t exit_no;
    uint32_t open_no;
    uint32_t close_no;
    uint32_t read_no;
    uint32_t write_no;

    //
    // Helper gadgets
    //

    cb_t dispatch;
    cb_t tramp;
    cb_t tramp2;
    cb_t tramp3;
    cb_t inc_4;
    cb_t dec_4;
    cb_t next_insn;
    cb_t syscall_dispatch;

    uint32_t cmp_args_size;
    cb_t cmp_args, cmp;
    uint32_t cmp_4_args_size;
    cb_t cmp_4_args, cmp_4;

    uint32_t add_args_size;
    cb_t add_args, add;
    uint32_t add_4_args_size;
    cb_t add_4_args, add_4;

    uint32_t eq_args_size;
    cb_t eq_args, eq;
    uint32_t eq_4_args_size;
    cb_t eq_4_args, eq_4;

    //
    // Instruction gadgets +-><[],.
    //

    cb_t inc;
    cb_t dec;
    cb_t right;
    cb_t left;
    cb_t lcond;
    cb_t rcond;
    cb_t input;
    cb_t output;

    //
    // Syscall gadgets
    //

    cb_t syscall_exit;
    cb_t syscall_open;
    cb_t syscall_close;
    cb_t syscall_read;
    cb_t syscall_write;

} bf_t;

//
// Functions
//

void
raw_setup_cb(
    struct control_block *cb,
    uint32_t dest,
    uint32_t src,
    size_t size,
    uint32_t next
    );

void
setup_cb(
    struct control_block *cb,
    void *dest,
    void *src,
    size_t size,
    struct control_block *next
    );

//
// Add new gadgets to the table
//

#define BUILD_TABLE(ENTRY)  \
    ENTRY(dispatch)         \
    ENTRY(inc_4)            \
    ENTRY(dec_4)            \
    ENTRY(next_insn)        \
    ENTRY(cmp)              \
    ENTRY(cmp_4)            \
    ENTRY(eq)               \
    ENTRY(eq_4)             \
    ENTRY(add)              \
    ENTRY(add_4)            \
    ENTRY(rightleft)        \
    ENTRY(incdec)           \
    ENTRY(cond)             \
    ENTRY(io)               \
    ENTRY(syscalls)         \
    ENTRY(insn_table)       \
    ENTRY(exit)             \
    ENTRY(read)             \
    ENTRY(write)            \
    ENTRY(syscall_table)    \


//
// Declare prototypes for all initialization functions.
//

typedef void(*BuildFunction_t)(bf_t *);

#define AS_BUILD_PROTOTYPE(NAME)    \
    void build_ ## NAME(bf_t *bf);  \

BUILD_TABLE(AS_BUILD_PROTOTYPE)


//
// A hackey way of retrieving the number of initialization functions.
//

#define AS_BUILD_ENTRIES(NAME)  _build_enum_ ## NAME,
enum _BUILD_NAMES_ENUM {
    BUILD_TABLE(AS_BUILD_ENTRIES)
    NUMBER_OF_BUILD_FUNCTIONS
};

extern BuildFunction_t Builds[NUMBER_OF_BUILD_FUNCTIONS];

#endif // GADGETS_H
