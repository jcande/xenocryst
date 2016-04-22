#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>

#include <err.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <stdio_ext.h>

#include "exec.h"
#include "gadgets.h"
#include "util.h"
#include "tests.h"

//
// Create a table containing each of our tests.
//

#define AS_TEST_TABLE_ENTRIES(NAME) test_ ## NAME,
TestFunction_t Tests[] = {
    TEST_TABLE(AS_TEST_TABLE_ENTRIES)
};


uint8_t true_value = TRUE_VALUE;
uint8_t false_value = FALSE_VALUE;

//
// For gadgets that implicitly invoke next_insn, our program at this point is
// null so next_insn will bail out of eval().
//

RESULT
test_cmp(
    bf_t *bf
    )
{
    struct {
        uint8_t cmp_value;
        uint32_t result;
    } *iter, cases[] = {
        { 0xff, TRUE_VALUE },
        { 0x0, FALSE_VALUE },
        { 0x07, TRUE_VALUE },
        { 0x80, TRUE_VALUE },
    };
    uint32_t i;
    RESULT status;
    cb_t cb = bf->next_cb;

    //
    // setup our condition
    //

    setup_cb(cb + 0, &bf->cmp_args[0].source, &cb[0].data, 4, cb + 1);
    cb[0].data = virtual_to_bus(&bf->scratch0);

    //
    // setup our true_block path
    //

    setup_cb(cb + 1, &bf->cmp_args[1].source, &cb[1].data, 4, cb + 2);
    cb[1].data = virtual_to_bus(cb + 3);

    //
    // setup our false_block path and then invoke cmp
    //

    setup_cb(cb + 2, &bf->cmp_args[2].source, &cb[2].data, 4, bf->cmp);
    cb[2].data = virtual_to_bus(cb + 4);

    //
    // true block
    //

    setup_cb(cb + 3, &bf->scratch1, &true_value, 1, cb + 5);

    //
    // false block
    //

    setup_cb(cb + 4, &bf->scratch1, &false_value, 1, cb + 5);

    //
    // Quit
    //

    setup_cb(cb + 5, &cb[6].next, &cb[5].data, 4, cb + 6);
    cb[5].data = QUIT;
    setup_cb(cb + 6, cb + 6, cb + 6, 0, NULL);

    status = TRUE_VALUE;
    for (i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        iter = &cases[i];

        bf->scratch0 = iter->cmp_value;
        eval(cb);
        if (memcmp(&bf->scratch1, &iter->result, 1) != 0)
        {
            errprintf(
                "cmp failed for value %02x: expected %08x, got %08x\n",
                iter->cmp_value,
                iter->result,
                bf->scratch1
            );

            status = FALSE_VALUE;
        }
    }

    return status;
}

RESULT
test_cmp_4(
    bf_t *bf
    )
{
    struct {
        uint32_t cmp_value;
        uint32_t result;
    } *iter, cases[] = {
        { 0x00000000, FALSE_VALUE },
        { 0xff000000, TRUE_VALUE },
        { 0x00ff0000, TRUE_VALUE },
        { 0x0000ff00, TRUE_VALUE },
        { 0x000000ff, TRUE_VALUE },
        { 0x00000008, TRUE_VALUE },
        { 0x00000080, TRUE_VALUE },
        { 0x00000800, TRUE_VALUE },
        { 0x00008000, TRUE_VALUE },
        { 0x00080000, TRUE_VALUE },
        { 0x00800000, TRUE_VALUE },
        { 0x08000000, TRUE_VALUE },
        { 0x80000000, TRUE_VALUE },
    };
    uint32_t i;
    RESULT status;
    cb_t cb = bf->next_cb;

    //
    // setup our condition
    //

    setup_cb(cb + 0, &bf->cmp_4_args[0].source, &cb[0].data, 4, cb + 1);
    cb[0].data = virtual_to_bus(&bf->scratch0);

    //
    // setup our true_block path
    //

    setup_cb(cb + 1, &bf->cmp_4_args[1].source, &cb[1].data, 4, cb + 2);
    cb[1].data = virtual_to_bus(cb + 3);

    //
    // setup our false_block path and then invoke cmp
    //

    setup_cb(cb + 2, &bf->cmp_4_args[2].source, &cb[2].data, 4, bf->cmp_4);
    cb[2].data = virtual_to_bus(cb + 4);

    //
    // true block
    //

    setup_cb(cb + 3, &bf->scratch1, &true_value, 1, cb + 5);

    //
    // false block
    //

    setup_cb(cb + 4, &bf->scratch1, &false_value, 1, cb + 5);

    //
    // Quit
    //

    setup_cb(cb + 5, &cb[6].next, &cb[5].data, 4, cb + 6);
    cb[5].data = QUIT;
    setup_cb(cb + 6, cb + 6, cb + 6, 0, NULL);

    status = TRUE_VALUE;
    for (i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        iter = &cases[i];

        bf->scratch0 = iter->cmp_value;
        eval(cb);
        if (memcmp(&bf->scratch1, &iter->result, 1) != 0)
        {
            errprintf(
                "cmp_4 failed for value %02x: expected %08x, got %08x\n",
                iter->cmp_value,
                iter->result,
                bf->scratch1
            );

            status = FALSE_VALUE;
        }
    }

    return status;
}

RESULT
test_eq(
    bf_t *bf
    )
{
    struct {
        uint8_t op_a, op_b;
        uint32_t result;
    } *iter, cases[] = {
        { 0x00, 0x01, FALSE_VALUE },
        { 0x01, 0x00, FALSE_VALUE },
        { 0x10, 0x00, FALSE_VALUE },
        { 0xf0, 0x0f, FALSE_VALUE },
        { 0xff, 0xff, TRUE_VALUE },
        { 0x00, 0x00, TRUE_VALUE },
        { 0x01, 0x01, TRUE_VALUE },
        { 0x10, 0x10, TRUE_VALUE },
        { 0x80, 0x80, TRUE_VALUE },
    };
    uint32_t i;
    RESULT status;
    cb_t cb = bf->next_cb;

    //
    // setup our operands
    //

    setup_cb(cb + 0, &bf->eq_args[0].source, &cb[0].data, 4, cb + 1);
    cb[0].data = virtual_to_bus(&bf->scratch0);

    setup_cb(cb + 1, &bf->eq_args[1].source, &cb[1].data, 4, cb + 2);
    cb[1].data = virtual_to_bus(&bf->scratch1);

    //
    // setup our true_block path
    //

    setup_cb(cb + 2, &bf->eq_args[2].source, &cb[2].data, 4, cb + 3);
    cb[2].data = virtual_to_bus(cb + 4);

    //
    // setup our false_block path and then invoke eq
    //

    setup_cb(cb + 3, &bf->eq_args[3].source, &cb[3].data, 4, bf->eq);
    cb[3].data = virtual_to_bus(cb + 5);

    //
    // true block
    //

    setup_cb(cb + 4, &bf->scratch2, &true_value, 1, cb + 6);

    //
    // false block
    //

    setup_cb(cb + 5, &bf->scratch2, &false_value, 1, cb + 6);

    //
    // Quit
    //

    setup_cb(cb + 6, &cb[7].next, &cb[6].data, 4, cb + 7);
    cb[6].data = QUIT;
    setup_cb(cb + 7, cb + 7, cb + 7, 0, NULL);

    status = TRUE_VALUE;
    for (i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        iter = &cases[i];

        bf->scratch0 = iter->op_a;
        bf->scratch1 = iter->op_b;
        eval(cb);
        if (memcmp(&bf->scratch2, &iter->result, 1) != 0)
        {
            errprintf(
                "eq failed for value %02x==%02x: expected %02x, got %02x\n",
                iter->op_a,
                iter->op_b,
                iter->result,
                bf->scratch2
            );

            status = FALSE_VALUE;
        }
    }

    return status;
}

RESULT
test_eq_4(
    bf_t *bf
    )
{
    struct {
        uint32_t op_a, op_b;
        uint32_t result;
    } *iter, cases[] = {
        { 0x00000000, 0x00100000, FALSE_VALUE },
        { 0x00001000, 0x00000000, FALSE_VALUE },
        { 0x00000110, 0xf0000110, FALSE_VALUE },
        { 0x0000f000, 0x000000f0, FALSE_VALUE },
        { 0x00000000, 0x00000000, TRUE_VALUE },
        { 0x00f00000, 0x00f00000, TRUE_VALUE },
        { 0x00f00001, 0x00f00001, TRUE_VALUE },
        { 0x00002010, 0x00002010, TRUE_VALUE },
        { 0x00080080, 0x00080080, TRUE_VALUE },
        { 0x00087080, 0x00087080, TRUE_VALUE },
        { 0x80ffffff, 0x80ffffff, TRUE_VALUE },
        { 0xffffffff, 0xffffffff, TRUE_VALUE },
    };
    uint32_t i;
    RESULT status;
    cb_t cb = bf->next_cb;

    //
    // setup our operands
    //

    setup_cb(cb + 0, &bf->eq_4_args[0].source, &cb[0].data, 4, cb + 1);
    cb[0].data = virtual_to_bus(&bf->scratch0);

    setup_cb(cb + 1, &bf->eq_4_args[1].source, &cb[1].data, 4, cb + 2);
    cb[1].data = virtual_to_bus(&bf->scratch1);

    //
    // setup our true_block path
    //

    setup_cb(cb + 2, &bf->eq_4_args[2].source, &cb[2].data, 4, cb + 3);
    cb[2].data = virtual_to_bus(cb + 4);

    //
    // setup our false_block path and then invoke eq_4
    //

    setup_cb(cb + 3, &bf->eq_4_args[3].source, &cb[3].data, 4, bf->eq_4);
    cb[3].data = virtual_to_bus(cb + 5);

    //
    // true block
    //

    setup_cb(cb + 4, &bf->scratch2, &true_value, 1, cb + 6);

    //
    // false block
    //

    setup_cb(cb + 5, &bf->scratch2, &false_value, 1, cb + 6);

    //
    // Quit
    //

    setup_cb(cb + 6, &cb[7].next, &cb[6].data, 4, cb + 7);
    cb[6].data = QUIT;
    setup_cb(cb + 7, cb + 7, cb + 7, 0, NULL);

    status = TRUE_VALUE;
    for (i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        iter = &cases[i];

        bf->scratch0 = iter->op_a;
        bf->scratch1 = iter->op_b;
        eval(cb);
        if (memcmp(&bf->scratch2, &iter->result, 1) != 0)
        {
            errprintf(
                "eq_4 failed for value %08x==%08x: expected %02x, got %02x\n",
                iter->op_a,
                iter->op_b,
                iter->result,
                bf->scratch2
            );

            status = FALSE_VALUE;
        }
    }

    return status;
}

RESULT
test_add_4(
    bf_t *bf
    )
{
    struct {
        uint32_t in0, in1;
        uint32_t result;
    } *iter, cases[] = {
        { 0x00000081, 0x00000080, 0x00000101 },
        { 0x07000081, 0x00040080, 0x07040101 },
        { 0x00000001, 0x0000008f, 0x00000090 },
        { 0x7fffffff, 0x00000001, 0x80000000 },
        { 0xffffffff, 0x00000001, 0x00000000 },

        { 0x00000000, 0x00000000, 0x00000000 },

        { 0x00000001, 0x00000000, 0x00000001 },
        { 0x00000000, 0x00000001, 0x00000001 },
        { 0x0000000f, 0x000000f0, 0x000000ff },
        { 0x000000ff, 0x00000001, 0x00000100 },
        { 0x00000001, 0x000000ff, 0x00000100 },

        { 0x00000100, 0x00000000, 0x00000100 },
        { 0x00000000, 0x00000100, 0x00000100 },
        { 0x00000f00, 0x0000f000, 0x0000ff00 },
        { 0x0000ff00, 0x00000100, 0x00010000 },
        { 0x00000100, 0x0000ff00, 0x00010000 },

        { 0x00010000, 0x00000000, 0x00010000 },
        { 0x00000000, 0x00010000, 0x00010000 },
        { 0x000f0000, 0x00f00000, 0x00ff0000 },
        { 0x00ff0000, 0x00010000, 0x01000000 },
        { 0x00010000, 0x00ff0000, 0x01000000 },

        { 0x01000000, 0x00000000, 0x01000000 },
        { 0x00000000, 0x01000000, 0x01000000 },
        { 0x0f000000, 0xf0000000, 0xff000000 },
        { 0xff000000, 0x01000000, 0x00000000 },
        { 0x01000000, 0xff000000, 0x00000000 },

        { 0x0f0e0d0c, 0x01020304, 0x10101010 },
    };
    uint32_t i;
    RESULT status;
    cb_t cb = bf->next_cb;

    //
    // set output
    //

    setup_cb(cb + 0, &bf->add_4_args[0].source, &cb[0].data, 4, cb + 1);
    cb[0].data = virtual_to_bus(&bf->scratch0);

    //
    // setup input0
    //

    setup_cb(cb + 1, &bf->add_4_args[1].source, &cb[1].data, 4, cb + 2);
    cb[1].data = virtual_to_bus(&bf->scratch1);

    //
    // setup input1
    //

    setup_cb(cb + 2, &bf->add_4_args[2].source, &cb[2].data, 4, cb + 3);
    cb[2].data = virtual_to_bus(&bf->scratch2);

    //
    // setup return address
    //

    setup_cb(cb + 3, &bf->add_4_args[3].source, &cb[3].data, 4, bf->add_4);
    cb[3].data = virtual_to_bus(cb + 4);

    //
    // stop
    //

    setup_cb(cb + 4, &cb[5].next, &cb[4].data, 4, cb + 5);
    cb[4].data = QUIT;
    setup_cb(cb + 5, cb + 5, cb + 5, 0, NULL);

    status = TRUE_VALUE;
    for (i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        iter = &cases[i];

        bf->scratch1 = iter->in0;
        bf->scratch2 = iter->in1;
        eval(cb);
        if (memcmp(&bf->scratch0, &iter->result, 4) != 0)
        {
            errprintf(
                "add_4 failed for sum %08x+%08x: expected %08x, got %08x\n",
                iter->in0,
                iter->in1,
                iter->result,
                bf->scratch0
            );

            status = FALSE_VALUE;
        }
    }

    return status;
}

RESULT
test_dec(
    bf_t *bf
    )
{
    struct {
        uint8_t initial;
        uint8_t result;
    } *iter, cases[] = {
        { 0x01, 0x00 },
        { 0x10, 0x0f },
        { 0x00, 0xff },
        { 0x0b, 0x0a },
        { 0x80, 0x7f },
    };
    uint32_t i;
    RESULT status;
    uint8_t program_data, *head, *pc;

    head = (uint8_t *)bus_to_virtual(bf->head);

    pc = bus_to_virtual(bf->pc);

    //
    // Set the next instruction to null so that we implicitly bail out when
    // "next_insn" is executed.
    //

    program_data = pc[1];
    pc[1] = 0;

    status = TRUE_VALUE;
    for (i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        iter = &cases[i];

        *head = iter->initial;
        eval(bf->dec);

        //
        // Reset pc.
        //

        bf->pc = virtual_to_bus(pc);

        if (*head != iter->result)
        {
            errprintf(
                "dec failed for value %02x: expected %02x, got %02x\n",
                iter->initial,
                iter->result,
                *head
            );

            status = FALSE_VALUE;
        }
    }

    //
    // leave the environment as we found it
    //

    *head = 0;

    bf->pc = virtual_to_bus(pc);
    pc[1] = program_data;

    return status;
}

RESULT
test_inc(
    bf_t *bf
    )
{
    struct {
        uint8_t initial;
        uint8_t result;
    } *iter, cases[] = {
        { 0x00, 0x01 },
        { 0x0f, 0x10 },
        { 0xff, 0x00 },
        { 0x0a, 0x0b },
        { 0x7f, 0x80 },
    };
    uint32_t i;
    RESULT status;
    uint8_t program_data, *head, *pc;

    head = bus_to_virtual(bf->head);

    pc = bus_to_virtual(bf->pc);

    //
    // Set the next instruction to null so that we implicitly bail out when
    // "next_insn" is executed.
    //

    program_data = pc[1];
    pc[1] = 0;

    status = TRUE_VALUE;
    for (i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        iter = &cases[i];

        *head = iter->initial;
        eval(bf->inc);

        //
        // Reset pc.
        //

        bf->pc = virtual_to_bus(pc);

        if (*head != iter->result)
        {
            errprintf(
                "inc failed for value %02x: expected %02x, got %02x\n",
                iter->initial,
                iter->result,
                *head
            );

            status = FALSE_VALUE;
        }
    }

    //
    // leave the environment as we found it
    //

    *head = 0;

    bf->pc = virtual_to_bus(pc);
    pc[1] = program_data;

    return status;
}

RESULT
test_rightleft(
    bf_t *bf
    )
{
    uint8_t program_data, *pc;
    uint32_t initial;
    RESULT status;

    status = TRUE_VALUE;

    pc = bus_to_virtual(bf->pc);

    //
    // Set the next instruction to null so that we implicitly bail out when
    // "next_insn" is executed.
    //

    program_data = pc[1];
    pc[1] = 0;

    initial = bf->head;

    //
    // Test out left (decrement head). Head currently is as far left as it
    // should go, so this should result in no change.
    //

    eval(bf->left);
    if (bf->head != initial)
    {
        errprintf(
            "left 1 failed: expected %08x, got %08x\n",
            initial,
            bf->head
        );

        status = FALSE_VALUE;
    }

    //
    // Reset pc.
    //

    bf->pc = virtual_to_bus(pc);

    //
    // Test out right (increment head)
    //

    eval(bf->right);
    if (bf->head != initial + 1)
    {
        errprintf(
            "right 1 failed: expected %08x, got %08x\n",
            initial + 1,
            bf->head
        );

        status = FALSE_VALUE;
    }

    //
    // Reset pc.
    //

    bf->pc = virtual_to_bus(pc);

    //
    // Test out left (decrement head).
    //

    eval(bf->left);
    if (bf->head != initial)
    {
        errprintf(
            "left 2 failed: expected %08x, got %08x\n",
            initial,
            bf->head
        );

        status = FALSE_VALUE;
    }

    //
    // Reset pc.
    //

    bf->pc = virtual_to_bus(pc);

    //
    // Set the tape to as far right as it should go.
    //

    bf->head = bf->tape_end;

    //
    // Test out right. It should result in a nop.
    //

    eval(bf->right);
    if (bf->head != bf->tape_end)
    {
        errprintf(
            "right 2 failed: expected %08x, got %08x\n",
            bf->tape_end,
            bf->head
        );

        status = FALSE_VALUE;
    }

    //
    // Restore the program.
    //

    bf->pc = virtual_to_bus(pc);
    pc[1] = program_data;

    //
    // Restore the environment.
    //

    bf->head = initial;

    return status;
}

RESULT
test_inc_4(
    bf_t *bf
    )
{
    struct {
        uint32_t initial;
        uint32_t result;
    } *iter, cases[] = {
        { 0x0, 0x1 },
        { 0xf, 0x10 },
        { 0xff, 0x100 },
        { 0x500a, 0x500b },
        { 0x7fffffff, 0x80000000 },
    };
    uint32_t i;
    RESULT status;
    cb_t cb = bf->next_cb;

    setup_cb(cb + 0, &bf->inc_4->source, &cb[0].data, 4, cb + 1);
    cb[0].data = virtual_to_bus(&bf->scratch0);
    setup_cb(cb + 1, &bf->tramp->next, &cb[1].data, 4, bf->inc_4);
    cb[1].data = QUIT;

    status = TRUE_VALUE;
    for (i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        iter = &cases[i];

        bf->scratch0 = iter->initial;
        eval(cb);
        if (bf->scratch0 != iter->result)
        {
            errprintf(
                "inc_4 failed for value %08x: expected %08x, got %08x\n",
                iter->initial,
                iter->result,
                bf->scratch0
            );

            status = FALSE_VALUE;
        }
    }

    return status;
}

RESULT
test_io(
    bf_t *bf
    )
{
    uint32_t i;
    RESULT status;
    uint8_t program_data, *head, *pc;

    head = bus_to_virtual(bf->head);

    pc = bus_to_virtual(bf->pc);

    //
    // Set the next instruction to null so that we implicitly bail out when
    // "next_insn" is executed.
    //

    program_data = pc[1];
    pc[1] = 0;

    //
    // Buffer stdout with a larger buffer than we will be using so that we can
    // clear it before it gets printed to the screen.
    //

    setvbuf(stdout, NULL, _IOFBF, 0x800);

    status = TRUE_VALUE;
    for (i = 0; i < 256; ++i)
    {
        //
        // Place a character into stdin's stream.
        //

        ungetc(i, stdin);

        eval(bf->input);
        if (*head != i)
        {
            errprintf(
                "input failed: expected %02x, got %02x\n",
                i,
                bf->head
            );

            status = FALSE_VALUE;
        }

        //
        // Reset pc.
        //

        bf->pc = virtual_to_bus(pc);

        eval(bf->output);
        if (io_memory->output != i)
        {
            errprintf(
                "output failed: expected %02x, got %02x\n",
                i,
                io_memory->output
            );

            status = FALSE_VALUE;
        }

        //
        // Reset pc.
        //

        bf->pc = virtual_to_bus(pc);
    }

    //
    // Leave the environment clean.
    //

    *head = 0;

    bf->pc = virtual_to_bus(pc);
    pc[1] = program_data;

    //
    // Clear pending output buffer.
    //

    __fpurge(stdout);
    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);

    memset(io_memory, 0, sizeof(*io_memory));

    return status;
}

RESULT
test_alignment(
    bf_t *bf
    )
{
    uint32_t i;
    RESULT status;
    struct {
        uint32_t alignment;
        uint32_t offset;
        char *name;
    } *iter, cases[] = {
        { 0x10000,  offsetof(bf_t, arithmetic_tables), "arithmetic_tables" },
        { 0x100,    offsetof(bf_t, dispatch_table), "dispatch_table" },
        { 0x100,    offsetof(bf_t, inc_table), "inc_table" },
        { 0x100,    offsetof(bf_t, dec_table), "dec_table" },
        { 0x100,    offsetof(bf_t, boolean_inc_table), "boolean_inc_table" },
        { 0x100,    offsetof(bf_t, boolean_dec_table), "boolean_dec_table" },
        { 0x100,    offsetof(bf_t, conditional_table), "conditional_table" },
        { 0x100,    offsetof(bf_t, bracket_table), "bracket_table" },
        { 0x100,    offsetof(bf_t, eq_table), "eq_table" },
        { 0x100,    offsetof(bf_t, insn_table), "insn_table" },
        { 0x100,    offsetof(bf_t, scanleft_table), "scanleft_table" },
        { 0x100,    offsetof(bf_t, scanright_table), "scanright_table" },
        { 0x100,    offsetof(bf_t, syscall_dispatch_table), "syscall_dispatch_table" },
        { 0x100,    offsetof(bf_t, syscall_table), "syscall_table" },
    };

    status = TRUE_VALUE;
    for (i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        uint32_t mask;
        long address;
        uint8_t *bf_as_byte_ptr;

        iter = &cases[i];

        mask = iter->alignment - 1;
        bf_as_byte_ptr = (uint8_t *)bf;
        address = (long)&bf_as_byte_ptr[iter->offset];

        if ((address & mask) != 0)
        {
            errprintf(
                "alignment failed for bf_t member %s: expected %08lx, got %08lx\n",
                iter->name,
                address & ~mask,
                address
            );

            status = FALSE_VALUE;
        }
    }

    return status;
}

RESULT
test_enum_size(
    bf_t *bf
    )
{
    RESULT status;

    status = TRUE_VALUE;
    if (MAXIMUM_CONDITION_INDEX_ENUM_VALUE >= ARRAY_SIZE(bf->conditional_table.True))
    {
        errprintf(
            "capacity failed for condition_table index enum: expected %08x (or less), got %08x\n",
            ARRAY_SIZE(bf->conditional_table.True),
            MAXIMUM_CONDITION_INDEX_ENUM_VALUE
        );

        status = FALSE_VALUE;
    }

    return status;
}

void
syscall_test_child(
    bf_t *bf,
    char *program
    )
{
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
    {
        err(1, "child: ptrace");
    }
    if (kill(getpid(), SIGSTOP) == -1)
    {
        err(1, "child: kill");
    }

    //
    // Write the test program into memory.
    //

    strncpy((char *)bf->program, program, sizeof(bf->tape));

    eval(bf->dispatch);

    exit(0);
}

RESULT
syscall_test_parent(
        bf_t *bf,
        pid_t child,
        long syscall_no,
        long arg0,
        long arg1,
        long arg2,
        long arg3,
        long arg4
    )
{
    struct user_regs_struct child_registers;
    RESULT status;
    int child_status;

    status = TRUE_VALUE;

    //
    // Wait for the child to ask for someone to trace it.
    //

    if (waitpid(child, &child_status, 0) == -1)
    {
        err(1, "waitpid: traceme");
    }

    //
    // Tell the Linux to set a flag when it delivers the trap message to
    // us so we can differentiate between syscalls and other traps.
    //

    if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD) == -1)
    {
        err(1, "ptrace: set options");
    }

    //
    // Resume the child and instruct the OS to call us when the child
    // invokes a syscall.
    //

    if (ptrace(PTRACE_SYSCALL, child, 0, 0) == -1)
    {
        err(1, "ptrace: syscall");
    }

    //
    // Wait for a syscall.
    //

    if (waitpid(child, &child_status, 0) == -1)
    {
        err(1, "waitpid: syscall");
    }
    else if (!(WIFSTOPPED(child_status) && WSTOPSIG(child_status) & 0x80))
    {
        //
        // The child did not invoke a syscall but still stopped for some
        // reason, most likely a segfault. This is unacceptable.
        //

        err(1, "child is on crack rock");
    }

    if (ptrace(PTRACE_GETREGS, child, NULL, &child_registers) == -1)
    {
        err(1, "ptrace: get registers");
    }

    //
    // Ensure the registers are kosher.
    //

    if (child_registers.orig_eax != syscall_no)
    {
        errprintf(
            "syscall %ld failed: expected syscall number %02lx, got %02lx\n",
            syscall_no,
            syscall_no,
            child_registers.orig_eax
        );

        status = FALSE_VALUE;
    }

    if (child_registers.ebx != arg0)
    {
        errprintf(
            "syscall %ld failed: expected arg0 %08lx, got %08lx\n",
            syscall_no,
            arg0,
            child_registers.ebx
        );

        status = FALSE_VALUE;
    }

    if (child_registers.ecx != arg1)
    {
        errprintf(
            "syscall %ld failed: expected arg1 %08lx, got %08lx\n",
            syscall_no,
            arg1,
            child_registers.ecx
        );

        status = FALSE_VALUE;
    }

    if (child_registers.edx != arg2)
    {
        errprintf(
            "syscall %ld failed: expected arg2 %08lx, got %08lx\n",
            syscall_no,
            arg2,
            child_registers.edx
        );

        status = FALSE_VALUE;
    }

    if (child_registers.esi != arg3)
    {
        errprintf(
            "syscall %ld failed: expected arg3 %08lx, got %08lx\n",
            syscall_no,
            arg3,
            child_registers.esi
        );

        status = FALSE_VALUE;
    }

    if (child_registers.edi != arg4)
    {
        errprintf(
            "syscall %ld failed: expected arg1 %08lx, got %08lx\n",
            syscall_no,
            arg4,
            child_registers.edi
        );

        status = FALSE_VALUE;
    }

    return status;
}

RESULT
test_syscalls(
    bf_t *bf
    )
{
// 128
#define MAKE_EXIT   "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
// 131
#define MAKE_READ   "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
// 132
#define MAKE_WRITE  "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    struct {
        long syscall_no, arg0, arg1, arg2, arg3, arg4;
        char program[512];
    } *iter, cases[] = {
        {
            SYS_exit, 5, 0, 0, 0, 0,

            //
            // This program sets the first cell to 0 (BF_EXIT), and the second
            // to 5 (arg0).
            //

            MAKE_EXIT ">+++++<#"
        },
        {
            SYS_read, 1, 3, 2, 0, 0,

            //
            // This program sets the first cell to 3 (BF_READ). The rest of the
            // args correspond to 1, 2, 3 (which get mapped to arg1, arg3, and
            // arg2).
            //

            MAKE_READ "> +> ++> +++>>><<< < < <#"
        },
        {
            SYS_write, 1, 3, 2, 0, 0,

            //
            // This program sets the first cell to 4 (BF_WRITE). The rest of the
            // args correspond to 1, 2, 3 (which get mapped to arg1, arg3, and
            // arg2).
            //

            MAKE_WRITE "> +> ++> +++>>><<< < < <#"
        },
    };
    RESULT status;
    uint32_t i;

    //
    // The calling convention for the syscalls is:
    //      bf_syscall_no = *(head + 0)
    //      arg0          = *(head + 1)
    //      arg1          = *(head + 2)
    //              ...
    //      argN          = *(head + N)
    //
    // NOTE: The last argument MAY be a dword (i.e., takes up 4 cells instead
    // of 1) and is to be treated as an offset from head. This part is why we
    // need to do the test fixup. Also, the bf_syscall might have a different
    // order to the arguments than the real syscall due to that fact (e.g.,
    // read/write).
    //

    status = TRUE_VALUE;
    for (i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        pid_t child;

        iter = &cases[i];

        //
        // Fixup some of the values as they are offsets.
        //

        if (iter->syscall_no == SYS_read)
        {
            iter->arg1 = (long)&bf->tape[iter->arg1];
        }
        else if (iter->syscall_no == SYS_write)
        {
            iter->arg1 = (long)&bf->tape[iter->arg1];
        }

        child = fork();

        if (child == 0)
        {
            syscall_test_child(
                bf,
                iter->program
            );
        }
        else if (child != -1)
        {
            RESULT result;

            result = syscall_test_parent(
                        bf,
                        child,
                        iter->syscall_no,
                        iter->arg0,
                        iter->arg1,
                        iter->arg2,
                        iter->arg3,
                        iter->arg4
                    );
            if (FAILED(result))
            {
                status = FALSE_VALUE;
            }
        }
        else
        {
            err(1, "fork");
        }
    }

    return status;
}

RESULT
test_add(
    bf_t *bf
    )
{
    uint8_t *output, *carry_out, *input0, *input1, *carry_in;
    uint32_t i, j, errors;
    RESULT status;

    cb_t cb;

    output = (uint8_t *)&bf->scratch0;
    carry_out = (uint8_t *)&bf->scratch1;
    input0 = (uint8_t *)&bf->scratch2;
    input1 = (uint8_t *)&bf->scratch3;
    carry_in = (uint8_t *)&bf->scratch4;

    cb = &bf->next_cb[0];

    //
    // setup our outputs
    //

    setup_cb(cb + 0, &bf->add_args[0].source, &cb[0].data, 4, cb + 1);
    cb[0].data = virtual_to_bus(output);

    setup_cb(cb + 1, &bf->add_args[1].source, &cb[1].data, 4, cb + 2);
    cb[1].data = virtual_to_bus(carry_out);

    //
    // setup our inputs
    //

    setup_cb(cb + 2, &bf->add_args[2].source, &cb[2].data, 4, cb + 3);
    cb[2].data = virtual_to_bus(input0);

    setup_cb(cb + 3, &bf->add_args[3].source, &cb[3].data, 4, cb + 4);
    cb[3].data = virtual_to_bus(input1);

    setup_cb(cb + 4, &bf->add_args[4].source, &cb[4].data, 4, cb + 5);
    cb[4].data = virtual_to_bus(carry_in);

    //
    // setup our return path and then invoke add
    //

    setup_cb(cb + 5, &bf->add_args[5].source, &cb[5].data, 4, bf->add);
    cb[5].data = virtual_to_bus(cb + 6);

    //
    // Quit
    //

    setup_cb(cb + 6, &cb[7].next, &cb[6].data, 4, cb + 7);
    cb[6].data = QUIT;
    setup_cb(cb + 7, cb + 7, cb + 7, 0, NULL);

    errors = 0;
    status = TRUE_VALUE;

    for (i = 0; i < 256; ++i)
    {
        for (j = 0; j < 256; ++j)
        {
            uint32_t sum;
            uint8_t cout, carry;

            for (carry = 0; carry < 2; ++carry)
            {
                sum = i + j + carry;
                cout = sum > 0xff;
                sum &= 0xff;

                *output = *carry_out = 0;
                *input0 = i;
                *input1 = j;
                *carry_in = carry;

                eval(cb);

                if (*output != sum || (!!*carry_out) != cout)
                {
                    errprintf(
                        "add failed for %02x+%02x+%d: expected %02x cout:%d : got %02x cout:%d instead\n",
                        *input0,
                        *input1,
                        *carry_in,
                        sum,
                        cout,
                        *output,
                        *carry_out
                    );

                    errors++;
                }
            }
        }
    }

    if (errors != 0)
    {
        status = FALSE_VALUE;
    }

    return status;
}

RESULT
test_dispatch(
    bf_t *bf
    )
{
    RESULT status;
    uint8_t program_data[0x100], *head, *pc;
    uint8_t test_program[] = "nop nop nop +++++[>++<-] >>";

    assert(sizeof(test_program) < sizeof(program_data));

    status = TRUE_VALUE;

    head = bus_to_virtual(bf->head);
    pc = bus_to_virtual(bf->pc);

    //
    // Save the original program and then copy over the test program.
    //

    memcpy(program_data, pc, sizeof(program_data));
    memcpy(pc, test_program, sizeof(test_program));

    eval(bf->dispatch);

    if (bus_to_virtual(bf->pc) != &pc[sizeof(test_program) - 1])
    {
        errprintf(
            "dispatch failed, pc isn't where it should be: expected %p, got %p\n",
            &pc[sizeof(test_program) - 1],
            bus_to_virtual(bf->pc)
        );

        status = FALSE_VALUE;
    }

    //
    // This corresponds to the ">>" at the end of the test program.
    //

    if (bus_to_virtual(bf->head) != &head[2])
    {
        errprintf(
            "dispatch failed, head isn't where it should be: expected %p, got %p\n",
            bus_to_virtual(bf->head),
            &head[2]
        );

        status = FALSE_VALUE;
    }

    //
    // We write 5 to the first cell, then in the loop we increment by 2 the
    // next cell. At the end of the loop, the first cell is 0 while the next is
    // 10.
    //

    if (head[0] != 0 || head[1] != 10)
    {
        errprintf(
            "dispatch failed, tape values aren't what they should be: expected "
                "%02x:%02x, got %02x:%02x\n",
            0,
            10,
            head[0],
            head[1]
        );

        status = FALSE_VALUE;
    }

    //
    // Zero the tape.
    //

    memset(&bf->tape[0], 0, sizeof(bf->tape));

    //
    // Restore the original program.
    //

    memcpy(pc, program_data, sizeof(program_data));

    //
    // Restore the register values.
    //

    bf->pc = virtual_to_bus(pc);

    bf->head = virtual_to_bus(head);

    return status;
}
