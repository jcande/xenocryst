#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <unistd.h>
#include <termios.h>

#include "exec.h"
#include "gadgets.h"
#include "util.h"

#include "tests.h"

void
disable_buffering(
    void
    )
{
    struct termios term;

    //
    // Disable all buffering
    //

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    tcgetattr(0, &term);
    term.c_lflag &= ~ICANON;
    tcsetattr(0, TCSANOW, &term);
}

size_t
copy_program(
    uint8_t *program,
    size_t program_max
    )
{
    size_t program_size;
    char *program_as_char;

    program_as_char = (char *)program;

    if (read(STDIN_FILENO, program, program_max) == -1)
    {
        err(1, "read");
    }

    program_size = strlen(program_as_char);

    return program_size;
}

void
setup_environment(
    bf_t *bf
    )
{
    uint32_t i;

    memset(bf, 0, sizeof(*bf));

    // Control blocks
    bf->next_cb = &bf->instructions[0];

    // 1. Set the pc, lc, and head.
    bf->pc = virtual_to_bus(&bf->program[0]);
    bf->head = virtual_to_bus(&bf->tape[0]);
    bf->lc = 0;

    // Program
    bf->program_size = copy_program(bf->program, sizeof(bf->program) - 1);

    // Tape bounds
    bf->tape_start  = virtual_to_bus(&bf->tape[0]);
    bf->tape_end    = virtual_to_bus(&bf->tape[sizeof(bf->tape) - 1]);

    // 2. Build the boolean tables.
    {
        uint32_t i;
        uint8_t true_second_LSB, false_second_LSB;

        true_second_LSB = virtual_to_bus(&bf->conditional_table.True[0]) >> 8;
        false_second_LSB = virtual_to_bus(&bf->conditional_table.False[0]) >> 8;

        //
        // If this were true, then reaching the "true" portion of the table
        // (true is laid out in memory after false) would involve a carry to
        // the third LSB, which goes against our logical assumptions.
        //
        assert(false_second_LSB != 0xff);
        assert(true_second_LSB != 0x00);

        for (i = 0; i < ARRAY_SIZE(bf->boolean_inc_table); ++i)
        {
            //
            // By default, initialize each element to index into the "true"
            // half.
            //

            bf->boolean_inc_table[i] = true_second_LSB;
        }
        bf->boolean_inc_table[0] = false_second_LSB;

        for (i = 0; i < ARRAY_SIZE(bf->boolean_dec_table); ++i)
        {
            //
            // By default, initialize each element to index into the "true"
            // half.
            //

            bf->boolean_dec_table[i] = true_second_LSB;
        }
        bf->boolean_dec_table[255] = false_second_LSB;
    }

    // 3. Build the interpreter.
    for (i = 0; i < ARRAY_SIZE(Builds); ++i)
    {
        BuildFunction_t build = Builds[i];

        build(bf);
    }


    if ((void *)bf->next_cb >= (void *)&bf->instructions[sizeof(bf->instructions)])
    {
        errx(1, "Too many entries!\n");
    }

#if DEBUG
    // tables
    printf("dispatch:\t%p\n", bf->dispatch_table);
    printf("inc:\t%p\n", bf->inc_table);
    printf("dec:\t%p\n", bf->dec_table);
    printf("boolean_inc_table:\t%p\n", bf->boolean_inc_table);
    printf("boolean_dec_table:\t%p\n", bf->boolean_dec_table);
    printf("bracket_table:\t%p\n", bf->bracket_table);
    printf("conditional_table:\t%p\n", &bf->conditional_table);
    printf("insn_table:\t%p\n", &bf->insn_table);
    printf("scanleft_table:\t%p\n", &bf->scanleft_table);
    printf("scanright_table:\t%p\n", &bf->scanright_table);
    printf("syscall_dispatch_table:\t%p\n", &bf->syscall_dispatch_table);
    printf("syscall_table:\t%p\n", &bf->syscall_table);

    // instructions
    printf("dispatch: %p\n", bf->dispatch);
    printf("tramp: %p\n", bf->tramp);
    printf("tramp2: %p\n", bf->tramp2);
    printf("tramp3: %p\n", bf->tramp3);
    printf("inc_4: %p\n", bf->inc_4);
    printf("dec_4: %p\n", bf->dec_4);
    printf("next_insn: %p\n", bf->next_insn);
    printf("syscall_dispatch: %p\n", bf->syscall_dispatch);
    printf("cmp: %p\n", bf->cmp);
    printf("cmp_4: %p\n", bf->cmp_4);
    printf("eq: %p\n", bf->eq);
    printf("eq_4: %p\n", bf->eq_4);
    printf("add_4: %p\n", bf->add_4);
    printf("inc: %p\n", bf->inc);
    printf("dec: %p\n", bf->dec);
    printf("right: %p\n", bf->right);
    printf("left: %p\n", bf->left);
    printf("lcond: %p\n", bf->lcond);
    printf("rcond: %p\n", bf->rcond);
    printf("input: %p\n", bf->input);
    printf("output: %p\n", bf->output);
    printf("syscall_exit: %p\n", bf->syscall_exit);
    printf("syscall_open: %p\n", bf->syscall_open);
    printf("syscall_close: %p\n", bf->syscall_close);
    printf("syscall_read: %p\n", bf->syscall_read);
    printf("syscall_write: %p\n", bf->syscall_write);
#endif

#if TEST
    uint32_t errors = 0;
    for (i = 0; i < ARRAY_SIZE(Tests); ++i)
    {
        TestFunction_t test = Tests[i];
        if (FAILED(test(bf)))
        {
            warnx("Test number %d failed\n", i);
            ++errors;
        }
    }

    if (errors != 0)
    {
        errx(1, "%d tests failed! Bailing out...", errors);
    }
    else
    {
        printf("All tests passed\n");
    }
#endif
}

int
main(
    int argc,
    char **argv
    )
{
    bf_t *bf;

    bf = (bf_t *)allocate_memory();

    setup_environment(bf);

    disable_buffering();

    eval(bf->dispatch);
//    hexdump(NULL, bf->tape, sizeof(bf->tape));

    cleanup_memory();

    return 0;
}
