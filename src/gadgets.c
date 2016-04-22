#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/syscall.h>

#include "exec.h"
#include "gadgets.h"
#include "util.h"

#define ARG_SIZE(NumberOfElements)  (sizeof(struct control_block)*(NumberOfElements))

uint8_t Zeroes[0x10000] = { 0 };

//
// Create a table containing each of our initialization functions.
//

#define AS_BUILD_TABLE_ENTRIES(NAME)    build_ ## NAME,
BuildFunction_t Builds[] = {
    BUILD_TABLE(AS_BUILD_TABLE_ENTRIES)
};

//
// NOTE When adding new gadgets, ensure that it sets the arguments to other gadgets
// properly. For example, if you are dynamically writing to an argument, zero it
// out beforehand.
//

void
raw_setup_cb(
    struct control_block *cb,
    uint32_t dest,
    uint32_t src,
    size_t size,
    uint32_t next
    )
{
    cb->source = src;
    cb->destination = dest;
    cb->size = size;
    cb->data = 0;
    cb->next = next;
}

void
setup_cb(
    struct control_block *cb,
    void *dest,
    void *src,
    size_t size,
    struct control_block *next
    )
{
    raw_setup_cb(
        cb,
        dest? virtual_to_bus(dest):0,
        src? virtual_to_bus(src):0,
        size,
        next? virtual_to_bus(next):0
    );
}

void
build_dispatch(
    bf_t *bf
    )
{
    uint32_t i;
    // Build the dispatch table.

    for (i = 0; i < 256; ++i)
    {
        bf->dispatch_table[i] = offsetof(insn_table_t, nop);
    }
    bf->dispatch_table['\0'] = offsetof(insn_table_t, quit);
    bf->dispatch_table['+'] = offsetof(insn_table_t, inc);
    bf->dispatch_table['-'] = offsetof(insn_table_t, dec);
    bf->dispatch_table['>'] = offsetof(insn_table_t, right);
    bf->dispatch_table['<'] = offsetof(insn_table_t, left);
    bf->dispatch_table['['] = offsetof(insn_table_t, lcond);
    bf->dispatch_table[']'] = offsetof(insn_table_t, rcond);
    bf->dispatch_table[','] = offsetof(insn_table_t, input);
    bf->dispatch_table['.'] = offsetof(insn_table_t, output);
    bf->dispatch_table['#'] = offsetof(insn_table_t, syscall_dispatch);

    cb_t cb = bf->next_cb;
    // To dispatch an instruction:
    // 0. Load the pc into the source of cb[1]
    // 1. Load the byte at the pc to use as an offset into the
    //    diapatch_table.
    // 2. Load 1 byte from the dispatch_table to use as an offset
    //    into the insn_table.
    // 3. Load 4 bytes from the insn_table to write into the next
    //    control block of tramp
    // 4. Do nothing in tramp.
    setup_cb(cb + 0, &cb[1].source, &bf->pc, 4, cb + 1);
    setup_cb(cb + 1, &cb[2].source, NULL, 1, cb + 2);
    setup_cb(cb + 2, &cb[3].source, &bf->dispatch_table[0], 1, cb + 3);
    setup_cb(cb + 3, &cb[4].next, &bf->insn_table, 4, cb + 4);
    setup_cb(cb + 4, cb + 4, cb + 4, 0, NULL);
    setup_cb(cb + 5, cb + 5, cb + 5, 0, NULL);
    setup_cb(cb + 6, cb + 6, cb + 6, 0, NULL);

    bf->dispatch = cb;
    bf->tramp = cb + 4;
    bf->tramp2 = cb + 5;
    bf->tramp3 = cb + 6;
    bf->next_cb = cb + 7;
}

/* This is a generic 4-byte increment gadget. The source address of
 * the first control block contains the address of the 4-byte aligned
 * uint32_t to increment. After the gadget is finished, it executes
 * the trampoline gadget tramp. */
void
build_inc_4(
    bf_t *bf
    )
{
    assert(bf->tramp);
    assert(bf->tramp2);
    cb_t cb = bf->next_cb;

    /* The basic algorithm is
     *     if (++*input)
     *         goto tramp;
     *     ++input;
     *     if (++*input)
     *         goto tramp;
     *     ++input;
     *     if (++*input)
     *         goto tramp;
     *     ++*input;
     * tramp:
     */

    bf->inc_4 = cb;
    for (int i = 0; ; ++i)
    {
        // 0. Copy 1 byte of the input into cb[2]'s source. This
        //    LSB is used as an offset into the inc_table.
        // 1. Copy the input into cb[2]'s destination.
        // 2. Load from the inc_table into the destination.
        uint32_t *input = &cb[0].source;
        setup_cb(cb + 0, &cb[2].source, NULL, 1, cb + 1);
        setup_cb(cb + 1, &cb[2].destination, input, 4, cb + 2);
        if (i == 3)
        {
            // Once we perform the increment, we're done
            // so goto tramp.
            setup_cb(cb + 2, NULL, bf->inc_table, 1, bf->tramp);
            cb = cb + 3;
            break;
        }
        // Perform the increment and continue.
        setup_cb(cb + 2, NULL, bf->inc_table, 1, cb + 3);

        // 3. Copy the input address into cb[3]'s source.
        // 4. Load the LSB (which we just wrote) and use as an index
        //    into the boolean_inc_table.
        // 5. Load from the boolean_inc_table and use as the 2nd LSB into
        //    the conditional_table.
        // 6. Load the offset from the conditional_table into tramp2
        //    and execute tramp2.
        setup_cb(cb + 3, &cb[4].source, input, 4, cb + 4);
        setup_cb(cb + 4, &cb[5].source, NULL, 1, cb + 5);
        setup_cb(cb + 5, (uint8_t *)&cb[6].source + 1, bf->boolean_inc_table, 1, cb + 6);
        setup_cb(cb + 6, &bf->tramp2->next, &bf->conditional_table.Test[INC_4_INDEX + i], 4, bf->tramp2);

        // If the value is 0, then we need to increment the next byte;
        // otherwise, goto tramp.
        bf->conditional_table.False[INC_4_INDEX + i] = virtual_to_bus(cb + 7);
        bf->conditional_table.True [INC_4_INDEX + i] = virtual_to_bus(bf->tramp);

        // Now we need to repeat the above, but we need to increment
        // the input address so that we operate on the next byte of
        // the word.

        // 7. Copy the input address into cb[7]'s source.
        // 8. Load the LSB of the address and use as an offset into
        //    inc_table.
        // 9. Load the incremented address and store it in
        //    cb[10]'s LSB.
        setup_cb(cb + 7, &cb[10].source, input, 4, cb + 8);
        setup_cb(cb + 8, &cb[9].source, input, 1, cb + 9);
        setup_cb(cb + 9, &cb[10].source, bf->inc_table, 1, cb + 10);

        // At this point, we can simply repeat
        cb = cb + 10;
    }

    bf->next_cb = cb;
}

/* This is a generic 4-byte decrement gadget. The source address of
 * the first control block contains the address of the 4-byte aligned
 * uint32_t to decrement. After the gadget is finished, it executes
 * the trampoline gadget tramp. */
void
build_dec_4(
    bf_t *bf
    )
{
    assert(bf->tramp);
    assert(bf->tramp2);
    cb_t cb = bf->next_cb;

    /* The basic algorithm is
     *     if (--*input)
     *         goto tramp;
     *     ++input;
     *     if (--*input)
     *         goto tramp;
     *     ++input;
     *     if (--*input)
     *         goto tramp;
     *     --*input;
     *
     * tramp:
     */

    bf->dec_4 = cb;
    for (int i = 0; ; ++i)
    {
        // 0. Copy 1 byte of the input into cb[2]'s source. This
        //      LSB is used as an offset into the inc_table.
        // 1. Copy the input into cb[2]'s destination.
        // 2. Load from the dec_table into the destination.
        uint32_t *input = &cb[0].source;
        setup_cb(cb + 0, &cb[2].source, NULL, 1, cb + 1);
        setup_cb(cb + 1, &cb[2].destination, input, 4, cb + 2);
        if (i == 3)
        {
            // Once we perform the decrement, we're done
            // so goto tramp.
            setup_cb(cb + 2, NULL, bf->dec_table, 1, bf->tramp);
            cb = cb + 3;
            break;
        }
        // Perform the decrement and continue.
        setup_cb(cb + 2, NULL, bf->dec_table, 1, cb + 3);

        // 4. Copy the input address into cb[3]'s source
        // 5. Load the LSB (which we just wrote) and use as an index
        //    into the boolean_dec_table.
        // 6. Load from the boolean_dec_table and use as the 2nd LSB
        //    into the conditional_table.
        // 7. Load the offset from the conditional_table into tramp2
        //    and execute tramp2.
        setup_cb(cb + 3, &cb[4].source, input, 4, cb + 4);
        setup_cb(cb + 4, &cb[5].source, NULL, 1, cb + 5);
        setup_cb(cb + 5, (uint8_t *)&cb[6].source + 1, bf->boolean_dec_table, 1, cb + 6);
        setup_cb(cb + 6, &bf->tramp2->next, &bf->conditional_table.Test[DEC_4_INDEX + i], 4, bf->tramp2);

        // If the value is 255, then we need to decrement the next byte;
        // otherwise, goto tramp.
        bf->conditional_table.False[DEC_4_INDEX + i] = virtual_to_bus(cb + 7);
        bf->conditional_table.True [DEC_4_INDEX + i] = virtual_to_bus(bf->tramp);

        // Now we need to repeat the above, but we need to increment
        // the input address so that we operate on the next byte of
        // the word.

        // 8. Copy the input address into cb[7]'s source.
        // 9. Load the LSB of the address and use as an offset into
        //    inc_table.
        // 10. Load the incremented address and store it in
        //     cb[11]'s LSB.
        setup_cb(cb + 7, &cb[10].source, input, 4, cb + 8);
        setup_cb(cb + 8, &cb[9].source, input, 1, cb + 9);
        setup_cb(cb + 9, &cb[10].source, bf->inc_table, 1, cb + 10);

        // At this point, we can simply repeat
        cb = cb + 10;
    }

    bf->next_cb = cb;
}

void
build_next_insn(
    bf_t *bf
    )
{
    assert(bf->dispatch);
    assert(bf->inc_4);
    assert(bf->tramp);

    cb_t cb = bf->next_cb;
    // To execute the next instruction, increment the pc by 1 and
    // then goto dispatch by using the trampoline
    setup_cb(cb + 0, &bf->inc_4->source, &cb[0].data, 4, cb + 1);
    cb[0].data = virtual_to_bus(&bf->pc);
    setup_cb(cb + 1, &bf->tramp->next, &cb[1].data, 4, bf->inc_4);
    cb[1].data = virtual_to_bus(bf->dispatch);

    bf->next_insn = cb;
    bf->next_cb = cb + 2;
}

void
build_incdec(
    bf_t *bf
    )
{
    assert(bf->next_insn);

    // Build the inc/dec tables.
    for (int i = 0; i < 256; ++i)
    {
        bf->inc_table[i] = i + 1;
        bf->dec_table[i] = i - 1;
    }

    cb_t cb = bf->next_cb;
    // Set up the control blocks for inc.
    bf->inc = cb;
    // 0. Copy from the head into cb[2]'s source
    setup_cb(cb + 0, &cb[2].source, &bf->head, 4, cb + 1);
    // 1. Copy from the head into cb[3]'s destination
    setup_cb(cb + 1, &cb[3].destination, &bf->head, 4, cb + 2);
    // 2. Copy from the tape into the LSB of cb[3]'s source
    setup_cb(cb + 2, &cb[3].source, NULL, 1, cb + 3);
    // 3. Copy from the increment table into the tape
    setup_cb(cb + 3, NULL, bf->inc_table, 1, bf->next_insn);
    cb += 4;

    // Set up the control blocks for dec which is identical to inc
    // except for the table.
    bf->dec = cb;
    // 0. Copy from the head into cb[2]'s source
    setup_cb(cb + 0, &cb[2].source, &bf->head, 4, cb + 1);
    // 1. Copy from the head into cb[3]'s destination
    setup_cb(cb + 1, &cb[3].destination, &bf->head, 4, cb + 2);
    // 2. Copy from the tape into the LSB of cb[3]'s source
    setup_cb(cb + 2, &cb[3].source, NULL, 1, cb + 3);
    // 3. Copy from the decrement table into the tape
    setup_cb(cb + 3, NULL, bf->dec_table, 1, bf->next_insn);
    cb += 4;

    bf->next_cb = cb;
}

void
build_rightleft(
    bf_t *bf
    )
{
    assert(bf->eq_4);
    assert(bf->next_insn);
    assert(bf->inc_4);
    assert(bf->dec_4);

    cb_t cb = bf->next_cb;

    // First we check the bounds for the tape. If we are within bounds we
    //increment the head, otherwise we go to the next instruction.
    // op a
    setup_cb(cb + 0, &bf->eq_4_args[0], &cb[0].data, 4, cb + 1);
    cb[0].data = virtual_to_bus(&bf->tape_end);
    // op b
    setup_cb(cb + 1, &bf->eq_4_args[1], &cb[1].data, 4, cb + 2);
    cb[1].data = virtual_to_bus(&bf->head);
    // true path (head points to tape_end), nop
    setup_cb(cb + 2, &bf->eq_4_args[2], &cb[2].data, 4, cb + 3);
    cb[2].data = virtual_to_bus(bf->next_insn);
    // false path (head is less than tape_end), increment head
    setup_cb(cb + 3, &bf->eq_4_args[3], &cb[3].data, 4, bf->eq_4);
    cb[3].data = virtual_to_bus(cb + 4);

    // To move right, increment the head by 1 and then goto
    // next_insn via the trampoline.
    setup_cb(cb + 4, &bf->inc_4->source, &cb[4].data, 4, cb + 5);
    cb[4].data = virtual_to_bus(&bf->head);
    setup_cb(cb + 5, &bf->tramp->next, &cb[5].data, 4, bf->inc_4);
    cb[5].data = virtual_to_bus(bf->next_insn);
    bf->right = cb;

    cb += 6;


    // First we check the bounds for the tape. If we are within bounds we
    // decrement the head, otherwise we go to the next instruction.
    // op a
    setup_cb(cb + 0, &bf->eq_4_args[0], &cb[0].data, 4, cb + 1);
    cb[0].data = virtual_to_bus(&bf->tape_start);
    // op b
    setup_cb(cb + 1, &bf->eq_4_args[1], &cb[1].data, 4, cb + 2);
    cb[1].data = virtual_to_bus(&bf->head);
    // true path (head points to tape_start), nop
    setup_cb(cb + 2, &bf->eq_4_args[2], &cb[2].data, 4, cb + 3);
    cb[2].data = virtual_to_bus(bf->next_insn);
    // false path (head is greater than tape_start), decrement head
    setup_cb(cb + 3, &bf->eq_4_args[3], &cb[3].data, 4, bf->eq_4);
    cb[3].data = virtual_to_bus(cb + 4);
    // To move left, decrement the head by 1 and then goto
    // next_insn via the trampoline.
    setup_cb(cb + 4, &bf->dec_4->source, &cb[4].data, 4, cb + 5);
    cb[4].data = virtual_to_bus(&bf->head);
    setup_cb(cb + 5, &bf->tramp->next, &cb[5].data, 4, bf->dec_4);
    cb[5].data = virtual_to_bus(bf->next_insn);
    bf->left = cb;
    bf->next_cb = cb + 6;
}

void
build_cond(
    bf_t *bf
    )
{
    uint32_t i;

    assert(bf->next_insn);
    assert(bf->inc_4);
    assert(bf->dec_4);

    // Build bracket table with offsets into scan(right||left)_table.
    for (i = 0; i < ARRAY_SIZE(bf->bracket_table); ++i)
    {
        bf->bracket_table[i] = offsetof(scan_table_t, keep_scanning);
    }
    bf->bracket_table['['] = offsetof(scan_table_t, left_bracket);
    bf->bracket_table[']'] = offsetof(scan_table_t, right_bracket);
    bf->bracket_table['\0'] = offsetof(scan_table_t, quit);

    cb_t cb = bf->next_cb;
    // Set up the control blocks for lcond.
    bf->lcond = cb;

    //
    // LCOND:
    //
    // 0/3. If !*head goto next_insn, else increment lc and scan right.
    setup_cb(cb + 0, &cb[1].source, &bf->head, 4, cb + 1);
    setup_cb(cb + 1, &cb[2].source, NULL, 1, cb + 2);
    setup_cb(cb + 2, (uint8_t *)&cb[3].source + 1, bf->boolean_inc_table, 1, cb + 3);
    setup_cb(cb + 3, &bf->tramp->next, &bf->conditional_table.Test[LCOND_INDEX], 4, bf->tramp);
    bf->conditional_table.False[LCOND_INDEX] = virtual_to_bus(cb + 4); // Increment lc, scan right.
    bf->conditional_table.True [LCOND_INDEX] = virtual_to_bus(bf->next_insn); // Goto next_insn.

    // 4/5. Increment the loop counter (lc).
    setup_cb(cb + 4, &bf->inc_4->source, &cb[4].data, 4, cb + 5);
    cb[4].data = virtual_to_bus(&bf->lc);
    setup_cb(cb + 5, &bf->tramp->next, &cb[5].data, 4, bf->inc_4);
    cb[5].data = virtual_to_bus(cb + 6);

    // SCAN RIGHT:
    // 6/7. Increment the program counter (pc).
    setup_cb(cb + 6, &bf->inc_4->source, &cb[6].data, 4, cb + 7);
    cb[6].data = virtual_to_bus(&bf->pc);
    setup_cb(cb + 7, &bf->tramp->next, &cb[7].data, 4, bf->inc_4);
    cb[7].data = virtual_to_bus(cb + 8);

    // 8. Copy the pc into cb[9]'s source.
    setup_cb(cb + 8, &cb[9].source, &bf->pc, 4, cb + 9);
    // 9. Load the LSB and use as index into the bracket_table.
    setup_cb(cb + 9, &cb[10].source, NULL, 1, cb + 10);
    // 10. Load from the bracket_table and use as index into scanright table.
    setup_cb(cb + 10, &cb[11].source, bf->bracket_table, 1, cb + 11);
    // 11. Load the offset from scanright_table into tramp and execute tramp.
    setup_cb(cb + 11, &bf->tramp->next, &bf->scanright_table, 4, bf->tramp);

    // Build scanright table after we setup the control blocks.
    memset(&bf->scanright_table, QUIT, sizeof(bf->scanright_table));
    bf->scanright_table.keep_scanning = virtual_to_bus(cb + 6); // Scan right.
    bf->scanright_table.left_bracket = virtual_to_bus(cb + 4); // If *pc = '['; ++lc.
    bf->scanright_table.right_bracket = virtual_to_bus(cb + 12); // If *pc = ']'; --lc.
    bf->scanright_table.quit = QUIT; // No matching ']' quit.

    // 12/13. Decrement the loop counter (lc).
    setup_cb(cb + 12, &bf->dec_4->source, &cb[12].data, 4, cb + 13);
    cb[12].data = virtual_to_bus(&bf->lc);
    setup_cb(cb + 13, &bf->tramp->next, &cb[13].data, 4, bf->dec_4);
    cb[13].data = virtual_to_bus(cb + 14);

    // 14/16. If the LSB of lc is 0 then check next byte, else scan right.
    setup_cb(cb + 14, &cb[15].source, &bf->lc, 1, cb + 15);
    setup_cb(cb + 15, (uint8_t *)&cb[16].source + 1, bf->boolean_inc_table, 1, cb + 16);
    setup_cb(cb + 16, &bf->tramp->next, &bf->conditional_table.Test[LCOND_LC_INDEX_0], 4, bf->tramp);
    bf->conditional_table.False[LCOND_LC_INDEX_0] = virtual_to_bus(cb + 17); // Check next byte.
    bf->conditional_table.True [LCOND_LC_INDEX_0] = virtual_to_bus(cb + 6); // Scan right.

    // 17/19. 2nd LSB.
    setup_cb(cb + 17, &cb[18].source, (uint8_t *)&bf->lc + 1, 1, cb + 18);
    setup_cb(cb + 18, (uint8_t *)&cb[19].source + 1, bf->boolean_inc_table, 1, cb + 19);
    setup_cb(cb + 19, &bf->tramp->next, &bf->conditional_table.Test[LCOND_LC_INDEX_1], 4, bf->tramp);
    bf->conditional_table.False[LCOND_LC_INDEX_1] = virtual_to_bus(cb + 20); // Check next byte.
    bf->conditional_table.True [LCOND_LC_INDEX_1] = virtual_to_bus(cb + 6); // Scan right.

    // 20/22. 3rd LSB.
    setup_cb(cb + 20, &cb[21].source, (uint8_t *)&bf->lc + 2, 1, cb + 21);
    setup_cb(cb + 21, (uint8_t *)&cb[22].source + 1, bf->boolean_inc_table, 1, cb + 22);
    setup_cb(cb + 22, &bf->tramp->next, &bf->conditional_table.Test[LCOND_LC_INDEX_2], 4, bf->tramp);
    bf->conditional_table.False[LCOND_LC_INDEX_2] = virtual_to_bus(cb + 23); // Check next byte.
    bf->conditional_table.True [LCOND_LC_INDEX_2] = virtual_to_bus(cb + 6); // Scan right.

    // 23/25. 4th LSB.
    setup_cb(cb + 23, &cb[24].source, (uint8_t *)&bf->lc + 3, 1, cb + 24);
    setup_cb(cb + 24, (uint8_t *)&cb[25].source + 1, bf->boolean_inc_table, 1, cb + 25);
    setup_cb(cb + 25, &bf->tramp->next, &bf->conditional_table.Test[LCOND_LC_INDEX_3], 4, bf->tramp);
    bf->conditional_table.False[LCOND_LC_INDEX_3] = virtual_to_bus(bf->next_insn); // Goto next_insn.
    bf->conditional_table.True [LCOND_LC_INDEX_3] = virtual_to_bus(cb + 6); // Scan right.

    cb += 26;
    // Set up the control blocks for rcond.
    bf->rcond = cb;

    //
    // RCOND:
    //
    // 0/3. If !*head goto next_insn, else increment lc and scan left.
    setup_cb(cb + 0, &cb[1].source, &bf->head, 4, cb + 1);
    setup_cb(cb + 1, &cb[2].source, NULL, 1, cb + 2);
    setup_cb(cb + 2, (uint8_t *)&cb[3].source + 1, bf->boolean_inc_table, 1, cb + 3);
    setup_cb(cb + 3, &bf->tramp->next, &bf->conditional_table.Test[RCOND_INDEX], 4, bf->tramp);
    bf->conditional_table.False[RCOND_INDEX] = virtual_to_bus(bf->next_insn); // Goto next_insn.
    bf->conditional_table.True [RCOND_INDEX] = virtual_to_bus(cb + 4); // Increment lc, scan left.

    // 4/5. Increment the loop counter (lc).
    setup_cb(cb + 4, &bf->inc_4->source, &cb[4].data, 4, cb + 5);
    cb[4].data = virtual_to_bus(&bf->lc);
    setup_cb(cb + 5, &bf->tramp->next, &cb[5].data, 4, bf->inc_4);
    cb[5].data = virtual_to_bus(cb + 6);

    // SCAN LEFT:
    // 6/7. Decrement the program counter (pc).
    setup_cb(cb + 6, &bf->dec_4->source, &cb[6].data, 4, cb + 7);
    cb[6].data = virtual_to_bus(&bf->pc);
    setup_cb(cb + 7, &bf->tramp->next, &cb[7].data, 4, bf->dec_4);
    cb[7].data = virtual_to_bus(cb + 8);

    // 8. Copy the pc into cb[9]'s source.
    setup_cb(cb + 8, &cb[9].source, &bf->pc, 4, cb + 9);
    // 9. Load the LSB and use as index into the bracket_table.
    setup_cb(cb + 9, &cb[10].source, NULL, 1, cb + 10);
    // 10. Load from the bracket_table and use as index into scanleft table.
    setup_cb(cb + 10, &cb[11].source, bf->bracket_table, 1, cb + 11);
    // 11. Load the offset from scanleft_table into tramp2 and execute tramp.
    setup_cb(cb + 11, &bf->tramp->next, &bf->scanleft_table, 4, bf->tramp);

    // 12/13. Decrement the loop counter (lc).
    setup_cb(cb + 12, &bf->dec_4->source, &cb[12].data, 4, cb + 13);
    cb[12].data = virtual_to_bus(&bf->lc);
    setup_cb(cb + 13, &bf->tramp->next, &cb[13].data, 4, bf->dec_4);
    cb[13].data = virtual_to_bus(cb + 14);

    // Build scanleft table after we setup the control blocks.
    memset(&bf->scanleft_table, QUIT, sizeof(bf->scanleft_table));
    bf->scanleft_table.keep_scanning = virtual_to_bus(cb + 6); // Scan left.
    bf->scanleft_table.left_bracket = virtual_to_bus(cb + 12); // If *pc = '['.
    bf->scanleft_table.right_bracket = virtual_to_bus(cb + 4); // If *pc = ']'.
    bf->scanleft_table.quit = QUIT; // No matching ']' quit.

    // 15/19. If !*lc goto dispatch, else goto scan left.
    setup_cb(cb + 14, &cb[15].source, &bf->lc, 1, cb + 15);
    setup_cb(cb + 15, (uint8_t *)&cb[16].source + 1, bf->boolean_inc_table, 1, cb + 16);
    setup_cb(cb + 16, &bf->tramp->next, &bf->conditional_table.Test[RCOND_LC_INDEX_0], 4, bf->tramp);
    bf->conditional_table.False[RCOND_LC_INDEX_0] = virtual_to_bus(cb + 17); // Check next byte.
    bf->conditional_table.True [RCOND_LC_INDEX_0] = virtual_to_bus(cb + 6); // Scan left.

    // 2nd LSB.
    setup_cb(cb + 17, &cb[18].source, (uint8_t *)&bf->lc + 1, 1, cb + 18);
    setup_cb(cb + 18, (uint8_t *)&cb[19].source + 1, bf->boolean_inc_table, 1, cb + 19);
    setup_cb(cb + 19, &bf->tramp->next, &bf->conditional_table.Test[RCOND_LC_INDEX_1], 4, bf->tramp);
    bf->conditional_table.False[RCOND_LC_INDEX_1] = virtual_to_bus(cb + 20); // Check next byte.
    bf->conditional_table.True [RCOND_LC_INDEX_1] = virtual_to_bus(cb + 6); // Scan left.

    // 3rd LSB.
    setup_cb(cb + 20, &cb[21].source, (uint8_t *)&bf->lc + 2, 1, cb + 21);
    setup_cb(cb + 21, (uint8_t *)&cb[22].source + 1, bf->boolean_inc_table, 1, cb + 22);
    setup_cb(cb + 22, &bf->tramp->next, &bf->conditional_table.Test[RCOND_LC_INDEX_2], 4, bf->tramp);
    bf->conditional_table.False[RCOND_LC_INDEX_2] = virtual_to_bus(cb + 23); // Check next byte.
    bf->conditional_table.True [RCOND_LC_INDEX_2] = virtual_to_bus(cb + 6); // Scan left.

    // 4th LSB.
    setup_cb(cb + 23, &cb[24].source, (uint8_t *)&bf->lc + 3, 1, cb + 24);
    setup_cb(cb + 24, (uint8_t *)&cb[25].source + 1, bf->boolean_inc_table, 1, cb + 25);
    setup_cb(cb + 25, &bf->tramp->next, &bf->conditional_table.Test[RCOND_LC_INDEX_3], 4, bf->tramp);
    bf->conditional_table.False[RCOND_LC_INDEX_3] = virtual_to_bus(bf->next_insn); // Goto next_insn.
    bf->conditional_table.True [RCOND_LC_INDEX_3] = virtual_to_bus(cb + 6); // Scan left.

    cb += 26;
    bf->next_cb = cb;
}

void
build_io(
    bf_t *bf
    )
{
    assert(bf->next_insn);
    assert(bf->tramp);

    cb_t cb = bf->next_cb;
    // Set up the control blocks for input.
    bf->input = cb;

    //
    // INPUT:
    //

    // write a non-zero value to memory to indicate our desire for input
    setup_cb(cb + 0, &io_memory->input_status, "1", 1, cb + 1);
    // set head to input
    setup_cb(cb + 1, &cb[2].destination, &bf->head, 4, cb + 2);
    setup_cb(cb + 2, NULL, &io_memory->input, 1, bf->next_insn);

    cb += 3;
    // Set up the control blocks for output.
    bf->output = cb;

    //
    // OUTPUT
    //

    // set output to head
    setup_cb(cb + 0, &cb[1].source, &bf->head, 4, cb + 1);
    setup_cb(cb + 1, &io_memory->output, NULL, 1, cb + 2);
    // write a non-zero value to memory to indicate our desire to output
    setup_cb(cb + 2, &io_memory->output_status, "0", 1, bf->next_insn);

    cb += 3;
    bf->next_cb = cb;
}

void
build_exit(
    bf_t *bf
    )
{
    cb_t cb;

    cb = bf->next_cb;

    // Exit syscall:
    bf->exit_no = SYS_exit;

    // set syscall_no to exit
    setup_cb(cb + 0, &syscall_memory->syscall_no, &bf->exit_no, 4, cb + 1);

    // increment head and store in scratch
    setup_cb(cb + 1, &syscall_memory->scratch, &bf->head, 4, cb + 2);
    setup_cb(cb + 2, &bf->inc_4->source, &cb[2].data, 4, cb + 3);
    cb[2].data = virtual_to_bus(&syscall_memory->scratch);
    setup_cb(cb + 3, &bf->tramp->next, &cb[3].data, 4, bf->inc_4);
    cb[3].data = virtual_to_bus(cb + 4);

    // dereference scratch and store in arg0
    // We have to do it in two parts because the value is stored in "bus"
    // terms. We let the memcpy() translate it for us in the second operation.
    setup_cb(cb + 4, &cb[5].source, &syscall_memory->scratch, 4, cb + 5);
    setup_cb(cb + 5, &syscall_memory->arg0, NULL, 1, cb + 6);

    // write a non-zero value to memory to indicate our desire to output
    setup_cb(cb + 6, &syscall_memory->do_syscall, "\x2a", 1, bf->next_insn);

    bf->syscall_exit = cb;
    cb += 7;
    bf->next_cb = cb;
}

// XXX read/write are the same but with a different syscall_no. Maybe make them
// share the body.
void
build_read(
    bf_t *bf
    )
{
    cb_t cb;

    cb = bf->next_cb;

    // Read syscall:
    bf->read_no = SYS_read;

    // set syscall_no to read
    setup_cb(cb + 0, &syscall_memory->syscall_no, &bf->read_no, 4, cb + 1);

    // copy head to scratch
    setup_cb(cb + 1, &syscall_memory->scratch, &bf->head, 4, cb + 2);

    // increment head and store in scratch (head + 1)
    setup_cb(cb + 2, &bf->inc_4->source, &cb[2].data, 4, cb + 3);
    cb[2].data = virtual_to_bus(&syscall_memory->scratch);
    setup_cb(cb + 3, &bf->tramp->next, &cb[3].data, 4, bf->inc_4);
    cb[3].data = virtual_to_bus(cb + 4);
    // dereference scratch and store in arg0 (fd)
    // We have to do it in two parts because the value is stored in "bus"
    // terms. We let the memcpy() translate it for us in the second operation.
    setup_cb(cb + 4, &cb[5].source, &syscall_memory->scratch, 4, cb + 5);
    setup_cb(cb + 5, &syscall_memory->arg0, NULL, 1, cb + 6);

    // increment scratch (head + 2)
    setup_cb(cb + 6, &bf->inc_4->source, &cb[6].data, 4, cb + 7);
    cb[6].data = virtual_to_bus(&syscall_memory->scratch);
    setup_cb(cb + 7, &bf->tramp->next, &cb[7].data, 4, bf->inc_4);
    cb[7].data = virtual_to_bus(cb + 8);
    // dereference scratch and store in arg2 (size)
    // We have to do it in two parts because the value is stored in "bus"
    // terms. We let the memcpy() translate it for us in the second operation.
    setup_cb(cb + 8, &cb[9].source, &syscall_memory->scratch, 4, cb + 9);
    setup_cb(cb + 9, &syscall_memory->arg2, NULL, 1, cb + 10);

    // increment scratch (head + 3)
    setup_cb(cb + 10, &bf->inc_4->source, &cb[10].data, 4, cb + 11);
    cb[10].data = virtual_to_bus(&syscall_memory->scratch);
    setup_cb(cb + 11, &bf->tramp->next, &cb[11].data, 4, bf->inc_4);
    cb[11].data = virtual_to_bus(cb + 12);

    // output is arg2
    setup_cb(cb + 12, &bf->add_4_args[0].source, &cb[12].data, 4, cb + 13);
    cb[12].data = virtual_to_bus(&syscall_memory->arg1);

    // this is used purely for its data (local variable)
    setup_cb(cb + 13, cb + 13, cb + 13, 0, cb + 14);
    cb[13].data = (uint32_t)&bf->tape[0];
    // *input0 == &tape[0]
    setup_cb(cb + 14, &bf->add_4_args[1].source, &cb[14].data, 4, cb + 15);
    cb[14].data = virtual_to_bus(&cb[13].data);

    // input1 == user_dword
    setup_cb(cb + 15, &bf->add_4_args[2].source, &syscall_memory->scratch, 4, cb + 16);

    // setup return
    setup_cb(cb + 16, &bf->add_4_args[3].source, &cb[16].data, 4, bf->add_4);
    cb[16].data = virtual_to_bus(cb + 17);

    // write a non-zero value to memory to indicate our desire to output
    setup_cb(cb + 17, &syscall_memory->do_syscall, "\xff", 1, bf->next_insn);

    bf->syscall_read = cb;
    cb += 18;
    bf->next_cb = cb;
}

void
build_write(
    bf_t *bf
    )
{
    cb_t cb;

    cb = bf->next_cb;

    // Write syscall:
    bf->write_no = SYS_write;

    // set syscall_no to read
    setup_cb(cb + 0, &syscall_memory->syscall_no, &bf->write_no, 4, cb + 1);

    // copy head to scratch
    setup_cb(cb + 1, &syscall_memory->scratch, &bf->head, 4, cb + 2);

    // increment head and store in scratch (head + 1)
    setup_cb(cb + 2, &bf->inc_4->source, &cb[2].data, 4, cb + 3);
    cb[2].data = virtual_to_bus(&syscall_memory->scratch);
    setup_cb(cb + 3, &bf->tramp->next, &cb[3].data, 4, bf->inc_4);
    cb[3].data = virtual_to_bus(cb + 4);
    // dereference scratch and store in arg0 (fd)
    // We have to do it in two parts because the value is stored in "bus"
    // terms. We let the memcpy() translate it for us in the second operation.
    setup_cb(cb + 4, &cb[5].source, &syscall_memory->scratch, 4, cb + 5);
    setup_cb(cb + 5, &syscall_memory->arg0, NULL, 1, cb + 6);

    // increment scratch (head + 2)
    setup_cb(cb + 6, &bf->inc_4->source, &cb[6].data, 4, cb + 7);
    cb[6].data = virtual_to_bus(&syscall_memory->scratch);
    setup_cb(cb + 7, &bf->tramp->next, &cb[7].data, 4, bf->inc_4);
    cb[7].data = virtual_to_bus(cb + 8);
    // dereference scratch and store in arg2 (size)
    // We have to do it in two parts because the value is stored in "bus"
    // terms. We let the memcpy() translate it for us in the second operation.
    setup_cb(cb + 8, &cb[9].source, &syscall_memory->scratch, 4, cb + 9);
    setup_cb(cb + 9, &syscall_memory->arg2, NULL, 1, cb + 10);

    // increment scratch (head + 3)
    setup_cb(cb + 10, &bf->inc_4->source, &cb[10].data, 4, cb + 11);
    cb[10].data = virtual_to_bus(&syscall_memory->scratch);
    setup_cb(cb + 11, &bf->tramp->next, &cb[11].data, 4, bf->inc_4);
    cb[11].data = virtual_to_bus(cb + 12);

    // output is arg2
    setup_cb(cb + 12, &bf->add_4_args[0].source, &cb[12].data, 4, cb + 13);
    cb[12].data = virtual_to_bus(&syscall_memory->arg1);

    // this is used purely for its data (local variable)
    setup_cb(cb + 13, cb + 13, cb + 13, 0, cb + 14);
    cb[13].data = (uint32_t)&bf->tape[0];
    // *input0 == &tape[0]
    setup_cb(cb + 14, &bf->add_4_args[1].source, &cb[14].data, 4, cb + 15);
    cb[14].data = virtual_to_bus(&cb[13].data);

    // input1 == user_dword
    setup_cb(cb + 15, &bf->add_4_args[2].source, &syscall_memory->scratch, 4, cb + 16);

    // setup return
    setup_cb(cb + 16, &bf->add_4_args[3].source, &cb[16].data, 4, bf->add_4);
    cb[16].data = virtual_to_bus(cb + 17);

    // write a non-zero value to memory to indicate our desire to output
    setup_cb(cb + 17, &syscall_memory->do_syscall, "\xff", 1, bf->next_insn);

    bf->syscall_write = cb;
    cb += 18;
    bf->next_cb = cb;
}

void
build_syscalls(
    bf_t *bf
    )
{
    uint32_t i;
    cb_t cb;

    assert(bf->next_insn);

    //
    // syscall dispatch table
    //

    // any invalid syscalls will result in nops
    for (i = 0; i < 256; ++i)
    {
        bf->syscall_dispatch_table[i] = offsetof(syscall_table_t, nop);
    }

    bf->syscall_dispatch_table[BF_EXIT]  = offsetof(syscall_table_t, exit);
/*
    bf->syscall_dispatch_table[BF_OPEN]  = offsetof(syscall_table_t, open);
    bf->syscall_dispatch_table[BF_CLOSE] = offsetof(syscall_table_t, close);
*/
    bf->syscall_dispatch_table[BF_READ]  = offsetof(syscall_table_t, read);
    bf->syscall_dispatch_table[BF_WRITE] = offsetof(syscall_table_t, write);

    cb = bf->next_cb;

    //
    // To dispatch a syscall:
    // 0. Load the pc into the source of cb[1]
    // 1. Load the byte at the pc to use as an offset into the
    //  syscall_diapatch_table.
    // 2. Load 1 byte from the syscall_dispatch_table to use as an offset
    //  into the syscall_table.
    // 3. Load 4 bytes from the syscall_table to write into the next
    //  control block of tramp
    // 4. Do nothing in tramp.
    //
    setup_cb(cb + 0, &cb[1].source, &bf->head, 4, cb + 1);
    setup_cb(cb + 1, &cb[2].source, NULL, 1, cb + 2);
    setup_cb(cb + 2, &cb[3].source, bf->syscall_dispatch_table, 1, cb + 3);
    setup_cb(cb + 3, &cb[4].next, &bf->syscall_table, 4, cb + 4);
    setup_cb(cb + 4, cb + 4, cb + 4, 0, NULL);

    bf->syscall_dispatch = cb;
    cb += 5;
    bf->next_cb = cb;

    //
    // syscalls:
    // open, close
    // NOTE args start at (head+1) as *(head+0) is what brought us here.
    //

    // XXX if we are to implement these then they could just open/read/write the flag

    // Open syscall:
    bf->open_no = SYS_open;

    // Close syscall:
    bf->close_no = SYS_close;

    bf->next_cb = cb;
}

void
build_insn_table(
    bf_t *bf
    )
{
    assert(bf->next_insn);
    assert(bf->inc);
    assert(bf->dec);
    assert(bf->right);
    assert(bf->left);
    assert(bf->lcond);
    assert(bf->rcond);
    assert(bf->dispatch);

    bf->insn_table.quit = QUIT;
    bf->insn_table.nop = virtual_to_bus(bf->next_insn);
    bf->insn_table.inc = virtual_to_bus(bf->inc);
    bf->insn_table.dec = virtual_to_bus(bf->dec);
    bf->insn_table.right = virtual_to_bus(bf->right);
    bf->insn_table.left = virtual_to_bus(bf->left);
    bf->insn_table.lcond = virtual_to_bus(bf->lcond);
    bf->insn_table.rcond = virtual_to_bus(bf->rcond);

    bf->insn_table.input = virtual_to_bus(bf->input);
    bf->insn_table.output = virtual_to_bus(bf->output);

    bf->insn_table.syscall_dispatch = virtual_to_bus(bf->syscall_dispatch);
}

void
build_add_4(
    bf_t *bf
    )
{
    uint32_t *output, *input0, *input1, *done_dest;
    uint32_t *add_output, *add_cout, *add_in0, *add_in1, *add_cin, *add_ret;
    uint32_t *carry;
    uint32_t i, max;
    cb_t cb;

    assert(bf->add);
    assert(bf->inc_4);

    /* The basic algorithm is
     * *output++ = add(*input0++, *input1++, 0, cout)
     * *output++ = add(*input0++, *input1++, *cout, cout)
     * *output++ = add(*input0++, *input1++, *cout, cout)
     * *output = add(*input0, *input1, *cout, 0)
     * done:
     */

    // allocate space for our 4 arguments (input0, input1, output, and done_dest).
    bf->add_4_args_size = 4;
    bf->add_4_args = bf->next_cb;
    bf->next_cb = &bf->add_4_args[bf->add_4_args_size];

    cb = bf->next_cb;

    bf->add_4 = cb;

    //
    // Name our arguments
    //

    output = &bf->add_4_args[0].source;
    input0 = &bf->add_4_args[1].source;
    input1 = &bf->add_4_args[2].source;
    done_dest = &bf->add_4_args[3].source;

    //
    // Name some local vars
    //

    carry = &bf->add_4_args[0].data;

    //
    // Name add's arguments
    //

    add_output = &bf->add_args[0].source;
    add_cout = &bf->add_args[1].source;
    add_in0 = &bf->add_args[2].source;
    add_in1 = &bf->add_args[3].source;
    add_cin = &bf->add_args[4].source;
    add_ret = &bf->add_args[5].source;

    // set carry to 0
    setup_cb(cb + 0, carry, Zeroes, 1, cb + 1);

    // carry_in = &carry
    // carry_out = &carry
    setup_cb(cb + 1, add_cin, &cb[1].data, 4, cb + 2);
    cb[1].data = virtual_to_bus(carry);
    setup_cb(cb + 2, add_cout, &cb[2].data, 4, cb + 3);
    cb[2].data = virtual_to_bus(carry);

    // loop this

    cb = &cb[3];
    max = 4;
    for (i = 0; i < max; ++i)
    {
        // setup output
        setup_cb(cb + 0, add_output, output, 4, cb + 1);
        // setup operands
        setup_cb(cb + 1, add_in0, input0, 4, cb + 2);
        setup_cb(cb + 2, add_in1, input1, 4, cb + 3);
        // setup_ret
        setup_cb(cb + 3, add_ret, &cb[3].data, 4, bf->add);
        cb[3].data = virtual_to_bus(cb + 4);

        cb = &cb[4];

        if (i < (max - 1))
        {
            // output++
            setup_cb(cb + 0, &bf->inc_4->source, &cb[0].data, 4, cb + 1);
            cb[0].data = virtual_to_bus(output);
            setup_cb(cb + 1, &bf->tramp->next, &cb[1].data, 4, bf->inc_4);
            cb[1].data = virtual_to_bus(cb + 2);

            // input0++
            setup_cb(cb + 2, &bf->inc_4->source, &cb[2].data, 4, cb + 3);
            cb[2].data = virtual_to_bus(input0);
            setup_cb(cb + 3, &bf->tramp->next, &cb[3].data, 4, bf->inc_4);
            cb[3].data = virtual_to_bus(cb + 4);

            // input1++
            setup_cb(cb + 4, &bf->inc_4->source, &cb[4].data, 4, cb + 5);
            cb[4].data = virtual_to_bus(input1);
            setup_cb(cb + 5, &bf->tramp->next, &cb[5].data, 4, bf->inc_4);
            cb[5].data = virtual_to_bus(cb + 6);

            cb = &cb[6];
        }
        else
        {
            break;
        }
    }
    setup_cb(cb + 0, &cb[1].next, done_dest, 4, cb + 1);
    setup_cb(cb + 1, cb + 1, cb + 1, 0, NULL);

    bf->next_cb = &cb[2];
}

/* This is a generic cmp (if-then-else) gadget. The source address of
 * the first control block contains the address of the uint32_t to be used in a
 * test for zero. After the gadget is finished, it executes the trampoline
 * gadget tramp2 to branch. */
void
build_cmp_4(
    bf_t *bf
    )
{
    uint32_t *cond, *true_block, *false_block;
    uint32_t i;
    cb_t cb;

    assert(bf->inc_4);
    assert(bf->cmp);

    /* The basic algorithm is
     *     if (*(byte*)cond)
     *         goto true_block;
     *   ++cond;
     *     if (*(byte*)cond)
     *         goto true_block;
     *   ++cond;
     *     if (*(byte*)cond)
     *         goto true_block;
     *   ++cond;
     *     if (*(byte*)cond)
     *         goto true_block;
     * false_block:
     */
    /* This is how to invoke this gadget
     *   *bf.scratch = 0x00010000;
     *   // setup our condition
     *   setup_cb(cb + 0, &bf.cmp_4_args[0].source, &cb[0].data, 4, cb + 1);
     *   cb[0].data = virtual_to_bus(bf.scratch);
     *   // setup our true_block path
     *   setup_cb(cb + 1, &bf.cmp_4_args[1].source, &cb[1].data, 4, cb + 2);
     *   cb[1].data = virtual_to_bus(bf.syscall_exit);
     *   cb[1].data = virtual_to_bus(0x41414141);
     *   // setup our false_block path and then invoke cmp_4
     *   setup_cb(cb + 2, &bf.cmp_4_args[2].source, &cb[2].data, 4, bf.cmp_4);
     *   cb[2].data = virtual_to_bus(0xdeadbeef);
     */

    // allocate space for our 3 arguments (conditional, true-block, and false-block)
    bf->cmp_4_args_size = 3;
    bf->cmp_4_args = bf->next_cb;
    bf->next_cb = &bf->cmp_4_args[bf->cmp_4_args_size];

    cb = bf->next_cb;

    bf->cmp_4 = cb;
    // name our arguments
    cond = &bf->cmp_4_args[0].source;
    true_block = &bf->cmp_4_args[1].source;
    false_block = &bf->cmp_4_args[2].source;

    for (i = 0; i < 4; ++i)
    {
        // setup our condition
        setup_cb(cb + 0, &bf->cmp_args[0].source, cond, 4, cb + 1);
        // setup our true_block path
        setup_cb(cb + 1, &bf->cmp_args[1].source, true_block, 4, cb + 2);
        // setup our false_block path and then invoke cmp
        setup_cb(cb + 2, &bf->cmp_args[2].source, &cb[2].data, 4, bf->cmp);
        cb[2].data = virtual_to_bus(cb + 3);

        setup_cb(cb + 3, &bf->inc_4->source, &cb[3].data, 4, cb + 4);
        cb[3].data = virtual_to_bus(cond);
        setup_cb(cb + 4, &bf->tramp->next, &cb[4].data, 4, bf->inc_4);
        cb[4].data = virtual_to_bus(cb + 5);

        cb = &cb[5];
    }
    setup_cb(cb + 0, &cb[1].next, false_block, 4, cb + 1);
    setup_cb(cb + 1, cb + 1, cb + 1, 0, NULL);

    bf->next_cb = &cb[2];
}

/* This is a generic cmp (if-then-else) gadget. The source address of
 * the first control block contains the address of the uint8_t to be used in a
 * test for zero. After the gadget is finished, it executes the trampoline
 * gadget tramp2 to branch. */
void
build_cmp(
    bf_t *bf
    )
{
    uint32_t *cond, *true_block, *false_block;
    uint8_t *byte;
    cb_t cb;

    assert(bf->tramp2);

    /* The basic algorithm is
     *     if (*(byte*)cond)
     *         goto true_block;
     * false_block:
     */
    /* This is how to invoke this gadget
     *  // setup our condition
     *  setup_cb(cb + 0, &bf.cmp_args[0].source, &cb[0].data, 4, cb + 1);
     *  *bf.scratch = 0xffffffff;
     *  cb[0].data = virtual_to_bus(bf.scratch);
     *  // setup our true_block path
     *  setup_cb(cb + 1, &bf.cmp_args[1].source, &cb[1].data, 4, cb + 2);
     *  cb[1].data = virtual_to_bus(0x41414141);
     *  // setup our false_block path and then invoke cmp
     *  setup_cb(cb + 2, &bf.cmp_args[2].source, &cb[2].data, 4, bf.cmp);
     *  cb[2].data = virtual_to_bus(0x24242424);
     */

    // allocate space for our 3 arguments (conditional, true-block, and false-block)
    bf->cmp_args_size = 3;
    bf->cmp_args = bf->next_cb;
    bf->next_cb = &bf->cmp_args[bf->cmp_args_size];

    cb = bf->next_cb;

    // name our arguments
    cond = &bf->cmp_args[0].source;
    true_block = &bf->cmp_args[1].source;
    false_block = &bf->cmp_args[2].source;

    // setup the jump table
    setup_cb(cb + 0, &bf->conditional_table.False[COND_INDEX], false_block, 4, cb + 1);
    setup_cb(cb + 1, &bf->conditional_table.True [COND_INDEX], true_block, 4, cb + 2);

    // copy the cond address into cb[1]'s source
    setup_cb(cb + 2, &cb[3].source, cond, 4, cb + 3);
    // load the LSB and use it as an index into the boolean_inc_table
    setup_cb(cb + 3, &cb[4].source, NULL, 1, cb + 4);
    // load from the boolean_inc_table and use as 2nd LSB into
    // conditional_table. Since the table is 0x200 bytes, the 2nd LSB breaks
    // the table cleanly into the first 0x100 bytes (false) or the second 0x100
    // bytes (true). The LSB is unaffected, which is why we wrote our branches
    // there.
    byte = (uint8_t *)&cb[5].source;
    setup_cb(cb + 4, &byte[1], bf->boolean_inc_table, 1, cb + 5);
    // load the offset from the conditional_table into tramp2 and execute tramp2
    setup_cb(cb + 5, &bf->tramp2->next, &bf->conditional_table.Test[COND_INDEX], 4, bf->tramp2);

    bf->cmp = cb;
    bf->next_cb = &cb[6];
}

void
build_syscall_table(
    bf_t *bf
    )
{
    assert(bf->next_insn);
    assert(bf->syscall_exit);
//    assert(bf->syscall_open);
//    assert(bf->syscall_close);
    assert(bf->syscall_read);
    assert(bf->syscall_write);

    bf->syscall_table.quit = QUIT;
    bf->syscall_table.nop = virtual_to_bus(bf->next_insn);

    bf->syscall_table.exit  = virtual_to_bus(bf->syscall_exit);
    bf->syscall_table.open  = virtual_to_bus(bf->syscall_open);
    bf->syscall_table.close = virtual_to_bus(bf->syscall_close);
    bf->syscall_table.read  = virtual_to_bus(bf->syscall_read);
    bf->syscall_table.write = virtual_to_bus(bf->syscall_write);
}

void
build_eq(
    bf_t *bf
    )
{
    uint32_t *a, *b, *true_block, *false_block;
    cb_t cb;

    assert(bf->cmp);

    // 1. zero eq table
    // 2. use operand A (a byte) to set the A'th entry in the eq table to a nonzero value (1)
    // 3. cmp operand B (a byte) to the B'th entry in the table. If it's the same value, they are identical

    /* This is how to invoke
     *   // setup our operands
     *   setup_cb(cb + 0, &bf->eq_args[0].source, &cb[0].data, 4, cb + 1);
     *   bf->scratch0 = 0x7f;
     *   cb[0].data = virtual_to_bus(&bf->scratch0);
     *
     *   setup_cb(cb + 1, &bf->eq_args[1].source, &cb[1].data, 4, cb + 2);
     *   bf->scratch1 = 0x80;
     *   cb[1].data = virtual_to_bus(&bf->scratch1);
     *
     *   // setup our true_block path
     *   setup_cb(cb + 2, &bf->eq_args[2].source, &cb[2].data, 4, cb + 3);
     *   cb[2].data = virtual_to_bus(0x41414141);
     *   // setup our false_block path and then invoke eq
     *   setup_cb(cb + 3, &bf->eq_args[3].source, &cb[3].data, 4, bf->eq);
     *   cb[3].data = virtual_to_bus(0x24242424);
     */

    // allocate space for our 4 arguments (operand a, operand b, true-block, and false-block)
    bf->eq_args_size = 4;
    bf->eq_args = bf->next_cb;
    bf->next_cb = &bf->eq_args[bf->eq_args_size];

    cb = bf->next_cb;

    // name our arguments
    a = &bf->eq_args[0].source;
    b = &bf->eq_args[1].source;
    true_block = &bf->eq_args[2].source;
    false_block = &bf->eq_args[3].source;

    // Zero out eq table
    setup_cb(cb + 0, &bf->eq_table[0], Zeroes, sizeof(bf->eq_table), cb + 1);
    // Zero out argumentsso we have a fresh state to work with. We did this initially because of a bug but it doesn't hurt to leave it.
    setup_cb(cb + 1, &bf->cmp_args[0].source, Zeroes, ARG_SIZE(bf->cmp_args_size), cb + 2);

    // load a into source of cb[2]
    setup_cb(cb + 2, &cb[3].source, a, 4, cb + 3);
    // use *a as an offset into eq_table
    setup_cb(cb + 3, &cb[4].destination, NULL, 1, cb + 4);
    // write the value into the a'th entry of the eq_table
    setup_cb(cb + 4, &bf->eq_table[0], "1", 1, cb + 5);

    // load b into source of cb[5]
    setup_cb(cb + 5, &cb[6].source, b, 4, cb + 6);
    // use *b as an offset into eq_table
    setup_cb(cb + 6, &cb[7].data, NULL, 1, cb + 7);

    // copy the value from the b'th entry into cmp_arg[0] (the condition arg)
    setup_cb(cb + 7, &bf->cmp_args[0].source, &cb[7].data, 4, cb + 8);
    cb[7].data = virtual_to_bus(&bf->eq_table[0]);
    setup_cb(cb + 8, &bf->cmp_args[1].source, true_block, 4, cb + 9);
    setup_cb(cb + 9, &bf->cmp_args[2].source, false_block, 4, bf->cmp);

    bf->eq = cb;
    bf->next_cb = &cb[10];
}

void
build_eq_4(
    bf_t *bf
    )
{
    uint32_t *a, *b, *true_block, *false_block;
    uint32_t i;
    cb_t cb;

    assert(bf->eq);
    assert(bf->inc_4);

    // 1. zero eq table
    // 2. use operand A (a byte) to set the A'th entry in the eq table to a nonzero value (1)
    // 3. cmp operand B (a byte) to the B'th entry in the table. If it's the same value, they are identical

    /* This is how to invoke
     *   // setup our operands
     *   setup_cb(cb + 0, &bf->eq_args[0].source, &cb[0].data, 4, cb + 1);
     *   bf->scratch0 = 0x7f;
     *   cb[0].data = virtual_to_bus(&bf->scratch0);
     *
     *   setup_cb(cb + 1, &bf->eq_args[1].source, &cb[1].data, 4, cb + 2);
     *   bf->scratch1 = 0x80;
     *   cb[1].data = virtual_to_bus(&bf->scratch1);
     *
     *   // setup our true_block path
     *   setup_cb(cb + 2, &bf->eq_args[2].source, &cb[2].data, 4, cb + 3);
     *   cb[2].data = virtual_to_bus(0x41414141);
     *   // setup our false_block path and then invoke eq
     *   setup_cb(cb + 3, &bf->eq_args[3].source, &cb[3].data, 4, bf->eq);
     *   cb[3].data = virtual_to_bus(0x24242424);
     */

    // allocate space for our 4 arguments (operand a, operand b, true-block, and false-block)
    bf->eq_4_args_size = 4;
    bf->eq_4_args = bf->next_cb;
    bf->next_cb = &bf->eq_4_args[bf->eq_4_args_size];

    cb = bf->next_cb;

    bf->eq_4 = cb;
    // name our arguments
    a = &bf->eq_4_args[0].source;
    b = &bf->eq_4_args[1].source;
    true_block = &bf->eq_4_args[2].source;
    false_block = &bf->eq_4_args[3].source;

    for (i = 0; i < 4; ++i)
    {
        // setup our operands
        setup_cb(cb + 0, &bf->eq_args[0].source, a, 4, cb + 1);
        setup_cb(cb + 1, &bf->eq_args[1].source, b, 4, cb + 2);
        // setup our true path
        setup_cb(cb + 2, &bf->eq_args[2].source, &cb[2].data, 4, cb + 3);
        cb[2].data = virtual_to_bus(cb + 4);
        // setup our false path
        setup_cb(cb + 3, &bf->eq_args[3].source, false_block, 4, bf->eq);

        // a = &a[1]
        setup_cb(cb + 4, &bf->inc_4->source, &cb[4].data, 4, cb + 5);
        cb[4].data = virtual_to_bus(a);
        setup_cb(cb + 5, &bf->tramp->next, &cb[5].data, 4, bf->inc_4);
        cb[5].data = virtual_to_bus(cb + 6);

        // b = &b[1]
        setup_cb(cb + 6, &bf->inc_4->source, &cb[6].data, 4, cb + 7);
        cb[6].data = virtual_to_bus(b);
        setup_cb(cb + 7, &bf->tramp->next, &cb[7].data, 4, bf->inc_4);
        cb[7].data = virtual_to_bus(cb + 8);

        cb = &cb[8];
    }
    setup_cb(cb + 0, &cb[1].next, true_block, 4, cb + 1);
    setup_cb(cb + 1, cb + 1, cb + 1, 0, NULL);

    bf->next_cb = &cb[2];
}

// XXX split this into half-adder, and carry_out. Then build add out of those two components.
void
build_add(
    bf_t *bf
    )
{
    uint32_t *output, *carry_out, *input0, *input1, *carry_in, *ret_addr;
    uint32_t *out_set, *in0_set, *in1_set;
    uint32_t i, j;
    uint8_t *byte;
    cb_t cb, goto_done;

    //
    // Initialize the lookup tables. We pre-compute addition between every pair
    // of 8-bit values. We then use input0 to select which secondary lookup table to
    // use (i.e., input0 selects the table that precomputed (input0 + x)). Then we use
    // input1 to select the output value from that table.
    //

    /*
     *      if (in0_set)
     *      {
     *          if (in1_set)
     *          {
     *              *cout = 1;
     *          }
     *          else
     *          {
     *              *cout = !out_set;
     *          }
     *      }
     *      else
     *      {
     *          if (in1_set)
     *          {
     *              *cout = !out_set;
     *          }
     *          else
     *          {
     *              *cout = 0;
     *          }
     *      }
     */

    /* Basic algorithm
     *  *output = lut[*input0][*input1]
     *  if (*carry_in)
     *      inc_no_carry(output)
     *  *cout = calculated_from_above_algorithm;
     *  ret_addr:
     */

    for (i = 0; i < 256; ++i)
    {
        for (j = 0; j < 256; ++j)
        {
            bf->arithmetic_tables.addition[i][j] = i + j;
        }
    }

    for (i = 0; i < 256; ++i)
    {
        bf->msb_set[i] = (i & 0x80) == 0x80;
    }

    // allocate space for our 6 arguments (output, carry_out, input0, input1, carry_in, return_address)
    bf->add_args_size = 6;
    bf->add_args = bf->next_cb;
    bf->next_cb = &bf->add_args[bf->add_args_size];

    cb = bf->next_cb;

    // name our arguments
    output = &bf->add_args[0].source;
    out_set = &bf->add_args[0].data;
    carry_out = &bf->add_args[1].source;
    input0 = &bf->add_args[2].source;
    in0_set = &bf->add_args[2].data;
    input1 = &bf->add_args[3].source;
    in1_set = &bf->add_args[3].data;
    carry_in = &bf->add_args[4].source;
    ret_addr = &bf->add_args[5].source;

    //
    // The main idea here is that our addition table is 64k aligned. This means
    // the bottom two bytes are zero. We can therefor simply set the bottom two
    // bytes to be i and j. The corresponding element will then be i+j.
    // e.g., 0xFFFF0000 is the base of our table. 0xFFFF[i][j] == i+j.
    //

    // this points to the trampoline at the end of this sequence
    goto_done = &cb[46];

    // point this to the cb source that contains the table
    byte = (uint8_t *)&cb[5].source;

    // load input0 into the source address of cb[1]
    setup_cb(cb + 0, &cb[1].source, input0, 4, cb + 1);
    // use *input0 as an offset into the lookup tables
    setup_cb(cb + 1, &byte[1], NULL, 1, cb + 2);

    // load input1 into the source address of cb[3]
    setup_cb(cb + 2, &cb[3].source, input1, 4, cb + 3);
    // use *input0 as the other offset into the lookup tables
    setup_cb(cb + 3, &byte[0], NULL, 1, cb + 4);

    // write the value of lut[in0][in1] to output
    setup_cb(cb + 4, &cb[5].destination, output, 4, cb + 5);
    setup_cb(cb + 5, NULL, &bf->arithmetic_tables.addition[0], 1, cb + 6);

    // if (*carry_in)
    setup_cb(cb + 6, &bf->cmp_args[0].source, carry_in, 4, cb + 7);
    setup_cb(cb + 7, &bf->cmp_args[1].source, &cb[7].data, 4, cb + 8);
    cb[7].data = virtual_to_bus(cb + 9);
    setup_cb(cb + 8, &bf->cmp_args[2].source, &cb[8].data, 4, bf->cmp);
    cb[8].data = virtual_to_bus(cb + 13);

        // then inc(output)
        setup_cb(cb + 9, &cb[10].source, output, 4, cb + 10);
        setup_cb(cb + 10, &cb[12].source, NULL, 1, cb + 11);
        setup_cb(cb + 11, &cb[12].destination, output, 4, cb + 12);
        setup_cb(cb + 12, NULL, &bf->inc_table[0], 1, cb + 13);

    // default (also false) path

    // lookup input0, input1, and output in the msb_set table.
    setup_cb(cb + 13, &cb[14].source, input0, 4, cb + 14);
    setup_cb(cb + 14, &cb[15].source, NULL, 1, cb + 15);
    setup_cb(cb + 15, in0_set, &bf->msb_set[0], 1, cb + 16);

    setup_cb(cb + 16, &cb[17].source, input1, 4, cb + 17);
    setup_cb(cb + 17, &cb[18].source, NULL, 1, cb + 18);
    setup_cb(cb + 18, in1_set, &bf->msb_set[0], 1, cb + 19);

    setup_cb(cb + 19, &cb[20].source, output, 4, cb + 20);
    setup_cb(cb + 20, &cb[21].source, NULL, 1, cb + 21);
    setup_cb(cb + 21, out_set, &bf->msb_set[0], 1, cb + 22);

    // logically invert out_set
    setup_cb(cb + 22, &bf->cmp_args[0].source, &cb[22].data, 4, cb + 23);
    cb[22].data = virtual_to_bus(out_set);
    setup_cb(cb + 23, &bf->cmp_args[1].source, &cb[23].data, 4, cb + 24);
    cb[23].data = virtual_to_bus(cb + 25); // true
    setup_cb(cb + 24, &bf->cmp_args[2].source, &cb[24].data, 4, bf->cmp);
    cb[24].data = virtual_to_bus(cb + 26); // false

    // !out_set == 0
    setup_cb(cb + 25, out_set, Zeroes, 1, cb + 27);
    // !out_set == 1
    setup_cb(cb + 26, out_set, "Y", 1, cb + 27);


    // if (in0_set)
    setup_cb(cb + 27, &bf->cmp_args[0].source, &cb[27].data, 4, cb + 28);
    cb[27].data = virtual_to_bus(in0_set);
    setup_cb(cb + 28, &bf->cmp_args[1].source, &cb[28].data, 4, cb + 29);
    cb[28].data = virtual_to_bus(cb + 30); // true
    setup_cb(cb + 29, &bf->cmp_args[2].source, &cb[29].data, 4, bf->cmp);
    cb[29].data = virtual_to_bus(cb + 38); // false

    // then

        // if (in1_set)
        setup_cb(cb + 30, &bf->cmp_args[0].source, &cb[30].data, 4, cb + 31);
        cb[30].data = virtual_to_bus(in1_set);
        setup_cb(cb + 31, &bf->cmp_args[1].source, &cb[31].data, 4, cb + 32);
        cb[31].data = virtual_to_bus(cb + 33); // true
        setup_cb(cb + 32, &bf->cmp_args[2].source, &cb[32].data, 4, bf->cmp);
        cb[32].data = virtual_to_bus(cb + 35); // false

        // then

            // cout = 1;
            setup_cb(cb + 33, &cb[34].destination, carry_out, 4, cb + 34);
            setup_cb(cb + 34, NULL, "\x01", 1, goto_done);

        // else
            // cout = !out_set
            setup_cb(cb + 35, &cb[37].destination, carry_out, 4, cb + 36);
            setup_cb(cb + 36, &cb[37].source, out_set, 4, cb + 37);
            setup_cb(cb + 37, NULL, NULL, 1, goto_done);

    // else

        // if (in1_set)
        setup_cb(cb + 38, &bf->cmp_args[0].source, &cb[38].data, 4, cb + 39);
        cb[38].data = virtual_to_bus(in1_set);
        setup_cb(cb + 39, &bf->cmp_args[1].source, &cb[39].data, 4, cb + 40);
        cb[39].data = virtual_to_bus(cb + 41); // true
        setup_cb(cb + 40, &bf->cmp_args[2].source, &cb[40].data, 4, bf->cmp);
        cb[40].data = virtual_to_bus(cb + 44); // false

        // then

            // cout = !out_set
            setup_cb(cb + 41, &cb[43].destination, carry_out, 4, cb + 42);
            setup_cb(cb + 42, &cb[43].source, out_set, 4, cb + 43);
            setup_cb(cb + 43, NULL, NULL, 1, goto_done);

        // else

            // cout = 0;
            setup_cb(cb + 44, &cb[45].destination, carry_out, 4, cb + 45);
            setup_cb(cb + 45, NULL, Zeroes, 1, goto_done);


    // return
    setup_cb(cb + 46, &cb[47].next, ret_addr, 4, cb + 47);
    setup_cb(cb + 47, cb + 47, cb + 47, 0, NULL);

    bf->add = cb;
    bf->next_cb = &cb[48];
}
