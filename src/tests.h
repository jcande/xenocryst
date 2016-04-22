#ifndef TESTS_H
#define TESTS_H

#define TRUE_VALUE      0x01
#define FALSE_VALUE     0x00

#define errprintf(...)  fprintf(stderr, __VA_ARGS__)

typedef uint32_t        RESULT;
#define SUCCEEDED(x)    ((x) == TRUE_VALUE)
#define FAILED(x)       (!SUCCEEDED(x))

//
// Add tests to the table
//

#define TEST_TABLE(ENTRY)   \
        ENTRY(alignment)    \
        ENTRY(enum_size)    \
        ENTRY(cmp)          \
        ENTRY(cmp_4)        \
        ENTRY(eq)           \
        ENTRY(eq_4)         \
        ENTRY(add)          \
        ENTRY(add_4)        \
        ENTRY(dec)          \
        ENTRY(inc)          \
        ENTRY(rightleft)    \
        ENTRY(inc_4)        \
        ENTRY(io)           \
        ENTRY(dispatch)     \
        ENTRY(syscalls)     \


//
// Declare prototypes for all tests.
//

typedef RESULT(*TestFunction_t)(bf_t *);

//#define AS_TEST_PROTOTYPE(NAME)  TestFunction_t test_ ## NAME;
#define AS_TEST_PROTOTYPE(NAME)     \
    RESULT test_ ## NAME(bf_t *bf); \

TEST_TABLE(AS_TEST_PROTOTYPE)


//
// A hackey way of retrieving the number of tests.
//

#define AS_TEST_ENTRIES(NAME)   _test_enum_ ## NAME,
enum _TEST_NAMES_ENUM {
    TEST_TABLE(AS_TEST_ENTRIES)
    NUMBER_OF_TESTS
};

extern TestFunction_t Tests[NUMBER_OF_TESTS];

#endif // TESTS_H
