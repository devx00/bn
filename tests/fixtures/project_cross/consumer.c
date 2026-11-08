#include "cross.h"
#include <stdlib.h>
#include <string.h>

CROSS_NOINLINE int cross_entry_sink(const char *input)
{
    return cross_a_sink(input);
}

CROSS_NOINLINE int cross_entry_return(const char *input)
{
    return system(cross_a_return(input));
}

CROSS_NOINLINE int cross_entry_buffer(const char *input)
{
    return system(cross_a_buffer(input));
}

CROSS_NOINLINE int cross_entry_modified_return(void)
{
    char *output = (char *)cross_a_buffer("constant");
    strcpy(output, getenv("BN_CROSS_INPUT"));
    return system(output);
}

CROSS_NOINLINE int cross_entry_out(const char *input)
{
    char output[128];
    cross_a_out(output, input);
    return system(output);
}

CROSS_NOINLINE int cross_entry_safe(const char *input)
{
    return system(cross_a_safe(input));
}

CROSS_NOINLINE int cross_entry_source_return(void)
{
    return system(cross_a_source_return());
}

CROSS_NOINLINE int cross_entry_source_out(void)
{
    char output[128];
    cross_a_source_out(output);
    return system(output);
}

CROSS_NOINLINE int cross_entry_cycle(const char *input, unsigned depth)
{
    return cross_a_cycle(input, depth);
}

CROSS_NOINLINE int cross_entry_unknown(const char *input)
{
    return cross_a_unknown(input);
}

CROSS_NOINLINE int cross_entry_anchor(const char *input)
{
    return cross_a_anchor(input);
}

CROSS_NOINLINE int cross_standalone_source(void)
{
    return system(getenv("PROJECT_CROSS_INPUT"));
}

/* All functions remain exported even without executing this unsafe fixture. */
int main(int argc, char **argv)
{
    if (argc < 3)
        return 0;
    switch (argv[1][0]) {
    case 's': return cross_entry_sink(argv[2]);
    case 'r': return cross_entry_return(argv[2]);
    case 'b': return cross_entry_buffer(argv[2]);
    case 'o': return cross_entry_out(argv[2]);
    case 'c': return cross_entry_safe(argv[2]);
    case 'R': return cross_entry_source_return();
    case 'O': return cross_entry_source_out();
    case 'y': return cross_entry_cycle(argv[2], (unsigned)argc);
    case 'u': return cross_entry_unknown(argv[2]);
    case 'a': return cross_entry_anchor(argv[2]);
    default: return 0;
    }
}
