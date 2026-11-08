#include "cross.h"
#include <stdlib.h>
#include <string.h>

/* Both libraries place a different real body at the same virtual address. */
CROSS_ANCHOR int cross_b_anchor(const char *input)
{
    return system(input);
}

CROSS_NOINLINE int cross_b_sink(const char *input)
{
    return system(input);
}

CROSS_NOINLINE const char *cross_b_return(const char *input)
{
    return input;
}

CROSS_NOINLINE const char *cross_b_buffer(const char *input)
{
    static char output[128];
    strcpy(output, input);
    return output;
}

CROSS_NOINLINE void cross_b_out(char *output, const char *input)
{
    strcpy(output, input);
}

CROSS_NOINLINE const char *cross_b_safe(const char *input)
{
    (void)input;
    return "printf safe";
}

CROSS_NOINLINE const char *cross_b_source_return(void)
{
    return getenv("PROJECT_CROSS_INPUT");
}

CROSS_NOINLINE void cross_b_source_out(char *output)
{
    const char *input = getenv("PROJECT_CROSS_INPUT");
    strcpy(output, input);
}

CROSS_NOINLINE int cross_b_cycle(const char *input, unsigned depth)
{
    if (depth != 0)
        return cross_b_cycle(input, depth - 1);
    return system(input);
}

/* Deliberately absent from every project file: never resolve by global name. */
extern int cross_missing_provider(const char *input);
CROSS_NOINLINE int cross_b_unknown(const char *input)
{
    return cross_missing_provider(input);
}
