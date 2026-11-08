#include "cross.h"

CROSS_ANCHOR int cross_a_anchor(const char *input)
{
    return cross_b_anchor(input);
}

CROSS_NOINLINE int cross_a_sink(const char *input)
{
    return cross_b_sink(input);
}

CROSS_NOINLINE const char *cross_a_return(const char *input)
{
    return cross_b_return(input);
}

CROSS_NOINLINE const char *cross_a_buffer(const char *input)
{
    return cross_b_buffer(input);
}

CROSS_NOINLINE void cross_a_out(char *output, const char *input)
{
    cross_b_out(output, input);
}

CROSS_NOINLINE const char *cross_a_safe(const char *input)
{
    return cross_b_safe(input);
}

CROSS_NOINLINE const char *cross_a_source_return(void)
{
    return cross_b_source_return();
}

CROSS_NOINLINE void cross_a_source_out(char *output)
{
    cross_b_source_out(output);
}

CROSS_NOINLINE int cross_a_cycle(const char *input, unsigned depth)
{
    return cross_b_cycle(input, depth);
}

CROSS_NOINLINE int cross_a_unknown(const char *input)
{
    return cross_b_unknown(input);
}
