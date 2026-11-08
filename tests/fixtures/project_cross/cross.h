#ifndef PROJECT_CROSS_H
#define PROJECT_CROSS_H

#define CROSS_NOINLINE __attribute__((noinline))
#define CROSS_ANCHOR __attribute__((noinline, section(".cross_identity")))

int cross_a_sink(const char *input);
const char *cross_a_return(const char *input);
const char *cross_a_buffer(const char *input);
void cross_a_out(char *output, const char *input);
const char *cross_a_safe(const char *input);
const char *cross_a_source_return(void);
void cross_a_source_out(char *output);
int cross_a_cycle(const char *input, unsigned depth);
int cross_a_unknown(const char *input);
int cross_a_anchor(const char *input);

int cross_b_sink(const char *input);
const char *cross_b_return(const char *input);
const char *cross_b_buffer(const char *input);
void cross_b_out(char *output, const char *input);
const char *cross_b_safe(const char *input);
const char *cross_b_source_return(void);
void cross_b_source_out(char *output);
int cross_b_cycle(const char *input, unsigned depth);
int cross_b_unknown(const char *input);
int cross_b_anchor(const char *input);

#endif
