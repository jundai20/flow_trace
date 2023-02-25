#ifndef LOG_H
#include <stdint.h>

#define TEST_LOG "test_log"

/* print out message immediately */
void output_message(const char *format, ...);
/* speed limited, one second one message at most, may lost message */
int log_subsys_init(const char* log_file);
#endif
