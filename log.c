#include "log.h"

#include <stdio.h>
#include <sys/time.h>
#include <stdarg.h>

static FILE *output_fd;

void output_message_limited (char *format, ...)
{
    struct timeval tv;
    static time_t saved_sec;
    va_list args;

    gettimeofday(&tv, NULL);
    if (saved_sec == tv.tv_sec) {
        return;
    }
    saved_sec = tv.tv_sec;
    va_start(args, format);
    vfprintf(output_fd, format, args);
    va_end(args);
}

void output_message (char *format, ...)
{
    va_list args;

    va_start(args, format);
    vfprintf(output_fd, format, args);
    va_end(args);
}

int log_subsys_init (const char* log_file)
{
    if (!log_file) {
        output_fd = stdout;
        return 0;
    }
    output_fd = fopen(log_file, "w+");
    if (output_fd) {
        return 0;
    }

    printf("Warning: can not open file to save log\n");
    output_fd = stdout;
    return -1;
}
