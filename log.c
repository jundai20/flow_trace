#include "log.h"

#include <stdio.h>
#include <sys/time.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

static FILE *output_fd;

void output_message (const char *format, ...)
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
        setbuf(output_fd, NULL);
        return 0;
    }
    output_fd = stdout;
    return -1;
}
