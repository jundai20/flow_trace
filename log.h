#ifndef LOG_H
/* print out message immediately */
void output_message(char *format, ...);
/* speed limited, one second one message at most, may lost message */
void output_message_limited(char *format, ...);

int log_subsys_init(const char* log_file);
#endif
