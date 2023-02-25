#ifndef GENERATE_CORE_H
#define GENERATE_CORE_H

struct traced_process_;

typedef int (*gen_coredump_cb) (char *core_fn, struct traced_process_ *proc);
int generate_coredump (char *core_fn, struct traced_process_ *proc);
extern gen_coredump_cb coredump_callback;
#endif
