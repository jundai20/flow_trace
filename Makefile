AR=ar

all: spy
.PHONY: spy

SPY_C_SRCS = spy.c func_addr.c pmparser.c breakpoint.c yparse_bp.c proc_ptrace.c log.c special_api.c
SPY_C_OBJS = $(patsubst %.c, %.o, $(SPY_C_SRCS))

CFLAGS	?= -g -Wall -Werror
$(SPY_C_OBJS):%.o: %.c
	$(CC) $(CFLAGS) $(COMPEL_OPT) -c $<

spy: $(SPY_C_OBJS)
	$(CC) $(CFLAGS) -g -o $@ $(SPY_C_OBJS) -lyaml -lunwind-ptrace -lunwind -lunwind-x86_64 -ldl
	patchelf --set-rpath '$$ORIGIN/' spy

clean:
	find . -name "*.o" | xargs rm -f
	rm -f rm spy watch_target watch_mem -f
