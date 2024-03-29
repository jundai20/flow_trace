AR=ar

all: ibut
.PHONY: ibut

IBUT_C_SRCS = ibut.c func_addr.c pmparser.c breakpoint.c log.c watchdog.c generate_core_x86_64.c
IBUT_C_OBJS = $(patsubst %.c, %.o, $(IBUT_C_SRCS))
breakpoint.o: breakpoint.h breakpoint.c

CFLAGS	?= -g -Wall -Werror -Wl,-E -D__x86_64__
LDFLAGS = -lunwind-ptrace -lunwind -lunwind-x86_64 -lpthread -ldl

$(IBUT_C_OBJS):%.o: %.c
	$(CC) $(CFLAGS) $(COMPEL_OPT) -c $<

ibut: $(IBUT_C_OBJS) ut
	$(CC) $(CFLAGS) -g -o $@ $(IBUT_C_OBJS) $(LDFLAGS)
	-patchelf --set-rpath '$$ORIGIN/' ibut
	gcc -shared -lpthread -fPIC -o ibut_plugin.so -I. ibut_plugin.c

ut:
	$(CC) test/test_mt.c -c -g -Og
	$(CC) test_mt.o -g -o test_mt -lpthread

tag:
	rm -rf filelist
	ls *.[ch] > filelist
	cscope -bkq -i filelist
clean:
	find . -name "*.o" | xargs rm -f
	rm ibut -f
