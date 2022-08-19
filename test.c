#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define NOP 500000

int baz (void)
{
    sleep(1);
    return random();
}

int bar (void)
{
    sleep(1);
    return baz();
}

int main ()
{
    int cnt = 0;

    printf("Run: ./spy -p %d -g\n", getpid());
    for (;;) {
        cnt+= bar();
    }
    return cnt;
}
