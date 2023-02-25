#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <signal.h>

static long run_count;

void foo (int i)
{
    printf("Enter foo\n");

    sleep(3);
    run_count += i;
    printf("[%ld]", run_count);
}

void bar (long *cnt)
{
    sleep(*cnt%3+1);
}

void* dummy_a (void *ctx)
{
    int i;

    while (1) {
        foo(i++);
    }
    return NULL;
}

void* dummy_b (void *ctx)
{
    int i = 42;

    while (1) {
        bar(&run_count);
    }
    return NULL;
}

void sigusr2_handler (int sig)
{
    printf("Received sigusr2 on %ld\n", syscall(SYS_gettid));
}

void sigstop_handler (int sig)
{
    printf("Received sigstop on %ld\n", syscall(SYS_gettid));
}

int main ()
{
    pthread_t tid1, tid2;

    setbuf(stdout, NULL);
    signal(SIGUSR2, sigusr2_handler);
    signal(SIGSTOP, sigstop_handler);

    pthread_create(&tid1, NULL, dummy_a, NULL);
    pthread_create(&tid2, NULL, dummy_b, NULL);

    printf("Main process id = %d , foo = %p, bar = %p, run_count@%p\n", getpid(), foo, bar, &run_count);

    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
}
