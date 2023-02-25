#include "watchdog.h"

#include <stdio.h>
#include <sys/time.h>
#include <signal.h>

static watchdog_expire_callback callback_fn;
static int watchdog_expire_counter;

static void hog_expire_callback (int signo)
{
    if (watchdog_expire_counter++ > WATCHDOG_EXPIRE && callback_fn) {
        callback_fn();
    }
}

int start_watchdog (watchdog_expire_callback callback)
{
    callback_fn = callback;
    struct itimerval timer;

    timer.it_value.tv_sec = 1;
    timer.it_value.tv_usec = 0;
    timer.it_interval = timer.it_value;

    if (setitimer(ITIMER_VIRTUAL, &timer, NULL)) {
        return -1;
    }
    signal(SIGVTALRM, hog_expire_callback);
    return 0;
}

void feed_dog (void)
{
    watchdog_expire_counter = 0;
}
