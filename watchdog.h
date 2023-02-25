#ifndef WATCHDOG_H
#define WATCHDOG_EXPIRE 20
typedef void (*watchdog_expire_callback)(void);

int start_watchdog (watchdog_expire_callback callback);
void feed_dog(void);
#endif
