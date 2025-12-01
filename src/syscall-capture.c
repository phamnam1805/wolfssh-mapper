#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <sys/select.h>
#include <unistd.h>

// Function pointer for original select
int (*original_select)(int nfds, fd_set *readfds, fd_set *writefds,
                       fd_set *exceptfds, struct timeval *timeout);

__attribute__((constructor)) void init() {
    original_select = (int (*)(int, fd_set *, fd_set *, fd_set *, struct timeval *))
                      dlsym(RTLD_NEXT, "select");
    if (!original_select) {
        fprintf(stderr, "[SYSCALL-CAPTURE] Error loading original select\n");
    }
    fprintf(stderr, "[SYSCALL-CAPTURE] Initialized\n");
}

// Hook select()
int select(int nfds, fd_set *readfds, fd_set *writefds,
           fd_set *exceptfds, struct timeval *timeout) {
    fprintf(stderr, "[SYSCALL-CAPTURE] select() called: nfds=%d\n", nfds);
    return original_select(nfds, readfds, writefds, exceptfds, timeout);
}
