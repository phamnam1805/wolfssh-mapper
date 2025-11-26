#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/select.h>

// Function pointer for original recv
ssize_t (*original_recv)(int sockfd, void *buf, size_t len, int flags);

__attribute__((constructor)) void register_original_functions() {
    // Load the original recv function
    original_recv = (ssize_t (*)(int, void *, size_t, int))
                    dlsym(RTLD_NEXT, "recv");;
    if (original_recv == NULL) {
        fprintf(stderr, "Error loading original recv: %s\n", dlerror());
    }
}

// static void handle_oob_byte(int fd, unsigned char b) {
//     fprintf(stderr, "[OOB-HANDLER] pid=%d fd=%d urgent_byte=0x%02x ('%c')\n",
//             getpid(), fd, b, (b >= 32 && b < 127) ? b : '?');
//     fflush(stderr);
// }

// Hook function for recv
ssize_t recv(int sockfd, void *buf, size_t len, int flags) {

    while (1) {
        fd_set readfds, exceptfds;
        struct timeval tv = {0, 0};

        FD_ZERO(&readfds);
        FD_ZERO(&exceptfds);
        FD_SET(sockfd, &readfds);
        FD_SET(sockfd, &exceptfds);

        int sel = select(sockfd + 1, &readfds, NULL, &exceptfds, &tv);
        if (sel < 0) { // Error
            return original_recv(sockfd, buf, len, flags);
        }  
        // if (sel == 0) break; // No data available

        if (FD_ISSET(sockfd, &exceptfds)) {
            unsigned char b;
            if (original_recv(sockfd, &b, 1, MSG_OOB | MSG_DONTWAIT) == 1) {
                fprintf(stderr, "[OOB-HANDLER] pid=%d recv: sockfd=%d urgent_byte=0x%02x ('%c')\n",
                        getpid(), sockfd, b, (b >= 32 && b < 127) ? b : '?');
                fflush(stderr);
            }
        }

        if (FD_ISSET(sockfd, &readfds)) {
            fprintf(stderr, "[OOB-HANDLER] pid=%d recv: sockfd=%d, len=%zu, flags=0x%x\n",
                    getpid(), sockfd, len, flags);
            fflush(stderr);
            return original_recv(sockfd, buf, len, flags);
        }
    }

    
}