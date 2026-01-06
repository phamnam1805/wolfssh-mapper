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
#include <poll.h>
#include <stdbool.h>
#include <fcntl.h>

// Token state: true means library holds token, false means mapper holds token
// At start, mapper holds token (has_token = false)
static bool has_token = false;

// Monitored file descriptor - will be set by accept() hook
// Initialize to 0 for wolfsshd case (stdin), but accept() will update it
static int MONITORED_FD = 0;

// Function pointers for original syscalls
ssize_t (*original_recv)(int sockfd, void *buf, size_t len, int flags);
ssize_t (*original_recvfrom)(int sockfd, void *buf, size_t len, int flags,
                             struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t (*original_read)(int fd, void *buf, size_t count);
ssize_t (*original_send)(int sockfd, const void *buf, size_t len, int flags);
int (*original_select)(int nfds, fd_set *readfds, fd_set *writefds,
                       fd_set *exceptfds, struct timeval *timeout);
int (*original_pselect)(int nfds, fd_set *readfds, fd_set *writefds,
                        fd_set *exceptfds, const struct timespec *timeout,
                        const sigset_t *sigmask);
int (*original_poll)(struct pollfd *fds, nfds_t nfds, int timeout);
int (*original_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

__attribute__((constructor)) void register_original_functions() {
    original_recv = (ssize_t (*)(int, void *, size_t, int))
                    dlsym(RTLD_NEXT, "recv");
    original_recvfrom = (ssize_t (*)(int, void *, size_t, int, struct sockaddr *, socklen_t *))
                        dlsym(RTLD_NEXT, "recvfrom");
    original_read = (ssize_t (*)(int, void *, size_t))
                    dlsym(RTLD_NEXT, "read");
    original_send = (ssize_t (*)(int, const void *, size_t, int))
                    dlsym(RTLD_NEXT, "send");
    original_select = (int (*)(int, fd_set *, fd_set *, fd_set *, struct timeval *))
                      dlsym(RTLD_NEXT, "select");
    original_pselect = (int (*)(int, fd_set *, fd_set *, fd_set *, const struct timespec *, const sigset_t *))
                       dlsym(RTLD_NEXT, "pselect");
    original_poll = (int (*)(struct pollfd *, nfds_t, int))
                    dlsym(RTLD_NEXT, "poll");
    original_accept = (int (*)(int, struct sockaddr *, socklen_t *))
                      dlsym(RTLD_NEXT, "accept");

    if (!original_recv || !original_recvfrom || !original_read ||
        !original_send || !original_select || !original_pselect ||
        !original_poll || !original_accept) {
        fprintf(stderr, "[OOB-HANDLER] Error loading original functions\n");
    }
    fflush(stderr);
}

// Hook function for accept
// Capture the client socket fd when a connection is accepted
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    int client_fd = original_accept(sockfd, addr, addrlen);

    if (client_fd >= 0) {
        // Update monitored fd to the newly accepted client socket
        MONITORED_FD = client_fd;

        char client_ip[INET_ADDRSTRLEN] = "unknown";
        int client_port = 0;

        if (addr && addr->sa_family == AF_INET) {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
            inet_ntop(AF_INET, &addr_in->sin_addr, client_ip, sizeof(client_ip));
            client_port = ntohs(addr_in->sin_port);
        }

        fprintf(stderr, "[OOB-HANDLER] pid=%d accept: new client_fd=%d from %s:%d, MONITORED_FD updated\n",
                getpid(), client_fd, client_ip, client_port);
        fflush(stderr);

        has_token = false;
    }

    return client_fd;
}

// Helper function to send OOB byte and release token
static void send_oob_token(int fd) {
    unsigned char oob_byte = 'X';  
    ssize_t n = original_send(fd, &oob_byte, 1, MSG_OOB);
    if (n == 1) {
        fprintf(stderr, "[OOB-HANDLER] pid=%d sent OOB token on fd=%d, token released\n",
                getpid(), fd);
        has_token = false;
    } else {
        fprintf(stderr, "[OOB-HANDLER] pid=%d failed to send OOB token on fd=%d: %s\n",
                getpid(), fd, strerror(errno));
    }
    fflush(stderr);
}

// Helper function to try receiving OOB byte (non-blocking)
static bool try_recv_oob_token(int fd) {
    unsigned char b;
    ssize_t n = original_recv(fd, &b, 1, MSG_OOB | MSG_DONTWAIT);
    if (n == 1) {
        fprintf(stderr, "[OOB-HANDLER] pid=%d received OOB token on fd=%d, byte=0x%02x\n",
                getpid(), fd, b);
        has_token = true;
        fflush(stderr);
        return true;
    }
    // fprintf(stderr, "[OOB-HANDLER] pid=%d no OOB token on fd=%d\n",
    //             getpid(), fd);
    
    return false;
}

// Hook function for recv
// [LIBRARY] When recv is called on monitored socket:
// - If library has token: send OOB and mark token as gone, then proceed with read
// - If library doesn't have token: try to read OOB non-blocking, if found mark token as received, then proceed
ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    // Only intercept on monitored fd
    if (sockfd != MONITORED_FD) {
        return original_recv(sockfd, buf, len, flags);
    }

    fprintf(stderr, "[OOB-HANDLER] pid=%d recv: sockfd=%d, len=%zu, flags=0x%x, has_token=%d\n",
            getpid(), sockfd, len, flags, has_token);
    fflush(stderr);

    if(!has_token){
        try_recv_oob_token(sockfd);
    }
    
    // Proceed with actual read
    return original_recv(sockfd, buf, len, flags | MSG_DONTWAIT);
}


// Hook function for select
// [LIBRARY] When select is called with monitored socket in read_fds AND NOT in write_fds,
// and library has token, send it before calling select
int select(int nfds, fd_set *readfds, fd_set *writefds,
           fd_set *exceptfds, struct timeval *timeout) {
    bool should_send_token = false;
    // fd_set new_exceptfds;

    // FD_ZERO(&new_exceptfds);

    // Check if monitored fd is in readfds and not in writefds
    if (readfds && FD_ISSET(MONITORED_FD, readfds)) {
        if (!writefds || !FD_ISSET(MONITORED_FD, writefds)) {
            // Server is trying to only read from socket
            // fprintf(stderr, "[OOB-HANDLER] pid=%d select: monitored_fd=%d in read_fds only\n", getpid(), MONITORED_FD);
            if (has_token) {
                should_send_token = true;
            } 
            // else {
            //     FD_SET(MONITORED_FD, &new_exceptfds);
            // }
        }
    }

    if (should_send_token) {
        fprintf(stderr, "[OOB-HANDLER] pid=%d select: monitored_fd=%d in read_fds only, sending token\n",
                getpid(), MONITORED_FD);
        fflush(stderr);
        send_oob_token(MONITORED_FD);
    }

    // Proceed with actual select
    // int ret = original_select(nfds, readfds, writefds, &new_exceptfds, timeout);
    // if (ret > 0 && FD_ISSET(MONITORED_FD, &new_exceptfds) && !FD_ISSET(MONITORED_FD, readfds) ) {
    //     fprintf(stderr, "[OOB-HANDLER] in select new exceptfds\n",
    //             getpid(), MONITORED_FD);
    //     try_recv_oob_token(MONITORED_FD);
    //     send_oob_token(MONITORED_FD);
    //     return original_select(nfds, readfds, writefds, exceptfds, timeout);
    // }

    return original_select(nfds, readfds, writefds, exceptfds, timeout);
}

// Hook function for send
// Just logging
ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    // Only log for monitored fd
    if (sockfd == MONITORED_FD && !(flags & MSG_OOB)) {
        fprintf(stderr, "[OOB-HANDLER] pid=%d send: sockfd=%d, len=%zu, flags=0x%x\n",
                getpid(), sockfd, len, flags);
        fflush(stderr);
    }

    return original_send(sockfd, buf, len, flags);
}
