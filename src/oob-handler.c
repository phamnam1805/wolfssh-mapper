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

// Enable/disable logging - set to true to enable logs
static bool ENABLE_LOGGING = true;

// Logging macro - only logs if ENABLE_LOGGING is true
#define LOG(...)                          \
    do                                    \
    {                                     \
        if (ENABLE_LOGGING)               \
        {                                 \
            fprintf(stderr, __VA_ARGS__); \
            fflush(stderr);               \
        }                                 \
    } while (0)

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

__attribute__((constructor)) void register_original_functions()
{
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
        !original_poll || !original_accept)
    {
        LOG("[OOB-HANDLER] Error loading original functions\n");
    }
}

// Hook function for accept
// Capture the client socket fd when a connection is accepted
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    int client_fd = original_accept(sockfd, addr, addrlen);

    if (client_fd >= 0)
    {
        // Update monitored fd to the newly accepted client socket
        MONITORED_FD = client_fd;

        char client_ip[INET_ADDRSTRLEN] = "unknown";
        int client_port = 0;

        if (addr && addr->sa_family == AF_INET)
        {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
            inet_ntop(AF_INET, &addr_in->sin_addr, client_ip, sizeof(client_ip));
            client_port = ntohs(addr_in->sin_port);
        }

        LOG("[OOB-HANDLER] pid=%d accept: new client_fd=%d from %s:%d, MONITORED_FD updated\n",
            getpid(), client_fd, client_ip, client_port);

        // Check SO_OOBINLINE status
        // int oobinline = 0;
        // socklen_t optlen = sizeof(oobinline);
        // if (getsockopt(client_fd, SOL_SOCKET, SO_OOBINLINE, &oobinline, &optlen) == 0)
        // {
        //     LOG("[OOB-HANDLER] pid=%d accept: SO_OOBINLINE=%d\n", getpid(), oobinline);
        // }

        has_token = false;
    }

    return client_fd;
}

// Helper function to send OOB byte and release token
static void send_oob_token(int fd)
{
    unsigned char oob_byte = 'X';
    ssize_t n = original_send(fd, &oob_byte, 1, MSG_OOB);
    if (n == 1)
    {
        LOG("[OOB-HANDLER] pid=%d sent OOB token on fd=%d, token released\n",
            getpid(), fd);
        has_token = false;
    }
    else
    {
        LOG("[OOB-HANDLER] pid=%d failed to send OOB token on fd=%d: %s\n",
            getpid(), fd, strerror(errno));
    }
}

// Helper function to try receiving OOB byte (non-blocking)
static bool try_recv_oob_token(int fd, int recv_func)
{
    unsigned char b;
    ssize_t n = original_recv(fd, &b, 1, MSG_OOB | MSG_DONTWAIT);
    if (n == 1)
    {
        if (recv_func)
        {
            LOG("[OOB-HANDLER] pid=%d received OOB token on fd=%d via recv(), byte=0x%02x\n",
                getpid(), fd, b);
        }
        else
        {
            LOG("[OOB-HANDLER] pid=%d received OOB token on fd=%d via select(), byte=0x%02x\n",
                getpid(), fd, b);
        }
        has_token = true;
        return true;
    }
    else if (n < 0)
    {
        // Log error for debugging
        // EINVAL on Linux means no OOB data available (normal case)
        // EAGAIN/EWOULDBLOCK means would block (also normal with MSG_DONTWAIT)
        int err = errno;
        if (err != EAGAIN && err != EWOULDBLOCK && err != EINVAL)
        {
            LOG("[OOB-HANDLER] pid=%d try_recv_oob_token failed: errno=%d (%s)\n",
                getpid(), err, strerror(err));
        }
    }
    return false;
}

// Hook function for recv
// [LIBRARY] When recv is called on monitored socket:
// Just proceed with actual read (OOB handling moved to select)
ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    // Only intercept on monitored fd
    if (sockfd != MONITORED_FD)
    {
        return original_recv(sockfd, buf, len, flags);
    }

    LOG("[OOB-HANDLER] pid=%d recv: sockfd=%d, len=%zu, flags=0x%x, has_token=%d\n",
        getpid(), sockfd, len, flags, has_token);

    if (!has_token)
    {
        try_recv_oob_token(MONITORED_FD, 1);
    }

    return original_recv(sockfd, buf, len, flags);
}

// Hook function for select
// [LIBRARY] When select is called with monitored socket in read_fds AND NOT in write_fds:
// - If has_token: send token and call original select with timeout=0
// - If !has_token: monitor exceptfds for OOB token with original timeout
int select(int nfds, fd_set *readfds, fd_set *writefds,
           fd_set *exceptfds, struct timeval *timeout)
{

    // Ultra-fast path: If MONITORED_FD >= nfds, it cannot be in any fd_set
    // This is just a single integer comparison, much faster than FD_ISSET
    if (MONITORED_FD >= nfds)
    {
        return original_select(nfds, readfds, writefds, exceptfds, timeout);
    }

    // Fast path: Check if MONITORED_FD is in readfds or writefds
    // Cache the results to avoid redundant FD_ISSET calls
    bool monitoring_read = readfds && FD_ISSET(MONITORED_FD, readfds);
    bool monitoring_write = writefds && FD_ISSET(MONITORED_FD, writefds);
    if (!monitoring_read && !monitoring_write)
    {
        // Fast path: MONITORED_FD not being monitored, pass through directly
        return original_select(nfds, readfds, writefds, exceptfds, timeout);
    }

    // MONITORED_FD is being monitored - handle OOB logic
    fd_set new_exceptfds;
    if (exceptfds)
    {
        new_exceptfds = *exceptfds;
    }
    else
    {
        FD_ZERO(&new_exceptfds);
    }

    // Decide what to do based on token state
    bool should_release_token = false;
    struct timeval zero_timeout = {0, 0};
    struct timeval *actual_timeout = timeout;

    if (!has_token)
    {
        // Don't have token - wait for OOB from client with normal timeout
        FD_SET(MONITORED_FD, &new_exceptfds);
    }
    else
    {
        // Have token - use zero timeout to avoid blocking
        actual_timeout = &zero_timeout;

        // Check if we're done sending (monitoring read = want to recv)
        if (monitoring_read && !monitoring_write)
        {
            should_release_token = true;
            LOG("[OOB-HANDLER] pid=%d select: has_token, will release after select\n", getpid());
        }
    }

    int ret = original_select(nfds, readfds, writefds, &new_exceptfds, actual_timeout);

    if (!has_token && ret > 0)
    {
        if (FD_ISSET(MONITORED_FD, &new_exceptfds))
        {
            if (try_recv_oob_token(MONITORED_FD, 0)){
                ret -= 1; // Adjust return value as we handled the OOB
            }
        }
    }

    // Release token if we decided to (after select, after potential recv)
    if (should_release_token)
    {
        LOG("[OOB-HANDLER] pid=%d select: releasing token after reading\n", getpid());
        send_oob_token(MONITORED_FD);
    }

    return ret;
}

// Hook function for send
// Just logging - token release happens in select()
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    // Only log for monitored fd
    if (sockfd == MONITORED_FD && !(flags & MSG_OOB))
    {
        LOG("[OOB-HANDLER] pid=%d send: sockfd=%d, len=%zu, flags=0x%x, has_token=%d\n",
            getpid(), sockfd, len, flags, has_token);
    }

    return original_send(sockfd, buf, len, flags);
}
