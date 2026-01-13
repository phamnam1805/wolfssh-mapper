sudo bpftrace -e '
BEGIN {
    printf("=== Tracing SUCCESSFUL OOB recv ===\n\n");
}

// Track when recv with MSG_OOB is called
tracepoint:syscalls:sys_enter_recvfrom /args->flags & 0x1/ {
    @recv_oob[tid] = 1;
    @recv_fd[tid] = args->fd;
}

// Only print when it SUCCEEDS (returns 1 byte)
tracepoint:syscalls:sys_exit_recvfrom /@recv_oob[tid] && args->ret == 1/ {
    printf("%s [PID %d %s] Successfully received OOB byte on fd=%d\n",
           strftime("%H:%M:%S.%f", nsecs),
           pid, comm, @recv_fd[tid]);
    delete(@recv_oob[tid]);
    delete(@recv_fd[tid]);
}

// Clean up on failure
tracepoint:syscalls:sys_exit_recvfrom /@recv_oob[tid] && args->ret != 1/ {
    delete(@recv_oob[tid]);
    delete(@recv_fd[tid]);
}

END {
    clear(@recv_oob);
    clear(@recv_fd);
}
'