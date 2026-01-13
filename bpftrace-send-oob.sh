sudo bpftrace -e '
BEGIN {
    printf("=== Tracing SUCCESSFUL OOB send ===\n\n");
}

// Track when send with MSG_OOB is called
tracepoint:syscalls:sys_enter_sendto /args->flags & 0x1/ {
    @send_oob[tid] = 1;
    @send_fd[tid] = args->fd;
    @send_len[tid] = args->len;
}

// Only print when it SUCCEEDS (returns expected length)
tracepoint:syscalls:sys_exit_sendto /@send_oob[tid] && args->ret > 0/ {
    printf("%s [PID %d %s] ✓ Sent %d byte(s) OOB on fd=%d\n",
           strftime("%H:%M:%S.%f", nsecs),
           pid, comm, args->ret, @send_fd[tid]);
    delete(@send_oob[tid]);
    delete(@send_fd[tid]);
    delete(@send_len[tid]);
}

// Clean up on failure
tracepoint:syscalls:sys_exit_sendto /@send_oob[tid]/ {
    delete(@send_oob[tid]);
    delete(@send_fd[tid]);
    delete(@send_len[tid]);
}

END {
    clear(@send_oob);
    clear(@send_fd);
    clear(@send_len);
}
'