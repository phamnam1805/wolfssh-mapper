FROM debian:trixie

# Install dependencies and debugging tools
RUN apt update && \
    apt install -y --no-install-recommends \
        git \
        perl \
        gcc \
        make \
        libc6-dev \
        dh-autoreconf \
        ca-certificates \
        python3 \
        openssl \
        # Debugging and tracing tools
        strace \
        gdb \
        # Utilities
        vim \
        less \
        rlwrap \
        net-tools \
        iproute2 \
        procps \
    && apt clean

# Build wolfSSL with specific version and debug symbols
RUN git clone --depth 1 --branch v5.8.0-stable https://github.com/wolfSSL/wolfssl.git
RUN cd wolfssl && \
    ./autogen.sh && \
    ./configure \
        --enable-ssh \
        --enable-keygen \
        --enable-opensslall \
        CFLAGS="-g -O0 -fno-omit-frame-pointer" \
        LDFLAGS="-g" && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Build wolfSSH with specific version and debug symbols
# You can switch DEBUG_OPTIONS to "--enable-debug" if you want more messages
ARG DEBUG_OPTIONS=
# You can also add a "RUN sed -i 's/^\(CFLAGS = .*\)/\1 -DSHOW_SECRETS/' Makefile && \" line before make if needed
RUN git clone --depth 1 --branch v1.4.21-stable https://github.com/wolfSSL/wolfssh.git
RUN cd wolfssh && \
    ./autogen.sh && \
    ./configure \
        --enable-all \
        ${DEBUG_OPTIONS} \
        CFLAGS="-g -O0 -fno-omit-frame-pointer" \
        LDFLAGS="-g" && \
    sed -i 's/^\(CFLAGS = *\)-Werror\(.*\)/\1\2/' Makefile && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Create SSH configuration and keys
RUN mkdir -p /etc/ssh && \
    openssl genrsa > /etc/ssh/sshd_rsa
COPY sshd_config /etc/ssh/sshd_config

# Create required users
RUN useradd -m -U sshd
RUN useradd -m -U user 
RUN printf "very-secret\nvery-secret\n" | passwd user && \
    umask 077 && \
    mkdir -p /home/user/.ssh

# Create project directory
RUN mkdir -p /project
WORKDIR /project

# Expose SSH port
EXPOSE 22

# Default shell when entering container
CMD ["/bin/bash"]
