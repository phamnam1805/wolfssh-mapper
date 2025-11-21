cargo run --bin ssh-mapper -- -s server -e 127.0.0.1:2222 -t 0.1 -v KexInit+Disconnect bdist --bdist 1

cargo run --bin ssh-run -- -s server -e 127.0.0.1:2222 -t 0.1 KexInit KexECDHInit NewKeys ServiceRequestUserAuth AuthRequestPassword



Le Tue, Nov 18, 2025 at 02:51:09PM +0100, Olivier Levillain a écrit :
Bonjour,

Here are some ideas from the discussion.

# Dockerfile

```Dockerfile
FROM debian:trixie

RUN apt update && \
     apt install -y --no-install-recommends git perl gcc make libc6-dev dh-autoreconf ca-certificates python3 vim less rlwrap strace && \
     apt clean

RUN git clone --depth 1 --branch v5.8.0-stable https://github.com/wolfSSL/wolfssl.git
RUN cd wolfssl && \
     ./autogen.sh && \
     ./configure --enable-ssh --enable-keygen --enable-opensslall && \
     make -j && \
     make install && \
     ldconfig

RUN git clone --depth 1 --branch v1.4.21-stable https://github.com/wolfSSL/wolfssh.git

# You can switch DEBUG_OPTIONS to "--enable-debug" if you want more messages
ARG DEBUG_OPTIONS=
# You can also add a "RUN sed -i 's/^\(CFLAGS = .*\)/\1 -DSHOW_SECRETS/' Makefile && \" line before make if needed
RUN cd wolfssh && \
     ./autogen.sh && \
     ./configure --enable-all ${DEBUG_OPTIONS} && \
     sed -i 's/^\(CFLAGS = *\)-Werror\(.*\)/\1\2/' Makefile && \
     make -j && \
     make install && \
     ldconfig

RUN mkdir /etc/ssh && touch /etc/ssh/sshd_config && openssl genrsa > /etc/ssh/sshd_rsa
RUN useradd -m -U sshd
RUN useradd -m -U user
RUN printf "very-secret\nvery-secret\n" | passwd user
RUN umask 077 && mkdir /home/user/.ssh
# COPY authorized_keys /home/user/.ssh/authorized_keys
# RUN chown user:user /home/user/.ssh/authorized_keys && chmod 400 /home/user/.ssh/authorized_keys

# TODO: Compile the syscall capture library
# TODO: Inject the compiled library
```


# Run it

```
$ docker build -t wolfssh .
$ docker run -ti --rm -p 2222:22 wolfssh
```


# Rubbish history

```
     1  wolfsshd -d -h /etc/ssh/sshd_rsa -D
     2  aptitude install strace vim less
     3  apt install strace vim less
     4  strace -f -o /tmp/wolfsshd.log wolfsshd -d -h /etc/ssh/sshd_rsa -D
```