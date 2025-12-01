Tasks
- have a working wolsshd (tested with ssh-run and ssh-mapper)
- write the library to handle OOB bytes in recvfrom and pselect and
   check ssh-run and ssh-mapper still work
- handle OOB bytes in lib.rs

diff --git a/src/lib.rs b/src/lib.rs
index e3fb7e5..32cf89c 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -542,6 +542,12 @@ impl Context {
     }

     pub fn recv_raw(&mut self, stream: &mut TcpStream) -> Result<SSHMessage, SSHError> {
+        // do a select on the socket (RD + EX)
+        // if !RD and EX (there is no pending data but there is an OOB byte)
+        //    consume it
+        //    mark OOB as sendable
+        //    quit the function with a TimeOut
+        // fi
         if !self.crypto_state.dec_material.enc_key.is_empty() {
             match read_binstring(stream) {
                 Ok(mut encrypted_msg) => {
@@ -705,6 +711,7 @@ impl Context {
             if msg == "NewKeys" && self.implicit_transitions {
                 self.crypto_state.install_enc_keys();
             }
+            // TODO if OOB sendable, send it and mark OOB as not sendable
         }
         for action in actions {
             self.run_internal_action(action);

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

Normal without oob
[OOB-HANDLER] pid=150 recv: sockfd=4, len=255, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=8, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=8, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=4, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=4, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=208, flags=0x0 
[OOB-HANDLER] pid=150 recv: sockfd=4, len=8, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=8, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=4, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=72, flags=0x0 
[OOB-HANDLER] pid=150 recv: sockfd=4, len=8, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=8, flags=0x0 
[OOB-HANDLER] pid=150 recv: sockfd=4, len=3, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=2, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=2, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=8, flags=0x0 
[OOB-HANDLER] pid=150 recv: sockfd=4, len=16, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=16, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=36, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=16, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=16, flags=0x0
[OOB-HANDLER] pid=150 recv: sockfd=4, len=68, flags=0x0 

With oob
[OOB-HANDLER] pid=153 recv: sockfd=4, len=255, flags=0x0
[OOB-HANDLER] pid=153 recv: sockfd=4, len=8, flags=0x0
[OOB-HANDLER] pid=153 recv: sockfd=4, len=8, flags=0x0
[OOB-HANDLER] pid=153 recv: sockfd=4, len=208, flags=0x0
[OOB-HANDLER] pid=153 fd=4 urgent_byte=0x58 ('X')
[OOB-HANDLER] pid=153 recv: sockfd=4, len=8, flags=0x0
[OOB-HANDLER] pid=153 recv: sockfd=4, len=8, flags=0x0
[OOB-HANDLER] pid=153 recv: sockfd=4, len=4, flags=0x0
[OOB-HANDLER] pid=153 recv: sockfd=4, len=3, flags=0x0
[OOB-HANDLER] pid=153 recv: sockfd=4, len=3, flags=0x0
[OOB-HANDLER] pid=153 recv: sockfd=4, len=72, flags=0x0
[OOB-HANDLER] pid=153 fd=4 urgent_byte=0x58 ('X')
[OOB-HANDLER] pid=153 recv: sockfd=4, len=8, flags=0x0
[OOB-HANDLER] pid=153 recv: sockfd=4, len=8, flags=0x0
[OOB-HANDLER] pid=153 recv: sockfd=4, len=2, flags=0x0
[OOB-HANDLER] pid=153 recv: sockfd=4, len=8, flags=0x0
[OOB-HANDLER] pid=153 fd=4 urgent_byte=0x58 ('X')
[OOB-HANDLER] pid=153 recv: sockfd=4, len=16, flags=0x0
[OOB-HANDLER] pid=153 recv: sockfd=4, len=16, flags=0x0
[OOB-HANDLER] pid=153 recv: sockfd=4, len=36, flags=0x0
[OOB-HANDLER] pid=153 fd=4 urgent_byte=0x58 ('X')
[OOB-HANDLER] pid=153 recv: sockfd=4, len=16, flags=0x0
[OOB-HANDLER] pid=153 recv: sockfd=4, len=16, flags=0x0
[OOB-HANDLER] pid=153 recv: sockfd=4, len=68, flags=0x0
[OOB-HANDLER] pid=153 fd=4 urgent_byte=0x58 ('X')


- the preloaded library should keep a boolean to know whether the
  mapper has sent an OOB byte (which can be seen as a token : at each
  time only one of the party [library/mapper] is suppose to hold the
  token, and at the start, the token is held by the mapper);
- the mapper should also keep a boolean to know whether it is currently
  holding the token;
- [MAPPER] when the mapper is done sending a message, it should send
  an OOB byte and mark the token as in the hands of the target;
- [MAPPER] when the mapper is about to read on the socket (which is
  currently simply a read guarded by a timeout), it should try and read
  an OOB (in a non-blocking way), and if it finds one, it should put
  the timeout to zero and proceed (since OOB can be received before the
  data, we should still exhaust the remaining data to read). It should
  also note that it (the mapper) is holding the token again;
- [LIBRARY] I suppose we know which syscall to monitor, which is
  simple in the wolfsshd case: it is all the socket-related calls, and
  they all happen on file descriptor 0; however, in other cases,
  knowing which fd to monitor is a task which will be necessary (and
  sometimes complex);
- [LIBRARY] When the server calls recv/recv_from (or read) on a
  monitored socket, if the library is currently holding the token, it
  should write an OOB byte and mark the token as gone. Then, it should
  proceed with the actual read call (*);
- [LIBRARY] When the server calls recv/recv_from (or read) on a
  monitored socket, if the library is currently *not* holding the token,
  it should try to read an OOB in a non blocking way (no select needs
  to be involved I believe). If it gets an OOB, the library will note
  that it is now holding the token, and proceed with the read;
- [LIBRARY] When the server calls select/poll or their variants, and if
  the monitored socket is in the read_fds *and not in the write_fds*
  (i.e. the server is trying to only read from the socket), if the
  library is currently holding the token, it should send it as in the
  read case earlier (case (*)).