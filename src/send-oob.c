#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <host> <port>\n", argv[0]);
        fprintf(stderr, "example: %s 127.0.0.1 22\n", argv[0]);
        return 1;
    }

    const char *host = argv[1];
    int port = atoi(argv[2]);

    // Create TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return 1;
    }

    // Setup server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sockfd);
        return 1;
    }

    // Connect to server
    printf("Connecting to %s:%d...\n", host, port);
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("connect");
        close(sockfd);
        return 1;
    }
    printf("Connected! Socket fd=%d\n", sockfd);

    // Send OOB byte
    char oob_byte = 'X';
    printf("Sending OOB byte: 0x%02x ('%c')\n", oob_byte, oob_byte);
    ssize_t n = send(sockfd, &oob_byte, 1, MSG_OOB);
    if (n == -1) {
        perror("send(MSG_OOB)");
        close(sockfd);
        return 1;
    }
    printf("OOB byte sent successfully!\n");

    sleep(1);

    close(sockfd);
    printf("Connection closed\n");
    return 0;
}