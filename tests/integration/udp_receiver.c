/*
 * udp_receiver.c — binds a UDP socket, receives up to <count> datagrams
 * within <timeout_sec> seconds, and prints the byte-length of each one
 * (one integer per line) to stdout.
 *
 * Usage: udp_receiver <port> <count> <timeout_sec>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <port> <count> <timeout_sec>\n", argv[0]);
        return 2;
    }
    int port        = atoi(argv[1]);
    int max_count   = atoi(argv[2]);
    int timeout_sec = atoi(argv[3]);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    /* Allow immediate reuse of the port */
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(fd); return 1;
    }

    char buf[65536];
    int received = 0;
    while (received < max_count) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
        int sel = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) { perror("select"); break; }
        if (sel == 0) break; /* timeout */

        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) { perror("recv"); break; }
        printf("%zd\n", n);
        fflush(stdout);
        received++;
    }

    close(fd);
    return 0;
}
