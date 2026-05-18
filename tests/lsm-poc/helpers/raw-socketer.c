/*
 * raw-socketer — open a raw / packet socket as the calling uid.
 *
 * Threat scenario: a compromised vhost user drops a scanner /
 * sniffer / spoofing toolkit and calls socket(AF_INET, SOCK_RAW, …)
 * or socket(AF_PACKET, SOCK_RAW, …) to gain L3 / L2 access. The
 * CFML-NET-002 LSM hook (socket_create) fires on every such
 * attempt by a watched uid.
 *
 * On a typical host the calling watched uid does NOT have
 * CAP_NET_RAW, so the socket(2) call returns -EPERM. The
 * socket_create LSM hook is invoked BEFORE the capability check,
 * so NET-002 emits regardless of whether the socket actually
 * opens. The PoC therefore succeeds without granting any
 * capabilities to the test user.
 *
 * We try three shapes in sequence to exercise every CFM_NET_OP_*
 * branch in the BPF program:
 *
 *   1. socket(AF_INET,   SOCK_RAW, IPPROTO_ICMP)
 *   2. socket(AF_INET6,  SOCK_RAW, IPPROTO_ICMPV6)
 *   3. socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
 *
 * Each opens a distinct event with op=raw_inet / raw_inet6 /
 * packet so the harness can verify any one fires.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void try_socket(int family, int type, int protocol, const char *label)
{
    int fd = socket(family, type, protocol);
    if (fd < 0) {
        fprintf(stderr, "socket(%s) returned -1 (errno=%d %s)\n",
                label, errno, strerror(errno));
    } else {
        fprintf(stderr, "socket(%s) returned fd=%d\n", label, fd);
        close(fd);
    }
}

int main(void)
{
    try_socket(AF_INET,   SOCK_RAW, IPPROTO_ICMP,        "AF_INET/SOCK_RAW");
    try_socket(AF_INET6,  SOCK_RAW, IPPROTO_ICMPV6,      "AF_INET6/SOCK_RAW");
    try_socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL),    "AF_PACKET/SOCK_RAW");
    return 0;
}
