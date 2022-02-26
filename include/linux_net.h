#ifndef LINUX_NET_HDR
#define LINUX_NET_HDR

#include <unistd.h>
#include <net/if.h> /* struct ifreq, ... */
#include <sys/time.h>
#include <sys/socket.h> /* AF_INET, socket() */
#include <netinet/in.h> /* IPPROTO_IP, ... */
#include <sys/fcntl.h>
#include <linux/if_packet.h>
#include <sys/mman.h>

#include "packets.h"
#include "results.h"
#include "memory.h"
#include "net_filter.h"

typedef struct read_socket_st{
    struct tpacket_req *tpack_r;
    int rx_ring_size;
    char *rx_ring;
    int sock_fd;
}rsock_obj;


rsock_obj *read_socket(char *, int, int);

int write_socket(int, int);

#endif