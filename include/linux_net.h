#ifndef LINUX_NET_HDR
#define LINUX_NET_HDR

#include <unistd.h>
#include <net/if.h> /* struct ifreq, ... */
#include <sys/time.h>
#include <sys/socket.h> /* AF_INET, socket() */
#include <netinet/in.h> /* IPPROTO_IP, ... */

#include "packets.h"
#include "results.h"
#include "net_filter.h"

#define SOCK_READ 0
#define SOCK_WRITE 1

int read_socket(char *, int, int);

int write_socket(int, int);

#endif