#ifndef RECV_H
#define RECV_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>

#include "net.h"
#include "memory.h"
#include "utils.h"
#include "stack.h"

#define HANDSHAKE_SCAN 0x01
#define SYN_SCAN 0x02

/* decides whether to call connect_scan() or raw_scan() */
/* based on the provided method                         */
int scan_mgr(scan_data *data, int method);

/* very simple scan uitilising the connect() syscall */
int connect_scan(scan_data *data);

/* transmitting and receiving of raw packets */
void read_write_cycle(int read_fd, int write_fd, scan_data *data, struct tpacket_req *treq, int tun);

/* sets packet flags based on provided method and creates */
/* transmitting and receiving sockets                     */
int raw_scan(scan_data *data, int method, int tun);

#endif
