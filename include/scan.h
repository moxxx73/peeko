#ifndef RECV_H
#define RECV_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h> /* malloc(), free() */
#include <unistd.h> /* close(), write() */
#include <string.h> /* strerror() */
#include <sys/select.h>

#include "net.h"
#include "memory.h"
#include "utils.h"
#include "stack.h"

#define HANDSHAKE_SCAN 0x01
#define SYN_SCAN 0x02

int scan_mgr(scan_data *data, int method);

int connect_scan(scan_data *data);

void read_write_cycle(int read_fd, int write_fd, scan_data *data, struct tpacket_req *treq);

int raw_scan(scan_data *data, int method);

void signal_handler(int);

#endif
