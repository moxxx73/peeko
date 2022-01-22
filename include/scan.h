#ifndef RECV_H
#define RECV_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h> /* malloc(), free() */
#include <unistd.h> /* close(), write() */
#include <string.h> /* strerror() */
#include <pthread.h>

#include "net.h"
#include "memory.h"
#include "utils.h"
#include "stack.h"

#define HANDSHAKE_SCAN 0x01
#define SYN_SCAN 0x02

int scan_mgr(scan_data *, int);

int connect_scan(scan_data *);

int spawn_threads(scan_data *);

int raw_scan(scan_data *, int);

void signal_handler(int);

#endif
