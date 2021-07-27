#include <unistd.h> /* close() */
#include <stdlib.h> /* malloc(), free() */
#include <stdio.h>
#include <sys/socket.h> /* socket(), AF_INET, ...*/
#include <netinet/in.h> /* IPPROTO_IP, ... */

#include "bpf.h"
#include "framez.h"

/* Just probes a single port */
int single_port(char *, unsigned int, unsigned int, short, short, int);
