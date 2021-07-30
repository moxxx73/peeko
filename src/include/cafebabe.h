#ifndef CAFEBABE_H
#define CAFEBABE_H

#include <netdb.h> /* gethostbyname() */
#include <stdio.h>
#include <unistd.h> /* close() */
#include <net/if.h> /* struct ifreq, IFNAMSIZ*/
#include <sys/ioctl.h> /* ioctl() */
#include <stdlib.h> /* free(), malloc() */
#include <sys/socket.h> /* AF_INET, ... */
#include <arpa/inet.h> /* inet_ntop() */
#include <string.h> /* memcpy() */

#include "scan.h"

typedef struct function_args{
    char *addr;
    char *ifn;
    short porta;
    short portb;
    short portc;
} cafebabe;

/* resolves the ip address of the provided name */
int resolve_name(char *, char *);

/* retrievs the ip address associated with an interface */
int getifaddr(char *, char *);

/* just the "main" function that'll probs branch off */
int cafebabe_main(cafebabe *, char*, int);

#endif
