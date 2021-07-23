#ifndef DEDSCAN_H
#define DEDSCAN_H

#include <netdb.h> /* gethostbyname() */
#include <stdio.h>
#include <stdlib.h> /* free(), malloc() */
#include <sys/socket.h> /* AF_INET, ... */
#include <arpa/inet.h> /* inet_ntop() */

/* resolves the ip address of the provided name */
int resolve_name(char *, char *);

/* just the "main" function that'll probs branch off */
int dedscan_main(char *, int, int);

#endif
