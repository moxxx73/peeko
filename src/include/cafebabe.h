#ifndef CAFEBABE_H
#define CAFEBABE_H

#include <netdb.h> /* gethostbyname() */
#include <stdio.h>
#include <stdlib.h> /* free(), malloc() */
#include <sys/socket.h> /* AF_INET, ... */
#include <arpa/inet.h> /* inet_ntop() */

#include "scan.h"

typedef struct function_args{
    char *addr;
    char *ifn;
    int porta;
    int portb;
    int portc;
    int verbose;
} cafebabe;

/* resolves the ip address of the provided name */
int resolve_name(char *, char *);

/* just the "main" function that'll probs branch off */
int cafebabe_main(cafebabe *, char*, int);

#endif
