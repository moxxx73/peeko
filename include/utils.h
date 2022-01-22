#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h> /* gethostbyname() */
#include <unistd.h> /* close() */
#include <sys/socket.h> /* AF_INET, ... */
#include <arpa/inet.h> /* inet_ntop() */
#include <net/if.h> /* struct ifreq, IFNAMSIZ*/
#include <sys/ioctl.h> /* ioctl() */
#include <ifaddrs.h>

typedef struct parse_ret{
    short *list;
    int llen;
} parse_r;

#define PRT_LST_SIZ sizeof(parse_r)
#define PRT_LST_TAG "prt_lst\0"

#define ERR_MSG_LEN 256

#define REDC "\x1b[31m"
#define GREENC "\x1b[32m"
#define BLUEC "\x1B[34m"
#define RESET "\x1b[0m"

/* resolves the ip address of the provided name */
int resolve_name(char *, char *);

/* retrievs the ip address associated with an interface */
int getifaddr(char *, char *);

int chr_count(char *, char, int);

int chr_index(char *, char, int);

short *parse_list(char *, int, int);

parse_r *parse_range(char *, int);

parse_r *parse_port_args(char *);

void err_msg(const char *);

void hex_dump(unsigned char *, int);

#endif