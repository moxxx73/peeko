#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>

/* data struct used when parsing -p flag */
/* and returning the provided ports     */
typedef struct parse_ret{
    short *list;
    int llen;
} parse_r;
#define PRT_LST_SIZ sizeof(parse_r)

#define ERR_MSG_LEN 256

#define REDC "\x1b[31m"
#define GREENC "\x1b[32m"
#define BLUEC "\x1B[34m"
#define RESET "\x1b[0m"

/* resolves a IPv4 address from a provided hostname */
int resolve_name(char *, char *);

/* automatically fetch an interfaces IPv4 address   */
/* for the source address field in raw IPv4 headers */
int getifaddr(char *, char *);

/* returns the amount of times a character occurs in a string */
int chr_count(char *, char, int);

/* returns the first index of a character in a string */
int chr_index(char *, char, int);

/* parse_list, parse_range and parse_file all take string based   */
/* arguments containing the intended ports to scan, converts them */
/* from ASCII to integer (shrunk to a word/short) and stores them */
/* in a list                                                      */
short *parse_list(char *, int, int);

parse_r *parse_range(char *, int);

/* parses CLI arguments for the -p flag */
/* and return the ports in an array     */
parse_r *parse_port_args(char *);

parse_r *parse_file(const char *fn);

/* whenever an occurs, output a message and the reason why it occurred */
void err_msg(const char *);

/* takes a buffer and outputs both the hex and ascii representation */
/* of each byte                                                     */
void hex_dump(unsigned char *, int);

#endif
