#ifndef NET_H
#define NET_H

#include <netinet/tcp.h> 
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <stdlib.h>
#include <string.h>

#include "results.h"

#define IP_SIZE sizeof(struct ip)
#define TCP_SIZE sizeof(struct tcphdr)
#define ETH_SIZE sizeof(struct ether_header)

#define ETHSIZ ETH_SIZE
#define IPSIZ IP_SIZE
#define TCPSIZ TCP_SIZE

#define SYN_METH 1

/* the tcp checksum uses a pseudo header as well the     */
/* tcp header to calculate the tcp/udp checksum          */
struct tcpPseudo{
	unsigned int src; /* Source IPv4 address */
	unsigned int dst; /* Destination IPv4 address */
	unsigned short length; /* length of the TCP header */
	unsigned char null; /* NULL byte */
	unsigned char protocol; /* set to IPPROTO_TCP */
	struct tcphdr tcp; /* TCP header */
};

/* TCP checksum algorithm*/
unsigned short checksum(unsigned short *, int);

/* assigns IPv4 header fields */
void ipv4Hdr(char *, unsigned short, unsigned short, unsigned short, unsigned char, unsigned char, unsigned short, unsigned int, unsigned int);

/* assigns TCP header fields */
void tcpHdr(char *, unsigned short, unsigned short, unsigned int, unsigned int, unsigned char, unsigned char, unsigned short, unsigned short, unsigned short);

#endif
