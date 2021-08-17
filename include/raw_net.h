#ifndef NET_H
#define NET_H

#include <netinet/tcp.h> /* struct tcphdr */
#include <netinet/ip.h> /* struct ip */
#include <net/ethernet.h> /* struct ether_header, ETHERTYPE_IP */
#include <sys/socket.h> /* socket(), AF_INET, ...*/
#include <netinet/in.h> /* IPPROTO_IP, ... */
#include <arpa/inet.h> /* htons(), ... */
#include <stdlib.h> /* malloc(), free() */
#include <string.h>

#define IP_SIZE sizeof(struct ip)
#define TCP_SIZE sizeof(struct tcphdr)
#define ETH_SIZE sizeof(struct ether_header)

#define SYNSIZ (IP_SIZE+TCP_SIZE)

#define SYN_METH 1

/* the tcp/udp checksum uses a pseudo header as well the */
/* tcp header to calculate the tcp/udp checksum */
struct tcpPseudo{
	unsigned int src;
	unsigned int dst;
	unsigned short length;
	unsigned char null;
	unsigned char protocol;
	struct tcphdr tcp;
};

/* the one stop place for packet data */
typedef struct packetData{
	unsigned int src;
	unsigned int dst;
	short sport;
	short dport;
	short id;
} packet_d;

short get_sport(char *);

/* just a wrapper for sendto */
int sendData(int, packet_d *, char *, int);

/*TCP checksum algorithm*/
unsigned short checksum(unsigned short *, int);

/* just fills in struct ip with the provided data */
void ipv4Hdr(char *, unsigned short, unsigned short, unsigned short, unsigned char, unsigned char, unsigned short, unsigned int, unsigned int);

/* just fills in struct tcphdr with the provided data */
void tcpHdr(char *, unsigned short, unsigned short, unsigned int, unsigned int, unsigned char, unsigned char, unsigned short, unsigned short, unsigned short);

/* builds SYN packet for TCP SYN scan (Incomplete handshake scan) */
void buildSYN(char *, packet_d *);

/* decides what packet to create based on the provided */
/* scan method */
char *buildPacket(char *, packet_d *, int);

#endif
