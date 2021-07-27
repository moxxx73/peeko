#ifndef FRAMEZ
#define FRAMEZ

#include <netinet/tcp.h> /* struct tcphdr */
#include <netinet/ip.h> /* struct ip */
#include <arpa/inet.h> /* htons(), ... */
#include <string.h> 

#define IP_SIZE sizeof(struct ip)
#define TCP_SIZE sizeof(struct tcphdr)

struct tcpPseudo{
	unsigned int src;
	unsigned int dst;
	unsigned short length;
	unsigned char null;
	unsigned char protocol;
	struct tcphdr tcp;
};

/*TCP checksum algorithm*/
unsigned short checksum(unsigned short *, int);

void ipv4Hdr(char *, unsigned short, unsigned short, unsigned short, unsigned char, unsigned char, unsigned short, unsigned int, unsigned int);

void tcpHdr(char *, unsigned short, unsigned short, unsigned int, unsigned int, unsigned char, unsigned char, unsigned short, unsigned short, unsigned short);

void buildSYN(char *, unsigned int, unsigned int, short, short, short);

#endif
