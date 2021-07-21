#ifndef FRAMEZ
#define FRAMEZ

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>

struct tcpPseudo{
	unsigned int src;
	unsigned int dst;
	unsigned short length;
	unsigned char null;
	unsigned char protocol;
	struct tcphdr tcp;
};

/*TCP checksum algorithm*/
unsigned checksum(unsigned short *, int);

void ipv4Hdr(char *, unsigned short, unsigned short, unsigned short, unsigned char, unsigned char, unsigned short, unsigned int, unsigned int);

void tcpHdr(char *, unsigned short, unsigned short, unsigned int, unsigned int, unsigned char, unsigned char, unsigned short, unsigned short, unsigned short);

#endif
