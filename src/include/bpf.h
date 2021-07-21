#ifndef BPF_H
#define BPF_H

#include <poll.h>
#include <sys/ioctl.h> /* ioctl() */
#include <fcntl.h> /* open() */
#include <string.h> /* memset() */
#include <stdio.h> /* sprintf() */
#include <stdlib.h> /* malloc(), free() */
#include <unistd.h> /* read() */

#include <net/bpf.h>
#include <net/if.h> /* struct ifreq */

/* linked list struct for bpf data */
struct bpfData{
	int length;
	char *data;
	struct bpfData *nxt;
};

#define NODESIZ sizeof(struct bpfData)

/* opens a /dev/bpf device file */
int openDev(void);

/* sets the bpf interface */
int setInterface(int, char *);

/* fetch the kernel bpf buffer size */
int getLength(int);

/* sets the interface associated with the device to promiscuous */
int setPromisc(int);

/* set immmediate mode for the bpf device */
int setImm(int);

/* initialises the linked list */
struct bpfData *initList(void);

/* adds a new node to the linked list */
int addData(struct bpfData *, char *, unsigned int );

/* trashes linked list */
void trashAll(struct bpfData *);

/* reads one or more packets from the bpf device */
int readDev(int, struct bpfData *, int);

#endif