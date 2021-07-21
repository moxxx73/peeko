#include "bpf.h"

/* opens a /dev/bpf device file */
int openDev(void){
	int fd, i;
	char fn[13];
	memset(fn, 0, 13);
	for(i=0;i<256;i++){
		sprintf(fn, "/dev/bpf%d", i);
		fd = open(fn, O_RDWR);
		if(fd > 0){
			return fd;
		}
	}
	return -1;
}

/* sets the bpf interface */
int setInterface(int bpf, char *ifn){
	struct ifreq ifr;
	strncpy(ifr.ifr_name, ifn, IFNAMSIZ);
	if(ioctl(bpf, BIOCSETIF, &ifr) < 0){
		return -1;
	}
	return 0;
}

/* fetch the kernel bpf buffer size */
int getLength(int bpf){
	int r;
	if(ioctl(bpf, BIOCGBLEN, &r) < 0){
		return -1;
	}
	return r;
}

/* sets the interface associated with the device to promiscuous */
int setPromisc(int bpf){
	int r;
	if(ioctl(bpf, BIOCPROMISC, &r) < 0){
		return -1;
	}
	return 0;
}

/* set immmediate mode for the bpf device */
int setImm(int bpf){
	int r;
	if(ioctl(bpf, BIOCIMMEDIATE, &r) < 0){
		return -1;
	}
	return 0;
}

/* initialises the linked list */
struct bpfData *initList(void){
	struct bpfData *p;
	p = (struct bpfData *)malloc(NODESIZ);
	if(p == NULL) return NULL;
	p->length = 0;
	p->data = NULL;
	p->nxt = NULL;
	return p;
}

/* adds a new node to the linked list */
int addData(struct bpfData *p, char *data, unsigned int l){
	struct bpfData *c = p;
	while(c->nxt != NULL){
		c = c->nxt;
	}
	c->nxt = (struct bpfData *)malloc(NODESIZ);
	if(c->nxt == NULL) return -1;
	c->length = l;
	c->nxt->data = (char *)malloc(l);
	if(c->nxt->data == NULL) return -2;
	memcpy(c->nxt->data, data, l);
	return 0;
}

/* trashes linked list */
void trashAll(struct bpfData *p){
	struct bpfData *c, *r;
	c = p;
	while(c != NULL){
		if(c->data != NULL) free(c->data);
		r = c;
		c = c->nxt;
		free(r);
	}
	c = NULL;
	p->nxt = NULL;
	return;
}

/* reads one or more packets from the bpf device */
int readDev(int bpf, struct bpfData *p, int blen){
	struct bpf_hdr *bpfHdr;
	char *internal;
	char *ptr;
	int b;

	if(p == NULL) return -1;
	internal = (char *)malloc(blen);
	if(internal == NULL) return -2;
	b = read(bpf, internal, blen);
	if(b < 0) return -3;
	else if(b > 0){
		ptr = internal;
		while(ptr < internal+b){
			bpfHdr = (struct bpf_hdr *)ptr;
			addData(p, (ptr+bpfHdr->bh_hdrlen), bpfHdr->bh_caplen);
			ptr += BPF_WORDALIGN(bpfHdr->bh_caplen+bpfHdr->bh_hdrlen);
		}
	}	
	return b;
}