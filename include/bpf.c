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
int devInterface(int bpf, char *ifn){
	struct ifreq ifr;
	strncpy(ifr.ifr_name, ifn, IFNAMSIZ);
	if(ioctl(bpf, BIOCSETIF, &ifr) < 0){
		return -1;
	}
	return 0;
}

/* fetch the kernel bpf buffer size */
int devLength(int bpf){
	int r;
	if(ioctl(bpf, BIOCGBLEN, &r) < 0){
		return -1;
	}
	return r;
}

/* sets the interface associated with the device to promiscuous */
int devPromisc(int bpf){
	int r=1;
	if(ioctl(bpf, BIOCPROMISC, &r) < 0){
		return -1;
	}
	return 0;
}

/* set immmediate mode for the bpf device */
int devImm(int bpf){
	int r=1;
	if(ioctl(bpf, BIOCIMMEDIATE, &r) < 0){
		return -1;
	}
	return 0;
}

/* simple filter that checks that we are receiving the */
/* correct packets, makes later check functions redundant */
int setFilter(int bpf, filter_data *ptr){
	struct bpf_program filter;
	struct bpf_insn program[] = {
		BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12), /* load ether_type into the vm accumulator */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0800, 0, 7), /* make sure we're receiving ipv4 packets */
		BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23), /* load ip protocol into to the accumulator */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_TCP, 0, 5), /* check whether protocol is tcp */
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 26),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, htonl(ptr->dst), 0, 3),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, htonl(ptr->src), 0, 1),
		BPF_STMT(BPF_RET+BPF_K, (unsigned int)-1),
		BPF_STMT(BPF_RET+BPF_K, 0)
	};
	filter.bf_len = 10;
	filter.bf_insns = &program[0];
	if(ioctl(bpf, BIOCSETF, &filter) < 0){
		return -1;
	}
	return 0;
}

int setAll(int bpf, char *ifn){
	int r;
	if(devInterface(bpf, ifn) < 0){
		return -1;
	}
	if(devImm(bpf) < 0){
		return -1;
	}
	if(devPromisc(bpf) < 0){
		return -1;
	}
	r = devLength(bpf);
	if(r < 0){
		return -1;
	}
	return r;
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
	c->nxt->nxt = NULL;
	return 0;
}

/* trashes linked list */
void trashAll(struct bpfData *p){
	struct bpfData *c, *r;
	c = p;
	while(c != NULL){
		if(c->data != NULL){
			free(c->data);
			c->data = NULL;
		}
		r = c->nxt;
		free(c);
		c = r;
	}
	return;
}

void *getData(struct bpfData *l, int offset){
	struct bpfData *p;
	int c=0;
	p = l;
	while(p!=NULL){
		if(c == offset) return p->data;
		p = p->nxt;
		c += 1;
	}
	return NULL;
}

int getLength(struct bpfData *list){
	struct bpfData *p;
	int x = 0;
	p = list;
	while(p != NULL){
		x += 1;
		p = p->nxt;
	}
	return x;
}

/* reads one or more packets from the bpf device */
int readDev(int bpf, struct bpfData *p, int blen){
	struct bpf_hdr *bpfHdr;
	char *internal;
	char *ptr;
	int b, count=0;

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
			count += 1;
		}
	}
	return count;
}
