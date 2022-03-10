#include "../include/net_filter.h"

/* the linux socket filter is derived from FreeBSDs berkeley packet filter, BPF.        */
/* making use of these filters is quite similar in my experience (that being utilising  */
/* socket filters on linux and MacOS) but there are obviously some differences.         */

/* i wont go on much further, details will be in future documentation im writing */

int set_filter(int fd, filter_data *ptr, int tun){
    struct sock_fprog program={0};
    struct sock_filter *filter=((void *)0);
    int prog_size=10;
    int ip=0;
    int eth_pad = 0;

    if(!tun){
        eth_pad = 14;
        prog_size = 12;
    }
    filter = (struct sock_filter *)malloc((sizeof(struct sock_filter)*prog_size));
    if(!filter){
        err_msg("malloc()");
        return -1;
    }
    /* if we're dealing with a layer 3 tunnel interface (indicated by int tun) then there will be */
    /* no ethernet address at the start of the received packet                                    */
    if(!tun){
        filter[0] = (struct sock_filter)BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12);
        filter[1] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0800, 0, 9);
        ip += 2;
    }
    filter[ip] = (struct sock_filter)BPF_STMT(BPF_LD+BPF_B+BPF_ABS, (9+eth_pad));
    filter[ip+1] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_TCP, 0, 7);
    filter[ip+2] = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (12+eth_pad));
    filter[ip+3] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, htonl(ptr->dst), 0, 5);
    filter[ip+4] = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (16+eth_pad));
    filter[ip+5] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, htonl(ptr->src), 0, 3);
    filter[ip+6] = (struct sock_filter)BPF_STMT(BPF_LD+BPF_H+BPF_ABS, (22+eth_pad));
    filter[ip+7] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ptr->dport, 0, 1);
    filter[ip+8] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, (unsigned int)-1);
    filter[ip+9] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, 0);

    program.len = prog_size;
    program.filter = filter;
    if(setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) < 0){
        err_msg("setsockopt()");
        return -1;
    }
	return 0;
}