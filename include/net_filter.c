#include "net_filter.h"

/* simple filter that checks that we are receiving the */
/* correct packets, makes later check functions redundant */
int set_filter(int fd, filter_data *ptr){
	#if __APPLE__
        struct bpf_program filter;
	    struct bpf_insn program[] = {
		    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12), /* load ether_type into the vm accumulator */
		    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0800, 0, 9), /* make sure we're receiving ipv4 packets */
		    BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23), /* load ip protocol into to the accumulator */
		    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_TCP, 0, 7), /* check whether protocol is tcp */
		    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 26),
		    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, htonl(ptr->dst), 0, 5),
		    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30),
		    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, htonl(ptr->src), 0, 3),
		    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 36),
		    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ptr->dport, 0, 1),
		    BPF_STMT(BPF_RET+BPF_K, (unsigned int)-1),
		    BPF_STMT(BPF_RET+BPF_K, 0)
	    };
	    filter.bf_len = 12;
	    filter.bf_insns = &program[0];
	    if(ioctl(fd, BIOCSETF, &filter) < 0){
		    return -1;
	    }
    #else
        struct sock_fprog program;
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0800, 0, 9), // tj, ft
            BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_TCP, 0, 7),
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 26),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, htonl(ptr->dst), 0, 5),
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, htonl(ptr->src), 0, 3),
            BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 36),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ptr->dport, 0, 1),
            BPF_STMT(BPF_RET+BPF_K, (unsigned int)-1),
            BPF_STMT(BPF_RET+BPF_K, 0)
        };
        program.len = 12;
        program.filter = filter;
        if(setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) < 0){
            return -1;
        }
    #endif
	return 0;
}