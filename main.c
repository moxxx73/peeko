#include <stdio.h>
#include <unistd.h> /* getuid() */
#include <string.h> /* memcpy(), strchr() */
#include <stdlib.h> /* malloc(), free() */

#include "include/cafebabe.h"

#define MAX_THREADS 5
#define SPORT 666
#define IFNAMSIZ 16

#define NAME "Cafebabe"
#define BUILD "1.0.0581-alpha"

char verbose=0;
char debug=0;
char underline[] = "\e[4m";
char reset[] = "\e[0m";

char opt_arr[2][4] = {"CON", "SYN"};
char arr_len=2;

void usage(char *bn){
    printf("Usage: %s [options] address/hostname\n", bn);
    return;
}

void help(void){
    printf("### Options ###\n");
    printf("\t-v: Enable verbose output\n");
    printf("\t-p: Specify which port(s) to scan. example: -p 80, 80-100\n");
    printf("\t-t: Number of threads to run\n");
    printf("\t-d: Enables output for debugging purposes\n");
    printf("\t    debug output is double indented\n");
    printf("\t-m: choose a scan method from the options provided below:\n");
    printf("\t    SYN: TCP SYN scan\n");
    printf("\t    CON: TCP connect() scan\n");
    return;
}

int chr_count(char *str, char c, int len){
    int i, count=0;
    for(i=0;i<len;i++){
        if(str[i] == c) count += 1;
    }
    return count;
}

short *parse_list(char *list, int len, int llen){
    int i, x, no_len;
    short *ret;
    int c = 0;
    char *ptr = list;
    char *tmp;
    if((ret = (short *)malloc(sizeof(short)*llen)) == NULL) return NULL;
    for(i=0;i<len;i++){
        if(list[i] == ','){
            no_len = &list[i] - ptr;
            if((tmp = (char *)malloc(no_len)) == NULL) return NULL;
            memcpy(tmp, ptr, no_len);
            x = atoi(tmp);
            ret[c] = (short)x;
            c += 1;
            i += 1;
            ptr = &list[i];
            free(tmp);
        }
    }
    no_len = &list[len] - ptr;
    if(no_len){
        if((tmp = (char *)malloc(no_len)) == NULL) return NULL;
        memcpy(tmp, ptr, no_len);
        x = atoi(tmp);
        ret[llen-1] = (short)x;
        free(tmp);

    }
    return ret;
}

parse_r *parse_port_args(char *argv){
    short *list;
    int x;
    int arg_len = strlen(argv);
    parse_r *ret;
    if((ret = (parse_r *)malloc(sizeof(parse_r))) == NULL) return NULL;
    x = chr_count(argv, ',', arg_len);
    if(x != 0){
        x += 1;
        list = parse_list(argv, arg_len, x);
        ret->llen = x;
        ret->list = list;
        return ret;
    }
    return NULL;
}

int main(int argc, char *argv[]){
    char target[255];
    /* static for now, i'll add the option to change it later */
    char ifn[] = "en0\0";
    char opt_buf[4];
    char *arg, method=SYN_METH;
    int x;
    int i=1, threads=MAX_THREADS;
    cafebabe *args;
    parse_r *list;
    if(argc < 2){
        usage(argv[0]);
        help();
        return 0;
    }
    args = (cafebabe *)malloc(sizeof(cafebabe));
    if(args == NULL){
        printf("[!] failed to allocate memory for cafebabe structure\n");
        return 1;
    }
    args->ifn = (char *)malloc(IFNAMSIZ);
    args->addr = (char *)malloc(INET_ADDRSTRLEN);
    for(;i<(argc-1);i++){
        if(argv[i][0] == '-'){
            switch(argv[i][1]){
                case 'p':
                    if((i+1) != argc){
                        if((list = parse_port_args(argv[i+1])) == NULL) return -1;
                        break;
                    }
                case 't':
                    if((i+1) != argc){
                        arg = argv[i+1];
                        threads = atoi(arg);
                    }
                    break;
                case 'v':
                    verbose=1;
                    break;
                case 'd':
                    debug=1;
                    break;
                case 'm':
                    if((i+1) != argc){
                        memcpy(opt_buf, argv[i+1], 3);
                        for(x=0;x<arr_len;x++){
                            if(strncmp(opt_buf, opt_arr[x], 3) == 0) method = (char)x;
                        }
                    }
            }
        }
    }
    printf("%s | Build: %s\n", NAME, BUILD);
    if(method > TCP_CON && getuid() != 0){
        printf("The scan method being used requires that u run this binary as root\n");
        printf("sorrryyy...\n");
        free(args->ifn);
        free(args->addr);
        free(args);
        return 0;
    }
    memset(target, 0, 255);
    memcpy(target, argv[argc-1], 255);
    memcpy(args->ifn, ifn, IFNAMSIZ);
    args->sport = (short)SPORT;
    args->method = method;
    cafebabe_main(args, target, list, threads);
    return 0;
}
