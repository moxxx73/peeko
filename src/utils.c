#include "../include/utils.h"

char underline[] = "\033[4m";
char reset[] = "\033[0m";
char red_c[] = "\033[31m";
char reverse_c[] = "\033[7m";

int resolve_name(char *name, char *b){
    struct hostent *r;
    r = gethostbyname(name);
    if(r != NULL){
        if(inet_ntop(AF_INET, ((struct sockaddr_in *)r->h_addr_list[0]), b, INET_ADDRSTRLEN) != NULL){
            return 1;
        }
    }
    return 0;
}

int getifaddr(char *ifn, char *b){
    struct ifreq ifr;
    int s;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if(s < 0) return 0;
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(ifr.ifr_name, ifn, IFNAMSIZ);

    if(ioctl(s, SIOCGIFADDR, &ifr) < 0){
        return 0;
    }
    close(s);
    if(inet_ntop(AF_INET, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, b, INET_ADDRSTRLEN) == NULL){
        return 0;
    }
    return 1;
}

int chr_count(char *str, char c, int len){
    int i, count=0;
    for(i=0;i<len;i++){
        if(str[i] == c) count += 1;
    }
    return count;
}

int chr_index(char *str, char c, int len){
    int index=0;
    for(;index<len;index++){
        if(str[index] == c) return index;
    }
    return index;
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

parse_r *parse_range(char *argv, int len){
    parse_r *ret;
    char *ptr;
    int index, a, b, i, llen;
    if((ret = (parse_r *)(malloc(sizeof(parse_r)))) == NULL) return NULL;
    index = chr_index(argv, '-', len);
    ptr = (char *)malloc(index+1);
    if(ptr == NULL){
        free(ret);
        return NULL;
    }
    memcpy(ptr, argv, index);
    a = atoi(ptr);
    ptr = realloc(ptr, strlen(argv)-(index+1));
    memcpy(ptr, argv+(index+1), strlen(argv)-(index+1));
    b = atoi(ptr);
    free(ptr);
    llen = (b-a);
    if(llen < 0){
        free(ret);
        return NULL;
    }
    llen += 1;
    ret->llen = llen;
    ret->list = (short *)malloc(llen*sizeof(short));
    for(i=0;i<llen;i++){
        ret->list[i] = a+i;
    }
    return ret;
}

parse_r *parse_port_args(char *argv){
    short *list;
    int x;
    int arg_len = strlen(argv);
    parse_r *ret;
    x = chr_count(argv, '-', arg_len);
    if(x == 1){
        ret = parse_range(argv, arg_len);
        return ret;
    }
    if((ret = (parse_r *)malloc(sizeof(parse_r))) == NULL) return NULL;
    x = chr_count(argv, ',', arg_len);
    if(x != 0){
        x += 1;
        list = parse_list(argv, arg_len, x);
        ret->llen = x;
        ret->list = list;
        return ret;
    }
    ret->llen = 1;
    if((ret->list = (short *)malloc(sizeof(short))) == NULL){
        free(ret);
        return NULL;
    }
    ret->list[0] = (short)atoi(argv);
    return ret;
}

void err_msg(char *msg){
    char err_buf[ERR_MSG_LEN];
    snprintf(err_buf, ERR_MSG_LEN, "%s%s[!]%s %s: %s\n", red_c, reverse_c, reset, msg, strerror(errno));
    printf("%s", err_buf);
    return;
}

/*char *default_interface(void){
    struct ifaddrs *ifp, *ptr;
    if(getifaddrs(&ifp) < 0){
        return -1;
    }
    
    return 0;
}*/
