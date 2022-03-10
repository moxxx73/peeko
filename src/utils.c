#include "../include/utils.h"

/* resolves a IPv4 address from a provided hostname */
int resolve_name(char *name, char *buf){
    struct hostent *r;
    r = gethostbyname(name);
    if(r != NULL){
        if(inet_ntop(AF_INET, ((struct sockaddr_in *)r->h_addr_list[0]), buf, INET_ADDRSTRLEN) != NULL){
            return 1;
        }
    }
    return 0;
}

/* automatically fetch an interfaces IPv4 address   */
/* for the source address field in raw IPv4 headers */
int getifaddr(char *ifn, char *buf){
    struct ifreq ifr;
    int s;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if(s < 0) return 0;
    
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(ifr.ifr_name, ifn, IFNAMSIZ);
    if(ioctl(s, SIOCGIFADDR, &ifr) < 0) return 0;
    
    close(s);
    if(inet_ntop(AF_INET, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, buf, INET_ADDRSTRLEN) == NULL) return 0;
    return 1;
}

/* returns the amount of times a character occurs in a string */
int chr_count(char *str, char c, int len){
    int i=0, count=0;
    for(;i<len;i++){
        if(str[i] == c) count += 1;
    }
    return count;
}

/* returns the first index of a character in a string */
int chr_index(char *str, char c, int len){
    int index=0;
    for(;index<len;index++){
        if(str[index] == c) return index;
    }
    return index;
}

/* parse_list, parse_range and parse_file all take string based   */
/* arguments containing the intended ports to scan, converts them */
/* from ASCII to integer (shrunk to a word/short) and stores them */
/* in a list                                                      */
short *parse_list(char *list, int len, int llen){
    int i=0, x=0, no_len=0;
    short *ret=NULL;
    int c = 0;
    char *ptr = list;
    char *tmp=NULL;

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
    parse_r *ret=NULL;
    char *ptr=NULL;
    int index=0, a=0, b=0, i=0, llen=0;
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

/* parses CLI arguments for the -p flag */
/* and return the ports in an array     */
parse_r *parse_port_args(char *argv){
    short *list=NULL;
    int x=0;
    int arg_len = strlen(argv);
    parse_r *ret=NULL;
    
    /* if the user provided a range of ports, e.g. -p 1-1000 */
    x = chr_count(argv, '-', arg_len);
    if(x == 1){
        ret = parse_range(argv, arg_len);
        return ret;
    }

    /* or if they provide a list of ports, e.g. -p 21,22,23,53,80 */
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

parse_r *parse_file(const char *fn){
    FILE *fd=NULL;
    struct stat st={0};
    
    char *r_buf=NULL;
    char tmp[64];
    short *sh_tmp=NULL, port;

    int file_size=0;
    parse_r *ret;

    ret = (parse_r *)malloc(sizeof(parse_r));
    if(!ret){
        err_msg("malloc()");
        return NULL;
    }
    if(stat(fn, &st) < 0){
        err_msg("stat()");
        return NULL;
    }
    file_size = st.st_size;
    r_buf = (char *)malloc((file_size+1));
    if(!r_buf){
        err_msg("malloc()");
        return NULL;
    }
    memset(r_buf, 0, (file_size+1));

    fd = fopen(fn, "r");
    if(!fd){
        err_msg("fopen()");
        goto parse_file_err;
    }
    ret->list = NULL;
    ret->llen = 0;

    while(fgets(r_buf, file_size, fd)){
        if(strlen(r_buf) < 64){
            memcpy(tmp, r_buf, (strlen(r_buf)-1));
            port = (short)atoi(tmp);
            if(port){
                ret->llen += 1;
                sh_tmp = realloc(ret->list, ret->llen*sizeof(short));
                if(!sh_tmp) goto parse_file_err;
                sh_tmp[(ret->llen-1)] = port;
                ret->list = sh_tmp;
            }
        }
        memset(r_buf, 0, file_size);
        memset(tmp, 0, 64);
    }
    free(r_buf);
    fclose(fd);
    return ret;
parse_file_err:
    if(ret) free(ret);
    if(r_buf) free(r_buf);
    if(fd) fclose(fd);
    return NULL;
}

/* whenever an occurs, output a message and the reason why it occurred */
void err_msg(const char *msg){
    char err_buf[ERR_MSG_LEN];
    snprintf(err_buf, ERR_MSG_LEN, "[%sERROR%s] %s: %s\n", REDC, RESET, msg, strerror(errno));
    printf("%s", err_buf);
    return;
}

/* takes a buffer and outputs both the hex and ascii representation */
/* of each byte                                                     */
void hex_dump(unsigned char *data, int length){
    int c=0, x=0, y=0, z=0;
    unsigned char ch;
    while(c < length){
        printf("\t0x%04x: ", c);
        for(;x<6;x++){
            if((c+x) >= length) break;
            printf("%02x ", data[c+x]);
        }
        z = x;
        if(x != 6){
            for(;x<6;x++){
                printf("   ");
            }
        }
        printf("%s|%s ", GREENC, RESET);
        for(;y<z;y++){
            ch = data[c+y];
            if(32 <= ch && ch < 127){
                printf("%c", ch);
            }
            else{
                printf(".");
            }
        }
        printf("\n");
        c += x;
        x = 0;
        y = 0;

    }
}