#include "memory.h"

/*
extern char debug;
extern char underline[];
extern char reset[];
*/

/* for whenever we get a SIGINT or an error occurs */
void clean_exit(pool_d *pool, int ret){
    pthread_cancel(pool->write_thread);
    pthread_cancel(pool->recv_thread);
    if(pool->recv_fd > 0) close(pool->recv_fd);
    if(pool->write_fd > 0) close(pool->write_fd);
    free_ptr_list(pool->ptrs);
    free(pool);
    exit(ret);
}

void *create_pool(pool_d *pool){
    pool = (pool_d *)malloc(sizeof(pool_d));
    if(pool != NULL){
        pool->allocations = 0;
        pool->recv_fd = -1;
        pool->write_fd = -1;
        if((pool->ptrs = (pointer_l *)malloc(sizeof(pointer_l))) != NULL){
            pool->ptrs->prev = NULL;
            pool->ptrs->ptr = NULL;
            pool->ptrs->next = NULL;
            //if(debug) printf("\t\t%s[DEBUG]%s Created heap pool @ %p\n", underline, reset, (void *)pool);
        }
    }
    return pool;
}

/* allocates space for the new pointer being appended to the array */
void *add_allocation(pointer_l *p, void *ptr){
    pointer_l *x, *y;
    x = p;
    y = NULL;
    //if(debug) printf("\t\t%s[DEBUG]%s Adding %p to pool\n", underline, reset, ptr);
    while(x->next != NULL){
        y = x;
        x = x->next;
    }
    x->next = (pointer_l *)malloc(sizeof(pointer_l));
    if(x->next != NULL){
        x->next->prev = x;
        x->next->ptr = ptr;
        x->next->next = NULL;
    }
    return NULL;
}

int get_ptr_index(pointer_l *p, void *ptr){
    pointer_l *x;
    int ret = 0;
    x = p;
    while(x != NULL){
        if(x->ptr == ptr) return ret;
        ret += 1;
        x = x->next;
    }
    return -1;
}

void display_ptrs(pointer_l *ptr){
    pointer_l *x;
    int index = 0;
    x = ptr;
    while(x != NULL){
        printf("Index: %d @ %p\n", index, (void *)x);
        printf("\t- Previous = %p\n", (void *)x->prev);
        printf("\t- Pointer = %p\n", (void *)x->ptr);
        printf("\t- Next = %p\n", (void *)x->next);
        index += 1;
        x = x->next;
    }
    return;
}

int remove_allocation(pointer_l *p, int index){
    pointer_l *x, *y=NULL, *z=NULL;
    int i = 0;
    x = p;
    while(x != NULL){
        if(index == i){
            //if(debug) printf("\t\t%s[DEBUG]%s Removing %p from pool\n", underline, reset, (void *)x->ptr);
            y = x->prev;
            z = x->next;
            if(y!=NULL) y->next = z;
            if(z!=NULL) z->prev = y;
            free(x);
            return 0;
        }
        x = x->next;
        i += 1;
    }
    return -1;
}

void free_ptr_list(pointer_l *ptr){
    pointer_l *x, *y;
    x = ptr;
    while(x != NULL){
        y = x;
        x = x->next;
        free(y);
    }
    return;
}
