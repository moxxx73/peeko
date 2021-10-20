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
        pool->allocated = 0;
        pool->freed = 0;
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
void *add_allocation(pool_d *p, void *ptr, short size, char *id){
    pointer_l *x;
    x = p->ptrs;
    //if(debug) printf("\t\t%s[DEBUG]%s Adding %p to pool\n", underline, reset, ptr);
    while(x->next != NULL){
        x = x->next;
    }
    x->next = (pointer_l *)malloc(sizeof(pointer_l));
    if(x->next != NULL){
        x->next->prev = x;
        x->next->ptr = ptr;
        x->next->size = size;
        memcpy(x->next->id, id, PTR_ID_SIZ);
        x->next->next = NULL;
        p->allocated += size;
        p->allocations += 1;
        return x->next;
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

int get_id_index(pointer_l *p, char *id){
    pointer_l *x;
    int index;
    x = p;
    index = 0;
    while(!x){
        if(strncmp(x->id, id, PTR_ID_SIZ) == 0){
            return index;
        }
        index += 1;
        x = x->next;
    }
    return -1;
}

pointer_l *ptr_via_index(pointer_l *p, void *ptr){
    pointer_l *x;
    x = p;
    while(!x){
        if(x->ptr == ptr) return x;
        x = x->next;
    }
    return NULL;
}

pointer_l *ptr_via_id(pointer_l *p, char *id){
    pointer_l *x;
    x = p;
    while(!x){
        if(strncmp(x->id, id, PTR_ID_SIZ) == 0){
            return x;
        }
        x = x->next;
    }
    return NULL;
}

void display_ptrs(pool_d *p){
    pointer_l *x;
    int index = 0;
    x = p->ptrs;
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

int remove_allocation(pool_d *p, int index){
    pointer_l *x, *y=NULL, *z=NULL;
    int i = 0;
    x = p->ptrs;
    while(x != NULL){
        if(index == i){
            //if(debug) printf("\t\t%s[DEBUG]%s Removing %p from pool\n", underline, reset, (void *)x->ptr);
            y = x->prev;
            z = x->next;
            if(y!=NULL) y->next = z;
            if(z!=NULL) z->prev = y;
            p->allocated -= x->size;
            p->allocations -= 1;
            p->freed += x->size;
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
