#include "../include/memory.h"

void clean_exit(pool_d *pool, int ret){
    int x=0;
    if(pool->write_threads){
        for(;x<pool->wthread_c;x++){
            if(pool->write_threads[x]) pthread_cancel(pool->write_threads[x]);
        }
        free(pool->write_threads);
    }
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
        pool->write_threads = NULL;
        pool->wthread_c = 0;
        if((pool->ptrs = (pointer_l *)malloc(sizeof(pointer_l))) != NULL){
            pool->ptrs->prev = NULL;
            pool->ptrs->ptr = NULL;
            pool->ptrs->next = NULL;
        }
    }
    return pool;
}

/* allocates space for the new pointer being appended to the array */
void *add_allocation(pool_d *p, void *ptr, short size, const char *tag){
    pointer_l *x;
    x = p->ptrs;
    while(x->next != NULL){
        x = x->next;
    }
    x->next = (pointer_l *)malloc(sizeof(pointer_l));
    if(x->next != NULL){
        x->next->prev = x;
        x->next->ptr = ptr;
        x->next->size = size;
        memcpy(x->next->tag, tag, PTR_TAG_SIZ);
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

int get_tag_index(pointer_l *p, const char *tag){
    pointer_l *x;
    int index;
    x = p;
    index = 0;
    while(!x){
        if(strncmp(x->tag, tag, PTR_TAG_SIZ) == 0){
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

pointer_l *ptr_via_tag(pointer_l *p, const char *tag){
    pointer_l *x;
    x = p;
    while(!x){
        if(strncmp(x->tag, tag, PTR_TAG_SIZ) == 0){
            return x;
        }
        x = x->next;
    }
    return NULL;
}

int remove_allocation(pool_d *p, int index){
    pointer_l *x, *y=NULL, *z=NULL;
    int i = 0;
    x = p->ptrs;
    while(x != NULL){
        if(index == i){
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

void display_stats(pool_d *p){
    printf("\nMemory pool @ %p\n", (void *)p);
    printf("    Total No. of allocations: %d\n", p->allocations);
    printf("    Memory currently allocated: %d Bytes\n", p->allocated);
    printf("    Memory freed: %d Bytes\n", p->freed);
    return;
}
