/* Copyright (c) 2013      Mellanox Technologies, Inc.
 *                         All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#include "oshmem_config.h"
#include "oshmem/proc/proc.h"
#include "oshmem/mca/spml/spml.h"
#include "oshmem/mca/memheap/memheap.h"
#include "oshmem/mca/memheap/ptmalloc/memheap_ptmalloc.h"
#include "oshmem/mca/memheap/ptmalloc/memheap_ptmalloc_component.h"
#include "oshmem/mca/memheap/base/base.h"
#include "orte/mca/grpcomm/grpcomm.h"
#include "opal/class/opal_hash_table.h"
#include "opal/class/opal_object.h"
#include "orte/util/name_fns.h"

mca_memheap_ptmalloc_module_t memheap_ptmalloc = {
    {
        .memheap_component         = &mca_memheap_ptmalloc_component,
        .memheap_finalize          = mca_memheap_ptmalloc_finalize,
        .memheap_alloc             = mca_memheap_ptmalloc_alloc,
        .memheap_alloc_with_hint   = mca_memheap_base_alloc_with_hint,
        .memheap_memalign          = mca_memheap_ptmalloc_align,
        .memheap_realloc           = mca_memheap_ptmalloc_realloc,
        .memheap_free              = mca_memheap_ptmalloc_free,

        .memheap_private_alloc     = mca_memheap_ptmalloc_alloc,
        .memheap_private_free      = mca_memheap_ptmalloc_free,

        .memheap_get_local_mkey    = mca_memheap_base_get_mkey,
        .memheap_is_symmetric_addr = mca_memheap_base_is_symmetric_addr,
        .memheap_get_all_mkeys     = mca_memheap_modex_recv_all,

        .memheap_size              = 0
    },
    100   /* priority */
};

/* Memory Heap Buddy Implementation */
/**
 * Initialize the Memory Heap
 */
int mca_memheap_ptmalloc_module_init(memheap_context_t *context)
{
    if (!context || !context->user_size || !context->private_size) {
        return OSHMEM_ERR_BAD_PARAM;
    }

    /* Construct a mutex object */
    OBJ_CONSTRUCT(&memheap_ptmalloc.lock, opal_mutex_t);
    memheap_ptmalloc.base = context->user_base_addr;
    memheap_ptmalloc.cur_size = 0;
    memheap_ptmalloc.max_size = context->user_size + context->private_size;
    memheap_ptmalloc.max_alloc_size = context->user_size;

    MEMHEAP_VERBOSE(1,
                    "symmetric heap memory (user+private): %llu bytes",
                    (unsigned long long)(context->user_size + context->private_size));

    /* disable till we figure out double modex&grpcomm.bad problem */
    //        memheap_modex_mkey_exchange();
    return OSHMEM_SUCCESS;

}

/**
 * Allocate size bytes on the symmetric heap.
 * The allocated variable is aligned to its size.
 */
int mca_memheap_ptmalloc_alloc(size_t size, void** p_buff)
{
    if (size > memheap_ptmalloc.max_alloc_size) {
        *p_buff = 0;
        return OSHMEM_ERR_OUT_OF_RESOURCE;
    }

    OPAL_THREAD_LOCK(&memheap_ptmalloc.lock);
    *p_buff = dlmalloc(size);
    OPAL_THREAD_UNLOCK(&memheap_ptmalloc.lock);

    if (NULL == *p_buff)
        return OSHMEM_ERROR;

    MCA_SPML_CALL(memuse_hook(*p_buff, size));
    return OSHMEM_SUCCESS;
}

int mca_memheap_ptmalloc_align(size_t align, size_t size, void **p_buff)
{
    if (size > memheap_ptmalloc.max_alloc_size) {
        *p_buff = 0;
        return OSHMEM_ERR_OUT_OF_RESOURCE;
    }

    if (align == 0) {
        *p_buff = 0;
        return OSHMEM_ERROR;
    }

    /* check that align is power of 2 */
    if (align & (align - 1)) {
        *p_buff = 0;
        return OSHMEM_ERROR;
    }

    OPAL_THREAD_LOCK(&memheap_ptmalloc.lock);
    *p_buff = dlmemalign(align, size);
    OPAL_THREAD_UNLOCK(&memheap_ptmalloc.lock);

    if (NULL == *p_buff)
        return OSHMEM_ERROR;

    MCA_SPML_CALL(memuse_hook(*p_buff, size));
    return OSHMEM_SUCCESS;
}

int mca_memheap_ptmalloc_realloc(size_t new_size,
                                 void *p_buff,
                                 void **p_new_buff)
{
    if (new_size > memheap_ptmalloc.max_alloc_size) {
        *p_new_buff = 0;
        return OSHMEM_ERR_OUT_OF_RESOURCE;
    }

    OPAL_THREAD_LOCK(&memheap_ptmalloc.lock);
    *p_new_buff = dlrealloc(p_buff, new_size);
    OPAL_THREAD_UNLOCK(&memheap_ptmalloc.lock);

    if (!*p_new_buff)
        return OSHMEM_ERR_OUT_OF_RESOURCE;

    MCA_SPML_CALL(memuse_hook(*p_new_buff, new_size));
    return OSHMEM_SUCCESS;
}

/*
 * Free a variable allocated on the
 * symmetric heap.
 */
int mca_memheap_ptmalloc_free(void* ptr)
{
    OPAL_THREAD_LOCK(&memheap_ptmalloc.lock);
    dlfree(ptr);
    OPAL_THREAD_UNLOCK(&memheap_ptmalloc.lock);
    return OSHMEM_SUCCESS;
}

int mca_memheap_ptmalloc_finalize()
{
    MEMHEAP_VERBOSE(5, "deregistering symmetric heap");
    return OSHMEM_SUCCESS;
}

int mca_memheap_ptmalloc_getpagesize(void)
{
    return 2 * 1024 * 1024;
}

/* must be same as in malloc.c */
#define PTMALLOC_MAX_SIZE_T           (~(size_t)0)
#define PTMALLOC_MFAIL                ((void*)(PTMALLOC_MAX_SIZE_T))
void *mca_memheap_ptmalloc_sbrk(size_t size)
{
    char *ret;

    if (memheap_ptmalloc.cur_size + size > memheap_ptmalloc.max_size) {
        return PTMALLOC_MFAIL ;
    }

    ret = (char *) memheap_ptmalloc.base + memheap_ptmalloc.cur_size;
    memheap_ptmalloc.cur_size += size;

    return ret;
}

