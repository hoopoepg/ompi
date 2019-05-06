/*
 * Copyright (c) 2019      Mellanox Technologies, Inc.
 *                         All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#include "oshmem_config.h"

#include "oshmem/mca/sshmem/sshmem.h"
#include "oshmem/include/shmemx.h"
#include "oshmem/mca/sshmem/base/base.h"

#include <ucs/sys/math.h>

#include "sshmem_ucx.h"

#define SSHMEM_UCX_SHADOW_FREE_ELEM (1 << 31)

typedef struct sshmem_ucx_shadow_alloc_elem {
    uint32_t flags;
    uint32_t length;
} sshmem_ucx_shadow_alloc_elem_t;

struct sshmem_ucx_shadow_allocator {
    size_t                         length;
    sshmem_ucx_shadow_alloc_elem_t elem[];
};


static size_t sshmem_ucx_shadow_get_length(size_t size)
{
    sshmem_ucx_shadow_allocator_t *allocator = NULL;

    return ucs_align_up(size, sizeof(allocator->elem[0])) / sizeof(allocator->elem[0]);
}

static int sshmem_ucx_shadow_is_free(sshmem_ucx_shadow_alloc_elem_t *elem)
{
    return elem->flags & SSHMEM_UCX_SHADOW_FREE_ELEM;
}

static void sshmem_ucx_shadow_set_elem(sshmem_ucx_shadow_alloc_elem_t *elem,
                                        size_t length, uint32_t flags)
{
    elem->flags  = flags;
    elem->length = length;
}

static void sshmem_ucx_shadow_clean_elem(sshmem_ucx_shadow_alloc_elem_t *elem)
{
    assert(elem->length);

    elem->flags  = 0;
    elem->length = 0;
}

sshmem_ucx_shadow_allocator_t *sshmem_ucx_shadow_create_allocator(size_t size)
{
    sshmem_ucx_shadow_allocator_t *allocator;
    size_t length = sshmem_ucx_shadow_get_length(size);

    allocator = malloc(sizeof(*allocator) + length * sizeof(allocator->elem[0]));
    if (allocator) {
        /* allocate data */
        allocator->length = length;
        memset(allocator->elem, 0, length * sizeof(allocator->elem[0]));

        /* init data: set first element as free to whole buffer */
        sshmem_ucx_shadow_set_elem(&allocator->elem[0], length, SSHMEM_UCX_SHADOW_FREE_ELEM);
    }

    return allocator;
}

void sshmem_ucx_shadow_destroy_allocator(sshmem_ucx_shadow_allocator_t *allocator)
{
    assert(sshmem_ucx_shadow_is_free(allocator->elem));
    assert(allocator->elem[0].length == allocator->length);
    free(allocator);
}

static sshmem_ucx_shadow_alloc_elem_t
*sshmem_ucx_shadow_get_elem(sshmem_ucx_shadow_allocator_t *allocator, size_t offset)
{
    return (sshmem_ucx_shadow_alloc_elem_t*)((char*)&allocator->elem[0] + offset);
}

int sshmem_ucx_shadow_alloc(sshmem_ucx_shadow_allocator_t *allocator,
                            size_t size, size_t *offset)
{
    size_t length = sshmem_ucx_shadow_get_length(size);
    sshmem_ucx_shadow_alloc_elem_t *elem;

    if (!size) {
        return OSHMEM_SUCCESS;
    }

    for (elem = &allocator->elem[0]; elem < &allocator->elem[allocator->length];
         elem += elem->length) {
        if (sshmem_ucx_shadow_is_free(elem) &&
            (elem->length >= length)) {
            /* found suitable free element */
            if (elem->length > length) {
                /* create new 'free' element for tail of current buffer */
                sshmem_ucx_shadow_set_elem(elem + length, elem->length - length,
                                            SSHMEM_UCX_SHADOW_FREE_ELEM);
            }

            sshmem_ucx_shadow_set_elem(elem, length, 0);
            *offset = (char*)elem - (char*)&allocator->elem[0];
            return OSHMEM_SUCCESS;
        }
    }

    return OSHMEM_ERR_OUT_OF_RESOURCE;
}

static void sshmem_ucx_shadow_merge_blocks(sshmem_ucx_shadow_allocator_t *allocator)
{
    sshmem_ucx_shadow_alloc_elem_t *elem;
    sshmem_ucx_shadow_alloc_elem_t *elem_clean;

    /* merge free elements */
    elem = allocator->elem;
    while ((elem < &allocator->elem[allocator->length]) &&
           (elem->length < allocator->length)) {
        if (sshmem_ucx_shadow_is_free(elem) &&
            sshmem_ucx_shadow_is_free(elem + elem->length)) {
            /* current & next elements are free, should be merged */
            elem_clean = elem + elem->length;
            elem->length += elem_clean->length;
            /* clean element which is merged */
            sshmem_ucx_shadow_clean_elem(elem_clean);
        } else {
            elem += elem->length;
        }
    }
}

int sshmem_ucx_shadow_free(sshmem_ucx_shadow_allocator_t *allocator, size_t offset)
{
    sshmem_ucx_shadow_alloc_elem_t *elem = sshmem_ucx_shadow_get_elem(allocator, offset);

    elem->flags |= SSHMEM_UCX_SHADOW_FREE_ELEM;

    /* merge free elements */
    sshmem_ucx_shadow_merge_blocks(allocator);

    return OSHMEM_SUCCESS;
}

int sshmem_ucx_shadow_realloc(sshmem_ucx_shadow_allocator_t *allocator,
                              size_t size, size_t old_offset, size_t *new_offset,
                              sshmem_ucx_shadow_realloc_copy_t *cp)
{
    size_t length = sshmem_ucx_shadow_get_length(size);
    sshmem_ucx_shadow_alloc_elem_t *elem;
    int res;

    if (!size) {
        return sshmem_ucx_shadow_free(allocator, old_offset);
    }

    elem = sshmem_ucx_shadow_get_elem(allocator, old_offset);

    if (length == elem->length) {
        *new_offset = old_offset;
        return OSHMEM_SUCCESS;
    }

    if (length < elem->length) {
        /* requested block is shorter than allocated block
         * then just cut current buffer */
        sshmem_ucx_shadow_set_elem(elem + length, 
                                    elem->length - length,
                                    SSHMEM_UCX_SHADOW_FREE_ELEM);
        elem->length = length;
        *new_offset  = old_offset;
        sshmem_ucx_shadow_merge_blocks(allocator);
        return OSHMEM_SUCCESS;
    }

    assert(length > elem->length);

    /* try to check if next element is free & has enough length */
    if ((elem + elem->length < &allocator->elem[allocator->length]) && /* non-last element? */
        sshmem_ucx_shadow_is_free(elem + elem->length)              && /* next is free */
        (elem[elem->length].length + elem->length >= length))
    {
        if (elem[elem->length].length + elem->length > length) {
            sshmem_ucx_shadow_set_elem(elem + length, elem[elem->length].length +
                                                      elem->length - length,
                                                      SSHMEM_UCX_SHADOW_FREE_ELEM);
        }

        sshmem_ucx_shadow_clean_elem(elem + elem->length);
        elem->length = length;
        *new_offset  = old_offset;
        return OSHMEM_SUCCESS;
    }

    /* ok, we have to allocate new buffer */
    res = sshmem_ucx_shadow_alloc(allocator, size, new_offset);
    if (res == OSHMEM_SUCCESS) {
        /* copy data into new buffer */
        cp->copy_cb(*new_offset, old_offset, length * sizeof(*elem), cp->arg);
    }

    sshmem_ucx_shadow_free(allocator, old_offset);

    return res;
}



