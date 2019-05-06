/*
 * Copyright (c) 2013-2014 Mellanox Technologies, Inc.
 *                         All rights reserved.
 * Copyright (c) 2014 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2014      Intel, Inc. All rights reserved
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#include "oshmem_config.h"

#include "oshmem/util/oshmem_util.h"
#include "oshmem/mca/sshmem/sshmem.h"
#include "oshmem/mca/sshmem/base/base.h"
#include "oshmem/mca/memheap/memheap.h"
#include "oshmem/mca/memheap/base/base.h"

static memheap_custom_allocator_t mca_memheap_allocator = {0};

int mca_memheap_base_alloc_init(mca_memheap_map_t *map, size_t size)
{
    int ret = OSHMEM_SUCCESS;
    char * seg_filename = NULL;

    assert(map);
    assert(HEAP_SEG_INDEX == map->n_segments);

    map_segment_t *s = &map->mem_segs[map->n_segments];
    seg_filename = oshmem_get_unique_file_name(oshmem_my_proc_id());
    ret = mca_sshmem_segment_create(s, seg_filename, size);

    if (OSHMEM_SUCCESS == ret) {
        map->n_segments++;
        mca_memheap_allocator.memheap_realloc = mca_memheap.memheap_realloc;
        mca_memheap_allocator.memheap_free    = mca_memheap.memheap_free;
        s->memheap                            = &mca_memheap_allocator;
        MEMHEAP_VERBOSE(1,
                        "Memheap alloc memory: %llu byte(s), %d segments by method: %d",
                        (unsigned long long)size, map->n_segments, s->type);
    }

    free(seg_filename);

    return ret;
}

int mca_memheap_base_hint_alloc_init(mca_memheap_map_t *map, size_t size, long hint)
{
    int ret = OSHMEM_SUCCESS;
    char * seg_filename = NULL;

    assert(map);
    assert(SYMB_SEG_INDEX <= map->n_segments);

    if (!size) {
        return OSHMEM_SUCCESS;
    }

    map_segment_t *s = &map->mem_segs[map->n_segments];
    seg_filename = oshmem_get_unique_file_name(oshmem_my_proc_id());
    ret = mca_sshmem_segment_hint_create(s, seg_filename, size, hint);

    if (OSHMEM_SUCCESS == ret) {
        map->n_segments++;
        MEMHEAP_VERBOSE(1,
                        "Memheap alloc_with_hint memory: %llu byte(s), %d "
                        "segments by method: %d, with hint: %lu",
                        (unsigned long long)size, map->n_segments, s->type, hint);
    }

    free(seg_filename);

    return ret;
}

void mca_memheap_base_alloc_exit(mca_memheap_map_t *map)
{
    if (map) {
        map_segment_t *s = &map->mem_segs[HEAP_SEG_INDEX];

        assert(s);

        mca_sshmem_segment_detach(s, NULL);
        mca_sshmem_unlink(s);
    }
}

int mca_memheap_base_alloc_with_hint(size_t size, long hint, void** ptr)
{
    int i;
    int ret;
    map_segment_t *s;

    for (i = SYMB_SEG_INDEX; i < mca_memheap_base_map.n_segments; i++) {
        s = &mca_memheap_base_map.mem_segs[i];
        if (s->memheap && s->memheap->memheap_alloc_with_hint) {
            ret = s->memheap->memheap_alloc_with_hint(size, hint, ptr);
            if (ret == OSHMEM_SUCCESS) {
                return OSHMEM_SUCCESS;
            } else if (ret != OSHMEM_ERR_NOT_IMPLEMENTED) {
                return ret;
            }
        }
    }

    /* no one provider supports for requested hint, ok, let's try
     * to allocate regular buffer */
    return MCA_MEMHEAP_CALL(alloc(size, ptr));
}
