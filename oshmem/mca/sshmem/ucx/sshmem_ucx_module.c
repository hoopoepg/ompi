/*
 * Copyright (c) 2017      Mellanox Technologies, Inc.
 *                         All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#include "oshmem_config.h"

#include "opal/constants.h"
#include "opal/util/output.h"
#include "opal/util/path.h"
#include "opal/util/show_help.h"
#include "orte/util/show_help.h"

#include "oshmem/proc/proc.h"
#include "oshmem/mca/sshmem/sshmem.h"
#include "oshmem/include/shmemx.h"
#include "oshmem/mca/sshmem/base/base.h"
#include "oshmem/util/oshmem_util.h"
#include "oshmem/mca/spml/ucx/spml_ucx.h"

#include "sshmem_ucx.h"

#include <ucs/sys/math.h>

#if HAVE_UCX_DEVICE_MEM
#include <ucp/core/ucp_resource.h>
#include <uct/ib/base/ib_alloc.h>
#endif


/* ////////////////////////////////////////////////////////////////////////// */
/* local functions */
static int
module_init(void);

static int
segment_create(map_segment_t *ds_buf,
               const char *file_name,
               size_t size);

static int
segment_hint_create(map_segment_t *ds_buf,
                    const char *file_name,
                    size_t size, long hint);

static void *
segment_attach(map_segment_t *ds_buf, sshmem_mkey_t *mkey);

static int
segment_detach(map_segment_t *ds_buf, sshmem_mkey_t *mkey);

static int
segment_unlink(map_segment_t *ds_buf);

static int
module_finalize(void);

static int
sshmem_ucx_memheap_alloc_with_hint(size_t size, long hint, void** ptr);

static int
sshmem_ucx_memheap_realloc(size_t size, void* old_ptr, void** new_ptr);

static int
sshmem_ucx_memheap_free(void* ptr);

/*
 * ucx shmem module
 */
mca_sshmem_ucx_module_t mca_sshmem_ucx_module = {
    /* super */
    .super = {
        .module_init         = module_init,
        .segment_create      = segment_create,
        .segment_hint_create = segment_hint_create,
        .segment_attach      = segment_attach,
        .segment_detach      = segment_detach,
        .unlink              = segment_unlink,
        .module_finalize     = module_finalize
    }
};

static int
module_init(void)
{
    /* nothing to do */
    return OSHMEM_SUCCESS;
}

/* ////////////////////////////////////////////////////////////////////////// */
static int
module_finalize(void)
{
    /* nothing to do */
    return OSHMEM_SUCCESS;
}

/* ////////////////////////////////////////////////////////////////////////// */

static int
segment_create_internal(map_segment_t *ds_buf, ucp_mem_map_params_t *params)
{
    int rc = OSHMEM_SUCCESS;
    mca_spml_ucx_t *spml = (mca_spml_ucx_t *)mca_spml.self;
    ucp_mem_attr_t mem_attr;
    ucp_mem_h mem_h;
    ucs_status_t status;

    assert(ds_buf);

    /* init the contents of map_segment_t */
    shmem_ds_reset(ds_buf);

    if (spml->heap_reg_nb) {
        params->flags |= UCP_MEM_MAP_NONBLOCK;
    }

    status = ucp_mem_map(spml->ucp_context, params, &mem_h);
    if (UCS_OK != status) {
        opal_output_verbose(0, oshmem_sshmem_base_framework.framework_output,
                            "ucp_mem_map() failed: %s\n", ucs_status_string(status));
        rc = OSHMEM_ERROR;
        goto out;
    }

    mem_attr.field_mask = UCP_MEM_ATTR_FIELD_ADDRESS | UCP_MEM_ATTR_FIELD_LENGTH;
    status = ucp_mem_query(mem_h, &mem_attr);

    ds_buf->super.va_base = mem_attr.address;
    ds_buf->seg_size      = mem_attr.length;
    ds_buf->super.va_end  = (void*)((uintptr_t)ds_buf->super.va_base + ds_buf->seg_size);
    ds_buf->context       = mem_h;
    ds_buf->type          = MAP_SEGMENT_ALLOC_UCX;

out:
    OPAL_OUTPUT_VERBOSE(
          (70, oshmem_sshmem_base_framework.framework_output,
           "%s: %s: create %s "
           "(id: %d, addr: %p size: %lu)\n",
           mca_sshmem_ucx_component.super.base_version.mca_type_name,
           mca_sshmem_ucx_component.super.base_version.mca_component_name,
           (rc ? "failure" : "successful"),
           ds_buf->seg_id, ds_buf->super.va_base, (unsigned long)ds_buf->seg_size)
      );
    return rc;
}

static int
segment_create(map_segment_t *ds_buf,
               const char *file_name,
               size_t size)
{
    ucp_mem_map_params_t mem_map_params = {
        .field_mask = UCP_MEM_MAP_PARAM_FIELD_ADDRESS |
                      UCP_MEM_MAP_PARAM_FIELD_LENGTH |
                      UCP_MEM_MAP_PARAM_FIELD_FLAGS,

        .address    = (void *)mca_sshmem_base_start_address,
        .length     = size,
        .flags      = UCP_MEM_MAP_ALLOCATE|UCP_MEM_MAP_FIXED,
    };

    return segment_create_internal(ds_buf, &mem_map_params);
}


static mca_memheap_base_module_t sshmem_ucx_allocator = {
    /* memheap interface to manage memory */
    .memheap_alloc_with_hint = sshmem_ucx_memheap_alloc_with_hint,
    .memheap_realloc         = sshmem_ucx_memheap_realloc,
    .memheap_free            = sshmem_ucx_memheap_free
};

static int
segment_hint_create(map_segment_t *ds_buf, const char *file_name, size_t size,
                    long hint)
{
#if HAVE_UCX_DEVICE_MEM
    mca_spml_ucx_t *spml = (mca_spml_ucx_t *)mca_spml.self;
    uct_ib_device_mem_h dev_mem;
    ucs_status_t status;
    void *address;
    size_t length;
    uct_md_h uct_md;
    int ret;

    if (!(hint & SHMEM_HINT_DEVICE_NIC_MEM)) {
        return OSHMEM_ERR_NOT_IMPLEMENTED;
    }

    uct_md = ucp_context_find_tl_md(spml->ucp_context, "mlx5");
    if (uct_md == NULL) {
        opal_output_verbose(0, oshmem_sshmem_base_framework.framework_output,
                            "ucp_context_find_tl_md() returned NULL\n");
        return OSHMEM_ERR_NOT_SUPPORTED;
    }

    length = size;
    address = NULL;
    status = uct_ib_md_alloc_device_mem(uct_md, &length, &address, UCT_MD_MEM_ACCESS_ALL,
                                        "sshmem_seg", &dev_mem);
    if (status != UCS_OK) {
        opal_output_verbose(0, oshmem_sshmem_base_framework.framework_output,
                            "uct_ib_md_alloc_dm() failed: %s\n",
                            ucs_status_string(status));
        return OSHMEM_ERR_NOT_SUPPORTED;
    }

    opal_output_verbose(3, oshmem_sshmem_base_framework.framework_output,
                        "uct_ib_md_alloc_dm() returned address %p\n",
                        address);

    ucp_mem_map_params_t mem_map_params = {
        .field_mask = UCP_MEM_MAP_PARAM_FIELD_ADDRESS |
                      UCP_MEM_MAP_PARAM_FIELD_LENGTH |
                      UCP_MEM_MAP_PARAM_FIELD_FLAGS,
        .address    = address,
        .length     = size,
        .flags      = 0
    };

    ret = segment_create_internal(ds_buf, &mem_map_params);
    if (ret == OSHMEM_SUCCESS) {
        ds_buf->memheap                          = &sshmem_ucx_allocator;
        /* TODO: added lookup of free element, for now only
         * one hint flag is supported, so, element [0] may be used */
        mca_sshmem_ucx_module.seg_info[0].segment  = ds_buf;
        mca_sshmem_ucx_module.seg_info[0].hint     = hint;
        mca_sshmem_ucx_module.seg_info[0].dev_mem  = dev_mem;

        opal_output_verbose(3, oshmem_sshmem_base_framework.framework_output,
                            "created DM segment at %p len %zu\n",
                            address, size);
    } else {
        uct_ib_md_release_device_mem(dev_mem);
    }

    return ret;
#else
    return OSHMEM_ERR_NOT_SUPPORTED;
#endif
}

static void *
segment_attach(map_segment_t *ds_buf, sshmem_mkey_t *mkey)
{
    assert(ds_buf);
    assert(mkey->va_base == 0);

    OPAL_OUTPUT((oshmem_sshmem_base_framework.framework_output,
                "can not attach to ucx segment\n"));
    oshmem_shmem_abort(-1);
    return NULL;
}

static int
segment_detach(map_segment_t *ds_buf, sshmem_mkey_t *mkey)
{
    OPAL_OUTPUT_VERBOSE(
        (70, oshmem_sshmem_base_framework.framework_output,
         "%s: %s: detaching "
            "(id: %d, addr: %p size: %lu)\n",
            mca_sshmem_ucx_component.super.base_version.mca_type_name,
            mca_sshmem_ucx_component.super.base_version.mca_component_name,
            ds_buf->seg_id, ds_buf->super.va_base, (unsigned long)ds_buf->seg_size)
    );

    /* reset the contents of the map_segment_t associated with this
     * shared memory segment.
     */
    shmem_ds_reset(ds_buf);

    return OSHMEM_SUCCESS;
}

static mca_sshmem_ucx_segment_info_t *sshmem_ucx_memheap_lookup_info(map_segment_t *ds_buf)
{
    unsigned i;

    for (i = 0; i < sizeof(mca_sshmem_ucx_module.seg_info) /
                    sizeof(mca_sshmem_ucx_module.seg_info[0]); i++) {
        if (ds_buf == mca_sshmem_ucx_module.seg_info[i].segment) {
            return &mca_sshmem_ucx_module.seg_info[i];
        }
    }
    return NULL;
}

static int
segment_unlink(map_segment_t *ds_buf)
{
    mca_spml_ucx_t *spml = (mca_spml_ucx_t *)mca_spml.self;
    mca_sshmem_ucx_segment_info_t *info;

    assert(ds_buf);

    ucp_mem_unmap(spml->ucp_context, (ucp_mem_h)ds_buf->context);

#if HAVE_UCX_DEVICE_MEM
    info = sshmem_ucx_memheap_lookup_info(ds_buf);
    opal_output_verbose(3, oshmem_sshmem_base_framework.framework_output,
                        "segment_unlink() info=%p\n",
                         info);
    if (info) {
        uct_ib_md_release_device_mem(info->dev_mem);
    }
#endif

    OPAL_OUTPUT_VERBOSE(
        (70, oshmem_sshmem_base_framework.framework_output,
         "%s: %s: unlinking "
            "(id: %d, addr: %p size: %lu)\n",
            mca_sshmem_ucx_component.super.base_version.mca_type_name,
            mca_sshmem_ucx_component.super.base_version.mca_component_name,
            ds_buf->seg_id, ds_buf->super.va_base, (unsigned long)ds_buf->seg_size)
    );

    ds_buf->seg_id = MAP_SEGMENT_SHM_INVALID;
    MAP_SEGMENT_INVALIDATE(ds_buf);

    return OSHMEM_SUCCESS;
}

static mca_sshmem_ucx_segment_info_t *sshmem_ucx_memheap_get_info(long hint)
{
    unsigned i;

    for (i = 0; i < sizeof(mca_sshmem_ucx_module.seg_info) /
                    sizeof(mca_sshmem_ucx_module.seg_info[0]); i++) {
        if (hint & mca_sshmem_ucx_module.seg_info[i].hint) {
            return &mca_sshmem_ucx_module.seg_info[i];
        }
    }
    return NULL;
}

#define SSHMEM_UCX_MEMHEAP_FREE_ELEM (1 << 31)

typedef struct sshmem_ucx_memheap_alloc_elem {
    uint32_t flags;
    uint32_t length;
} sshmem_ucx_memheap_alloc_elem_t;

typedef struct sshmem_ucx_memheap_allocator {
    size_t                          length;
    sshmem_ucx_memheap_alloc_elem_t elem[];
} sshmem_ucx_memheap_allocator_t;


static int sshmem_ucx_memheap_is_free(sshmem_ucx_memheap_alloc_elem_t *elem)
{
    return elem->flags & SSHMEM_UCX_MEMHEAP_FREE_ELEM;
}

static void sshmem_ucx_memheap_set_elem(sshmem_ucx_memheap_alloc_elem_t *elem,
                                        size_t length, uint32_t flags)
{
    elem->flags  = flags;
    elem->length = length;
}

static void sshmem_ucx_memheap_clean_elem(sshmem_ucx_memheap_alloc_elem_t *elem)
{
    assert(elem->length);

    elem->flags  = 0;
    elem->length = 0;
}

static size_t sshmem_ucx_memheap_get_length(size_t size)
{
    sshmem_ucx_memheap_allocator_t *allocator = NULL;

    return ucs_align_up(size, sizeof(allocator->elem[0])) / sizeof(allocator->elem[0]);
}

static sshmem_ucx_memheap_allocator_t *sshmem_ucx_memheap_create_allocator(size_t size)
{
    sshmem_ucx_memheap_allocator_t *allocator;
    size_t length = sshmem_ucx_memheap_get_length(size);

    allocator = malloc(sizeof(*allocator) + length * sizeof(allocator->elem[0]));
    if (allocator) {
        /* allocate data */
        allocator->length = length;
        memset(allocator->elem, 0, length * sizeof(allocator->elem[0]));

        /* init data: set first element as free to whole buffer */
        sshmem_ucx_memheap_set_elem(&allocator->elem[0], length, SSHMEM_UCX_MEMHEAP_FREE_ELEM);
    }

    return allocator;
}

static int
sshmem_ucx_memheap_alloc_internal(size_t size,
                                  mca_sshmem_ucx_segment_info_t *info,
                                  void **ptr)
{
    sshmem_ucx_memheap_allocator_t *allocator = info->ctx;
    size_t length = sshmem_ucx_memheap_get_length(size);
    sshmem_ucx_memheap_alloc_elem_t *elem;

    if (!size) {
        return OSHMEM_SUCCESS;
    }

    for (elem = &allocator->elem[0]; elem < &allocator->elem[allocator->length];
         elem += elem->length) {
        if (sshmem_ucx_memheap_is_free(elem) &&
            (elem->length >= length)) {
            /* found suitable free element */
            if (elem->length > length) {
                /* create new 'free' element for tail of current buffer */
                sshmem_ucx_memheap_set_elem(elem + length, elem->length - length,
                                            SSHMEM_UCX_MEMHEAP_FREE_ELEM);
            }

            sshmem_ucx_memheap_set_elem(elem, length, 0);
            *ptr = (char*)info->segment->super.va_base +
                   ((char*)&allocator->elem[0] - (char*)elem);
            assert(*ptr >= info->segment->super.va_base);
            assert(*ptr < info->segment->super.va_end);
            return OSHMEM_SUCCESS;
        }
    }

    return OSHMEM_ERR_OUT_OF_RESOURCE;
}


static sshmem_ucx_memheap_alloc_elem_t
*sshmem_ucx_memheap_get_elem(mca_sshmem_ucx_segment_info_t *info, void *ptr)
{
    sshmem_ucx_memheap_allocator_t *allocator = info->ctx;

    assert(ptr >= info->segment->super.va_base);
    assert(ptr < info->segment->super.va_end);

    return (sshmem_ucx_memheap_alloc_elem_t*)((char*)ptr - (char*)info->segment->super.va_base +
                                              (char*)&allocator->elem[0]);
}

static void sshmem_ucx_memheap_merge_blocks(sshmem_ucx_memheap_allocator_t *allocator)
{
    sshmem_ucx_memheap_alloc_elem_t *elem;
    sshmem_ucx_memheap_alloc_elem_t *elem_clean;

    /* merge free elements */
    elem = allocator->elem;
    while ((elem < &allocator->elem[allocator->length]) &&
           (elem->length < allocator->length)) {
        if (sshmem_ucx_memheap_is_free(elem) &&
            sshmem_ucx_memheap_is_free(elem + elem->length)) {
            /* current & next elements are free, should be merged */
            elem_clean = elem + elem->length;
            elem->length += elem_clean->length;
            /* clean element which is merged */
            sshmem_ucx_memheap_clean_elem(elem_clean);
        } else {
            elem += elem->length;
        }
    }
}

static int
sshmem_ucx_memheap_free_internal(mca_sshmem_ucx_segment_info_t *info, void *ptr)
{
    sshmem_ucx_memheap_allocator_t *allocator = info->ctx;
    sshmem_ucx_memheap_alloc_elem_t *elem = sshmem_ucx_memheap_get_elem(info, ptr);

    elem->flags |= SSHMEM_UCX_MEMHEAP_FREE_ELEM;

    /* merge free elements */
    sshmem_ucx_memheap_merge_blocks(allocator);

    return OSHMEM_SUCCESS;
}

static int sshmem_ucx_memheap_alloc_with_hint(size_t size, long hint, void** ptr)
{
    mca_sshmem_ucx_segment_info_t *info;

    if (!(hint & SHMEM_HINT_DEVICE_NIC_MEM)) {
        return OSHMEM_ERR_NOT_IMPLEMENTED;
    }

    info = sshmem_ucx_memheap_get_info(hint);
    if (!info) {
        return OSHMEM_ERR_OUT_OF_RESOURCE;
    }

    if (!info->ctx) {
        info->ctx = sshmem_ucx_memheap_create_allocator(info->segment->seg_size);
        if (!info->ctx) {
            return OSHMEM_ERR_OUT_OF_RESOURCE;
        }
    }

    return sshmem_ucx_memheap_alloc_internal(size, info, ptr);
}

static int sshmem_ucx_memheap_realloc(size_t size, void* old_ptr, void** new_ptr)
{
    size_t length = sshmem_ucx_memheap_get_length(size);
    map_segment_t *seg;
    mca_sshmem_ucx_segment_info_t *info;
    sshmem_ucx_memheap_alloc_elem_t *elem;
    sshmem_ucx_memheap_allocator_t *allocator;
    int res;
    size_t i;
    long *src;
    long *dst;

    if (!size) {
        return sshmem_ucx_memheap_free(old_ptr);
    }

    if (!old_ptr) {
        /* should not be here */
        return OSHMEM_ERROR;
    }

    seg = memheap_find_va(old_ptr);
    if (!seg) {
        return OSHMEM_ERROR;
    }

    info = sshmem_ucx_memheap_lookup_info(seg);
    if (!info) {
        return OSHMEM_ERR_OUT_OF_RESOURCE;
    }
    assert(info->ctx);

    allocator = info->ctx;
    elem      = sshmem_ucx_memheap_get_elem(info, old_ptr);

    if (length == elem->length) {
        return OSHMEM_SUCCESS;
    }

    if (length < elem->length) {
        /* requested block is shorter than allocated block
         * then just cut current buffer */
        sshmem_ucx_memheap_set_elem(elem + length, 
                                    elem->length - length,
                                    SSHMEM_UCX_MEMHEAP_FREE_ELEM);
        elem->length = length;
        sshmem_ucx_memheap_merge_blocks(info->ctx);
        return OSHMEM_SUCCESS;
    }

    assert(length > elem->length);

    /* try to check if next element is free & has enough length */
    if ((elem + elem->length < &allocator->elem[allocator->length]) && /* non-last element? */
        sshmem_ucx_memheap_is_free(elem + elem->length)            && /* next is free */
        (elem[elem->length].length + elem->length >= length))
    {
        if (elem[elem->length].length + elem->length > length) {
            sshmem_ucx_memheap_set_elem(elem + length, elem[elem->length].length +
                                                       elem->length - length,
                                                       SSHMEM_UCX_MEMHEAP_FREE_ELEM);
        }

        sshmem_ucx_memheap_clean_elem(elem + elem->length);
        elem->length = length;
        return OSHMEM_SUCCESS;
    }

    /* ok, we have to allocate new buffer */
    res = sshmem_ucx_memheap_alloc_internal(size, info, new_ptr);
    if (res == OSHMEM_SUCCESS) {
        /* copy data into new buffer */
        for (i = 0, src = old_ptr, dst = *new_ptr; i < length; i++, src++, dst++) {
            *dst = *src;
        }
    }

    sshmem_ucx_memheap_free_internal(info, old_ptr);

    return res;
}

static int sshmem_ucx_memheap_free(void* ptr)
{
    map_segment_t *seg;
    mca_sshmem_ucx_segment_info_t *info;

    if (!ptr) {
        return OSHMEM_SUCCESS;
    }

    seg = memheap_find_va(ptr);
    if (!seg) {
        return OSHMEM_ERROR;
    }

    info = sshmem_ucx_memheap_lookup_info(seg);
    if (!info) {
        return OSHMEM_ERR_OUT_OF_RESOURCE;
    }
    assert(info->ctx);

    return sshmem_ucx_memheap_free_internal(info, ptr);
}

