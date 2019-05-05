/*
 * Copyright (c) 2017      Mellanox Technologies, Inc.
 *                         All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#ifndef MCA_SSHMEM_UCX_EXPORT_H
#define MCA_SSHMEM_UCX_EXPORT_H

#include "oshmem_config.h"

#include "oshmem/mca/sshmem/sshmem.h"

#include <uct/api/uct.h>

BEGIN_C_DECLS

/**
 * globally exported variable to hold the ucx component.
 */
typedef struct mca_sshmem_ucx_component_t {
    /* base component struct */
    mca_sshmem_base_component_t super;
    /* priority for ucx component */
    int priority;
} mca_sshmem_ucx_component_t;

OSHMEM_MODULE_DECLSPEC extern mca_sshmem_ucx_component_t
mca_sshmem_ucx_component;

typedef struct mca_sshmem_ucx_segment_info {
    map_segment_t       *segment;
    long                hint;
    void                *ctx;
    void*               dev_mem;
} mca_sshmem_ucx_segment_info_t;

typedef struct mca_sshmem_ucx_module_t {
    mca_sshmem_base_module_t      super;
    mca_sshmem_ucx_segment_info_t seg_info[sizeof(long) * 8];
} mca_sshmem_ucx_module_t;
extern mca_sshmem_ucx_module_t mca_sshmem_ucx_module;

END_C_DECLS

#endif /* MCA_SHMEM_UCX_EXPORT_H */
