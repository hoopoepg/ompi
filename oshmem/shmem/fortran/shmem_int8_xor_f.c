/*
 * Copyright (c) 2018      Mellanox Technologies, Inc.
 *                         All rights reserved.
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#include "oshmem_config.h"
#include "oshmem/shmem/fortran/bindings.h"
#include "oshmem/include/shmem.h"
#include "oshmem/shmem/shmem_api_logger.h"
#include "oshmem/runtime/runtime.h"
#include "oshmem/mca/atomic/atomic.h"
#include "ompi/datatype/ompi_datatype.h"
#include "oshmem/op/op.h"
#include "stdio.h"

#if OSHMEM_PROFILING
#include "oshmem/shmem/fortran/profile/pbindings.h"
SHMEM_GENERATE_WEAK_BINDINGS(SHMEM_INT8_XOR, shmem_int8_xor)
#include "oshmem/shmem/fortran/profile/defines.h"
#endif

SHMEM_GENERATE_FORTRAN_BINDINGS_SUB (void,
        SHMEM_INT8_XOR,
        shmem_int8_xor_,
        shmem_int8_xor__,
        shmem_int8_xor_f,
        (FORTRAN_POINTER_T target, FORTRAN_POINTER_T value, MPI_Fint *pe),
        (target,value,pe) )

void shmem_int8_xor_f(FORTRAN_POINTER_T target, FORTRAN_POINTER_T value, MPI_Fint *pe)
{
    MCA_ATOMIC_CALL(xor(FPTR_2_VOID_PTR(target),
        FPTR_2_INT(value, sizeof(ompi_fortran_integer8_t)),
        sizeof(value),
        OMPI_FINT_2_INT(*pe)));
}

