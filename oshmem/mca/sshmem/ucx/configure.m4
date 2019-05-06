/*
 * Copyright (c) 2017      Mellanox Technologies, Inc.
 *                         All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

# MCA_oshmem_sshmem_ucx_CONFIG([action-if-can-compile],
#                    [action-if-cant-compile])
# ------------------------------------------------
AC_DEFUN([MCA_oshmem_sshmem_ucx_CONFIG],[
    AC_CONFIG_FILES([oshmem/mca/sshmem/ucx/Makefile])

    OMPI_CHECK_UCX([sshmem_ucx],
                   [sshmem_ucx_happy="yes"],
                   [sshmem_ucx_happy="no"])

    AS_IF([test "$sshmem_ucx_happy" = "yes"],
          [$1],
          [$2])

	# Check for UCX device memory allocation support
    save_LDFLAGS="$LDFLAGS"
    save_LIBS="$LIBS"
    save_CPPFLAGS="$CPPFLAGS"
    
    # TODO lib64, and what if $ompi_check_ucx_dir is not set?
    alloc_dm_LDFLAGS=" -L$ompi_check_ucx_libdir/ucx"
    alloc_dm_LIBS=" -luct_ib"
    CPPFLAGS+=" $sshmem_ucx_CPPFLAGS"
    LDFLAGS+=" $sshmem_ucx_LDFLAGS $alloc_dm_LDFLAGS"
    LIBS+=" $sshmem_ucx_LIBS $alloc_dm_LIBS"
    
    # TODO remove debug prints below
    AC_MSG_NOTICE([ompi_check_ucx_dir=$ompi_check_ucx_dir])
    AC_MSG_NOTICE([ompi_check_ucx_libdir=$ompi_check_ucx_libdir])
    AC_MSG_NOTICE([alloc_dm_LDFLAGS=$alloc_dm_LDFLAGS])
    AC_MSG_NOTICE([alloc_dm_LIBS=$alloc_dm_LIBS])
    AC_MSG_NOTICE([sshmem_ucx_LDFLAGS=$sshmem_ucx_LDFLAGS])
    AC_MSG_NOTICE([sshmem_ucx_LIBS=$sshmem_ucx_LIBS])
    
    AC_LANG_PUSH([C])
    AC_LINK_IFELSE([AC_LANG_PROGRAM(
          [[
            #include <ucp/core/ucp_resource.h>
            #include <uct/ib/base/ib_alloc.h>
          ]],
          [[
            uct_md_h md = ucp_context_find_tl_md((ucp_context_h)NULL, "");
            (void)uct_ib_md_alloc_device_mem(md, NULL, NULL, 0, "", NULL);
            uct_ib_md_release_device_mem(NULL);
          ]])],
          [
           AC_MSG_NOTICE([UCX device memory allocation is supported])
           AC_DEFINE([HAVE_UCX_DEVICE_MEM], [1], [Support for device memory allocation])
           sshmem_ucx_LIBS+=" $alloc_dm_LIBS"
           sshmem_ucx_LDFLAGS+=" $alloc_dm_LDFLAGS"
          ],
          [AC_MSG_NOTICE([UCX device memory allocation is not supported])])
    AC_LANG_POP([C])

    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
    LIBS="$save_LIBS"

    # substitute in the things needed to build ucx 
    AC_SUBST([sshmem_ucx_CFLAGS])
    AC_SUBST([sshmem_ucx_CPPFLAGS])
    AC_SUBST([sshmem_ucx_LDFLAGS])
    AC_SUBST([sshmem_ucx_LIBS])
])dnl

