/*
 * Public domain
 * sys/types.h compatibility shim
 */

#include_next <sys/types.h>

#ifndef LIBCOMPAT_SYS_TYPES_H
#define LIBCOMPAT_SYS_TYPES_H

#include <stdint.h>

#ifdef __MINGW32__
#include <_bsd_types.h>
#endif

#if !defined(HAVE_ATTRIBUTE__DEAD) && !defined(__dead)
#define __dead      __attribute__((__noreturn__))
#endif

#if !defined(HAVE_ATTRIBUTE__BOUNDED__) && !defined(__bounded__)
# define __bounded__(x, y, z)
#endif

#endif
