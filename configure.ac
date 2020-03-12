AC_INIT(bgpq4,0.0.6,job@ntt.net)
AM_INIT_AUTOMAKE
AC_PACKAGE_URL(https://github.com/bgp/bgpq4)
AM_CONFIG_HEADER(config.h)
AM_SILENT_RULES([yes])

AC_PROG_CC
CC=cc
CFLAGS="${CFLAGS} -std=gnu11"

AC_PROG_INSTALL

AC_CHECK_HEADERS([sys/cdefs.h sys/queue.h sys/tree.h sys/select.h])

AC_MSG_CHECKING([for STAILQ_ interface in queue.h])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
#if HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include "sys_queue.h"
#endif
struct blah {
   STAILQ_ENTRY(blah) next;
};
])],
[AC_MSG_RESULT(yes)
AC_DEFINE([HAVE_STAILQ_IN_SYS_QUEUE], [1], [sys/queue.h have STAILQ_])],
[AC_MSG_RESULT(no)])


AC_CHECK_PROGS([MARKDOWN], [markdown_py markdown2 markdown], [echo])

AC_CHECK_FUNCS(strlcpy)
AC_CHECK_FUNCS(pledge)

AC_CHECK_LIB(socket,socket)
AC_CHECK_LIB(nsl,getaddrinfo)

AC_OUTPUT(Makefile)

