AC_INIT(bgpq4,0.0.7,job@sobornost.net)
AM_INIT_AUTOMAKE
AC_PACKAGE_URL(https://github.com/bgp/bgpq4)
AC_CONFIG_HEADERS([config.h])
AM_SILENT_RULES([yes])

AC_PROG_CC
CC=cc
CFLAGS="${CFLAGS} -std=gnu11"

AC_PROG_INSTALL

AC_CHECK_HEADERS([sys/cdefs.h sys/queue.h sys/tree.h sys/select.h])

AC_MSG_CHECKING([for STAILQ_ interface in queue.h])

AC_CHECK_FUNCS(strlcpy)
AC_CHECK_FUNCS(pledge)

AC_CHECK_LIB(socket,socket)
AC_CHECK_LIB(nsl,getaddrinfo)

AC_CONFIG_FILES([
	Makefile
	include/Makefile
	compat/Makefile
])

AC_OUTPUT
