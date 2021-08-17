AM_CPPFLAGS = -I$(top_srcdir)/include

noinst_LTLIBRARIES = libcompat.la libcompatnoopt.la

# compatibility functions that need to be built without optimizations
libcompatnoopt_la_CFLAGS = -O0
libcompatnoopt_la_SOURCES =

libcompat_la_SOURCES =

if !HAVE_STRLCPY
libcompat_la_SOURCES += strlcpy.c
endif
