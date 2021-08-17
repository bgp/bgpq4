AM_CPPFLAGS = -I$(top_srcdir)/include

noinst_LTLIBRARIES = libcompat.la

libcompat_la_SOURCES =
libcompat_la_LIBADD = $(PLATFORM_LDADD)

if !HAVE_STRLCPY
libcompat_la_SOURCES += strlcpy.c
endif
