SUBDIRS = include
ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CPPFLAGS += -I$(top_srcdir)/compat

AUTOMAKE_OPTIONS=foreign subdir-objects

bin_PROGRAMS=bgpq4
man8_MANS=bgpq4.8

bgpq4_LDADD = $(PLATFORM_LDADD) $(PROG_LDADD)

if !HAVE_STRLCPY
SUBDIRS += compat
bgpq4_LDADD += $(top_builddir)/compat/libcompat.la
endif

bgpq4_SOURCES=main.c extern.h printer.c expander.c \
    sx_maxsockbuf.c \
    sx_prefix.c sx_prefix.h \
    sx_report.c sx_report.h \
    sx_slentry.c


EXTRA_DIST=bootstrap README.md CHANGES

MAINTAINERCLEANFILES=configure aclocal.m4 compile \
                     install-sh missing Makefile.in depcomp \
                     stamp-h1 compat/Makefile.in \
		     config.guess config.sub include/Makefile.in \
		     ltmain.sh

maintainer-clean-local:
	-rm -rf m4 autom4te.cache
