SUBDIRS = include compat
ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CPPFLAGS += -I$(top_srcdir)/compat

AUTOMAKE_OPTIONS=foreign subdir-objects

bin_PROGRAMS=bgpq4
man_MANS=bgpq4.8

bgpq4_LDADD = $(PLATFORM_LDADD) $(PROG_LDADD)
bgpq4_LDADD += $(top_builddir)/compat/libcompat.la

bgpq4_SOURCES=bgpq4.c bgpq4.h config.h bgpq4_printer.c bgpq_expander.c \
    expander_freeall.c sx_maxsockbuf.c \
    sx_prefix.c sx_prefix.h sx_report.c sx_report.h \
    sx_slentry.c sx_slentry.h


EXTRA_DIST=bootstrap README.md CHANGES bgpq4.spec

MAINTAINERCLEANFILES=configure aclocal.m4 compile \
                     install-sh missing Makefile.in depcomp \
                     stamp-h1 config.h.in compat/Makefile.in \
		     config.guess config.sub include/Makefile.in \
		     ltmain.sh

maintainer-clean-local:
	-rm -rf m4 autom4te.cache config.h.in~
