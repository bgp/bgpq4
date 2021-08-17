AM_CPPFLAGS = -I$(top_srcdir)/include

AUTOMAKE_OPTIONS=foreign subdir-objects

SUBDIRS = include compat

ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS=bgpq4

bgpq4_SOURCES=bgpq4.c bgpq4.h config.h bgpq4_printer.c bgpq_expander.c \
    expander_freeall.c sx_maxsockbuf.c \
    sx_prefix.c sx_prefix.h sx_report.c sx_report.h \
    sx_slentry.c sx_slentry.h

dist_man8_MANS=bgpq4.8

EXTRA_DIST=bootstrap README.md CHANGES COPYRIGHT bgpq4.spec

MAINTAINERCLEANFILES=configure aclocal.m4 compile \
                     install-sh missing Makefile.in depcomp \
                     stamp-h1 config.h.in compat/Makefile.in \
		     config.guess config.sub include/Makefile.in \
		     ltmain.sh

maintainer-clean-local:
	-rm -rf m4 autom4te.cache config.h.in~
