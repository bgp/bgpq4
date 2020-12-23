AUTOMAKE_OPTIONS=foreign subdir-objects
bin_PROGRAMS=bgpq4
bgpq4_SOURCES=bgpq4.c bgpq4.h config.h bgpq4_printer.c bgpq_expander.c \
			  expander_freeall.c expander_freeall.h strlcpy.c sx_maxsockbuf.c \
			  sx_maxsockbuf.h sx_prefix.c sx_prefix.h sx_report.c sx_report.h \
			  sx_slentry.c sx_slentry.h sys_queue.h sys_tree.h
dist_man8_MANS=bgpq4.8
EXTRA_DIST=bootstrap readme.header README.md CHANGES COPYRIGHT bgpq4.spec
MAINTAINERCLEANFILES=configure aclocal.m4 compile \
                     install-sh missing Makefile.in depcomp \
                     stamp-h1 config.h.in

maintainer-clean-local:
	-rm -rf autom4te.cache config.h.in~
