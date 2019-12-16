AUTOMAKE_OPTIONS=foreign subdir-objects
bin_PROGRAMS=bgpq4
bgpq4_SOURCES=bgpq4.c sx_report.c bgpq_expander.c sx_slentry.c \
              bgpq4_printer.c sx_prefix.c strlcpy.c sx_maxsockbuf.c \
              bgpq4.h config.h sx_maxsockbuf.h sx_prefix.h \
              sx_report.h sx_slentry.h sys_queue.h sys_tree.h
dist_doc_DATA=bgpq4.html
dist_man8_MANS=bgpq4.8
EXTRA_DIST=bootstrap readme.header README.md CHANGES COPYRIGHT bgpq4.spec
CLEANFILES=bgpq4.html
MAINTAINERCLEANFILES=configure aclocal.m4 compile \
                     install-sh missing Makefile.in depcomp \
                     stamp-h1 config.h.in

bgpq4.html: readme.header README.md
	cat readme.header README.md | @MARKDOWN@ > bgpq4.html

maintainer-clean-local:
	-rm -rf autom4te.cache
