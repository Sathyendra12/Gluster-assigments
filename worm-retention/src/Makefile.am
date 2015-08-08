xlator_LTLIBRARIES = worm-retention.la
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/features

worm-retention_la_LDFLAGS = -module -avoid-version

worm-retention_la_SOURCES = worm-retention.c
worm-retention_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la 

noinst_HEADERS = worm-retention.h wr-mem-types.h

AM_CPPFLAGS = $(GF_CPPFLAGS) -I$(top_srcdir)/libglusterfs/src

AM_CFLAGS = -Wall $(GF_CFLAGS)

CLEANFILES = 
