xlator_LTLIBRARIES = file-tracker.la
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/features

file_tracker_la_LDFLAGS = -module -avoid-version

file_tracker_la_SOURCES = file-tracker.c
file_tracker_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la 

noinst_HEADERS = file-tracker.h

AM_CPPFLAGS = $(GF_CPPFLAGS) -I$(top_srcdir)/libglusterfs/src

AM_CFLAGS = -Wall $(GF_CFLAGS)

CLEANFILES = 
