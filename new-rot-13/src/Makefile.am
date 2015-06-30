xlator_LTLIBRARIES = new-rot-13.la
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/features

new_rot_13_la_LDFLAGS = -module -avoid-version

new_rot_13_la_SOURCES = new-rot-13.c
new_rot_13_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la 

noinst_HEADERS = new-rot-13.h

AM_CPPFLAGS = $(GF_CPPFLAGS) -I$(top_srcdir)/libglusterfs/src

AM_CFLAGS = -Wall $(GF_CFLAGS)

CLEANFILES = 
