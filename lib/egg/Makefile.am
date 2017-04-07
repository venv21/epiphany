noinst_LTLIBRARIES = libegg.la

libegg_la_SOURCES = \
	egg-animation.c			\
	egg-animation.h			\
	egg-elastic-bin.c		\
	egg-elastic-bin.h		\
	egg-frame-source.c		\
	egg-frame-source.h		\
	egg-suggestion.c		\
	egg-suggestion-entry-buffer.c	\
	egg-suggestion-entry-buffer.h	\
	egg-suggestion-entry.c		\
	egg-suggestion-entry.h		\
	egg-suggestion.h		\
	egg-suggestion-popover.c	\
	egg-suggestion-popover.h	\
	egg-suggestion-row.c		\
	egg-suggestion-row.h		\
	eggtreemultidnd.c		\
	eggtreemultidnd.h

nodist_libegg_la_SOURCES = \
	egg-resources.c	\
	egg-resources.h

libegg_la_CPPFLAGS = $(GTK_CFLAGS)

libegg_la_LIBADD = $(GTK_LIBS)

BUILT_SOURCES =
CLEANFILES =
DISTCLEANFILES =
EXTRA_DIST =

glib_resources_xml = egg.gresources.xml
glib_resources_c = egg-resources.c
glib_resources_h = egg-resources.h
glib_resources_namespace = egg
include $(top_srcdir)/build-aux/Makefile.am.gresources

-include $(top_srcdir)/git.mk
