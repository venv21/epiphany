SUBDIRS = help libgd gvdb lib embed src data po
if ENABLE_TESTS
SUBDIRS += tests
endif

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--enable-appstream-util	\
	--enable-debug

@CODE_COVERAGE_RULES@

# Ignore gtk theme cache files on distcheck
distuninstallcheck_listfiles = find . -type f -print | grep -v 'icon-theme.cache'

@GENERATE_CHANGELOG_RULES@
CHANGELOG_START = $(EPIPHANY_CHANGELOG_START)
CHANGELOG_GIT_FLAGS = --stat --no-color --no-decorate
dist-hook: dist-ChangeLog

MAINTAINERCLEANFILES = \
	$(GITIGNORE_MAINTAINERCLEANFILES_TOPLEVEL)	\
	$(GITIGNORE_MAINTAINERCLEANFILES_MAKEFILE_IN)	\
	$(GITIGNORE_MAINTAINERCLEANFILES_M4_LIBTOOL)	\
	m4/

-include $(top_srcdir)/git.mk
