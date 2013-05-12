# Makefile.in generated by automake 1.11.1 from Makefile.am.
# modules/afmef/Makefile.  Generated from Makefile.in by configure.

# Copyright (C) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002,
# 2003, 2004, 2005, 2006, 2007, 2008, 2009  Free Software Foundation,
# Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.





pkgdatadir = $(datadir)/syslog-ng
pkgincludedir = $(includedir)/syslog-ng
pkglibdir = $(libdir)/syslog-ng
pkglibexecdir = $(libexecdir)/syslog-ng
am__cd = CDPATH="$${ZSH_VERSION+.}$(PATH_SEPARATOR)" && cd
install_sh_DATA = $(install_sh) -c -m 644
install_sh_PROGRAM = $(install_sh) -c
install_sh_SCRIPT = $(install_sh) -c
INSTALL_HEADER = $(INSTALL_DATA)
transform = $(program_transform_name)
NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
build_triplet = x86_64-unknown-linux-gnu
host_triplet = x86_64-unknown-linux-gnu
DIST_COMMON = $(srcdir)/Makefile.am $(srcdir)/Makefile.in \
	$(top_srcdir)/build/lex-rules.am afmef-grammar.c
subdir = modules/afmef
ACLOCAL_M4 = $(top_srcdir)/aclocal.m4
am__aclocal_m4_deps = $(top_srcdir)/m4/ax_cflags_gcc_option.m4 \
	$(top_srcdir)/m4/libtool.m4 $(top_srcdir)/m4/ltoptions.m4 \
	$(top_srcdir)/m4/ltsugar.m4 $(top_srcdir)/m4/ltversion.m4 \
	$(top_srcdir)/m4/lt~obsolete.m4 $(top_srcdir)/m4/pkg.m4 \
	$(top_srcdir)/configure.in
am__configure_deps = $(am__aclocal_m4_deps) $(CONFIGURE_DEPENDENCIES) \
	$(ACLOCAL_M4)
mkinstalldirs = $(install_sh) -d
CONFIG_HEADER = $(top_builddir)/config.h
CONFIG_CLEAN_FILES =
CONFIG_CLEAN_VPATH_FILES =
am__vpath_adj_setup = srcdirstrip=`echo "$(srcdir)" | sed 's|.|.|g'`;
am__vpath_adj = case $$p in \
    $(srcdir)/*) f=`echo "$$p" | sed "s|^$$srcdirstrip/||"`;; \
    *) f=$$p;; \
  esac;
am__strip_dir = f=`echo $$p | sed -e 's|^.*/||'`;
am__install_max = 40
am__nobase_strip_setup = \
  srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*|]/\\\\&/g'`
am__nobase_strip = \
  for p in $$list; do echo "$$p"; done | sed -e "s|$$srcdirstrip/||"
am__nobase_list = $(am__nobase_strip_setup); \
  for p in $$list; do echo "$$p $$p"; done | \
  sed "s| $$srcdirstrip/| |;"' / .*\//!s/ .*/ ./; s,\( .*\)/[^/]*$$,\1,' | \
  $(AWK) 'BEGIN { files["."] = "" } { files[$$2] = files[$$2] " " $$1; \
    if (++n[$$2] == $(am__install_max)) \
      { print $$2, files[$$2]; n[$$2] = 0; files[$$2] = "" } } \
    END { for (dir in files) print dir, files[dir] }'
am__base_list = \
  sed '$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;s/\n/ /g' | \
  sed '$$!N;$$!N;$$!N;$$!N;s/\n/ /g'
am__installdirs = "$(DESTDIR)$(moduledir)"
LTLIBRARIES = $(module_LTLIBRARIES)
am__DEPENDENCIES_1 =
libafmef_notls_la_DEPENDENCIES = $(am__DEPENDENCIES_1) \
	$(am__DEPENDENCIES_1) $(am__DEPENDENCIES_1)
am__objects_1 =
am_libafmef_notls_la_OBJECTS = libafmef_notls_la-afmef.lo \
	libafmef_notls_la-afmef-grammar.lo \
	libafmef_notls_la-afmef-parser.lo \
	libafmef_notls_la-afmef-plugin.lo $(am__objects_1)
libafmef_notls_la_OBJECTS = $(am_libafmef_notls_la_OBJECTS)
libafmef_notls_la_LINK = $(LIBTOOL) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) \
	$(libafmef_notls_la_LDFLAGS) $(LDFLAGS) -o $@
DEFAULT_INCLUDES = -I. -I$(top_builddir)
depcomp = $(SHELL) $(top_srcdir)/depcomp
am__depfiles_maybe = depfiles
am__mv = mv -f
COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
LTCOMPILE = $(LIBTOOL) --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) \
	--mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
	$(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
CCLD = $(CC)
LINK = $(LIBTOOL) --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) \
	--mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) \
	$(LDFLAGS) -o $@
YACCCOMPILE = $(YACC) $(YFLAGS) $(AM_YFLAGS)
LTYACCCOMPILE = $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) \
	--mode=compile $(YACC) $(YFLAGS) $(AM_YFLAGS)
YLWRAP = $(top_srcdir)/ylwrap
SOURCES = $(libafmef_notls_la_SOURCES)
DIST_SOURCES = $(libafmef_notls_la_SOURCES)
DATA = $(noinst_DATA)
ETAGS = etags
CTAGS = ctags
DISTFILES = $(DIST_COMMON) $(DIST_SOURCES) $(TEXINFOS) $(EXTRA_DIST)
ACLOCAL = ${SHELL} /home/dthk/syslog-ng-3.2.5/missing --run aclocal-1.11
AMTAR = ${SHELL} /home/dthk/syslog-ng-3.2.5/missing --run tar
AR = ar
AUTOCONF = ${SHELL} /home/dthk/syslog-ng-3.2.5/missing --run autoconf
AUTOHEADER = ${SHELL} /home/dthk/syslog-ng-3.2.5/missing --run autoheader
AUTOMAKE = ${SHELL} /home/dthk/syslog-ng-3.2.5/missing --run automake-1.11
AWK = gawk
BASE_LIBS =  -lrt -lnsl
CC = gcc -std=gnu99
CCDEPMODE = depmode=gcc3
CFLAGS =  -Wall -g
CFLAGS_NOWARN_POINTER_SIGN =  -Wno-pointer-sign
CORE_DEPS_LIBS =   -lrt -lnsl -Wl,--export-dynamic -lgmodule-2.0 -lglib-2.0   -L/usr/local/lib -levtlog       -ldl
CPP = gcc -std=gnu99 -E
CPPFLAGS =  -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include   -I/usr/local/include/eventlog        -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
CURRDATE = Tue, 07 May 2013 19:40:18 -0500
CYGPATH_W = echo
DEFS = -DHAVE_CONFIG_H
DEPDIR = .deps
DSYMUTIL = 
DUMPBIN = 
ECHO_C = 
ECHO_N = -n
ECHO_T = 
EGREP = /bin/grep -E
EVTLOG_CFLAGS = -I/usr/local/include/eventlog  
EVTLOG_LIBS = -L/usr/local/lib -levtlog  
EXEEXT = 
FGREP = /bin/grep -F
GLIB_CFLAGS = -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include  
GLIB_LIBS = -Wl,--export-dynamic -lgmodule-2.0 -lglib-2.0  
GREP = /bin/grep
INSTALL = /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_STRIP_PROGRAM = $(install_sh) -c -s
LD = /usr/bin/ld -m elf_x86_64
LDFLAGS = 
LEX = flex
LEXLIB = -lfl
LEX_OUTPUT_ROOT = lex.yy
LIBDBI_CFLAGS = 
LIBDBI_LIBS = 
LIBNET_CFLAGS = 
LIBNET_LIBS = 
LIBOBJS = 
LIBS = 
LIBTOOL = $(SHELL) $(top_builddir)/libtool
LIBWRAP_CFLAGS = 
LIBWRAP_LIBS = 
LIPO = 
LN_S = ln -s
LTLIBOBJS = 
MAKEINFO = ${SHELL} /home/dthk/syslog-ng-3.2.5/missing --run makeinfo
MKDIR_P = /bin/mkdir -p
MODULE_DEPS_LIBS = $(top_builddir)/lib/libsyslog-ng.la
MODULE_LDFLAGS = -avoid-version -module -no-undefined
NM = /usr/bin/nm -B
NMEDIT = 
OBJDUMP = objdump
OBJEXT = o
OPENSSL_CFLAGS =  
OPENSSL_LIBS = -Wl,-z,relro -lssl -lcrypto -ldl -lz  
OTOOL = 
OTOOL64 = 
PACKAGE = syslog-ng
PACKAGE_BUGREPORT = 
PACKAGE_NAME = 
PACKAGE_STRING = 
PACKAGE_TARNAME = 
PACKAGE_VERSION = 
PATH_SEPARATOR = :
PCRE_CFLAGS = 
PCRE_LIBS = 
PKG_CONFIG = /usr/bin/pkg-config
PKG_CONFIG_LIBDIR = 
PKG_CONFIG_PATH = /home/dthk/eventlog-0.2.12/
RANLIB = ranlib
RELEASE_TAG = unstable
RESOLV_LIBS = 
SED = /bin/sed
SET_MAKE = 
SHELL = /bin/sh
SNAPSHOT_VERSION = 
SOURCE_REVISION = ssh+git://bazsi@git.balabit//var/scm/git/syslog-ng/syslog-ng-ose--mainline--3.2#master#9d4bea28198bd731df1a61e980a2af5b88d81116
STRIP = strip
SYSLOGNG_DEPS_LIBS =   -lrt -lnsl -Wl,--export-dynamic -lgmodule-2.0 -lglib-2.0   -L/usr/local/lib -levtlog       -ldl
SYSLOGNG_LINK = $(LINK)
TOOL_DEPS_LIBS =   -lrt -lnsl -Wl,--export-dynamic -lgmodule-2.0 -lglib-2.0   -L/usr/local/lib -levtlog       -ldl
VERSION = 3.2.5
YACC = bison -y
YFLAGS = -d
ZLIB_CFLAGS = 
ZLIB_LIBS = 
abs_builddir = /home/dthk/syslog-ng-3.2.5/modules/afmef
abs_srcdir = /home/dthk/syslog-ng-3.2.5/modules/afmef
abs_top_builddir = /home/dthk/syslog-ng-3.2.5
abs_top_srcdir = /home/dthk/syslog-ng-3.2.5
ac_ct_CC = gcc
ac_ct_DUMPBIN = 
am__include = include
am__leading_dot = .
am__quote = 
am__tar = ${AMTAR} chf - "$$tardir"
am__untar = ${AMTAR} xf -
bindir = ${exec_prefix}/bin
build = x86_64-unknown-linux-gnu
build_alias = 
build_cpu = x86_64
build_os = linux-gnu
build_vendor = unknown
builddir = .
datadir = ${datarootdir}
datarootdir = ${prefix}/share
docdir = ${datarootdir}/doc/${PACKAGE}
dvidir = ${docdir}
exec_prefix = ${prefix}
expanded_sysconfdir = /usr/local/etc
host = x86_64-unknown-linux-gnu
host_alias = 
host_cpu = x86_64
host_os = linux-gnu
host_vendor = unknown
htmldir = ${docdir}
includedir = ${prefix}/include
infodir = ${datarootdir}/info
install_sh = ${SHELL} /home/dthk/syslog-ng-3.2.5/install-sh
libdir = ${exec_prefix}/lib
libexecdir = ${exec_prefix}/libexec
localedir = ${datarootdir}/locale
localstatedir = ${prefix}/var
lt_ECHO = echo
mandir = ${datarootdir}/man
mkdir_p = /bin/mkdir -p
moduledir = ${exec_prefix}/lib/syslog-ng
oldincludedir = /usr/include
pdfdir = ${docdir}
pidfiledir = ${localstatedir}
prefix = /usr/local
program_transform_name = s,x,x,
psdir = ${docdir}
sbindir = ${exec_prefix}/sbin
sharedstatedir = ${prefix}/com
srcdir = .
sysconfdir = ${prefix}/etc
systemdsystemunitdir = 
target_alias = 
timezonedir = 
top_build_prefix = ../../
top_builddir = ../..
top_srcdir = ../..
AM_CPPFLAGS = -I$(top_srcdir)/lib -I../../lib
SYSTEMD_SOURCES = 
module_LTLIBRARIES := libafmef-notls.la
noinst_DATA = libafmef.la
libafmef_notls_la_SOURCES = \
	afmef.c afmef.h afinet.h \
	afmef-grammar.y afmef-parser.c afmef-parser.h afmef-plugin.c \
	$(SYSTEMD_SOURCES)

libafmef_notls_la_CPPFLAGS = $(AM_CPPFLAGS)
libafmef_notls_la_LIBADD = $(MODULE_DEPS_LIBS) $(LIBNET_LIBS) $(LIBWRAP_LIBS)
libafmef_notls_la_LDFLAGS = $(MODULE_LDFLAGS)
BUILT_SOURCES = afmef-grammar.y afmef-grammar.c afmef-grammar.h
EXTRA_DIST = $(BUILT_SOURCES) afmef-grammar.ym
CLEANFILES = libafmef.la
all: $(BUILT_SOURCES)
	$(MAKE) $(AM_MAKEFLAGS) all-am

.SUFFIXES:
.SUFFIXES: .c .h .l .lo .o .obj .y
$(srcdir)/Makefile.in:  $(srcdir)/Makefile.am $(top_srcdir)/build/lex-rules.am $(am__configure_deps)
	@for dep in $?; do \
	  case '$(am__configure_deps)' in \
	    *$$dep*) \
	      ( cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh ) \
	        && { if test -f $@; then exit 0; else break; fi; }; \
	      exit 1;; \
	  esac; \
	done; \
	echo ' cd $(top_srcdir) && $(AUTOMAKE) --foreign modules/afmef/Makefile'; \
	$(am__cd) $(top_srcdir) && \
	  $(AUTOMAKE) --foreign modules/afmef/Makefile
.PRECIOUS: Makefile
Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status
	@case '$?' in \
	  *config.status*) \
	    cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh;; \
	  *) \
	    echo ' cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe)'; \
	    cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe);; \
	esac;

$(top_builddir)/config.status: $(top_srcdir)/configure $(CONFIG_STATUS_DEPENDENCIES)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh

$(top_srcdir)/configure:  $(am__configure_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(ACLOCAL_M4):  $(am__aclocal_m4_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(am__aclocal_m4_deps):
install-moduleLTLIBRARIES: $(module_LTLIBRARIES)
	@$(NORMAL_INSTALL)
	test -z "$(moduledir)" || $(MKDIR_P) "$(DESTDIR)$(moduledir)"
	@list='$(module_LTLIBRARIES)'; test -n "$(moduledir)" || list=; \
	list2=; for p in $$list; do \
	  if test -f $$p; then \
	    list2="$$list2 $$p"; \
	  else :; fi; \
	done; \
	test -z "$$list2" || { \
	  echo " $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=install $(INSTALL) $(INSTALL_STRIP_FLAG) $$list2 '$(DESTDIR)$(moduledir)'"; \
	  $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=install $(INSTALL) $(INSTALL_STRIP_FLAG) $$list2 "$(DESTDIR)$(moduledir)"; \
	}

uninstall-moduleLTLIBRARIES:
	@$(NORMAL_UNINSTALL)
	@list='$(module_LTLIBRARIES)'; test -n "$(moduledir)" || list=; \
	for p in $$list; do \
	  $(am__strip_dir) \
	  echo " $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=uninstall rm -f '$(DESTDIR)$(moduledir)/$$f'"; \
	  $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=uninstall rm -f "$(DESTDIR)$(moduledir)/$$f"; \
	done

clean-moduleLTLIBRARIES:
	-test -z "$(module_LTLIBRARIES)" || rm -f $(module_LTLIBRARIES)
	@list='$(module_LTLIBRARIES)'; for p in $$list; do \
	  dir="`echo $$p | sed -e 's|/[^/]*$$||'`"; \
	  test "$$dir" != "$$p" || dir=.; \
	  echo "rm -f \"$${dir}/so_locations\""; \
	  rm -f "$${dir}/so_locations"; \
	done
libafmef-notls.la: $(libafmef_notls_la_OBJECTS) $(libafmef_notls_la_DEPENDENCIES) 
	$(libafmef_notls_la_LINK) -rpath $(moduledir) $(libafmef_notls_la_OBJECTS) $(libafmef_notls_la_LIBADD) $(LIBS)

mostlyclean-compile:
	-rm -f *.$(OBJEXT)

distclean-compile:
	-rm -f *.tab.c

include ./$(DEPDIR)/libafmef_notls_la-afmef-grammar.Plo
include ./$(DEPDIR)/libafmef_notls_la-afmef-parser.Plo
include ./$(DEPDIR)/libafmef_notls_la-afmef-plugin.Plo
include ./$(DEPDIR)/libafmef_notls_la-afmef.Plo

.c.o:
	$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
#	source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(COMPILE) -c $<

.c.obj:
	$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ `$(CYGPATH_W) '$<'`
	$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
#	source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(COMPILE) -c `$(CYGPATH_W) '$<'`

.c.lo:
	$(LTCOMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Plo
#	source='$<' object='$@' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(LTCOMPILE) -c -o $@ $<

libafmef_notls_la-afmef.lo: afmef.c
	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(libafmef_notls_la_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT libafmef_notls_la-afmef.lo -MD -MP -MF $(DEPDIR)/libafmef_notls_la-afmef.Tpo -c -o libafmef_notls_la-afmef.lo `test -f 'afmef.c' || echo '$(srcdir)/'`afmef.c
	$(am__mv) $(DEPDIR)/libafmef_notls_la-afmef.Tpo $(DEPDIR)/libafmef_notls_la-afmef.Plo
#	source='afmef.c' object='libafmef_notls_la-afmef.lo' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(libafmef_notls_la_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o libafmef_notls_la-afmef.lo `test -f 'afmef.c' || echo '$(srcdir)/'`afmef.c

libafmef_notls_la-afmef-grammar.lo: afmef-grammar.c
	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(libafmef_notls_la_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT libafmef_notls_la-afmef-grammar.lo -MD -MP -MF $(DEPDIR)/libafmef_notls_la-afmef-grammar.Tpo -c -o libafmef_notls_la-afmef-grammar.lo `test -f 'afmef-grammar.c' || echo '$(srcdir)/'`afmef-grammar.c
	$(am__mv) $(DEPDIR)/libafmef_notls_la-afmef-grammar.Tpo $(DEPDIR)/libafmef_notls_la-afmef-grammar.Plo
#	source='afmef-grammar.c' object='libafmef_notls_la-afmef-grammar.lo' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(libafmef_notls_la_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o libafmef_notls_la-afmef-grammar.lo `test -f 'afmef-grammar.c' || echo '$(srcdir)/'`afmef-grammar.c

libafmef_notls_la-afmef-parser.lo: afmef-parser.c
	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(libafmef_notls_la_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT libafmef_notls_la-afmef-parser.lo -MD -MP -MF $(DEPDIR)/libafmef_notls_la-afmef-parser.Tpo -c -o libafmef_notls_la-afmef-parser.lo `test -f 'afmef-parser.c' || echo '$(srcdir)/'`afmef-parser.c
	$(am__mv) $(DEPDIR)/libafmef_notls_la-afmef-parser.Tpo $(DEPDIR)/libafmef_notls_la-afmef-parser.Plo
#	source='afmef-parser.c' object='libafmef_notls_la-afmef-parser.lo' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(libafmef_notls_la_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o libafmef_notls_la-afmef-parser.lo `test -f 'afmef-parser.c' || echo '$(srcdir)/'`afmef-parser.c

libafmef_notls_la-afmef-plugin.lo: afmef-plugin.c
	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(libafmef_notls_la_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT libafmef_notls_la-afmef-plugin.lo -MD -MP -MF $(DEPDIR)/libafmef_notls_la-afmef-plugin.Tpo -c -o libafmef_notls_la-afmef-plugin.lo `test -f 'afmef-plugin.c' || echo '$(srcdir)/'`afmef-plugin.c
	$(am__mv) $(DEPDIR)/libafmef_notls_la-afmef-plugin.Tpo $(DEPDIR)/libafmef_notls_la-afmef-plugin.Plo
#	source='afmef-plugin.c' object='libafmef_notls_la-afmef-plugin.lo' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(libafmef_notls_la_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o libafmef_notls_la-afmef-plugin.lo `test -f 'afmef-plugin.c' || echo '$(srcdir)/'`afmef-plugin.c

mostlyclean-libtool:
	-rm -f *.lo

clean-libtool:
	-rm -rf .libs _libs

ID: $(HEADERS) $(SOURCES) $(LISP) $(TAGS_FILES)
	list='$(SOURCES) $(HEADERS) $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '{ files[$$0] = 1; nonempty = 1; } \
	      END { if (nonempty) { for (i in files) print i; }; }'`; \
	mkid -fID $$unique
tags: TAGS

TAGS:  $(HEADERS) $(SOURCES)  $(TAGS_DEPENDENCIES) \
		$(TAGS_FILES) $(LISP)
	set x; \
	here=`pwd`; \
	list='$(SOURCES) $(HEADERS)  $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '{ files[$$0] = 1; nonempty = 1; } \
	      END { if (nonempty) { for (i in files) print i; }; }'`; \
	shift; \
	if test -z "$(ETAGS_ARGS)$$*$$unique"; then :; else \
	  test -n "$$unique" || unique=$$empty_fix; \
	  if test $$# -gt 0; then \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      "$$@" $$unique; \
	  else \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      $$unique; \
	  fi; \
	fi
ctags: CTAGS
CTAGS:  $(HEADERS) $(SOURCES)  $(TAGS_DEPENDENCIES) \
		$(TAGS_FILES) $(LISP)
	list='$(SOURCES) $(HEADERS)  $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '{ files[$$0] = 1; nonempty = 1; } \
	      END { if (nonempty) { for (i in files) print i; }; }'`; \
	test -z "$(CTAGS_ARGS)$$unique" \
	  || $(CTAGS) $(CTAGSFLAGS) $(AM_CTAGSFLAGS) $(CTAGS_ARGS) \
	     $$unique

GTAGS:
	here=`$(am__cd) $(top_builddir) && pwd` \
	  && $(am__cd) $(top_srcdir) \
	  && gtags -i $(GTAGS_ARGS) "$$here"

distclean-tags:
	-rm -f TAGS ID GTAGS GRTAGS GSYMS GPATH tags

distdir: $(DISTFILES)
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	  dist_files=`for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t"`; \
	case $$dist_files in \
	  */*) $(MKDIR_P) `echo "$$dist_files" | \
			   sed '/\//!d;s|^|$(distdir)/|;s,/[^/]*$$,,' | \
			   sort -u` ;; \
	esac; \
	for file in $$dist_files; do \
	  if test -f $$file || test -d $$file; then d=.; else d=$(srcdir); fi; \
	  if test -d $$d/$$file; then \
	    dir=`echo "/$$file" | sed -e 's,/[^/]*$$,,'`; \
	    if test -d "$(distdir)/$$file"; then \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    if test -d $(srcdir)/$$file && test $$d != $(srcdir); then \
	      cp -fpR $(srcdir)/$$file "$(distdir)$$dir" || exit 1; \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    cp -fpR $$d/$$file "$(distdir)$$dir" || exit 1; \
	  else \
	    test -f "$(distdir)/$$file" \
	    || cp -p $$d/$$file "$(distdir)/$$file" \
	    || exit 1; \
	  fi; \
	done
check-am: all-am
check: $(BUILT_SOURCES)
	$(MAKE) $(AM_MAKEFLAGS) check-am
all-am: Makefile $(LTLIBRARIES) $(DATA)
installdirs:
	for dir in "$(DESTDIR)$(moduledir)"; do \
	  test -z "$$dir" || $(MKDIR_P) "$$dir"; \
	done
install: $(BUILT_SOURCES)
	$(MAKE) $(AM_MAKEFLAGS) install-am
install-exec: install-exec-am
install-data: install-data-am
uninstall: uninstall-am

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am

installcheck: installcheck-am
install-strip:
	$(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	  install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	  `test -z '$(STRIP)' || \
	    echo "INSTALL_PROGRAM_ENV=STRIPPROG='$(STRIP)'"` install
mostlyclean-generic:

clean-generic:
	-test -z "$(CLEANFILES)" || rm -f $(CLEANFILES)

distclean-generic:
	-test -z "$(CONFIG_CLEAN_FILES)" || rm -f $(CONFIG_CLEAN_FILES)
	-test . = "$(srcdir)" || test -z "$(CONFIG_CLEAN_VPATH_FILES)" || rm -f $(CONFIG_CLEAN_VPATH_FILES)

maintainer-clean-generic:
	@echo "This command is intended for maintainers to use"
	@echo "it deletes files that may require special tools to rebuild."
	-rm -f afmef-grammar.c
	-test -z "$(BUILT_SOURCES)" || rm -f $(BUILT_SOURCES)
clean: clean-am

clean-am: clean-generic clean-libtool clean-moduleLTLIBRARIES \
	mostlyclean-am

distclean: distclean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
distclean-am: clean-am distclean-compile distclean-generic \
	distclean-tags

dvi: dvi-am

dvi-am:

html: html-am

html-am:

info: info-am

info-am:

install-data-am: install-moduleLTLIBRARIES

install-dvi: install-dvi-am

install-dvi-am:

install-exec-am:
	@$(NORMAL_INSTALL)
	$(MAKE) $(AM_MAKEFLAGS) install-exec-hook
install-html: install-html-am

install-html-am:

install-info: install-info-am

install-info-am:

install-man:

install-pdf: install-pdf-am

install-pdf-am:

install-ps: install-ps-am

install-ps-am:

installcheck-am:

maintainer-clean: maintainer-clean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
maintainer-clean-am: distclean-am maintainer-clean-generic

mostlyclean: mostlyclean-am

mostlyclean-am: mostlyclean-compile mostlyclean-generic \
	mostlyclean-libtool

pdf: pdf-am

pdf-am:

ps: ps-am

ps-am:

uninstall-am: uninstall-moduleLTLIBRARIES
	@$(NORMAL_INSTALL)
	$(MAKE) $(AM_MAKEFLAGS) uninstall-hook
.MAKE: all check install install-am install-exec-am install-strip \
	uninstall-am

.PHONY: CTAGS GTAGS all all-am check check-am clean clean-generic \
	clean-libtool clean-moduleLTLIBRARIES ctags distclean \
	distclean-compile distclean-generic distclean-libtool \
	distclean-tags distdir dvi dvi-am html html-am info info-am \
	install install-am install-data install-data-am install-dvi \
	install-dvi-am install-exec install-exec-am install-exec-hook \
	install-html install-html-am install-info install-info-am \
	install-man install-moduleLTLIBRARIES install-pdf \
	install-pdf-am install-ps install-ps-am install-strip \
	installcheck installcheck-am installdirs maintainer-clean \
	maintainer-clean-generic mostlyclean mostlyclean-compile \
	mostlyclean-generic mostlyclean-libtool pdf pdf-am ps ps-am \
	tags uninstall uninstall-am uninstall-hook \
	uninstall-moduleLTLIBRARIES

export top_srcdir

install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)$(moduledir)
	ln -sf libafmef-notls.so $(DESTDIR)$(moduledir)/libafmef.so

libafmef.la: 
	ln -sf libafmef-notls.la libafmef.la

uninstall-hook:
	rm -f $(DESTDIR)$(moduledir)/libafmef.so
%.y: %.ym $(top_srcdir)/lib/merge-grammar.pl $(top_srcdir)/lib/cfg-grammar.y
	$(top_srcdir)/lib/merge-grammar.pl $< > $@

.l.c:
	$(am__skiplex) $(SHELL) $(YLWRAP) $< $(LEX_OUTPUT_ROOT).c $*.c $(LEX_OUTPUT_ROOT).h $*.h -- $(LEXCOMPILE)

.l.h:
	$(am__skiplex) $(SHELL) $(YLWRAP) $< $(LEX_OUTPUT_ROOT).c $*.c $(LEX_OUTPUT_ROOT).h $*.h -- $(LEXCOMPILE)

.y.c:
	$(am__skipyacc) $(SHELL) $(YLWRAP) $< y.tab.c $@ y.tab.h $*.h y.output $*.output -- $(YACCCOMPILE) 2>&1 | $(EGREP) -v "warning: ([0-9]+ )?(nonterminal|rule)s? useless in grammar"

.y.h:
	$(am__skipyacc) $(SHELL) $(YLWRAP) $< y.tab.c $@ y.tab.h $*.h y.output $*.output -- $(YACCCOMPILE) 2>&1 | $(EGREP) -v "warning: ([0-9]+ )?(nonterminal|rule)s? useless in grammar"

# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
