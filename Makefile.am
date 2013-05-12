moduledir = @moduledir@
AM_CPPFLAGS = -I$(top_srcdir)/lib -I../../lib
export top_srcdir

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

install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)$(moduledir)
	ln -sf libafmef-notls.so $(DESTDIR)$(moduledir)/libafmef.so


libafmef.la: 
	ln -sf libafmef-notls.la libafmef.la

uninstall-hook:
	rm -f $(DESTDIR)$(moduledir)/libafmef.so

CLEANFILES = libafmef.la

include $(top_srcdir)/build/lex-rules.am
