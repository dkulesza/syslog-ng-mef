moduledir = @moduledir@
AM_CPPFLAGS = -I$(top_srcdir)/lib -I../../lib
export top_srcdir

if ENABLE_SYSTEMD
if WITH_LIBSYSTEMD
SYSTEMD_SOURCES =
else
SYSTEMD_SOURCES = sd-daemon.c sd-daemon.h
endif
else
SYSTEMD_SOURCES =
endif

module_LTLIBRARIES := libafmef-notls.la
noinst_DATA = libafmef.la
libafmef_notls_la_SOURCES = \
	afmef.c		\
	afmef.h		\
	afmef-dest.c		\
	afmef-dest.h		\
	afinet.c		\
	afinet.h		\
	afmef-grammar.y	\
	afmef-parser.c	\
	afmef-parser.h	\
	afmef-plugin.c 	\
        logproto-mef-client.c \
	logproto-mef-client.h \
	$(SYSTEMD_SOURCES)
libafmef_notls_la_CPPFLAGS = $(AM_CPPFLAGS) $(libsystemd_daemon_CFLAGS)
libafmef_notls_la_LIBADD = $(MODULE_DEPS_LIBS) $(LIBNET_LIBS) $(LIBWRAP_LIBS) $(libsystemd_daemon_LIBS)
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
