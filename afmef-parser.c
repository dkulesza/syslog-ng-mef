/*
 * Copyright (c) 2002-2012 BalaBit IT Ltd, Budapest, Hungary
 * Copyright (c) 1998-2012 Balázs Scheidler
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 *
 */

#include "afmef.h"
#include "driver.h"
#include "cfg-parser.h"
#include "afmef-grammar.h"

extern int afmef_debug;

int afmef_parse(CfgLexer *lexer, LogDriver **instance, gpointer arg);

static CfgLexerKeyword afmef_keywords[] = {
  { "mef",                KW_MEF },

  { "localip",            KW_LOCALIP },
  { "ip",                 KW_IP },
  { "localport",          KW_LOCALPORT },
  { "port",               KW_PORT },
  { "destport",           KW_DESTPORT },
  { "ip_ttl",             KW_IP_TTL },
  { "ip_tos",             KW_IP_TOS },
  { "so_broadcast",       KW_SO_BROADCAST },
  { "so_rcvbuf",          KW_SO_RCVBUF },
  { "so_sndbuf",          KW_SO_SNDBUF },
  { "so_keepalive",       KW_SO_KEEPALIVE },
  { "tcp_keep_alive",     KW_SO_KEEPALIVE }, /* old, once deprecated form, but revived in 3.4 */
  { "tcp_keepalive",      KW_SO_KEEPALIVE, 0x0304 }, /* alias for so-keepalive, as tcp is the only option actually using it */
  { "tcp_keepalive_time", KW_TCP_KEEPALIVE_TIME, 0x0304 },
  { "tcp_keepalive_probes", KW_TCP_KEEPALIVE_PROBES, 0x0304 },
  { "tcp_keepalive_intvl", KW_TCP_KEEPALIVE_INTVL, 0x0304 },
  { "spoof_source",       KW_SPOOF_SOURCE },
  { "transport",          KW_TRANSPORT },
  { "ip_protocol",        KW_IP_PROTOCOL },
  { "max_connections",    KW_MAX_CONNECTIONS },
  { "keep_alive",         KW_KEEP_ALIVE },
  { NULL }
};

CfgParser afmef_parser =
{
#if ENABLE_DEBUG
  .debug_flag = &afmef_debug,
#endif
  .name = "afmef",
  .keywords = afmef_keywords,
  .parse = (gint (*)(CfgLexer *, gpointer *, gpointer)) afmef_parse,
  .cleanup = (void (*)(gpointer)) log_pipe_unref,
};

CFG_PARSER_IMPLEMENT_LEXER_BINDING(afmef_, LogDriver **)
