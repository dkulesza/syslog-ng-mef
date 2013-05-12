/*
 * Copyright (c) 2002-2010 BalaBit IT Ltd, Budapest, Hungary
 * Copyright (c) 1998-2010 Balázs Scheidler
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 *
 */

#include "afmef.h"
#include "cfg-parser.h"
#include "afmef-grammar.h"

extern int afmef_debug;

int afmef_parse(CfgLexer *lexer, LogDriver **instance);

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
  { "tcp_keep_alive",     KW_SO_KEEPALIVE, 0, KWS_OBSOLETE, "so_keepalive" },
  { "spoof_source",       KW_SPOOF_SOURCE },
  { "transport",          KW_TRANSPORT },
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
  .parse = (gint (*)(CfgLexer *, gpointer *)) afmef_parse,
  .cleanup = (void (*)(gpointer)) log_pipe_unref,
};

CFG_PARSER_IMPLEMENT_LEXER_BINDING(afmef_, LogDriver **)
