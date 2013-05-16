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

#ifndef AFSOCKET_DEST_H_INCLUDED
#define AFSOCKET_DEST_H_INCLUDED

#include "afmef.h"
#include "driver.h"
#include "logwriter.h"
#include "afinet.h"

#include <iv.h>



typedef struct _AFSocketDestDriver AFSocketDestDriver;
typedef struct _AFSocketDestWriter AFSocketDestWriter;

struct _AFSocketDestWriter
{
  LogPipe super;
  GStaticMutex lock;
  AFSocketDestDriver *owner;
  GString *src_hostname;
  LogPipe *writer;
  GSockAddr *bind_addr;
  GSockAddr *dest_addr;
  gchar *saddr;
  gint fd;
  gint time_reopen;
  struct iv_timer reap_timer;
  gboolean reopen_pending, queue_pending;
  struct iv_fd connect_fd;
  struct iv_timer reconnect_timer;
  //SocketOptions *sock_options_ptr; 
 /*
 * Apply transport options, set up bind_addr/dest_addr based on the
 * information processed during parse time. This used to be
 * constructed during the parser, however that made the ordering of
 * various options matter and behave incorrectly when the port() was
 * specified _after_ transport(). Now, it collects the information,
 * and then applies them with a separate call to apply_transport()
 * during init().
 */

  gboolean (*apply_transport)(AFSocketDestWriter *s);

};

struct _AFSocketDestDriver
{
  LogDestDriver super;

  gboolean
    connections_kept_alive_accross_reloads:1,
    syslog_protocol:1,
    require_tls:1;
//  gint fd;
  /* SOCK_DGRAM or SOCK_STREAM or other SOCK_XXX values used by the socket() call */
  gint sock_type;
  /* protocol parameter for the socket() call, 0 for default or IPPROTO_XXX for specific transports */
  gint sock_protocol;
  LogPipe *writer;
  LogWriterOptions writer_options;
  GHashTable *writer_hash;

  LogProtoClientFactory *proto_factory;
  gint address_family;
  gchar *hostname;
  /* transport as specified by the user */
  gchar *transport;
  gchar *bind_ip;
  /* character as it can contain a service name from /etc/services */
  gchar *dest_port;

  /* logproto plugin name, borrowed char pointer, no need to free. If
   * allocated dynamically, a free must be added and an strdup to all
   * initializations!  */
  gchar *logproto_name;
  //GSockAddr *bind_addr;
  //GSockAddr *dest_addr;
  gchar *dest_name;
  gint time_reopen;
  //struct iv_fd connect_fd;
  //struct iv_timer reconnect_timer;
  InetSocketOptions sock_options;

  /* once the socket is opened, set up socket related options (IP_TTL,
     IP_TOS, SO_RCVBUF etc) */

  gboolean (*setup_socket)(AFSocketDestWriter *s, gint fd);
};



void afmef_dd_set_destport(LogDriver *self, gchar *service);
void afmef_dd_set_localip(LogDriver *self, gchar *ip);
void afmef_dw_set_sync_freq(LogDriver *self, gint sync_freq);

void afmef_dd_set_transport(LogDriver *s, const gchar *transport);
void afmef_dd_set_keep_alive(LogDriver *self, gint enable);
void afmef_dd_init_instance(AFSocketDestDriver *self, SocketOptions *sock_options, gint family, gint sock_type, const gchar *hostname);
gboolean afmef_dd_init(LogPipe *s);
void afmef_dd_free(LogPipe *s);

LogDriver *afmef_dd_new(gint af, gint sock_type, gchar *host);

#endif
