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

#ifndef AFMEF_H_INCLUDED
#define AFMEF_H_INCLUDED

#include "driver.h"
#include "logreader.h"
#include "logwriter.h"

#define AFMEF_DGRAM               0x0001
#define AFMEF_STREAM              0x0002
#define AFMEF_LOCAL               0x0004

#define AFMEF_SYSLOG_PROTOCOL     0x0008
#define AFMEF_KEEP_ALIVE          0x0100

typedef enum
{
  AFMEF_DIR_RECV = 0x01,
  AFMEF_DIR_SEND = 0x02,
} AFSocketDirection;

typedef struct _AFSocketDestDriver AFSocketDestDriver;

typedef struct _AFSocketDestWriter AFSocketDestWriter;

typedef struct _SocketOptions
{
  gint sndbuf;
  gint rcvbuf;
  gint broadcast;
  gint keepalive;
} SocketOptions;

gboolean afmef_setup_socket(gint fd, SocketOptions *sock_options, AFSocketDirection dir);

struct _AFSocketDestDriver
{
  LogDriver super;
  guint32 flags;
  LogPipe *single_writer;
  
  LogWriterOptions writer_options;

  GHashTable *writer_hash;
  gchar *transport;
  gchar *hostname;
  gchar *dest_name;
  gchar *local_ip;
  gint local_port;
  gint dest_port;
  gint time_reopen;
  gint time_reap;
  guint reap_timer;
  SocketOptions sock_options;
  gboolean (*setup_socket)(AFSocketDestWriter *s, gint fd);
};

void afmef_dd_set_keep_alive(LogDriver *self, gint enable);
void afmef_dd_init_instance(AFSocketDestDriver *self, SocketOptions *sock_options, guint32 flags, gchar *hostname, gchar *dest_name);
gboolean afmef_dd_init(LogPipe *s);
void afmef_dd_free(LogPipe *s);

static inline const gchar *
afmef_dd_get_proto_name(LogDriver *s)
{
  AFSocketDestDriver *self = (AFSocketDestDriver *) s;

  if (self->flags & AFMEF_DGRAM)
    return "udp";
  else
    return "tcp";
}


#endif
