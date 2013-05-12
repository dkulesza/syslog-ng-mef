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
#include "afinet.h"
#include "messages.h"
#include "driver.h"
#include "misc.h"
#include "logwriter.h"
#include "gprocess.h"
#include "gsocket.h"
#include "stats.h"
#include "logproto.h"
#include "persist-state.h"
#include "compat.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>

#if ENABLE_TCP_WRAPPER
#include <tcpd.h>
int allow_severity = 0;
int deny_severity = 0;
#endif

#define MAGIC_SYNC_PACKET 0xfeedfaceaa55aa55LL
//#define IP_START  0x060030000000000001000400 //12
//#define MSG_START 0x06 03 00 00 00 00 01 00 00 00 00 00 00 00 //14
#define IP_START {0x06, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00}
#define MSG_START {0x06, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
/* MSG_START FFFF (SIZE) MESSAGE */

static gboolean afmef_dw_connected(AFSocketDestWriter *);
static void afmef_dw_start_reconnect_timer(AFSocketDestWriter *);
static gboolean afmef_dw_start_connect(AFSocketDestWriter *);
static gint afmef_dw_stats_source(AFSocketDestWriter *);
static gchar *afmef_dw_stats_instance(AFSocketDestWriter *);
static void afmef_dw_reconnect(AFSocketDestWriter *self);
static void afmef_dd_notify(LogPipe *, LogPipe *, gint, gpointer);

#define LPFCS_SESS_INIT	    0
#define LPFCS_FRAME_INIT    1
#define LPFCS_FRAME_SEND    2
#define LPFCS_MESSAGE_SEND  3


typedef struct _LogProtoPlainClient
{
  LogProto super;
  guchar *partial;
  gsize partial_len, partial_pos;
} LogProtoTextClient;

typedef struct _AFMefLogProtoFramedClient
{
  LogProtoTextClient super; //Pointer 8bytes
  char *saddr;
  gchar frame_hdr_buf[24]; //Are bytes getting borked down the way? 
  guchar *buffer;
  gsize buffer_size;
  gint state;
  gint frame_hdr_len; //4Byte
  gint frame_hdr_pos; //4Byte
} AFMefLogProtoFramedClient;

static gboolean
afmef_log_proto_text_client_prepare(LogProto *s, gint *fd, GIOCondition *cond, gint *timeout)
{
  LogProtoTextClient *self = (LogProtoTextClient *) s;

  *fd = self->super.transport->fd;
  *cond = self->super.transport->cond;

  /* if there's no pending I/O in the transport layer, then we want to do a write */
  if (*cond == 0)
    *cond = G_IO_OUT;
  return FALSE;
}


static LogProtoStatus
log_proto_text_client_post(LogProto *s, guchar *msg, gsize msg_len, gboolean *consumed)
{
     msg_debug("Debug log entry",
            evt_tag_str("Message:", "In log_proto_text_client_post"),
            NULL);

  LogProtoTextClient *self = (LogProtoTextClient *) s;
  gint rc;

  /* NOTE: the client does not support charset conversion for now */
  g_assert(self->super.convert == (GIConv) -1);

  *consumed = FALSE;
  /* attempt to flush previously buffered data */
  if (self->partial)
    {
      gint len = self->partial_len - self->partial_pos;

      rc = log_transport_write(self->super.transport, &self->partial[self->partial_pos], len);
      if (rc < 0)
        {
          goto write_error;
        }
      else if (rc != len)
        {
          self->partial_pos += rc;
          return LPS_SUCCESS;
        }
      else
        {
          g_free(self->partial);
          self->partial = NULL;
          /* NOTE: we return here to give a chance to the framed protocol to send the frame header. */
          return LPS_SUCCESS;
        }
    }

  /* OK, partial buffer empty, now flush msg that we just got */
  rc = log_transport_write(self->super.transport, msg, msg_len);

  if (rc < 0 || rc != msg_len)
    {
      /* error OR partial flush, we sent _some_ of the message that we got, save it to self->partial and tell the caller that we consumed it */
      if (rc < 0 && errno != EAGAIN && errno != EINTR)
        goto write_error;

      /* NOTE: log_proto_framed_client_post depends on our current
 *        * behaviour, that we consume every message that we can, even if we
 *               * couldn't write a single byte out.
 *                      *
 *                             * If we return LPS_SUCCESS and self->partial == NULL, it assumes that
 *                                    * the message was sent.
 *                                           */


      self->partial = msg;
      self->partial_len = msg_len;
      self->partial_pos = rc > 0 ? rc : 0;
      *consumed = TRUE;
    }
  else
    {
      /* all data was nicely sent */
      g_free(msg);
      *consumed = TRUE;
    }
  return LPS_SUCCESS;

 write_error:
  if (errno != EAGAIN && errno != EINTR)
    {
      msg_error("I/O error occurred while writing",
                evt_tag_int("fd", self->super.transport->fd),
                evt_tag_errno(EVT_TAG_OSERROR, errno),
                NULL);
      return LPS_ERROR;
    }

  return LPS_SUCCESS;
}


LogProtoStatus
afmef_log_proto_framed_client_post(LogProto *s, guchar *msg, gsize msg_len, gboolean *consumed)
{
        msg_debug("Debug log entry",
            evt_tag_str("Message: ", "afmef_log_proto_framed_client_post"),
            NULL);

  AFMefLogProtoFramedClient *self = (AFMefLogProtoFramedClient *) s;
  gint rc;
  uint64_t magic = MAGIC_SYNC_PACKET;
  char msg_start[14] = MSG_START;
  unsigned long ip;
  char startmsg[24];
  char ip_start[12] = IP_START;
  char *okay;
 
  if (msg_len > 9999999)
    {
      static const guchar *warn_msg;

      if (warn_msg != msg)
        {
          msg_warning("Error, message length too large for framed protocol, truncated",
                      evt_tag_int("length", msg_len),
                      NULL);
          warn_msg = msg;
        }
      msg_len = 9999999;
    }
  switch (self->state)
    {
    case LPFCS_SESS_INIT:
    ip = inet_network(self->saddr);

    memcpy(startmsg, &magic, sizeof(magic));
    memcpy(startmsg + sizeof(magic), ip_start, sizeof(ip_start));
  /* only need 4 bytes - not sure why data type holds 8 ? */
    memcpy(startmsg + sizeof(magic) + sizeof(ip_start), &ip, 4);

    rc = log_transport_write(s->transport, startmsg, sizeof(startmsg));
    read_frame:
            msg_debug("Debug log entry",
            evt_tag_str("Message: ", "Waiting for OKAY packet"),
            NULL);

    rc = log_transport_read(s->transport, self->buffer, self->buffer_size, NULL);
    okay = (char*)memmem(self->buffer, self->buffer_size, "OKAY", 4);
    
    if(!okay)
	goto read_frame;

    self->state = LPFCS_FRAME_INIT;
    case LPFCS_FRAME_INIT:
      memcpy(self->frame_hdr_buf, &magic, sizeof(magic));
      memcpy(self->frame_hdr_buf + sizeof(magic), msg_start, sizeof(msg_start));
      memcpy(self->frame_hdr_buf + sizeof(magic) + sizeof(msg_start), &msg_len, 4);
      self->frame_hdr_len = sizeof(self->frame_hdr_buf);
      self->frame_hdr_pos = 0;
      self->state = LPFCS_FRAME_SEND;
    case LPFCS_FRAME_SEND:
      rc = log_transport_write(s->transport, &self->frame_hdr_buf[self->frame_hdr_pos], self->frame_hdr_len - self->frame_hdr_pos);
      if (rc < 0)
        {
          if (errno != EAGAIN)
            {
              msg_error("I/O error occurred while writing",
                        evt_tag_int("fd", self->super.super.transport->fd),
                        evt_tag_errno(EVT_TAG_OSERROR, errno),
                        NULL);
              return LPS_ERROR;
            }
         break;
        }
      else
        {
          self->frame_hdr_pos += rc;
          if (self->frame_hdr_pos != self->frame_hdr_len)
            break;
          self->state = LPFCS_MESSAGE_SEND;
        }
    case LPFCS_MESSAGE_SEND:
      rc = log_proto_text_client_post(s, msg, msg_len, consumed);

      /* NOTE: we don't check *consumed here, as we might have a pending
 *        * message in self->partial before we begin, in which case *consumed
 *               * will be FALSE. */

      if (rc == LPS_SUCCESS && self->super.partial == NULL)
        {
          self->state = LPFCS_FRAME_INIT;
        }
      return rc;
    default:
      g_assert_not_reached();
    }
  return LPS_SUCCESS;
}

LogProto *
afmef_log_proto_framed_client_new(LogTransport *transport, char *saddr)
{

        msg_debug("Debug log entry",
            evt_tag_str("Message: ", "afmef_log_proto_framed_client_new"),
            NULL);

  AFMefLogProtoFramedClient *self = g_new0(AFMefLogProtoFramedClient, 1);

  self->super.super.prepare = afmef_log_proto_text_client_prepare;
  self->super.super.post = afmef_log_proto_framed_client_post;
  self->super.super.transport = transport;
  self->super.super.convert = (GIConv) -1;

  self->buffer_size = 8192 + 25; //MAX MSG SIZE & FRAME SIZE
  self->buffer = g_malloc(self->buffer_size);

  self->saddr = saddr;
  return &self->super.super;
}


struct _AFSocketDestWriter
{
  LogPipe super;
  AFSocketDestDriver *owner;
  LogPipe *writer; 
 // gchar *transport;
  GSockAddr *bind_addr;
  GSockAddr *dest_addr;
  GString *hostname;
  char *saddr;
  int fd;
  //gint time_reopen;
  guint source_id;
  guint reconnect_timer;
  SocketOptions *sock_options_ptr;
  //gboolean (*setup_socket)(AFSocketDestDriver *s, gint fd);

};

gchar *
afmef_dd_format_persist_name(AFSocketDestDriver *self, const gchar *dest_name, gboolean qfile)
{
  static gchar persist_name[128];

  g_snprintf(persist_name, sizeof(persist_name),
             qfile ? "afmef_dd_qfile(%s,%s)" : "afmef_dw_connection(%s,%s)",
             !!(self->flags & AFMEF_STREAM) ? "stream" : "dgram",
             dest_name);
  return persist_name;
}

gboolean
afmef_dw_deinit(LogPipe *s)
{
 AFSocketDestWriter *self = (AFSocketDestWriter *) s;

  if (self->reconnect_timer)
    g_source_remove(self->reconnect_timer);

   if (self->source_id && g_source_remove(self->source_id))
    {
      msg_verbose("Closing connecting fd",
                  evt_tag_int("fd", self->fd),
                  NULL);
      close(self->fd);
    }

 if(self->writer)
  {
    log_pipe_deinit(self->writer);
  }
 return TRUE;
}


//TODO: FIXME
gboolean
afmef_dw_init(LogPipe *s)
{
        msg_debug("Debug log entry",
            evt_tag_str("Message: ", "In afmef_dw_init"),
            NULL);

 AFSocketDestWriter *self = (AFSocketDestWriter *) s;
 AFSocketDestDriver *driver = self->owner;
 GlobalConfig *cfg = log_pipe_get_config(s);

    if (!self->writer)
      {
         log_writer_options_init(&driver->writer_options, cfg, 0);
	 //driver->writer_options.template = driver->mytemplate;
        /* NOTE: we open our writer with no fd, so we can send messages down there
         * even while the connection is not established */
  
        if ((driver->flags & AFMEF_KEEP_ALIVE))
          self->writer = cfg_persist_config_fetch(cfg, afmef_dd_format_persist_name(driver, driver->dest_name, FALSE));
  
        if (!self->writer)
          self->writer = log_writer_new(LW_FORMAT_PROTO |
                                        ((driver->flags & AFMEF_STREAM) ? LW_DETECT_EOF : 0)|
                                        (driver->flags & AFMEF_SYSLOG_PROTOCOL ? LW_SYSLOG_PROTOCOL : 0));
        //TODO: FIXME
        log_writer_set_options((LogWriter *) self->writer, &self->super, &driver->writer_options, 0, afmef_dw_stats_source(self), driver->super.id, afmef_dw_stats_instance(self));
        log_pipe_init(self->writer, NULL);
        log_pipe_append(&self->super, self->writer);
      }
  
 //GlobalConfig *cfg = log_pipe_get_config(s);
 //This is the "magic" - If we don't do this msg's stay in a disk/memory queue
 afmef_dw_reconnect(self);
 return TRUE;
}

/*static gboolean
afmef_dd_deinit(LogPipe *s)
{
  AFSocketDestWriter *self = (AFSocketDestWriter *) s;

  if (self->writer)
    {
      log_pipe_deinit(self->writer);
    }
  return TRUE;
}*/

void
afmef_dw_queue(LogPipe *s, LogMessage *lm, const LogPathOptions *path_options)
{
      msg_debug("Debug log entry",
            evt_tag_str("Message: ", "In afmef_dw_queue"),
            NULL);

  AFSocketDestWriter *self = (AFSocketDestWriter *) s;
  
  if (!s->pipe_next)
    {
      log_pipe_init(&self->super, NULL);
    }

  if (s->pipe_next)
  {
    log_pipe_forward_msg(s, lm, path_options);
               msg_debug("Debug log entry",
            evt_tag_str("Message: ", "forward_msg in afmef_dw_queue"),
            NULL);
  }
  else
    log_msg_drop(lm, path_options);
}

void
afmef_dw_free(LogPipe *s)
{
  AFSocketDestWriter *self = (AFSocketDestWriter *) s;

  log_pipe_unref(self->writer);
  self->writer = NULL;
  
  //TODO: FIXME clean up gaddr?
  //g_string_free(self->filename, TRUE);
  g_sockaddr_unref(self->bind_addr);
  g_sockaddr_unref(self->dest_addr);
  g_free(self->hostname);
 
  log_pipe_unref(&self->owner->super.super);
  log_pipe_free_method(s);
}

AFSocketDestWriter *
afmef_dw_new(AFSocketDestDriver *owner, GString *hostname)
{

   AFSocketDestWriter *self = g_new0(AFSocketDestWriter, 1);

   log_pipe_init_instance(&self->super);
 
  self->owner = owner;
  self->super.init = afmef_dw_init;
  self->super.deinit = afmef_dw_deinit;
  self->super.free_fn = afmef_dw_free;
  self->super.queue = afmef_dw_queue;
  self->super.notify = afmef_dd_notify;
  log_pipe_ref(&owner->super.super);

  self->bind_addr = g_sockaddr_inet_new("0.0.0.0", 0);
  self->dest_addr = g_sockaddr_inet_new("0.0.0.0", 8081);


  /* we have to take care about freeing filename later. 
     This avoids a move of the filename. */
  self->hostname = hostname;
  return self;
}

gboolean
afmef_setup_gen_socket(gint fd, SocketOptions *sock_options, AFSocketDirection dir)
{
        msg_debug("Debug log entry",
            evt_tag_str("Message: ", "In afmef_gen_socket"),
            NULL);

  if (dir & AFMEF_DIR_RECV)
    {
      if (sock_options->rcvbuf)
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sock_options->rcvbuf, sizeof(sock_options->rcvbuf));
    }
  if (dir & AFMEF_DIR_SEND)
    {
      if (sock_options->sndbuf)
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sock_options->sndbuf, sizeof(sock_options->sndbuf));
      if (sock_options->broadcast)
        setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &sock_options->broadcast, sizeof(sock_options->broadcast));
    }
  setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &sock_options->keepalive, sizeof(sock_options->keepalive));
  return TRUE;
}

static gboolean
afmef_open_socket(GSockAddr *bind_addr, int stream_or_dgram, int *fd)
{
  gint sock;

  if (stream_or_dgram)
    sock = socket(bind_addr->sa.sa_family, SOCK_STREAM, 0);
  else
    sock = socket(bind_addr->sa.sa_family, SOCK_DGRAM, 0);

  if (sock != -1)
    {
      cap_t saved_caps;

      g_fd_set_nonblock(sock, TRUE);
      g_fd_set_cloexec(sock, TRUE);
      saved_caps = g_process_cap_save();
      g_process_cap_modify(CAP_NET_BIND_SERVICE, TRUE);
      g_process_cap_modify(CAP_DAC_OVERRIDE, TRUE);
      if (g_bind(sock, bind_addr) != G_IO_STATUS_NORMAL)
        {
          gchar buf[256];

          g_process_cap_restore(saved_caps);
          msg_error("Error binding socket",
                    evt_tag_str("addr", g_sockaddr_format(bind_addr, buf, sizeof(buf), GSA_FULL)),
                    evt_tag_errno(EVT_TAG_OSERROR, errno),
                    NULL);
          close(sock);
          return FALSE;
        }
      g_process_cap_restore(saved_caps);

      *fd = sock;
      return TRUE;
    }
  else
    {
      msg_error("Error creating socket",
                evt_tag_errno(EVT_TAG_OSERROR, errno),
                NULL);
      return FALSE;
    }
}

/* socket destinations */

gboolean
afmef_dw_start_connect(AFSocketDestWriter *self)
{
  int sock, rc;
  gchar buf1[MAX_SOCKADDR_STRING], buf2[MAX_SOCKADDR_STRING];
  AFSocketDestDriver *driver = self->owner;

  if (!afmef_open_socket(self->bind_addr, !!(driver->flags & AFMEF_STREAM), &sock))
    {
      return FALSE;
    }

  if (driver->setup_socket && !driver->setup_socket(self, sock))
    {
      close(sock);
      return FALSE;
    }

  rc = g_connect(sock, self->dest_addr);
  if (rc == G_IO_STATUS_NORMAL)
    {
      self->fd = sock;
      afmef_dw_connected(self);
    }
  else if (rc == G_IO_STATUS_ERROR && errno == EINPROGRESS)
    {
      GSource *source;

      /* we must wait until connect succeeds */

      self->fd = sock;
      source = g_connect_source_new(sock);

      /* a reference is added on behalf of the source, it will be unrefed when
       * the source is destroyed */
      log_pipe_ref(&self->super);
      g_source_set_callback(source, (GSourceFunc) afmef_dw_connected, self, (GDestroyNotify) log_pipe_unref);
      self->source_id = g_source_attach(source, NULL);
      g_source_unref(source);
    }
  else
    {
      /* error establishing connection */
      msg_error("Connection failed",
                evt_tag_int("fd", sock),
                evt_tag_str("server", g_sockaddr_format(self->dest_addr, buf2, sizeof(buf2), GSA_FULL)),
                evt_tag_str("local", g_sockaddr_format(self->bind_addr, buf1, sizeof(buf1), GSA_FULL)),
                evt_tag_errno(EVT_TAG_OSERROR, errno),
                NULL);
      close(sock);
      return FALSE;
    }

  return TRUE;
}



static void
afmef_dw_reconnect(AFSocketDestWriter *self)
{
   msg_debug("Debug log entry",
            evt_tag_str("Message:", "In afmef_dw_reconnect"),
            NULL);
  AFSocketDestDriver *driver = self->owner;

  if (!afmef_dw_start_connect(self))
    {
      msg_error("Initiating connection failed, reconnecting",
                evt_tag_int("time_reopen", driver->time_reopen),
                NULL);
      afmef_dw_start_reconnect_timer(self);
    }
}

void
afmef_dd_set_keep_alive(LogDriver *s, gint enable)
{
  AFSocketDestDriver *self = (AFSocketDestDriver *) s;

  if (enable)
    self->flags |= AFMEF_KEEP_ALIVE;
  else
    self->flags &= ~AFMEF_KEEP_ALIVE;
}


gint
afmef_dw_stats_source(AFSocketDestWriter *self)
{
  AFSocketDestDriver *driver = self->owner;
  gint source;

  if ((driver->flags & AFMEF_SYSLOG_PROTOCOL) == 0)
    {
      switch (self->dest_addr->sa.sa_family)
        {
        case AF_UNIX:
          source = !!(driver->flags & AFMEF_STREAM) ? SCS_UNIX_STREAM : SCS_UNIX_DGRAM;
          break;
        case AF_INET:
          source = !!(driver->flags & AFMEF_STREAM) ? SCS_TCP : SCS_UDP;
          break;
        default:
          g_assert_not_reached();
          break;
        }
    }
  else
    {
      source = SCS_SYSLOG;
    }
  return source;
}

static gchar *
afmef_dw_stats_instance(AFSocketDestWriter *self)
{
 AFSocketDestDriver *driver = self->owner; 

 if ((driver->flags & AFMEF_SYSLOG_PROTOCOL) == 0)
    {
      return driver->dest_name;
    }
  else
    {
      static gchar buf[256];

      g_snprintf(buf, sizeof(buf), "%s,%s", driver->transport, driver->dest_name);
      return buf;
    }
}

static gboolean
afmef_dw_reconnect_timer(gpointer s)
{
  AFSocketDestWriter *self = (AFSocketDestWriter *) s;

  afmef_dw_reconnect(self);
  return FALSE;
}

void
afmef_dw_start_reconnect_timer(AFSocketDestWriter *self)
{
 AFSocketDestDriver *driver = self->owner;
   msg_debug("Debug log entry",
            evt_tag_str("Message:", "In dw_start_reconnect_timer"),
            NULL);

  if (self->reconnect_timer)
    g_source_remove(self->reconnect_timer);
  self->reconnect_timer = g_timeout_add(driver->time_reopen * 1000, afmef_dw_reconnect_timer, self);
}


//Connected needs to be called by my DataWriter
//Equivalent of AFFileDestWriter
gboolean
afmef_dw_connected(AFSocketDestWriter *self)
{
  AFSocketDestDriver *driver = self->owner;
  
  gchar buf1[256], buf2[256];
  int error = 0;
  socklen_t errorlen = sizeof(error);
  LogTransport *transport;
  LogProto *proto;
  guint32 transport_flags = 0;
  gint rc;
  unsigned long ip;
  char startmsg[24];  
  char ip_start[12] = IP_START;
  uint64_t magic = MAGIC_SYNC_PACKET;

  if (driver->flags & AFMEF_STREAM)
    {
      transport_flags |= LTF_SHUTDOWN;
      if (getsockopt(self->fd, SOL_SOCKET, SO_ERROR, &error, &errorlen) == -1)
        {
          msg_error("getsockopt(SOL_SOCKET, SO_ERROR) failed for connecting socket",
                    evt_tag_int("fd", self->fd),
                    evt_tag_str("server", g_sockaddr_format(self->dest_addr, buf2, sizeof(buf2), GSA_FULL)),
                    evt_tag_errno(EVT_TAG_OSERROR, errno),
                    evt_tag_int("time_reopen", driver->time_reopen),
                    NULL);
          close(self->fd);
          goto error_reconnect;
        }
      if (error)
        {
          msg_error("Syslog connection failed",
                    evt_tag_int("fd", self->fd),
                    evt_tag_str("server", g_sockaddr_format(self->dest_addr, buf2, sizeof(buf2), GSA_FULL)),
                    evt_tag_errno(EVT_TAG_OSERROR, error),
                    evt_tag_int("time_reopen", driver->time_reopen),
                    NULL);
          close(self->fd);
          goto error_reconnect;
        }
    }
  msg_notice("Syslog connection established",
              evt_tag_int("fd", self->fd),
              evt_tag_str("server", g_sockaddr_format(self->dest_addr, buf2, sizeof(buf2), GSA_FULL)),
              evt_tag_str("local", g_sockaddr_format(self->bind_addr, buf1, sizeof(buf1), GSA_FULL)),
              NULL);

  if (self->source_id)
    {
      g_source_remove(self->source_id);
      self->source_id = 0;
    }

  transport = log_transport_plain_new(self->fd, transport_flags);

  proto = afmef_log_proto_framed_client_new(transport, self->saddr);

  //ip = inet_network(self->saddr);
  
  //memcpy(startmsg, &magic, sizeof(magic));
  //memcpy(startmsg + sizeof(magic), ip_start, sizeof(ip_start));
  /* only need 4 bytes - not sure why data type holds 8 ? */
  //memcpy(startmsg + sizeof(magic) + sizeof(ip_start), &ip, 4);

  //rc = log_transport_write(transport, startmsg, sizeof(startmsg));
  
  log_writer_reopen(self->writer, proto);
  return TRUE;
 error_reconnect:
  afmef_dw_start_reconnect_timer(self);
  return FALSE;
}

static void
afmef_dd_queue(LogPipe *s, LogMessage *msg, const LogPathOptions *path_options)
{
  msg_debug("Debug log entry",
            evt_tag_str("Message:", "In afmef_dd_queue"),
            NULL);

  AFSocketDestDriver *self = (AFSocketDestDriver *) s;
  AFSocketDestWriter *next;

  char *saddr;
  struct in_addr sinaddr;

  GlobalConfig *cfg = log_pipe_get_config(s);

  if(g_sockaddr_inet_check(msg->saddr))
  {
        sinaddr = g_sockaddr_inet_get_address(msg->saddr);

        saddr = inet_ntoa(sinaddr);

      msg_debug("Debug log entry",
            evt_tag_str("Source IP Address", saddr),
            NULL);
  }
  else
  {
        msg_debug("Debug log entry",
                evt_tag_str("Message: ", "No source IP Address."), NULL);

  }

      //GString *host;

      if(!self->writer_hash)
        self->writer_hash = g_hash_table_new(g_str_hash, g_str_equal);

        next = g_hash_table_lookup(self->writer_hash, saddr);
        if(next)
        {
                      msg_debug("Debug log entry",
            evt_tag_str("Message: ", "Found writer in hashtable"),
            NULL);

        }

        if(!next)
        {
            msg_debug("Debug log entry",
            evt_tag_str("Message: ", "Calling afmef_dw_new in dd_queue"),
            NULL);
          next = afmef_dw_new(self, g_string_new(saddr));
          next->saddr = saddr;
          if (!log_pipe_init(&next->super, cfg))
            {
              log_pipe_unref(&next->super);
              next = NULL;
            }
        else
           g_hash_table_insert(self->writer_hash, saddr, next);
        }
        else
               //g_string_free(filename, TRUE);
		saddr = NULL;

  if (next)
   {
              msg_debug("Debug log entry",
            evt_tag_str("Message: ", "Calling log_pipe_queue in dd_queue"),
            NULL);
    log_pipe_queue(&next->super, msg, path_options);
   } 
   else
    log_msg_drop(msg, path_options);
   //log_pipe_forward_msg(s, msg, path_options);
}


gboolean
afmef_dd_init(LogPipe *s)
{
          msg_debug("Debug log entry",
            evt_tag_str("Message: ", "In afmef_dd_init"),
            NULL);

  AFSocketDestDriver *self = (AFSocketDestDriver *) s;
  GlobalConfig *cfg = log_pipe_get_config(s);
 

  if (cfg->time_reopen)
    {
      self->time_reopen = cfg->time_reopen;
    }
  
   //Here is how the magic can happen....
   //Can create a template for log messages
   //Multiple templates for different protocols?  
   //self->mytemplate = log_template_new(cfg, "mef", "MAGICMESSAGE: $MSGHDR$MSG");
   //log_template_compile(self->mytemplate, NULL);

 
/*
*  if (!self->writer)
*    {
*      log_writer_options_init(&self->writer_options, cfg, 0);
*      * NOTE: we open our writer with no fd, so we can send messages down there
*       * even while the connection is not established *
*
*      if ((self->flags & AFMEF_KEEP_ALIVE))
*        self->writer = cfg_persist_config_fetch(cfg, afmef_dd_format_persist_name(self, self->dest_name, FALSE));
*
*      if (!self->writer)
*        self->writer = log_writer_new(LW_FORMAT_PROTO |
*                                      ((self->flags & AFMEF_STREAM) ? LW_DETECT_EOF : 0)|
*                                      (self->flags & AFMEF_SYSLOG_PROTOCOL ? LW_SYSLOG_PROTOCOL : 0));
*      log_writer_set_options((LogWriter *) self->writer, &self->super.super, &self->writer_options, 0, afmef_dd_stats_source(self), self->super.id, afmef_dd_stats_instance(self));
*      log_pipe_init(self->writer, NULL);
*      log_pipe_append(&self->super.super, self->writer);
*    }
*/
  //afmef_dw_reconnect(self);
  return TRUE;
}

static void
afmef_dd_destroy_writer(gpointer value)
{
  AFSocketDestWriter *writer = (AFSocketDestWriter *) value;
  log_pipe_deinit(&writer->super);
  log_pipe_unref(&writer->super);
}


/*
 * This function is called as a g_hash_table_foreach_remove() callback to
 * free the specific AFFileDestWriter instance in the hashtable.
 */
static gboolean
afmef_dd_destroy_writer_hr(gpointer key, gpointer value, gpointer user_data)
{
  afmef_dd_destroy_writer(value);
  return TRUE;
}


/**
 * affile_dd_destroy_writer_hash:
 * @value: GHashTable instance passed as a generic pointer
 *
 * Destroy notify callback for the GHashTable storing AFFileDestWriter instances.
 **/
static void
afmef_dd_destroy_writer_hash(gpointer value)
{
  GHashTable *writer_hash = (GHashTable *) value;
 
  g_hash_table_foreach_remove(writer_hash, afmef_dd_destroy_writer_hr, NULL);
  g_hash_table_destroy(writer_hash);
}


static void
afmef_dd_deinit_writer(gpointer key, gpointer value, gpointer user_data)
{
  log_pipe_deinit((LogPipe *) value);
}

gboolean
afmef_dd_deinit(LogPipe *s)
{
  AFSocketDestDriver *self = (AFSocketDestDriver *) s;
  //GlobalConfig *cfg = log_pipe_get_config(s);

  if (self->single_writer)
    {
      g_assert(self->writer_hash == NULL);

      log_pipe_deinit(self->single_writer);
      //cfg_persist_config_add(cfg, afmef_dd_format_persist_name(self, self->dest_name, FALSE), self->single_writer, afmef_dd_destroy_writer, FALSE);
      self->single_writer = NULL;

    } 
  else if (self->writer_hash)
  {
      g_assert(self->single_writer == NULL);

      g_hash_table_foreach(self->writer_hash, afmef_dd_deinit_writer, NULL);
      //cfg_persist_config_add(cfg, afmef_dd_format_persist_name(self, self->dest_name, FALSE), self->writer_hash, afmef_dd_destroy_writer_hash, FALSE);
      self->writer_hash = NULL;
  }

//Does this go in the writer deinit??
  if (self->flags & AFMEF_KEEP_ALIVE)
    {
      //cfg_persist_config_add(cfg, afmef_dd_format_persist_name(self, self->dest_name, FALSE), self->single_writer, (GDestroyNotify) log_pipe_unref, FALSE);
      self->single_writer = NULL;
    }
  if(self->reap_timer)
    g_source_remove(self->reap_timer);

  return TRUE;
}


//WTF IS afmef_dd_notify???
static void
afmef_dd_notify(LogPipe *s, LogPipe *sender, gint notify_code, gpointer user_data)
{
  
          msg_debug("Debug log entry",
            evt_tag_str("Message: ", "In afmef_dd_notify"),
            NULL);

  AFSocketDestWriter *self = (AFSocketDestWriter *) s;
  AFSocketDestDriver *driver = self->owner;
  gchar buf[MAX_SOCKADDR_STRING];

  switch (notify_code)
    {
    case NC_CLOSE:
    case NC_WRITE_ERROR:
       //MAGICAL
      log_writer_reopen(self->writer, NULL);

      msg_notice("Syslog connection broken",
                 evt_tag_int("fd", self->fd),
                 evt_tag_str("server", g_sockaddr_format(self->dest_addr, buf, sizeof(buf), GSA_FULL)),
                 evt_tag_int("time_reopen", driver->time_reopen),
                 NULL);
      if (self->reconnect_timer)
        {
          g_source_remove(self->reconnect_timer);
          self->reconnect_timer = 0;
        }
      self->reconnect_timer = g_timeout_add(driver->time_reopen * 1000, afmef_dw_reconnect_timer, self);
      break;
    }
}

gint
afmef_port(gchar *service, const gchar *proto)
{
      gchar *end;
      gint port;

      /* check if service is numeric */
      port = strtol(service, &end, 10);
      if ((*end != 0))
        {
          struct servent *se;

          /* service is not numeric, check if it's a service in /etc/services */
          se = getservbyname(service, proto);
          if (se)
            {
              port = ntohs(se->s_port);
            }
          else
            {
              msg_error("Error finding port number, falling back to default",
                        evt_tag_printf("service", "%s/%s", proto, service),
                        NULL);
              return -1;
            }
        }
  
     return port;
}

static void
afmef_set_port(GSockAddr *addr, gchar *service, const gchar *proto)
{
  if (addr)
    {
      gint port;

      port = afmef_port(service, proto);

      switch (addr->sa.sa_family)
        {
        case AF_INET:
          g_sockaddr_inet_set_port(addr, port);
          break;
        default:
          g_assert_not_reached();
          break;
        }
    
     }
}

void
afmef_dw_set_localport(AFSocketDestWriter *s, gchar *service, const gchar *proto)
{
 afmef_set_port(s->bind_addr, service, proto);
}

void
afmef_dd_set_localport(LogDriver *s, gchar *service, const gchar *proto)
{
  AFSocketDestDriver *self = (AFSocketDestDriver *) s;
  self->local_port = afmef_port(service,proto);
}


//Imported from afinet
void
afmef_dw_set_destport(AFSocketDestWriter *s, gchar *service, const gchar *proto)
{
  AFSocketDestDriver *driver = s->owner;

  afmef_set_port(s->dest_addr, service, proto);

  g_free(driver->dest_name);
  driver->dest_name = g_strdup_printf("%s:%d", driver->hostname,
                  g_sockaddr_inet_check(s->dest_addr) ? g_sockaddr_inet_get_port(s->dest_addr)
                                                               : 0);
}

void
afmef_dd_set_destport(LogDriver *s, gchar *service, const gchar *proto)
{
  AFSocketDestDriver *self = (AFSocketDestDriver *) s;

          msg_debug("Debug log entry",
            evt_tag_str("Message: ", "In afmef_set_destport"),
            NULL);
 
  self->dest_port = afmef_port(service, proto);
}

void
afmef_dw_set_localip(AFSocketDestWriter *s, gchar *ip)
{
 resolve_hostname(&s->bind_addr, ip);

}

void
afmef_dd_set_localip(LogDriver *s, gchar *ip)
{
  AFSocketDestDriver *self = (AFSocketDestDriver *) s;
  self->local_ip = ip;
}

void
afmef_dd_set_transport(LogDriver *s, const gchar *transport)
{
  AFSocketDestDriver *self = (AFSocketDestDriver *) s;

  if (self->transport)
    g_free(self->transport);
  self->transport = g_strdup(transport);

  if (strcasecmp(transport, "tcp") == 0)
    {
      self->flags = (self->flags & ~0x0003) | AFMEF_STREAM;
    }
  else
    {
      msg_error("Unknown syslog transport specified, please use one of udp, tcp, or tls",
                evt_tag_str("transport", transport),
                NULL);
    }
}

//Imported from AFINET
gboolean
afinet_setup_socket(gint fd, GSockAddr *addr, SocketOptions *sock_options, AFSocketDirection dir)
{
  //gint off = 0;

        msg_debug("Debug log entry",
            evt_tag_str("Message: ", "In afinet_setup_socket"),
            NULL);

  if (!afmef_setup_gen_socket(fd, sock_options, dir))
    return FALSE;
/*
  switch (addr->sa.sa_family)
    {
    case AF_INET:
      {
        struct ip_mreq mreq;

        if (IN_MULTICAST(ntohl(g_sockaddr_inet_get_address(addr).s_addr)))
          {
            if (dir & AFMEF_DIR_RECV)
              {
                memset(&mreq, 0, sizeof(mreq));
                mreq.imr_multiaddr = g_sockaddr_inet_get_address(addr);
                mreq.imr_interface.s_addr = INADDR_ANY;
                setsockopt(fd, SOL_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
                setsockopt(fd, SOL_IP, IP_MULTICAST_LOOP, &off, sizeof(off));
              }
            if (dir & AFMEF_DIR_SEND)
              {
                if (sock_options->ttl)
                  setsockopt(fd, SOL_IP, IP_MULTICAST_TTL, &sock_options->ttl, sizeof(sock_options->ttl));
              }

          }
        else
          {
            if (sock_options->ttl && (dir & AFMEF_DIR_SEND))
              setsockopt(fd, SOL_IP, IP_TTL, &sock_options->ttl, sizeof(sock_options->ttl));
          }
        if (sock_options->tos && (dir & AFMEF_DIR_SEND))
          setsockopt(fd, SOL_IP, IP_TOS, &sock_options->tos, sizeof(sock_options->tos));

        break;
      }
    } */
  return TRUE;
}

//Imported from AFINET
gboolean
afmef_dd_setup_socket(AFSocketDestWriter *self, gint fd)
{
  AFSocketDestDriver *driver = self->owner;

  if (!resolve_hostname(&self->dest_addr, driver->hostname))
    return FALSE;

  return afinet_setup_socket(fd, self->dest_addr, &driver->sock_options, AFMEF_DIR_SEND);
}


//TODO: FIXME
void
afmef_dd_free(LogPipe *s)
{
          msg_debug("Debug log entry",
            evt_tag_str("Message: ", "In afmef_dd_free"),
            NULL);

  AFSocketDestDriver *self = (AFSocketDestDriver *) s;
 /* NOTE: this must be null as deinit has freed it, otherwise we'd have a circular reference */
  g_assert(self->single_writer == NULL && self->writer_hash ==NULL);
  
  log_pipe_unref(self->single_writer);
  g_free(self->hostname);
  g_free(self->transport);
  g_free(self->dest_name);
  g_free(self->local_ip);
  log_writer_options_destroy(&self->writer_options);
  log_drv_free(s);
}

//Driver init from afinet
LogDriver *
afmef_dd_new(gint af, gchar *host, gint port, guint flags)
{
          msg_debug("Debug log entry",
            evt_tag_str("Message: ", "Creating new driver"),
            NULL);
  AFSocketDestDriver *self = g_new0(AFSocketDestDriver, 1);
 
  if (self->flags & AFMEF_STREAM)
    self->transport = g_strdup("tcp");

  log_drv_init_instance(&self->super);
  log_writer_options_defaults(&self->writer_options);

  //INIT appears to be good
  self->super.super.init = afmef_dd_init;

  //DEINIT is only in afsocket.c
  self->super.super.deinit = afmef_dd_deinit;
  //Need to have a dw_queue
  //TODO: init bind_addr & dest_addr in QUEUE
  self->super.super.queue = afmef_dd_queue;
  //Validated 
  self->super.super.free_fn = afmef_dd_free;

  //self->super.super.notify = afmef_dd_notify;

  self->setup_socket = afmef_dd_setup_socket;
  
  //self->sock_options = sock_options;
  
  self->flags = flags  | AFMEF_KEEP_ALIVE;

  self->hostname = g_strdup(host);
  self->dest_name = g_strdup_printf("%s:%d", host, port);

          msg_debug("Debug log entry",
            evt_tag_str(": ", self->hostname),
            NULL);


//AFINET INITIALIZATION
//:
//  if (af == AF_INET)
 //   {
//      self->super.bind_addr = g_sockaddr_inet_new("0.0.0.0", 0);
 //     self->super.dest_addr = g_sockaddr_inet_new("0.0.0.0", port);
 //   }
 // else
  //  {
  //    g_assert_not_reached();
  //  }
          msg_debug("Debug log entry",
            evt_tag_str("Message: ", "Returning new driver"),
            NULL);
  return &self->super;
}
