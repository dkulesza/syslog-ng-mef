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

#include "afmef-dest.h"
#include "logproto-mef-client.h"
#include "afinet.h"
#include "messages.h"
#include "misc.h"
#include "logwriter.h"
#include "gsocket.h"
#include "stats.h"
#include "mainloop.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

static gboolean afmef_dw_setup_socket(AFSocketDestWriter *, gint);
static gboolean afmef_dw_apply_transport(AFSocketDestWriter *);

void
afmef_dd_set_transport(LogDriver *s, const gchar *transport)
{
  AFSocketDestDriver *self = (AFSocketDestDriver *) s;

  if (self->transport)
    g_free(self->transport);
  self->transport = g_strdup(transport);
}

void
afmef_dd_set_keep_alive(LogDriver *s, gboolean enable)
{
  AFSocketDestDriver *self = (AFSocketDestDriver *) s;

  self->connections_kept_alive_accross_reloads = enable;
}


static gchar *
afmef_dd_format_persist_name(AFSocketDestDriver *self, gboolean qfile)
{
  static gchar persist_name[128];

  g_snprintf(persist_name, sizeof(persist_name),
             qfile ? "afmef_dd_qfile(%s,%s)" : "afmef_dd_connection(%s,%s)",
             (self->sock_type == SOCK_STREAM) ? "stream" : "dgram",
             self->dest_name);
  return persist_name;
}


static gint
afmef_dw_stats_source(AFSocketDestWriter *self)
{
  AFSocketDestDriver *driver = self->owner;
  gint source = 0;

  /* FIXME: make this a overrideable function */
  if (!driver->syslog_protocol)
    {
      switch (self->bind_addr->sa.sa_family)
        {
        case AF_INET:
          source = (driver->sock_type == SOCK_STREAM) ? SCS_TCP : SCS_UDP;
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

  if (!driver->syslog_protocol)
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

static gboolean afmef_dw_connected(AFSocketDestWriter *self);
static void afmef_dw_reconnect(AFSocketDestWriter *self);

static void
afmef_dw_init_watches(AFSocketDestWriter *self)
{
  IV_FD_INIT(&self->connect_fd);
  self->connect_fd.cookie = self;
  self->connect_fd.handler_out = (void (*)(void *)) afmef_dw_connected;

  IV_TIMER_INIT(&self->reconnect_timer);
  self->reconnect_timer.cookie = self;
  self->reconnect_timer.handler = (void (*)(void *)) afmef_dw_reconnect;
}

static void
afmef_dw_start_watches(AFSocketDestWriter *self)
{
  main_loop_assert_main_thread();

  self->connect_fd.fd = self->fd;
  iv_fd_register(&self->connect_fd);
}

static void
afmef_dw_stop_watches(AFSocketDestWriter *self)
{
  main_loop_assert_main_thread();

  if (iv_fd_registered(&self->connect_fd))
    {
      iv_fd_unregister(&self->connect_fd);

      /* need to close the fd in this case as it wasn't established yet */
      msg_verbose("Closing connecting fd",
                  evt_tag_int("fd", self->fd),
                  NULL);
      close(self->fd);
    }
  if (iv_timer_registered(&self->reconnect_timer))
    iv_timer_unregister(&self->reconnect_timer);
}

static void
afmef_dw_start_reconnect_timer(AFSocketDestWriter *self)
{
  main_loop_assert_main_thread();

  if (iv_timer_registered(&self->reconnect_timer))
    iv_timer_unregister(&self->reconnect_timer);
  iv_validate_now();

  self->reconnect_timer.expires = iv_now;
  timespec_add_msec(&self->reconnect_timer.expires, self->time_reopen * 1000);
  iv_timer_register(&self->reconnect_timer);
}

static gboolean
afmef_dw_connected(AFSocketDestWriter *self)
{
        msg_debug("Debug log entry",
            evt_tag_str("Message: ", "In afmef_dw_connected"),
            NULL);


  AFSocketDestDriver *driver = self->owner;

  gchar buf1[256], buf2[256];
  int error = 0;
  socklen_t errorlen = sizeof(error);
  LogTransport *transport;
  LogProtoClient *proto;

  main_loop_assert_main_thread();

  if (iv_fd_registered(&self->connect_fd))
    iv_fd_unregister(&self->connect_fd);

  if (driver->sock_type == SOCK_STREAM)
    {
      if (getsockopt(self->fd, SOL_SOCKET, SO_ERROR, &error, &errorlen) == -1)
        {
          msg_error("getsockopt(SOL_SOCKET, SO_ERROR) failed for connecting socket",
                    evt_tag_int("fd", self->fd),
                    evt_tag_str("server", g_sockaddr_format(self->dest_addr, buf2, sizeof(buf2), GSA_FULL)),
                    evt_tag_errno(EVT_TAG_OSERROR, errno),
                    evt_tag_int("time_reopen", self->time_reopen),
                    NULL);
          goto error_reconnect;
        }
      if (error)
        {
          msg_error("Syslog connection failed",
                    evt_tag_int("fd", self->fd),
                    evt_tag_str("server", g_sockaddr_format(self->dest_addr, buf2, sizeof(buf2), GSA_FULL)),
                    evt_tag_errno(EVT_TAG_OSERROR, error),
                    evt_tag_int("time_reopen", self->time_reopen),
                    NULL);
          goto error_reconnect;
        }
    }
  msg_notice("Syslog connection established",
              evt_tag_int("fd", self->fd),
              evt_tag_str("server", g_sockaddr_format(self->dest_addr, buf2, sizeof(buf2), GSA_FULL)),
              evt_tag_str("local", g_sockaddr_format(self->bind_addr, buf1, sizeof(buf1), GSA_FULL)),
              NULL);


  transport = log_transport_stream_socket_new(self->fd);

  //proto = log_proto_client_factory_construct(driver->proto_factory, transport, &driver->writer_options.proto_options.super);

  proto = log_proto_mef_client_new(transport, &driver->writer_options.proto_options.super, self->saddr);

  log_writer_reopen(self->writer, proto);
  return TRUE;
 error_reconnect:
  close(self->fd);
  self->fd = -1;
  afmef_dw_start_reconnect_timer(self);
  return FALSE;
}

static gboolean
afmef_dw_start_connect(AFSocketDestWriter *self)
{
        msg_debug("Debug log entry",
            evt_tag_str("Message: ", "In afmef_dw_start_connect"),
            NULL);


  AFSocketDestDriver *driver = self->owner;
  int sock, rc;
  gchar buf1[MAX_SOCKADDR_STRING], buf2[MAX_SOCKADDR_STRING];

  main_loop_assert_main_thread();
  if (!afmef_open_socket(self->bind_addr, driver->sock_type, driver->sock_protocol, &sock))
    {
      return FALSE;
    }

  if (driver->setup_socket && !driver->setup_socket(self, sock))
    {
      close(sock);
      return FALSE;
    }

  g_assert(self->dest_addr);

  rc = g_connect(sock, self->dest_addr);
  if (rc == G_IO_STATUS_NORMAL)
    {
      self->fd = sock;
      afmef_dw_connected(self);
    }
  else if (rc == G_IO_STATUS_ERROR && errno == EINPROGRESS)
    {
      /* we must wait until connect succeeds */

      self->fd = sock;
      afmef_dw_start_watches(self);
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
  if (!afmef_dw_start_connect(self))
    {
      msg_error("Initiating connection failed, reconnecting",
                evt_tag_int("time_reopen", self->time_reopen),
                NULL);
      afmef_dw_start_reconnect_timer(self);
    }
}

gboolean
afmef_dd_init(LogPipe *s)
{
  AFSocketDestDriver *self = (AFSocketDestDriver *) s;
  GlobalConfig *cfg = log_pipe_get_config(s);

  if (!log_dest_driver_init_method(s))
    return FALSE;
  
  /*Copied over from apply_transport */

  if (self->transport == NULL)
    {
        afmef_dd_set_transport(&self->super.super, "tcp");
    }

  if (strcasecmp(self->transport, "tcp") == 0)
    {
      if (self->syslog_protocol)
        {
          self->logproto_name = "text";
          self->dest_port = "8081";
        }
      else
        {
          self->logproto_name = "text";
          self->dest_port = "8081";
        }
      self->sock_type = SOCK_STREAM;
      self->sock_protocol = 0;
    }
  else
    {
      self->sock_type = SOCK_STREAM;
      self->logproto_name = self->transport;
    }

 /* End copy from apply_transport */
   

  self->proto_factory = log_proto_client_get_factory(cfg, self->logproto_name);
  if (!self->proto_factory)
    {
      msg_error("Unknown value specified in the transport() option, no such LogProto plugin found",
                evt_tag_str("transport", self->logproto_name),
                NULL);
      return FALSE;
    }

  /* these fields must be set up by apply_transport, so let's check if it indeed did */
  g_assert(self->transport);
  g_assert(self->hostname);
  //g_assert(self->dest_name);

  if (cfg)
    {
      self->time_reopen = cfg->time_reopen;
    }
   log_writer_options_init(&self->writer_options, cfg, 0);
   self->writer = cfg_persist_config_fetch(cfg, afmef_dd_format_persist_name(self, FALSE));

  return TRUE;
}

gboolean
afmef_dd_deinit(LogPipe *s)
{
  AFSocketDestDriver *self = (AFSocketDestDriver *) s;
  GlobalConfig *cfg = log_pipe_get_config(s);


  if (self->writer)
    log_pipe_deinit(self->writer);

  if (self->connections_kept_alive_accross_reloads)
    {
      cfg_persist_config_add(cfg, afmef_dd_format_persist_name(self, FALSE), self->writer, (GDestroyNotify) log_pipe_unref, FALSE);
      self->writer = NULL;
    }

  if (!log_dest_driver_deinit_method(s))
    return FALSE;

  return TRUE;
}


static void
afmef_dw_notify(LogPipe *s, LogPipe *sender, gint notify_code, gpointer user_data)
{
  AFSocketDestWriter *self = (AFSocketDestWriter *) s;
  gchar buf[MAX_SOCKADDR_STRING];

  switch (notify_code)
    {
    case NC_CLOSE:
    case NC_WRITE_ERROR:
      log_writer_reopen(self->writer, NULL);

      msg_notice("Syslog connection broken",
                 evt_tag_int("fd", self->fd),
                 evt_tag_str("server", g_sockaddr_format(self->dest_addr, buf, sizeof(buf), GSA_FULL)),
                 evt_tag_int("time_reopen", self->time_reopen),
                 NULL);
      afmef_dw_start_reconnect_timer(self);
      break;
    }
}

void
afmef_dd_free(LogPipe *s)
{
  AFSocketDestDriver *self = (AFSocketDestDriver *) s;

  log_writer_options_destroy(&self->writer_options);
  g_free(self->hostname);
  g_free(self->dest_name);
  g_free(self->transport);
  log_dest_driver_free(s);
}

void
afmef_dd_init_instance(AFSocketDestDriver *self, SocketOptions *sock_options, gint family, gint sock_type, const gchar *hostname)
{
  log_dest_driver_init_instance(&self->super);

  log_writer_options_defaults(&self->writer_options);
  self->super.super.super.init = afmef_dd_init;
  self->super.super.super.deinit = afmef_dd_deinit;
  /* NULL behaves as if log_msg_forward_msg was specified */
  self->super.super.super.queue = NULL;
  self->super.super.super.free_fn = afmef_dd_free;
  self->setup_socket = afmef_dw_setup_socket;
  self->sock_options.super = *sock_options;
  self->sock_type = sock_type;
  self->address_family = family;
  self->connections_kept_alive_accross_reloads = TRUE;

  self->hostname = g_strdup(hostname);

  self->writer_options.mark_mode = MM_GLOBAL;
}


/*AFMEF_DW code here */

void
afmef_dw_queue(LogPipe *s, LogMessage *lm, const LogPathOptions *path_options, gpointer user_data)
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

  g_sockaddr_unref(self->bind_addr);
  g_sockaddr_unref(self->dest_addr);
  log_pipe_unref(self->writer);
 }
  

gboolean
afmef_dw_deinit(LogPipe *s)
{
 AFSocketDestWriter *self = (AFSocketDestWriter *) s;

 afmef_dw_stop_watches(self);

  if(self->writer)
    log_pipe_deinit(self->writer);
 
 
 return TRUE;
}


gboolean
afmef_dw_init(LogPipe *s)
{

        msg_debug("Debug log entry",
            evt_tag_str("Message: ", "In afmef_dw_init"),
            NULL);

 AFSocketDestWriter *self = (AFSocketDestWriter *) s;
 AFSocketDestDriver *driver = self->owner;
 GlobalConfig *cfg = log_pipe_get_config(s);

  if (!afmef_dw_apply_transport(self))
     return FALSE;

  g_assert(self->bind_addr);
  
    log_writer_options_init(&driver->writer_options, cfg, 0);
    self->writer = cfg_persist_config_fetch(cfg, afmef_dd_format_persist_name(driver, FALSE));
   
    if (!self->writer)
      {
              msg_debug("Debug log entry",
            evt_tag_str("Message: ", "Creating writer"),
            NULL);

         self->writer = log_writer_new(LW_FORMAT_PROTO |
                                        ((driver->sock_type == SOCK_STREAM) ? LW_DETECT_EOF : 0) |
                                        (driver->syslog_protocol ? LW_SYSLOG_PROTOCOL : 0));
       }   
	log_writer_set_options((LogWriter *) self->writer, &self->super, &driver->writer_options, 0, afmef_dw_stats_source(self), driver->super.super.id, afmef_dw_stats_instance(self));

	log_writer_set_queue(self->writer, log_dest_driver_acquire_queue(&driver->super, afmef_dd_format_persist_name(driver, TRUE)));

        log_pipe_init(self->writer, NULL);
        log_pipe_append(&self->super, self->writer);

  
  if (!log_writer_opened((LogWriter *) self->writer))
  {
	      msg_debug("Debug log entry",
            evt_tag_str("Message: ", "Calling reconnect"),
            NULL);

	afmef_dw_reconnect(self);
  }
 return TRUE;

}


AFSocketDestWriter *
afmef_dw_new(AFSocketDestDriver *owner, GString *src_hostname)
{
  AFSocketDestWriter *self = g_new0(AFSocketDestWriter, 1);

  log_pipe_init_instance(&self->super);

  self->owner = owner;
  self->super.init = afmef_dw_init;
  self->super.deinit = afmef_dw_deinit;
  self->super.free_fn = afmef_dw_free;
  self->super.queue = afmef_dw_queue;
  self->super.notify = afmef_dw_notify;
  self->apply_transport = afmef_dw_apply_transport;
  log_pipe_ref(&owner->super.super.super);

  self->bind_addr = g_sockaddr_inet_new("0.0.0.0", 0);
  self->dest_addr = g_sockaddr_inet_new("0.0.0.0", 8081);


  /* we have to take care about freeing filename later. 
 *      This avoids a move of the filename. */
  self->src_hostname = src_hostname;

  afmef_dw_init_watches(self);
  
  return self;


}

/*AFINET specific code below here*/

void
afmef_dd_set_localip(LogDriver *s, gchar *ip)
{
  AFSocketDestDriver *self = (AFSocketDestDriver *) s;

  if (self->bind_ip)
    g_free(self->bind_ip);
  self->bind_ip = g_strdup(ip);
}

void
afmef_dd_set_destport(LogDriver *s, gchar *service)
{
  AFSocketDestDriver *self = (AFSocketDestDriver *) s;

  if (self->dest_port)
    g_free(self->dest_port);
  self->dest_port = g_strdup(service);
}

static gboolean
afmef_dw_apply_transport(AFSocketDestWriter *self)
{
  AFSocketDestDriver *driver = self->owner;
  //GlobalConfig *cfg = log_pipe_get_config(&driver->super.super.super);
  gchar *default_dest_port  = NULL;
  struct protoent *ipproto_ent;

  g_sockaddr_unref(self->bind_addr);
  g_sockaddr_unref(self->dest_addr);

  if (driver->address_family == AF_INET)
    {
      self->bind_addr = g_sockaddr_inet_new("0.0.0.0", 0);
      self->dest_addr = g_sockaddr_inet_new("0.0.0.0", 0);
    }
  else
    {
      /* address family not known */
      g_assert_not_reached();
    }

  if ((driver->bind_ip && !resolve_hostname(&self->bind_addr, driver->bind_ip)))
    return FALSE;

  if (!driver->sock_protocol)
    {
        driver->sock_protocol = IPPROTO_TCP;
    }

  ipproto_ent = getprotobynumber(driver->sock_protocol);
  afinet_set_port(self->dest_addr, driver->dest_port ? : default_dest_port,
                  ipproto_ent ? ipproto_ent->p_name
                              : (driver->sock_type == SOCK_STREAM) ? "tcp" : "udp");

  if (!driver->dest_name)
    driver->dest_name = g_strdup_printf("%s:%d", driver->hostname,
                                            g_sockaddr_inet_check(self->dest_addr) ? g_sockaddr_inet_get_port(self->dest_addr)
                                            : 0
                                            );


  return TRUE;
}

static gboolean
afmef_dw_setup_socket(AFSocketDestWriter *self, gint fd)
{
  AFSocketDestDriver *driver = self->owner;

  if (!resolve_hostname(&self->dest_addr, driver->hostname))
    return FALSE;

  return afinet_setup_socket(fd, self->dest_addr, (InetSocketOptions *) &driver->sock_options, AFSOCKET_DIR_SEND);
}


static void
afmef_dd_queue(LogPipe *s, LogMessage *msg, const LogPathOptions *path_options, gpointer user_data)
{

    msg_debug("Debug log entry",
            evt_tag_str("Message:", "In afmef_dd_queue"),
            NULL);

  AFSocketDestDriver *self = (AFSocketDestDriver *) s;
  AFSocketDestWriter *next;

  char *saddr = NULL;
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
                saddr = NULL;

  if (next)
   {
             msg_debug("Debug log entry",
            evt_tag_str("Message: ", "Calling log_pipe_queue in dw_queue"),
            NULL);
    log_pipe_queue(&next->super, msg, path_options);
   }
   else
    log_msg_drop(msg, path_options);

  //log_dest_driver_queue_method(s, msg, path_options, user_data);
}

AFSocketDestDriver *
afmef_dd_new_instance(gint af, gint sock_type, gchar *host)
{
  AFSocketDestDriver *self = g_new0(AFSocketDestDriver, 1);

  afmef_dd_init_instance(self, &self->sock_options.super, af, sock_type, host);

  self->super.super.super.init = afmef_dd_init;
  self->super.super.super.queue = afmef_dd_queue;
  self->super.super.super.free_fn = afmef_dd_free;
  self->setup_socket = afmef_dw_setup_socket;
  
  if (sock_type == SOCK_STREAM)
    {
      self->sock_options.super.so_keepalive = TRUE;
#if defined(TCP_KEEPTIME) && defined(TCP_KEEPIDLE) && defined(TCP_KEEPCNT)
      self->sock_options.tcp_keepalive_time = 60;
      self->sock_options.tcp_keepalive_intvl = 10;
      self->sock_options.tcp_keepalive_probes = 6;
#endif
    }

  return self;
}

LogDriver *
afmef_dd_new(gint af, gint sock_type, gchar *host)
{
  return &afmef_dd_new_instance(af, sock_type, host)->super.super;
}

