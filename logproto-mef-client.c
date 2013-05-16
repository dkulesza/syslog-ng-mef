/*
 * Copyright (c) 2002-2012 BalaBit IT Ltd, Budapest, Hungary
 * Copyright (c) 1998-2012 Balázs Scheidler
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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
#include "logproto-mef-client.h"
#include "logproto-text-client.h"
#include "netinet/in.h"
#include "arpa/inet.h"
#include "messages.h"
#include "stdio.h"

#define LPFCS_SESS_INIT     0 
#define LPFCS_FRAME_SEND    1 
#define LPFCS_MESSAGE_SEND  2 

#define MAGIC_SYNC_PACKET 0xfeedfaceaa55aa55LL
#define IP_START {0x06, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00}
#define MSG_START {0x06, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

typedef struct _LogProtoMEFClient
{
  LogProtoTextClient super;
  char *saddr;
  guchar *buffer;
  gint buffer_size;
  guchar frame_hdr_buf[24];
} LogProtoMEFClient;

static LogProtoStatus
log_proto_mef_client_post(LogProtoClient *s, guchar *msg, gsize msg_len, gboolean *consumed)
{
  LogProtoMEFClient *self = (LogProtoMEFClient *) s;
  gint frame_hdr_len;
  gint rc;
  unsigned long ip;
  uint64_t magic = MAGIC_SYNC_PACKET;
  char msg_start[14] = MSG_START;
  char ip_start[12] = IP_START;
  char startmsg[24];
  char *okay;

  if (G_UNLIKELY(!self->buffer))
  {
     self->buffer_size = 8194 + 25;
     self->buffer = g_malloc(self->buffer_size);

  }


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

  rc = LPS_SUCCESS;
  while (rc == LPS_SUCCESS && !(*consumed) && self->super.partial == NULL)
    {
      switch (self->super.state)
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
    	    if(rc > 0)
	    {
	    	okay = (char*)memmem(self->buffer, self->buffer_size, "OKAY", 4);

   	    	if(!okay)
        	   goto read_frame;
	    } else 
		goto read_frame;

	    self->super.state = LPFCS_FRAME_SEND;
	  break;
	case LPFCS_FRAME_SEND:
          
	  memcpy(self->frame_hdr_buf, &magic, sizeof(magic));
      	  memcpy(self->frame_hdr_buf + sizeof(magic), msg_start, sizeof(msg_start));
          memcpy(self->frame_hdr_buf + sizeof(magic) + sizeof(msg_start), &msg_len, 4);
          frame_hdr_len = sizeof(self->frame_hdr_buf);

	  rc = log_proto_text_client_submit_write(s, self->frame_hdr_buf, frame_hdr_len, NULL, LPFCS_MESSAGE_SEND);
          break;
        case LPFCS_MESSAGE_SEND:
          *consumed = TRUE;
          rc = log_proto_text_client_submit_write(s, msg, msg_len, (GDestroyNotify) g_free, LPFCS_FRAME_SEND);
          break;
        default:
          g_assert_not_reached();
        }
    }

  return rc;
}


LogProtoClient *
log_proto_mef_client_new(LogTransport *transport, const LogProtoClientOptions *options, char *saddr)
{
  LogProtoMEFClient *self = g_new0(LogProtoMEFClient, 1);

  log_proto_text_client_init(&self->super, transport, options);
  self->super.super.post = log_proto_mef_client_post;
  self->saddr = saddr; 
  self->super.state = LPFCS_SESS_INIT;
  return &self->super.super;
}
