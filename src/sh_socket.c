/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2003,2005 Rainer Wichmann                                 */
/*                                                                         */
/*  This program is free software; you can redistribute it                 */
/*  and/or modify                                                          */
/*  it under the terms of the GNU General Public License as                */
/*  published by                                                           */
/*  the Free Software Foundation; either version 2 of the License, or      */
/*  (at your option) any later version.                                    */
/*                                                                         */
/*  This program is distributed in the hope that it will be useful,        */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of         */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          */
/*  GNU General Public License for more details.                           */
/*                                                                         */
/*  You should have received a copy of the GNU General Public License      */
/*  along with this program; if not, write to the Free Software            */
/*  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.              */

#include "config_xor.h"

/* define if you want debug info
 * #define SH_DEBUG_SOCKET
 */

#if defined(SH_WITH_SERVER) && defined(__linux__)
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#if TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#include "samhain.h"
#include "sh_socket.h"
#include "sh_error.h"
#include "sh_unix.h"
#include "sh_calls.h"
#include "sh_guid.h"
#include "sh_fifo.h"
#include "sh_utils.h"

#undef  FIL__
#define FIL__  _("sh_socket.c")

#if defined (SH_WITH_CLIENT)

#include <signal.h>

typedef struct delta_tofetch {
  char            uuid[SH_UUID_BUF];
  time_t          last_time;
  unsigned int    count;
} SH_DELTA_DB;

static SH_DELTA_DB * parse_entry(SH_DELTA_DB * db, const char * str)
{
  long last_time;
  unsigned int count;
  char buf[SH_UUID_BUF];
  int res = sscanf(str, _("%u:%ld:%36s"), &count, &last_time, buf);
  if (res == 3)
    {
      db->count = count;
      db->last_time  = (time_t) last_time;
      sl_strlcpy(db->uuid, buf, SH_UUID_BUF);
      return db;
    }
  return NULL;
}

static char * unparse_entry(const SH_DELTA_DB * db, char * str, size_t len)
{
  int nbytes = sl_snprintf(str, len, _("%u:%ld:%s"), 
			   db->count, (long) db->last_time, db->uuid);
  if (nbytes < 0 || nbytes >= (int) len)
    return NULL;
  return str;
}

static SH_FIFO xfifo = SH_FIFO_INITIALIZER;

int sh_socket_store_uuid(const char * cmd)
{
  char * p = sh_util_strdup(cmd);
  char * q = strchr(cmd, ':');
  char   entry[SH_BUFSIZE];
  SH_DELTA_DB db;

  if (!q) { SH_FREE(p); return -1; }

  ++q;

  if (0 != sh_uuid_check(q)) { SH_FREE(p); return -1; }

  db.count = 0;
  db.last_time = (time_t) 0;
  sl_strlcpy(db.uuid, q, SH_UUID_BUF);
  SH_FREE(p);

  if (NULL != unparse_entry(&db, entry, sizeof(entry)))
    {
      sh_fifo_push(&xfifo, entry);
      return 0;
    }
  return -1;
}

static unsigned int try_interval = 60;
static unsigned int try_max = 2;

int set_delta_retry_interval(const char * str)
{
  long val = strtol (str, (char **)NULL, 10);

  if (val < 0 || val > INT_MAX)
    return -1;
  try_interval = (unsigned int) val;
  return 0;
}
int set_delta_retry_count(const char * str)
{
  long val = strtol (str, (char **)NULL, 10);

  if (val < 0 || val > INT_MAX)
    return -1;
  try_max = (unsigned int) val;
  return 0;
}

char * sh_socket_get_uuid(int * errflag, unsigned int * count, time_t * last)
{
  char * entry = sh_fifo_pop(&xfifo);
  char * uuid = NULL;

  if (entry)
    {
      SH_DELTA_DB db;
      time_t      now;
      
      if (NULL == parse_entry(&db, entry))
	{
	  SH_FREE(entry);
	  sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			  _("Bad entry in fifo"), 
			  _("sh_socket_get_uuid"));
	  *errflag = -1;
	  return NULL;
	}

      now = time(NULL);

      if ( (db.count > 0) && ((unsigned long)(now - db.last_time) < try_interval) )
	{
	  sh_fifo_push_tail(&xfifo, entry);
	  SH_FREE(entry);
	  *errflag = -1;
	  return NULL;
	}

      SH_FREE(entry);
      uuid   = sh_util_strdup(db.uuid);
      *count = db.count;
      *last  = db.last_time;
    }

  *errflag = 0;
  return uuid;
}

int sh_socket_return_uuid (const char * uuid, unsigned int count, time_t last)
{
  (void) last;

  if (count < try_max)
    {
      char   entry[SH_BUFSIZE];
      SH_DELTA_DB db;
      time_t now = time(NULL);

      db.count     = count + 1;
      db.last_time = now;
      sl_strlcpy(db.uuid, uuid, SH_UUID_BUF);

      if (NULL != unparse_entry(&db, entry, sizeof(entry)))
	return sh_fifo_push_tail(&xfifo, entry); /* >0 for success */
    }
  return -1;
}

void sh_socket_server_cmd(const char * srvcmd)
{
  SL_ENTER(_("sh_tools_server_cmd"));

  if ((srvcmd == NULL) || (srvcmd[0] == '\0') || (sl_strlen(srvcmd) < 4))
    {
      SL_RET0(_("sh_socket_server_cmd"));
    }

  if (0 == strncmp(srvcmd, _("STOP"), 4))
    {
      TPT((0, FIL__, __LINE__, _("msg=<stop command from server>\n")));
#ifdef SIGQUIT
      raise(SIGQUIT);
#else
      sig_terminate       = 1;
      ++sig_raised;
#endif
    } 

  else if (0 == strncmp(srvcmd, _("RELOAD"), 6))
    {
      TPT((0, FIL__, __LINE__, _("msg=<reload command from server>\n")));
#ifdef SIGHUP
      raise(SIGHUP);
#else
      sig_config_read_again = 1;
      ++sig_raised;
#endif
    }

  else if (0 == strncmp(srvcmd, _("DELTA:"), 6))
    {
      TPT((0, FIL__, __LINE__, _("msg=<delta load command from server>\n")));

      if (sh_socket_store_uuid(srvcmd) == 0)
	{
	  ++sh_load_delta_flag;
	  ++sig_raised;
	}
    }

  else if (0 == strncmp(srvcmd, _("SCAN"), 4))
    {
      TPT((0, FIL__, __LINE__, _("msg=<scan command from server>\n")));
      if (sh.flag.isdaemon == S_TRUE) 
	{ 
#ifdef SIGTTOU
	  raise(SIGTTOU);
#else
	  sig_force_check = 1;
	  ++sig_raised;
#endif
	} 
      else 
	{
	  sig_force_check = 1;
	  ++sig_raised;
	}
    }

  /* Unknown command 
   */
  else
    {
      sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      srvcmd, 
		      _("sh_socket_server_cmd"));
    }
  SL_RET0(_("sh_socket_server_cmd"));
}
#endif  /* #if defined (SH_WITH_CLIENT) */

#if defined(SH_WITH_SERVER)
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <fcntl.h>

#include <time.h>

#include <sys/socket.h>
#include <sys/un.h>


#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#if !defined(HAVE_GETPEEREID) && !defined(SO_PEERCRED)
#if defined(HAVE_STRUCT_CMSGCRED) || defined(HAVE_STRUCT_FCRED) || defined(HAVE_STRUCT_SOCKCRED)
#include <sys/param.h>
#include <sys/ucred.h>
#endif
#endif


int    pf_unix_fd  = -1;
static char * sh_sockname = NULL;
static char   sh_sockpass_real[SOCKPASS_MAX+1];

struct socket_cmd {
  char cmd[SH_MAXMSGLEN];
  char clt[SH_MAXMSGLEN];
  char cti[81];
  struct socket_cmd * next;
};

#if !defined(O_NONBLOCK)
#if defined(O_NDELAY)
#define O_NONBLOCK  O_NDELAY
#else
#define O_NONBLOCK  0
#endif
#endif

#if !defined(AF_FILE)
#define AF_FILE AF_UNIX
#endif

static struct socket_cmd * cmdlist    = NULL;
static struct socket_cmd * runlist    = NULL;

static int    sh_socket_flaguse = S_FALSE;
static int    sh_socket_flaguid = 0;

#include "sh_utils.h"

/* The reload list stores information about
 * reloads confirmed by clients (startup and/or
 * runtime cinfiguration reloaded).
 */
struct reload_cmd {
  char          clt[SH_MAXMSGLEN];
  time_t        cti;
  struct reload_cmd * next;
};
static struct reload_cmd * reloadlist = NULL;

void sh_socket_add2reload (const char * clt)
{
  struct reload_cmd  * new = reloadlist;

  while (new)
    {
      if (0 == sl_strcmp(new->clt, clt))
	{
#ifdef SH_DEBUG_SOCKET
	  fprintf(stderr, "add2reload: time reset for %s\n", clt);
#endif
	  sl_strlcpy (new->clt, clt, SH_MAXMSGLEN);
	  new->cti = time(NULL);
	  return;
	}
      new = new->next;
    }

  new = SH_ALLOC(sizeof(struct reload_cmd));
#ifdef SH_DEBUG_SOCKET
  fprintf(stderr, "add2reload: time set for %s\n", clt);
#endif
  sl_strlcpy (new->clt, clt, SH_MAXMSGLEN);
  new->cti = time(NULL);

  new->next    = reloadlist;
  reloadlist   = new;

  return;
}

#include "zAVLTree.h"
#include "sh_html.h"
#include "sh_tools.h"
static void sh_socket_add2list (struct socket_cmd * in);

static void sh_socket_probe4reload (void)
{
  struct reload_cmd  * new;
  struct socket_cmd    cmd;

  zAVLCursor avlcursor;
  client_t * item;
  extern zAVLTree * all_clients;

  char     * file;
  unsigned long dummy;
  struct stat buf;

  for (item = (client_t *) zAVLFirst(&avlcursor, all_clients); item;
       item = (client_t *) zAVLNext(&avlcursor))
    {
      if (item->status_now != CLT_INACTIVE)
	{
	  int flag = 0;

	  file = get_client_conf_file (item->hostname, &dummy);

	  if (0 == stat (file, &buf))
	    {
	      new = reloadlist;
	      while (new)
		{
		  if (0 == sl_strcmp(new->clt, item->hostname))
		    {
		      flag = 1; /* Client is in list already */

		      if (buf.st_mtime > new->cti)
			{
			  /* reload */
			  sl_strlcpy(cmd.cmd, _("RELOAD"),    SH_MAXMSGLEN);
			  sl_strlcpy(cmd.clt, item->hostname, SH_MAXMSGLEN);
			  sh_socket_add2list (&cmd);
			}
		      break;
		    }
		  new = new->next;
		}

	      if (flag == 0)
		{
		  /* client is active, but start message has been missed; reload 
		   */
		  sl_strlcpy(cmd.cmd, _("RELOAD"),    SH_MAXMSGLEN);
		  sl_strlcpy(cmd.clt, item->hostname, SH_MAXMSGLEN);
		  sh_socket_add2list (&cmd);

		  /* Add the client to the reload list and set
		   * time to 0, since we don't know the startup time.
		   */
		  sh_socket_add2reload (item->hostname);
		  new = reloadlist;
		  while (new)
		    {
		      if (0 == sl_strcmp(new->clt, item->hostname))
			{
			  new->cti = 0;
			  break;
			}
		      new = new->next;
		    }
		}
	    } /* if stat(file).. */
	} /* if !CLT_INACTIVE */
    } /* loop over clients */
  return;
}

char * sh_get_sockpass (void)
{
  size_t j = 0;

  while (skey->sh_sockpass[2*j] != '\0' && j < sizeof(sh_sockpass_real))
    {
      sh_sockpass_real[j] = skey->sh_sockpass[2*j];
      ++j;
    }
  sh_sockpass_real[j] = '\0';

  return sh_sockpass_real;
}

void sh_set_sockpass (void)
{
  int j;
  for (j = 0; j < 15; ++j)
    {
      sh_sockpass_real[j] = '\0';
    }
}

int sh_socket_use (const char * c)
{
  return sh_util_flagval(c, &sh_socket_flaguse);
}

int sh_socket_remove ()
{
  int retval = 0;
#ifdef S_ISSOCK
  struct stat sbuf;
#endif

  SL_ENTER(_("sh_socket_remove"));

  if (NULL == sh_sockname)
    {
      SL_RETURN((retval),_("sh_socket_remove"));
    }

  if (0 != tf_trust_check (DEFAULT_PIDDIR, SL_YESPRIV))
    {
      SL_RETURN((-1),_("sh_socket_remove"));
    }

  if ( (retry_lstat(FIL__, __LINE__, sh_sockname, &sbuf) == 0) && 
       (sbuf.st_uid == getuid()))
    {
#ifdef S_ISSOCK
      if (S_ISSOCK (sbuf.st_mode))
	{
	  retval = retry_aud_unlink (FIL__, __LINE__, sh_sockname);
	}
#else
      retval = retry_aud_unlink (FIL__, __LINE__, sh_sockname);
#endif
    }
  SL_RETURN((retval),_("sh_socket_remove"));
}

#if !defined(HAVE_GETPEEREID) && !defined(SO_PEERCRED) && !defined(HAVE_STRUCT_CMSGCRED) && !defined(HAVE_STRUCT_FCRED) && !(defined(HAVE_STRUCT_SOCKCRED) && defined(LOCAL_CREDS))

#define NEED_PASSWORD_AUTH
#endif

int sh_socket_uid (const char * c)
{
  uid_t val = (uid_t) strtol (c, (char **)NULL, 10);
  sh_socket_flaguid = val;
#if defined(NEED_PASSWORD_AUTH)
  sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, errno, MSG_E_SUBGEN,
		  _("Config option SetSocketAllowUID not supported, use SetSocketPassword"), 
		  _("sh_socket_uid"));
#endif
  return 0;
}

int sh_socket_password (const char * c)
{
#if defined(NEED_PASSWORD_AUTH)
  int j, i;
  
#define LCG(n) ((69069 * n) & 0xffffffffUL)

  i = sl_strlen(c);
  if (i > SOCKPASS_MAX) {
    return -1;
  }
  for (j = 0; j < (2*SOCKPASS_MAX+1); ++j)
    {
      skey->sh_sockpass[j] = '\0';
    }
  for (j = 0; j < i; ++j)
    {
      skey->sh_sockpass[2*j]     = c[j];
      skey->sh_sockpass[(2*j)+1] = (LCG(c[j]) % 256);
    }
  return 0;
#else
  sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, errno, MSG_E_SUBGEN,
		  _("Config option SetSocketPassword not supported, use SetSocketAllowUID"), 
		  _("sh_socket_password"));
  (void) c;
  return 0;
#endif
}


int sh_socket_open_int ()
{
  struct sockaddr_un name;
  size_t size;
  int    flags;
#if defined(SO_PASSCRED) 
  socklen_t    optval = 1;
#endif
  struct stat buf;
  char errbuf[SH_ERRBUF_SIZE];
  
  SL_ENTER(_("sh_socket_open_int"));

  if (sh_socket_flaguse == S_FALSE)
    {
      SL_RETURN(0, _("sh_socket_open_int"));
    }

  if (sh_sockname == NULL)
    {
      size = sl_strlen(DEFAULT_PIDDIR) + 1 + sl_strlen(SH_INSTALL_NAME) + 6;
      sh_sockname = SH_ALLOC(size); /* compile-time constant */
      sl_strlcpy(sh_sockname, DEFAULT_PIDDIR, size);
      sl_strlcat(sh_sockname, "/", size);
      sl_strlcat(sh_sockname, SH_INSTALL_NAME, size);
      sl_strlcat(sh_sockname, _(".sock"), size);
    }

  if (0 != sh_unix_check_piddir (sh_sockname))
    {
      SH_FREE(sh_sockname);
      SL_RETURN((-1),_("sh_socket_open_int"));
    }

  pf_unix_fd = socket (PF_UNIX, SOCK_STREAM, 0);
  if ((pf_unix_fd) < 0)
    {
      sh_error_handle ((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		       sh_error_message (errno, errbuf, sizeof(errbuf)), 
		       _("sh_socket_open_int: socket"));
      SL_RETURN( (-1), _("sh_socket_open_int"));
    }

  if (sizeof(name.sun_path) < (1 + sl_strlen(sh_sockname)))
    {
      sl_close_fd(FIL__, __LINE__, pf_unix_fd); pf_unix_fd = -1;
      sh_error_handle ((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
		       _("PID dir path too long"), 
		       _("sh_socket_open_int"));
      SL_RETURN( (-1), _("sh_socket_open_int"));
    }

  name.sun_family = AF_FILE;
  sl_strlcpy (name.sun_path, sh_sockname, sizeof(name.sun_path));

  size = (offsetof (struct sockaddr_un, sun_path)
          + strlen (name.sun_path) + 1);

  flags = retry_lstat (FIL__, __LINE__, sh_sockname, &buf);

  if (flags == 0)
    {
      sh_error_handle(SH_ERR_INFO, FIL__, __LINE__, -1, MSG_E_SUBGEN,
		      _("Socket exists, trying to unlink it"), 
		      _("sh_socket_open_int"));
      if (sh_socket_remove() < 0) 
	{
	  sl_close_fd(FIL__, __LINE__, pf_unix_fd); pf_unix_fd = -1;
	  sh_error_handle ((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
			   _("Unlink of socket failed, maybe path not trusted"), 
			   _("sh_socket_open_int"));
	  SL_RETURN( (-1), _("sh_socket_open_int"));
	}
    }

  if (bind ((pf_unix_fd), (struct sockaddr *) &name, size) < 0)
    {
      sl_close_fd(FIL__, __LINE__, pf_unix_fd); pf_unix_fd = -1;
      sh_error_handle ((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		       sh_error_message (errno, errbuf, sizeof(errbuf)), 
		       _("sh_socket_open_int: bind"));
      SL_RETURN( (-1), _("sh_socket_open_int"));
    }

#ifdef SO_PASSCRED
  if (0 != setsockopt(pf_unix_fd, SOL_SOCKET, SO_PASSCRED, 
		      &optval, sizeof(optval)))
    {
      sl_close_fd(FIL__, __LINE__, pf_unix_fd); pf_unix_fd = -1;
      sh_error_handle ((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		       sh_error_message (errno, errbuf, sizeof(errbuf)), 
		       _("sh_socket_open_int: setsockopt"));
      SL_RETURN( (-1), _("sh_socket_open_int"));
    }
#endif

  flags = fcntl((pf_unix_fd), F_GETFL);
  if (flags < 0)
    {
      sl_close_fd(FIL__, __LINE__, pf_unix_fd); pf_unix_fd = -1;
      sh_error_handle ((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		       sh_error_message (errno, errbuf, sizeof(errbuf)), 
		       _("sh_socket_open_int: fcntl1"));
      SL_RETURN( (-1), _("sh_socket_open_int"));
    }

  flags = fcntl((pf_unix_fd), F_SETFL, flags|O_NONBLOCK);
  if (flags < 0)
    {
      sl_close_fd(FIL__, __LINE__, pf_unix_fd); pf_unix_fd = -1;
      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		      sh_error_message (errno, errbuf, sizeof(errbuf)), 
		      _("sh_socket_open_int: fcntl2"));
      SL_RETURN( (-1), _("sh_socket_open_int"));
    }

  if (0 != listen(pf_unix_fd, 5))
    {
      sl_close_fd(FIL__, __LINE__, pf_unix_fd); pf_unix_fd = -1;
      sh_error_handle ((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		       sh_error_message (errno, errbuf, sizeof(errbuf)), 
		       _("sh_socket_open_int: listen"));
      SL_RETURN( (-1), _("sh_socket_open_int"));
    }
  SL_RETURN( (0), _("sh_socket_open_int"));
}


/*
 * Parts of the socket authentication code is copied from PostgreSQL:
 *
 * PostgreSQL Database Management System
 * (formerly known as Postgres, then as Postgres95)
 *
 * Portions Copyright (c) 1996-2001, The PostgreSQL Global Development Group
 *
 * Portions Copyright (c) 1994, The Regents of the University of California
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose, without fee, and without a written agreement
 * is hereby granted, provided that the above copyright notice and this
 * paragraph and the following two paragraphs appear in all copies.
 *
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS
 * DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATIONS TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 */

static int receive_message(int talkfd, struct msghdr * msg, size_t message_size)
{
  unsigned int retry = 0;
  int nbytes;
  char * message = msg->msg_iov->iov_base;
  char errbuf[SH_ERRBUF_SIZE];

  do {
    nbytes = recvmsg (talkfd, msg, 0);
    if ((nbytes < 0) && (errno != EAGAIN))
      {
	sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
			sh_error_message (errno, errbuf, sizeof(errbuf)),
			_("sh_socket_read: recvmsg"));
	sl_close_fd(FIL__, __LINE__, talkfd);	
	return -1;
      }
    else if (nbytes < 0)
      {
	++retry;
	retry_msleep(0, 10);
      }
  } while ((nbytes < 0) && (retry < 3));

  /* msg.msg_iov.iov_base, filled by recvmsg
   */
  message[message_size-1] = '\0';

  if (nbytes < 0)
    {
      if (errno == EAGAIN)
	{
	  /* no data */
	  sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, errno, MSG_E_SUBGEN,
			  sh_error_message (errno, errbuf, sizeof(errbuf)), 
			  _("sh_socket_read: recvfrom"));
	  sl_close_fd(FIL__, __LINE__, talkfd);
	  return 0;
	}
      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		      sh_error_message (errno, errbuf, sizeof(errbuf)), 
		      _("sh_socket_read: recvfrom"));
      sl_close_fd(FIL__, __LINE__, talkfd);
      return -1;
    }
  return 0;
}

#if defined(HAVE_GETPEEREID)

static int get_peer_uid(int talkfd)
{
  uid_t peer_uid;
  gid_t peer_gid;
  char errbuf[SH_ERRBUF_SIZE];

  if (0 != getpeereid(talkfd, &peer_uid, &peer_gid))
    {
      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		      sh_error_message (errno, errbuf, sizeof(errbuf)), 
		      _("sh_socket_read: getpeereid"));
      sl_close_fd(FIL__, __LINE__, talkfd);
      return -1;
    }
  return peer_uid;
}

#elif defined(SO_PEERCRED) 

static int get_peer_uid(int talkfd)
{
  char errbuf[SH_ERRBUF_SIZE];
  struct ucred cr;
#ifdef HAVE_SOCKLEN_T
  socklen_t cl = sizeof(cr);
#else
  int       cl = sizeof(cr);
#endif 

  if (0 != getsockopt(talkfd, SOL_SOCKET, SO_PEERCRED, &cr, &cl))
    {
      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		      sh_error_message (errno, errbuf, sizeof(errbuf)), 
		      _("sh_socket_read: getsockopt"));
      sl_close_fd(FIL__, __LINE__, talkfd);
      return -1;
    }
  return cr.uid;
}

#endif

#if defined(NEED_PASSWORD_AUTH)
char * check_password(char * message, int * client_uid, int talkfd)
{
  char * cmd = NULL;
  char * eopw = NULL;
  char * goodpassword = NULL;

  goodpassword = sh_get_sockpass();
  eopw = strchr(message, '@');
  if (eopw) 
    *eopw = '\0';
  /*
   * message is null-terminated and >> goodpassword
   */
  if (0 == strcmp(goodpassword, message) &&
      strlen(goodpassword) < (sizeof(message)/2))
    {
      *client_uid = sh_socket_flaguid;
      cmd = &message[strlen(goodpassword)+1];
      sh_set_sockpass();
    }
  else
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      _("Bad password"), 
		      _("sh_socket_read"));
      sh_set_sockpass();
      sl_close_fd(FIL__, __LINE__, talkfd);
      return NULL;
    }
  return cmd;
}
#endif

static int list_all (int talkfd, char * cmd);
static int process_message(int talkfd, char * cmd, struct socket_cmd * srvcmd);

static 
int sh_socket_read (struct socket_cmd * srvcmd)
{
  char message[SH_MAXMSG];
  struct sockaddr_un name;
  ACCEPT_TYPE_ARG3 size = sizeof(name);
  int talkfd;
  char * cmd = NULL;
  int  client_uid = -1;
  char errbuf[SH_ERRBUF_SIZE];
  struct msghdr msg;
  struct iovec iov;
  int status;

  if (pf_unix_fd  < 0)
    return 0;

  iov.iov_base = (char *) &message;
  iov.iov_len  = sizeof(message);

  memset (&msg, 0, sizeof (msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  /* the socket is non-blocking 
   * 'name' is the address of the sender socket
   */
  do {
    talkfd = accept(pf_unix_fd, (struct sockaddr *) &name, &size);
  } while (talkfd < 0 && errno == EINTR);

  if ((talkfd < 0) && (errno == EAGAIN))
    {
      return 0;
    }
  else if (talkfd < 0)
    {
      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		      sh_error_message (errno, errbuf, sizeof(errbuf)), 
		      _("sh_socket_read: accept"));
      return -1;
    }

  if (receive_message(talkfd, &msg, sizeof(message)) < 0)
    return -1;

  /* Authenticate request by peer uid or password.
   */
#if defined(HAVE_GETPEEREID)
  client_uid = get_peer_uid(talkfd);
  cmd = message;

#elif defined(SO_PEERCRED)
  client_uid = get_peer_uid(talkfd);
  cmd = message;

#elif defined(NEED_PASSWORD_AUTH)
  cmd = check_password(message, &client_uid, talkfd);

#else
  sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		  _("Socket credentials not supported on this OS"), 
		  _("sh_socket_read"));
  sl_close_fd(FIL__, __LINE__, talkfd);
  return -1;
#endif

  if (client_uid != sh_socket_flaguid)
    {
      sh_error_handle((-1), FIL__, __LINE__, client_uid, MSG_E_SUBGEN,
		      _("client does not have required uid"), 
		      _("sh_socket_read: getsockopt"));
      sl_close_fd(FIL__, __LINE__, talkfd);
      return -1;
    }

  status = process_message(talkfd, cmd, srvcmd);

  sl_close_fd(FIL__, __LINE__, talkfd);
  return status;
}

static int check_valid_command(const char * str)
{
  unsigned int i = 0;
  char * commands[] = { N_("DELTA"),  N_("RELOAD"),  N_("STOP"), N_("SCAN"),
			N_("CANCEL"), N_("LISTALL"), N_("LIST"), N_("PROBE"), NULL };

  while (commands[i])
    {
      if (0 == strcmp(_(commands[i]), str))
	{
	  return 0;
	}
      ++i;
    }
  return -1;
}

static int send_reply (int fd, char * msg)
{
  int nbytes = send (fd, msg, strlen(msg) + 1, 0);

  if (nbytes < 0)
    {
      char errbuf[SH_ERRBUF_SIZE];
      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		      sh_error_message (errno, errbuf, sizeof(errbuf)), 
		      _("send_reply"));
      return -1;
    }

  return nbytes;
}

static int process_message(int talkfd, char * cmd, struct socket_cmd * srvcmd)
{
  int nbytes;
  char error_type[SH_ERRBUF_SIZE] = { '\0' };
  char * clt  = (cmd) ? strchr(cmd, ':') : NULL;

  if (clt && 0 == strncmp(cmd, _("DELTA:"), 6))
    {
      /* DELTA:uuid:hostname 
       */
      char * uuid = clt;
      
      *uuid = '\0'; ++uuid;
      clt = strchr(uuid, ':');
      if (clt) { *clt = '\0'; ++clt; }
      
      if (sh_uuid_check(uuid) < 0)
	{
	  sl_strlcpy(error_type, _("!E:uuid-format:"), sizeof(error_type));
	  sl_strlcat(error_type, uuid, sizeof(error_type));
	  clt = NULL;
	}
      
      --uuid; *uuid = ':';
    }
  else if (clt && *clt == ':')
    { 
      *clt = '\0'; ++clt; 
      if (check_valid_command(cmd) < 0)
	{
	  sl_strlcpy(error_type, _("!E:cmd-invalid:"), sizeof(error_type));
	  sl_strlcat(error_type, cmd, sizeof(error_type));
	  clt = NULL;
	}
    }
    
  if (clt != NULL) 
    {
      if (sl_strlen(cmd) >= SH_MAXMSGLEN)
	{
	  sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
			  _("Bad message format: command too long"), 
			  _("sh_socket_read"));
	  sl_strlcpy(error_type, _("!E:cmd-toolong"), sizeof(error_type));
	  send_reply(talkfd, error_type);
	  return -1;
	}
      else if (sl_strlen(clt) >= SH_MAXMSGLEN)
	{
	  sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
			  _("Bad message format: hostname too long"), 
			  _("sh_socket_read"));
	  sl_strlcpy(error_type, _("!E:hostname-toolong"), sizeof(error_type));
	  send_reply(talkfd, error_type);
	  return -1;
	}

      if (0 == strncmp(cmd, _("LIST"), 4))
	return list_all(talkfd, cmd);
      else if (0 == strncmp(cmd, _("PROBE"), 4))
	{
	  sh_socket_probe4reload();
	  sl_strlcpy(cmd, _("LIST"), 5);
	  return list_all(talkfd, cmd);
	}

      sl_strlcpy (srvcmd->cmd, cmd, SH_MAXMSGLEN);
      sl_strlcpy (srvcmd->clt, clt, SH_MAXMSGLEN);
      --clt; *clt = ':';
    }
  else
    {
      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
		      _("Bad message format"), 
		      _("sh_socket_read"));
      if (error_type[0] == '\0')
	sl_strlcpy(error_type, _("!E:message-format"), sizeof(error_type));
      send_reply(talkfd, error_type);
      return -1;
    }

  /* Bounce the message back to the sender. 
   */
  nbytes = send_reply(talkfd, cmd);

  return nbytes;
}

static int list_all (int talkfd, char * cmd)
{
  int nbytes;
  struct socket_cmd * list_cmd;
  char message[SH_MAXMSG];
  char errbuf[SH_ERRBUF_SIZE];

  if (0 == strncmp(cmd, _("LISTALL"), 7))
    {
      list_cmd = runlist;
      while (list_cmd)
	{
	  sl_snprintf(message, sizeof(message), _("SENT  %42s  %32s  %s"),
		      list_cmd->cmd, list_cmd->clt, list_cmd->cti);

	  nbytes = send (talkfd, message, sl_strlen(message) + 1, 0);
	  if (nbytes < 0)
	    {
	      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
			      sh_error_message (errno, errbuf, sizeof(errbuf)), 
			      _("sh_socket_read: sendto"));
	      return -1;
	    }
	  list_cmd = list_cmd->next;
	}
    }

  list_cmd = cmdlist;
  while (list_cmd)
    {
      sl_snprintf(message, sizeof(message), _(">>>>  %42s  %32s  %s"),
		  list_cmd->cmd, list_cmd->clt, list_cmd->cti);

      nbytes = send (talkfd, message, sl_strlen(message) + 1, 0);
      if (nbytes < 0)
	{
	  sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
			  sh_error_message (errno, errbuf, sizeof(errbuf)), 
			  _("sh_socket_read: sendto"));
	  return -1;
	}
      list_cmd = list_cmd->next;
    }

  send (talkfd, _("END"), 4, 0);
  return 0;
}

static void sh_socket_add2list (struct socket_cmd * in)
{
  struct socket_cmd  * new  = cmdlist;
  struct socket_cmd  * last = cmdlist;

  while (new)
    {
      /* Only skip identical commands.
       */
      if (0 == sl_strcmp(new->clt,  in->clt) &&
	  0 == sl_strcmp(new->cmd,  in->cmd))
	{
	  (void) sh_unix_time(0, new->cti, sizeof(new->cti));
	  return;
	}
      new = new->next;
    }

  new = SH_ALLOC(sizeof(struct socket_cmd));
  sl_strlcpy (new->cmd,  in->cmd,  sizeof(new->cmd));
  sl_strlcpy (new->clt,  in->clt,  sizeof(new->clt));
  (void) sh_unix_time(0, new->cti, sizeof(new->cti));
  new->next  = NULL;

  if (last)
    {
      while (last->next) { last = last->next; }
      last->next = new;
    }
  else
    {
      cmdlist = new;
    }
  return;
}

static void sh_socket_add2run (struct socket_cmd * in)
{
  struct socket_cmd  * new  = runlist;
  struct socket_cmd  * last = runlist;

  while (new)
    {
      /* Only skip identical commands. First 5 will
       * make all 'DELTA' identical.
       */
      if (0 == sl_strcmp(new->clt,  in->clt) &&
	  0 == sl_strncmp(new->cmd,  in->cmd, 5))
	{
	  sl_strlcpy (new->cmd,  in->cmd,  sizeof(new->cmd));
	  (void) sh_unix_time(0, new->cti, sizeof(new->cti));
	  return;
	}
      new = new->next;
    }

  new = SH_ALLOC(sizeof(struct socket_cmd));
  sl_strlcpy (new->cmd,  in->cmd,  sizeof(new->cmd));
  sl_strlcpy (new->clt,  in->clt,  sizeof(new->clt));
#ifdef SH_DEBUG_SOCKET
  fprintf(stderr, "add2run: time set for %s\n", new->clt);
#endif
  (void) sh_unix_time(0, new->cti, sizeof(new->cti));
  new->next  = NULL;

  if (last)
    {
      while (last->next) { last = last->next; }
      last->next = new;
    }
  else
    {
      runlist = new;
    }
  return;
}



static void sh_socket_rm2list (const char * client_name, int remove_all)
{
  struct socket_cmd * old = cmdlist;
  struct socket_cmd * new = cmdlist;
  
  while (new)
    {
      if (0 == sl_strcmp(new->clt, client_name))
	{
	  if ((new == cmdlist) && (new->next == NULL))
	    {
	      /* There is only one entry */
	      cmdlist = NULL;
	      SH_FREE(new);
	      return;
	    }
	  else if (new == cmdlist)
	    {
	      /* first entry: new = old = cmdlist */
	      cmdlist = new->next;
	      SH_FREE(new);
	      if (remove_all == S_FALSE)
		return;
	      old = cmdlist;
	      new = cmdlist;
	      continue;
	    }
	  else
	    {
	      old->next = new->next;
	      SH_FREE(new);
	      if (remove_all == S_FALSE)
		return;
	      new = old;
	    }
	}
      old = new;
      new = new->next;
    }
  return;
}

/* poll the socket to gather input
 */
int sh_socket_poll()
{
  struct socket_cmd   cmd;
  char   cancel_cmd[SH_MAXMSGLEN];
 
  /* struct pollfd sh_poll = { pf_unix_fd, POLLIN, 0 }; */

  if (pf_unix_fd  < 0)
    return 0;

  sl_strlcpy(cancel_cmd, _("CANCEL"), sizeof(cancel_cmd)); 

  while (sh_socket_read (&cmd) > 0)
    {
      if (0 == sl_strcmp(cmd.cmd, cancel_cmd))
	sh_socket_rm2list  (cmd.clt, S_TRUE);
      else
	sh_socket_add2list (&cmd);
    }
  return 0;
}

/* return the command associated with client_name
   and remove the corresponding entry
 */
char * sh_socket_check(const char * client_name)
{
  struct socket_cmd * new = cmdlist;
  static char         out[SH_MAXMSGLEN];

  while (new)
    {
      if (0 == sl_strcmp(new->clt, client_name))
	{
	  sl_strlcpy(out,  new->cmd,  sizeof(out));
	  sh_socket_add2run (new);
	  sh_socket_rm2list (client_name, S_FALSE);
	  return out;
	}
      new = new->next;
    }
  return NULL;
}
/* #if defined (SH_WITH_SERVER)
 */
#endif


#ifdef SH_CUTEST
#include "CuTest.h"

void Test_cmdlist (CuTest *tc) {

#if defined (SH_WITH_SERVER)
  struct socket_cmd cmd;
  char * p;

  sl_strlcpy(cmd.clt, "one", sizeof(cmd.clt));
  sl_strlcpy(cmd.cmd, "RELOAD", sizeof(cmd.cmd));

  sh_socket_add2list (&cmd);
  p = sh_socket_check("one");
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc, "RELOAD", p);

  p = sh_socket_check("one");
  CuAssertPtrEquals(tc, NULL, p);

  sh_socket_add2list (&cmd);
  sl_strlcpy(cmd.cmd, "STOP",   sizeof(cmd.cmd));
  sh_socket_add2list (&cmd);

  sl_strlcpy(cmd.clt, "two", sizeof(cmd.clt));
  sl_strlcpy(cmd.cmd, "STOP", sizeof(cmd.cmd));
  sh_socket_add2list (&cmd);
  sl_strlcpy(cmd.clt, "three", sizeof(cmd.clt));
  sl_strlcpy(cmd.cmd, "STOP", sizeof(cmd.cmd));
  sh_socket_add2list (&cmd);

  sl_strlcpy(cmd.clt, "one", sizeof(cmd.clt));
  sl_strlcpy(cmd.cmd, "DELTA",   sizeof(cmd.cmd));
  sh_socket_add2list (&cmd);

  p = sh_socket_check("one");
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc, "RELOAD", p);

  sl_strlcpy(cmd.clt, "two", sizeof(cmd.clt));
  sl_strlcpy(cmd.cmd, "RELOAD", sizeof(cmd.cmd));
  sh_socket_add2list (&cmd);
  sl_strlcpy(cmd.clt, "three", sizeof(cmd.clt));
  sl_strlcpy(cmd.cmd, "RELOAD", sizeof(cmd.cmd));
  sh_socket_add2list (&cmd);

  p = sh_socket_check("one");
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc, "STOP", p);
  p = sh_socket_check("one");
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc, "DELTA", p);
  p = sh_socket_check("one");
  CuAssertPtrEquals(tc, NULL, p);

  /* Test removal in correct order */
  sl_strlcpy(cmd.clt, "one", sizeof(cmd.clt));
  sl_strlcpy(cmd.cmd, "RELOAD", sizeof(cmd.cmd));
  sh_socket_add2list (&cmd);
  sl_strlcpy(cmd.cmd, "STOP",   sizeof(cmd.cmd));
  sh_socket_add2list (&cmd);
  sl_strlcpy(cmd.cmd, "DELTA",  sizeof(cmd.cmd));
  sh_socket_add2list (&cmd);
  sl_strlcpy(cmd.cmd, "FOOBAR", sizeof(cmd.cmd));
  sh_socket_add2list (&cmd);
  
  sh_socket_rm2list ("one", S_FALSE);

  p = sh_socket_check("one");
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc, "STOP", p);

  sh_socket_rm2list ("one", S_FALSE);
  
  p = sh_socket_check("one");
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc, "FOOBAR", p);

  p = sh_socket_check("one");
  CuAssertPtrEquals(tc, NULL, p);

  sl_strlcpy(cmd.clt, "one", sizeof(cmd.clt));
  sl_strlcpy(cmd.cmd, "RELOAD", sizeof(cmd.cmd));
  sh_socket_add2list (&cmd);
  sl_strlcpy(cmd.cmd, "STOP",   sizeof(cmd.cmd));
  sh_socket_add2list (&cmd);

  sl_strlcpy(cmd.clt, "two", sizeof(cmd.clt));
  sl_strlcpy(cmd.cmd, "RELOAD", sizeof(cmd.cmd));
  sh_socket_add2list (&cmd);
  sl_strlcpy(cmd.clt, "three", sizeof(cmd.clt));
  sl_strlcpy(cmd.cmd, "RELOAD", sizeof(cmd.cmd));
  sh_socket_add2list (&cmd);

  sl_strlcpy(cmd.clt, "one", sizeof(cmd.clt));
  sl_strlcpy(cmd.cmd, "DELTA",  sizeof(cmd.cmd));
  sh_socket_add2list (&cmd);
  sl_strlcpy(cmd.cmd, "FOOBAR", sizeof(cmd.cmd));
  sh_socket_add2list (&cmd);

  sh_socket_rm2list ("one", S_TRUE);
  p = sh_socket_check("one");
  CuAssertPtrEquals(tc, NULL, p);

  p = sh_socket_check("two");
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc, "STOP", p);
  p = sh_socket_check("two");
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc, "RELOAD", p);
  p = sh_socket_check("two");
  CuAssertPtrEquals(tc, NULL, p);

  p = sh_socket_check("three");
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc, "STOP", p);
  p = sh_socket_check("three");
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc, "RELOAD", p);
  p = sh_socket_check("three");
  CuAssertPtrEquals(tc, NULL, p);

  p = sh_socket_check("four");
  CuAssertPtrEquals(tc, NULL, p);
#else
  (void) tc;
#endif
}

#endif  /* #ifdef SH_CUTEST */



