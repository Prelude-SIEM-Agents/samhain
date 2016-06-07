/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999, 2000 Rainer Wichmann                                */
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

/* Must be early on FreeBSD
 */
#include <sys/types.h>
#include <sys/socket.h> 
#include <netdb.h>
#include <netinet/in.h>

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

#include <unistd.h>
#include <fcntl.h>

#ifdef SH_WITH_SERVER

#include "samhain.h"
#include "sh_tools.h"
#include "sh_utils.h"
#include "sh_ipvx.h"

#undef  FIL__
#define FIL__  _("sh_xfer_syslog.c")

#ifdef INET_SYSLOG

extern void sh_xfer_printerr(char * str, int errnum, unsigned int port, int line);
extern int sh_xfer_syslog_sock[SH_SOCKMAX];
extern int sh_xfer_syslog_sock_n;
extern int SH_MINSOCK;

/* Unlike Linux / FreeBSD, most systems don't define the stuff below
 * in syslog.h
 */

#ifndef LOG_FAC
#define LOG_FAC(p)      (((p) & LOG_FACMASK) >> 3)
#endif

#ifndef LOG_PRI
#define LOG_PRI(p)      ((p) & LOG_PRIMASK)
#endif

typedef struct sh_code {
        char    *c_name;
        int     c_val;
} SH_CODE;

SH_CODE sh_facilitynames[] =
{
#ifdef LOG_AUTH
  { N_("auth"), LOG_AUTH },
#endif
#ifdef LOG_AUTHPRIV 
  { N_("authpriv"), LOG_AUTHPRIV },
#endif
#ifdef LOG_CRON
  { N_("cron"), LOG_CRON },
#endif
#ifdef LOG_DAEMON
  { N_("daemon"), LOG_DAEMON },
#endif
#ifdef LOG_FTP
  { N_("ftp"), LOG_FTP },
#endif
#ifdef LOG_KERN
  { N_("kern"), LOG_KERN },
#endif
#ifdef LOG_LPR
  { N_("lpr"), LOG_LPR },
#endif
#ifdef LOG_MAIL
  { N_("mail"), LOG_MAIL },
#endif
#ifdef INTERNAL_MARK
  { N_("mark"), INTERNAL_MARK },          /* INTERNAL */
#endif
#ifdef LOG_NEWS
  { N_("news"), LOG_NEWS },
#endif
#ifdef LOG_AUTH
  { N_("security"), LOG_AUTH },           /* DEPRECATED */
#endif
#ifdef LOG_SYSLOG
  { N_("syslog"), LOG_SYSLOG },
#endif
#ifdef LOG_USER
  { N_("user"), LOG_USER },
#endif
#ifdef LOG_UUCP
  { N_("uucp"), LOG_UUCP },
#endif
#ifdef LOG_LOCAL0
  { N_("local0"), LOG_LOCAL0 },
#endif
#ifdef LOG_LOCAL1
  { N_("local1"), LOG_LOCAL1 },
#endif
#ifdef LOG_LOCAL2 
  { N_("local2"), LOG_LOCAL2 },
#endif
#ifdef LOG_LOCAL3
  { N_("local3"), LOG_LOCAL3 },
#endif
#ifdef LOG_LOCAL4
  { N_("local4"), LOG_LOCAL4 },
#endif
#ifdef LOG_LOCAL5
  { N_("local5"), LOG_LOCAL5 },
#endif
#ifdef LOG_LOCAL6
  { N_("local6"), LOG_LOCAL6 },
#endif
#ifdef LOG_LOCAL7
  { N_("local7"), LOG_LOCAL7 },
#endif
  { NULL, -1 }
};
 

SH_CODE sh_prioritynames[] =
{  
#ifdef LOG_ALERT
  { N_("alert"), LOG_ALERT },
#endif
#ifdef LOG_CRIT
  { N_("crit"), LOG_CRIT },
#endif
#ifdef LOG_DEBUG
  { N_("debug"), LOG_DEBUG },
#endif
#ifdef LOG_EMERG
  { N_("emerg"), LOG_EMERG },
#endif
#ifdef LOG_ERR
  { N_("err"), LOG_ERR },
#endif
#ifdef LOG_ERR
  { N_("error"), LOG_ERR },               /* DEPRECATED */
#endif
#ifdef LOG_INFO
  { N_("info"), LOG_INFO },
#endif
#ifdef INTERNAL_NOPRI
  { N_("none"), INTERNAL_NOPRI },         /* INTERNAL */
#endif
#ifdef LOG_NOTICE
  { N_("notice"), LOG_NOTICE },
#endif
#ifdef LOG_EMERG
  { N_("panic"), LOG_EMERG },             /* DEPRECATED */
#endif
#ifdef LOG_WARNING
  { N_("warn"), LOG_WARNING },            /* DEPRECATED */
#endif
#ifdef LOG_WARNING
  { N_("warning"), LOG_WARNING },
#endif
  { NULL, -1 }
};

static int enable_syslog_socket = S_FALSE;

int sh_xfer_recv_syslog_socket (int fd)
{
  static time_t      return_next = 0;
  int                priority = 0;
  int                fac, pri;
  int                i;
  char             * cfac = NULL;
  char             * cpri = NULL;
  int                res;
  char             * tmp;
  char             * bptr;
  char             * ptr = NULL;
  char               buf[1048];
  struct sockaddr_in from;
  char errbuf[SH_ERRBUF_SIZE];

  struct sh_sockaddr ss;
  struct sockaddr * sa = (struct sockaddr *) &from;
  char   namebuf[SH_BUFSIZE];

  /* The 6th argument in recvfrom is *socklen_t in Linux and *BSD, 
   * but *int everywhere else. Because socklen_t is unsigned int, there
   * should be no problem as long as  sizeof(struct sockaddr_in) < INT_MAX ...
   */
  unsigned int fromlen = sizeof(from);

  if (enable_syslog_socket == S_FALSE)
    return 0;

  SL_ENTER(_("sh_xfer_recv_syslog_socket"));

  if (return_next > 0)
    {
      if ( (time(NULL) - return_next) < 2)
	SL_RETURN( 0, _("sh_xfer_recv_syslog_socket"));
      else
	return_next = 0;
    }

  res = recvfrom(fd,  buf,  1047, 0, (struct sockaddr *) &from, &fromlen);

  sh_ipvx_save(&ss, sa->sa_family, (struct sockaddr *) &from);
  sh_ipvx_ntoa(namebuf, sizeof(namebuf), &ss);

  if (res > 0)
    {
      res = (res < 1047) ? res : 1047; 
      buf[res] = '\0';
      if (res > 1 && buf[res-1] == '\n')
	buf[res-1] = '\0';

      /* here we expect an xml formatted message, thus we don't
	 escape xml special chars (flag == 0) */
      /* commented out to not escape twice    */
      /* bptr = sh_tools_safe_name(buf, 0);   */
      bptr = buf;

      if (!bptr || !(*bptr))
	{
	  res = errno;
	  TPT(( 0, FIL__, __LINE__, _("msg=<UDP error: %d>\n"), res));
	  sh_error_handle((-1), FIL__, __LINE__, res, MSG_ERR_SYSLOG,
			  sh_error_message(res, errbuf, sizeof(errbuf)), 
			  namebuf);
	  SL_RETURN( (-1), _("sh_xfer_recv_syslog_socket"));
	}      

      TPT(( 0, FIL__, __LINE__, _("msg=<UDP message from %s>\n"), namebuf ));

      ptr = bptr;
      i = 0;
      if (*ptr == '<') 
	{
	  ++ptr; ++i;
	  while (i < res &&
		 (unsigned char) *ptr > 47 && (unsigned char) *ptr < 58)
	    {
	      priority = 10 * priority + (*ptr - '0');
	      ++ptr;
	      ++i;
	    }
	  if (*ptr == '>')
	    ++ptr;
	}
      fac = LOG_FAC(priority);
      i = 0; 
      while (sh_facilitynames[i].c_name != NULL)
	{
	  if (sh_facilitynames[i].c_val == (fac<<3))
	    { cfac = sh_util_strdup(_(sh_facilitynames[i].c_name)); break; }
	  ++i;
	}
      pri = LOG_PRI(priority);
      i = 0; 
      while (sh_prioritynames[i].c_name != NULL)
	{
	  if (sh_prioritynames[i].c_val == pri)
	    { cpri = sh_util_strdup(_(sh_prioritynames[i].c_name)); break; }
	  ++i;
	}

      /* here we do not expect an xml formatted message, thus we escape
	 xml special chars (flag == 1) */
      tmp = sh_tools_safe_name (ptr, 1);
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_INET_SYSLOG,
		      namebuf, 
		      (cfac == NULL) ? _("none") : cfac, 
		      (cpri == NULL) ? _("none") : cpri, 
		      (tmp  == NULL) ? _("none") : tmp);
      if (cfac != NULL)
	SH_FREE(cfac);
      if (cpri != NULL)
	SH_FREE(cpri);
      SH_FREE(tmp);
      /* SH_FREE(bptr); */
    }

  else if (res < 0 && errno != EINTR)
    {
      res = errno;
      TPT(( 0, FIL__, __LINE__, _("msg=<UDP error: %d>\n"), res));
      sh_error_handle((-1), FIL__, __LINE__, res, MSG_ERR_SYSLOG,
		      sh_error_message(res, errbuf, sizeof(errbuf)), 
		      namebuf);

      /* don't accept anything the next 2 seconds
       */
      return_next = time(NULL);
      SL_RETURN( (-1), _("sh_xfer_recv_syslog_socket"));
    }      
  SL_RETURN( (0), _("sh_xfer_recv_syslog_socket"));
}

int set_syslog_active(const char * c)
{
  return sh_util_flagval(c, &enable_syslog_socket);
}

static int do_syslog_socket(int domain, int type, int protocol,
			    struct sockaddr * sa, int salen)
{
  int                flag = 1;  /* non-zero to enable an option */
  int sock;
  int errnum;
  int res;

  /* create the socket, bind() it and listen()
   */
  sock = socket(domain, type, protocol);

  if (sock < 0)
    {
      errnum = errno; 
      sh_xfer_printerr (_("syslog socket"), errnum, 514, __LINE__);
      return -1;
    }
  (void) retry_fcntl( FIL__, __LINE__, sock, F_SETFD, 1 );
  
  if ( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		  (void *) &flag, sizeof(flag)) < 0 )
    {
      errnum = errno;
      sh_xfer_printerr (_("syslog setsockopt SO_REUSEADDR"), 
			   errnum, 514, __LINE__);
      return -1;
    }

#if defined(SO_BSDCOMPAT)
  if ( setsockopt(sock, SOL_SOCKET, SO_BSDCOMPAT,
		  (void *) &flag, sizeof(flag)) < 0 )
    {
      errnum = errno;
      sh_xfer_printerr (_("syslog setsockopt SO_BSDCOMPAT"), 
			   errnum, 514, __LINE__);
      return -1;
    }
#endif
  
  res = bind(sock, sa, salen);

  if ( res < 0) 
    {
      errnum = errno;
      sh_xfer_printerr (_("syslog bind"), errnum, 514, __LINE__);
      sl_close_fd(FIL__, __LINE__, sock);
      return -1;
    }
  return sock;
}

/* callerFlag == S_TRUE means override the enable_syslog_socket flag
 */
int sh_xfer_create_syslog_socket (int callerFlag)
{
  int sock;

#if defined(USE_IPVX)
  struct addrinfo *ai;
  struct addrinfo *p;
  struct addrinfo hints;
#else
  struct sockaddr_in addr;
  int addrlen      = sizeof(addr);
#endif

  SL_ENTER(_("sh_xfer_create_syslog_socket"));

  if (callerFlag == S_FALSE)
    {
      if (enable_syslog_socket == S_FALSE && sh_xfer_syslog_sock_n > 0)
	{
	  /* user does not wish to use this facility
	   */
	  TPT(( 0, FIL__, __LINE__, _("msg=<close syslog socket>\n")));
	  for (sock = 0; sock < sh_xfer_syslog_sock_n; ++sock)
	    {
	      sl_close_fd(FIL__, __LINE__, sh_xfer_syslog_sock[sock]);
	      sh_xfer_syslog_sock[0] = -1;
	    }
	}
      SL_RETURN((-1), _("sh_xfer_create_syslog_socket"));
    }

  sh_xfer_printerr (NULL, 0, 514, __LINE__);

#if !defined(USE_IPVX)

  memset(&addr, 0, sizeof(addr));
  addr.sin_family      = AF_INET;
  addr.sin_port        = htons(514);
  
  sock = do_syslog_socket(AF_INET, SOCK_DGRAM, 0, 
			  (struct sockaddr *) &addr, addrlen);

  if (sock >= 0) {
    sh_xfer_syslog_sock[0] = sock;
    sh_xfer_syslog_sock_n  = 1;
  }

#else
  memset (&hints, '\0', sizeof (hints));
  hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
  hints.ai_socktype = SOCK_DGRAM;
  if (getaddrinfo (NULL, "syslog", &hints, &ai) != 0)
    {
      int errnum = errno;
      sh_xfer_printerr (_("getaddrinfo"), errnum, 514, __LINE__);
      SL_RETURN((-1), _("sh_xfer_create_syslog_socket"));
    }
  
  p = ai;

  while (p != NULL && sh_xfer_syslog_sock_n < SH_SOCKMAX)
    {
      sock = do_syslog_socket(p->ai_family, p->ai_socktype, p->ai_protocol,
			      p->ai_addr, p->ai_addrlen);
      
      if (sock >= 0) {
	if (sh_xfer_syslog_sock_n < SH_SOCKMAX) {
	  sh_xfer_syslog_sock[sh_xfer_syslog_sock_n] = sock;
	  ++sh_xfer_syslog_sock_n;
	}
	else {
	  sl_close_fd (FIL__, __LINE__, sock);
	}    
      } else if (sock == -1) {
	freeaddrinfo (ai);
	goto end;
      }
      p = p->ai_next;
    }
  freeaddrinfo (ai);

 end:
#endif
  if (sh_xfer_syslog_sock_n > 1)
    SH_MINSOCK += (sh_xfer_syslog_sock_n - 1);

  SL_RETURN((sh_xfer_syslog_sock_n), _("sh_xfer_create_syslog_socket"));
}
/* #ifdef INET_SYSLOG */
#endif

/* #ifdef SH_WITH_SERVER */
#endif
