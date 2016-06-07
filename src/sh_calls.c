/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999 Rainer Wichmann                                      */
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

#ifdef HOST_IS_HPUX          
#define _XOPEN_SOURCE_EXTENDED
#endif                       

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#ifndef S_SPLINT_S
#include <arpa/inet.h>
#else
#define AF_INET 2
#endif

#include <time.h>

#ifndef HAVE_LSTAT
#define lstat stat
#endif

#include "samhain.h"
#include "sh_error.h"
#include "sh_calls.h"
#include "sh_ipvx.h"
#include "sh_sub.h"
#include "sh_utils.h"

#undef  FIL__
#define FIL__  _("sh_calls.c")

extern int flag_err_debug;

char aud_err_message[64];

typedef struct cht_struct 
{
  const char           * str;
  unsigned long    val;
} cht_type;

static cht_type aud_tab[] =
{
  { N_("execve"),    AUD_EXEC   },
  { N_("utime"),     AUD_UTIME  },
  { N_("unlink"),    AUD_UNLINK },
  { N_("dup"),       AUD_DUP    },
  { N_("chdir"),     AUD_CHDIR  },
  { N_("open"),      AUD_OPEN   },
  { N_("kill"),      AUD_KILL   },
  { N_("exit"),      AUD_EXIT   },
  { N_("fork"),      AUD_FORK   },
  { N_("setuid"),    AUD_SETUID },
  { N_("setgid"),    AUD_SETGID },
  { N_("pipe"),      AUD_PIPE   },
  { NULL,            0 }
};

/* Set aud functions
 */
int sh_aud_set_functions(const char * str_s)
{
  int i = 0;

  SL_ENTER(_("sh_aud_set_functions"));
  
  if (str_s == NULL)
    return -1;

  while (aud_tab[i].str != NULL)
    {
      if (NULL != sl_strstr (str_s, _(aud_tab[i].str)))
	{
	  sh.flag.audit     = 1;
	  sh.flag.aud_mask |= aud_tab[i].val;
	}
      ++i;
    }

  SL_RETURN(0,_("sh_aud_set_functions"));
}

  


/* Need to catch EINTR for these functions.
 */
long int retry_sigaction(const char * file, int line,
			 int signum,  const  struct  sigaction  *act,
			 struct sigaction *oldact)
{
  int error;
  long int val_retry = -1;
  char errbuf[SH_ERRBUF_SIZE];
  errno              = 0;

  SL_ENTER(_("retry_sigaction"));

  do {
    val_retry = sigaction(signum, act, oldact);
  } while (val_retry < 0 && errno == EINTR);

  error = errno;
  if (val_retry < 0) {
      sh_error_handle ((-1), file, line, error, MSG_ERR_SIGACT, 
		       sh_error_message(error, errbuf, sizeof(errbuf)),
		       (long) signum );
  }
  errno = error;    
  SL_RETURN(val_retry, _("retry_sigaction"));
}

static struct sh_sockaddr bind_addr;
static int        use_bind_addr = 0;

int sh_calls_set_bind_addr (const char * str)
{
  static int reject = 0;

  if (reject == 1)
    return (0);

  if (sh.flag.opts == S_TRUE)  
    reject = 1;

  if (0 == sh_ipvx_aton(str, &bind_addr)) 
    return -1;

  use_bind_addr = 1;
  return 0;
}


long int retry_connect(const char * file, int line, int sockfd, 
		       struct sockaddr *serv_addr, int addrlen)
{
  int error;
  int err_bind = 0;
  long int val_retry = 0;
  char errbuf[SH_ERRBUF_SIZE];

  SL_ENTER(_("retry_connect"));

  errno = 0;

  if (use_bind_addr) 
    {
      int slen = SH_SS_LEN(bind_addr);
      struct sockaddr *b_addr = sh_ipvx_sockaddr_cast(&bind_addr);

      if (bind_addr.ss_family == AF_INET)
	b_addr->sa_family = AF_INET;
#if defined(USE_IPVX)
      else
	b_addr->sa_family = AF_INET6;
#endif
      val_retry = bind(sockfd, b_addr, slen);
    }

  if (val_retry == 0)
    {
      do {
	val_retry = connect(sockfd, serv_addr, addrlen);
      } while (val_retry < 0 && (errno == EINTR || errno == EINPROGRESS));
    }
  else
    {
      err_bind = 1;
    }

  error = errno;
  if (val_retry != 0) {
    long eport = 0;
    char eaddr[SH_IP_BUF];
    char emesg[SH_BUFSIZE];
    struct sockaddr *err_addr = serv_addr;
    struct sh_sockaddr ss;

    if (err_bind)
      err_addr = sh_ipvx_sockaddr_cast(&bind_addr);

    sh_ipvx_save(&ss, err_addr->sa_family, err_addr);
    sh_ipvx_ntoa(eaddr, sizeof(eaddr), &ss);
    
    if (err_addr->sa_family == AF_INET)
      eport = (long) ntohs(((struct sockaddr_in *)serv_addr)->sin_port);
#if defined(USE_IPVX)
    else
      eport = (long) ntohs(((struct sockaddr_in6 *)serv_addr)->sin6_port);
#endif

    sl_strlcpy(emesg, sh_error_message(error, errbuf, sizeof(errbuf)), sizeof(emesg));
    sl_strlcat(emesg, 
	       (err_addr->sa_family == AF_INET) ? _(", AF_INET") : _(", AF_INET6"),
	       sizeof(emesg));

    sl_strlcat(emesg, 
	       (err_bind) ? _(", bind") : _(", connect"),
	       sizeof(emesg));
    
    sh_error_handle ((-1), file, line, error, MSG_ERR_CONNECT,
		     emesg,
		     (long) sockfd, eport, eaddr);
  }
  errno = error;    
  SL_RETURN(val_retry, _("retry_connect"));
}

long int retry_accept(const char * file, int line, int fd, 
		      struct sh_sockaddr *serv_addr, int * addrlen)
{
  int  error;
  long int val_retry = -1;
  char errbuf[SH_ERRBUF_SIZE];
  struct sockaddr_storage ss;

  ACCEPT_TYPE_ARG3 my_addrlen = sizeof(ss);

  errno              = 0;

  SL_ENTER(_("retry_accept"));

  do {
    val_retry = accept(fd, (struct sockaddr *)&ss, &my_addrlen);
  } while (val_retry < 0 && errno == EINTR);

  error = errno;
  if (val_retry < 0) {
      sh_error_handle ((-1), file, line, error, MSG_ERR_ACCEPT, 
		       sh_error_message(error, errbuf, sizeof(errbuf)),
		       (long) fd );
  }
  errno = error;

  if (flag_err_debug == S_TRUE)
    {
      char ipbuf[SH_IP_BUF];
      char buf[SH_BUFSIZE];
#if defined(USE_IPVX)
      sl_strlcpy(errbuf, _("Address family: "), sizeof(errbuf));
      sl_strlcat(errbuf, 
		 (ss.ss_family == AF_INET6) ? _("AF_INET6") : _("AF_INET"),
		 sizeof(errbuf));
      getnameinfo((struct sockaddr *)&ss, my_addrlen,
		  ipbuf, sizeof(ipbuf), NULL, 0, NI_NUMERICHOST);
#else
      struct sockaddr_in sa;
      char * p;
      memcpy(&(sa), (struct sockaddr_in*)&ss, sizeof(struct sockaddr_in));
      p = inet_ntoa(sa.sin_addr);
      sl_strlcpy(ipbuf, p, sizeof(ipbuf));
      sl_strlcpy(errbuf, _("Address family: AF_INET"), sizeof(errbuf));
#endif
      sl_strlcpy(buf, _("Address: "), sizeof(buf));
      sl_strlcat(buf, ipbuf, sizeof(buf));
      sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		       errbuf, _("retry_accept"));
      sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		       buf, _("retry_accept"));
    }

  sh_ipvx_save(serv_addr, ss.ss_family, (struct sockaddr *) &ss);

  if (flag_err_debug == S_TRUE)
    {
      char ipbuf[SH_IP_BUF];
      char ipbuf2[SH_IP_BUF];
      char buf[SH_BUFSIZE];
#if defined(USE_IPVX)
      int len = (serv_addr->ss_family == AF_INET) ? 
	sizeof(struct sockaddr_in) :
	sizeof(struct sockaddr_in6);
      getnameinfo(sh_ipvx_sockaddr_cast(serv_addr), len,
		  ipbuf2, sizeof(ipbuf2), NULL, 0, NI_NUMERICHOST);
#else
      char * p = inet_ntoa((serv_addr->sin).sin_addr);
      sl_strlcpy(ipbuf2, p, sizeof(ipbuf2));
#endif
      sh_ipvx_ntoa (ipbuf, sizeof(ipbuf), serv_addr);
      sl_snprintf(buf, sizeof(buf), _("Address: %s / %s"),
		  ipbuf, ipbuf2);
      sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		       buf, _("retry_accept"));
    }

  *addrlen = (int) my_addrlen;
  SL_RETURN(val_retry, _("retry_accept"));
}

static int sh_enable_use_sub = 0;

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)
#if defined(HOST_IS_CYGWIN) || defined(__cygwin__) || defined(__CYGWIN32__) || defined(__CYGWIN__)
static int sh_use_sub = 0;
#else
static int sh_use_sub = 1;
#endif
#else
static int sh_use_sub = 0;
#endif

void sh_calls_enable_sub()
{
  sh_enable_use_sub = 1;
  return;
}

int sh_calls_set_sub (const char * str)
{
  int ret = sh_util_flagval(str, &sh_use_sub);

  if ((ret == 0) && (!sh_use_sub))
    {
      sh_kill_sub();
    }
  return ret;
}

long int retry_lstat_ns(const char * file, int line, 
			const char *file_name, struct stat *buf)
{
  int error;
  long int val_retry = -1;
  char errbuf[SH_ERRBUF_SIZE];
 
  SL_ENTER(_("retry_lstat_ns"));

  do {
    val_retry = /*@-unrecog@*/lstat (file_name, buf)/*@+unrecog@*/;
  } while (val_retry < 0 && errno == EINTR);

  error = errno;
  if (val_retry < 0) {
      (void) sh_error_message(error, aud_err_message, 64);
      sh_error_handle ((-1), file, line, error, MSG_ERR_LSTAT, 
		       sh_error_message(error, errbuf, sizeof(errbuf)),
		       file_name );
  }
  errno = error;    

  SL_RETURN(val_retry, _("retry_lstat_ns"));
}

long int retry_lstat(const char * file, int line, 
		     const char *file_name, struct stat *buf)
{
  int error;
  long int val_retry = -1;
  char errbuf[SH_ERRBUF_SIZE];
 
  SL_ENTER(_("retry_lstat"));

  if (sh_use_sub && sh_enable_use_sub)
    {
      val_retry = sh_sub_lstat (file_name, buf);
    }
  else
    {
      do {
	val_retry = /*@-unrecog@*/lstat (file_name, buf)/*@+unrecog@*/;
      } while (val_retry < 0 && errno == EINTR);
    }

  error = errno;
  if (val_retry < 0) {
      (void) sh_error_message(error, aud_err_message, 64);
      sh_error_handle ((-1), file, line, error, MSG_ERR_LSTAT, 
		       sh_error_message(error, errbuf, sizeof(errbuf)),
		       file_name );
  }
  errno = error;    

  SL_RETURN(val_retry, _("retry_lstat"));
}

long int retry_stat(const char * file, int line, 
		    const char *file_name, struct stat *buf)
{
  int error;
  long int val_retry = -1;
  char errbuf[SH_ERRBUF_SIZE];
 
  SL_ENTER(_("retry_stat"));

  if (sh_use_sub && sh_enable_use_sub)
    {
      val_retry = sh_sub_stat (file_name, buf);
    }
  else
    {
      do {
	val_retry = stat (file_name, buf);
      } while (val_retry < 0 && errno == EINTR);
    }

  error = errno;
  if (val_retry < 0) {
      (void) sh_error_message(error, aud_err_message, 64);
      sh_error_handle ((-1), file, line, error, MSG_ERR_STAT, 
		       sh_error_message(error, errbuf, sizeof(errbuf)),
		       file_name );
  }
  errno = error;    

  SL_RETURN(val_retry, _("retry_stat"));
}

long int retry_fstat(const char * file, int line, int filed, struct stat *buf)
{
  int error;
  long int val_retry = -1;
  char errbuf[SH_ERRBUF_SIZE];
 
  SL_ENTER(_("retry_fstat"));

  do {
    val_retry = fstat (filed, buf);
  } while (val_retry < 0 && errno == EINTR);
  error = errno;
  if (val_retry < 0) {
      sh_error_handle ((-1), file, line, error, MSG_ERR_FSTAT, 
		       sh_error_message(error, errbuf, sizeof(errbuf)),
		       (long) filed );
  }
  errno = error;    
  SL_RETURN(val_retry, _("retry_fstat"));
}

long int retry_fcntl(const char * file, int line, int fd, int cmd, long arg)
{
  int error;
  long int val_retry = -1;
  char errbuf[SH_ERRBUF_SIZE];
  errno              = 0;

  SL_ENTER(_("retry_fcntl"));

  if (cmd == F_GETFD || cmd == F_GETFL)
    {
      do {
	val_retry = fcntl(fd, cmd);
      } while (val_retry < 0 && errno == EINTR);
    }
  else
    {
      do {
	val_retry = fcntl(fd, cmd, arg);
      } while (val_retry < 0 && errno == EINTR);
    }
  error = errno;
  if (val_retry < 0) {
      sh_error_handle ((-1), file, line, error, MSG_ERR_FCNTL, 
		       sh_error_message(error, errbuf, sizeof(errbuf)),
		       (long) fd, (long) cmd, arg );
  }
  errno = error;    
  SL_RETURN(val_retry, _("retry_fcntl"));
}

long int retry_msleep (int sec, int millisec)
{
  int result = 0;
#if defined(HAVE_NANOSLEEP)
  struct timespec req, rem;
#endif

  errno  = 0;
  if (millisec > 999) millisec = 999;
  if (millisec < 0)   millisec = 0;
  if (sec < 0)         sec = 0;

#if defined(HAVE_NANOSLEEP)
  /*@-usedef@*/
  req.tv_sec  = sec;                   rem.tv_sec  = 0;
  req.tv_nsec = millisec * 1000000;    rem.tv_nsec = 0;
  /*@+usedef@*/
  do {
    result = /*@-unrecog@*/nanosleep(&req, &rem)/*@+unrecog@*/;

    req.tv_sec = rem.tv_sec;   rem.tv_sec  = 0;
    req.tv_nsec = rem.tv_nsec; rem.tv_nsec = 0;
    
  } while ((result == -1) && (errno == EINTR));
#else
  if (sec > 0)
    sleep (sec); /* nanosleep not available */
  else {
#ifdef HAVE_USLEEP
    if (millisec > 0)
      usleep(1000 * millisec);
#else
    if (millisec > 0)
      sleep (1);
#endif
  }
#endif
  return result;
}

/***************************************************
 *
 *   Audit these functions.
 *
 ***************************************************/

long int retry_aud_execve  (const char * file, int line, 
			    const  char *dateiname, char * argv[],
			    char * envp[])
{
  uid_t a = geteuid();
  gid_t b = getegid();
  int   i;
  int   error;
  char errbuf[SH_ERRBUF_SIZE];

  SL_ENTER(_("retry_aud_execve"));

  if (sh.flag.audit != 0 && (sh.flag.aud_mask & AUD_EXEC) != 0)
    sh_error_handle ((-1), file, line, 0, MSG_AUD_EXEC,
		     dateiname, (long) a, (long) b );
  do {
    i = execve(dateiname, argv, envp);
  } while (i < 0 && errno == EINTR);

  error = errno;
  if (i < 0) {
      sh_error_handle ((-1), file, line, error, MSG_ERR_EXEC, 
		       sh_error_message(error, errbuf, sizeof(errbuf)),
		       dateiname, (long) a, (long) b );
  }
  errno = error;    
  SL_RETURN(i, _("retry_aud_execve"));
}


long int retry_aud_utime (const char * file, int line, 
			  char * path, struct utimbuf *buf)
{
  long int val_return;
  int  error;
  char errbuf[SH_ERRBUF_SIZE];
  errno      = 0;

  SL_ENTER(_("retry_aud_utime"));

  do {
    val_return = utime (path, buf);
  } while (val_return < 0 && errno == EINTR);

  error = errno;
  if (sh.flag.audit != 0 && (sh.flag.aud_mask & AUD_UTIME) != 0)
    sh_error_handle ((-1), file, line, 0, MSG_AUD_UTIME,
		     path, 
		     (unsigned long) buf->actime, 
		     (unsigned long) buf->modtime);
  if (val_return < 0) {
      sh_error_handle ((-1), file, line, error, MSG_ERR_UTIME, 
		       sh_error_message(error, errbuf, sizeof(errbuf)),
		       path, 
		       (unsigned long) buf->actime, 
		       (unsigned long) buf->modtime);
  }
  errno = error;
  SL_RETURN(val_return, _("retry_aud_utime"));
}

long int retry_aud_unlink (const char * file, int line, 
			   char * path)
{
  long int val_return;
  int error;
  char errbuf[SH_ERRBUF_SIZE];
  errno      = 0;

  SL_ENTER(_("retry_aud_unlink"));

  do {
    val_return = unlink (path);
  } while (val_return < 0 && errno == EINTR);

  error = errno;
  if (sh.flag.audit != 0 && (sh.flag.aud_mask & AUD_UNLINK) != 0)
    sh_error_handle ((-1), file, line, 0, MSG_AUD_UNLINK,
		     path);
  if (val_return < 0) {
      sh_error_handle ((-1), file, line, error, MSG_ERR_UNLINK, 
		       sh_error_message(error, errbuf, sizeof(errbuf)),
		       path);
  }
  errno = error;
  SL_RETURN(val_return, _("retry_aud_unlink"));
}

long int retry_aud_dup2 (const char * file, int line, 
			 int fd, int fd2)
{
  long int val_return;
  int error;
  char errbuf[SH_ERRBUF_SIZE];
  errno      = 0;

  SL_ENTER(_("retry_aud_dup2"));

  do {
    val_return = dup2 (fd, fd2);
  } while (val_return < 0 && errno == EINTR);

  error = errno;
  if (sh.flag.audit != 0 && (sh.flag.aud_mask & AUD_DUP) != 0)
    sh_error_handle ((-1), file, line, 0, MSG_AUD_DUP,
		      (long) fd, val_return);
  if (val_return < 0) {
      sh_error_handle ((-1), file, line, error, MSG_ERR_DUP, 
		       sh_error_message(error, errbuf, sizeof(errbuf)),
		       (long) fd, val_return);
  }
  errno = error;
  SL_RETURN(val_return, _("retry_aud_dup2"));
}

long int retry_aud_dup (const char * file, int line, 
			int fd)
{
  long int val_return;
  int error;
  char errbuf[SH_ERRBUF_SIZE];
  errno      = 0;

  SL_ENTER(_("retry_aud_dup"));

  do {
    val_return = dup (fd);
  } while (val_return < 0 && errno == EINTR);
  error = errno;
  if (sh.flag.audit != 0 && (sh.flag.aud_mask & AUD_DUP) != 0)
    sh_error_handle ((-1), file, line, 0, MSG_AUD_DUP,
		     (long) fd, val_return);
  if (val_return < 0) {
      sh_error_handle ((-1), file, line, error, MSG_ERR_DUP, 
		       sh_error_message(error, errbuf, sizeof(errbuf)),
		       (long) fd, val_return);
  }
  errno = error;
  SL_RETURN(val_return, _("retry_aud_dup"));
}


  
long int retry_aud_chdir (const char * file, int line, 
			  const char *path)
{
  long int val_return;
  int      error      = 0;
  char errbuf[SH_ERRBUF_SIZE];
  errno      = 0;

  SL_ENTER(_("retry_aud_chdir"));

  do {
    val_return = chdir (path);
  } while (val_return < 0 && errno == EINTR);

  error = errno;
  if (sh.flag.audit != 0 && (sh.flag.aud_mask & AUD_CHDIR) != 0)
    sh_error_handle ((-1), file, line, 0, MSG_AUD_CHDIR,
		     path);
  if (val_return < 0) {
      sh_error_handle ((-1), file, line, error, MSG_ERR_CHDIR, 
		       sh_error_message(error, errbuf, sizeof(errbuf)),
		       path);
  }
  errno = error;
  SL_RETURN(val_return, _("retry_aud_chdir"));
}


long int aud_open_noatime (const char * file, int line, int privs,
			   const char *pathname, int flags, mode_t mode,
			   int * o_noatime)
{
  long int val_return;
  int error;
  char errbuf[SH_ERRBUF_SIZE];

  SL_ENTER(_("aud_open"));

#ifdef USE_SUID
  if (0 == strcmp(pathname, "/usr/bin/sudo"))
    {
      uid_t ruid; uid_t euid; uid_t suid;
      getresuid(&ruid, &euid, &suid);
    }
  if (privs == SL_YESPRIV)
    sl_set_suid();
#else
  /*@-noeffect@*/
  (void) privs; /* fix compiler warning */
  /*@+noeffect@*/
#endif

  val_return = open (pathname, *o_noatime|flags, mode);

#ifdef USE_SUID
  if (privs == SL_YESPRIV)
    sl_unset_suid();
#endif

  if ((val_return < 0) && (*o_noatime != 0))
    {
      val_return = open (pathname, flags, mode);
      if (val_return >= 0)
	*o_noatime = 0;
    }
  error = errno;

  if (val_return < 0)
    {
      (void) sh_error_message(error, aud_err_message, 64);
    }

  if (sh.flag.audit != 0 && (sh.flag.aud_mask & AUD_OPEN) != 0)
    {
      sh_error_handle ((-1), file, line, 0, MSG_AUD_OPEN,
		       pathname, (long) flags, (long) mode, val_return);
    }
  if (val_return < 0) {
    sh_error_handle ((-1), file, line, error, MSG_ERR_OPEN, 
		     sh_error_message(error, errbuf, sizeof(errbuf)),
		     pathname, (long) flags, (long) mode, val_return);
  }
  errno = error;
  SL_RETURN(val_return, _("aud_open"));
}

long int aud_open (const char * file, int line, int privs,
		   const char *pathname, int flags, mode_t mode)
{
  long int val_return;
  int error;
  char errbuf[SH_ERRBUF_SIZE];

  SL_ENTER(_("aud_open"));

#ifdef USE_SUID
  if (privs == SL_YESPRIV)
    sl_set_suid();
#else
  /*@-noeffect@*/
  (void) privs; /* fix compiler warning */
  /*@+noeffect@*/
#endif

  val_return = open (pathname, flags, mode);

#ifdef USE_SUID
  if (privs == SL_YESPRIV)
    sl_unset_suid();
#endif

  error = errno;

  if (val_return < 0)
    {
      (void) sh_error_message(error, aud_err_message, 64);
    }

  if (sh.flag.audit != 0 && (sh.flag.aud_mask & AUD_OPEN) != 0)
    {
      sh_error_handle ((-1), file, line, 0, MSG_AUD_OPEN,
		       pathname, (long) flags, (long) mode, val_return);
    }
  if (val_return < 0) {
    sh_error_handle ((-1), file, line, error, MSG_ERR_OPEN, 
		     sh_error_message(error, errbuf, sizeof(errbuf)),
		     pathname, (long) flags, (long) mode, val_return);
  }
  errno = error;
  SL_RETURN(val_return, _("aud_open"));
}
  
long int aud_kill (const char * file, int line, pid_t pid, int sig)
{
  int  myerror;
  long int val_return = kill (pid, sig);
  char errbuf[SH_ERRBUF_SIZE];
  myerror = errno;

  SL_ENTER(_("aud_kill"));

  if (sh.flag.audit != 0 && (sh.flag.aud_mask & AUD_KILL) != 0)
    sh_error_handle ((-1), file, line, 0, MSG_AUD_KILL,
		      (long) pid, (long) sig);
  if (val_return < 0) {
      sh_error_handle ((-1), file, line, myerror, MSG_ERR_KILL, 
		       sh_error_message(myerror, errbuf, sizeof(errbuf)),
		       (long) pid, (long) sig);
  }
  errno = myerror;
  SL_RETURN(val_return, _("aud_kill"));
}
  
/*@noreturn@*/
void aud_exit (const char * file, int line, int exitval)
{
  if (sh.flag.audit != 0 && (sh.flag.aud_mask & AUD_EXIT) != 0)
    sh_error_handle ((-1), file, line, 0, MSG_AUD_EXIT,
		      (long) exitval);

  SL_ENTER(_("aud_exit"));

  sh.flag.exit = exitval;
  exit(exitval);
}

/*@noreturn@*/
void aud__exit (const char * file, int line, int exitval)
{
  if (sh.flag.audit != 0 && (sh.flag.aud_mask & AUD_EXIT) != 0)
    sh_error_handle ((-1), file, line, 0, MSG_AUD_EXIT,
		      (long) exitval);

  SL_ENTER(_("aud__exit"));

  sh.flag.exit = exitval;
  _exit(exitval);
}

pid_t aud_fork (const char * file, int line)
{
  int error;
  pid_t i = fork();
  char errbuf[SH_ERRBUF_SIZE];

  error = errno;
  SL_ENTER(_("aud_fork"));

  if (sh.flag.audit != 0 && (sh.flag.aud_mask & AUD_FORK) != 0 && (i > 0))
    sh_error_handle ((-1), file, line, 0, MSG_AUD_FORK,
		      (long) i);
  if (i == (pid_t) -1) {
    sh_error_handle ((-1), file, line, error, MSG_ERR_FORK, 
		     sh_error_message(error, errbuf, sizeof(errbuf)),
		     (long) i);
  }
  errno = error;
  SL_RETURN(i, _("aud_fork"));
}

int aud_setuid (const char * file, int line, uid_t uid)
{
  int error = 0;
  int i = 0;
  char errbuf[SH_ERRBUF_SIZE];

  SL_ENTER(_("aud_setuid"));

  if (uid != (uid_t) 0) { 
    i = setuid(uid);
    error = errno;
  }
  if (sh.flag.audit != 0 && (sh.flag.aud_mask & AUD_SETUID) != 0)
    sh_error_handle ((-1), file, line, 0, MSG_AUD_SETUID,
		     (long) uid);
  if (uid == (uid_t) 0) {
    i = setuid(uid);
    error = errno;
  }
  if (i < 0) {
    sh_error_handle ((-1), file, line, error, MSG_ERR_SETUID, 
		     sh_error_message(error, errbuf, sizeof(errbuf)),
		     (long) uid);
  }
  errno = error;
  SL_RETURN(i, _("aud_setuid"));
}

int aud_setgid (const char * file, int line, gid_t gid)
{
  int error = 0;
  int i = 0;
  char errbuf[SH_ERRBUF_SIZE];

  SL_ENTER(_("aud_setgid"));

  if (gid != (gid_t) 0) {
    i = setgid(gid);
    error = errno;
  }

  if (sh.flag.audit != 0 && (sh.flag.aud_mask & AUD_SETGID) != 0)
    sh_error_handle ((-1), file, line, 0, MSG_AUD_SETGID,
		      (long) gid);
  if (gid == (gid_t) 0) {
    i = setgid(gid);
    error = errno;
  }
  if (i < 0) {
    sh_error_handle ((-1), file, line, error, MSG_ERR_SETGID, 
		     sh_error_message(error, errbuf, sizeof(errbuf)),
		     (long) gid);
  }
  errno = error;
  SL_RETURN(i, _("aud_setgid"));
}

int aud_pipe (const char * file, int line, int * modus)
{
  int error;
  int i = pipe (modus);
  char errbuf[SH_ERRBUF_SIZE];

  SL_ENTER(_("aud_pipe"));

  error = errno;
  if (sh.flag.audit != 0 && (sh.flag.aud_mask & AUD_PIPE) != 0)
    {
      if (i < 0)
	sh_error_handle ((-1), file, line, 0, MSG_AUD_PIPE,
			 (long) 0, (long) 0);
      else
	sh_error_handle ((-1), file, line, 0, MSG_AUD_PIPE,
			 (long) modus[0], (long) modus[1]);
    }
  if (i < 0) {
    if (i < 0)
      sh_error_handle ((-1), file, line, error, MSG_ERR_PIPE, 
		       sh_error_message(error, errbuf, sizeof(errbuf)),
		       (long) 0, (long) 0);
    else
      sh_error_handle ((-1), file, line, error, MSG_ERR_PIPE, 
		       sh_error_message(error, errbuf, sizeof(errbuf)),
		       (long) modus[0], (long) modus[1]);
  }
  SL_RETURN(i, _("aud_pipe"));
}
