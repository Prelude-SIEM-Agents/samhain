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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifdef HAVE_UTADDR
#include <sys/socket.h>
#include <netinet/in.h>
#ifndef S_SPLINT_S
#include <arpa/inet.h>
#else
#define AF_INET 2
#endif
#endif

#ifdef SH_USE_UTMP

#ifdef HAVE_UTMPX_H

#ifdef S_SPLINT_S
typedef pid_t __pid_t;
#endif

#include <utmpx.h>
#define SH_UTMP_S utmpx
#undef  ut_name
#define ut_name ut_user
#ifdef HAVE_UTXTIME
#undef  ut_time
#define ut_time        ut_xtime
#else
#undef  ut_time
#define ut_time        ut_tv.tv_sec
#endif

#else
#include <utmp.h>
#define SH_UTMP_S utmp
#endif


#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#undef  FIL__
#define FIL__  _("sh_utmp.c")

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 


#include "samhain.h"
#include "sh_utils.h"
#include "sh_error.h"
#include "sh_modules.h"
#include "sh_utmp.h"
#include "sh_pthread.h"
#include "sh_inotify.h"

SH_MUTEX_EXTERN(mutex_thread_nolog);

#ifdef TM_IN_SYS_TIME
#include <sys/time.h>
#else
#include <time.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif 

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#define NAMLEN(dirent) sl_strlen((dirent)->d_name)
#else
#define dirent direct
#define NAMLEN(dirent) (dirent)->d_namlen
#ifdef HAVE_SYS_NDIR_H
#include <sys/ndir.h>
#endif
#ifdef HAVE_SYS_DIR_H
#include <sys/dir.h>
#endif
#ifdef HAVE_NDIR_H
#include <ndir.h>
#endif
#endif

#ifndef HAVE_LSTAT
#define lstat stat
#endif 

#ifndef UT_LINESIZE
#ifndef __UT_LINESIZE
#define UT_LINESIZE            12
#else
#define UT_LINESIZE __UT_LINESIZE
#endif 
#endif

#ifndef UT_NAMESIZE
#ifndef __UT_NAMESIZE
#define UT_NAMESIZE             8
#else
#define UT_NAMESIZE __UT_NAMESIZE
#endif
#endif

#ifndef UT_HOSTSIZE
#ifndef __UT_HOSTSIZE
#define UT_HOSTSIZE            16
#else
#define UT_HOSTSIZE __UT_HOSTSIZE
#endif
#endif

#ifdef HAVE_UTMPX_H

#ifndef _PATH_UTMP
#ifdef   UTMPX_FILE
#define _PATH_UTMP   UTMPX_FILE
#else  
#error  You must define UTMPX_FILE in the file config.h 
#endif
#endif
#ifndef _PATH_WTMP
#ifdef   WTMPX_FILE
#define _PATH_WTMP   WTMPX_FILE
#else
#error  You must define WTMPX_FILE in the file config.h
#endif
#endif

#else

#ifndef _PATH_UTMP
#ifdef   UTMP_FILE
#define _PATH_UTMP   UTMP_FILE
#else  
#error  You must define UTMP_FILE in the file config.h 
#endif
#endif
#ifndef _PATH_WTMP
#ifdef   WTMP_FILE
#define _PATH_WTMP   WTMP_FILE
#else
#error  You must define WTMP_FILE in the file config.h
#endif
#endif

#endif

typedef struct log_user {
  char                ut_tty[UT_LINESIZE+1];    
  char                name[UT_NAMESIZE+1];
  char                ut_host[UT_HOSTSIZE+1];
  char                ut_ship[SH_IP_BUF]; /* IP address */
  time_t              time;
  struct log_user   * next;
} blah_utmp;

#ifdef HAVE_UTTYPE
static char   terminated_line[UT_HOSTSIZE]; 
#endif

static char * mode_path[] = { _PATH_WTMP, _PATH_WTMP, _PATH_UTMP };

static struct SH_UTMP_S save_utmp;

static void sh_utmp_logout_morechecks(struct log_user   * user);
static void sh_utmp_login_morechecks(struct SH_UTMP_S * ut);
static void sh_utmp_addlogin (struct SH_UTMP_S * ut);
static void sh_utmp_check_internal(int mode);

static int    ShUtmpLoginSolo    = SH_ERR_INFO;
static int    ShUtmpLoginMulti   = SH_ERR_WARN;
static int    ShUtmpLogout       = SH_ERR_INFO;
static int    ShUtmpActive       = S_TRUE;
static time_t ShUtmpInterval     = 300;

sh_rconf sh_utmp_table[] = {
  {
    N_("severityloginmulti"),
    sh_utmp_set_login_multi
  },
  {
    N_("severitylogin"),
    sh_utmp_set_login_solo
  },
  {
    N_("severitylogout"),
    sh_utmp_set_logout_good
  },
  {
    N_("logincheckactive"),
    sh_utmp_set_login_activate
  },
  {
    N_("logincheckinterval"),
    sh_utmp_set_login_timer
  },
  {
    N_("logincheckfirst"),
    sh_login_set_checklevel
  },
  {
    N_("logincheckoutlier"),
    sh_login_set_siglevel
  },
  {
    N_("logincheckdate"),
    sh_login_set_def_allow
  },
  {
    N_("logincheckuserdate"),
    sh_login_set_user_allow
  },
  {
    NULL,
    NULL
  },
};

static void set_defaults(void)
{
  ShUtmpLoginSolo    = SH_ERR_INFO;
  ShUtmpLoginMulti   = SH_ERR_WARN;
  ShUtmpLogout       = SH_ERR_INFO;
  ShUtmpActive       = S_TRUE;
  ShUtmpInterval     = 300;

  sh_login_reset();
  return;
}


#if defined (HAVE_SETUTENT) && defined (USE_SETUTENT)

#ifdef HAVE_UTMPX_H

#define sh_utmp_utmpname     utmpxname
#define sh_utmp_setutent     setutxent
#define sh_utmp_endutent     endutxent
#define sh_utmp_getutent     getutxent
#define sh_utmp_getutid      getutxid
#define sh_utmp_getutline    getutxline

#else

#define sh_utmp_utmpname     utmpname
#define sh_utmp_setutent     setutent
#define sh_utmp_endutent     endutent
#define sh_utmp_getutent     getutent
#define sh_utmp_getutid      getutid
#define sh_utmp_getutline    getutline

#endif

#else

/* BSD lacks getutent() etc.
 * utmpname(), setutent(), and endutent() return void,
 * so we do not perform much error handling.
 * Errors must be recognized by getutent() returning NULL.
 * Apparently, the application cannot check whether wtmp is empty,
 * or whether there was an fopen() error.
 */

static FILE * sh_utmpfile = NULL;
static char   sh_utmppath[80] = _PATH_UTMP;

/* sh_utmp_feed_forward is for optimizing
 * (fseek instead of getutent loop)
 */
static long   sh_utmp_feed_forward = 0;

static void sh_utmp_utmpname(const char * str)
{
  SL_ENTER(_("sh_utmp_utmpname"));
  if (sh_utmpfile != NULL)
    {
      (void) sl_fclose (FIL__, __LINE__, sh_utmpfile);
      sh_utmpfile = NULL;
    }

  (void) sl_strlcpy (sh_utmppath, str, 80);
  SL_RET0(_("sh_utmp_utmpname"));
}

static void sh_utmp_setutent(void)
{
  int error;
  int fd;

  SL_ENTER(_("sh_utmp_setutent"));

  if (sh_utmpfile == NULL) 
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      fd = (int) aud_open (FIL__, __LINE__, SL_NOPRIV, 
			   sh_utmppath, O_RDONLY, 0);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      if (fd >= 0)
	{
	  sh_utmpfile = fdopen(fd, "r");
	}

      /* -- If (sh_utmpfile == NULL) then either the open() or the fdopen()
       *    has failed.
       */
      if (sh_utmpfile == NULL) 
	{
	  error = errno;
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, error, MSG_E_ACCESS,
			   (long) sh.real.uid, sh_utmppath);
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  SL_RET0(_("sh_utmp_setutent"));
	}
    }
  (void) fseek (sh_utmpfile, 0L, SEEK_SET);
  if (-1 == fseek (sh_utmpfile, sh_utmp_feed_forward, SEEK_CUR))
    {
      sh_utmp_feed_forward = 0; /* modified Apr 4, 2004 */
      (void) fseek (sh_utmpfile, 0L, SEEK_SET);
    }
  clearerr (sh_utmpfile);
  SL_RET0(_("sh_utmp_setutent"));
}

static void sh_utmp_endutent(void)
{
  SL_ENTER(_("sh_utmp_endutent"));
  if (NULL != sh_utmpfile)
    (void) sl_fclose(FIL__, __LINE__, sh_utmpfile);
  sh_utmpfile = NULL;
  SL_RET0(_("sh_utmp_endutent"));
}

static struct SH_UTMP_S * sh_utmp_getutent(void)
{
  size_t in;
  static struct SH_UTMP_S out;

  SL_ENTER(_("sh_utmp_getutent"));

  ASSERT_RET((sh_utmpfile != NULL), _("sh_utmpfile != NULL"), (NULL))

  in = fread (&out, sizeof(struct SH_UTMP_S), 1, sh_utmpfile);

  if (in != 1) 
    {
      if (ferror (sh_utmpfile) != 0) 
	{
	  clearerr (sh_utmpfile);
	  SL_RETURN(NULL, _("sh_utmp_getutent"));
	} 
      else 
	{
	  SL_RETURN(NULL, _("sh_utmp_getutent"));
	}
    }
  SL_RETURN(&out, _("sh_utmp_getutent"));
}

#ifdef USE_UNUSED

static struct SH_UTMP_S * sh_utmp_getutline(struct SH_UTMP_S * ut)
{
  struct SH_UTMP_S * out;
 
  while (1) {
      if ((out = sh_utmp_getutent()) == NULL) {
       	return NULL;
      }
#ifdef HAVE_UTTYPE  
      if (out->ut_type == USER_PROCESS || out->ut_type == LOGIN_PROCESS)
	if (sl_strcmp(ut->ut_line, out->ut_line) == 0) 
	  return out;
#else
      if ( 0 != sl_strncmp (out->ut_name, "reboot",   6) &&
	   0 != sl_strncmp (out->ut_name, "shutdown", 8) &&
	   0 != sl_strncmp (out->ut_name, "date",     4) )
	return out;
#endif
  }
  return NULL;
}

static struct SH_UTMP_S * sh_utmp_getutid(struct SH_UTMP_S * ut)
{
#ifdef HAVE_UTTYPE  
  struct SH_UTMP_S * out;

  if (ut->ut_type == RUN_LVL  || ut->ut_type == BOOT_TIME ||
      ut->ut_type == NEW_TIME || ut->ut_type == OLD_TIME) 
    {
      while (1) {
	if ((out = sh_utmp_getutent()) == NULL) {
	  return NULL;
	}
	if (out->ut_type == ut->ut_type) 
	  return out;
      }
    } 
  else if (ut->ut_type == INIT_PROCESS || ut->ut_type == LOGIN_PROCESS ||
	   ut->ut_type == USER_PROCESS || ut->ut_type == DEAD_PROCESS ) 
    {
      while (1) {
	if ((out = sh_utmp_getutent()) == NULL) {
	  return NULL;
	}
	if (sl_strcmp(ut->ut_id, out->ut_id) == 0) 
	  return out;
      }
    }
#endif
  return NULL;
}
/* #ifdef USE_UNUSED */
#endif

/* #ifdef HAVE_SETUTENT */
#endif

#ifdef HAVE_UTADDR
#ifdef HAVE_UTADDR_V6
static char * my_inet_ntoa(SINT32 * ut_addr_v6, char * buf, size_t buflen)
{
  struct in_addr in;

  buf[0] = '\0';

  if (0 == (ut_addr_v6[1] + ut_addr_v6[2] + ut_addr_v6[3]))
    {
      memcpy(&in, ut_addr_v6, sizeof(struct in_addr));
      sl_strlcpy(buf, inet_ntoa(in), buflen);
    }
  else
    {
      inet_ntop(AF_INET6, ut_addr_v6, buf, buflen);
    }
  return buf;
}
#else
static char * my_inet_ntoa(SINT32 ut_addr, char * buf, size_t buflen)
{
  struct in_addr in;

  buf[0] = '\0';

  memcpy(&in, ut_addr, sizeof(struct in_addr));
  sl_strlcpy(buf, inet_ntoa(in), buflen);
  return buf;
}
#endif
/* #ifdef HAVE_UTADDR */
#endif

#if defined(__linux__) && !defined(ut_addr)
#define ut_addr         ut_addr_v6[0]
#endif


static struct log_user   * userlist   = NULL;
static time_t  lastcheck;
static int     init_done = 0;

/*************
 *
 * module init
 *
 *************/

static int sh_utmp_init_internal (void)
{

  SL_ENTER(_("sh_utmp_init"));
  if (ShUtmpActive == BAD)
    SL_RETURN( (-1), _("sh_utmp_init"));

  /* do not re-initialize after a re-configuration
   */
  if (init_done == 1) {
    SL_RETURN( (0), _("sh_utmp_init"));
  }
  lastcheck  = time (NULL);
  userlist   = NULL;
  memset (&save_utmp, 0, sizeof(struct SH_UTMP_S));
  sh_utmp_check_internal (2); /* current logins */
  sh_utmp_check_internal (0);
  init_done = 1;
  SL_RETURN( (0), _("sh_utmp_init"));
}

int sh_utmp_init (struct mod_type * arg)
{
#if !defined(HAVE_PTHREAD)
  (void) arg;
#endif
  if (ShUtmpActive == BAD)
    return SH_MOD_FAILED;
#ifdef HAVE_PTHREAD
  if (arg != NULL && arg->initval < 0 && 
      (sh.flag.isdaemon == S_TRUE || sh.flag.loop == S_TRUE))
    {
      if (0 == sh_pthread_create(sh_threaded_module_run, (void *)arg))
	return SH_MOD_THREAD;
      else
	return SH_MOD_FAILED;
    }
  else if (arg != NULL && arg->initval == SH_MOD_THREAD &&
	   (sh.flag.isdaemon == S_TRUE || sh.flag.loop == S_TRUE))
    {
      return SH_MOD_THREAD;
    }
#endif
  return sh_utmp_init_internal();
}

/*************
 *
 * module cleanup
 *
 *************/
#ifdef HAVE_UTTYPE
static int sh_utmp_login_clean(void);
#endif

#if defined(HAVE_PTHREAD)
static sh_watches inotify_watch = SH_INOTIFY_INITIALIZER;
#endif

int sh_utmp_end ()
{
  struct log_user * user    = userlist;
  struct log_user * userold;

  SL_ENTER(_("sh_utmp_end"));
  while (user)
    {
      userold = user;
      user    = user->next;
      SH_FREE(userold);
    }
  userlist = NULL;
#ifdef HAVE_UTTYPE
  (void) sh_utmp_login_clean();
#endif
  /* Reset the flag, such that the module
   * can be re-enabled.
   */
  set_defaults();
  init_done          = 0;

#if defined(HAVE_PTHREAD)
  sh_inotify_remove(&inotify_watch);
#endif

  SL_RETURN( (0), _("sh_utmp_end"));
}


int sh_utmp_reconf()
{
  set_defaults();
#if defined(HAVE_PTHREAD)
  sh_inotify_remove(&inotify_watch);
#endif
  return 0;
}


/*************
 *
 * module timer
 *
 *************/
int sh_utmp_timer (time_t tcurrent)
{
#if !defined(HAVE_PTHREAD)
  retry_msleep(1, 0);

  if ((time_t) (tcurrent - lastcheck) >= ShUtmpInterval)
    {
      lastcheck  = tcurrent;
      return (-1);
    }
  return 0;
#else
  int errnum = 0;
  
  if ( (sh.flag.isdaemon == S_TRUE || sh.flag.loop == S_TRUE) &&
       sh.flag.checkSum != SH_CHECK_INIT )
    {
      sh_inotify_wait_for_change(mode_path[1], &inotify_watch, 
				 &errnum, ShUtmpInterval);
    }
  
  lastcheck  = tcurrent;

  if (SH_INOTIFY_ERROR(errnum))
    {
      char ebuf[SH_ERRBUF_SIZE];

      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_message(errnum, ebuf, sizeof(ebuf));
      sh_error_handle (SH_ERR_WARN, FIL__, __LINE__, errnum, MSG_E_SUBGEN,
		       ebuf,
		       _("sh_utmp_timer") );
      SH_MUTEX_UNLOCK(mutex_thread_nolog);    
    }
  return -1;
#endif
}

/*************
 *
 * module check
 *
 *************/
int sh_utmp_check ()
{
  SL_ENTER(_("sh_utmp_check"));
  if (ShUtmpActive == BAD)
    {
#if defined(HAVE_PTHREAD)
      sh_inotify_remove(&inotify_watch);
#endif
      SL_RETURN( (-1), _("sh_utmp_check"));
    }
  SH_MUTEX_LOCK(mutex_thread_nolog);
  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_UT_CHECK);
  SH_MUTEX_UNLOCK(mutex_thread_nolog);
  sh_utmp_check_internal (1);

  SL_RETURN(0, _("sh_utmp_check"));
}

/*************
 *
 * module setup
 *
 *************/

int sh_utmp_set_login_solo  (const char * c)
{
  int retval;
  char tmp[32];

  SL_ENTER(_("sh_utmp_set_login_solo"));
  tmp[0] = '='; tmp[1] = '\0';
  (void) sl_strlcat (tmp, c, 32);
  SH_MUTEX_LOCK(mutex_thread_nolog);
  retval = sh_error_set_level (tmp, &ShUtmpLoginSolo);
  SH_MUTEX_UNLOCK(mutex_thread_nolog);
  SL_RETURN(retval, _("sh_utmp_set_login_solo"));
}

int sh_utmp_set_login_multi (const char * c)
{
  int retval;
  char tmp[32];

  SL_ENTER(_("sh_utmp_set_login_multi"));
  tmp[0] = '='; tmp[1] = '\0';
  (void) sl_strlcat (tmp, c, 32);
  SH_MUTEX_LOCK(mutex_thread_nolog);
  retval = sh_error_set_level (tmp, &ShUtmpLoginMulti);
  SH_MUTEX_UNLOCK(mutex_thread_nolog);
  SL_RETURN(retval, _("sh_utmp_set_login_multi"));
}

int sh_utmp_set_logout_good (const char * c)
{
  int retval;
  char tmp[32];

  SL_ENTER(_("sh_utmp_set_logout_good"));
  tmp[0] = '='; tmp[1] = '\0';
  (void) sl_strlcat (tmp, c, 32);
  SH_MUTEX_LOCK(mutex_thread_nolog);
  retval = sh_error_set_level (tmp, &ShUtmpLogout);
  SH_MUTEX_UNLOCK(mutex_thread_nolog);
  SL_RETURN(retval, _("sh_utmp_set_logout_good"));
}

int sh_utmp_set_login_timer (const char * c)
{
  long val;

  SL_ENTER(_("sh_utmp_set_login_timer"));
  val = strtol (c, (char **)NULL, 10);
  if (val <= 0)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS,
		       _("utmp timer"), c);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      SL_RETURN((-1), _("sh_utmp_set_login_timer"));
    }

  ShUtmpInterval = (time_t) val;
  SL_RETURN(0, _("sh_utmp_set_login_timer"));
}

int sh_utmp_set_login_activate (const char * c)
{
  int i;
  SL_ENTER(_("sh_utmp_set_login_activate"));
  i = sh_util_flagval(c, &ShUtmpActive);
  SL_RETURN(i, _("sh_utmp_set_login_activate"));
}

#ifdef HAVE_UTTYPE
struct login_ct {
  char name[UT_NAMESIZE+1];
  int  nlogin;
  struct login_ct * next;
};

static struct login_ct * login_ct_list = NULL;

static int sh_utmp_login_clean(void)
{
  struct login_ct * list = login_ct_list;
  struct login_ct * old;

  login_ct_list = NULL;

  while (list)
    {
      old  = list;
      list = list->next;
      SH_FREE(old);
    }
  return 0;
}

/* add a username to the list of logged-in users
 */
static int sh_utmp_login_a(char * str)
{
  struct login_ct * list = login_ct_list;

  while (list)
    {
      if (0 == sl_strcmp(list->name, str))
	{
	  ++(list->nlogin);
	  return list->nlogin;
	}
      list = list->next;
    }
  list = SH_ALLOC(sizeof(struct login_ct));
  (void) sl_strlcpy(list->name, str, UT_NAMESIZE+1);
  list->nlogin  = 1;
  list->next    = login_ct_list;
  login_ct_list = list;
  return 1;
}

static int sh_utmp_login_r(char * str)
{
  struct login_ct * list = login_ct_list;
  struct login_ct * old  = login_ct_list;

  while (list)
    {
      if (0 == sl_strcmp(list->name, str))
	{
	  list->nlogin -= 1;
	  if (list->nlogin > 0)
	    {
	      return list->nlogin;
	    }
	  if (login_ct_list == list) /* modified Apr 4, 2004 */
	    {
	      login_ct_list = list->next;
	      SH_FREE(list);
	    }
	  else
	    {
	      old->next = list->next;
	      SH_FREE(list);
	    }
	  return 0;
	}
      old  = list;
      list = list->next;
    }
  return 0;
}

#endif


/* for each login:
 *    - allocate a log record
 *    - link device.ut_record -> log_record
 *    - link user.ut_record   -> log_record
 */

#ifdef HAVE_UTTYPE  
static int sh_utmp_is_virtual (char * in_utline, char * in_uthost)
{

  if (in_uthost != NULL   &&
      in_utline != NULL   &&
      in_uthost[0] == ':' && 
      in_uthost[1] == '0' && 
      0 == sl_strncmp(in_utline, _("pts/"), 4))
    {
      return 1;
    }

  return 0;
}
#endif

/* These variables are not used anywhere. They only exist
 * to assign &userold, &user to them, which keeps gcc from
 * putting them into a register, and avoids the 'clobbered
 * by longjmp' warning. And no, 'volatile' proved insufficient.
 */
void * sh_dummy_850_userold = NULL;
void * sh_dummy_851_user    = NULL;


static void sh_utmp_addlogin (struct SH_UTMP_S * ut)
{
  struct log_user   * user     = userlist;
  struct log_user   * userold  = userlist;
#ifdef HAVE_UTTYPE  
  struct log_user   * username = userlist;
#endif

  char   ttt[TIM_MAX];
#ifdef HAVE_UTTYPE
  volatile int    status;
#endif

  SL_ENTER(_("sh_utmp_addlogin"));

  if (ut->ut_line[0] == '\0')
    SL_RET0(_("sh_utmp_addlogin"));

  /* for some stupid reason, AIX repeats the wtmp entry for logouts
   * with ssh
   */
  if (memcmp (&save_utmp, ut, sizeof(struct SH_UTMP_S)) == 0)
    {
      memset(&save_utmp, (int) '\0', sizeof(struct SH_UTMP_S));
      SL_RET0(_("sh_utmp_addlogin"));
    }
  memcpy (&save_utmp, ut, sizeof(struct SH_UTMP_S));

  /* Take the address to keep gcc from putting them into registers. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_850_userold = (void*) &userold;
  sh_dummy_851_user    = (void*) &user;

  /* ------- find user -------- 
   */
  while (user != NULL) 
    {
      if (0 == sl_strncmp((char*)(user->ut_tty), ut->ut_line, UT_LINESIZE) ) 
	break;
      userold = user;
      user = user->next;
    }

#ifdef HAVE_UTTYPE  
  while (username != NULL) 
    {
      if (0 == sl_strncmp(username->name, ut->ut_name, UT_NAMESIZE) ) 
	break;
      username = username->next;
    }
#endif
  
#ifdef HAVE_UTTYPE  
  /* ---------- LOGIN -------------- */
  if (ut->ut_type == USER_PROCESS) 
    {
      if (user == NULL)
	{
	  user = SH_ALLOC(sizeof(struct log_user));
	  user->next       = userlist;
	  userlist         = (struct log_user *) user;
	}
      (void) sl_strlcpy((char*)(user->ut_tty),  ut->ut_line, UT_LINESIZE+1);
      (void) sl_strlcpy((char*)(user->name),    ut->ut_name, UT_NAMESIZE+1);
#ifdef HAVE_UTHOST
      (void) sl_strlcpy((char*)(user->ut_host), ut->ut_host, UT_HOSTSIZE+1);
#else
      user->ut_host[0] = '\0';
#endif
#ifdef HAVE_UTADDR
#ifdef HAVE_UTADDR_V6
      my_inet_ntoa(ut->ut_addr_v6, user->ut_ship, SH_IP_BUF);
#else
      my_inet_ntoa(ut->ut_addr, user->ut_ship, SH_IP_BUF);
#endif
#endif
      user->time = ut->ut_time;

      if (username == NULL                              /* not yet logged in */
          || 0 == sl_strncmp(ut->ut_line, _("ttyp"), 4) /* in virt. console  */
          || 0 == sl_strncmp(ut->ut_line, _("ttyq"), 4) /* in virt. console  */
	  ) {
	status = sh_utmp_login_a((char*)user->name);
	SH_MUTEX_LOCK(mutex_thread_nolog);
	(void) sh_unix_time (user->time, ttt, TIM_MAX);
	sh_error_handle( ShUtmpLoginSolo, FIL__, __LINE__, 0,
#if defined(HAVE_UTHOST) && defined(HAVE_UTADDR)
			 MSG_UT_LG1X,
#elif defined(HAVE_UTHOST)
			 MSG_UT_LG1A,
#else
			 MSG_UT_LG1B,
#endif
			 user->name,
			 user->ut_tty,
#if defined(HAVE_UTHOST) && defined(HAVE_UTADDR)
			 user->ut_host,
			 user->ut_ship,
#elif defined(HAVE_UTHOST)
			 user->ut_host,
#endif
			 ttt,
			 status
			 );
	SH_MUTEX_UNLOCK(mutex_thread_nolog);
      } else
	if (0 == sh_utmp_is_virtual(ut->ut_line, (char*)user->ut_host))
	  {       
	    status = sh_utmp_login_a((char*)user->name);
	    SH_MUTEX_LOCK(mutex_thread_nolog);
	    (void) sh_unix_time (user->time, ttt, TIM_MAX);
	    sh_error_handle( ShUtmpLoginMulti, FIL__, __LINE__, 0,
#if defined(HAVE_UTHOST) && defined(HAVE_UTADDR)
			     MSG_UT_LG2X,
#elif defined(HAVE_UTHOST)
			     MSG_UT_LG2A,
#else
			     MSG_UT_LG2B,
#endif
			     user->name,
			     user->ut_tty,
#if defined(HAVE_UTHOST) && defined(HAVE_UTADDR)
			     user->ut_host,
			     user->ut_ship,
#elif defined(HAVE_UTHOST)
			     user->ut_host,
#endif
			     ttt,
			     status
			     );
	    SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  }
      
      sh_utmp_login_morechecks(ut);
      goto out;
    }


  /* ---------  LOGOUT ---------------- */
  else if (ut->ut_name[0] == '\0'
	   || ut->ut_type == DEAD_PROCESS  /* solaris does not clear ut_name */
	   )
    {
      if (user != NULL)
	{
#if defined(__linux__)
	  if (0 == sh_utmp_is_virtual(ut->ut_line, (char*)user->ut_host)) {
#endif
	    status = sh_utmp_login_r((char*)user->name);
	    SH_MUTEX_LOCK(mutex_thread_nolog);
	    (void) sh_unix_time (ut->ut_time, ttt, TIM_MAX);
	    sh_error_handle( ShUtmpLogout, FIL__, __LINE__, 0,
#if defined(HAVE_UTHOST) && defined(HAVE_UTADDR)
			     MSG_UT_LG3X,
#elif defined(HAVE_UTHOST)
			     MSG_UT_LG3A,
#else
			     MSG_UT_LG3B,
#endif
			     user->name,
			     user->ut_tty,
#if defined(HAVE_UTHOST) && defined(HAVE_UTADDR)
			     user->ut_host,
			     user->ut_ship,
#elif defined(HAVE_UTHOST)
			     user->ut_host,
#endif
			     ttt,
			     status
			     );
	    SH_MUTEX_UNLOCK(mutex_thread_nolog);
	    userold->next = user->next;
	    if (user == userlist)
	      userlist = user->next;
	    sh_utmp_logout_morechecks((struct log_user *)user);
	    SH_FREE((struct log_user *)user);
	    user = NULL;
#if defined(__linux__)
	  }
#endif
	}
      else
	{
	  (void) sl_strlcpy(terminated_line, ut->ut_line, UT_HOSTSIZE);
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  (void) sh_unix_time (ut->ut_time, ttt, TIM_MAX);
	  sh_error_handle( ShUtmpLogout, FIL__, __LINE__, 0,
			   MSG_UT_LG3C,
			   terminated_line,
			   ttt, 0
			   );
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	}
      goto out;
    }

  /* default */
  goto out;

  /* #ifdef HAVE_UTTYPE                   */
#else

  if (user == NULL)   /* probably a login */
    {
      user = SH_ALLOC(sizeof(struct log_user));
      sl_strlcpy(user->ut_tty,  ut->ut_line, UT_LINESIZE+1);
      sl_strlcpy(user->name,    ut->ut_name, UT_NAMESIZE+1);
#ifdef HAVE_UTHOST
      sl_strlcpy(user->ut_host, ut->ut_host, UT_HOSTSIZE+1);
#endif
#ifdef HAVE_UTADDR
#ifdef HAVE_UTADDR_V6
      my_inet_ntoa(ut->ut_addr_v6, user->ut_ship, SH_IP_BUF);
#else
      my_inet_ntoa(ut->ut_addr, user->ut_ship, SH_IP_BUF);
#endif
#endif
      user->time       = ut->ut_time;
      user->next       = userlist;
      userlist         = user;

      SH_MUTEX_LOCK(mutex_thread_nolog);
      (void) sh_unix_time (user->time, ttt, TIM_MAX);
      sh_error_handle( ShUtmpLoginSolo, FIL__, __LINE__, 0,
#if defined(HAVE_UTHOST) && defined(HAVE_UTADDR)
		       MSG_UT_LG1X,
#elif defined(HAVE_UTHOST)
		       MSG_UT_LG1A,
#else
		       MSG_UT_LG1B,
#endif
		       user->name,
		       user->ut_tty,
#if defined(HAVE_UTHOST) && defined(HAVE_UTADDR)
		       user->ut_host,
		       user->ut_ship,
#elif defined(HAVE_UTHOST)
		       user->ut_host,
#endif
		       ttt,
		       1
		       );
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      sh_utmp_login_morechecks(ut);
    }
  else  /* probably a logout */
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      (void) sh_unix_time (ut->ut_time, ttt, TIM_MAX);
      sh_error_handle( ShUtmpLogout, FIL__, __LINE__, 0,
#if defined(HAVE_UTHOST) && defined(HAVE_UTADDR)
		       MSG_UT_LG2X,
#elif defined(HAVE_UTHOST)
		       MSG_UT_LG2A,
#else
		       MSG_UT_LG2B,
#endif
		       user->name,
		       user->ut_tty,
#if defined(HAVE_UTHOST) && defined(HAVE_UTADDR)
		       user->ut_host,
		       user->ut_ship,
#elif defined(HAVE_UTHOST)
		       user->ut_host,
#endif
		       ttt,
		       1
		       );
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      sh_utmp_logout_morechecks(user);
      userold->next = user->next;
      if (user == userlist)       /* inserted Apr 4, 2004 */
	userlist = user->next;
      SH_FREE(user);
      user = NULL;
    }

#endif

 out:
  sh_dummy_851_user    = NULL;
  sh_dummy_850_userold = NULL;

  SL_RET0(_("sh_utmp_addlogin"));
}

static time_t        lastmod  = 0;
static off_t         lastsize = 0;
static unsigned long lastread = 0;

static void sh_utmp_check_internal (int mode)
{
  struct stat   buf;
  int           error;
  struct SH_UTMP_S * ut;
  unsigned long this_read;
  int           val_retry;

  SL_ENTER(_("sh_utmp_check_internal"));

  /* error if no access
   */
  do {
    val_retry = /*@-unrecog@*/lstat ( mode_path[mode], &buf)/*@+unrecog@*/;
  } while (val_retry < 0 && errno == EINTR);

  if (0 != val_retry) 
    {
      error = errno;
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle((-1), FIL__, __LINE__, error, MSG_E_ACCESS,
		      (long) sh.real.uid, mode_path[mode]);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      SL_RET0(_("sh_utmp_check_internal"));
    }

  /* modification time
   */
  if (mode < 2)
    {
      if (/*@-usedef@*/buf.st_mtime <= lastmod/*@+usedef@*/)
	{ 
	  SL_RET0(_("sh_utmp_check_internal"));
	}
      else
	lastmod = buf.st_mtime;
    }

  /* file size
   */
  if (/*@-usedef@*/buf.st_size < lastsize/*@+usedef@*/ && mode < 2) 
    { 
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_UT_ROT,
		      mode_path[mode]);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      lastread = 0;
#ifndef USE_SETUTENT
      sh_utmp_feed_forward = 0L;
#endif
    }

  if (mode < 2)
    lastsize = buf.st_size;

  if (buf.st_size == 0) 
    SL_RET0(_("sh_utmp_check_internal"));

  sh_utmp_utmpname(mode_path[mode]);
  sh_utmp_setutent();

  /* 
   * feed forward if initializing
   * we need to do this here
   */
  this_read = 0;

  if (mode < 2)
    {
      while (this_read < lastread) {
	(void) sh_utmp_getutent();
	++this_read;
      }
    }

  /* start reading
   */
  this_read = 0;
  while (1 == 1) {
    ut = sh_utmp_getutent();
    if (ut == NULL) 
      break;
    /* modified: ut_user --> ut_name */
    if (mode == 1 || (mode == 2 && ut->ut_name[0] != '\0'
#ifdef HAVE_UTTYPE
		      && ut->ut_type != DEAD_PROCESS
#endif
		      ))
      sh_utmp_addlogin (ut);
    ++this_read;
  }

  sh_utmp_endutent();

  if (mode < 2)
    {
      lastread += this_read;
#ifndef USE_SETUTENT
      sh_utmp_feed_forward += (long) (this_read * sizeof(struct SH_UTMP_S));
      lastread = 0;
#endif
    }

  SL_RET0(_("sh_utmp_check_internal"));
}

extern void sh_ltrack_check(struct SH_UTMP_S * ut);

static void sh_utmp_login_morechecks(struct SH_UTMP_S * ut)
{
  sh_ltrack_check(ut);
  return;
}

static void sh_utmp_logout_morechecks(struct log_user * user)
{
  (void) user;
  return;
}

#endif


/* #ifdef SH_USE_UTMP */
#endif



