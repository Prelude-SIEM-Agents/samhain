/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2006 Rainer Wichmann                                      */
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

/***************************************************************************
 *
 * This file provides a module for samhain to check for hidden/faked/missing
 * processes on the host.
 *
 */

#include "config_xor.h"

/* changed from 500 to 600 b/o FreeBSD (see sys/cdefs.h) 
 * which needs _POSIX_C_SOURCE >= 200112 for lstat()
 */
#if defined(__sun) || defined(__sun__) || defined(sun)
#define _XOPEN_SOURCE 500
#else
#define _XOPEN_SOURCE 600
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>

#ifdef _POSIX_PRIORITY_SCHEDULING
#include <sched.h>
#endif

#ifdef HAVE_GETPRIORITY
#include <errno.h>
#include <sys/resource.h>
#endif

#ifdef HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif


#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#include "samhain.h"
#include "sh_modules.h"
#include "sh_processcheck.h"
#include "sh_utils.h"
#include "sh_error.h"
#include "sh_extern.h"
#include "sh_calls.h"
#include "sh_pthread.h"

#ifdef SH_USE_PROCESSCHECK

#define FIL__  _("sh_processcheck.c")

#ifdef __linux__
#define PS_THREADS
#endif

/* We won't want to build this into yule 
 */
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)

SH_MUTEX_STATIC(mutex_proc_check, PTHREAD_MUTEX_INITIALIZER);

/* sh_prochk_maxpid is one more than the largest pid
 */
static  size_t  sh_prochk_minpid = 0x0001;
static  size_t  sh_prochk_maxpid = 0x8000;
static  size_t  sh_prochk_size   = 0;

static  int     ShProchkActive  = S_TRUE;
static  short * sh_prochk_res   = NULL; 

static  char  * sh_prochk_pspath = NULL;
static  char  * sh_prochk_psarg  = NULL;

#define SH_PROCHK_INTERVAL 300
static time_t   sh_prochk_interval = SH_PROCHK_INTERVAL;
static int      sh_prochk_severity = SH_ERR_SEVERE;
static int      sh_prochk_openvz   = S_FALSE;

static int sh_prochk_set_maxpid  (const char * str);
static int sh_prochk_set_minpid  (const char * str);
static int sh_prochk_set_active  (const char *str);
static int sh_prochk_add_process (const char *str);
static int sh_prochk_set_pspath  (const char *str);
static int sh_prochk_set_psarg   (const char *str);
static int sh_prochk_set_interval(const char *str);
static int sh_prochk_set_severity(const char *str);
static int sh_prochk_set_openvz  (const char *str);

sh_rconf sh_prochk_table[] = {
    {
        N_("severityprocesscheck"),
        sh_prochk_set_severity,
    },
    {
        N_("processcheckexists"),
        sh_prochk_add_process,
    },
    {
        N_("processcheckactive"),
        sh_prochk_set_active,
    },
    {
        N_("processcheckminpid"),
        sh_prochk_set_minpid,
    },
    {
        N_("processcheckmaxpid"),
        sh_prochk_set_maxpid,
    },
    {
        N_("processcheckpspath"),
        sh_prochk_set_pspath,
    },
    {
        N_("processcheckpsarg"),
        sh_prochk_set_psarg,
    },
    {
        N_("processcheckinterval"),
        sh_prochk_set_interval,
    },
    {
        N_("processcheckisopenvz"),
        sh_prochk_set_openvz,
    },
    {
        NULL,
        NULL
    }
};

#define    SH_PROC_MISSING 1
#define    SH_PROC_FAKED   2
#define    SH_PROC_HIDDEN  4
#define    SH_PROC_EXISTS  8

#ifndef HAVE_LSTAT
#define lstat(x,y) stat(x,y)
#endif /* HAVE_LSTAT */

#if defined(S_IFLNK) && !defined(S_ISLNK)
#define S_ISLNK(mode) (((mode) & S_IFMT) == S_IFLNK)
#else
#if !defined(S_ISLNK)
#define S_ISLNK(mode) (0)
#endif
#endif

static const short SH_PR_PS       = 0x0001;

static const short SH_PR_GETSID   = 0x0002;
static const short SH_PR_KILL     = 0x0004;
static const short SH_PR_GETPGID  = 0x0008;

static const short SH_PR_LSTAT    = 0x0010;
static const short SH_PR_OPENDIR  = 0x0020;
static const short SH_PR_CHDIR    = 0x0040;
static const short SH_PR_SCHED    = 0x0080;

static const short SH_PR_PRIORITY = 0x0100;
static const short SH_PR_STATVSF  = 0x0200;

static const short SH_PR_PS2      = 0x1000;
static const short SH_PR_PS_ANY   = 0x2000;
static const short SH_PR_ALL      = 0x4000;
static const short SH_PR_ANY      = 0x8000;

/* /proc: 
 *        linux:     /proc/pid/exe
 *        freebsd:   /proc/pid/file
 *        solaris10: /proc/pid/path/a.out
 */
static char * get_user_and_path (pid_t pid, char * user, size_t usrlen)
{
  extern char *  sh_unix_getUIDname (int level, uid_t uid, char * out, size_t len);

  char        path[128];
  char *      buf;
  struct stat sbuf;
  int         len;
  char *      tmp;

  sl_snprintf (path, sizeof(path), _("/proc/%ld/exe"), (unsigned long) pid);

  if (0 == retry_lstat(FIL__, __LINE__, path, &sbuf) && S_ISLNK(sbuf.st_mode))
    {
      goto linkread;
    }

  sl_snprintf (path, sizeof(path), _("/proc/%ld/file"), (unsigned long) pid);

  if (0 == retry_lstat(FIL__, __LINE__, path, &sbuf) && S_ISLNK(sbuf.st_mode))
    {
      goto linkread;
    }

  sl_snprintf (path, sizeof(path), _("/proc/%ld/path/a.out"), (unsigned long) pid);

  if (0 == retry_lstat(FIL__, __LINE__, path, &sbuf) && S_ISLNK(sbuf.st_mode))
    {
      goto linkread;
    }

  return NULL;

 linkread:

  buf = SH_ALLOC(PATH_MAX);
  len = readlink(path, buf, PATH_MAX);   /* flawfinder: ignore */
  len = (len >= PATH_MAX) ? (PATH_MAX-1) : len;

  if (len > 0)
    { 
      buf[len] = '\0';
    }
  else
    {
      SH_FREE(buf);
      return NULL;
    }

  tmp = sh_unix_getUIDname (SH_ERR_ALL, sbuf.st_uid, user, usrlen);

  if (!tmp)
    sl_snprintf (user, usrlen, "%ld", (unsigned long) sbuf.st_uid);

  return buf;
}


struct watchlist {
  char        * str;
  unsigned long pid;
#ifdef HAVE_REGEX_H
  regex_t       preg;
#endif
  int           seen;

  struct watchlist *next;
};

static struct watchlist * process_check = NULL;

static struct watchlist * list_missing  = NULL;
static struct watchlist * list_fake     = NULL;
static struct watchlist * list_hidden   = NULL;

/* recursively remove all list entries
 */
static void kill_list (struct watchlist * head)
{
  if (head->next)
    kill_list (head->next);

  if (head->str)
    SH_FREE(head->str);
  SH_FREE(head);

  return;
}

  
/* check the list for old entries; clean out old entries; reset others
 * Return number of non-obsolete entries
 */
static size_t clean_list (struct watchlist ** head_ptr)
{
  size_t count = 0;
  struct watchlist * ptr = *head_ptr;
  struct watchlist * pre = *head_ptr;

  while (ptr)
    {
      if (ptr->seen == S_FALSE) /* obsolete entry */
	{
	  if (ptr == pre)       /* at head        */
	    {
	      ptr       = pre->next;
	      *head_ptr = pre->next;
	      if (pre->str) 
		SH_FREE(pre->str);
	      SH_FREE(pre);
	      pre       = ptr;
	    }
	  else
	    {
	      pre->next = ptr->next;
	      if (ptr->str) 
		SH_FREE(ptr->str);
	      SH_FREE(ptr);
	      ptr       = pre->next;
	    }
	}
      else
	{
	  ++count;
	  ptr->seen = S_FALSE; /* reset status */
	  pre = ptr;
	  ptr = ptr->next;
	}
    }
  return count;
}

/* check if process is in list; if not, add it and return false
 */
static int  is_in_list (struct watchlist ** head_ptr, 
			char * str, unsigned long pid)
{
  struct watchlist * ptr = *head_ptr;

  if (str)
    {
      while (ptr)
	{
	  if (ptr->str && (0 == strcmp(str, ptr->str)))
	    {
	      ptr->seen = S_TRUE;
	      return S_TRUE;
	    }
	  ptr = ptr->next;
	}
    }
  else
    {
      while (ptr)
	{
	  if (ptr->pid == pid)
	    {
	      ptr->seen = S_TRUE;
	      return S_TRUE;
	    }
	  ptr = ptr->next;
	}
    }

  ptr = SH_ALLOC(sizeof(struct watchlist));

  if (str)
    {
      ptr->str = sh_util_strdup(str);
    }
  else
    {
      ptr->str = NULL;
      ptr->pid = pid;
    }
  ptr->next = *head_ptr;
  ptr->seen = S_TRUE;
  *head_ptr = ptr;

  return S_FALSE;
}

static int is_in_watchlist (const char *str, unsigned long num)
{
  struct watchlist * list = process_check;

  while (list) 
    {
#ifdef HAVE_REGEX_H
      if (0 == regexec(&(list->preg), str, 0, NULL, 0))
	{
	  list->seen = S_TRUE;
	  list->pid  = num;
	  return S_TRUE;
	}
#else
      if (strstr(str, list->str)) 
	{
	  list->seen = S_TRUE;
	  list->pid  = num;
	  return S_TRUE;
	}
#endif
      list = list->next;
    }
  return S_FALSE;
} 

/* These variables are not used anywhere. They only exist
 * to assign &userold, &user to them, which keeps gcc from
 * putting them into a register, and avoids the 'clobbered
 * by longjmp' warning. And no, 'volatile' proved insufficient.
 */
void * sh_dummy_413_watchlist = NULL;

static void check_watchlist (short * res)
{
  struct watchlist * list = process_check;
  char * tmp;
  size_t indx;

  /* Take the address to keep gcc from putting them into registers. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_413_watchlist = (void*) &list;

  while (list) 
    {
      if (list->seen == S_FALSE)
	{
	  /* avoid repetition of messages
	   */
	  if (S_FALSE == is_in_list(&list_missing, list->str, 0))
	    {
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      tmp = sh_util_safe_name (list->str);
	      sh_error_handle(sh_prochk_severity, FIL__, __LINE__, 0, 
			      MSG_PCK_MISS,
			      tmp);
	      SH_FREE(tmp);
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	    }
	}
      else
	{
	  indx = list->pid - sh_prochk_minpid;

	  if (list->pid < sh_prochk_maxpid && list->pid >= sh_prochk_minpid && 
	      ((res[indx] & SH_PR_ANY) == 0) && /* not found         */
	      ((res[indx] & SH_PR_PS)  != 0) && /* seen in first ps  */ 
	      ((res[indx] & SH_PR_PS2) != 0))   /* seen in second ps */
	    {
	      /* fake process, thus considered missing
	       */
	      if (S_FALSE == is_in_list(&list_missing, list->str, 0))
		{
		  SH_MUTEX_LOCK(mutex_thread_nolog);
		  tmp = sh_util_safe_name (list->str);
		  sh_error_handle(sh_prochk_severity, FIL__, __LINE__, 0, 
				  MSG_PCK_MISS, 
				  tmp);
		  SH_FREE(tmp);
		  SH_MUTEX_UNLOCK(mutex_thread_nolog);
		}
	    }
	  list->seen = S_FALSE;
	}
      list = list->next;
    }

  sh_dummy_413_watchlist = NULL;
  return;
}

/* Add 'str' to the list of watched processes for which
 * existence should be checked.
 */
int sh_prochk_add_process (const char *str) 
{
  struct watchlist *new;
  int               status;
  char              errbuf[256];
    
  SL_ENTER(_("sh_prochk_add_process"));

  if( str == NULL )
    SL_RETURN(-1, _("sh_prochk_add_process") );

  new       = SH_ALLOC(sizeof(struct watchlist));
  new->next = process_check;
  new->str  = sh_util_strdup(str);
#ifdef HAVE_REGEX_H
  status = regcomp(&(new->preg), str, REG_NOSUB|REG_EXTENDED);
  if (status != 0)
    {
      regerror(status, &(new->preg), errbuf, sizeof(errbuf));
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle((-1), FIL__, __LINE__, status, MSG_E_SUBGEN, 
		      errbuf, _("sh_processes_add_process"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      SH_FREE(new->str);
      SH_FREE(new);
      SL_RETURN(-1, _("sh_prochk_add_process") );
    }
#endif
  new->pid  = 0;
  new->seen = S_FALSE;

  process_check = new;
  SL_RETURN(0, _("sh_prochk_add_process") );
}

/* severity
 */
int sh_prochk_set_severity  (const char * c)
{
  char tmp[32];
  tmp[0] = '='; tmp[1] = '\0';
  sl_strlcat (tmp, c, 32);
  return sh_error_set_level (tmp, &sh_prochk_severity);
}



/* Path to ps
 */
int sh_prochk_set_pspath(const char *str) 
{
  SL_ENTER(_("sh_prochk_set_pspath"));

  if (!str || ('/' != str[0]))
    SL_RETURN((-1), _("sh_prochk_set_pspath"));
  if (sh_prochk_pspath)
    SH_FREE(sh_prochk_pspath);
#ifdef SH_EVAL_SHELL
  sh_prochk_pspath = sh_util_strdup (str);
  SL_RETURN((0), _("sh_prochk_set_pspath"));
#else
  sh_prochk_pspath = NULL;
  SL_RETURN((-1), _("sh_prochk_set_pspath"));
#endif
}

/* argument for ps
 */
int sh_prochk_set_psarg(const char *str) 
{
  SL_ENTER(_("sh_prochk_set_psarg"));

  if (sh_prochk_psarg)
    SH_FREE(sh_prochk_psarg);
#ifdef SH_EVAL_SHELL
  sh_prochk_psarg = sh_util_strdup (str);
  SL_RETURN((0), _("sh_prochk_set_psarg"));
#else
  (void) str;
  sh_prochk_psarg = NULL;
  SL_RETURN((-1), _("sh_prochk_set_psarg"));
#endif
}


/* Decide if we're active.
 */
int sh_prochk_set_active(const char *str) 
{
  int value;
    
  SL_ENTER(_("sh_prochk_set_active"));

  value = sh_util_flagval(str, &ShProchkActive);

  SL_RETURN((value), _("sh_prochk_set_active"));
}

/* Are we on openvz.
 */
static int openvz_hidden = 0;

int sh_prochk_set_openvz(const char *str) 
{
  int value;
    
  SL_ENTER(_("sh_prochk_set_openvz"));

  value = sh_util_flagval(str, &sh_prochk_openvz);

  if (sh_prochk_openvz != S_FALSE) {
    openvz_hidden = 1;
  }

  SL_RETURN((value), _("sh_prochk_set_openvz"));
}

/* Minimum PID
 */
int sh_prochk_set_minpid(const char * str)
{
  size_t  value;
  char * foo;
  int    retval = 0;

  SL_ENTER(_("sh_prochk_set_minpid"));

  value = (size_t) strtoul(str, &foo, 0);
  if (*foo != '\0')
    retval = -1;
  else
    sh_prochk_minpid = value;

  SL_RETURN((retval), _("sh_prochk_set_minpid"));
}

/* Maximum PID
 */
static int userdef_maxpid = 0;

int sh_prochk_set_maxpid(const char * str)
{
  size_t  value;
  char * foo;
  int    retval = -1;

  SL_ENTER(_("sh_prochk_set_maxpid"));

  value = (size_t) strtoul(str, &foo, 0);

  if (*foo == '\0' && S_TRUE == sl_ok_adds(value, 1)) {
    sh_prochk_maxpid = value + 1;
    userdef_maxpid   = 1;
    retval = 0;
  }

  SL_RETURN((retval), _("sh_prochk_set_maxpid"));
}

int sh_prochk_set_interval (const char * c)
{
  int retval = 0;
  long val;

  SL_ENTER(_("sh_prochk_set_interval"));
  val = strtol (c, (char **)NULL, 10);
  if (val <= 0)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS,
		       _("process check interval"), c);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      retval = -1;
    }
  else
    {
      sh_prochk_interval = (time_t) val;
    }
  SL_RETURN(retval, _("sh_prochk_set_interval"));
}



/* Recurse to the end of the list and then free the data as we return
 * back up towards the start, making sure to free any strdupped strings
 */
static void sh_prochk_free_list(struct watchlist *head) 
{
  if ( head != NULL ) 
    {
      sh_prochk_free_list(head->next);
      if (head->str)
	SH_FREE(head->str);
#ifdef HAVE_REGEX_H
      regfree(&(head->preg));
#endif
      SH_FREE(head);
    }
  return;
}

#if defined(__linux__)
#define PROC_PID_MAX _("/proc/sys/kernel/pid_max")

static int proc_max_pid (size_t * procpid)
{
  char * ret;
  unsigned long  pid;
  FILE * fd;
  char   str[128];
  char * ptr;

  SL_ENTER(_("proc_max_pid"));

  if (userdef_maxpid != 0)
    SL_RETURN((-1), _("proc_max_pid"));
    
  if (0 == access(PROC_PID_MAX, R_OK)) /* flawfinder: ignore */
    {
      if (NULL != (fd = fopen(PROC_PID_MAX, "r")))
	{
	  str[0] = '\0';
	  ret = fgets(str, 128, fd);
	  if (ret && *str != '\0')
	    {
	      pid = strtoul(str, &ptr, 0);
	      if (*ptr == '\0' || *ptr == '\n')
		{
		  sl_fclose(FIL__, __LINE__, fd);
		  *procpid = (size_t) pid;
		  SL_RETURN(0, _("proc_max_pid"));
		}
	    }
	  sl_fclose(FIL__, __LINE__, fd);
	}
    }
  SL_RETURN((-1), _("proc_max_pid"));
}
#else
static int proc_max_pid(size_t * dummy)
{
  (void) dummy;
  return -1;
}
#endif

static void sh_processes_tlist (char * list, size_t len, short res)
{
  if (res & SH_PR_PS)       sl_strlcat(list, _(" ps(initial)"), len);
  if (res & SH_PR_CHDIR)    sl_strlcat(list, _(" chdir"), len);
  if (res & SH_PR_OPENDIR)  sl_strlcat(list, _(" opendir"), len);
  if (res & SH_PR_LSTAT)    sl_strlcat(list, _(" lstat"), len);
  if (res & SH_PR_PRIORITY) sl_strlcat(list, _(" getpriority"), len);
  if (res & SH_PR_SCHED)    sl_strlcat(list, _(" sched_getparam"), len);
  if (res & SH_PR_GETSID)   sl_strlcat(list, _(" getsid"), len);
  if (res & SH_PR_GETPGID)  sl_strlcat(list, _(" getpgid"), len);
  if (res & SH_PR_KILL)     sl_strlcat(list, _(" kill"), len);
  if (res & SH_PR_STATVSF)  sl_strlcat(list, _(" statvfs"), len);
  if (res & SH_PR_PS2)      sl_strlcat(list, _(" ps(final)"), len);
  return;
}


static short sh_processes_check (pid_t pid, short res)
{
  int  have_checks = 0;
  int  need_checks = 0;
#ifdef HAVE_PROCFS
  char path[128];
  struct stat buf;
  DIR * dir;
  int  retval;
#if defined(HAVE_STATVFS) && !defined(__FreeBSD__)
  struct statvfs vfsbuf;
#endif
#endif

#if !defined(sun) && !defined(__sun) && !defined(__sun__)
#ifdef _POSIX_PRIORITY_SCHEDULING
  struct sched_param p;
#endif
#endif

  if (0 == kill(pid, 0))
    { 
      res |= SH_PR_KILL;    res |= SH_PR_ANY; ++have_checks;
      ++need_checks;
    }
  else if (errno != EPERM)
    {
      ++need_checks;
    }


#ifdef HAVE_GETPGID
  if ((pid_t)-1 != getpgid(pid))
    { 
      res |= SH_PR_GETPGID; res |= SH_PR_ANY; ++have_checks;
    }
  ++need_checks;
#endif

#ifdef HAVE_GETSID
  if ((pid_t)-1 != getsid(pid))
    { 
      res |= SH_PR_GETSID;  res |= SH_PR_ANY; ++have_checks;
    }
  ++need_checks;
#endif

  /* sched_getparam() is broken on solaris 10, may segfault in librt
   */
#if !defined(sun) && !defined(__sun) && !defined(__sun__)
#ifdef _POSIX_PRIORITY_SCHEDULING
  if (0 == sched_getparam (pid, &p))
    { 
      res |= SH_PR_SCHED;   res |= SH_PR_ANY; ++have_checks;
    }
  ++need_checks;
#endif
#endif

#ifdef HAVE_GETPRIORITY
  errno = 0;
  if (((-1) == getpriority (PRIO_PROCESS, (int) pid)) && (errno == ESRCH));
  else
    { 
      res |= SH_PR_PRIORITY; res |= SH_PR_ANY; ++have_checks;
    }
  ++need_checks;
#endif

#ifdef HAVE_PROCFS
  sl_snprintf (path, sizeof(path), "/proc/%ld", (unsigned long) pid);

  do {
    retval = lstat (path, &buf);
  } while (retval < 0 && errno == EINTR);

  if (0 == retval)
    { 
      res |= SH_PR_LSTAT;   res |= SH_PR_ANY; ++have_checks;
    }
  ++need_checks;

  if (NULL != (dir = opendir(path)))
    {
      res |= SH_PR_OPENDIR; res |= SH_PR_ANY; ++have_checks;
      closedir(dir);
    }
  ++need_checks;

#if defined(HAVE_STATVFS) && !defined(__FreeBSD__)
  do {
    retval = statvfs (path, &vfsbuf);
  } while (retval < 0 && errno == EINTR);

  if (0 == retval)
    { 
      res |= SH_PR_STATVSF;   res |= SH_PR_ANY; ++have_checks;
    }
  ++need_checks;
#endif

#if !defined(SH_PROFILE)
  if (0 == chdir(path))
    {
      res |= SH_PR_CHDIR;   res |= SH_PR_ANY; ++have_checks;
      do {
	retval = chdir ("/");
      } while (retval < 0 && errno == EINTR);
    }
  ++need_checks;
#endif
#endif

  if (have_checks == need_checks)
    {
      res |= SH_PR_ALL;
    }
  return res;
}

extern int flag_err_debug;

static int sh_processes_readps (FILE * in, short * res, 
				char * str, size_t len, 
				short flag, pid_t pid)
{
  int  cc; 
  volatile unsigned int  lnum   = 0;
  volatile unsigned long num    = 0;
  char c;
  unsigned int  pos = 0;
#define SH_TWAIT_MAX 60
  volatile unsigned int  twait = 0;
  char tstr[256];
  enum { SKIP_TO_WS, SKIP_WS, SKIP_TO_WS2, SKIP_WS2, GET_NUM, SKIP_END, GET_NUM2 } line;

  SL_ENTER(_("sh_processes_readps"));

  if (!in) {
    SL_RETURN((-1), _("sh_processes_readps"));
  }

  tstr[(sizeof(tstr)-1)] = '\0';
  tstr[0]                = '\0';
  line = SKIP_END;		/* Skip 1st line */

  do
    {
      cc = fgetc(in);

      if (EOF == cc) 
	{
	  if (feof(in))
	    {
	      break;
	    }
	  else if ((errno == EAGAIN) && (twait < SH_TWAIT_MAX))
	    {
	      clearerr(in);
	      retry_msleep(1, 0);
	      ++twait;
	      continue;
	    }
#ifdef HOST_IS_OPENBSD
	  else if (errno == ENODEV)
	    {
	      clearerr(in);
	      continue;
	    }
#endif
	  else
	    {
	      char errbuf[SH_ERRBUF_SIZE];

	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, errno, MSG_E_SUBGEN,
			      sh_error_message(errno, errbuf, sizeof(errbuf)),
			      _("sh_processes_readps"));
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	      break;
	    }
	}

      c = (char) cc;

      if (pos < (sizeof(tstr)-1))
	{ 
	  tstr[pos] = c; ++pos; 
	}

      switch(line)
	{
	case SKIP_END:
	  if (c == '\n')
	    { 
	      tstr[pos-1] = '\0';
	      if (flag_err_debug == S_TRUE)
		{
		  SH_MUTEX_LOCK(mutex_thread_nolog);
		  sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, num, 
				  MSG_E_SUBGEN,
				  tstr,
				  _("sh_processes_readps"));
		  SH_MUTEX_UNLOCK(mutex_thread_nolog);
		}
	      /* fprintf(stderr, "<%ld> %s\n", num, tstr); */
	      line = SKIP_WS; pos = 0;
	      if (str != NULL && num == (unsigned long) pid)
		sl_strlcpy(str, tstr, len);
	      if (lnum != 0)
		is_in_watchlist (tstr, num);
	      ++lnum;
	    }
	  break;
	case SKIP_TO_WS:
	  if (!isspace(cc))
	    break;
	  line = SKIP_WS;
	  /* fallthrough */
	case SKIP_WS:
	  if (isspace(cc))
	    break;
	  num  = 0;
	  line = GET_NUM;
	  /* fallthrough */
	case GET_NUM:
	  if (isdigit(cc))
	    {
	      num = num * 10 + (c - '0');
	      break;
	    }
	  else if (isspace(cc))
	    {
#ifdef PS_THREADS
	      num  = 0;
	      line = SKIP_WS2;
#else
	      if (num < sh_prochk_maxpid && num >= sh_prochk_minpid)
		{
		  res[num - sh_prochk_minpid] |= flag;
		}
	      line = SKIP_END;
#endif
	      break;
	    }
	  else
	    {
	      line = SKIP_TO_WS;
	      break;
	    }
	case SKIP_TO_WS2:
	  if (!isspace(cc))
	    break;
	  line = SKIP_WS2;
	  /* fallthrough */
	case SKIP_WS2:
	  if (isspace(cc))
	    break;
	  num  = 0;
	  line = GET_NUM2;
	  /* fallthrough */
	case GET_NUM2:
	  if (isdigit(cc))
	    {
	      num = num * 10 + (c - '0');
	      break;
	    }
	  else if (isspace(cc))
	    {
	      if (num < sh_prochk_maxpid && num >= sh_prochk_minpid)
		{
		  res[num - sh_prochk_minpid] |= flag;
		}
	      line = SKIP_END;
	      break;
	    }
	  else
	    {
	      line = SKIP_TO_WS2;
	      break;
	    }
	default:
	  SL_RETURN ((-1), _("sh_processes_readps"));
	}
    } while (1);

  if (ferror(in))
    {
      SL_RETURN ((-1), _("sh_processes_readps"));
    }

  SL_RETURN ((0), _("sh_processes_readps"));
}

static int sh_processes_runps (short * res, char * str, size_t len, 
			       short flag, pid_t pid)
{
  sh_tas_t task;

  int    status = 0;
  char * p;
  int retval = 0;
  char  dir[SH_PATHBUF];

  SL_ENTER(_("sh_processes_runps"));

  sh_ext_tas_init(&task);
  p = sh_unix_getUIDdir (SH_ERR_ERR, task.run_user_uid, dir, sizeof(dir));
  if (p)
    {
      (void) sh_ext_tas_add_envv (&task, _("HOME"), p);
    }
  (void) sh_ext_tas_add_envv (&task, _("SHELL"), 
			      _("/bin/sh")); 
  (void) sh_ext_tas_add_envv (&task, _("PATH"),  
			      _("/sbin:/usr/sbin:/bin:/usr/bin")); 
  if (sh.timezone != NULL)
    {
      (void) sh_ext_tas_add_envv(&task,  "TZ", sh.timezone);
    }

  if (!sh_prochk_pspath)
    sh_ext_tas_command(&task,  PSPATH);
  else
    sh_ext_tas_command(&task,  sh_prochk_pspath);

  (void) sh_ext_tas_add_argv(&task,  _("ps"));

  if (!sh_prochk_psarg)
    {
#ifdef PS_THREADS
      (void) sh_ext_tas_add_argv(&task,  _("-eT"));
#else
      (void) sh_ext_tas_add_argv(&task,  PSARG);
#endif
    }
  else
    {
      (void) sh_ext_tas_add_argv(&task,  sh_prochk_psarg);
    }

  task.rw = 'r';
  task.fork_twice = S_FALSE;

  status = sh_ext_popen(&task);
  if (status != 0)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, status, MSG_E_SUBGEN, 
		      _("Could not open pipe"), _("sh_processes_runps"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      SL_RETURN ((-1), _("sh_processes_runps"));
    }

  /* read from the open pipe
   */
  if (task.pipe != NULL)
    {
      retval = sh_processes_readps (task.pipe, res, str, len, flag, pid);
    }

  /* close pipe and return exit status
   */
  (void) sh_ext_pclose(&task);
  sh_ext_tas_free (&task);
  SL_RETURN ((retval), _("sh_processes_runps"));
}

/* Check whether there is a visible process
 * with PID = i + 1024
 */
static size_t p_store = 0;

static int openvz_ok(short * res, size_t i)
{

  if (sh_prochk_openvz == S_FALSE) {
    return 0;
  }

  i += 1024;

  if (i >= sh_prochk_size) {
    return 0;
  }

  if ( ((res[i] & SH_PR_PS) || (res[i] & SH_PR_PS2)) && (res[i] & SH_PR_ANY))
    {
      /* This is a system process corresponding to a 'virtual'
       * process that has a PID offset by 1024
       */
      return 1;
    }

  if (openvz_hidden > 0)
    {
      p_store = i;
      --openvz_hidden;
      return 1;
    }
  else if (i == p_store)
    {
      return 1;
    }

  return 0;
}

static int sh_process_check_int (short * res)
{
  volatile size_t i;
  size_t j;
  char  tests[512];
  volatile int   retval;

  pid_t this_pid;

  SL_ENTER(_("sh_process_check_int"));

  this_pid = getpid();

  if (!res)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN, 
		      _("Internal error: NULL argument, switching off"), 
		      _("sh_process_check_int"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      SL_RETURN ((-1), _("sh_process_check_int"));
    }

  retval = sh_processes_runps (res, NULL, 0, SH_PR_PS, 0);

  for (i = sh_prochk_minpid; i != sh_prochk_maxpid; ++i)
    {
      j      = i - sh_prochk_minpid; 
      res[j] = sh_processes_check ((pid_t) i, res[j]);
    }

  retval += sh_processes_runps (res, NULL, 0, SH_PR_PS2, 0);

  if (retval != 0)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN, 
		      _("Failed to run ps, switching off"), 
		      _("sh_process_check_int"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      SL_RETURN ((-1), _("sh_process_check_int"));
    }

  /* Evaluate results
   */
  for (i = sh_prochk_minpid; i != sh_prochk_maxpid; ++i)
    {
      /* don't check the current process
       */
      if (i == (size_t) this_pid)
	continue;

      j      = i - sh_prochk_minpid;

      if (((res[j] & SH_PR_PS) != 0) || ((res[j] & SH_PR_PS2) != 0))
	{
	  res[j] |= SH_PR_PS_ANY;
	}
      else
	{
	  res[j] &= ~SH_PR_PS_ANY;
	}

      tests[0] = '\0';

      if ((res[j] & SH_PR_ANY) || (res[j] & SH_PR_PS_ANY))
	{
	  /* list all tests where the pid was found
	   */
	  sh_processes_tlist (tests, sizeof(tests), res[j]);

	  /* 
	   * case 1: in ps and found 
	   */
	  if ((res[j] & SH_PR_PS_ANY) && (res[j] & SH_PR_ANY))
	    {
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_PCK_OK, 
			      (unsigned long) i, tests);
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	    }

	  /* 
	   * case 2: not in ps and found
	   */
	  else if ((res[j] & SH_PR_PS_ANY) == 0) 
	    {
	      res[j] = sh_processes_check ((pid_t) i, 0);
	      /*
	       * if still there, it is real and hidden
	       */
	      if ((res[j] & SH_PR_ANY) && !openvz_ok(res, j))
		{
		  if (S_FALSE == is_in_list(&list_hidden, NULL, i))
		    {
		      char   user[16];
		      char * aout;
		      char * safe;

		      SH_MUTEX_LOCK(mutex_thread_nolog);
		      aout = get_user_and_path ((pid_t) i, user, sizeof(user));
		      SH_MUTEX_UNLOCK(mutex_thread_nolog);

		      if (aout)
			{
			  safe = sh_util_safe_name (aout);
			  SH_MUTEX_LOCK(mutex_thread_nolog);
			  sh_error_handle(sh_prochk_severity, FIL__, __LINE__, 0, 
					  MSG_PCK_P_HIDDEN,
					  (unsigned long) i, tests, safe, user);
			  SH_MUTEX_UNLOCK(mutex_thread_nolog);
			  SH_FREE(safe);
			  SH_FREE(aout);
			}
		      else
			{
			  SH_MUTEX_LOCK(mutex_thread_nolog);
			  sh_error_handle(sh_prochk_severity, FIL__, __LINE__, 0, 
					  MSG_PCK_HIDDEN,
					  (unsigned long) i, tests);
			  SH_MUTEX_UNLOCK(mutex_thread_nolog);
			}
		    }
		}
	    }

	  /*
	   * case 3: in ps, but not found
	   */
	  else
	    {
	      if (((res[j] & SH_PR_PS) != 0) && ((res[j] & SH_PR_PS2) != 0))
		{
		  if (S_FALSE == is_in_list(&list_fake, NULL, i))
		    {
		      SH_MUTEX_LOCK(mutex_thread_nolog);
		      sh_error_handle(sh_prochk_severity, FIL__, __LINE__, 0, 
				      MSG_PCK_FAKE, 
				      (unsigned long) i, tests);
		      SH_MUTEX_UNLOCK(mutex_thread_nolog);
		    }
		}
	    }
	}
    } /* loop end */

  check_watchlist (res);

  SL_RETURN (0, _("sh_process_check_int"));
}

/* Initialise. 
 */
static int sh_prochk_init_internal(void) 
{
  SL_ENTER(_("sh_prochk_init"));

  (void) proc_max_pid (&sh_prochk_maxpid);

  if (sh_prochk_minpid > sh_prochk_maxpid)
    ShProchkActive = S_FALSE;

  /* We need to free anything allocated by the configuration functions if
   * we find that the module is to be left inactive - otherwise _reconf()
   * won't quite work. 
   */
  if( ShProchkActive == S_FALSE ) 
    {
      sh_prochk_free_list(process_check);
      process_check = NULL;
      SL_RETURN(-1, _("sh_prochk_init"));
    }

  sh_prochk_size = sh_prochk_maxpid - sh_prochk_minpid;

  if (sh_prochk_res == NULL)
    {
      sh_prochk_res  = SH_ALLOC(sizeof(short) * sh_prochk_size);
    }
  memset (sh_prochk_res, 0, sizeof(short) * sh_prochk_size);
  
  SL_RETURN(0, _("sh_prochk_init"));
}

int sh_prochk_init (struct mod_type * arg)
{
#ifndef HAVE_PTHREAD
  (void) arg;
#endif

  if (ShProchkActive == S_FALSE)
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
      sh_prochk_init_internal();
      return SH_MOD_THREAD;
    }
#endif
  return sh_prochk_init_internal();
}

int sh_prochk_timer(time_t tcurrent) 
{
  static time_t lastcheck = 0;

  SL_ENTER(_("sh_prochk_timer"));
  if ((time_t) (tcurrent - lastcheck) >= sh_prochk_interval)
    {
      lastcheck  = tcurrent;
      SL_RETURN((-1), _("sh_prochk_timer"));
    }
  SL_RETURN(0, _("sh_prochk_timer"));
}

int sh_prochk_check(void) 
{
  int status;

  SL_ENTER(_("sh_prochk_check"));

  SH_MUTEX_LOCK(mutex_proc_check);

  status = 0;

  if( ShProchkActive != S_FALSE )
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_PCK_CHECK, 
		      (unsigned long) sh_prochk_minpid, 
		      (unsigned long) (sh_prochk_maxpid-1));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);

      if (sh_prochk_res) {
	memset (sh_prochk_res, 0, sizeof(short) * sh_prochk_size);
      }
      status = sh_process_check_int(sh_prochk_res);

      if (status != 0)
	ShProchkActive = S_FALSE;

      /* clean out old entries which are not marked 
       * as missing/hidden/fake anymore
       */
      clean_list (&list_missing);
      clean_list (&list_hidden);
      clean_list (&list_fake);
    }

  SH_MUTEX_UNLOCK(mutex_proc_check);

  SL_RETURN(status, _("sh_prochk_check"));
}

/* Free our lists and the associated memory 
 */
int sh_prochk_cleanup(void) 
{
  SL_ENTER(_("sh_prochk_cleanup"));

  sh_prochk_reconf();

  if (list_missing) {
    kill_list(list_missing);
    list_missing = NULL;
  }
  if (list_hidden) {
    kill_list(list_hidden);
    list_hidden  = NULL;
  }
  if (list_fake) {
    kill_list(list_fake);
    list_fake    = NULL;
  }
  
  SL_RETURN(0, _("sh_prochk_cleanup"));
}

/* Free our lists and the associated memory 
 */
int sh_prochk_reconf(void) 
{
  SL_ENTER(_("sh_prochk_reconf"));

  SH_MUTEX_LOCK(mutex_proc_check);
  userdef_maxpid     = 0;
  sh_prochk_maxpid   = 0x8000;
  sh_prochk_minpid   = 0x0001;
  sh_prochk_interval = SH_PROCHK_INTERVAL;
  sh_prochk_openvz   = S_FALSE;
  p_store            = 0;
  openvz_hidden      = 0;

  sh_prochk_free_list(process_check);
  process_check = NULL;
  if (sh_prochk_res != NULL)
    SH_FREE(sh_prochk_res);
  sh_prochk_res = NULL;

  if (sh_prochk_psarg)
    SH_FREE(sh_prochk_psarg);
  sh_prochk_psarg = NULL;
  if (sh_prochk_pspath)
    SH_FREE(sh_prochk_pspath);
  sh_prochk_pspath = NULL;
  SH_MUTEX_UNLOCK(mutex_proc_check);

  SL_RETURN(0, _("sh_prochk_reconf"));
}

/* #if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) */
#endif

/* #ifdef SH_USE_PROCESSCHECK */
#endif


#ifdef SH_CUTEST
#include "CuTest.h"

void Test_processcheck_watchlist_ok (CuTest *tc) {
#if defined(SH_USE_PROCESSCHECK) && (defined(SH_WITH_CLIENT) || defined(SH_STANDALONE))
  CuAssertTrue(tc, 0 == sh_prochk_add_process("init"));
  CuAssertTrue(tc, 
	       S_TRUE  == is_in_watchlist("    1 ?        00:00:00 init", 0));
  CuAssertTrue(tc, 
	       S_FALSE == is_in_watchlist("    1 ?        00:00:00 flix", 0));
  CuAssertTrue(tc, 
	       S_TRUE  == is_in_watchlist("25218 ?        SNs    0:01 /usr/sbin/init -k start -DSSL", 0));
  CuAssertTrue(tc, 
	       S_FALSE  == is_in_watchlist("25218 ?        SNs    0:01 /usr/sbin/apache2 -k start -DSSL", 0));


  sh_prochk_free_list(process_check);
  process_check = NULL;
  CuAssertTrue(tc, S_FALSE == is_in_watchlist("init", 0));

  CuAssertTrue(tc, 0 == sh_prochk_add_process("init"));
  CuAssertTrue(tc, 0 == sh_prochk_add_process("ssh"));
  CuAssertTrue(tc, 0 == sh_prochk_add_process("syslog"));
  CuAssertTrue(tc, S_TRUE  == is_in_watchlist("init", 0));
  CuAssertTrue(tc, S_TRUE  == is_in_watchlist("ssh", 0));
  CuAssertTrue(tc, S_TRUE  == is_in_watchlist("syslog", 0));

  sh_prochk_free_list(process_check);
  process_check = NULL;
  CuAssertTrue(tc, S_FALSE == is_in_watchlist("init", 0));
  CuAssertTrue(tc, S_FALSE == is_in_watchlist("ssh", 0));
  CuAssertTrue(tc, S_FALSE == is_in_watchlist("syslog", 0));
#else
  (void) tc; /* fix compiler warning */
#endif
  return;
}

void Test_processcheck_listhandle_ok (CuTest *tc) {
#if defined(SH_USE_PROCESSCHECK) && (defined(SH_WITH_CLIENT) || defined(SH_STANDALONE))
  CuAssertTrue(tc, S_FALSE == is_in_list(&list_missing, "init", 0));
  CuAssertTrue(tc, S_TRUE  == is_in_list(&list_missing, "init", 0));
  CuAssertTrue(tc, S_FALSE == is_in_list(&list_missing, "foobar", 0));
  CuAssertTrue(tc, S_TRUE  == is_in_list(&list_missing, "foobar", 0));

  if (list_missing)
    kill_list(list_missing);
  list_missing = NULL;

  CuAssertTrue(tc, S_FALSE == is_in_list(&list_missing, "init", 0));
  CuAssertTrue(tc, S_TRUE  == is_in_list(&list_missing, "init", 0));
  CuAssertTrue(tc, S_FALSE == is_in_list(&list_missing, "foobar", 0));
  CuAssertTrue(tc, S_TRUE  == is_in_list(&list_missing, "foobar", 0));

  if (list_missing)
    kill_list(list_missing);
  list_missing = NULL;

  CuAssertTrue(tc, S_FALSE == is_in_list(&list_missing, "init", 0));
  CuAssertTrue(tc, S_TRUE  == is_in_list(&list_missing, "init", 0));
  CuAssertTrue(tc, S_FALSE == is_in_list(&list_missing, "foobar", 0));
  CuAssertTrue(tc, S_TRUE  == is_in_list(&list_missing, "foobar", 0));

  CuAssertTrue(tc, 2  == clean_list(&list_missing));
  CuAssertPtrNotNull(tc, list_missing);

  CuAssertTrue(tc, S_TRUE  == is_in_list(&list_missing, "init", 0));
  CuAssertTrue(tc, S_TRUE  == is_in_list(&list_missing, "foobar", 0));

  CuAssertTrue(tc, 2  == clean_list(&list_missing));
  CuAssertPtrNotNull(tc, list_missing);

  CuAssertTrue(tc, 0  == clean_list(&list_missing));
  CuAssertTrue(tc, NULL == list_missing);
#else
  (void) tc; /* fix compiler warning */
#endif
  return;
}


/* #ifdef SH_CUTEST */
#endif

