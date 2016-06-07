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

/* Required on Linux to get the correct strerror_r function. Also
 * for recursive mutexes (_XOPEN_SOURCE >= 500). Gives funny error
 * on Solaris 10/gcc ('c99' compiler required - huh? Isn't gcc 
 * good enough?).
 */
#if !defined(__sun__) && !defined(__sun)
#define _XOPEN_SOURCE 600
#undef  _GNU_SOURCE
#endif
#include <string.h>
#include <stdio.h>     
#include <stdlib.h>     
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>

/* Required on FreeBSD
 */
#include <sys/types.h>

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
#include <sys/mman.h>
#endif



#include "samhain.h"

#include "sh_cat.h"
#include "sh_database.h"
#include "sh_error.h"
#include "sh_utils.h"
#include "sh_unix.h"
#include "sh_tiger.h"
#include "sh_nmail.h"
#include "sh_xfer.h"
#include "sh_prelude.h"
#include "sh_pthread.h"

#if defined(WITH_DATABASE)
#include "sh_tools.h"
#endif

#if defined(WITH_EXTERNAL)
#include "sh_extern.h"
#endif

#undef  FIL__
#define FIL__  _("sh_error.c")
/*@-noret -compmempass@*/
extern int clt_class;

int flag_err_debug = S_FALSE;
int flag_err_info  = S_FALSE;

int  ShDFLevel[SH_ERR_T_END];

typedef struct _log_t {
  char file[SH_PATHBUF];
  char format[SH_PATHBUF];
  /*@null@*/char * msg;
  size_t  msg_len;
  int  severity;
  int  class;
  int  pid;
  long status;
  long line;
  char timestamp[TIM_MAX];
} sh_log_t;


struct  _errFlags  errFlags;

static int  sh_error_init (void);

inline
static const char * get_format(unsigned long msg_id, int * priority, 
			       unsigned int * class);

static int sh_error_string (struct _log_t * lmsg, va_list vl);

extern int  sh_log_console (/*@null@*/const char *message);
extern int  sh_log_syslog  (int  severity, /*@null@*/char *message);
extern int  sh_log_file    (/*@null@*/char *message, 
			    /*@null@*/char * inet_peer);
/* convert a string to a numeric priority
 */ 
int sh_error_convert_level (const char * str_s);

static int  IsInitialized = BAD;

/* --- Only log to stderr. --- 
 */
int  OnlyStderr    = S_TRUE; 

/* --- Enable facilities not safe for closeall(). --- 
 */
int  enableUnsafe  = S_FALSE;

/*********************************************
 *  utility functions for verifying entries
 *********************************************/

int sh_error_verify (const char * s)
{
  char * foo;
  char hashbuf[KEYBUF_SIZE];

  if (s[0] == '/')
    {
      foo = sh_tiger_hash_gpg (s, TIGER_FILE, TIGER_NOLIM);
      fprintf (stdout, _("%s\n"),  foo);
      SH_FREE(foo);
    }
  else
    {
      fprintf (stdout, _("string=<%s>, hash=<%s>\n"), 
	       s, sh_tiger_hash (s, TIGER_DATA, 
				 (unsigned long) sl_strlen(s), 
				 hashbuf, sizeof(hashbuf))
	       );
    }
  (void) fflush(stdout);
  _exit (EXIT_SUCCESS);
  /*@i@*/return 0;
}



/*********************************************
 *  end utility functions
 *********************************************/

void sh_error_only_stderr (int flag)
{
  OnlyStderr    = flag;
  return;
}

void sh_error_enable_unsafe (int flag)
{
  enableUnsafe    = flag;
  return;
}

static int dbg_store = 0;
static int dbg_flag  = 0;

static
void compute_flag_err_debug(void)
{
  if ((errFlags.loglevel & SH_ERR_ALL) != 0)
    flag_err_debug = S_TRUE;
  else if ((errFlags.printlevel & SH_ERR_ALL) != 0)
    flag_err_debug = S_TRUE;
  else if ((errFlags.maillevel & SH_ERR_ALL) != 0)
    flag_err_debug = S_TRUE;
  else if ((errFlags.exportlevel & SH_ERR_ALL) != 0)
    flag_err_debug = S_TRUE;
  else if ((errFlags.sysloglevel & SH_ERR_ALL) != 0)
    flag_err_debug = S_TRUE;
  else if ((errFlags.externallevel & SH_ERR_ALL) != 0)
    flag_err_debug = S_TRUE;
  else if ((errFlags.databaselevel & SH_ERR_ALL) != 0)
    flag_err_debug = S_TRUE;
  else if ((errFlags.preludelevel & SH_ERR_ALL) != 0)
    flag_err_debug = S_TRUE;
  else
    flag_err_debug = S_FALSE;
  return;
}

static
void compute_flag_err_info(void)
{
  if ((errFlags.loglevel & SH_ERR_INFO) != 0)
    flag_err_info = S_TRUE;
  else if ((errFlags.printlevel & SH_ERR_INFO) != 0)
    flag_err_info = S_TRUE;
  else if ((errFlags.maillevel & SH_ERR_INFO) != 0)
    flag_err_info = S_TRUE;
  else if ((errFlags.exportlevel & SH_ERR_INFO) != 0)
    flag_err_info = S_TRUE;
  else if ((errFlags.sysloglevel & SH_ERR_INFO) != 0)
    flag_err_info = S_TRUE;
  else if ((errFlags.externallevel & SH_ERR_INFO) != 0)
    flag_err_info = S_TRUE;
  else if ((errFlags.databaselevel & SH_ERR_INFO) != 0)
    flag_err_info = S_TRUE;
  else if ((errFlags.preludelevel & SH_ERR_INFO) != 0)
    flag_err_info = S_TRUE;
  else
    flag_err_info = S_FALSE;
  return;
}

void sh_error_dbg_switch(void)
{
  if (dbg_flag == 0)
    {
      dbg_store           = errFlags.printlevel;
      errFlags.printlevel = (SH_ERR_ALL    | SH_ERR_INFO  | SH_ERR_NOTICE | 
			     SH_ERR_WARN   | SH_ERR_STAMP | SH_ERR_ERR    | 
			     SH_ERR_SEVERE | SH_ERR_FATAL);
      dbg_flag  = 1;
      flag_err_debug = S_TRUE;
    }
  else {
    errFlags.printlevel = dbg_store;
    dbg_store = 0;
    dbg_flag  = 0;
    compute_flag_err_debug();
  }
  return;
}

static int sh_error_set_classmask (const char * str, int * facility_mask)
{
  char * p;
  int    num = 0;
  unsigned int    i;
  size_t len;
  char * c;

  SL_ENTER(_("sh_error_set_classmask"));
  
  if (str == NULL)
    SL_RETURN( -1, _("sh_error_set_classmask"));

  if (IsInitialized == BAD) 
    (void) sh_error_init();

  if (str[0] == (char) 34)
    ++str;
  len = strlen(str);

  c = SH_ALLOC(len+1);
  sl_strlcpy(c, str, len+1);

  if (c[len-1] == (char) 34)
    c[len-1] = '\0';

  *facility_mask = 0;

  do {
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
    char * saveptr;
    if (num == 0) {
      p = strtok_r (c, " ,\t", &saveptr);
      ++num;
    } else {
      p = strtok_r (NULL, " ,\t", &saveptr);
    }
#else
    if (num == 0) {
      p = strtok (c, " ,\t");
      ++num;
    } else {
      p = strtok (NULL, " ,\t");
    }
#endif

    if (p == NULL)
      break;

    for (i = 0; i < SH_CLA_MAX; ++i)
      {
	if (i < SH_CLA_RAW_MAX) {
	  if (0 == strcmp(p, _(class_cat[i])))
	    *facility_mask |= (1 << i);
	} else {
	  if (0 == strcmp(p, _(class_cat[SH_CLA_RAW_MAX + 0])))
	    *facility_mask |= OTHER_CLA;
	  if (0 == strcmp(p, _(class_cat[SH_CLA_RAW_MAX + 1])))
	    *facility_mask |= RUN_NEW;
	  if (0 == strcmp(p, _(class_cat[SH_CLA_RAW_MAX + 2])))
	    *facility_mask |= FIL_NEW;
	  if (0 == strcmp(p, _(class_cat[SH_CLA_RAW_MAX + 3])))
	    *facility_mask |= ERROR_CLA;
	}	  
      }

  } while (p);

  SH_FREE(c);
  SL_RETURN( 0, _("sh_error_set_classmask"));
}

int sh_error_log_mask (const char * c)
{
  return (sh_error_set_classmask(c, &(errFlags.log_class)));
}
int sh_error_mail_mask (const char * c)
{
  return (sh_error_set_classmask(c, &(errFlags.mail_class)));
}
int sh_error_print_mask (const char * c)
{
  return (sh_error_set_classmask(c, &(errFlags.print_class)));
}
int sh_error_export_mask (const char * c)
{
  return (sh_error_set_classmask(c, &(errFlags.export_class)));
}
int sh_error_syslog_mask (const char * c)
{
  return (sh_error_set_classmask(c, &(errFlags.syslog_class)));
}
int sh_error_external_mask (const char * c)
{
  return (sh_error_set_classmask(c, &(errFlags.external_class)));
}
int sh_error_database_mask (const char * c)
{
  return (sh_error_set_classmask(c, &(errFlags.database_class)));
}
int sh_error_prelude_mask (const char * c)
{
  return (sh_error_set_classmask(c, &(errFlags.prelude_class)));
}
  


char * sh_error_message (int tellme, char * str, size_t len)
{

#if defined(HAVE_STRERROR_R)
  if (len > 0) str[0] = '\0';
  strerror_r(tellme, str, len);
  return str;
#elif defined(HAVE_STRERROR)
  sl_strlcpy(str, strerror(tellme), len);
  return str;
#else

  char *p = NULL;
#ifdef EACCES
    if (tellme == EACCES)  p = _("Permission denied.");
#endif
#ifdef EAGAIN
    if (tellme == EAGAIN)  p = _("Try again.");
#endif
#ifdef EBADF
    if (tellme == EBADF)   p = _("File descriptor in bad state.");
#endif
#ifdef EEXIST
    if (tellme == EEXIST)  p = _("File exists.");
#endif
#ifdef EFAULT
    if (tellme == EFAULT)  p = _("Bad address.");
#endif
#ifdef EINVAL
    if (tellme == EINVAL)  p = _("Invalid argument.");
#endif
#ifdef EISDIR
    if (tellme == EISDIR)  p = _("Is a directory.");
#endif
#ifdef EINTR
    if (tellme == EINTR)   p = _("System call was interrupted.");
#endif
#ifdef EIO
    if (tellme == EIO)     p = _("Low-level I/O error.");
#endif
#ifdef ELOOP
    if (tellme == ELOOP)   p = _("Too many symbolic links encountered.");
#endif
#ifdef EMFILE
    if (tellme == EMFILE)  p = _("Too many open files.");
#endif
#ifdef EMLINK
    if (tellme == EMLINK)  p = _("Too many links.");
#endif
#ifdef ENAMETOOLONG
    if (tellme == ENAMETOOLONG) 
                           p = _("File name too long."); 
#endif
#ifdef ENFILE
    if (tellme == ENFILE)  p = _("File table overflow.");
#endif
#ifdef ENOENT
    if (tellme == ENOENT)  p = _("File does not exist.");
#endif
#ifdef ENOMEM
    if (tellme == ENOMEM)  p = _("Out of memory.");
#endif
#ifdef ENOSPC
    if (tellme == ENOSPC)  p = _("No space on device.");
#endif
#ifdef ENOTDIR
    if (tellme == ENOTDIR) p = _("Not a directory.");
#endif
#ifdef ENOTSOCK
    if (tellme == ENOTSOCK) p = _("Not a socket.");
#endif
#ifdef EOPNOTSUPP
    if (tellme == EOPNOTSUPP) p = _("Socket is not of type SOCK_STREAM.");
#endif
#ifdef EPERM
    if (tellme == EPERM)   p = _("Permission denied.");
#endif
#ifdef EPIPE
    if (tellme == EPIPE)   p = _("No read on pipe.");
#endif
#ifdef EROFS
    if (tellme == EROFS)    p = _("Read-only file system.");
#endif
#ifdef ETXTBSY
    if (tellme == ETXTBSY) p = _("Text file busy.");
#endif
#ifdef EWOULDBLOCK
    if (tellme == EWOULDBLOCK) 
      p = _("No connections on non-blocking socket.");
#endif
#ifdef EXDEV
    if (tellme == EXDEV)    p = _("Not on same file system.");
#endif
    if (!p) p = _("Unknown error");
    sl_strlcpy(str, p, len);
    return str;
#endif /* ifndef HAVE_STRERROR */
}


/* switch off file log
 */
void sh_error_logoff()
{
  errFlags.HaveLog = BAD;
  return;
}

/* switch on file log 
 */
void sh_error_logrestore()
{
  errFlags.HaveLog = GOOD;
  return;
}

/* --- Relate priority levels to literals. ---
 */
typedef struct eef 
{
  const char * str;
  int    val;
} eef_struc;

static eef_struc eef_tab[] =
{
  { N_("none"),    SH_ERR_NOT    },
  { N_("debug"),   SH_ERR_ALL    },
  { N_("info"),    SH_ERR_INFO   },
  { N_("notice"),  SH_ERR_NOTICE },
  { N_("warn"),    SH_ERR_WARN   },
  { N_("mark"),    SH_ERR_STAMP  },
  { N_("err"),     SH_ERR_ERR    },
  { N_("crit"),    SH_ERR_SEVERE },
  { N_("alert"),   SH_ERR_FATAL  },
#if defined(SH_WITH_SERVER)
#define SH_EEF_MAX 10
  { N_("inet"),    SH_ERR_INET   },
#else
#define SH_EEF_MAX 9
#endif
};

int sh_error_convert_level (const char * str_s)
{
  int i;
  int level = (-1);
  
  SL_ENTER(_("sh_error_convert_level"));
  
  if (str_s == NULL)
     SL_RETURN( -1, _("sh_error_convert_level"));

  for (i = 0; i < SH_EEF_MAX; ++i)
    {
      if (0 == sl_strncmp(str_s, _(eef_tab[i].str), 
                          sl_strlen(eef_tab[i].str))) 
	{
	  level = eef_tab[i].val;
	  break;
	}
    }

  SL_RETURN( level, _("sh_error_convert_level"));
}


/* --- Set severity levels. ---
 */
int sh_error_set_iv (int iv, const char *  str_s)
{
  int level = (-1);

  SL_ENTER(_("sh_error_set_iv"));
  
  if (IsInitialized == BAD) 
    (void) sh_error_init();

  level = sh_error_convert_level (str_s);

  if (level == (-1)) 
    {
      sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS,
		       _("severity"), 
		       str_s != NULL ? str_s : _("(NULL)"));
      SL_RETURN (-1, _("sh_error_set_iv"));
    }

  if (iv > SH_ERR_T_START && iv < SH_ERR_T_END) 
    {
      ShDFLevel[iv] =  level;
    } 
  else 
    {
      sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALL, 
		       _("severity"), (long) iv);
      SL_RETURN (-1, _("sh_error_set_iv"));
    }
  SL_RETURN (0, _("sh_error_set_iv"));
}

int sh_error_set_level(const char * str_in, int * facility)
{
  register int  i, j, f = BAD;

  int  old_facility;
  const char * str_s = str_in;

  SL_ENTER(_("sh_error_set_level"));

  if (IsInitialized == BAD) 
    (void) sh_error_init();

  old_facility = *facility;
  *facility    = 0;

 checkstr:

  if (str_s != NULL) 
    {
      if (0 == sl_strncmp(str_s, _(eef_tab[0].str), sl_strlen(eef_tab[0].str)))
	{
	  *facility |= eef_tab[0].val;  /* This is 'none' */
	  for (i = 1; i < SH_EEF_MAX; ++i)
	    *facility &= ~eef_tab[i].val;
	  f = GOOD;
	}
      else if (str_s[0] == '*') /* all */
	{
	  for (i = 1; i < SH_EEF_MAX; ++i)
	    *facility |= eef_tab[i].val;
	  f = GOOD;
	}
      else if (str_s[0] == '=')
	{
	  for (i = 1; i < SH_EEF_MAX; ++i)
	    if (0 == sl_strncmp(&str_s[1], _(eef_tab[i].str), 
				sl_strlen(eef_tab[i].str)))
	      { 
		*facility |= eef_tab[i].val; 
		f = GOOD; 
	      }
	}
      else if (str_s[0] == '!')
	{
	  if (str_s[1] == '*' ||
	      0 == sl_strncmp(&str_s[1], _(eef_tab[1].str), 
			      sl_strlen(eef_tab[1].str)))
	    {
	      *facility |= eef_tab[0].val;  /* This is 'none' */
	      for (i = 1; i < SH_EEF_MAX; ++i)
		*facility &= ~eef_tab[i].val;
	      f = GOOD;
	    }
	  else if (str_s[1] == '=')
	    {
	      for (i = 1; i < SH_EEF_MAX; ++i)
		{
		  if (0 == sl_strncmp(&str_s[2], _(eef_tab[i].str), 
				      sl_strlen(eef_tab[i].str)))
		    { 
		      *facility &= ~eef_tab[i].val;
		      f = GOOD; 
		    }
		}
	    }
	  else
	    {
	      for (i = 1; i < SH_EEF_MAX; ++i)
		{
		  if (0 == sl_strncmp(&str_s[1], _(eef_tab[i].str), 
				      sl_strlen(eef_tab[i].str)))
		    { 
		      for (j = i; j < SH_EEF_MAX; ++j)
			{
			  *facility &= ~eef_tab[j].val;
			}
		      f = GOOD; 
		    }
		}
	    }
	}
      else /* plain severity name */
	{
	  for (i = 1; i < SH_EEF_MAX; ++i)
	    {
	      if (0 == sl_strncmp(str_s, _(eef_tab[i].str), 
				  sl_strlen(eef_tab[i].str))) 
		{
		  for (j = i; j < SH_EEF_MAX; ++j)
		    {
		      *facility |= eef_tab[j].val;
		    }
		  f = GOOD; 
		  break;
		}
	    }
	}
    }

  if (!str_s)
    {
      SL_RETURN ((-1), _("sh_error_set_level"));
    }
  /* skip to end of string
   */
  while (*str_s != '\0' && *str_s != ';' && *str_s != ',' && 
	 *str_s != ' '  && *str_s != '\t')
    ++str_s;

  /* skip seperator
   */
  while ((*str_s != '\0') && 
	 (*str_s == ';' || *str_s == ',' || *str_s == ' '  || *str_s == '\t'))
    ++str_s;

  if (*str_s != '\0')
    {
      f = BAD;
      goto checkstr;
    }

  if (f == BAD) 
    {
      *facility = old_facility; 
      sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS, 
		       _("priority"), str_in);
      SL_RETURN (-1, _("sh_error_set_level"));
    }
  compute_flag_err_debug();
  compute_flag_err_info();
  SL_RETURN (0, _("sh_error_set_level"));
}

#if defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER)
/* set severity for TCP export
 */
int sh_error_setexport(const char *  str_s)
{
  static int reject = 0;
  if (reject == 1)
    return (0);

  if (sh.flag.opts == S_TRUE)  
    reject = 1;

  return (sh_error_set_level(str_s, &errFlags.exportlevel));
}
#endif

/* set severity for printing
 */
extern void dlog_set_active(int flag);

int sh_error_setprint(const char *  str_s)
{
  static int reject = 0;
  int        retval;

  if (reject == 1)
    return (0);

  if (sh.flag.opts == S_TRUE)   
    reject = 1;

  retval = sh_error_set_level(str_s, &errFlags.printlevel);

  if (0 != (errFlags.printlevel & SH_ERR_INFO))
    dlog_set_active(1);
  if (0 != (errFlags.printlevel & SH_ERR_ALL))
    dlog_set_active(2);
  return retval;
}


/* set level for error logging
 */
int sh_error_setlog(const char * str_s)
{
  static int reject = 0;
  if (reject == 1)
    return (0);

  if (sh.flag.opts == S_TRUE)  
    reject = 1;

  return ( sh_error_set_level(str_s, &errFlags.loglevel) );
}


/* set severity for syslog
 */
int sh_error_set_syslog (const char * str_s)
{
  static int reject = 0;
  if (reject == 1)
    return (0);

  if (sh.flag.opts == S_TRUE)  
    reject = 1;

  return (sh_error_set_level(str_s, &errFlags.sysloglevel));
}

#if defined(WITH_EXTERNAL)
/* set severity for external
 */
int sh_error_set_external (const char * str_s)
{
  static int reject = 0;
  if (reject == 1)
    return (0);

  if (sh.flag.opts == S_TRUE)  
    reject = 1;

  return (sh_error_set_level(str_s, &errFlags.externallevel));
}
#endif

#if defined(WITH_DATABASE)
/* set severity for database
 */
int sh_error_set_database (const char * str_s)
{
  static int reject = 0;
  if (reject == 1)
    return (0);

  if (sh.flag.opts == S_TRUE)  
    reject = 1;

  return (sh_error_set_level(str_s, &errFlags.databaselevel));
}
#endif

#if defined(HAVE_LIBPRELUDE)
/* set severity for prelude
 */
int sh_error_set_prelude (const char * str_s)
{
  static int reject = 0;

  if (reject == 1)
    return (0);

  if (sh.flag.opts == S_TRUE)  
    reject = 1;

  return sh_error_set_level(str_s, &errFlags.preludelevel);
}
#endif

/* init or re-init log facilities that need it
 */
void sh_error_fixup(void)
{
#if defined(HAVE_LIBPRELUDE)
  if ((errFlags.preludelevel & SH_ERR_NOT)   == 0)
    sh_prelude_init();
  else
    sh_prelude_stop();
#endif
#ifdef WITH_DATABASE
  sh_database_reset();
#endif
  return;
}

/* to be called from sh_prelude_reset
 */
void sh_error_init_prelude(void)
{
#if defined(HAVE_LIBPRELUDE)
  if ((errFlags.preludelevel & SH_ERR_NOT)   == 0)
    sh_prelude_init();
  else
    sh_prelude_stop();
#endif
  return;
}


/* set severity for mailing
 */
int sh_error_setseverity (const char * str_s)
{
  static int reject = 0;
  if (reject == 1)
    return (0);

  if (sh.flag.opts == S_TRUE)  
    reject = 1;

  return (sh_error_set_level(str_s, &errFlags.maillevel));
}

#ifdef SH_WITH_SERVER
static char inet_peer[SH_MINIBUF] = { '\0' };
#ifdef HAVE_LIBPRELUDE
static char inet_peer_ip[SH_IP_BUF] = { '\0' };

void sh_error_set_peer_ip(const char * str)
{
  if (str == NULL)
    inet_peer_ip[0] = '\0';
  else
    sl_strlcpy(inet_peer_ip, str, sizeof(inet_peer_ip));
}
#endif

void sh_error_set_peer(const char * str)
{
  if (str == NULL)
    inet_peer[0] = '\0';
  else
    sl_strlcpy(inet_peer, str, sizeof(inet_peer));
}
#endif

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
#include "sh_checksum.h"
static char * sh_error_replace(const char * msg)
{
  char * ret   = NULL;

  if (sh_tiger_get_hashtype () == SH_SHA256)
    {
      char * store = NULL;

#ifdef SH_USE_XML
      char c_end  = '"';
      char * str  = _("chksum_old=\"");
      char * str2 = _("chksum_new=\"");
#else
      char c_end  = '>';
      char * str  = _("chksum_old=<");
      char * str2 = _("chksum_new=<");
#endif

      ret = SHA256_ReplaceBaseByHex(msg, str, c_end);

      if (ret) {
	store = ret;
	ret   = SHA256_ReplaceBaseByHex(ret, str2, c_end);
	if (ret)
	  SH_FREE(store);
	else
	  ret = store;
      } else {
	ret   = SHA256_ReplaceBaseByHex(msg, str2, c_end);
      }
    }
  return ret;
}
static void sh_replace_free(char * msg)
{
  if (msg)
    SH_FREE(msg);
  return;
}
#else
static char * sh_error_replace(const char * msg) { (void) msg; return NULL; }
static void sh_replace_free(char * msg) { (void) msg; return; }
#endif

/**********************************************************
 **********************************************************
 *
 * --------  MAIN ERROR HANDLING FUNCTION -----------------
 *
 *
 * this function should be called to report an error
 *
 ********************************************************** 
 **********************************************************/

SH_MUTEX_RECURSIVE(mutex_err_handle);

void sh_error_handle (int sev1, const char * file, long line, 
		      long status, unsigned long msg_id, ...)
{
  va_list         vl;                 /* argument list          */
  struct _log_t * lmsg;

  int    severity;
  unsigned int class;
  const char * fmt;
  volatile int sev = sev1;            /* Avoids the 'clobbered by longjmp' warning. */

  int    flag_inet;

#ifdef SH_WITH_SERVER
  int    class_inet = clt_class;      /* initialize from global */
  char   local_inet_peer[SH_MINIBUF];
#ifdef HAVE_LIBPRELUDE
  char   local_inet_peer_ip[SH_IP_BUF];
#endif    
#endif

#if defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER)
  char   * ex_msg;
#endif
#if defined(WITH_DATABASE)
  char   * escape_msg;
#endif

  char   * hexmsg = NULL;

  static int    own_block = 0;

  /* 
   * Block a facility for errors generated
   * within that facility.
   */
  static int print_block  = 0;
#if defined(SH_WITH_MAIL)
  static int mail_block   = 0;
#endif
  static int syslog_block = 0;
  static int log_block    = 0;
#if defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER)
  static int export_block = 0;
#endif
#if defined(WITH_EXTERNAL)
  static int external_block = 0;
#endif
#if defined(WITH_DATABASE)
  static int database_block = 0;
#endif
#ifdef HAVE_LIBPRELUDE
  static int prelude_block = 0;
#endif

  SL_ENTER(_("sh_error_handle"));

  SH_MUTEX_RECURSIVE_INIT(mutex_err_handle);
  SH_MUTEX_RECURSIVE_LOCK(mutex_err_handle);

#ifdef SH_WITH_SERVER
  /* copy the global string into a local array
   */
  if ((msg_id == MSG_TCP_MSG) && (inet_peer[0] != '\0'))
    {
      sl_strlcpy(local_inet_peer, inet_peer, sizeof(local_inet_peer));
      sh_error_set_peer(NULL);
    }
  else
    local_inet_peer[0] = '\0';

#ifdef HAVE_LIBPRELUDE
  if ((msg_id == MSG_TCP_MSG) && (inet_peer_ip[0] != '\0'))
    {
      sl_strlcpy(local_inet_peer_ip, inet_peer_ip, sizeof(local_inet_peer_ip));
      sh_error_set_peer_ip(NULL);
    }
  else
    local_inet_peer_ip[0] = '\0';
#endif

  clt_class = (-1);      /* reset global */
#endif


  if (own_block == 1)
    {
      goto exit_here;
    }

  /* --- Initialize to default values. ---
   */
  if (IsInitialized == BAD) 
    (void) sh_error_init();

  /* Returns pointer to (constant|thread-specific) static memory
   */
  fmt = /*@i@*/get_format (msg_id, &severity, &class);

#ifdef SH_WITH_SERVER
  if (class_inet != (-1))
    class = (unsigned int) class_inet;
#endif

  /* --- Consistency check. ---
   */
  ASSERT((fmt != NULL), _("fmt != NULL"))
  if (fmt == NULL)
    {
      fprintf(stderr, 
	      _("ERROR: msg=<NULL format>, file=<%s>, line=<%ld>\n"), 
	      file, line);
      goto exit_here;
    }

  /* --- Override the catalogue severity. ---
   */
  if (sev != (-1))
    severity = sev;

  /* --- Some statistics. ---
   */
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)
  if ( ((1 << class) & ERROR_CLA) && 
       (severity & (SH_ERR_ERR|SH_ERR_SEVERE|SH_ERR_FATAL)))
    {
      ++sh.statistics.files_error;
    }
#endif

  /* these are messages from remote sources
   */
  if ((severity  & SH_ERR_INET) != 0)
    {
      flag_inet = S_TRUE;
    }
  else
    {
      flag_inet  = S_FALSE;
    }

  /* --- Messages not wanted for logging. ---
   */
  if ( ( (errFlags.printlevel   & severity    ) == 0 || 
         (errFlags.print_class  & (1 << class)) == 0 )     &&
       ( (errFlags.loglevel     & severity    ) == 0 ||
	 (errFlags.log_class    & (1 << class)) == 0 )     &&
       ( (errFlags.sysloglevel  & severity    ) == 0 || 
	 (errFlags.syslog_class & (1 << class)) == 0 )     &&
#if defined(SH_WITH_CLIENT) || defined(SH_WITH_CLIENT)
       ( (errFlags.exportlevel  & severity    ) == 0 ||
	 (errFlags.export_class & (1 << class)) == 0 )     &&
#endif
#ifdef WITH_EXTERNAL
       ( (errFlags.externallevel  & severity    ) == 0 ||
	 (errFlags.external_class & (1 << class)) == 0 )     &&
#endif
#ifdef HAVE_LIBPRELUDE
       ( (errFlags.preludelevel   & severity    ) == 0 ||
	 (errFlags.prelude_class  & (1 << class)) == 0 )     &&
#endif
#ifdef WITH_DATABASE
       ( (errFlags.databaselevel  & severity    ) == 0 ||
	 (errFlags.database_class & (1 << class)) == 0 )     &&
#endif
       ( (errFlags.maillevel     & severity    ) == 0 ||
	 (errFlags.mail_class    & (1 << class)) == 0 )
#ifdef SH_WITH_SERVER
       && (flag_inet == S_FALSE) /* still log messages from remote sources */
#endif
       )
    {
      goto exit_here;
    }

  if ((severity & SH_ERR_NOT) != 0)
    {
      goto exit_here;
    }
  
#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
  if ((sh_global_check_silent > SH_SILENT_STD) &&
      (((1 << FIL) & (1 << class)) != 0))
    {
      goto exit_here;
    }
#endif

  /* Allocate space for the message.
   */
  own_block = 1;
  lmsg = (struct _log_t *) SH_ALLOC(sizeof(struct _log_t));
  MLOCK( (char *) lmsg, sizeof(struct _log_t));
  /*@i@*/lmsg->msg = NULL;

  /*@i@*/(void) sl_strlcpy(lmsg->format, fmt, SH_PATHBUF);
  (void) sl_strlcpy(lmsg->file, file, SH_PATHBUF);
  lmsg->severity = severity;
  lmsg->class    = (int) class;
  lmsg->line     = line;
  lmsg->status   = status;

  /* Format the log message with timestamp etc.
   * Allocate lmsg->msg
   */
  va_start (vl, msg_id);
  (void) sh_error_string (lmsg, vl);
  va_end (vl);
  own_block = 0;

  hexmsg = sh_error_replace(lmsg->msg);

  /* Log to stderr.
   */
  if ( ((errFlags.printlevel  & severity)     != 0   && 
	(errFlags.print_class & (1 << class)) != 0   &&
	(errFlags.printlevel  & SH_ERR_NOT)   == 0)
#ifdef SH_WITH_SERVER
       || (flag_inet == S_TRUE) 
#endif
       )
    { 
      if (print_block == 0 && (errFlags.printlevel & SH_ERR_NOT) == 0) 
	{
	  /* no truncation
	   */
	  print_block = 1;
	  TPT(( 0, FIL__, __LINE__, lmsg->msg)); 
	  /*
	   *  Reports first error after failure. Always tries.
	   */
	  (void) sh_log_console (hexmsg ? hexmsg : lmsg->msg);
	  print_block = 0;
	}
    }


  /* Full logging enabled.
   */
  if (OnlyStderr == S_FALSE)  /* full error logging enabled */
    {

      /* Log to syslog.
       */
      if ( (errFlags.sysloglevel  & severity)      != 0 &&
	   (errFlags.syslog_class & (1 << class))  != 0 &&
#ifndef INET_SYSLOG
	   (flag_inet != S_TRUE)                        && /* !inet->syslog */
#endif
	   (errFlags.sysloglevel  & SH_ERR_NOT)    == 0 ) 
	{
	  /* will truncate to 1023 bytes 
	   */
	  if (syslog_block == 0)
	    {
	      syslog_block = 1;
	      /*
	       * Ignores errors. Always tries.
	       */
	      (void) sh_log_syslog (lmsg->severity, hexmsg ? hexmsg : lmsg->msg);
	      syslog_block = 0;
	    }
	}

#if defined(WITH_EXTERNAL)
      /* 
       * -- external facility 
       */
      if ((errFlags.externallevel  & severity)     != 0 && 
	  (errFlags.external_class & (1 << class)) != 0 &&
	  (errFlags.externallevel  & SH_ERR_NOT)   == 0 &&
	  class != AUD)
	{
	  if (external_block == 0)
	    {
	      /* no truncation
	       */
	      external_block = 1;
	      /*
	       *  Reports first error after failure. Always tries.
	       */
	      (void) sh_ext_execute ('l', 'o', 'g', hexmsg ? hexmsg : lmsg->msg, 0);
	      external_block = 0;
	    }
	}
#endif

#if defined(WITH_DATABASE)
      /* 
       * -- database facility 
       */
      if ((errFlags.databaselevel  & severity)     != 0 && 
	  (errFlags.database_class & (1 << class)) != 0 &&
	  (errFlags.databaselevel  & SH_ERR_NOT)   == 0 &&
	  class != AUD)
	{
	  if (database_block == 0 && enableUnsafe == S_TRUE)
	    {
	      /* truncates; query_max is 16k
	       */
	      database_block = 1;
#ifndef SH_STANDALONE
	      if (msg_id == MSG_TCP_MSG 
#ifdef INET_SYSLOG
		  || msg_id == MSG_INET_SYSLOG
#endif
		  )
		{
		  /* do not escape twice
		   */
		  /*
		   *  Reports failure every 60 min. Always tries.
		   */
		  (void) sh_database_insert (lmsg->msg);
		}
	      else
#endif
		{
		  escape_msg = sh_tools_safe_name(lmsg->msg, 0);
		  /*
		   *  Reports failure every 60 min. Always tries.
		   */
		  (void) sh_database_insert (escape_msg);
		  SH_FREE(escape_msg);
		}
	      database_block = 0;
	    }
	}
#endif

      /****************************************************
       * Optionally include client code for TCP forwarding
       * to log server
       ****************************************************/
#if defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER)
      /* Export by TCP.
       */

      if ( ((errFlags.exportlevel  & severity  )   != 0 &&
	    (errFlags.export_class & (1 << class)) != 0 &&
	    (errFlags.exportlevel  & SH_ERR_NOT)   == 0 &&
	    class != AUD                               )
#ifdef SH_WITH_SERVER
	   /* always log inet to export */
	   || (flag_inet == S_TRUE && sh.srvexport.name[0] != '\0') 
#endif
          /* sh.flag.isserver != GOOD                    && */
          /* (flag_inet == S_FALSE) */ /* don't log inet to export */
	   )
        {
          if (export_block == 0)
            {
	      int retval;
	      size_t ex_len;

	      /* will truncate to 65280 bytes 
	       */
              export_block = 1;
	      /* ex_len = 64 + sl_strlen(lmsg->msg) + 1; */
	      ex_len = sl_strlen(lmsg->msg);
	      if (sl_ok_adds(ex_len, 65))
		ex_len = 64 + ex_len + 1;
	      ex_msg = SH_ALLOC (ex_len);

	      sl_snprintf(ex_msg, ex_len, _("%d?%u?%s"),
		      severity, class, lmsg->msg);
              retval = sh_xfer_report (ex_msg);
	      SH_FREE(ex_msg);
              export_block = 0;
	      if (retval == -2)
		{
		  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_QUEUE_FULL,
				   _("log server"));
		}
            }
        }
#endif


      /* Log to mail.
       */
#if defined(SH_WITH_MAIL)
      if ((errFlags.maillevel  & severity  )   != 0  &&
	  (errFlags.mail_class & (1 << class)) != 0  &&
	  (errFlags.maillevel  & SH_ERR_NOT)   == 0  &&
	  class != AUD                               &&
	  (flag_inet == S_FALSE) ) /* don't log inet to email */
	{
	  if (mail_block == 0)
	    {
	      int retval; 

	      /* will truncate to 998 bytes 
	       */
	      mail_block = 1;

	      BREAKEXIT(sh_nmail_msg);
	      if ( (severity & SH_ERR_FATAL) == 0) 
		retval = sh_nmail_pushstack (severity, hexmsg ? hexmsg : lmsg->msg, NULL);
	      else 
		retval = sh_nmail_msg (severity, hexmsg ? hexmsg : lmsg->msg, NULL);

	      mail_block = 0;
	      if (retval == -2)
		{
		  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_QUEUE_FULL,
				   _("email"));
		}
	    }
	}
#endif

#ifdef HAVE_LIBPRELUDE
      if (((errFlags.preludelevel  & severity  )   != 0  &&
	   (errFlags.prelude_class & (1 << class)) != 0  &&
	   (errFlags.preludelevel  & SH_ERR_NOT)   == 0  &&
	   (class != AUD)) 
#ifdef SH_WITH_SERVER
	     || (flag_inet == S_TRUE)
#endif
	  )
	{
	  if (prelude_block == 0 && enableUnsafe == S_TRUE)
	    {
	      /* will truncate to 998 bytes 
	       */
	      prelude_block = 1;

	      BREAKEXIT(sh_prelude_alert);
	      /*
	       *  Reports first error after failure. Always tries.
	       */
#if defined(HAVE_LIBPRELUDE) && defined(SH_WITH_SERVER) 
	      (void) sh_prelude_alert (severity, (int) class, 
				       hexmsg ? hexmsg : lmsg->msg, lmsg->status, msg_id, 
				       local_inet_peer_ip);
#else
	      (void) sh_prelude_alert (severity, (int) class, 
				       hexmsg ? hexmsg : lmsg->msg, lmsg->status, msg_id, 
				       NULL);
#endif
	      prelude_block = 0;
	    }
	}
#endif

      /* Log to logfile
       */

      if ( ( (  (errFlags.loglevel  & severity)     != 0 &&
		(errFlags.log_class & (1 << class)) != 0 &&
		(errFlags.loglevel  & SH_ERR_NOT)   == 0 )
#ifdef SH_WITH_SERVER
	     || (flag_inet == S_TRUE)
#endif
	     )                       &&
	   class != AUD              &&
	   (errFlags.HaveLog != BAD) &&  /* temporary switched off */
	   (severity & SH_ERR_NOT) == 0 /* paranoia */
	  ) 
	{
	  if (log_block == 0)
	    {
	      /* no truncation
	       */
	      log_block = 1;
	      BREAKEXIT(sh_log_file);
#ifdef SH_WITH_SERVER
	      if (0 != sl_ret_euid())
		{
		  /*
		   *  Reports first error after failure. Always tries.
		   */
		  if (local_inet_peer[0] == '\0')
		    (void) sh_log_file (lmsg->msg, NULL);
		  else
                    (void) sh_log_file (lmsg->msg, local_inet_peer);
		}
#else
              (void) sh_log_file (hexmsg ? hexmsg : lmsg->msg, NULL);
#endif
	      /* sh_log_file (lmsg->msg); */
	      log_block = 0;
	    }
	}

    }

  /* Cleanup.
   */
  own_block = 1;

  if (lmsg->msg)
    SH_FREE( lmsg->msg );
  sh_replace_free(hexmsg);

  memset ( lmsg, (int) '\0', sizeof(struct _log_t) );
  MUNLOCK( (char *) lmsg,       sizeof(struct _log_t) );
  SH_FREE( lmsg );
  own_block = 0;

 exit_here:
  ; /* label at end of compound statement */
  SH_MUTEX_RECURSIVE_UNLOCK(mutex_err_handle);

  /*@i@*/SL_RET0(_("sh_error_handle"));
/*@i@*/}

#if defined(SH_WITH_MAIL)
void sh_error_mail (const char * alias, int sev, 
		    const char * file, long line, 
		    long status, unsigned long msg_id, ...)
{
  va_list         vl;                 /* argument list          */
  struct _log_t * lmsg;

  int    severity;
  unsigned int class;
  const char * fmt;
  int retval; 

  SL_ENTER(_("sh_error_mail"));

  /* Returns pointer to (constant|thread-specific) static memory
   */
  fmt = /*@i@*/get_format (msg_id, &severity, &class);

  if (!fmt)
    {
      SL_RET0(_("sh_error_mail"));
    }

  /* --- Override the catalogue severity. ---
   */
  if (sev != (-1))
    severity = sev;

  /* --- Build the message. ---
   */
  lmsg = (struct _log_t *) SH_ALLOC(sizeof(struct _log_t));
  MLOCK( (char *) lmsg, sizeof(struct _log_t));
  /*@i@*/lmsg->msg = NULL;

  /*@i@*/(void) sl_strlcpy(lmsg->format, fmt, SH_PATHBUF);
  (void) sl_strlcpy(lmsg->file, file, SH_PATHBUF);
  lmsg->severity = severity;
  lmsg->class    = (int) class;
  lmsg->line     = line;
  lmsg->status   = status;

  /* Format the log message with timestamp etc.
   * Allocate lmsg->msg
   */
  va_start (vl, msg_id);
  (void) sh_error_string (lmsg, vl);
  va_end (vl);

  if ( (severity & SH_ERR_FATAL) == 0) 
    retval = sh_nmail_pushstack (severity, lmsg->msg, alias);
  else 
    retval = sh_nmail_msg (severity, lmsg->msg, alias);
  
  if (retval == -2)
    {
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_QUEUE_FULL,
		       _("email"));
    }
  SL_RET0(_("sh_error_mail"));
}
#else
void sh_error_mail (const char * alias, int sev, 
		    const char * file, long line, 
		    long status, unsigned long msg_id, ...)
{
  (void) alias;
  (void) sev;
  (void) file;
  (void) line;
  (void) status;
  (void) msg_id;

  return;
}
/* defined(SH_WITH_MAIL) */
#endif 

/* -------------------------  
 *
 * private functions below
 *
 * -------------------------
 */


/* --- Get the format from the message catalog. ---
 */
/*@owned@*/ /*@null@*/inline
static const char * get_format(unsigned long msg_id, /*@out@*/ int * priority, 
			 /*@out@*/unsigned int * class)
{
  int i = 0;

  SL_ENTER(_("get_format"));
  while (1 == 1)
    {
      if ( msg_cat[i].format == NULL )
	break;

      if ( (unsigned long) msg_cat[i].id == msg_id)
	{
	  *priority = (int) msg_cat[i].priority;
	  *class    = (unsigned int) msg_cat[i].class;
	  SL_RETURN (((const char *) _(msg_cat[i].format)), _("get_format"));
	}
      ++i;
    }
  *priority = SH_ERR_ERR;
  *class = ERR;
  SL_RETURN (NULL, _("get_format"));
}

/*@null@*//*@only@*/static char * ehead_format = NULL;

/* allocate space for user-defined message header
 */
int sh_error_ehead (/*@null@*/const char * str_s)
{
  size_t size;
  const char * s;

  SL_ENTER(_("sh_error_ehead"));

  if (str_s == NULL)
    {
      SL_RETURN (-1, _("sh_error_ehead"));
    }

  /* ascii 34 ist t\"ttelchen
   */
  /*@i@*/ if (str_s[0] == 34) s = &str_s[1];
  else s = str_s;
  
  size = /*@i@*/strlen(s);
  if (/*@i@*/s[size-1] == (char) 34) --size; /* truncate */

  if (ehead_format != NULL)
    SH_FREE(ehead_format);
  
  /*@i@*/ehead_format = SH_ALLOC(size+1);
  /*@i@*/ (void) sl_strlcpy(ehead_format, s, size+1);

  SL_RETURN( 0, _("sh_error_ehead"));
}

#if !defined(VA_COPY)
#if defined(__GNUC__) && defined(__PPC__) && (defined(_CALL_SYSV) || defined(_WIN32))
#define VA_COPY(ap1, ap2)     (*(ap1) = *(ap2))
#elif defined(VA_COPY_AS_ARRAY)
#define VA_COPY(ap1, ap2)     memmove ((ap1), (ap2), sizeof (va_list))
#else /* va_list is a pointer */
#define VA_COPY(ap1, ap2)     ((ap1) = (ap2))
#endif
#endif 


/* print an error  into string
 */
static int sh_error_string (struct _log_t * lmsg, va_list vl)
{
  size_t len;
  int required;
  unsigned long line;
  char sev[16] = "";
  char cla[16] = "";
  char tst[64] = "";
  char *p;
  va_list       vl2;

  st_format rep_ehead_tab[] = {
    { 'S', S_FMT_STRING,  0, 0, NULL},  /* severity  */
    { 'T', S_FMT_STRING,  0, 0, NULL},  /* timestamp */
    { 'F', S_FMT_STRING,  0, 0, NULL},  /* file      */
    { 'L', S_FMT_ULONG,   0, 0, NULL},  /* line      */
    { 'C', S_FMT_STRING,  0, 0, NULL},  /* class     */
    { 'E', S_FMT_LONG,    0, 0, NULL},  /* status    */
    {'\0', S_FMT_ULONG,   0, 0, NULL},
  };

  SL_ENTER(_("sh_error_string"));

  if (ehead_format == NULL)
    {
      ehead_format = SH_ALLOC(64);
#ifdef SH_USE_XML
      if ((errFlags.printlevel & SH_ERR_ALL) == 0) 
	(void) sl_strlcpy(ehead_format, 
			  _("<log sev=\"%S\" tstamp=\"%T\" "), 64);
      else
	(void) sl_strlcpy(ehead_format, 
			  _("<log sev=\"%S\" tstamp=\"%T\" p.f=\"%F\" p.l=\"%L\" p.s=\"%E\" "), 64);
#else
      if ((errFlags.printlevel & SH_ERR_ALL) == 0) 
	(void) sl_strlcpy(ehead_format, _("%S %T "), 64);
      else
	(void) sl_strlcpy(ehead_format, _("%S %T (%F, %L, %E) "), 64);
#endif
    }

  /* header of error message
   */
#ifdef SH_USE_XML
  if      ( (lmsg->severity & SH_ERR_INET) != 0)
    (void) sl_strlcpy (sev, _("RCVT"), 11);
  else if ( (lmsg->severity & SH_ERR_ALL) != 0)
    (void) sl_strlcpy (sev, _("DEBG"), 11);
  else if ( (lmsg->severity & SH_ERR_INFO) != 0)
    (void) sl_strlcpy (sev, _("INFO"), 11);
  else if ( (lmsg->severity & SH_ERR_NOTICE) != 0)
    (void) sl_strlcpy (sev, _("NOTE"), 11);
  else if ( (lmsg->severity & SH_ERR_WARN) != 0)
    (void) sl_strlcpy (sev, _("WARN"), 11);
  else if ( (lmsg->severity & SH_ERR_STAMP) != 0)
    (void) sl_strlcpy (sev, _("MARK"), 11);
  else if ( (lmsg->severity & SH_ERR_ERR) != 0)
    (void) sl_strlcpy (sev, _("ERRO"), 11);
  else if ( (lmsg->severity & SH_ERR_SEVERE) != 0)
    (void) sl_strlcpy (sev, _("CRIT"), 11);
  else if ( (lmsg->severity & SH_ERR_FATAL) != 0)
    (void) sl_strlcpy (sev, _("ALRT"), 11);
  else {
    (void) sl_strlcpy (sev, _("????"), 11);
#else
#if defined(INET_SYSLOG)
  if      ( (lmsg->severity & SH_ERR_INET) != 0)
    (void) sl_strlcpy (sev, _("<NET>  : "), 11);
#else
  if      ( (lmsg->severity & SH_ERR_INET) != 0)
    (void) sl_strlcpy (sev, _("<TCP>  : "), 11);
#endif
  else if ( (lmsg->severity & SH_ERR_ALL) != 0)
    (void) sl_strlcpy (sev, _("DEBUG  : "), 11);
  else if ( (lmsg->severity & SH_ERR_INFO) != 0)
    (void) sl_strlcpy (sev, _("INFO   : "), 11);
  else if ( (lmsg->severity & SH_ERR_NOTICE) != 0)
    (void) sl_strlcpy (sev, _("NOTICE : "), 11);
  else if ( (lmsg->severity & SH_ERR_WARN) != 0)
    (void) sl_strlcpy (sev, _("WARN   : "), 11);
  else if ( (lmsg->severity & SH_ERR_STAMP) != 0)
    (void) sl_strlcpy (sev, _("MARK   : "), 11);
  else if ( (lmsg->severity & SH_ERR_ERR) != 0)
    (void) sl_strlcpy (sev, _("ERROR  : "), 11);
  else if ( (lmsg->severity & SH_ERR_SEVERE) != 0)
    (void) sl_strlcpy (sev, _("CRIT   : "), 11);
  else if ( (lmsg->severity & SH_ERR_FATAL) != 0)
    (void) sl_strlcpy (sev, _("ALERT  : "), 11);
  else {
    (void) sl_strlcpy (sev, _("???    : "), 11);
#endif
  }

  (void) sh_unix_time (0, tst, 64);
  line = (unsigned long) lmsg->line;
  (void) sl_strlcpy (cla, _(class_cat[lmsg->class]), 11);

  /*@i@*/rep_ehead_tab[0].data_str   = sev;
  /*@i@*/rep_ehead_tab[1].data_str   = tst;
  /*@i@*/rep_ehead_tab[2].data_str   = lmsg->file;
  /*@i@*/rep_ehead_tab[3].data_ulong = line;
  /*@i@*/rep_ehead_tab[4].data_str   = cla;
  /*@i@*/rep_ehead_tab[5].data_long  = lmsg->status;
  
  p = /*@i@*/sh_util_formatted(ehead_format, rep_ehead_tab);

  /* ---  copy the header to lmsg->msg  ---
   */
  /*@i@*/lmsg->msg     = SH_ALLOC(SH_BUFSIZE);
  lmsg->msg_len = SH_BUFSIZE;

  if (p)
    {
      (void) sl_strlcpy (lmsg->msg, p, SH_BUFSIZE);
      SH_FREE(p);
    }
  else
    {
      lmsg->msg[0] = '\0';
    }


  /* --- copy message to lmsg->msg ---
   */
  if ( NULL == strchr(lmsg->format, '%') ) 
    {
      (void) sl_strlcat (lmsg->msg, lmsg->format, (size_t) lmsg->msg_len);
    }
  else 
    {
      /* use VA_COPY */
      /*@i@*/VA_COPY(vl2, vl);
      len      = sl_strlen(lmsg->msg);
      /*@i@*/required = sl_vsnprintf(&(lmsg->msg[len]), 
				     (lmsg->msg_len - len), lmsg->format, vl);

      if ((required >= 0) && 
	  sl_ok_adds(required, len) &&
	  sl_ok_adds((required+len), 4) &&
	  ((required + len) > (lmsg->msg_len - 4)) )
	{
	  /*@i@*/p = SH_ALLOC(required + len + 4);
	  (void) sl_strlcpy (p, lmsg->msg, required + len + 1);
	  SH_FREE(lmsg->msg);
	  lmsg->msg = p;
	  lmsg->msg_len = required + len + 4;
	  (void) sl_vsnprintf(&(lmsg->msg[len]), 
			      (required + 1), lmsg->format, vl2);
	}
      va_end(vl2);
    }

#ifdef SH_USE_XML
  /* closing tag
   */
  if (lmsg->msg[sl_strlen(lmsg->msg)-1] != '>')
    (void) sl_strlcat (lmsg->msg, _(" />"), lmsg->msg_len);
#endif

  SL_RETURN(0, _("sh_error_string"));
}

     


/* --- Initialize. ---
 */
static int  sh_error_init ()
{
  register int j;

  SL_ENTER(_("sh_error_init"));

  errFlags.debug          = 0;
  errFlags.HaveLog        = GOOD;
  errFlags.sysloglevel    = SH_ERR_NOT;
#if defined(SH_STEALTH)
  errFlags.loglevel       = SH_ERR_NOT;
#else
  errFlags.loglevel       = (SH_ERR_STAMP | SH_ERR_ERR    | SH_ERR_SEVERE |
			     SH_ERR_FATAL);
#endif
  errFlags.externallevel  = SH_ERR_NOT;
  errFlags.databaselevel  = SH_ERR_NOT;
  errFlags.preludelevel   = SH_ERR_NOT;
  errFlags.maillevel      = SH_ERR_FATAL;
#if defined(SH_STEALTH)
  errFlags.printlevel     = SH_ERR_NOT;
#else
  errFlags.printlevel     = (SH_ERR_INFO  | SH_ERR_NOTICE | SH_ERR_WARN   | 
			     SH_ERR_STAMP | SH_ERR_ERR    | SH_ERR_SEVERE |
			     SH_ERR_FATAL);
  flag_err_info           = S_TRUE;
#endif

#if defined(SH_WITH_SERVER)
  errFlags.exportlevel    = SH_ERR_NOT;
#else
  errFlags.exportlevel    = (SH_ERR_STAMP | SH_ERR_ERR    | SH_ERR_SEVERE |
			     SH_ERR_FATAL);
#endif

  errFlags.log_class      = 0xFFFF;
  errFlags.print_class    = 0xFFFF;
  errFlags.mail_class     = 0xFFFF;
  errFlags.export_class   = 0xFFFF;
  errFlags.syslog_class   = 0xFFFF;
  errFlags.external_class = 0xFFFF;
  errFlags.database_class = 0xFFFF;
  errFlags.prelude_class  = 0xFFFF;


  for (j = 0; j < SH_ERR_T_END; ++j) 
    ShDFLevel[j] = SH_ERR_SEVERE;

  IsInitialized = GOOD;
  SL_RETURN (0, _("sh_error_init"));
}
