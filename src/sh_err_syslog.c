/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2000 Rainer Wichmann                                      */
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

#include <syslog.h>
#include <stdio.h>
#include <string.h>

#include "samhain.h"
#include "sh_error.h"

#undef  FIL__
#define FIL__  _("sh_err_syslog.c")

typedef struct log_fac_struct {
  const char * name;
  int    facility;
} logfct;

static logfct fct_tab[] = {
#ifdef LOG_AUTH
  { N_("LOG_AUTH"),     LOG_AUTH     },
#endif
#ifdef LOG_AUTHPRIV
  { N_("LOG_AUTHPRIV"), LOG_AUTHPRIV },
#endif
#ifdef LOG_CRON
  { N_("LOG_CRON"),     LOG_CRON     },
#endif
#ifdef LOG_DAEMON
  { N_("LOG_DAEMON"),   LOG_DAEMON   },
#endif
#ifdef LOG_FTP
  { N_("LOG_FTP"),      LOG_FTP      },
#endif
#ifdef LOG_KERN
  { N_("LOG_KERN"),     LOG_KERN     },
#endif
#ifdef LOG_LOCAL0
  { N_("LOG_LOCAL0"),   LOG_LOCAL0   },
#endif
#ifdef LOG_LOCAL1
  { N_("LOG_LOCAL1"),   LOG_LOCAL1   },
#endif
#ifdef LOG_LOCAL2
  { N_("LOG_LOCAL2"),   LOG_LOCAL2   },
#endif
#ifdef LOG_LOCAL3
  { N_("LOG_LOCAL3"),   LOG_LOCAL3   },
#endif
#ifdef LOG_LOCAL4
  { N_("LOG_LOCAL4"),   LOG_LOCAL4   },
#endif
#ifdef LOG_LOCAL5
  { N_("LOG_LOCAL5"),   LOG_LOCAL5   },
#endif
#ifdef LOG_LOCAL6
  { N_("LOG_LOCAL6"),   LOG_LOCAL6   },
#endif
#ifdef LOG_LOCAL7
  { N_("LOG_LOCAL7"),   LOG_LOCAL7   },
#endif
#ifdef LOG_LPR
  { N_("LOG_LPR"),      LOG_LPR      },
#endif
#ifdef LOG_MAIL
  { N_("LOG_MAIL"),     LOG_MAIL     },
#endif
#ifdef LOG_NEWS
  { N_("LOG_NEWS"),     LOG_NEWS     },
#endif
#ifdef LOG_SYSLOG
  { N_("LOG_SYSLOG"),   LOG_SYSLOG   },
#endif
#ifdef LOG_USER
  { N_("LOG_USER"),     LOG_USER     },
#endif
#ifdef LOG_UUCP
  { N_("LOG_UUCP"),     LOG_UUCP     },
#endif
  { NULL,               -1           }
};

#ifdef LOG_AUTHPRIV
static int my_syslog_facility = LOG_AUTHPRIV;
#else
/*@-unrecog@*/
static int my_syslog_facility = LOG_AUTH;
/*@+unrecog@*/
#endif


/* set syslog facility 
 */
int  sh_log_set_facility (const char * c)
{
  int loop = 0; 
  SL_ENTER(_("sh_log_set_facility"));

  if (c == NULL)
    SL_RETURN(-1, _("sh_log_set_facility"));

  while (fct_tab[loop].name != NULL)
    {
      if (0 == strcmp ( _(fct_tab[loop].name), c))
	{
	  my_syslog_facility = fct_tab[loop].facility;
	  SL_RETURN(0, _("sh_log_set_facility"));
	}
      ++loop;
    }

  SL_RETURN(-1, _("sh_log_set_facility"));
}
  
static int sh_stamp_priority = LOG_ERR;

/* set priority for heartbeat messages
 */
int  sh_log_set_stamp_priority (const char * c)
{
  int retval = 0;

  if      (0 == strcmp(c, _("LOG_DEBUG")))   { sh_stamp_priority = LOG_DEBUG; }
  else if (0 == strcmp(c, _("LOG_INFO")))    { sh_stamp_priority = LOG_INFO;  }
  else if (0 == strcmp(c, _("LOG_NOTICE")))  { sh_stamp_priority = LOG_NOTICE;}
  else if (0 == strcmp(c, _("LOG_WARNING"))) { sh_stamp_priority = LOG_WARNING;}
  else if (0 == strcmp(c, _("LOG_ERR")))     { sh_stamp_priority = LOG_ERR;   }
  else if (0 == strcmp(c, _("LOG_CRIT")))    { sh_stamp_priority = LOG_CRIT;  }
  else if (0 == strcmp(c, _("LOG_ALERT")))   { sh_stamp_priority = LOG_ALERT; }
#ifdef LOG_EMERG
  else if (0 == strcmp(c, _("LOG_EMERG")))   { sh_stamp_priority = LOG_EMERG; }
#endif
  else { retval = -1; }

  return retval;
}  

/* syslog error message
 */
int  sh_log_syslog (int  severity, /*@null@*/char *errmsg)
{
  int    priority;
  size_t len;
  size_t i;
  char   store;
  char * p;
  
  static int init = 0;

  SL_ENTER(_("sh_log_syslog"));

  ASSERT_RET((errmsg != NULL), _("errmsg != NULL"), 0);

  /*@-unrecog@*/
  if      (severity == SH_ERR_ALL)    priority = LOG_DEBUG;
  else if (severity == SH_ERR_INFO)   priority = LOG_INFO;
  else if (severity == SH_ERR_NOTICE) priority = LOG_NOTICE;
  else if (severity == SH_ERR_WARN)   priority = LOG_WARNING;
  else if (severity == SH_ERR_STAMP)  priority = sh_stamp_priority;
  else if (severity == SH_ERR_ERR)    priority = LOG_ERR;
  else if (severity == SH_ERR_SEVERE) priority = LOG_CRIT;
  else if (severity == SH_ERR_FATAL)  priority = LOG_ALERT;
  else priority = LOG_DEBUG;
  /*@+unrecog@*/

#ifndef LOG_PID
#define LOG_PID 0
#endif

  if (init == 0)
    {
      /*@-unrecog@*/
      openlog (sh.prg_name, LOG_PID, my_syslog_facility);
      /*@+unrecog@*/
      init = 1;
    }

  /* --- Limit the message size. ---
   */
  len = sl_strlen(errmsg);
  if (len < 960)
    {
      /*@-unrecog@*/
      syslog (priority, "%s", errmsg);
      /*@+unrecog@*/
    }
  else
    {
      i         = 960;
      p         = errmsg;

      while (i < len)
	{
	  store     = errmsg[i];
	  errmsg[i] = '\0';
	  /*@-unrecog@*/
	  syslog (priority, "%s", p);
	  /*@+unrecog@*/
	  errmsg[i] = store;
	  p         = &errmsg[i];
	  i        += 960;
	}
      if (i != len)
	{
	  /*@-unrecog@*/
	  syslog (priority, "%s", p);
	  /*@+unrecog@*/
	}
    }

  /* Solaris does not recover if a closeall() closes the
   * syslog file descriptor, so close it here.
   */
  /*@-unrecog@*/
  closelog();
  /*@+unrecog@*/
  init = 0;
  SL_RETURN(0, _("sh_log_syslog"));
}



