/**************************************
 **
 ** PARSER RULES
 **
 ** (a) must set record->host 
 **     (eventually to dummy value)
 **
 ** (b) must set record->prefix
 **     (eventually to dummy value) 
 **
 **
 **************************************/

/* for strptime */
#define _XOPEN_SOURCE

#include "config_xor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(HOST_IS_SOLARIS)
/* For 'struct timeval' in <sys/time.h> */
#define __EXTENSIONS__
#endif

#include <sys/types.h>
#include <time.h>

#ifdef USE_LOGFILE_MONITOR

#include "samhain.h"
#include "sh_pthread.h"
#include "sh_log_check.h"
#include "sh_utils.h"
#include "sh_string.h"

#undef  FIL__
#define FIL__  _("sh_log_parse_syslog.c")

static int hidepid = 0;
extern int flag_err_debug;

int sh_get_hidepid()
{
  return hidepid;
}

int sh_set_hidepid(const char *s)
{
  return sh_util_flagval(s, &hidepid);
}

struct sh_logrecord * sh_parse_syslog (sh_string * logline, void * fileinfo)
{
  static const char *    format0_1 = N_("%b %d %T");
  static const char *    format0_2 = N_("%Y-%m-%dT%T");

  static char   format_1[16]; 
  static char   format_2[16];
  static int    format_init = 0;

  static struct tm old_tm;
  static time_t    old_time;

  const unsigned int Tpos = 10;
  volatile unsigned int tlen = 16;

  (void) fileinfo;

  if (!format_init)
    {
      sl_strlcpy(format_1, _(format0_1), sizeof(format_1));
      sl_strlcpy(format_2, _(format0_2), sizeof(format_2));
      format_init = 1;
    }


  if (flag_err_debug == S_TRUE && sh_string_len(logline) > 0)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      logline->str,
		      _("sh_parse_syslog"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }

  if (logline && sh_string_len(logline) > tlen)
    {
      struct tm btime;
      char * ptr;
      int    flag;
      size_t lengths[3];

      memset(&btime, '\0', sizeof(struct tm));
      btime.tm_isdst = -1;

      /* This is RFC 3164. 
       */
      if (logline->str[Tpos] != 'T')
	{
	  logline->str[tlen-1] = '\0';
	  ptr = /*@i@*/strptime(logline->str, format_1, &btime);
	}

      /* RFC 3339 describes an alternative timestamp format.
       * Unfortunately, POSIX strptime() does not support reading 
       * the TZ offset.
       */
      else
	{
	  ptr = strptime(logline->str, format_2, &btime);
	  if (ptr)
	    { 
	      tlen = 20;
	      if (*ptr && *ptr != ' ') {
		do { ++ptr; ++tlen; } while (*ptr && *ptr != ' ');
		if (*ptr == ' ') *ptr = '\0'; 
	      }
	    }
	}

      if (ptr && *ptr == '\0') /* no error, whole string consumed */
	{
	  unsigned int  fields = 3; /* host program(\[pid\])+: message */
	  char ** array  = split_array_ws(&(logline->str[tlen]), &fields, lengths);

	  if (fields == 3)
	    {
	      struct sh_logrecord * record = SH_ALLOC(sizeof(struct sh_logrecord));

	      record->timestamp = conv_timestamp(&btime, &old_tm, &old_time);
	      record->timestr   = sh_string_new_from_lchar(logline->str, (tlen-1)); 

	      /* host
	       */
	      record->host = sh_string_new_from_lchar(array[0], lengths[0]);

	      /* program and pid
	       */
	      if (NULL != (ptr = strchr(array[1], '[')))
		{
		  *ptr = '\0';
		  ++ptr;
		  record->pid = (pid_t) atoi(ptr);

		  if (hidepid == 0 || !*ptr) {
		    --ptr;
		    *ptr = '[';
		  } else {
		    *ptr = '\0'; /* overwrite first digit */
		    --ptr;
		    *ptr = ':';  /* overwrite ex-':' */
		    lengths[1] = strlen(array[1]);
		  }
		}
	      else
		{
		  flag = 0;
		  ptr = array[1];
		  if (ptr[lengths[1]] == ':') {
		    ptr[lengths[1]] = '\0';
		    flag = 1;
		  }
		  record->pid = PID_INVALID;
		  if (flag == 1) {
		    ptr[lengths[1]] = ':';
		  }
		}

	      /* message
	       */
	      record->message = sh_string_new_from_lchar3(array[1], lengths[1],
							  " ", 1,
							  array[2], lengths[2]);

	      SH_FREE(array);
	      return record;
	    }
	  SH_FREE(array);
	}
    }
  /* corrupted logline
   */
  return NULL;
}

/* USE_LOGFILE_MONITOR */
#endif
