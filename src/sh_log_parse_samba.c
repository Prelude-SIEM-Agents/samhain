/**************************************
 **
 ** PARSER RULES
 **
 ** (a) must set record->host 
 **     (eventually to dummy value)
 **
 ** (b) must set record->prefix
 **     (command) 
 **
 **
 **************************************/

/* for strptime */
#define _XOPEN_SOURCE

#include "config_xor.h"
#include <string.h>

#if defined(HOST_IS_SOLARIS)
/* For 'struct timeval' in <sys/time.h> */
#define __EXTENSIONS__
#endif

#include <time.h>

#if defined(USE_LOGFILE_MONITOR)

#include "samhain.h"
#include "sh_pthread.h"
#include "sh_log_check.h"
#include "sh_string.h"

#undef  FIL__
#define FIL__  _("sh_log_parse_samba.c")


sh_string * sh_read_samba (sh_string * record, struct sh_logfile * logfile)
{
  return sh_cont_reader (record, logfile, " \t");
}

struct sh_logrecord * sh_parse_samba (sh_string * logline, void * fileinfo)
{
  static struct tm old_tm;
  static time_t    old_time;

  struct sh_logrecord * record = NULL;

  static const char *    format0_1 = N_("[%Y/%m/%d %T");
  static char   format_1[16]; 
  static int    format_init = 0;

  (void) fileinfo;

  if (!format_init)
    {
      sl_strlcpy(format_1, _(format0_1), sizeof(format_1));
      format_init = 1;
    }

  if (logline && sh_string_len(logline) > 0)
    {
      size_t lengths[3];
      unsigned int  fields = 3;
      char ** array;
      char * p = strchr(sh_string_str(logline), ',');

      *p = '\0'; ++p;
      array = split_array_ws(p, &fields, lengths);

      if (fields == 3)
	{
	  struct tm btime;
	  char * ptr;

	  memset(&btime, '\0', sizeof(struct tm));
	  btime.tm_isdst = -1;

	  ptr = strptime(sh_string_str(logline), format_1, &btime);

	  if (ptr && *ptr == '\0') /* no error, whole string consumed */
	    {
	      record = SH_ALLOC(sizeof(struct sh_logrecord));

	      record->timestamp = conv_timestamp(&btime, &old_tm, &old_time);

	      p = sh_string_str(logline); ++p;
	  
	      record->timestr   = sh_string_new_from_lchar(p, strlen(p));
	      
	      record->message   = sh_string_new_from_lchar(array[2], lengths[2]);
	  
	      record->pid       = 0;
	      record->host      = sh_string_new_from_lchar(sh.host.name, 
							   strlen(sh.host.name));
	    }
	}
      SH_FREE(array);
    }
  return record;
}

#endif
