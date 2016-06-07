/**************************************
 **
 ** PARSER RULES
 **
 ** (a) must set record->host 
 **     (eventually to dummy value)
 **
 ** (b) must set record->prefix
 **     (itoa(status)) 
 **
 **
 **************************************/

/* for strptime */
#define _XOPEN_SOURCE 500

#include "config_xor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#ifdef USE_LOGFILE_MONITOR

#undef  FIL__
#define FIL__  _("sh_log_parse_apache.c")

/* Debian/Ubuntu: libpcre3-dev */
#ifdef HAVE_PCRE_PCRE_H
#include <pcre/pcre.h>
#else
#include <pcre.h>
#endif

#include "samhain.h"
#include "sh_pthread.h"
#include "sh_log_check.h"
#include "sh_utils.h"
#include "sh_string.h"

extern int flag_err_debug;

struct sh_fileinfo_apache {
  pcre * line_regex;
  int  * line_ovector;         /* captured substrings     */
  int    line_ovecnum;         /* how many captured       */
  
  int    pos_host;
  int    pos_status;
  int    pos_time;
  char * format_time;
};

static const char lf_error0[]    = N_("%error");
static const char lf_common0[]   = N_("%h %l %u %t \"%r\" %>s %b");
static const char lf_combined0[] = N_("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"");

/* This variable is not used anywhere. It only exist
 * to assign &new to them, which keeps gcc from
 * putting it into a register, and avoids the 'clobbered
 * by longjmp' warning. And no, 'volatile' proved insufficient.
 */
void * sh_dummy_65_new = NULL;
void * sh_dummy_66_fti = NULL;
void * sh_dummy_67_ftr = NULL;

void * sh_eval_fileinfo_apache(char * str)
{
  struct sh_fileinfo_apache * result = NULL;
  unsigned int i, quotes;
  unsigned int nfields = 64;
  size_t       lengths[64];
  char *       new = NULL;
  char **      splits;
  char *       token;
  sh_string  * re_string;
  char *       p;
  volatile int          p_host = -1;
  volatile int          p_status = -1;
  volatile int          p_time = -1;
  char                * f_time = NULL;
  const char * error;
  int          erroffset;
  
  /* Take the address to keep gcc from putting them into registers. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_65_new = (void*) &new;
  sh_dummy_66_fti = (void*) &f_time;
  sh_dummy_67_ftr = (void*) &result;

  if (0 == strncmp("common", str, 6))
    {
      new    = sh_util_strdup(_(lf_common0));
    }
  else if (0 == strncmp("combined", str, 8))
    {
      new    = sh_util_strdup(_(lf_combined0));
    }
  else if (0 == strncmp("error", str, 8))
    {
      new    = sh_util_strdup(_(lf_error0));
    }
  else
    {
      new    = sh_util_strdup(str);
    }

  if (flag_err_debug == S_TRUE)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      new,
		      _("eval_fileinfo"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }

  splits = split_array_ws(new, &nfields, lengths);

  if (nfields < 1)
    {
      SH_FREE(splits);
      SH_FREE(new);
      return NULL;
    }

  /* Build the regex string re_string
   */
  re_string =  sh_string_new(0);
  sh_string_add_from_char(re_string, "^");

  for (i = 0; i < nfields; ++i)
    {

      if (i > 0)
	sh_string_add_from_char(re_string, " ");

      if (splits[i][0] != '"')
	quotes = 0;
      else
	quotes = 1;

      if (quotes && lengths[i] > 1 && splits[i][lengths[i]-1] == '"')
	{
	  splits[i][lengths[i]-1] = '\0'; /* cut trailing quote */
	  token = &(splits[i][1]);
	} else {
	  token = splits[i];
	}

      if(quotes)
	{
	  if(strcmp(token, "%r") == 0 || 
	     strstr(token, _("{Referer}")) != NULL || 
             strstr(token, _("{User-Agent}")) != NULL ||
	     strstr(token, _("{X-Forwarded-For}")) != NULL )
	    {
	      /*
	      p = "\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"";
	      sh_string_add_from_char(re_string, p);
	      */
	      sh_string_add_from_char(re_string, "\"([^");
	      sh_string_add_from_char(re_string, "\"\\\\");
	      sh_string_add_from_char(re_string, "]*");
	      sh_string_add_from_char(re_string, "(?:");
	      sh_string_add_from_char(re_string, "\\\\.");
	      sh_string_add_from_char(re_string, "[^\"");
	      sh_string_add_from_char(re_string, "\\\\]*");
	      sh_string_add_from_char(re_string, ")*)\"");
	    }    
	  else
	    {
	      sh_string_add_from_char(re_string, "(");
	      sh_string_add_from_char(re_string, "\\S+");
	      sh_string_add_from_char(re_string, ")");
	    }
	}
      else if (token[0] == 'R' && token[1] == 'E' && token[2] == '{' && token[strlen(token)-1] == '}') 
	{
	  char * lb =  strchr(token, '{');
	  char * rb = strrchr(token, '}');

	  if (lb && rb)
	    {
	      ++lb; *rb = '\0';
	      sh_string_add_from_char(re_string, lb);
	    }
	}
      else if (token[0] == '%' && token[strlen(token)-1] == 't') 
	{
	  char * lb = strchr(token, '{');
	  char * rb = strchr(token, '}');

	  sh_string_add_from_char(re_string, "\\[");
	  sh_string_add_from_char(re_string, "([^");
	  sh_string_add_from_char(re_string, "(\\]");
	  sh_string_add_from_char(re_string, "]+)");
	  sh_string_add_from_char(re_string, "\\]");

	  p_time = i+1;
	  if (lb && rb)
	    {
	      ++lb; *rb = '\0';
	      f_time = sh_util_strdup(lb);
	    }
	  else
	    {
	      f_time = sh_util_strdup(_("%d/%b/%Y:%T"));
	    }
	}
      else if (token[0] == '%' && token[1] == 'e' && 0 == strcmp(token, _("%error"))) 
	{
	  sh_string_add_from_char(re_string, "\\[");
	  sh_string_add_from_char(re_string, "([^");
	  sh_string_add_from_char(re_string, "]");
	  sh_string_add_from_char(re_string, "]+)");
	  sh_string_add_from_char(re_string, "\\]");

	  p_time = i+1; f_time = sh_util_strdup(_("%a %b %d %T %Y")); ++i;
	  sh_string_add_from_char(re_string, " ");

	  sh_string_add_from_char(re_string, "\\[");
	  sh_string_add_from_char(re_string, "([^");
	  sh_string_add_from_char(re_string, "]");
	  sh_string_add_from_char(re_string, "]+)");
	  sh_string_add_from_char(re_string, "\\]");

	  p_status = i+1;
	  sh_string_add_from_char(re_string, " ");

	  p = "(.+)";
	  sh_string_add_from_char(re_string, p);

	  nfields = 3;

	  break;
	}
      else
	{
	  sh_string_add_from_char(re_string, "(");
	  sh_string_add_from_char(re_string, "\\S+");
	  sh_string_add_from_char(re_string, ")");
	  if (token[0] == '%' && token[strlen(token)-1] == 's')
	    p_status = i+1;
	  else if (token[0] == '%' && token[strlen(token)-1] == 'v')
	    p_host = i+1;
	}
    }
  sh_string_add_from_char(re_string, "$");

  if (flag_err_debug == S_TRUE)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      sh_string_str(re_string),
		      _("eval_fileinfo"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }

  result = SH_ALLOC(sizeof(struct sh_fileinfo_apache));
  result->line_regex = pcre_compile(sh_string_str(re_string), 0, 
				    &error, &erroffset, NULL);
  if (!(result->line_regex))
    {
      sh_string * msg =  sh_string_new(0);
      sh_string_add_from_char(msg, _("Bad regex: "));
      sh_string_add_from_char(msg, sh_string_str(re_string));
      
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      sh_string_str(msg),
		      _("eval_fileinfo"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);

      SH_FREE(result);
      SH_FREE(splits);
      SH_FREE(new);   
      sh_string_destroy(&msg);
      sh_string_destroy(&re_string);

      return NULL;
    }
  sh_string_destroy(&re_string);

  result->line_ovector  = SH_ALLOC(sizeof(int) * (nfields+1) * 3);
  result->line_ovecnum  = nfields;
  result->pos_host      = p_host;
  result->pos_status    = p_status;
  result->pos_time      = p_time;
  result->format_time   = f_time;

  SH_FREE(splits);
  SH_FREE(new);
  return (void*)result;
}

struct sh_logrecord * sh_parse_apache (sh_string * logline, void * fileinfo)
{
  static struct tm old_tm;
  static time_t    old_time;

  char         tstr[128];
  char         sstr[128];
  const char * hstr;
  int          res;
  const char **hstr_addr = (const char **) &hstr;

  struct sh_fileinfo_apache * info = (struct sh_fileinfo_apache *) fileinfo;

  if (sh_string_len(logline) > 0 && flag_err_debug == S_TRUE)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      sh_string_str(logline),
		      _("sh_parse_apache"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }

  if (logline == NULL || info == NULL)
    {
      return NULL;
    }

  res = pcre_exec(info->line_regex, NULL, 
		  sh_string_str(logline), (int)sh_string_len(logline), 0,
		  0, info->line_ovector, (3*(1+info->line_ovecnum)));

  if (res == (1+info->line_ovecnum))
    {
      struct sh_logrecord * record;
      time_t timestamp = 0;

      if (info->pos_time > 0)
	{
	  res = pcre_copy_substring(sh_string_str(logline), 
				    info->line_ovector, res,
				    info->pos_time, tstr, sizeof(tstr));
	  if (res <= 0)
	    goto corrupt;
	}
      else
	{
	  res = 0;
	  timestamp = 0;
	  info->format_time = sh_util_strdup(_("%d/%b/%Y:%T"));
	  sl_strlcpy(tstr, _("01/Jan/1970:00:00:00"), sizeof(tstr));
	}

      if (res > 0)
	{
	  struct tm btime;
	  char * ptr = NULL;

	  memset(&btime, '\0', sizeof(struct tm));
	  btime.tm_isdst = -1;
	  
	  /* example: 01/Jun/2008:07:55:28 +0200 */

	  ptr = /*@i@*/strptime(tstr, info->format_time, &btime);

	  if (ptr)
	    {
	      timestamp = conv_timestamp(&btime, &old_tm, &old_time);
	    }
	  else
	    goto corrupt;
	}

      if (info->pos_status > 0)
	{
	  res = pcre_copy_substring(sh_string_str(logline), 
				    info->line_ovector, res,
				    info->pos_status, sstr, sizeof(sstr));
	  if (res <= 0)
	    goto corrupt;
	}
      else
	{
	  sl_strlcpy(sstr, _("000"), sizeof(sstr));
	}

      if (info->pos_host > 0)
	{
	  res = pcre_get_substring(sh_string_str(logline), 
				   info->line_ovector, res,
				   info->pos_host, hstr_addr);
	  if (res <= 0)
	    goto corrupt;
	}
      else
	{
	  hstr = NULL;
	}

      record = SH_ALLOC(sizeof(struct sh_logrecord));
      
      record->timestamp = timestamp;
      record->timestr   = sh_string_new_from_lchar(tstr, strlen(tstr));

      if (hstr)
	record->host = sh_string_new_from_lchar(hstr, strlen(hstr));
      else
	record->host = sh_string_new_from_lchar(sh.host.name, strlen(sh.host.name));

      record->message   = sh_string_new_from_lchar(sh_string_str(logline), 
						   sh_string_len(logline));
      record->pid       = PID_INVALID;

      pcre_free_substring(hstr); 
      return record;
    }
  else
    {
      char msg[128];
      sl_snprintf(msg, sizeof(msg), _("Incorrect number of captured subexpressions: %d vs %d"),
		  res, info->line_ovecnum);
      
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      msg,
		      _("sh_parse_apache"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }

  /* Corrupted logline */
 corrupt:

  {
    sh_string * msg =  sh_string_new(0);
    sh_string_add_from_char(msg, _("Corrupt logline: "));
    sh_string_add_from_char(msg, sh_string_str(logline));
    
    SH_MUTEX_LOCK(mutex_thread_nolog);
    sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		    sh_string_str(msg),
		    _("sh_parse_apache"));
    SH_MUTEX_UNLOCK(mutex_thread_nolog);
    sh_string_destroy(&msg);
  }
  return NULL;
}

/* USE_LOGFILE_MONITOR */
#endif
