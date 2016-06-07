#include "config_xor.h"

#ifdef USE_LOGFILE_MONITOR

#undef  FIL__
#define FIL__  _("sh_log_correlate.c")

#include <string.h>
#include <time.h>

/* Debian/Ubuntu: libpcre3-dev */
#ifdef HAVE_PCRE_PCRE_H
#include <pcre/pcre.h>
#else
#include <pcre.h>
#endif

#ifndef PCRE_NO_AUTO_CAPTURE
#define PCRE_NO_AUTO_CAPTURE 0
#endif

#include "samhain.h"
#include "sh_pthread.h"
#include "sh_utils.h"
#include "sh_string.h"
#include "sh_log_check.h"
#include "sh_log_evalrule.h"

extern int flag_err_debug;

/*--------------------------------------------------------------
 *
 *   Event correlation
 *
 *--------------------------------------------------------------*/

/* For each even to be correlated, we keep a label in a list. We
 * then build a string from the (time-sorted) list of labels, and
 * match this string against a regular expression.
 */

/* -- The list of labels kept in memory ----------------------- */

struct sh_keep
{
  sh_string       * label;           /* label of keep rule      */
  unsigned long     delay;           /* valid delay             */
  time_t            last;            /* seen at                 */
  struct sh_keep *  next; 
};

static struct sh_keep * keeplist  = NULL;
static struct sh_keep * keeplast  = NULL;
static unsigned long    keepcount = 0;

static void sh_keep_free(void * item)
{
  struct sh_keep * keep = (struct sh_keep *) item;

  if (!keep)
    return;
  sh_string_destroy(&(keep->label));
  SH_FREE(keep);
}

void sh_keep_destroy()
{
  struct sh_keep * keep;

  while (keeplist)
    {
      keep = keeplist;
      keeplist = keep->next;
      sh_keep_free(keep);
      --keepcount;
    }
  keeplist  = NULL;
  keeplast  = NULL;
  keepcount = 0;
}

int sh_keep_add(sh_string * label, unsigned long delay, time_t last)
{
  struct sh_keep * keep = SH_ALLOC(sizeof(struct sh_keep));

  keep->label = sh_string_copy(label);
  keep->delay = delay;
  keep->last  = last;
  keep->next  = NULL;

  if (keeplast && keeplist)
    {
      keeplast->next = keep;
      keeplast       = keep;
    }
  else
    {
      keeplist = keep;
      keeplast = keeplist;
    }
  ++keepcount;
  return 0;
}

int sh_keep_comp(const void * a, const void * b)
{
  return ( (int)(((const struct sh_keep *)a)->last) - 
	   (int)(((const struct sh_keep *)b)->last) );
}

/* -- Sort the kept labels and build a string ----------------- */

static sh_string * sh_keep_eval()
{
  unsigned long count   = 0;
  sh_string * res       = NULL;
  time_t now            = time(NULL);
  struct sh_keep * keep = keeplist;
  struct sh_keep * prev = keeplist;
  struct sh_keep * arr;

  if (keepcount > 0)
    {
      arr = SH_ALLOC (keepcount * sizeof(struct sh_keep));

      while (count < keepcount && keep)
	{
	  if ((now >= keep->last) && 
	      ((unsigned long)(now - keep->last) <= keep->delay))
	    {
	      memcpy(&(arr[count]), keep, sizeof(struct sh_keep));
	      ++count;
	      prev = keep;
	      keep = keep->next;
	    }
	  else /* Too old or in future, delete it */
	    {
	      if (keep != keeplist)
		{
		  prev->next = keep->next;
		  sh_keep_free(keep);
		  keep = prev->next;
		  --keepcount;
		}
	      else /* list head */
		{
		  keeplist = keep->next;
		  prev     = keeplist;
		  sh_keep_free(keep);
		  keep     = keeplist;
		  --keepcount;
		}
	    }
	}

      if (count > 0)
	{
	  unsigned long i;
	  qsort(arr, count, sizeof(struct sh_keep), sh_keep_comp);
	  res = sh_string_copy(arr[0].label);
	  for (i = 1; i < count; ++i)
	    res = sh_string_add(res, arr[i].label);
	}
      SH_FREE(arr);
    }

  return res;
}

/* -- Match the string against correlation rules -------------- */

struct sh_mkeep
{
  sh_string       * label;           /* label of match rule     */
  pcre            * rule;            /* compiled regex for rule */
  time_t            reported;        /* last reported           */
  struct sh_qeval * queue;           /* assigned queue          */
  struct sh_mkeep * next; 
};

struct sh_mkeep * mkeep_list = NULL;
unsigned long     mkeep_deadtime = 60;

int sh_keep_deadtime (const char * str)
{
  unsigned long  value;
  char * foo;

  value = (size_t) strtoul(str, &foo, 0);

  if (*foo == '\0') {
    mkeep_deadtime = value;
    return 0;
  }
  return -1;
}

int sh_keep_match_add(const char * str, const char * queue, 
		      const char * pattern)
{
  unsigned int nfields = 1; /* seconds:label */
  size_t       lengths[1];
  char *       new    = sh_util_strdup(str);
  char **      splits = split_array_braced(new, _("CORRELATE"), 
					   &nfields, lengths);

  if (nfields == 1 && lengths[0] > 0)
    {
      struct sh_mkeep * mkeep = SH_ALLOC(sizeof(struct sh_mkeep));
      const char * error;
      int          erroffset;
      struct sh_qeval * rqueue = NULL;

      mkeep->rule = pcre_compile(pattern, PCRE_NO_AUTO_CAPTURE, 
			     &error, &erroffset, NULL);
      if (!(mkeep->rule))
	{
	  sh_string * msg =  sh_string_new(0);
	  sh_string_add_from_char(msg, _("Bad regex: "));
	  sh_string_add_from_char(msg, pattern);
	  
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			  sh_string_str(msg),
			  _("sh_keep_match_add"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  sh_string_destroy(&msg);
	  
	  SH_FREE(splits);
	  SH_FREE(mkeep);
	  SH_FREE(new);
	  return -1;
	}

      if (0 != strcmp(queue, _("trash")))
	{

	  rqueue = sh_log_find_queue(queue);
	  if (!rqueue)
	    {
	      pcre_free(mkeep->rule);
	      SH_FREE(splits);
	      SH_FREE(mkeep);
	      SH_FREE(new);
	      return -1;
	    }
	}

      mkeep->queue = rqueue;
      mkeep->label = sh_string_new_from_lchar(splits[0], strlen(splits[0]));
      mkeep->reported = 0;
      mkeep->next  = mkeep_list;
      mkeep_list   = mkeep;
    }
  SH_FREE(new);
  return 0;
}

void sh_keep_match_del()
{
  struct sh_mkeep * mkeep = mkeep_list;
  while (mkeep)
    {
      mkeep_list = mkeep->next;
      sh_string_destroy(&(mkeep->label));
      pcre_free(mkeep->rule);
      mkeep = mkeep_list;
    }
  mkeep_list = NULL;
}

static struct sh_mkeep ** dummy_mkeep;

void sh_keep_match()
{
  if (mkeep_list)
    {
      sh_string       * res = sh_keep_eval();

      if (res)
	{
	  struct sh_mkeep * mkeep = mkeep_list;

	  dummy_mkeep = &mkeep;

	  while (mkeep)
	    {
	      /* Use pcre_dfa_exec() to obtain number of matches. Needs ovector
	       * array, otherwise number of matches is not returned.
	       */
#if defined(HAVE_PCRE_DFA_EXEC)
	      int ovector[SH_MINIBUF];
	      int wspace[SH_MINIBUF];
#endif

#if defined(HAVE_PCRE_DFA_EXEC)
	      int val = pcre_dfa_exec(mkeep->rule, NULL, 
				      sh_string_str(res), 
				      (int)sh_string_len(res), 
				      0, /* start at offset 0 in the subject */
				      0, 
				      ovector, SH_MINIBUF,
				      wspace, SH_MINIBUF);
#else
	      int val = pcre_exec(mkeep->rule, NULL, 
				  sh_string_str(res), 
				  (int)sh_string_len(res), 
				  0, /* start at offset 0 in the subject */
				  0, 
				  NULL, 0);
	      val = (val >= 0) ? 1 : val;			      
#endif

	      if (val >= 0)
		{
		  sh_string * alias;
		  time_t      now = time(NULL);

		  if ((mkeep->reported < now) &&
		      (mkeep_deadtime < (unsigned int)(now - mkeep->reported)))
		    {
		      mkeep->reported = now;

		      SH_MUTEX_LOCK(mutex_thread_nolog);
		      sh_error_handle (mkeep->queue->severity, FIL__, __LINE__, 0, 
				       MSG_LOGMON_COR, sh_string_str(mkeep->label),
				       val);

		      alias = mkeep->queue->alias;
		      if (alias)
			{
			  sh_error_mail (sh_string_str(alias), 
					 mkeep->queue->severity, FIL__, __LINE__, 0, 
					 MSG_LOGMON_COR, sh_string_str(mkeep->label),
					 val);
			}
		      
		      SH_MUTEX_UNLOCK(mutex_thread_nolog);
		    }
		}
	      mkeep = mkeep->next;
	    }
	  sh_string_destroy(&res);
	}
    }
  return;
}

#endif
