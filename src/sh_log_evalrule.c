
#include "config_xor.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>

#ifdef USE_LOGFILE_MONITOR

#undef  FIL__
#define FIL__  _("sh_log_evalrule.c")

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
#include "sh_log_correlate.h"
#include "sh_log_mark.h"
#include "sh_log_repeat.h"
#include "zAVLTree.h"

extern int flag_err_debug;

/* #define DEBUG_EVALRULES */

#ifdef DEBUG_EVALRULES
static void DEBUG(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap); /* flawfinder: ignore *//* we control fmt string */
  va_end(ap);
  return;
}
#else
static void DEBUG(const char *fmt, ...)
{
  (void) fmt;
  return;
}
#endif

struct sh_ceval    /* Counter for summarizing    */
{
  sh_string   * hostname;
  sh_string   * counted_str;
  sh_string   * filename;
  unsigned long count;
  time_t        start;
  time_t        interval;
};

void sh_ceval_free(void * item)
{
  struct sh_ceval * counter = (struct sh_ceval *) item;
  if (!counter)
    return;
  sh_string_destroy(&(counter->hostname));
  sh_string_destroy(&(counter->counted_str));
  sh_string_destroy(&(counter->filename));
  SH_FREE(counter);
}

enum {
  RFL_ISRULE  = 1 << 0,
  RFL_ISGROUP = 1 << 1,
  RFL_KEEP    = 1 << 2,
  RFL_MARK    = 1 << 3
};


/*--------------------------------------------------------------
 *
 *   Adding rules/groups/hosts
 *
 *--------------------------------------------------------------*/

struct sh_geval  /* Group of rules (may be a single rule) */
{
  sh_string       * label;           /* label for this group    */
  pcre            * rule;            /* compiled regex for rule */
  pcre_extra      * rule_extra;
  int             * ovector;         /* captured substrings     */
  int               ovecnum;         /* how many captured       */
  int               captures;        /* (captures+1)*3 required */
  int               flags;           /* bit flags               */
  unsigned long     delay;           /* delay for keep rules    */
  zAVLTree        * counterlist;     /* counters if EVAL_SUM    */
  struct sh_qeval * queue;           /* queue for this rule     */
  struct sh_geval * nextrule;        /* next rule in this group */
  struct sh_geval * next;            /* next group of rules     */
  struct sh_geval * gnext;           /* grouplist next          */
};

struct sh_heval  /* host-specific rules */
{
  pcre            * hostname;        /* compiled regex for hostname */
  pcre_extra      * hostname_extra;
  struct sh_geval * rulegroups;      /* list of group of rules      */
  struct sh_heval * next;
};

static struct sh_heval * hostlist  = NULL;
static struct sh_qeval * queuelist = NULL;
static struct sh_geval * grouplist = NULL;

/* These flags are set if we are within 
 * the define of a host/rule group.
 */
static struct sh_heval * host_open  = NULL;
static struct sh_geval * group_open = NULL;

int sh_eval_gend (const char * str)
{
  (void) str;
  if (group_open) {
    group_open = NULL;
    return 0;
  }
  return -1;
}

int sh_eval_gadd (const char * str)
{
  struct sh_geval * ng;
  struct sh_geval * tmp;
  pcre *  group;
  pcre_extra * group_extra;
  const char * error;
  int          erroffset;
  unsigned int nfields = 2;
  size_t       lengths[2];
  char *       new = sh_util_strdup(str);
  char **      splits = split_array(new, &nfields, ':', lengths);

  /* group is label:regex
   */

  if (group_open)
    group_open = NULL;

  if (nfields != 2)
    {
      SH_FREE(splits);
      SH_FREE(new);
      return -1;
    }

  group = pcre_compile(splits[1], PCRE_NO_AUTO_CAPTURE, 
		       &error, &erroffset, NULL);
  if (!group)
    {
      sh_string * msg =  sh_string_new(0);
      sh_string_add_from_char(msg, _("Bad regex: "));
      sh_string_add_from_char(msg, splits[1]);
      
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      sh_string_str(msg),
		      _("sh_eval_gadd"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      sh_string_destroy(&msg);
      
      SH_FREE(splits);
      SH_FREE(new);
      return -1;
    }
  group_extra = NULL; /* pcre_study(group, 0, &error); */

  ng = SH_ALLOC(sizeof(struct sh_geval));
  memset(ng, '\0', sizeof(struct sh_geval));

  ng->label       = sh_string_new_from_lchar(splits[0], lengths[0]);
  ng->flags       = RFL_ISGROUP;

  ng->rule        = group;
  ng->rule_extra  = group_extra;
  ng->ovector     = NULL;
  ng->ovecnum     = 0;
  ng->captures    = 0;
  ng->counterlist = NULL;
  ng->queue       = NULL;
  ng->nextrule    = NULL;
  ng->next        = NULL;
  ng->gnext       = NULL;

  if (!host_open)
    {
      if (0 != sh_eval_hadd("^.*"))
	{
	  pcre_free(group);
	  sh_string_destroy(&(ng->label));
	  SH_FREE(splits);
	  SH_FREE(new);
	  SH_FREE(ng);
	  return -1;
	}
    }

  /* 
   * Insert at end, to keep user-defined order 
   */ 

  if (host_open)
    {
      if (grouplist) 
	{
	  tmp = grouplist; 
	  while (tmp->gnext != NULL) { tmp = tmp->gnext; }
	  tmp->gnext = ng;
	} else {
	  grouplist = ng;
        }


      /* 
       * If there is an open host group, add it to its
       * rulegroups
       */

      if (host_open->rulegroups) 
	{
	  tmp = host_open->rulegroups; 
	  while (tmp->next != NULL) { tmp = tmp->next; }
	  tmp->next = ng;
	} else {
	  host_open->rulegroups = ng;
        }
    }

  group_open = ng;
  SH_FREE(splits);
  SH_FREE(new);
  return 0;
}

int sh_eval_hend (const char * str)
{
  (void) str;
  if (host_open) {
    host_open = NULL;
    return 0;
  }
  return -1;
}

int sh_eval_hadd (const char * str)
{
  struct sh_heval * nh;
  struct sh_heval * tmp;
  pcre *  host;
  pcre_extra * host_extra;
  const char * error;
  int          erroffset;

  if (host_open)
    host_open = NULL;

  host = pcre_compile(str, PCRE_NO_AUTO_CAPTURE, 
		      &error, &erroffset, NULL);
  if (!host)
    {
      sh_string * msg =  sh_string_new(0);
      sh_string_add_from_char(msg, _("Bad regex: "));
      sh_string_add_from_char(msg, str);
      
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      sh_string_str(msg),
		      _("sh_eval_hadd"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      sh_string_destroy(&msg);

      return -1;
    }
  host_extra = NULL; /* pcre_study(host, 0, &error); */

  nh = SH_ALLOC(sizeof(struct sh_heval));
  memset(nh, '\0', sizeof(struct sh_heval));

  nh->hostname = host;
  nh->hostname_extra = host_extra;
  nh->rulegroups = NULL;

  /* 
   * Insert at end, to keep user-defined order 
   */ 
  nh->next = NULL;
  if (hostlist) {
    tmp = hostlist; 
    while (tmp->next != NULL) { tmp = tmp->next; }
    tmp->next = nh;
  } else {
    hostlist = nh;
  }
  host_open = nh;

  return 0;
}

int sh_eval_qadd (const char * str)
{
  struct sh_qeval * nq;
  int     severity;
  unsigned int nfields = 5; /* label:interval:(report|sum):severity[:alias] */
  size_t  lengths[5];
  char *  new = sh_util_strdup(str);
  char ** splits = split_array(new, &nfields, ':', lengths);

  if (nfields < 4)
    {
      SH_FREE(splits);
      SH_FREE(new);
      return -1;
    }

  if (strcmp(splits[2], _("sum")) && strcmp(splits[2], _("report")))
    {
      SH_FREE(splits);
      SH_FREE(new);
      return -1;
    }

  if (!strcmp(splits[2], _("sum")) && atoi(splits[1]) < 0)
    {
      SH_FREE(splits);
      SH_FREE(new);
      return -1;
    }
  
  if (!strcmp(splits[1], _("trash"))) /* predefined, reserved */
    {
      SH_FREE(splits);
      SH_FREE(new);
      return -1;
    }
  
  severity = sh_error_convert_level (splits[3]);
  if (severity < 0)
    {
      SH_FREE(splits);
      SH_FREE(new);
      return -1;
    }

  nq = SH_ALLOC(sizeof(struct sh_qeval));
  memset(nq, '\0', sizeof(struct sh_qeval));

  nq->label = sh_string_new_from_lchar(splits[0], lengths[0]);
  nq->alias = NULL;

  DEBUG("debug: splits[2] = %s, policy = %d\n",splits[2],nq->policy); 
  if (0 == strcmp(splits[2], _("report"))) {
    nq->policy   = EVAL_REPORT;
    nq->interval = 0;
  }
  else {
    nq->policy   = EVAL_SUM;
    nq->interval = (time_t) atoi(splits[1]);
  }

  nq->severity = severity;

  if (nfields == 5)
    {
      nq->alias = sh_string_new_from_lchar(splits[4], lengths[4]);
    }

  nq->next     = queuelist;
  queuelist    = nq;

  SH_FREE(splits);
  SH_FREE(new);
  return 0;
}

struct sh_qeval * sh_log_find_queue(const char * str)
{
  struct sh_qeval * retval = queuelist;

  if (!str)
    return NULL;

  while (retval)
    {
      if (0 == strcmp(str, sh_string_str(retval->label)))
	break;
      retval = retval->next;
    }
  return retval;
}

int sh_log_lookup_severity(const char * str)
{
  struct sh_qeval * queue;

  if (str)
    {
      if (0 != strcmp(str, _("trash")))
	{
	  queue = sh_log_find_queue(str);
	  
	  if (queue)
	    return queue->severity;
	}
    }
  return SH_ERR_SEVERE;
}

sh_string * sh_log_lookup_alias(const char * str)
{
  struct sh_qeval * queue;

  if (str)
    {
      if (0 != strcmp(str, _("trash")))
	{
	  queue = sh_log_find_queue(str);
	  
	  if (queue)
	    return queue->alias;
	}
    }
  return NULL;
}


static char * get_label_and_time(const char * inprefix, char * str, 
				 unsigned long * seconds)
{
  char       * res    = NULL;
  char       * endptr = NULL;

  unsigned int nfields = 2; /* seconds:label */
  size_t       lengths[2];
  char *       prefix = sh_util_strdup(inprefix);
  char *       new    = sh_util_strdup(str);
  char **      splits = split_array_braced(new, prefix, &nfields, lengths);

  if (splits && nfields == 2 && lengths[0] > 0 && lengths[1] > 0)
    {
      *seconds = strtoul(splits[0], &endptr, 10);
      if ((endptr == '\0' || endptr != splits[0]) && (*seconds != ULONG_MAX))
	{
	  res = sh_util_strdup(splits[1]);
	}
    }
  if (splits)
    SH_FREE(splits);
  SH_FREE(new);
  SH_FREE(prefix);
  return res;
}

struct sh_qeval ** sh_dummy_472_queue;
char            ** sh_dummy_473_dstr;

int sh_eval_radd (const char * str)
{
  struct sh_geval * nr;
  struct sh_geval * tmp;
  struct sh_qeval * queue;
  pcre *  rule;
  pcre_extra * rule_extra;
  const char * error;
  int          erroffset;
  int          captures = 0;
  unsigned int nfields = 2; /* queue:regex */
  size_t       lengths[3];
  char *       new    = sh_util_strdup(str);
  char **      splits;

  int           qpos  = 0;
  volatile int  rpos  = 1;
  unsigned long dsec  = 0;
  char *        dstr  = NULL;
  char *        s     = new;
  volatile char pflag = '-';

  while ( *s && isspace((int)*s) ) ++s;
  if (0 == strncmp(s, _("KEEP"), 4)      || 
      0 == strncmp(s, _("CORRELATE"), 9) ||
      0 == strncmp(s, _("MARK"), 4))
    {
      pflag   = s[0];
      nfields = 3;
    }

  splits = split_array(new, &nfields, ':', lengths);

  sh_dummy_472_queue = &queue;
  sh_dummy_473_dstr  = &dstr;

  queue = NULL;

  if (nfields < 2 || nfields > 3)
    {
      SH_FREE(splits);
      SH_FREE(new);
      return -1;
    }

  if (nfields == 3)
    {
      if (pflag == 'K')
	{
	  /* KEEP(nsec,label):queue:regex
	   */
	  dstr = get_label_and_time(_("KEEP"), splits[0], &dsec);
	  if (!dstr)
	    {
	      SH_FREE(splits);
	      SH_FREE(new);
	      return -1;
	    }
	}
      else if (pflag == 'C')
	{
	  /* CORRELATE(description):queue:regex 
	   */
	  int retval = sh_keep_match_add(splits[0], splits[1], splits[2]);
	  SH_FREE(splits);
	  SH_FREE(new);
	  return retval;
	}
      else if (pflag == 'M')
	{
	  /* MARK(description, interval):queue:regex 
	   */
	  int retval = -1;

	  dstr = get_label_and_time(_("MARK"), splits[0], &dsec);
	  if (dstr)
	    {
	      retval = sh_log_mark_add(dstr, dsec, splits[1]);
	    }
	  if (retval != 0)
	    {
	      SH_FREE(splits);
	      SH_FREE(new);
	      return retval;
	    }
	}
      ++qpos; ++rpos;
    }

  if (0 != strcmp(splits[qpos], _("trash")))
    {
      queue = sh_log_find_queue(splits[qpos]);
      if (!queue)
	{
	  SH_FREE(splits);
	  SH_FREE(new);
	  return -1;
	}
    }

  rule = pcre_compile(splits[rpos], 0, 
		      &error, &erroffset, NULL);
  if (!rule)
    {
      sh_string * msg =  sh_string_new(0);
      sh_string_add_from_char(msg, _("Bad regex: "));
      sh_string_add_from_char(msg, splits[rpos]);
      
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      sh_string_str(msg),
		      _("sh_eval_radd"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      sh_string_destroy(&msg);

      SH_FREE(splits);
      SH_FREE(new);
      return -1;
    }
  rule_extra = NULL; /* pcre_study(rule, 0, &error); */
  pcre_fullinfo(rule, rule_extra, PCRE_INFO_CAPTURECOUNT, &captures);

  if (flag_err_debug == S_TRUE)
    {
      char * emsg = SH_ALLOC(SH_ERRBUF_SIZE);
      if (dstr)
	sl_snprintf(emsg,  SH_ERRBUF_SIZE, _("Adding rule: |%s| with %d captures, keep(%lu,%s)"), 
		    splits[rpos], captures, dsec, dstr);
      else
	sl_snprintf(emsg,  SH_ERRBUF_SIZE, _("Adding rule: |%s| with %d captures"), 
		    splits[rpos], captures);
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      emsg, _("sh_eval_radd"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      SH_FREE(emsg);
    }

  DEBUG("adding rule: |%s| with %d captures\n", splits[rpos], captures);

  SH_FREE(splits);
  SH_FREE(new);

  nr = SH_ALLOC(sizeof(struct sh_geval));
  memset(nr, '\0', sizeof(struct sh_geval));

  nr->label       = NULL;
  nr->flags       = RFL_ISRULE;
  nr->delay       = 0;

  nr->rule        = rule;
  nr->rule_extra  = rule_extra;
  nr->captures    = captures;
  nr->ovector     = SH_ALLOC(sizeof(int) * (captures+1) * 3);
  nr->ovecnum     = 0;
  nr->counterlist = NULL;
  nr->queue       = queue;
  nr->nextrule    = NULL;
  nr->next        = NULL;
  nr->gnext       = NULL;


  if (pflag == 'K')
    {
      nr->label   = sh_string_new_from_lchar(dstr, sl_strlen(dstr));
      nr->flags  |= RFL_KEEP;
      nr->delay   = dsec;
      SH_FREE(dstr);
    }
  else if (pflag == 'M')
    {
      nr->label   = sh_string_new_from_lchar(dstr, sl_strlen(dstr));
      nr->flags  |= RFL_MARK;
      nr->delay   = dsec;
      SH_FREE(dstr);
    }

  /* 
   * If there is an open group, add it to its
   * rules
   */
  if (group_open)
    {
      if (flag_err_debug == S_TRUE)
	{
	  char * emsg = SH_ALLOC(SH_ERRBUF_SIZE);
	  sl_snprintf(emsg,  SH_ERRBUF_SIZE, _("Adding rule to group |%s|"), 
		      sh_string_str(group_open->label));
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			  emsg, _("sh_eval_radd"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  SH_FREE(emsg);
	}

      DEBUG("adding rule to group |%s|\n", sh_string_str(group_open->label));

      if (group_open->nextrule) 
	{
	  tmp = group_open->nextrule; 
	  while (tmp->nextrule != NULL) { tmp = tmp->nextrule; } /* next -> nextrule */
	  tmp->nextrule = nr;                                    /* next -> nextrule */
	} else {
	  group_open->nextrule = nr;
	}
    }

  /* 
   * ..else, add it to the currently open host (open the
   * default host, if there is no open one)
   */
  else
    {
      if (!host_open)
	{
	  if (0 != sh_eval_hadd("^.*"))
	    {
	      if (nr->label)
		sh_string_destroy(&(nr->label));
	      SH_FREE(nr->ovector);
	      SH_FREE(nr);
	      return -1;
	    }
	}

      if (host_open)
	{
	  /* 
	   * Add rule as member to grouplist, to facilitate cleanup
	   */

	  DEBUG("adding solitary rule to grouplist\n");

	  if (grouplist) 
	    {
	      tmp = grouplist; 
	      while (tmp->gnext != NULL) { tmp = tmp->gnext; }
	      tmp->gnext = nr;
	    } else {
	      grouplist = nr;
	    }


	  /* 
	   * Add rule to host rulegroups
	   */
	  DEBUG("adding solitary rule to host rulegroups\n");

	  if (host_open->rulegroups) 
	    {
	      /* Second, third, ... rule go to host_open->rulegroups->next,
	       * since test_grules() iterates over nextrules
	       */
	      tmp = host_open->rulegroups; 
	      while (tmp->next != NULL) { tmp = tmp->next; }
	      tmp->next = nr;
	    } 
	  else 
	    {
	      /* First rule goes to host_open->rulegroups */
	      host_open->rulegroups = nr;
	    }
	}
      else
	{
	  if (nr->label)
	    sh_string_destroy(&(nr->label));
	  SH_FREE(nr->ovector);
	  SH_FREE(nr);
	  return -1;
	}
    }

  return 0;
}

void sh_eval_cleanup()
{
  struct sh_geval * gtmp;
  struct sh_qeval * qtmp;
  struct sh_heval * htmp;

  while (grouplist)
    {
      gtmp      = grouplist;
      grouplist = gtmp->gnext;

      if (gtmp->label)      sh_string_destroy(&(gtmp->label));
      if (gtmp->rule_extra) (*pcre_free)(gtmp->rule_extra);
      if (gtmp->rule)       (*pcre_free)(gtmp->rule);
      if (gtmp->counterlist)
	zAVLFreeTree(gtmp->counterlist, sh_ceval_free);
      if (gtmp->ovector)
	SH_FREE(gtmp->ovector);
#if 0
      while (gtmp->nextrule)
	{
	  tmp            = gtmp->nextrule;
	  gtmp->nextrule = tmp->nextrule;

	  if (tmp->rule_extra) (*pcre_free)(tmp->rule_extra);
	  if (tmp->rule)       (*pcre_free)(tmp->rule);
	  if (tmp->counterlist)
	    zAVLFreeTree(tmp->counterlist, sh_ceval_free);
	  if (tmp->ovector)
	    SH_FREE(tmp->ovector);
	  SH_FREE(tmp);
	}
#endif
      SH_FREE(gtmp);
    }

  qtmp = queuelist;
  while (qtmp)
    {
      if (qtmp->label)      sh_string_destroy(&(qtmp->label));
      queuelist = qtmp->next;
      SH_FREE(qtmp);
      qtmp = queuelist;
    }

  htmp = hostlist;
  while (htmp)
    {
      if (htmp->hostname_extra) (*pcre_free)(htmp->hostname_extra);
      if (htmp->hostname)       (*pcre_free)(htmp->hostname);
      if (htmp->rulegroups)     htmp->rulegroups = NULL;
      hostlist = htmp->next;
      htmp->next = NULL;
      SH_FREE(htmp);
      htmp = hostlist;
    }

  hostlist   = NULL;
  queuelist  = NULL;
  grouplist  = NULL;

  host_open  = NULL;
  group_open = NULL;

  sh_keep_destroy();
  sh_keep_match_del();

  return;
}

/**********************************************************************
 *
 * Actual rule processing
 *
 **********************************************************************/ 

/* Test a list of rules against msg; return matched rule, with ovector 
 * filled in
 */
struct sh_geval ** sh_dummy_828_rule;

static struct sh_geval * test_rule (struct sh_geval * rule, sh_string *msg, time_t tstamp)
{
  int res; 
  volatile int    count;
  volatile time_t timestamp = tstamp;

  sh_dummy_828_rule = &rule;

  if (!rule)
    DEBUG("debug: (NULL) rule\n");

  if (rule && sh_string_len(msg) < (size_t)INT_MAX)
    {
      count = 1;
      do {

	if (flag_err_debug == S_TRUE)
	  {
	    char * emsg = SH_ALLOC(SH_ERRBUF_SIZE);
	    sl_snprintf(emsg,  SH_ERRBUF_SIZE, _("Check rule %d for |%s|"), 
			count, sh_string_str(msg));
	    SH_MUTEX_LOCK(mutex_thread_nolog);
	    sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			    emsg, _("test_rule"));
	    SH_MUTEX_UNLOCK(mutex_thread_nolog);
	    SH_FREE(emsg);
	  }

	DEBUG("debug: check rule %d for <%s>\n", count, msg->str);
	res = pcre_exec(rule->rule, rule->rule_extra, 
			sh_string_str(msg), (int)sh_string_len(msg), 0,
			0, rule->ovector, (3*(1+rule->captures)));
	if (res >= 0)
	  {
	    rule->ovecnum = res;

	    if (flag_err_debug == S_TRUE)
	      {
		char * emsg = SH_ALLOC(SH_ERRBUF_SIZE);
		if ( rule->flags & RFL_KEEP )
		  sl_snprintf(emsg,  SH_ERRBUF_SIZE, _("Rule %d matches, result = %d (keep)"), 
			      count, res);
		else if ( rule->flags & RFL_MARK )
		  sl_snprintf(emsg,  SH_ERRBUF_SIZE, _("Rule %d matches, result = %d (mark)"), 
			      count, res);
		else
		  sl_snprintf(emsg,  SH_ERRBUF_SIZE, _("Rule %d matches, result = %d"), 
			      count, res);
		SH_MUTEX_LOCK(mutex_thread_nolog);
		sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
				emsg, _("test_rule"));
		SH_MUTEX_UNLOCK(mutex_thread_nolog);
		SH_FREE(emsg);
	      }

	    if ( rule->flags & RFL_KEEP )
	      {
		DEBUG("debug: rule %d matches (keep), timestamp = %lu\n", count, timestamp);
		sh_keep_add(rule->label, rule->delay, 
			    timestamp == 0 ? time(NULL) : timestamp);
	      }

	    else if ( rule->flags & RFL_MARK )
	      {
		DEBUG("debug: rule %d matches (mark)\n", count);
		sh_log_mark_update(rule->label,
				   timestamp == 0 ? time(NULL) : timestamp);
	      }

	    break; /* return the matching rule; ovector is filled in */
	  }

	if (flag_err_debug == S_TRUE)
	  {
	    char * emsg = SH_ALLOC(SH_ERRBUF_SIZE);
	    sl_snprintf(emsg,  SH_ERRBUF_SIZE, _("Rule %d did not match"), 
			count);
	    SH_MUTEX_LOCK(mutex_thread_nolog);
	    sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			    emsg, _("test_rule"));
	    SH_MUTEX_UNLOCK(mutex_thread_nolog);
	    SH_FREE(emsg);
	  }
	DEBUG("debug: rule %d did not match\n", count);

	rule = rule->nextrule; ++count;
      } while (rule);
    }
  if (!rule)
    DEBUG("debug: no match found\n");
  /* If there was no match, this is NULL */
  sh_dummy_828_rule = NULL;
  return rule;
}
  
/* Test a (struct sh_geval *), which may be single rule or a group of rules,
 * against msg
 */
struct sh_geval ** sh_dummy_928_result;
struct sh_geval ** sh_dummy_929_group;

static struct sh_geval * test_grules (struct sh_heval * host, 
				      sh_string       * msg,
				      time_t            timestamp)
{
  struct sh_geval * result = NULL;
  struct sh_geval * group  = host->rulegroups;

  sh_dummy_928_result = &result;
  sh_dummy_929_group  = &group;

  if (group && sh_string_len(msg) < (size_t)INT_MAX)
    {
      DEBUG("debug: if group\n");
      do {
	if( (group->label != NULL) && (0 != (group->flags & RFL_ISGROUP))) 
	  {
	    /* this is a rule group */

	    if (flag_err_debug == S_TRUE)
	      {
		char * emsg = SH_ALLOC(SH_ERRBUF_SIZE);
		sl_snprintf(emsg,  SH_ERRBUF_SIZE, _("Checking group |%s| of rules against |%s|"), 
			    sh_string_str(group->label), sh_string_str(msg));
		SH_MUTEX_LOCK(mutex_thread_nolog);
		sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
				emsg, _("test_rule"));
		SH_MUTEX_UNLOCK(mutex_thread_nolog);
		SH_FREE(emsg);
	      }

	    DEBUG("debug: if group->label %s\n", sh_string_str(group->label));
	    if (pcre_exec(group->rule, group->rule_extra,
			  sh_string_str(msg), (int) sh_string_len(msg),
			  0, 0, NULL, 0) >= 0)
	      {
		result = test_rule(group->nextrule, msg, timestamp);
		if (result)
		  break;
	      }
	  }
	else
	  {
	    /* If there is no group label, the 'group' is actually a solitary 
	     * rule (not within any group).
	     */

	    if (flag_err_debug == S_TRUE)
	      {
		char * emsg = SH_ALLOC(SH_ERRBUF_SIZE);
		sl_snprintf(emsg,  SH_ERRBUF_SIZE, _("Checking solitary rules"));
		SH_MUTEX_LOCK(mutex_thread_nolog);
		sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
				emsg, _("test_rule"));
		SH_MUTEX_UNLOCK(mutex_thread_nolog);
		SH_FREE(emsg);
	      }

	    DEBUG("debug: else (single rule)\n");
	    result = test_rule(group, msg, timestamp);
	    if (result)
	      break;
	  }
	group = group->next; /* next group of rules */
      } while (group);
    }

  sh_dummy_928_result = NULL;
  sh_dummy_929_group  = NULL;
  return result;
}

/* Top-level find_rule() function
 */
static struct sh_geval * find_rule (sh_string *host, 
				    sh_string *msg,
				    time_t     timestamp)
{
  struct sh_geval * result = NULL;
  struct sh_heval * hlist  = hostlist;

  if (hlist && sh_string_len(host) < (size_t)INT_MAX)
    {
      do {
	if (pcre_exec(hlist->hostname, hlist->hostname_extra, 
		      sh_string_str(host), (int) sh_string_len(host), 
		      0, 0, NULL, 0) >= 0)
	  {
	    /* matching host, check rules/groups of rules */
	    result = test_grules(hlist, msg, timestamp);
	    if (result)
	      break;
	  }
	hlist = hlist->next;
      } while (hlist);
    }
  return result;
}

/* copy the message and replace captured substrings with '___'
 */
static sh_string * replace_captures(const sh_string * message, 
				    int * ovector, int ovecnum)
{
  sh_string * retval = sh_string_new_from_lchar(sh_string_str(message), 
						sh_string_len(message));

  if (ovecnum > 1)
    {
      retval = sh_string_replace(retval, &(ovector[2]), (ovecnum-1), "___", 3);
    }
  return retval;
}

static void msg_report(int severity, const sh_string * alias, 
		       struct sh_geval * rule, struct sh_logrecord * record)
{
  char      * tmp;
  char      * msg;
  sh_string * mmm = NULL;
  char      * ttt;


  SH_MUTEX_LOCK(mutex_thread_nolog);
  if (rule) {
    mmm = replace_captures(record->message, rule->ovector, 
			   rule->ovecnum);
    rule->ovecnum = 0;
    msg = sh_util_safe_name_keepspace (sh_string_str(mmm));
  }
  else {
    msg = sh_util_safe_name_keepspace (sh_string_str(record->message));
  }
  tmp = sh_util_safe_name_keepspace (record->filename);
  ttt = sh_util_safe_name_keepspace (sh_string_str(record->timestr));
  sh_error_handle (severity, FIL__, __LINE__, 0, MSG_LOGMON_REP,
		   msg,
		   ttt,
		   sh_string_str(record->host),
		   tmp);
  if (alias)
    {
      sh_error_mail (sh_string_str(alias),
		     severity, FIL__, __LINE__, 0, MSG_LOGMON_REP,
		     msg,
		     ttt,
		     sh_string_str(record->host),
		     tmp);
    }
  SH_FREE(ttt);
  SH_FREE(msg);
  SH_FREE(tmp);
  if (mmm)
    sh_string_destroy(&mmm);
  SH_MUTEX_UNLOCK(mutex_thread_nolog);
}

static void sum_report(int severity, const sh_string * alias,
		       sh_string * host, sh_string * message, sh_string * path)
{
  char * tmp;
  char * msg;

  SH_MUTEX_LOCK(mutex_thread_nolog);
  tmp = sh_util_safe_name_keepspace (sh_string_str(path));
  msg = sh_util_safe_name_keepspace (sh_string_str(message));
  sh_error_handle (severity, FIL__, __LINE__, 0, MSG_LOGMON_SUM,
		   msg,
		   sh_string_str(host), 
		   tmp);
  if (alias)
    {
      sh_error_mail (sh_string_str(alias),
		     severity, FIL__, __LINE__, 0, MSG_LOGMON_SUM,
		     msg,
		     sh_string_str(host),
		     tmp);
    }
  SH_FREE(msg);
  SH_FREE(tmp);
  SH_MUTEX_UNLOCK(mutex_thread_nolog);
}

static zAVLKey sh_eval_getkey(void const *item)
{
  return ((const struct sh_ceval *)item)->hostname->str;
}

/* Find the counter, or initialize one if there is none already
 */
static struct sh_ceval * find_counter(struct sh_geval * rule, 
				      sh_string * host, time_t interval)
{
  struct sh_ceval * counter;

  if (!(rule->counterlist))
    {
      DEBUG("debug: allocate new counterlist AVL tree\n");
      rule->counterlist = zAVLAllocTree(sh_eval_getkey, zAVL_KEY_STRING);
    }

  counter = (struct sh_ceval *) zAVLSearch (rule->counterlist, 
					    sh_string_str(host));

  if (!counter)
    {
      DEBUG("debug: no counter found\n");

      counter = SH_ALLOC(sizeof(struct sh_ceval));
      memset(counter, '\0', sizeof(struct sh_ceval));

      counter->hostname    = sh_string_new_from_lchar(sh_string_str(host), 
						      sh_string_len(host));
      counter->counted_str = NULL;
      counter->filename    = NULL;
      counter->count       = 0;
      counter->start       = time(NULL);
      counter->interval    = interval;

      zAVLInsert(rule->counterlist, counter);
    }
  return counter;
		       
}


/* process the counter for a SUM rule
 */
static int  process_counter(struct sh_ceval * counter, 
			    struct sh_geval * rule,  
			    struct sh_logrecord * record)
{
  int retval = -1;
  time_t  now;

  if (!(counter->counted_str))
    {
      counter->counted_str = replace_captures(record->message, rule->ovector, 
					      rule->ovecnum);
      rule->ovecnum        = 0;
      counter->filename    = sh_string_new_from_lchar(record->filename,
						      strlen(record->filename));
      DEBUG("debug: counted_str after replace: %s\n", 
	    sh_string_str(counter->counted_str)); 
    }

  ++(counter->count);
  now = time(NULL); now -= counter->start;
  DEBUG("debug: count %lu, interval %lu, time %lu\n", 
	counter->count, counter->interval, now);
  if (now >= counter->interval)
    {
      DEBUG("debug: report count\n");
      sum_report(rule->queue->severity, rule->queue->alias,
		 counter->hostname, counter->counted_str, counter->filename);
      counter->start = time(NULL);
      counter->count = 0;
    }
  return retval;
}

/* Process a rule
 */
static int  process_rule(struct sh_geval * rule, struct sh_logrecord * record)
{
  int retval = -1;
  struct sh_qeval * queue = rule->queue;

  if (queue)
    {
      DEBUG("debug: queue policy = %d found\n", queue->policy);
      if (queue->policy == EVAL_REPORT)
	{
	  DEBUG("debug: EVAL_REPORT host: %s, message: %s\n",
		 sh_string_str(record->host), 
		 sh_string_str(record->message));
	  msg_report(queue->severity, queue->alias, rule, record);
	  retval = 0;
	}
      else if (queue->policy == EVAL_SUM)
	{
	  
	  struct sh_ceval * counter = 
	    find_counter(rule, record->host, queue->interval);
	  DEBUG("debug: EVAL_SUM host: %s, message: %s\n",
		 sh_string_str(record->host),
		 sh_string_str(record->message));
	  if (counter)
	    {
	      DEBUG("debug: counter found\n");
	      retval = process_counter(counter, rule, record);
	    }
	}
    }
  else
    {
      DEBUG("debug: no queue found -- trash\n");
      /* No queue means 'trash' */
      retval = 0;
    }
  return retval;
}

#define DEFAULT_SEVERITY (-1)

int sh_eval_process_msg(struct sh_logrecord * record)
{
  static unsigned long i = 0;
  if (record)
    {
      struct sh_geval * rule = find_rule (record->host,
					  record->message,
					  record->timestamp);

      if (rule)
	{
	  DEBUG("debug: (%lu) rule found\n", i); ++i;
	  return process_rule(rule, record);
	}
      else
	{
	  DEBUG("debug: (%lu) no rule found\n", i); ++i;
	  msg_report(DEFAULT_SEVERITY, NULL, NULL, record);
	}

      sh_repeat_message_check(record->host, 
			      record->message, 
			      record->timestamp);
			      
      return 0;
    }
  return -1;
}

#endif
