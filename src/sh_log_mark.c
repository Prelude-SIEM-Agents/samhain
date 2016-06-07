#include "config_xor.h"

#ifdef USE_LOGFILE_MONITOR

#include <string.h>
#include <time.h>

#undef  FIL__
#define FIL__  _("sh_log_mark.c")


#include "samhain.h"
#include "sh_pthread.h"
#include "sh_mem.h"
#include "sh_string.h"
#include "sh_error_min.h"
#include "sh_log_check.h"
#include "sh_log_evalrule.h"
#include "zAVLTree.h"

/* #define DEBUG_MARK */

#ifdef DEBUG_MARK
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

static zAVLTree * marklist = NULL;

struct sh_mark_event
{
  sh_string   * label;
  sh_string   * queue_id;
  time_t        last_seen;
  time_t        interval;
  time_t        delay;
  time_t        last_reported;
};

static void sh_marklist_free(void * item)
{
  struct sh_mark_event * event = (struct sh_mark_event *) item;
  if (!event)
    return;
  sh_string_destroy(&(event->label));
  sh_string_destroy(&(event->queue_id));
  SH_FREE(event);
  return;
}

void sh_log_mark_destroy()
{
  zAVLFreeTree(marklist, sh_marklist_free);
}

static zAVLKey sh_log_mark_getkey(void const *item)
{
  return ((const struct sh_mark_event *)item)->label->str;
}

int sh_log_mark_add (const char * label, time_t interval, const char * qlabel)
{
  struct sh_mark_event * event;

  if (!(marklist))
    {
      marklist = zAVLAllocTree(sh_log_mark_getkey, zAVL_KEY_STRING);
    }

  event = (struct sh_mark_event *) zAVLSearch(marklist, label);
  if (event)
    {
      event->interval     = interval;
      sh_string_destroy(&(event->queue_id));
      event->queue_id     = sh_string_new_from_lchar(qlabel, strlen(qlabel));
      return 0;
    }

  event = SH_ALLOC(sizeof(struct sh_mark_event));

  event->last_seen      = time(NULL);
  event->interval       = interval;
  event->delay          = 0;
  event->last_reported  = 0;
  event->label          = sh_string_new_from_lchar(label, strlen(label));
  event->queue_id       = sh_string_new_from_lchar(qlabel, strlen(qlabel));

  if (0 != zAVLInsert(marklist, event))
    {
      sh_marklist_free(event);
      return -1;
    }
  return 0;
}

void sh_log_mark_update (sh_string * label, time_t timestamp)
{
  struct sh_mark_event * event = 
    (struct sh_mark_event *) zAVLSearch (marklist, sh_string_str(label));

  DEBUG("debug: running mark update for %s\n", sh_string_str(label));
 
  if (event)
    {
      DEBUG("debug: updating, timestamp %lu, last_seen %lu, interval %d\n",
	    (unsigned long)timestamp, (unsigned long) event->last_seen,
	    (int)event->interval);

      if ((timestamp > event->last_seen) && 
	  (event->interval < (timestamp - event->last_seen)) &&
	  (timestamp > event->last_reported) && 
	  (event->interval < (timestamp - event->last_reported)))
	{
	  event->delay        = timestamp - event->last_seen;
	  DEBUG("debug: updating delay to %d\n", (int) event->delay);
	}
      event->last_seen    = timestamp;
    }
  return;
}

/* This should allow to get all overdue labels with a for loop like:
 *   for (label = sh_log_mark_first(); label; label = sh_log_mark_next()) {} 
 */

static zAVLCursor mark_cursor;

static struct sh_mark_event * sh_log_mark_cursor(time_t * delay, time_t now, 
						 struct sh_mark_event * event)
{
  while (event)
    {
      DEBUG("debug: echeck, delay %d, now %lu, last_seen %lu, reported %lu\n",
	    (int) event->delay,
	    (unsigned long)now, (unsigned long) event->last_seen,
	    (unsigned long)event->last_reported);
      if (event->delay > 0)
	{
	  DEBUG("debug: event delay > 0, value %d\n", (int) event->delay);
	  *delay = event->delay;
	  event->delay = 0;
	  event->last_reported = time(NULL);
	  return event;
	}
      else if ((now > event->last_seen) && 
	       (now > event->last_reported) &&
	       (event->interval < (now - event->last_seen)) &&
	       (event->interval < (now - event->last_reported))
	       )
	{
	  DEBUG("debug: event delay 0, now %lu, last_seen %lu, reported %lu\n",
		(unsigned long)now, (unsigned long) event->last_seen,
		(unsigned long)event->last_reported);
	  *delay = now - event->last_seen;
	  event->delay = 0;
	  /* Subtract 1 sec to prevent accumulation of the
	   * one second offset. */
	  event->last_reported = time(NULL) - 1;
	  return event;
	}
      event = (struct sh_mark_event *) zAVLNext(&mark_cursor);
    }

  return NULL;
}

struct sh_mark_event * sh_log_mark_first(time_t * delay, time_t now)
{
  struct sh_mark_event * event = 
    (struct sh_mark_event *) zAVLFirst(&mark_cursor, marklist);
  
  return sh_log_mark_cursor (delay, now, event);
}

struct sh_mark_event * sh_log_mark_next(time_t * delay, time_t now)
{
  struct sh_mark_event * event = 
    (struct sh_mark_event *) zAVLNext(&mark_cursor);
  
  return sh_log_mark_cursor (delay, now, event);
}

static int sh_mark_default_severity = SH_ERR_SEVERE;

int sh_log_set_mark_severity (const char * str)
{
  int val = sh_error_convert_level(str);
  if (val < 0)
    return -1;
  sh_mark_default_severity = val;
  return 0;
}

static struct sh_mark_event ** dummy_event;

void sh_log_mark_check()
{
  struct sh_mark_event * event;
  time_t now = time(NULL);
  time_t delay;

  /* variable 'event' might be clobbered by 'longjmp' or 'vfork'
   */
  dummy_event = &event;

  DEBUG("debug: running mark check\n"); 
  for (event = sh_log_mark_first(&delay, now); event; 
       event = sh_log_mark_next (&delay, now)) 
    {
      int severity;
      sh_string * alias;
      SH_MUTEX_LOCK(mutex_thread_nolog);

      severity = sh_log_lookup_severity(sh_string_str(event->queue_id));
      if (severity < 0)
	severity = sh_mark_default_severity;

      DEBUG("debug: mark check: queue %s, severity %d\n", 
	    sh_string_str(event->queue_id), severity); 
      sh_error_handle (severity, 
		       FIL__, __LINE__, 0, MSG_LOGMON_MARK, 
		       sh_string_str(event->label), 
		       (unsigned long) delay);
      alias = sh_log_lookup_alias(sh_string_str(event->queue_id));
      if (alias)
	{
	  sh_error_mail (sh_string_str(alias), severity, 
			 FIL__, __LINE__, 0, MSG_LOGMON_MARK, 
			 sh_string_str(event->label), 
			 (unsigned long) delay);
	}

      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }
  return;
}

#endif
