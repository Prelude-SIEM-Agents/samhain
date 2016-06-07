#ifndef SH_EVALRULE_H
#define SH_EVALRULE_H

/* Clean up everything.
 */
void sh_eval_cleanup();

/* Define a new reporting queue, str := label:interval:(report|sum):severity
 */
int sh_eval_qadd (const char * str);

/* Add a new rule, str := queue:regex
 * If there is an open group, add it to its rules.
 * ..else, add it to the currently open host (open the
 * default host, if there is no open one)
 */
int sh_eval_radd (const char * str);

/* Open a new host group definition.
 */
int sh_eval_hadd (const char * str);
/*
 * End the host definition
 */
int sh_eval_hend (const char * str);


/* Open a new group definition. If a host is currently open, 
 * the new group will automatically be added to that host.
 */
int sh_eval_gadd (const char * str);
/*
 * End the group definition
 */
int sh_eval_gend (const char * str);

/* Process a single log record
 */
int sh_eval_process_msg(struct sh_logrecord * record);

enum policies {
  EVAL_REPORT,
  EVAL_SUM
};

struct sh_qeval  /* Queue with definitions */
{
  sh_string       * label;
  enum policies     policy;
  int               severity;
  sh_string       * alias;
  time_t            interval;        /* if EVAL_SUM, interval   */ 
  struct sh_qeval * next;
};

struct sh_qeval * sh_log_find_queue(const char * str);

int sh_log_lookup_severity(const char * str);
sh_string * sh_log_lookup_alias(const char * str);

#endif
