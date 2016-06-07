#ifndef SH_SCHEDULE_H
#define SH_SCHEDULE_H

/************************************************
 * 
 * Scheduler class - public definitions
 *
 ************************************************/

typedef struct sh_schedule_ {
  int    max[5];
  int    min[5];
  int    step[5];
  int    min_step;
  time_t last_exec;
  int    first;
  struct sh_schedule_ * next;
} sh_schedule_t;

/* This function parses a crontab-like schedule and fills a
 * sh_schedule_t structure provided by the caller.
 */
int create_sched (const char * ssched, sh_schedule_t * isched);

/* This function returns 1 if the scheduled event should be executed,
 * else 0
 */
int test_sched   (sh_schedule_t * isched);

#endif
