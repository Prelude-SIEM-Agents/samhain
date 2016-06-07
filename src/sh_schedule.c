/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2002 Rainer Wichmann                                      */
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

/* 
   gcc -Wall -O2 -o mysched sh_schedule.c -DTESTONLY
 */
#ifndef TESTONLY


#undef  FIL__
#define FIL__  _("sh_schedule.c")

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
#define SCHEDULER_YES
#endif

#if TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#include "samhain.h"
#include "sh_mem.h"
#include "sh_error_min.h"

/* TESTONLY */
#else

#define SCHEDULER_YES
#include <time.h>

#endif

#include "sh_schedule.h"



#ifdef SCHEDULER_YES

/************************************************
 * 
 * Scheduler class - private area
 *
 ************************************************/


static const int  sh_schedule_max[5] = { 59, 23, 31, 12, 7 };
static const int  sh_schedule_min[5] = {  0,  0,  0,  0, 0 };

static
int test_val (int i, int min, int max, int min_step, 
	      time_t * last, time_t now, int nval, int first_flag)
{
  /* don't miss a minute's task
   * IDEA:  set last = now after first check (? seems to work)
   */
  if (i == 0 && max == min && nval > max 
      /* && ( ((now - *last) > min_step) || (*last == (time_t)-1) ) */ )
    {
      if (*last == (time_t)-1)
	{
	  /* fake execution at nval-max
	   */
	  *last = now - 60 * (nval-max);
	  return 0;
	}
      if ((int)(now - *last) > min_step)
	return 1;
    }

  /* out of range
   */
  if (nval > max || nval < min) 
    return 0;

  /* first call - invalid last_exec

  if (*last == (time_t)-1)
    return 1;
  */

  if (first_flag == 0)
    return 1;


  /* before min_step - too early (e.g. same minute)
   */
  if ((int)(now - *last) <= min_step)
    return 0;

  return 1;
}

static
int test_sched_int (sh_schedule_t * isched)
{
  time_t now;
  struct tm * tval;
  int count, i, nval;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_LOCALTIME_R)
  struct tm     time_tm;
#endif

  if (!isched)
    return 0;

  now  = time(NULL);
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_LOCALTIME_R)
  tval = localtime_r(&now, &time_tm);
#else
  tval = localtime(&now);
#endif

  if (!tval)
    {
      sh_error_handle ((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
                       _("localime() failed"), _("test_sched_int") );
      return 0;
    }

  count = 0;
  for (i = 0; i < 5; ++i)
    {
      if      (i == 0) nval = tval->tm_min;
      else if (i == 1) nval = tval->tm_hour;
      else if (i == 2) nval = tval->tm_mday;
      else if (i == 3) nval = tval->tm_mon;
      else             nval = tval->tm_wday;
      count += test_val (i, isched->min[i], isched->max[i], 
			 isched->min_step, &(isched->last_exec), 
			 now, nval, isched->first);
    }

  if (count == 5)
    {
      isched->first = 1;
      isched->last_exec = now;
      return 1;
    }

  return 0;
}

/* test a linked list of schedules
 */
int test_sched (sh_schedule_t * isched)
{
  sh_schedule_t * intern = isched;
  int             retval = 0;

  while (intern != NULL)
    {
      if (test_sched_int(intern) == 1)
	retval = 1;
      intern = intern->next;
    }
  return retval;
}

static 
char DayNames[7][4] = { "sun", "mon", "tue", "wed", "thu", "fri", "sat" };
static
char MonNames[12][4] = { "jan", "feb", "mar", "apr", "may", "jun", 
		       "jul", "aug", "sep", "oct", "nov", "dec" };

static
int parse_func (int i, char * p)
{
  int j, k, l;
  char *tail;

  errno = 0;
  j = (int) strtol(p, &tail, 10);

  if (errno != 0)     /* overflow          */
    return -1;
  if (j < 0)
    return -1;
  if (tail != p)      /* numeric           */
    return j;
  if (i < 3)          /* names not allowed */
    return -1;

  if (i == 3)
    {
      for (j = 0; j < 12; ++j) {
	l = 0;
	/*@+charint@*//* Incompatible types for == (char, char): ??? */
	for (k = 0; k < 3; ++k)
	  if (p[k] != '\0' && tolower((int) p[k]) == MonNames[j][k]) ++l;
	/*@-charint@*/
	if (l == 3)
	  return j;
      }
    }
  if (i == 4)
    {
      for (j = 0; j < 7; ++j) {
	l = 0;
	/*@+charint@*//* Incompatible types for == (char, char): ??? */
	for (k = 0; k < 3; ++k)
	  if (p[k] != '\0' && tolower((int) p[k]) == DayNames[j][k]) ++l;
	/*@-charint@*/
	if (l == 3)
	  return j;
      }
    }

  return -1;
}  

static
int parse_token(int i, sh_schedule_t * isched, char * p)
{
  char * q;

  if ( NULL != (q = strchr(p, ',')))
    return -1;

  if (*p == '*')
    {
      isched->min[i] = sh_schedule_min[i];
      isched->max[i] = sh_schedule_max[i];
    }
  else 
    {
      isched->min[i] = parse_func(i, p);
      if (i == 4 && isched->min[i] == 7)
	isched->min[i] = 0;
      if (isched->min[i] < sh_schedule_min[i] || 
	  isched->min[i] > sh_schedule_max[i])
	{
	  return -1;
	}
      if ( NULL != (q = strchr(p, '-')))
	{
	  ++q;
	  isched->max[i] = parse_func(i, q);
	  if (i == 4 && isched->max[i] == 7)
	    isched->max[i] = 0;
	  if (isched->max[i] < sh_schedule_min[i] || 
	      isched->max[i] > sh_schedule_max[i] ||
	      isched->max[i] < isched->min[i])
	    {
	      return -1;
	    }
	}
      else
	isched->max[i] = isched->min[i];
    }

  if ( NULL != (q = strchr(p, '/')))
    {
      ++q;
      isched->step[i] = atoi(q);
      if (isched->step[i] < 1 || isched->step[i] > sh_schedule_max[i])
	{
	  return -1;
	}
      if (i == 4 && isched->step[i] == 7)
	isched->step[i] = 6;
    }
  else
    {
      isched->step[i] = 1;
    }

  switch (i) 
    {
    case 0:
      if (isched->max[i] == isched->min[i])
	isched->min_step = 3599;
      else
	isched->min_step = (isched->step[i] * 60) - 1;
      break;
    case 1:
      if (isched->max[i] == isched->min[i])
	{
	  /* fix for daylight saving time: subtract 3600 sec 
	   */
	  if (isched->min_step == 3599)
	    isched->min_step = 86399 - 3600;
	}
      else
	{
	  if (isched->min_step == 3599)
	    isched->min_step = (isched->step[i] * 3600) - 1;
	}
      break;
    default:
      break;
    }
     
  return 0;
}

static
int parse_sched (const char * ssched, sh_schedule_t * isched)
{
  char * p;
  char * copy;
  int    i = 0;
  size_t len;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
  char * saveptr;
#endif

  if (!ssched || !isched)
    return -1;

  len = strlen(ssched)+1;
#ifdef TESTONLY
  copy = calloc(1,len);                 /* testonly code */
#else
  copy = SH_ALLOC(len);
#endif
  sl_strlcpy(copy, ssched, len);

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
  p = strtok_r(copy, " \t", &saveptr); /* parse crontab-style schedule */
#else
  p = strtok(copy, " \t"); /* parse crontab-style schedule */
#endif

  if (!p)
    goto err; 
  if (parse_token(i, isched, p) == -1)
    goto err;

  for (i = 1; i < 5; ++i)
    {
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
      p = strtok_r(NULL, " \t", &saveptr); /* parse crontab-style schedule */
#else
      p = strtok(NULL, " \t"); /* parse crontab-style schedule */
#endif
      if (!p)
	goto err; 
      if (parse_token(i, isched, p) == -1)
	goto err;
    }

  isched->last_exec = (time_t)-1;
  isched->first     = 0;
  isched->next      = NULL;

#ifdef TESTONLY
  free(copy);
#else
  SH_FREE(copy);
#endif
  return 0;

 err:
#ifdef TESTONLY
  free(copy);
#else
  SH_FREE(copy);
#endif
  return -1;
}

int create_sched (const char * ssched, sh_schedule_t * isched)
{
  int j;

  if (!isched || !ssched)
    return -1;

  j = parse_sched(ssched, isched);

#ifdef TESTONLY
  if (j == 0)
    {
      int i;
      for (i = 0; i < 5; ++i)
	printf("%2d MIN  %3d  MAX  %3d  STEP  %3d\n", 
	       i, isched->max[i], isched->min[i], isched->step[i]);
      printf("MINSTEP   %7d\n", isched->min_step);
      printf("LASTEXEC  %7ld\n", (long) isched->last_exec);
    }
#endif

  return j;
}

/* #ifdef SCHEDULER_YES */
#endif

/**************************************************
 *
 * Schedule class - Test driver
 *
 **************************************************/
#ifdef TESTONLY

int main(int argc, char * argv[])
{
  sh_schedule_t isched;

  if (argc < 2)
    {
      fprintf(stderr, "Usage: %s 'schedule'\n", argv[0]);
      exit (1);
    }

  if (create_sched(argv[1], &isched) < 0)
    {
      fprintf(stderr, "Bad schedule <%s>\n", argv[1]);
      exit (1);
    }

  while (1 == 1)
    {
      if (test_sched(&isched))
	printf("EXECUTE  at: %s", ctime(&(isched.last_exec))); /* TESTONLY */
      sleep (1); /* TESTONLY */
    }
  return 0;
}
#endif
