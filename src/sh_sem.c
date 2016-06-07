/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999, 2000, 2015 Rainer Wichmann                          */
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
#include <stdlib.h>
#include <stdio.h>

#if defined(HAVE_SYS_SEM_H) && defined(HAVE_UNISTD_H)
#include "samhain.h"
#include "sh_sem.h"
#include "sh_error_min.h"

#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <unistd.h>

#undef  FIL__
#define FIL__  _("sh_sem.c")

typedef enum {
  exit_ok   = 0,
  exit_fail = 1,
  exit_time = 2,
  exit_err  = 3
} sh_estat;

#if 0
/* FreeBSD 6.1 defines this in <sys/sem.h> too...     */
#if defined(__GNU_LIBRARY__) && !defined(_SEM_SEMUN_UNDEFINED)
/* union semun is defined by including <sys/sem.h>    */
#else
/* according to X/OPEN we have to define it ourselves */
union semun {
  int val;
  struct semid_ds *buf;
  unsigned short *array;
};
#endif
#endif

#define SH_SEMVMX 32767

static int get_semaphore (void) 
{
  key_t  key = ftok(DEFAULT_DATAROOT, '#');
  int    semid;

  if (key < 0)
    return -1;
  semid = semget (key, 0, IPC_PRIVATE);
  if (semid < 0)
    return -1;
  return semid;
}

static void sem_purge(int sem_id)
{
  if (sem_id != -1)
    semctl(sem_id, 0, IPC_RMID, (int)0);
  return;
}

static void sem_purge_stale()
{
  int stale_ID = get_semaphore();
  if (stale_ID != -1)
    sem_purge(stale_ID);
  return;
}

static int report_err(int errnum, char * file, int line, char * func)
{
  char errbuf[SH_ERRBUF_SIZE];
  sh_error_message(errnum, errbuf, sizeof(errbuf));
  sh_error_handle((-1), file, line, errnum, MSG_E_SUBGEN,
		  errbuf, func);
  return -1;
}

static int init_semaphore (int nsems) 
{
  int    i;
  mode_t mask;
  int    semid;
  int    errnum;
  key_t  key = ftok(DEFAULT_DATAROOT, '#');

  if (key < 0)
    return report_err(errno, FIL__, __LINE__, _("ftok"));

  mask   = umask(0);
  semid  = semget (key, nsems, IPC_CREAT | IPC_EXCL | 0660);
  errnum = errno;
  umask(mask);

  if (semid < 0)
    return report_err(errnum, FIL__, __LINE__, _("semget"));
  for (i=0; i<nsems; ++i)
    if (semctl (semid, i, SETVAL, (int) 1) == -1)
      return report_err(errnum, FIL__, __LINE__, _("semclt"));
  return semid;
}


static int sem_set(int semid, int sem_no, int val)
{
  if (semid < 0)
    return -1;
  if (semctl (semid, sem_no, SETVAL, val) == -1)
    return -1;
  return 0;
}

static int sem_get(int semid, int sem_no)
{
  if (semid < 0)
    return -1;
  return semctl (semid, sem_no, GETVAL, (int) 0);
}


static int sem_change(int semid, int sem_no, int amount)
{
  struct sembuf tmp;
  int retval;

  tmp.sem_num = sem_no;
  tmp.sem_flg = SEM_UNDO;
  tmp.sem_op  = amount;

  do { retval = semop(semid, &tmp, 1);
  } while (retval == -1 && errno == EINTR);

  return retval;
}

static int sem_try_change(int semid, int sem_no, int amount)
{
  struct sembuf tmp;
  int retval;

  tmp.sem_num = sem_no;
  tmp.sem_flg = IPC_NOWAIT|SEM_UNDO;
  tmp.sem_op  = amount;

  do { retval = semop(semid, &tmp, 1);
  } while (retval == -1 && errno == EINTR);

  return retval;
}

#define SH_SEMAPHORE_EXTERN(S)  int S = get_semaphore()
#define SH_SEMAPHORE_INIT(S, N) int S = init_semaphore(N)
#define SH_SEMAPHORE_TRYLOCK(S) sem_try_change(S, 0, SH_SEM_LOCK)
#define SH_SEMAPHORE_LOCK(S)    sem_change(S, 0, SH_SEM_LOCK)
#define SH_SEMAPHORE_UNLOCK(S)  sem_change(S, 0, SH_SEM_UNLOCK)
#define SH_SEMAPHORE_PURGE(S)   sem_purge(S)

static int sem_ID = -1;

void sh_sem_open()
{
  if (sh.flag.isdaemon != S_TRUE)
    return;

  if (sem_ID < 0)
    {
      sem_purge_stale();
      sem_ID = init_semaphore(2);
      sem_set(sem_ID, 1, (int) 0);
    }

  return;
}

void sh_sem_trylock()
{
  SH_SEMAPHORE_TRYLOCK(sem_ID);
  return;
}

void sh_sem_lock()
{
  SH_SEMAPHORE_LOCK(sem_ID);
  return;
}

void sh_sem_unlock (long val)
{
  if (val >= 0)
    {
      val = (val > SH_SEMVMX) ? SH_SEMVMX : val; /* signed short int maxval */
      sem_set(sem_ID, 1, (int) val);
    }
  SH_SEMAPHORE_UNLOCK(sem_ID);
  return;
}

void sh_sem_close()
{
  SH_SEMAPHORE_PURGE(sem_ID);
  return;
}

static volatile int alarm_triggered = 0;
static void alarm_handler(int sig)
{
  (void) sig;
  alarm_triggered = 1;
  return;
}

int  sh_sem_wait(const char * wait)
{
  int rc, flag = 0;
  int time_wait = atoi(wait);

  SH_SEMAPHORE_EXTERN(sem_id);

  if (time_wait < 0) { time_wait *= (-1); time_wait -= 1; flag = 1; }
  if (time_wait < 0 || time_wait > (24*3600))
    {
      fprintf(stderr, _("Invalid argument <%d>.\n"), time_wait);
      _exit(exit_err);
    }
  if (sem_id == -1)
    {
      if (flag && errno == ENOENT) { 
	do { retry_msleep(1, 0); rc = get_semaphore(); } while (rc == -1);
	sem_id = rc;
      } else {
	if (errno == ENOENT) {
	  fputs(_("Samhain IPC not initialized.\n"), stderr);
	  _exit(exit_err); }
	else if (errno == EACCES)
	  fputs(_("No permission to access Samhain IPC.\n"), stderr);
	_exit(exit_err);
      }
    }

  retry_msleep(0, 50);

  if (time_wait > 0)
    {
      signal(SIGALRM, alarm_handler);
      alarm(time_wait);
    }
  rc = SH_SEMAPHORE_LOCK(sem_id);
  if (rc == -1 && errno == EINTR)
    {
      if (alarm_triggered)
        {
	  fputs(_("Timeout on wait.\n"), stderr);
	  _exit(exit_time);
        }
    }
  else if (rc == -1)
    {
      if (errno == EACCES)
	fputs(_("No permission to access Samhain IPC.\n"), stderr);
      else
	perror(_("semop"));
      _exit(exit_err);
    }

  rc = sem_get(sem_id, 1);
  if (rc == 0)    
    _exit(exit_ok);
  else if (rc == SH_SEMVMX)
    fprintf(stdout, _("%d or more issues reported\n"), rc);
  else
    fprintf(stdout, _("%d issues reported\n"), rc);
  _exit(exit_fail);
}

#else

void sh_sem_open()    { return; }
void sh_sem_trylock() { return; }
void sh_sem_lock()    { return; }
void sh_sem_unlock(long val)  { (void) val; return; }
void sh_sem_close()   { return; }
int  sh_sem_wait(const char * wait)
{
  (void) wait;
  fputs(_("Function not implemented (OS does not support SysV semaphores).\n"),
	stderr);
  exit(exit_err);
}

#endif /* defined(HAVE_SYS_SEM_H) && defined(HAVE_UNISTD_H) */
