/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2011 Rainer Wichmann                                      */
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

/* 0->1 for debug */ 
#if 0
#define SH_SUB_DBG 1
#endif

#ifndef NULL
#if !defined(__cplusplus)
#define NULL ((void*)0)
#else
#define NULL (0)
#endif
#endif


#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include "samhain.h"
#include "sh_pthread.h"

#ifndef HAVE_LSTAT
#define lstat stat
#endif

#define FIL__ _("sh_sub.c")

static pid_t sh_child_pid = -1;
static pid_t sh_wait_ret  =  1;

static int parent2child[2];
static int child2parent[2];

SH_MUTEX_STATIC(mutex_sub,      PTHREAD_MUTEX_INITIALIZER);
SH_MUTEX_STATIC(mutex_sub_work, PTHREAD_MUTEX_INITIALIZER);

static void wait_for_command();
static ssize_t sh_sub_read(int fd, void *buf, size_t count);

void sh_kill_sub()
{
  SH_MUTEX_LOCK(mutex_sub);

  if (sh_child_pid != -1)
    {
      int status;
#ifdef WCONTINUED
      int wflags = WNOHANG|WUNTRACED|WCONTINUED;
#else
      int wflags = WNOHANG|WUNTRACED;
#endif

      close (parent2child[1]);
      close (child2parent[0]);

      /* Let's be rude. */
      kill(sh_child_pid, SIGKILL);

      retry_msleep(1,0);

      if (sh_wait_ret == 0)
	sh_wait_ret = waitpid(          -1, &status, wflags);
      else
	sh_wait_ret = waitpid(sh_child_pid, &status, wflags);

      sh_child_pid = -1;
    }

  SH_MUTEX_UNLOCK(mutex_sub);
  return;
}

static int sh_create_sub()
{
  pid_t res;
  volatile int   retval = 0;

  SH_MUTEX_LOCK(mutex_sub);

#if !defined(O_NONBLOCK)
#if defined(O_NDELAY)
#define O_NONBLOCK  O_NDELAY
#else
#define O_NONBLOCK  0
#endif
#endif

  if (sh_child_pid == -1)
    {
      sigset_t signal_set_new;
      sigset_t signal_set_old;

      sigfillset ( &signal_set_new );
      sigemptyset( &signal_set_old );

      /* Create pipes. */
      res = pipe (parent2child);
      if (res == 0)
	res = pipe (child2parent);
      
      if (res != 0)
	goto out;

      SH_SETSIGMASK(SIG_BLOCK, &signal_set_new, &signal_set_old);

      res = fork();
      
      if (res == 0)
	{
	  /* Child process. */
#ifdef _SC_OPEN_MAX
	  int fdlimit = sysconf (_SC_OPEN_MAX);
#else
#ifdef OPEN_MAX
	  int fdlimit = OPEN_MAX;
#else
	  int fdlimit = _POSIX_OPEN_MAX;
#endif
#endif
	  int sflags, i, fd = 0;
	  struct sigaction act;

	  /* zero private information 
	   */
	  memset(skey, 0, sizeof(sh_key_t)); 

	  close (parent2child[1]);
	  close (child2parent[0]);
	  
	  sflags = fcntl(parent2child[0], F_GETFL, 0);
	  fcntl(parent2child[0], F_SETFL, sflags | O_NONBLOCK);
	  sflags = fcntl(child2parent[1], F_GETFL, 0);
	  fcntl(child2parent[1], F_SETFL, sflags | O_NONBLOCK);

	  /* close inherited file descriptors 
	   */
	  if (fdlimit < 0) 
	    fdlimit = 20;  /* POSIX lower limit */
	  while (fd < fdlimit)
	    {
	      if (fd != parent2child[0] && fd != child2parent[1])
		close(fd);
	      ++fd;
	    }

	  /*
	  for (i = 0; i < 3; ++i)
	    {
	      if ( fcntl(i, F_GETFL, 0) == (-1))
		(void) open(_("/dev/null"), O_RDWR, 0);
	    }
	  */

	  /* reset signal handling 
	   */
	  act.sa_handler = SIG_DFL;
	  act.sa_flags   = 0;
	  sigemptyset( &act.sa_mask );
	  
	  for (i = 1; i < NSIG; ++i)
	    sigaction(i, &act, NULL);
	  SH_SETSIGMASK(SIG_UNBLOCK, &signal_set_new, NULL);

	  wait_for_command();
	  
	  _exit(0);
	}
      else if (res > 0)
	{
	  /* Parent process. */
	  int sflags;

	  SH_SETSIGMASK(SIG_SETMASK, &signal_set_old, NULL);

	  close (parent2child[0]);
	  close (child2parent[1]);
	  
	  sflags = fcntl(parent2child[1], F_GETFL, 0);
	  fcntl(parent2child[1], F_SETFL, sflags | O_NONBLOCK);
	  sflags = fcntl(child2parent[0], F_GETFL, 0);
	  fcntl(child2parent[0], F_SETFL, sflags | O_NONBLOCK);

	  sh_child_pid = res;
	}
      else
	{
	  /* Failure. */

	  SH_SETSIGMASK(SIG_SETMASK, &signal_set_old, NULL);

	  close (parent2child[0]);
	  close (parent2child[1]);

	  close (child2parent[0]);
	  close (child2parent[1]);
	  
	  retval = -1;
	}
    }

 out:
  ; /* 'label at end of compound statement' */
  SH_MUTEX_UNLOCK(mutex_sub);
  return retval;
}

#define  SH_SUB_BUF (PIPE_BUF-1)
struct sh_sub_in {
  char   command;
  char   path[SH_SUB_BUF];
};

struct sh_sub_out {
  int retval;
  int errnum;
  struct stat sbuf;
};

#define SH_COM_STAT  0
#define SH_COM_LSTAT 1

static ssize_t sh_sub_write(int fd, const void *buf, size_t count)
{
  const char * mbuf = (const char *) buf;
  ssize_t rcount;
  int ttl = 5; /* 0, 1, 9, 81, 729 millisec */
  int tti = 1; 

  do {

    rcount = write(fd, mbuf, count);
    if (rcount > 0) 
      {
	count -= rcount; mbuf += rcount; --ttl;
      }

    if (count > 0)
      {
	if (ttl > 0)
	  {
	    retry_msleep(0, tti);
	    tti *= 9;
	  }
	else
	  {
	    return -1;
	  }
      }
  } while (count > 0 && (errno == EAGAIN || errno == EWOULDBLOCK));

  if (count > 0)
    return -1;
  return 0;
}

static void wait_for_command()
{
  int               ret;
  struct pollfd     fds;
  struct sh_sub_in  inbuf;
  struct sh_sub_out outbuf;

  fds.fd     = parent2child[0];
  fds.events = POLLIN;

  do {

    do {
      ret = poll(&fds, 1, -1);
    } while (ret < 0 && errno == EINTR);

    if (ret > 0)
      {
	ret = sh_sub_read(parent2child[0], &inbuf, sizeof(inbuf));

	if (ret == 0)
	  {
	    if (inbuf.command == SH_COM_LSTAT)
	      {
		do { 
		  outbuf.retval = lstat(inbuf.path, &(outbuf.sbuf)); 
		} while (outbuf.retval < 0 && errno == EAGAIN);
	      }
	    else
	      {
		do { 
		  outbuf.retval = stat(inbuf.path, &(outbuf.sbuf)); 
		} while (outbuf.retval < 0 && errno == EAGAIN);
	      }

	    outbuf.errnum = errno;

	    ret = sh_sub_write(child2parent[1], &outbuf, sizeof(outbuf));
	    if (ret < 0)
	      {
		return;
	      }
	  }
	else /* sh_sub_read() < 0 */
	  {
	    return;
	  }
      }
  } while (1 == 1);
}

#ifndef ETIMEDOUT
#define ETIMEDOUT EIO
#endif

static ssize_t sh_sub_read(int fd, void *buf, size_t count)
{
  char * mbuf = (char *) buf;
  ssize_t rcount;
  int ttl = 5; /* 0, 1, 9, 81, 729 millisec */
  int tti = 1; 

  do {
    rcount = read(fd, mbuf, count);

    if (rcount > 0) 
      {
	count -= rcount; mbuf += rcount; --ttl;
      }

    if (count > 0)
      {
	if (ttl > 0)
	  {
	    retry_msleep(0, tti);
	    tti *= 9;
	  }
	else
	  {
	    if (rcount >= 0) 
	      errno = ETIMEDOUT;
	    return -1;
	  }
      }
  } while (count > 0 && 
	   (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR));

  if (count > 0)
    return -1;

  return 0;
}

#ifdef SH_SUB_DBG
#include <stdarg.h>
static void debug_it (const char *fmt, ...)
{
  char msg[256];
  va_list ap;

  int fd = open("debug.it", O_CREAT|O_WRONLY|O_APPEND, 0666);

  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);  /* flawfinder: ignore */
  va_end(ap);

  write(fd, msg, strlen(msg));
  write(fd, "\n", 1);
  close(fd);
  return;
}
#endif

static int sh_sub_stat_int(const char *path, struct stat *buf, char command)
{
  int retval;
  volatile int sflag = 0;
  struct sh_sub_in  inbuf;
  struct sh_sub_out outbuf;
  struct pollfd     pfds;

  size_t len = strlen(path) + 1;

  if (len > SH_SUB_BUF)
    {
      if (command == SH_COM_LSTAT)
	{
	  do { 
	    retval = lstat(path, buf); 
	  } while (retval < 0 && errno == EAGAIN);

	  return retval;
	}
      else
	{
	  do { 
	    retval = stat(path, buf); 
	  } while (retval < 0 && errno == EAGAIN);

	  return retval;
	}
    }

  sl_strlcpy(inbuf.path, path, SH_SUB_BUF);
  inbuf.command = command;

 start:

#ifdef SH_SUB_DBG
  debug_it("%d sh_child_pid %d\n", (int)getpid(), (int) sh_child_pid);
#endif

  if (sh_child_pid == -1)
    sh_create_sub();

#ifdef SH_SUB_DBG
  debug_it("%d stat_sub %s (%d)\n", (int)getpid(), inbuf.path, (int) sh_child_pid);
#endif

  SH_MUTEX_LOCK(mutex_sub_work);

  retval = sh_sub_write(parent2child[1], &inbuf, sizeof(inbuf));
  if (retval < 0)
    {
      int error = errno;
      sh_kill_sub();
      errno = error;
      sflag = 1;
      goto end;
    }

#ifdef SH_SUB_DBG
  debug_it("%d stat_sub polling..\n", (int)getpid());
#endif

  pfds.fd     = child2parent[0];
  pfds.events = POLLIN;

  do {
    retval = poll(&pfds, 1, 300 * 1000);
  } while (retval < 0 && errno == EINTR);

  if (retval <= 0)
    {
      int error = errno;
      sh_kill_sub();
      errno = (retval == 0) ? ETIMEDOUT : error;
      sflag = -1;
      goto end;
    }

#ifdef SH_SUB_DBG
  debug_it("%d stat_sub reading..\n", (int)getpid());
#endif

  retval = sh_sub_read (child2parent[0], &outbuf, sizeof(outbuf));
  if (retval < 0)
    {
      int error = errno;
      sh_kill_sub();
      errno = error;
      sflag = 1;
      goto end;
    }

 end:
  ; /* 'label at end of compound statement' */
  SH_MUTEX_UNLOCK(mutex_sub_work);

  if      (sflag == 0)
    {
#ifdef SH_SUB_DBG
      debug_it("%d stat_sub done..\n", (int)getpid());
#endif
      memcpy(buf, &(outbuf.sbuf), sizeof(struct stat));
      errno = outbuf.errnum;
      return outbuf.retval;
    }
  else if (sflag == 1)
    {
#ifdef SH_SUB_DBG
      debug_it("%d stat_sub error..\n", (int)getpid());
#endif
      /* could not read, thus subprocess may have gone */
      sflag = 0;
      goto start;
    }

  return -1;
}

int sh_sub_stat (const char *path, struct stat *buf)
{
  return sh_sub_stat_int(path, buf, SH_COM_STAT);
}

int sh_sub_lstat(const char *path, struct stat *buf)
{
  return sh_sub_stat_int(path, buf, SH_COM_LSTAT);
}

