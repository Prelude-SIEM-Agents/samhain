#include "config_xor.h"

#include "sh_pthread.h"

#ifdef HAVE_PTHREAD

#include <signal.h>
#include "sh_calls.h"
#include "sh_modules.h"
extern volatile  int      sh_thread_pause_flag;

SH_MUTEX_INIT(mutex_skey,         PTHREAD_MUTEX_INITIALIZER);
SH_MUTEX_INIT(mutex_resolv,       PTHREAD_MUTEX_INITIALIZER);
SH_MUTEX_INIT(mutex_pwent,        PTHREAD_MUTEX_INITIALIZER);
SH_MUTEX_INIT(mutex_readdir,      PTHREAD_MUTEX_INITIALIZER);
SH_MUTEX_INIT(mutex_thread_nolog, PTHREAD_MUTEX_INITIALIZER);

int sh_pthread_setsigmask(int how, const void *set, void *oldset)
{
  return pthread_sigmask(how, (const sigset_t *)set, (sigset_t *)oldset);
}

void sh_pthread_mutex_unlock (void *arg)
{
  (void) pthread_mutex_unlock ((pthread_mutex_t *)arg);
  return;
}

int sh_pthread_init_threadspecific(void)
{
  int rc = 0;
#ifdef SH_STEALTH
  do {
    extern int sh_g_thread(void);

    rc = sh_g_thread();
  } while (0);
#endif

  return rc;
}


/* 
 *  ----  Utilities for modules  ----
 */

/* MODULES: init()
 *
 * #ifdef HAVE_PTHREAD
 *  if (arg != NULL)
 *    {
 *      if (0 == sh_pthread_create(sh_threaded_module_run, (void *)arg))
 *	  return SH_MOD_THREAD;
 *      else
 *	  return SH_MOD_FAILED;
 *    }
 * #else
 *  return sh_utmp_init_internal();
 * #endif
 *
 *
 *          sh_threaded_module_run(module_struct) 
 *             -- calls internal init, 
 *             -- polls timer, 
 *             -- runs module check,
 *             -- runs sh_pthread_testcancel()
 *             -- returns (return == exit)
 */

#define SH_NUM_THREADS 16
static pthread_t threads[SH_NUM_THREADS];
static int       ithread[SH_NUM_THREADS];
static pthread_mutex_t  create_mutex = PTHREAD_MUTEX_INITIALIZER;

int sh_pthread_create(void *(*start_routine)(void*), void *arg)
{
  int rc, nthread = 1;
  sigset_t signal_set;
  int retval = 0;

  pthread_mutex_lock(&create_mutex);

  /* block all signals 
   */
  sigfillset( &signal_set );
#if defined(SCREW_IT_UP)
  /*
   * raise(SIGTRAP) sends to same thread, like 
   * pthread_kill(pthread_self(), sig); so we need to unblock the
   * signal. 
   */
  sigdelset( &signal_set, SIGTRAP );
#endif 
  pthread_sigmask( SIG_BLOCK, &signal_set, NULL );

  /* find a free slot in threads[]
   */
  while (nthread < SH_NUM_THREADS) 
    {
      if (ithread[nthread] == 0)
	break;
      ++nthread;
      if (nthread == SH_NUM_THREADS)
	{
	  retval = -1;
	  goto err_out;
	}
    } 

  rc = pthread_create(&threads[nthread], NULL, start_routine, arg);
  if (rc != 0)
    {
      retval = -1;
      goto err_out;
    }

  ithread[nthread] = 1;

 err_out:
  pthread_sigmask( SIG_UNBLOCK, &signal_set, NULL );
  pthread_mutex_unlock(&create_mutex);
  return retval;
}

int sh_pthread_cancel_all()
{
  int i;
  int ret = 0;

  SH_MUTEX_LOCK(create_mutex);

  for (i = 1; i < SH_NUM_THREADS; ++i)
    {
      if (ithread[i] != 0)
	if (0 != pthread_cancel(threads[i]))
	  ithread[i] = 0;
    }

  for (i = 1; i < SH_NUM_THREADS; ++i)
    {
      if (ithread[i] != 0)
	pthread_join(threads[i], NULL);
      ithread[i] = 0;
    }

  SH_MUTEX_UNLOCK(create_mutex);
  return ret;
}

/* ---- Utility functions for modules ----
 */

#undef  S_TRUE
#define S_TRUE    1
#undef  S_FALSE
#define S_FALSE   0

void sh_threaded_module_cleanup(void *arg)
{
  sh_mtype * this_module = (sh_mtype *) arg;
  this_module->mod_cleanup();
  this_module->initval = -1;
  return;
}

void * sh_threaded_module_run(void *arg)
{
  sh_mtype * this_module = (sh_mtype *) arg;

  /* First we lock the module. This ensures that it cannot be
   * run twice.
   */
  pthread_cleanup_push(sh_pthread_mutex_unlock, (void*) &(this_module->mod_mutex));
  pthread_mutex_lock(&(this_module->mod_mutex));

  if (0 == sh_pthread_init_threadspecific())
    {

      if (0 == this_module->mod_init(NULL))
	{
	  pthread_cleanup_push(sh_threaded_module_cleanup, arg);

	  while (1)
	    {
	      if (sh_thread_pause_flag != S_TRUE)
		{
		  this_module->flags &= ~SH_MODFL_ISPAUSED;
		  
		  if (0 != this_module->mod_timer(time(NULL)))
		    {
		      /* If module has been de-activated on reconfigure,
		       * mod_check() must return non-zero.
		       * The mod_cleanup() routine must then enable the 
		       * module to be re-activated eventually.
		       */
		      if (0 != this_module->mod_check())
			break;
		      pthread_testcancel();
		    }
		}
	      else
		{
		  this_module->flags |= SH_MODFL_ISPAUSED;
		}
	      if (0 == (SH_MODFL_NOTIMER & this_module->flags) ||
		  sh_thread_pause_flag == S_TRUE)
		retry_msleep(1,0);
	    }

	  pthread_cleanup_pop(1); /* notreached,but required */
	}
    }

  pthread_cleanup_pop(1);

  return NULL;
}


/*
 *  ----  Implementation of recursive mutexes from libxml2  ----
 */
#if !defined(HAVE_PTHREAD_MUTEX_RECURSIVE)
/**
 * libxml2 threads.c: set of generic threading related routines 
 *
 * Gary Pennington <Gary.Pennington@uk.sun.com>
 * daniel@veillard.com
 
 * Except where otherwise noted in the source code (e.g. the files hash.c,
 * list.c and the trio files, which are covered by a similar licence but
 * with different Copyright notices) all the files are:
 *
 *    Copyright (C) 1998-2003 Daniel Veillard.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is fur-
 * nished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FIT-
 * NESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * DANIEL VEILLARD BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CON-
 * NECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Except as contained in this notice, the name of Daniel Veillard shall not
 * be used in advertising or otherwise to promote the sale, use or other deal-
 * ings in this Software without prior written authorization from him.
 */

/* Modified NewRMutex -> InitRMutex. We use a static structure, rather than 
 * allocating one. Also dropped code for non-POSIX OSes.
 */
void sh_InitRMutex(struct sh_RMutex * tok)
{
  pthread_mutex_init(&tok->lock, NULL);
  tok->held = 0;
  tok->waiters = 0;
  pthread_cond_init(&tok->cv, NULL);

  return;
}

void sh_RMutexLock(struct sh_RMutex * tok)
{
  if (tok == NULL)
    return;

  pthread_mutex_lock(&tok->lock);
  if (tok->held) {
    if (pthread_equal(tok->tid, pthread_self())) {
      tok->held++;
      pthread_mutex_unlock(&tok->lock);
      return;
    } else {
      tok->waiters++;
      while (tok->held)
	pthread_cond_wait(&tok->cv, &tok->lock);
      tok->waiters--;
    }
  }
  tok->tid = pthread_self();
  tok->held = 1;
  pthread_mutex_unlock(&tok->lock);
}

void sh_RMutexUnlock(void * arg)
{
  struct sh_RMutex * tok = (struct sh_RMutex *) arg;

  if (tok == NULL)
    return;
    
  pthread_mutex_lock(&tok->lock);
  tok->held--;
  if (tok->held == 0) {
    if (tok->waiters)
      pthread_cond_signal(&tok->cv);
    tok->tid = 0;
  }
  pthread_mutex_unlock(&tok->lock);
}
#endif

#else

#include <signal.h>

int sh_pthread_setsigmask(int how, const void *set, void *oldset)
{
  return sigprocmask(how, (const sigset_t *)set, (sigset_t *)oldset);
}


#endif
