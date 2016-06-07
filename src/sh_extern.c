/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2000,2004 Rainer Wichmann                                 */
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
#include <string.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

/* replace #if 0 by #if 1 and set an appropriate path in front of '/pdbg.'
 * for debugging
 */
#if 0
#define PDGBFILE "/pdbg."
#endif


#if defined(PDGBFILE)
static FILE * pdbg = NULL;
static FILE * pdbgc = NULL;
#define PDBG_OPEN    if (pdbg == NULL) pdbg = fopen(PDGBFILE"main",  "a")  
#define PDBG_CLOSE   sl_fclose (FIL__, __LINE__, pdbg); pdbg = NULL
#define PDBG(arg)    fprintf(pdbg,  "PDBG: step %d\n", arg); fflush(pdbg)
#define PDBG_D(arg)  fprintf(pdbg,  "PDBG: %d\n", arg); fflush(pdbg)
#define PDBG_S(arg)  fprintf(pdbg,  "PDBG: %s\n", arg); fflush(pdbg)

#define PDBGC_OPEN   if (pdbgc == NULL) pdbgc = fopen(PDGBFILE"child", "a")  
#define PDBGC_CLOSE  sl_fclose (FIL__, __LINE__, pdbgc); pdbgc = NULL
#define PDBGC(arg)   fprintf(pdbgc, "PDBGC: step %d\n", arg); fflush(pdbgc)
#define PDBGC_D(arg) fprintf(pdbgc, "PDBGC: %d\n", arg); fflush(pdbgc)
#define PDBGC_S(arg) fprintf(pdbgc, "PDBGC: %s\n", arg); fflush(pdbgc)
#else
#define PDBG_OPEN    
#define PDBG_CLOSE   
#define PDBG(arg)    
#define PDBG_D(arg)  
#define PDBG_S(arg)  
#define PDBGC_OPEN    
#define PDBGC_CLOSE   
#define PDBGC(arg)    
#define PDBGC_D(arg)  
#define PDBGC_S(arg)  
#endif


#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/wait.h>

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
#include "sh_utils.h"
#include "sh_unix.h"
#include "sh_tiger.h"
#include "sh_extern.h"
#include "sh_calls.h"
#include "sh_filter.h"
#define SH_NEED_PWD_GRP 1
#include "sh_static.h"


#undef  FIL__
#define FIL__  _("sh_extern.c")

extern int get_the_fd (SL_TICKET ticket);

/*
 * -- generic safe popen
 */

int sh_ext_popen (sh_tas_t * task)
{
  long status = 0;
  int    flags;
  char * tmp;
  char * tmp2;
  int    errnum;
  int    pipedes[2];
  FILE * outf = NULL;
  char * envp[1];
  char * argp[2];

  char * errfile;
  char errbuf[SH_ERRBUF_SIZE];

  static int some_error = 0;

#if defined (__linux__)
  SL_TICKET   fd  = -1;
  char        pname[128];
  int         pfd = -1;
#endif

  SL_ENTER(_("sh_ext_popen"));

  /* Linux, HP-UX and FreeBSD will happily accept envp = argp = NULL
   * (newer Linuxes (gcc 4.4.4) warn on argp == NULL, but accept it,
   * as reported by T. Luettgert)
   * Solaris (and probably some other Unices) 
   *         needs a valid *envp[] with envp[0] = NULL;
   *         and similarly for argp
   * OpenBSD finally needs non-null argp[0] ...
   */
  argp[0] = task->command;
  argp[1] = NULL;
  envp[0] = NULL;

  /* 
   * --  check whether path is trustworthy
   */
  status = sl_trustfile(task->command, NULL, NULL);
#if 0
  if ((uid_t) -1 != task->trusted_users[0])
    {
      status = sl_trustfile(task->command, task->trusted_users, NULL);
    }
#endif

  PDBG_OPEN;
  PDBG_D( (int) status);

  if ( SL_ENONE != status)
    { 
      PDBG_S("SL_ENONE != status");
      if (some_error == 0)
	{
	  tmp  = sh_util_safe_name (task->command);
	  errfile = sl_trust_errfile();
	  if (errfile[0] != '\0')
	    {
	      tmp2  = sh_util_safe_name (sl_trust_errfile());
	      sh_error_handle((-1), FIL__, __LINE__, status, MSG_E_TRUST2,
			      sl_error_string((int)status), tmp, tmp2);
	      SH_FREE(tmp2);  
	    }
	  else
	    {
	      sh_error_handle((-1), FIL__, __LINE__, status, MSG_E_TRUST1,
			      sl_error_string((int)status), tmp);
	    }
	  SH_FREE(tmp);
	}
      some_error = 1;
      SL_RETURN ((-1), _("sh_ext_popen"));
    }

  PDBG(1);

  /* 
   * --  check whether the checksum is correct; with linux emulate fdexec
   */
#if ( !defined(__linux__) || ( defined(__linux__) && defined(HAVE_PTHREAD)) ) && !defined(SL_DEBUG)
  if (task->checksum[0]  != '\0')
    {
      char hashbuf[KEYBUF_SIZE];
      PDBG_S("checksum test");
      if (0 != sl_strcmp(task->checksum, 
			 sh_tiger_hash (task->command, TIGER_FILE, TIGER_NOLIM,
					hashbuf, sizeof(hashbuf))
			 )
	  )
	{
	  PDBG_S("checksum mismatch");
	  if (some_error == 0)
	    {
	      tmp  = sh_util_safe_name (task->command);
	      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_HASH, tmp);
	      SH_FREE(tmp);
	    }
	  some_error = 1;
	  SL_RETURN ((-1), _("sh_ext_popen"));
 	}
    }
#endif

  some_error = 0;

  PDBG(2);

  /* 
   * -- Create the pipe 
   */
  if (aud_pipe(FIL__, __LINE__, pipedes) < 0) 
    {
      PDBG_S("pipe() failure");
      errnum = errno;
      sh_error_handle((-1), FIL__, __LINE__, errnum, MSG_E_SUBGEN, 
		      sh_error_message(errnum, errbuf, sizeof(errbuf)), _("pipe"));
      SL_RETURN ((-1), _("sh_ext_popen"));
    }

  PDBG(3);

  /* 
   * -- Flush streams and fork 
   */
  fflush (NULL);

  task->pid = aud_fork(FIL__, __LINE__);

  if (task->pid == (pid_t) - 1) 
    {
      PDBG_S("fork() failure");
      /*@-usedef@*/
      (void) sl_close_fd(FIL__, __LINE__, pipedes[0]);
      (void) sl_close_fd(FIL__, __LINE__, pipedes[1]);
      /*@+usedef@*/
      errnum = errno;
      sh_error_handle((-1), FIL__, __LINE__, errnum, MSG_E_SUBGEN, 
		      sh_error_message(errnum, errbuf, sizeof(errbuf)), _("fork"));
      SL_RETURN ((-1), _("sh_ext_popen"));
    }
  
  PDBG(4);

  if (task->pid == (pid_t) 0) 
    {
      /* 
       * -- fork again, if requested
       */
      if (S_TRUE == task->fork_twice)
	{
	  task->pid = fork();

	  if (task->pid == (pid_t) - 1) 
	    {
	      _exit (EXIT_FAILURE);
	    }
	}

      if (task->pid == (pid_t) 0)
	{
	  int val_return;

	  PDBGC_OPEN;
	  PDBGC(1);

	  /*
	   * -- grandchild - make write side of the pipe stdin 
	   */
	  if (task->rw == 'w')
	    {
	      do {
		val_return = dup2 (pipedes[STDIN_FILENO], STDIN_FILENO);
	      } while (val_return < 0 && errno == EINTR);

	      if (val_return < 0)
		_exit(EXIT_FAILURE);
	    }
	  else
	    {
	      do {
		val_return = dup2 (pipedes[STDOUT_FILENO], STDOUT_FILENO);
	      } while (val_return < 0 && errno == EINTR);

	      if (val_return < 0)
		_exit(EXIT_FAILURE);
	    }
	  PDBGC(2);
	    
	  
	  /* close the pipe descriptors 
	   */
	  (void) sl_close_fd   (FIL__, __LINE__, pipedes[STDIN_FILENO]);
	  (void) sl_close_fd   (FIL__, __LINE__, pipedes[STDOUT_FILENO]);
	  
	  /* don't leak file descriptors
	   */
#if !defined(PDGBFILE)
	  sh_unix_closeall (3, task->com_fd, S_TRUE); /* in child process */
#endif

	  /* drop root privileges, if possible && requested
	   */
	  if (task->privileged == 0 && 0 == getuid())
	    {
	      PDBGC_S("privileged");

	      /* zero priv info
	       */
	      memset(skey, 0, sizeof(sh_key_t));

	      if (setgid((gid_t) task->run_user_gid) != 0)
		_exit(EXIT_FAILURE);
	      if (setuid((uid_t) task->run_user_uid) != 0)
		_exit(EXIT_FAILURE);

	      /* make sure we cannot get root again
	       */
	      if (setuid(0) >= 0)
		_exit(EXIT_FAILURE);
	    }
	  
	  PDBGC(3);
	  (void) fflush(NULL);
	  
	  if (task->rw == 'w')
	    {
	      PDBGC_S("w");
	      (void) fcntl  (STDOUT_FILENO, F_SETFD, FD_CLOEXEC);
	      (void) fcntl  (STDERR_FILENO, F_SETFD, FD_CLOEXEC);
	      /*
	      freopen(_("/dev/null"), "r+", stderr);
	      freopen(_("/dev/null"), "r+", stdout);
	      */
	    }
	  else
	    {
	      PDBGC_S("r");
	      do {
		val_return = dup2 (STDOUT_FILENO, STDERR_FILENO);
	      } while (val_return < 0 && errno == EINTR);

	      (void) fcntl  (STDIN_FILENO, F_SETFD, FD_CLOEXEC);
	      /*
	      freopen(_("/dev/null"), "r+", stdin);
	      */
	    }
	  
	  PDBGC(4);
	  
	  
#if defined(__linux__)
	  /* 
	   * --  emulate an fdexec with checksum testing
	   */

#if !defined(HAVE_PTHREAD)
	  if (task->checksum[0]  != '\0')
#endif
	    {
	      PDBGC_S("fexecve");
	      if (task->com_fd != (-1))
		{
		  do {
		    val_return = dup (task->com_fd);
		  } while (val_return < 0 && errno == EINTR);
		  pfd = val_return;
		  if (pfd < 0)
		    {
		      PDBGC_S("fexecve: dup failed");
		      _exit(EXIT_FAILURE);
		    }
		}
#if !defined(HAVE_PTHREAD)
	      else
		{
		  char hashbuf[KEYBUF_SIZE];

		  fd = 
		    sl_open_read(FIL__, __LINE__, task->command, 
				 task->privileged==0 ? SL_NOPRIV : SL_YESPRIV);

		  if (0 != sl_strcmp(task->checksum, 
				     sh_tiger_hash (task->command, 
						    fd, TIGER_NOLIM, hashbuf, sizeof(hashbuf))))
		    {
		      PDBGC_S("fexecve: checksum mismatch");
		      sl_close(fd);
		      _exit(EXIT_FAILURE);
		    }

		  pfd = get_the_fd(fd);

		  do {
		    val_return = dup (pfd);
		  } while (val_return < 0 && errno == EINTR);
		  pfd = val_return;

		  sl_close(fd);
		  fd = -1;

		  if (pfd < 0)
		    {
		      PDBGC_S("fexecve: dup (2) failed");
		      _exit(EXIT_FAILURE);
		    }
		}
#endif
              
	      PDBGC(5);
	      /* Cannot use sprintf because of deadlock in malloc/free */
	      {
		static char digit[] = "0123456789";
		char str0[128];
		char str1[128];
		int ival = pfd;
		unsigned int n = 0;
		unsigned int m = 0;

		if (ival < 0) ival = -ival;
		do {
		  str0[n] = digit[ival % 10];
		  ++n;
		  ival /= 10;
		} while (ival);

		if (pfd < 0)
		  {
		    str0[n] = '-';
		    ++n;
		  }
		str0[n] = '\0';
		str1[n] = '\0';
		while (n > 0)
		  {
		    str1[m] = str0[n-1];
		    ++m; --n;
		  }
		sl_strlcpy(pname, _("/proc/self/fd/"), sizeof(pname));
		sl_strlcat(pname, str1, sizeof(pname));
	      }
              if (access(pname, R_OK|X_OK) == 0) /* flawfinder: ignore */
		{
		  PDBGC(6);
		  PDBGC_CLOSE;
		  fcntl  (pfd, F_SETFD, FD_CLOEXEC);
		  do {
		    val_return = execve (pname, 
					 (task->argc == 0) ? argp : task->argv, 
					 (task->envc == 0) ? NULL : task->envv
					 );
		  } while (val_return < 0 && errno == EINTR);
		  
		  errnum = errno;
		  PDBGC_OPEN;
		  PDBGC_S(strerror(errnum));
		  PDBGC_S(task->command);
		  PDBGC_S("fexecve: failed");
		  PDBGC_CLOSE;
		  /* failed 
		   */
		  _exit((errnum == 0) ? (EXIT_SUCCESS) : (EXIT_FAILURE));
              }
	      PDBGC_S("fexecve: not working");
	      /* 
	       * procfs not working, go ahead; checksum is tested already
	       */
	      if (fd != -1)
		sl_close(fd);
	      else if (pfd != -1)
		sl_close_fd(FIL__, __LINE__, pfd);
	    }
#endif

	  PDBGC_S(" -- non fexecve --");
	  /* 
	   * --  execute path if executable
	   */
	  if (0 == access(task->command, R_OK|X_OK)) /* flawfinder: ignore */
	    {
	      PDBGC(5);
	      PDBGC_CLOSE;
	      do {
		val_return = execve (task->command, 
				     (task->argc == 0) ? argp : task->argv, 
				     (task->envc == 0) ? envp : task->envv
				     );
	      } while (val_return < 0 && errno == EINTR);
	    }
	  errnum = errno;
	  PDBGC_OPEN;
	  PDBGC_S(strerror(errnum));
	  PDBGC_S(task->command);
	  PDBGC_S("execve: failed");
	  PDBGC_CLOSE;
	  /* failed 
	   */
	  _exit((errnum == 0) ? (EXIT_SUCCESS) : (EXIT_FAILURE));
	}
      /* 
       * if we have forked twice, this is parent::detached_subprocess
       */
      if (S_TRUE == task->fork_twice)
	{
	  _exit (0);
	}
    }

  
  /*
   * -- parent; task->pid is child pid; exit status is status of
   *    grandchild if exited
   */
  if (S_TRUE == task->fork_twice)
    {
      (void) waitpid (task->pid, NULL, 0);
    }

  PDBG(5);
  /* open an output stream on top of the write side of the pipe
   */
  if (task->rw == 'w')
    {
      PDBG_S("is w");
      (void) sl_close_fd (FIL__, __LINE__, pipedes[STDIN_FILENO]);
      (void) retry_fcntl (FIL__, __LINE__, pipedes[STDOUT_FILENO], 
			  F_SETFD, FD_CLOEXEC);
      outf = fdopen (pipedes[STDOUT_FILENO], "w");
    }
  else
    {
      PDBG_S("is r");
      (void) sl_close_fd (FIL__, __LINE__, pipedes[STDOUT_FILENO]);
      (void) retry_fcntl (FIL__, __LINE__, pipedes[STDIN_FILENO], 
			  F_SETFD, FD_CLOEXEC);
      outf = fdopen (pipedes[STDIN_FILENO], "r");
    }

  if (outf == NULL) 
    {
      errnum = errno;
      PDBG_S("outf == NULL");
      tmp  = sh_util_safe_name (task->command);
      
      if (task->privileged == 0 && 0 == getuid())
	sh_error_handle((-1), FIL__, __LINE__, errnum, MSG_NOEXEC,
			(UID_CAST) task->run_user_uid, tmp);
      else
	sh_error_handle((-1), FIL__, __LINE__, errnum, MSG_NOEXEC,
			(UID_CAST) getuid(), tmp);

      SH_FREE(tmp);

      (void) aud_kill (FIL__, __LINE__, task->pid, SIGKILL);
      (void) sl_close_fd (FIL__, __LINE__, pipedes[STDOUT_FILENO]);
      (void) sl_close_fd (FIL__, __LINE__, pipedes[STDIN_FILENO]);
      (void) waitpid (task->pid, NULL, 0);
      task->pid = 0;

      SL_RETURN ((-1), _("sh_ext_popen"));
    }
  
  if (task->rw == 'w')
    task->pipeFD   = pipedes[STDOUT_FILENO];
  else
    task->pipeFD   = pipedes[STDIN_FILENO];

  PDBG_D(task->pipeFD);

  task->pipeTI = sl_make_ticket(FIL__, __LINE__, task->pipeFD, _("pipe"), outf);

  flags = (int) retry_fcntl (FIL__, __LINE__, task->pipeFD, F_GETFL, 0);
  if (flags != (-1))
    (void) retry_fcntl (FIL__, __LINE__, task->pipeFD, 
			F_SETFL, flags|O_NONBLOCK);
  task->pipe     = outf;

  PDBG_S("return from popen");
  PDBG_CLOSE;
  
  SL_RETURN (0, _("sh_ext_popen"));
}

/*
 * -- close the pipe
 */
extern int flag_err_debug;

int sh_ext_pclose (sh_tas_t * task)
{
  int   status = 0;
  int   retry  = 0;
  pid_t retval;
  char  infomsg[256];

#ifdef WCONTINUED
      int wflags = WNOHANG|WUNTRACED|WCONTINUED;
#else
      int wflags = WNOHANG|WUNTRACED;
#endif

  SL_ENTER(_("sh_ext_pclose"));

  PDBG_OPEN;
  PDBG_S(" -> pclose");
  (void) fflush(task->pipe);
  if (!SL_ISERROR(task->pipeTI))
    (void) sl_close(task->pipeTI);

  task->pipe     = NULL;
  task->pipeFD   = (-1);
  task->pipeTI   = SL_ETICKET;

  if (S_FALSE == task->fork_twice)
    {
      infomsg[0] = '\0';

    nochmal:
      retval = waitpid(task->pid, &(task->exit_status), wflags);
      /*@-bufferoverflowhigh@*/
      if (task->pid == retval)
	{
#ifndef USE_UNO
	  if (WIFEXITED(task->exit_status) != 0)
	    {
	      task->exit_status = WEXITSTATUS(task->exit_status);
	      if ((flag_err_debug == S_TRUE) || (task->exit_status != 0))
		sl_snprintf(infomsg, sizeof(infomsg),
			    _("Subprocess exited normally with status %d"),
			    task->exit_status);
	    }
	  else if (WIFSIGNALED(task->exit_status) != 0)
	    {
	      sl_snprintf(infomsg, sizeof(infomsg),
			  _("Subprocess terminated by signal %d"),
			  WTERMSIG(task->exit_status));
	      task->exit_status = EXIT_FAILURE;
	    }
	  else if (WIFSTOPPED(task->exit_status) != 0)
	    {
	      sl_snprintf(infomsg, sizeof(infomsg),
			  _("Subprocess stopped by signal %d, killing"),
			  WSTOPSIG(task->exit_status));
	      task->exit_status = EXIT_FAILURE;
	      (void) aud_kill (FIL__, __LINE__, task->pid, 9);
	      (void) retry_msleep (0, 30);
	      (void) waitpid (task->pid, NULL, wflags);
	    }
	  else
	    {
	      sl_snprintf(infomsg, sizeof(infomsg),
			  _("Subprocess exit status unknown"));
	      task->exit_status = EXIT_FAILURE;
	    }
#else
	  task->exit_status = EXIT_FAILURE;
#endif 
	}
      else if (0 == retval)
	{
	  if (retry < 3)
	    {
	      ++retry;
	      (void) retry_msleep(0, (retry * 30));
	      goto nochmal;
	    }
	  (void) aud_kill (FIL__, __LINE__, task->pid, 9);
	  sl_snprintf(infomsg, sizeof(infomsg),
		      _("Subprocess not yet exited, killing"));
	  task->exit_status = EXIT_FAILURE;
	  (void) waitpid (task->pid, NULL, 0);
	}
      else
	{
	  sl_snprintf(infomsg, sizeof(infomsg),
		      _("Waitpid returned error %d\n"), errno);
	  task->exit_status = EXIT_FAILURE;
	}
      /*@+bufferoverflowhigh@*/
      status = task->exit_status;
      if (flag_err_debug == S_TRUE)
	{
	  sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, task->exit_status, 
			  MSG_E_SUBGEN, infomsg, _("sh_ext_pclose"));
	}
      else if (status != 0)
	{
	  sh_error_handle(SH_ERR_INFO, FIL__, __LINE__, task->exit_status, 
			  MSG_E_SUBGEN, infomsg, _("sh_ext_pclose"));
	}
    }

  task->pid = 0;
  task->exit_status = 0;
  PDBG_S(" <--");
  PDBG_CLOSE;
  SL_RETURN (status, _("sh_ext_pclose"));
}

void sh_ext_tas_init (sh_tas_t * tas)
{
  int i;

  tas->command       = NULL;
  tas->argc          = 0;
  tas->envc          = 0;
  tas->checksum[0]   = '\0';
  tas->pipeFD        = (-1);
  tas->pipeTI        = SL_ETICKET;
  tas->pid           = (pid_t) -1;
  tas->privileged    = 1;
  tas->pipe          = NULL;
  tas->rw            = 'w';
  tas->exit_status   = 0;
  tas->fork_twice    = S_TRUE;

  for (i = 0; i < 32; ++i)
    {
      tas->argv[i]          = NULL;
      tas->envv[i]          = NULL;
#if 0
      tas->trusted_users[i] = (uid_t) -1;
#endif
    }

  tas->run_user_uid     = (uid_t) getuid();
  tas->run_user_gid     = (gid_t) getgid();

  tas->com_fd = -1;
  tas->com_ti = -1;
  return;
}


int sh_ext_tas_add_envv(sh_tas_t * tas, const char * key, const char * val)
{
  size_t sk = 0, sv = 0;
  int    si;

  SL_ENTER(_("sh_ext_tas_add_envv"));

  if (tas == NULL ||  (key == NULL      && val == NULL)      || 
      tas->envc >= 30)
    {
      SL_RETURN (-1, _("sh_ext_tas_add_envv"));
    }
  if (key != NULL)
    sk = strlen(key) + 1;
  if (val != NULL)
    sv = strlen(val) + 1;

  if (!sl_ok_adds(sk, sv))
    {
      SL_RETURN (-1, _("sh_ext_tas_add_envv"));
    }
  si = tas->envc;
  tas->envv[si] = SH_ALLOC(sk + sv);

  if (key != NULL)
    {
      (void) sl_strlcpy(tas->envv[si], key, sk+sv);
      (void) sl_strlcat(tas->envv[si], "=", sk+sv);
      if (val != NULL)
	(void) sl_strlcat(tas->envv[si], val, sk+sv);
    }
  else
    (void) sl_strlcpy(tas->envv[si], val, sv);

  ++(tas->envc);
  SL_RETURN ((tas->envc), _("sh_ext_tas_add_envv"));
}

int sh_ext_tas_rm_argv(sh_tas_t * tas)
{
  int last;

  SL_ENTER(_("sh_ext_tas_rm_argv"));
  if (tas == NULL || tas->argc == 0)
    {
      SL_RETURN (-1, _("sh_ext_tas_rm_argv"));
    }

  last = (tas->argc - 1);
  --(tas->argc);
  SH_FREE(tas->argv[last]);
  tas->argv[last] = NULL;
  SL_RETURN ((tas->argc), _("sh_ext_tas_rm_argv"));
}

int sh_ext_tas_add_argv(sh_tas_t * tas, const char * val)
{
  size_t sv = 0;
  int    si;

  SL_ENTER(_("sh_ext_tas_add_argv"));

  if (tas == NULL ||  val == NULL  || 
      tas->argc >= 30)
    {
      SL_RETURN (-1, _("sh_ext_tas_add_argv"));
    }

  if (val != NULL)
    sv = strlen(val) + 1;

  si = tas->argc;
  tas->argv[si] = SH_ALLOC(sv);

  (void) sl_strlcpy(tas->argv[si], val, sv);

  ++(tas->argc);
  SL_RETURN ((tas->argc), _("sh_ext_tas_add_argv"));
}

void sh_ext_tas_command(sh_tas_t * tas, const char * command)
{
  size_t len = sl_strlen(command);
  tas->command = SH_ALLOC(len+1);
  (void) sl_strlcpy(tas->command, command, len+1);
  return;
}

void sh_ext_tas_free(sh_tas_t * tas)
{
  int i;
  if (NULL != tas->command)    SH_FREE(tas->command);
  
  for (i = 0; i < 32; ++i)
    {
      if (NULL != tas->argv[i])   SH_FREE(tas->argv[i]);
      if (NULL != tas->envv[i])   SH_FREE(tas->envv[i]);
    }

  if (tas->com_ti != (-1))
    {
      (void) sl_close(tas->com_ti);
      tas->com_ti = -1;
      tas->com_fd = -1;
    }

  return;
}

static void task_init (sh_tas_t * task)
{
  sh_ext_tas_init(task);

  (void) sh_ext_tas_add_envv (task, _("SHELL"), 
			      _("/bin/sh")); 
  (void) sh_ext_tas_add_envv (task, _("PATH"),  
			      _("/sbin:/bin:/usr/sbin:/usr/bin:/usr/ucb")); 
  (void) sh_ext_tas_add_envv (task, _("IFS"), " \n\t"); 

  if (sh.timezone != NULL)
    {
      (void) sh_ext_tas_add_envv(task,  "TZ", sh.timezone);
    }
  return;
}

int sh_ext_popen_init (sh_tas_t * task, const char * command, char * argv0, ...)
{
  va_list vl;
  int status;

  task_init (task);
  
  if (!argv0)
    {
      sh_ext_tas_command(task,  _("/bin/sh"));

      (void) sh_ext_tas_add_argv(task,  _("/bin/sh"));
      (void) sh_ext_tas_add_argv(task,  _("-c"));
      (void) sh_ext_tas_add_argv(task,  command);
    }
  else
    {
      char * s;

      sh_ext_tas_command(task,  command);

      (void) sh_ext_tas_add_argv(task, argv0);

      va_start (vl, argv0);
      s = va_arg (vl, char * );
      while (s != NULL)
	{
	  (void) sh_ext_tas_add_argv(task, s);
	  s = va_arg (vl, char * );
	}
      va_end (vl);

    }
  task->rw = 'r';
  task->fork_twice = S_FALSE;

  status = sh_ext_popen(task);

  return status;
}

/* Execute a system command */

int sh_ext_system (char * command, char * argv0, ...)
{
  sh_tas_t task;
  int    status;
  va_list vl;
  char * s;

  SL_ENTER(_("sh_ext_system"));

  task_init (&task);
  
  sh_ext_tas_command(&task,  command);

  (void) sh_ext_tas_add_argv(&task, argv0);
  
  va_start (vl, argv0);
  s = va_arg (vl, char * );
  while (s != NULL)
    {
      (void) sh_ext_tas_add_argv(&task, s);
      s = va_arg (vl, char * );
    }
  va_end (vl);

  task.rw = 'r';
  task.fork_twice = S_FALSE;

  status = sh_ext_popen(&task);

  if (status != 0)
    {
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, status, MSG_E_SUBGEN, 
                      _("Could not execute command"), _("sh_ext_system"));
      SL_RETURN ((-1), _("sh_ext_system"));
    }

  /* close pipe and return exit status
   */
  (void) sh_ext_pclose(&task);
  sh_ext_tas_free (&task);
  SL_RETURN ((status), _("sh_ext_system"));
}

/* Execute command, return first line of output
 * ifconfig | grep -1 lo | tail -n 1 | sed s/.*inet addr:\([0-9.]*\)\(.*\)/\1/
 */
char * sh_ext_popen_str (const char * command)
{
  sh_tas_t task;
  struct  sigaction  new_act;
  struct  sigaction  old_act;
  char * out = NULL;
  int    status;

  SL_ENTER(_("sh_ext_popen_str"));

  status = sh_ext_popen_init (&task, command, NULL, NULL);

  if (status != 0)
    {
      sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, status, MSG_E_SUBGEN, 
                      _("Could not open pipe"), _("sh_ext_popen_str"));
      SL_RETURN ((NULL), _("sh_ext_popen_str"));
    }

   /* ignore SIGPIPE (instead get EPIPE if connection is closed)
    */
   new_act.sa_handler = SIG_IGN;
   new_act.sa_flags   = 0;
   sigemptyset( &new_act.sa_mask );
   
   (void) retry_sigaction (FIL__, __LINE__, SIGPIPE, &new_act, &old_act);
   
  /* read from the open pipe
   */
  if (task.pipe != NULL)
    {
      int try = 1200; /* 1000 * 0.1 = 120 sec */
      sh_string * s = sh_string_new(0);
      do {
	sh_string_read(s, task.pipe, 0);
	if (sh_string_len(s) == 0)
	  {
	    --try; retry_msleep(0, 100);
	  }
      } while (sh_string_len(s) == 0 && try != 0);

      if (sh_string_len(s) == 0)
	{
	  sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, status, MSG_E_SUBGEN, 
			  _("No output from command"), _("sh_ext_popen_str"));
	}

      out = sh_util_strdup(sh_string_str(s));
      sh_string_destroy(&s);
    }

  /* restore old signal handler
   */
  (void) retry_sigaction (FIL__, __LINE__, SIGPIPE, &old_act, NULL);

  /* close pipe and return exit status
   */
  (void) sh_ext_pclose(&task);
  sh_ext_tas_free (&task);
  SL_RETURN ((out), _("sh_ext_popen_str"));
}




/* ---------------  EXTERN STUFF ------------------- */

#if defined(WITH_EXTERNAL)

typedef struct _sh_com_t
{
  char     type[4];

  sh_filter_type * filter;

  time_t   deadtime;
  time_t   last_run;

  sh_tas_t tas;

  struct _sh_com_t * next;

} sh_com_t;


static
void set3 (char * pos, char c1, char c2, char c3)
{
  pos[0] = c1;
  pos[1] = c2;
  pos[2] = c3;
  pos[3] = '\0';
  return;
}



/* initialize the external command structure
 */
static
sh_com_t * command_init(void)
{
  uid_t       ff_euid;
  sh_com_t  * ext_com = NULL;

  SL_ENTER(_("command_init"));

  ext_com = (sh_com_t *) SH_ALLOC(sizeof(sh_com_t));

  if (!ext_com)
    {
      SL_RETURN( NULL, _("command_init"));
    }

  sh_ext_tas_init (&(ext_com->tas));

  (void) sl_get_euid(&ff_euid);
#if 0
  ext_com->tas.trusted_users[0] = (uid_t) 0;
  ext_com->tas.trusted_users[1] = (uid_t) (ff_euid);
#endif

  /* ------------------------------------------------- */

  set3(ext_com->type, 'l', 'o', 'g');
  ext_com->filter       = NULL;
  ext_com->deadtime     = 0;
  ext_com->last_run     = 0;

  ext_com->next             = NULL;

  SL_RETURN( ext_com, _("command_init"));
}

/* the list of external commands
 */
static sh_com_t * ext_coms   = NULL;

/* if -1, allocation of last command has failed,
 * thus don't fill in options
 */
static int ext_failed = -1;

static
int sh_ext_add_envv(const char * key, const char * val)
{
  int retval; 

  SL_ENTER(_("sh_ext_add_envv"));

  if (ext_coms == NULL || ext_failed == (-1) || 
      (key == NULL      && val == NULL)      || 
      ext_coms->tas.envc >= 30)
    {
      SL_RETURN (-1, _("sh_ext_add_envv"));
    }

  retval = sh_ext_tas_add_envv(&(ext_coms->tas), key, val);

  if (retval >= 0) 
    retval = 0;

  SL_RETURN (retval, _("sh_ext_add_envv"));
}



static 
int sh_ext_init(const char * command)
{
  sh_com_t * retval;
  size_t     size;

  SL_ENTER(_("sh_ext_init"));

  if (command == NULL)
    {
      SL_RETURN (-1, _("sh_ext_init"));
    }
  size = strlen(command);
  if (command[0] != '/' || size < 2)
    {
      SL_RETURN (-1, _("sh_ext_init"));
    }

  if (NULL == (retval = command_init()))
    {
      SL_RETURN (-1, _("sh_ext_init"));
    }

  sh_ext_tas_command(&(retval->tas), command);

  if (sh.timezone != NULL)
    {
      (void) sh_ext_add_envv( "TZ", sh.timezone);
    }

  retval->next = ext_coms;
  ext_coms     = retval;
  SL_RETURN (0, _("sh_ext_init"));
}

static
int sh_ext_uid (const char * user, /*@out@*/uid_t * uid, /*@out@*/gid_t * gid)
{
  struct passwd *  tempres;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
  struct passwd    pwd;
  char           * buffer = SH_ALLOC(SH_PWBUF_SIZE);
#endif

  SL_ENTER(_("sh_ext_uid"));

  *uid = (uid_t)-1; *gid = (gid_t)-1;

  if (user == NULL)
    {
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
      SH_FREE(buffer);
#endif
      SL_RETURN (-1, _("sh_ext_uid"));
    }

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
  sh_getpwnam_r(user, &pwd, buffer, SH_PWBUF_SIZE, &tempres);
#else
  tempres = sh_getpwnam(user);
#endif

  if (NULL != tempres) 
    {
      *uid = tempres->pw_uid;  
      *gid = tempres->pw_gid;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
      SH_FREE(buffer);
#endif
      SL_RETURN (0, _("sh_ext_uid"));
    } 

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
  SH_FREE(buffer);
#endif
  SL_RETURN (-1, _("sh_ext_uid"));
}


static
int sh_ext_add (const char * argstring, int * ntok, char * stok[])
{
  int    i = 0;
  size_t s;
  char * p;
  char * new;
  size_t len;

  SL_ENTER(_("sh_ext_add"));

  if (NULL == argstring)
    {
      SL_RETURN((-1), _("sh_ext_add")); 
    }

  len = strlen(argstring) + 1;
  new = SH_ALLOC(len);
  sl_strlcpy(new, argstring, len); 

  do
    {
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
      char * saveptr;
      if (i == 0)
	p = strtok_r (new, ", \t", &saveptr);
      else
	p = strtok_r (NULL, ", \t", &saveptr);
#else
      if (i == 0)
	p = strtok (new, ", \t");
      else
	p = strtok (NULL, ", \t");
#endif

      if (p == NULL)
	break;

      s = strlen(p) + 1;
      if (stok[i] != NULL)
	SH_FREE(stok[i]);
      stok[i] = SH_ALLOC(s);
      (void) sl_strlcpy(stok[i], p, s);

      ++i;
      if (i == 30)
	break;
    }
  while (p != NULL);

  *ntok = i;
  SH_FREE(new);

  SL_RETURN (0, _("sh_ext_add"));
}

/*********************************************************
 *
 * Public functions
 *
 *
 *********************************************************/
 
/* 
 * -- start a new external command, and add it to the list
 */ 
int sh_ext_setcommand(const char * cmd)
{
  int i;

  SL_ENTER(_("sh_ext_setcommand"));
  if ( (i = sh_ext_init(cmd)) < 0)
    ext_failed = -1;
  else
    ext_failed = 0;
  SL_RETURN( i, _("sh_ext_setcommand"));
}


/* 
 * -- clean up the command list
 */
int sh_ext_cleanup(void)
{
  sh_com_t * retval;

  SL_ENTER(_("sh_ext_cleanup"));

  while (ext_coms != NULL)
    {
      retval   = ext_coms;
      ext_coms = retval->next;

      sh_ext_tas_free (&(retval->tas));

      if (retval->filter)
	sh_filter_free (retval->filter);

      SH_FREE(retval);

    }

  SL_RETURN (0, _("sh_ext_cleanup"));
}

/*
 * -- explicitely close a command
 */
int sh_ext_close_command (const char * str)
{
  (void) str;
  if (ext_coms == NULL || ext_failed == (-1))
    return (-1);
  ext_failed = (-1);
  return 0;
}

/*
 * -- add keywords to the OR filter
 */
int sh_ext_add_or (const char * str)
{
  if (ext_coms == NULL || ext_failed == (-1))
    return (-1);
  if (ext_coms->filter == NULL)
    ext_coms->filter = sh_filter_alloc();
  return (sh_filter_add(str, ext_coms->filter, SH_FILT_OR));
}

/*
 * -- add keywords to the AND filter
 */
int sh_ext_add_and (const char * str)
{
  if (ext_coms == NULL || ext_failed == (-1))
    return (-1);
  if (ext_coms->filter == NULL)
    ext_coms->filter = sh_filter_alloc();
  return (sh_filter_add(str, ext_coms->filter, SH_FILT_AND));
}

/*
 * -- add keywords to the NOT filter
 */
int sh_ext_add_not (const char * str)
{
  if (ext_coms == NULL || ext_failed == (-1))
    return (-1);
  if (ext_coms->filter == NULL)
    ext_coms->filter = sh_filter_alloc();
  return (sh_filter_add(str, ext_coms->filter, SH_FILT_NOT));
}

/*
 * -- add keywords to the CL argument list
 */
int sh_ext_add_argv (const char * str)
{
  if (ext_coms == NULL || ext_failed == (-1))
    return (-1);
  return (sh_ext_add (str, &(ext_coms->tas.argc), ext_coms->tas.argv));
}

/*
 * -- add a path to the environment
 */
int sh_ext_add_default (const char * dummy)
{
  char * p = NULL;
  int    i;
  char   dir[SH_PATHBUF];

  SL_ENTER(_("sh_ext_add_default"));
  if (dummy[0] == 'n' ||  dummy[0] == 'N' ||
      dummy[0] == 'f' ||  dummy[0] == 'F' || dummy[0] == '0')
    {
      SL_RETURN(0, _("sh_ext_add_default"));
    }
  p = sh_unix_getUIDdir (SH_ERR_ERR, (uid_t) ext_coms->tas.run_user_uid, 
			 dir, sizeof(dir));
  if (p)
    (void) sh_ext_add_envv (_("HOME"), p);
  (void) sh_ext_add_envv (_("SHELL"), _("/bin/sh")); 
  (void) sh_ext_add_envv (_("PATH"),  _("/sbin:/bin:/usr/sbin:/usr/bin")); 
  (void) sh_ext_add_envv (_("IFS"), " \n\t"); 
  i = (p == NULL ? (-1) :  0);
  SL_RETURN(i, _("sh_ext_add_default"));
}

/*
 * -- add an environment variable
 */
int sh_ext_add_environ (const char * str)
{
  int i;

  SL_ENTER(_("sh_ext_add_environ"));
  i = sh_ext_add_envv (NULL, str);
  SL_RETURN(i, _("sh_ext_add_environ"));
}

/*
 * -- set deadtime
 */
int sh_ext_deadtime (const char * str)
{
  long    deadtime = 0;
  char  * tail     = NULL;

  SL_ENTER(_("sh_ext_deadtime"));

  if (ext_coms == NULL || ext_failed == (-1) || str == NULL)
    {
      SL_RETURN (-1, _("sh_ext_deadtime"));
    }
  deadtime = strtol(str, &tail, 10);
  if (tail == str || deadtime < 0 || deadtime == LONG_MAX)
    {
      SL_RETURN (-1, _("sh_ext_deadtime"));
    }
  
  ext_coms->deadtime = (time_t) deadtime;  
  SL_RETURN (0, _("sh_ext_deadtime"));  
}

/*
 * -- define type
 */
int sh_ext_type (const char * str)
{
  SL_ENTER(_("sh_ext_type"));

  if (ext_coms == NULL || ext_failed == (-1) || str == NULL)
    {
      SL_RETURN((-1), _("sh_ext_type"));
    }

  if (strlen(str) != 3)
    {
      SL_RETURN((-1), _("sh_ext_type"));
    }

  set3(ext_coms->type, str[0], str[1], str[2]);

  if      (str[0] == 'l' && str[1] == 'o' && str[2] == 'g')
    ext_coms->tas.rw = 'w';
  else if (str[0] == 's' && str[1] == 'r' && str[2] == 'v')
    ext_coms->tas.rw = 'w';
  else if (str[0] == 'm' && str[1] == 'o' && str[2] == 'n')
    ext_coms->tas.rw = 'r';
  else
    {
      SL_RETURN((-1), _("sh_ext_type"));
    }

  SL_RETURN(0, _("sh_ext_type"));
} 
  


/*
 * -- define checksum
 */
int sh_ext_checksum (const char * str)
{
  SL_ENTER(_("sh_ext_checksum"));
  if (ext_coms == NULL || ext_failed == (-1) || str == NULL)
    {
      SL_RETURN((-1), _("sh_ext_checksum"));
    }

  if (sl_strlen(str) != KEY_LEN)
    {
      SL_RETURN((-1), _("sh_ext_checksum"));
    }

  (void) sl_strlcpy (ext_coms->tas.checksum, str, KEY_LEN+1);

  SL_RETURN((0), _("sh_ext_checksum"));
}

/*
 * -- choose privileges
 */
int sh_ext_priv (const char * c)
{

  uid_t me_uid;
  gid_t me_gid;

  SL_ENTER(_("sh_ext_priv"));
  if (0 == sh_ext_uid (c, &me_uid, &me_gid))
    {
      ext_coms->tas.run_user_uid = me_uid;
      ext_coms->tas.run_user_gid = me_gid;
      if (me_uid != (uid_t) 0)
	ext_coms->tas.privileged   = 0;
      SL_RETURN((0), _("sh_ext_priv"));
    }

  SL_RETURN (-1, _("sh_ext_priv"));
}




/*
 * -- check filters
 */
static int sh_ext_filter (char * message, sh_com_t * task)
{
  time_t now_time;

  SL_ENTER(_("sh_ext_filter"));

  if (task->filter)
    {
      if (0 != sh_filter_filter (message, task->filter))
	{
	  SL_RETURN ((-1), _("sh_ext_filter"));
	}
    }

  /* Filter passed, check deadtime */

  if (task->deadtime != (time_t) 0)
    {
      now_time = time (NULL);
      
      if (task->last_run == (time_t) 0)
	{
	  task->last_run = now_time;
	}
      else if ((time_t)(now_time-task->last_run) < task->deadtime)
	{
	  SL_RETURN ((-1), _("sh_ext_filter"));
	}
      else
	{
	  task->last_run = now_time;
	}
    }

  SL_RETURN ((0), _("sh_ext_filter"));
}



/*
 * -- execute external script/program
 */
int sh_ext_execute (char t1, char t2, char t3, /*@null@*/char * message, 
		    size_t msg_siz)
{
  int        caperr;
  sh_com_t * listval = ext_coms;
  int        status = 0;
  char     * tmp;
  char errbuf[SH_ERRBUF_SIZE];

  static  int some_error = 0;

  struct  sigaction  new_act;
  struct  sigaction  old_act;

  SL_ENTER(_("sh_ext_execute"));

  PDBG_OPEN;

  if (listval == NULL || message == NULL)
    {
      SL_RETURN ((-1), _("sh_ext_execute"));
    }

  PDBG(-1);

  if (msg_siz == 0)
    msg_siz = sl_strlen(message);


  /* ignore SIGPIPE (instead get EPIPE if connection is closed)
   */
  new_act.sa_handler = SIG_IGN;
  (void) retry_sigaction (FIL__, __LINE__, SIGPIPE, &new_act, &old_act);

  while (listval != NULL)
    {
      PDBG_OPEN;
      PDBG(-2);
      if (t1 == listval->type[0] &&
	  t2 == listval->type[1] &&
	  t3 == listval->type[2] &&
	  0 == sh_ext_filter (message, listval))
	{
	  PDBG(-3);

	  if (0 != (caperr = sl_get_cap_sub()))
	    {
	      sh_error_handle((-1), FIL__, __LINE__, caperr, MSG_E_SUBGEN,
			      sh_error_message (caperr, errbuf, sizeof(errbuf)), 
			      _("sl_get_cap_sub"));
	    }
	  if (0 == sh_ext_popen (&(listval->tas)))
	    {
	      PDBG_OPEN;
	      PDBG(-4);
	      if (NULL != listval->tas.pipe && listval->tas.rw == 'w')
		{
		  PDBG(-5);
		  if (message != NULL)
		    {
		      PDBG(-6);
		      status = (int) write (listval->tas.pipeFD, 
					    message, msg_siz);
		      if (status >= 0)
			status = (int) write (listval->tas.pipeFD, "\n", 1);
		    }
		  PDBG_D(status);
		  if (status >= 0)
		    status = (int) write (listval->tas.pipeFD, "[", 1);
		  PDBG_D(status);
		  if (status >= 0)
		    status = (int) write (listval->tas.pipeFD, "E", 1);
		  PDBG_D(status);
		  if (status >= 0)
		    status = (int) write (listval->tas.pipeFD, "O", 1);
		  PDBG_D(status);
		  if (status >= 0)
		    status = (int) write (listval->tas.pipeFD, "F", 1);
		  PDBG_D(status);
		  if (status >= 0)
		    status = (int) write (listval->tas.pipeFD, "]", 1);
		  PDBG_D(status);
		  if (status >= 0)
		    status = (int) write (listval->tas.pipeFD, "\n", 1);
		  PDBG_D(status);
		  if (status >= 0)
		    {
		      some_error = 0;
		    }
		  if ((status < 0) && (some_error == 0))
		    {
		      some_error = 1;
		      PDBG_S("some error");
		      PDBG_D(status);
		      tmp  = sh_util_safe_name (listval->tas.command);

		      if (tmp)
			{
			  if (listval->tas.privileged == 0 && 
			      (0 == getuid() || 0 != sl_is_suid()) )
			    sh_error_handle((-1), FIL__, __LINE__, 0, 
					    MSG_NOEXEC,
					    (UID_CAST) listval->tas.run_user_uid, 
					    tmp);
			  else
			    sh_error_handle((-1), FIL__, __LINE__, 0, 
					    MSG_NOEXEC,
					    (UID_CAST) getuid(), tmp);
			  
			  SH_FREE(tmp);
			}

		    } 
		  PDBG(-7);
		  (void) fflush(listval->tas.pipe);
		}
	      PDBG(-8);
	      (void) sh_ext_pclose(&(listval->tas));
	    }
	  else
	    {
	      PDBG_OPEN;
	      PDBG_S("0 != sh_ext_popen()");
	    }
	  if (0 != (caperr = sl_drop_cap_sub()))
	    {
	      sh_error_handle((-1), FIL__, __LINE__, caperr, MSG_E_SUBGEN,
			      sh_error_message (caperr, errbuf, sizeof(errbuf)), 
			      _("sl_drop_cap_sub"));
	    }

	}
      listval = listval->next;
    }
  PDBG_OPEN;
  PDBG_S("no more commands");

  /* restore old signal handler
   */
  (void) retry_sigaction (FIL__, __LINE__, SIGPIPE, &old_act, NULL);
  PDBG_S("return");
  PDBG_CLOSE;

  SL_RETURN ((0), _("sh_ext_execute"));
}
  
  
/* #if defined(WITH_EXTERNAL) */
#endif
