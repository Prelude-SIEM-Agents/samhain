/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2001 Rainer Wichmann                                      */
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#ifdef HAVE_SCHED_H
#include <sched.h>
#endif

#ifdef SH_USE_SUIDCHK

#undef  FIL__
#define FIL__  _("sh_suidchk.c")

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 

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

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#define NAMLEN(dirent) sl_strlen((dirent)->d_name)
#else
#define dirent direct
#define NAMLEN(dirent) (dirent)->d_namlen
#ifdef HAVE_SYS_NDIR_H
#include <sys/ndir.h>
#endif
#ifdef HAVE_SYS_DIR_H
#include <sys/dir.h>
#endif
#ifdef HAVE_NDIR_H
#include <ndir.h>
#endif
#endif
#define NEED_ADD_DIRENT

#include "samhain.h"
#include "sh_pthread.h"
#include "sh_utils.h"
#include "sh_error.h"
#include "sh_modules.h"
#include "sh_suidchk.h"
#include "sh_hash.h"
#include "sh_dbIO.h"
#include "sh_unix.h"
#include "sh_files.h"
#include "sh_schedule.h"
#include "sh_calls.h"
#include "zAVLTree.h"


sh_rconf sh_suidchk_table[] = {
  {
    N_("severitysuidcheck"),
    sh_suidchk_set_severity
  },
  {
    N_("suidcheckactive"),
    sh_suidchk_set_activate
  },
  {
    N_("suidcheckinterval"),
    sh_suidchk_set_timer
  },
  {
    N_("suidcheckschedule"),
    sh_suidchk_set_schedule
  },
  {
    N_("suidcheckexclude"),
    sh_suidchk_set_exclude
  },
  {
    N_("suidcheckfps"),
    sh_suidchk_set_fps
  },
  {
    N_("suidcheckyield"),
    sh_suidchk_set_yield
  },
  {
    N_("suidchecknosuid"),
    sh_suidchk_set_nosuid
  },
  {
    N_("suidcheckquarantinefiles"),
    sh_suidchk_set_quarantine
  },
  {
    N_("suidcheckquarantinemethod"),
    sh_suidchk_set_qmethod
  },
  {
    N_("suidcheckquarantinedelete"),
    sh_suidchk_set_qdelete
  },
  {
    NULL,
    NULL
  },
};


static time_t  lastcheck         = (time_t) 0;
static int     ShSuidchkActive   = S_TRUE;
static time_t  ShSuidchkInterval = 7200;
static unsigned long    ShSuidchkFps      = 0;
static int     ShSuidchkNosuid   = S_FALSE;
static int     ShSuidchkYield    = S_FALSE;
static int     ShSuidchkQEnable  = S_FALSE;
static int     ShSuidchkQMethod  = SH_Q_CHANGEPERM;
static int     ShSuidchkQDelete  = S_FALSE;
static int     ShSuidchkSeverity = SH_ERR_SEVERE;

static time_t  FileLimNow        = 0;
static time_t  FileLimStart      = 0;
static unsigned long    FileLimNum        = 0;
static unsigned long    FileLimTotal      = 0;

static sh_schedule_t * ShSuidchkSched = NULL;


static zAVLTree *  ShSuidchkExclude  = NULL;
static void sh_suid_exclude_free()
{
  zAVL_string_reset(ShSuidchkExclude);
  ShSuidchkExclude  = NULL;
  return;
}
static int sh_suid_exclude_add(const char * str)
{
  size_t len;
  int    ret;
  char * key = sh_util_strdup(str);

  len = sl_strlen (key);
  if (len && key[len-1] == '/')
    {
      key[len-1] = '\0';
    }
  ret = zAVL_string_set(&ShSuidchkExclude, key);
  SH_FREE(key);
  return ret;
}


static char *
filesystem_type (char * path, char * relpath, struct stat * statp);

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

SH_MUTEX_STATIC(mutex_suid_check, PTHREAD_MUTEX_INITIALIZER);

extern unsigned long sh_files_maskof (int class);

static void set_defaults (void)
{
  ShSuidchkActive   = S_TRUE;
  ShSuidchkInterval = 7200;
  ShSuidchkFps      = 0;
  ShSuidchkNosuid   = S_FALSE;
  ShSuidchkYield    = S_FALSE;
  ShSuidchkQEnable  = S_FALSE;
  ShSuidchkQMethod  = SH_Q_CHANGEPERM;
  ShSuidchkQDelete  = S_FALSE;
  ShSuidchkSeverity = SH_ERR_SEVERE;
  if (ShSuidchkExclude != NULL)
    sh_suid_exclude_free();

  FileLimNow        = 0;
  FileLimStart      = 0;
  FileLimNum        = 0;
  FileLimTotal      = 0;

  return;
}

/* Recursively descend into the directory to make sure that
 * there is no symlink in the path.
 *
 * Use retry_lstat_ns() here because we cannot chdir the subprocess
 * that does the lstat().
 */
static int do_truncate_int (char * path, int depth)
{
  char      * q;
  struct stat one; 
  struct stat two;
  int         fd;
  char errbuf[SH_ERRBUF_SIZE];

  if (depth > 99)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, EINVAL,
		       MSG_SUID_ERROR,
		       _("do_truncate: max depth 99 exceeded"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      return -1;
    }
  ++depth;
  if (path[0] != '/')
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, EINVAL,
		       MSG_SUID_ERROR,
		       _("do_truncate: not an absolute path"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      return -1;
    }
  ++path;
  q = strchr(path, '/');
  if (q)
    {
      *q = '\0';
      if (0 != retry_lstat_ns(FIL__, __LINE__, path, &one))
	{ 
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, errno,
			   MSG_SUID_ERROR,
			   sh_error_message(errno, errbuf, sizeof(errbuf)));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  *q = '/'; 
	  return -1; 
	}
      if (/*@-usedef@*/!S_ISDIR(one.st_mode)/*@+usedef@*/)
	
	{ 
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, EINVAL,
			   MSG_SUID_ERROR,
			   _("Possible race: not a directory"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  *q = '/'; 
	  return -1; 
	}


      if (0 != chdir(path))
	{
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, errno,
			   MSG_SUID_ERROR,
			   sh_error_message(errno, errbuf, sizeof(errbuf)));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  *q = '/';
	  return -1;
	}
      *q = '/';
      if (0 != retry_lstat_ns(FIL__, __LINE__, ".", &two))
	{ 
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, errno,
			   MSG_SUID_ERROR,
			   sh_error_message(errno, errbuf, sizeof(errbuf)));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  return -1; 
	}
      if (/*@-usedef@*/(one.st_dev != two.st_dev) || 
	  (one.st_ino != two.st_ino) || 
	  (!S_ISDIR(two.st_mode))/*@+usedef@*/)
	{ 
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, EINVAL,
			   MSG_SUID_ERROR,
			   _("Possible race: lstat(dir) != lstat(.)"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  return -1;
	}


      return (do_truncate_int(q, depth));
    }
  else
    {
      /* no more '/', so this is the file 
       */
      if (*path == '\0')
	return -1;
      if (0 != retry_lstat_ns(FIL__, __LINE__, path, &one))
	{
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, errno,
			   MSG_SUID_ERROR,
			   sh_error_message(errno, errbuf, sizeof(errbuf)));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  return -1;
	} 
      fd = open(path, O_RDWR);
      if (-1 == fd)
	{
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, errno,
			   MSG_SUID_ERROR,
			   sh_error_message(errno, errbuf, sizeof(errbuf)));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  return -1;
	} 
      if (0 != retry_fstat(FIL__, __LINE__, fd, &two))
	{ 
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, errno,
			   MSG_SUID_ERROR,
			   sh_error_message(errno, errbuf, sizeof(errbuf)));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  (void) sl_close_fd(FIL__, __LINE__, fd);
	  return -1; 
	}
      if (/*@-usedef@*/(one.st_dev != two.st_dev) || 
	  (one.st_ino != two.st_ino)/*@+usedef@*/)
	{ 
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, EINVAL,
			   MSG_SUID_ERROR,
			   _("Possible race: lstat != fstat"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  (void) sl_close_fd(FIL__, __LINE__, fd); 
	  return -1;
	}
      if (!S_ISREG(two.st_mode))
	{ 
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, EINVAL,
			   MSG_SUID_ERROR,
			   _("Possible race: not a regular file"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  (void) sl_close_fd(FIL__, __LINE__, fd); 
	  return -1;
	}
      if ((0 == (two.st_mode & S_ISUID)) && (0 == (two.st_mode & S_ISGID)))
	{ 
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, EINVAL,
			   MSG_SUID_ERROR,
			   _("Possible race: not a suid/sgid file"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  (void) sl_close_fd(FIL__, __LINE__, fd); 
	  return -1;
	}
      if (ShSuidchkQDelete == S_FALSE)
	{
	  if ((two.st_mode & S_ISUID) > 0)
	    two.st_mode -= S_ISUID;
	  if ((two.st_mode & S_ISGID) > 0)
	    two.st_mode -= S_ISGID;
#ifdef HAVE_FCHMOD
	  if (-1 == /*@-unrecog@*/fchmod(fd, two.st_mode)/*@+unrecog@*/)
	    {
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle ((-1), FIL__, __LINE__, errno,
			       MSG_SUID_ERROR,
			       sh_error_message(errno, errbuf, sizeof(errbuf)));
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	      (void) sl_close_fd(FIL__, __LINE__, fd); 
	      return -1;
	    }
#else
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, errno,
			   MSG_SUID_ERROR,
			   _("The fchmod() function is not available"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  (void) sl_close_fd(FIL__, __LINE__, fd); 
	  return -1;
#endif
	  if (two.st_nlink > 1)
	    {
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle ((-1), FIL__, __LINE__, 0,
			       MSG_SUID_ERROR,
			       _("Not truncated because hardlink count gt 1"));
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	      (void) sl_close_fd(FIL__, __LINE__, fd); 
	      return -1;
	    }
	  /* The man page says: 'POSIX has ftruncate'
	   */
	  if (-1 == /*@-unrecog@*/ftruncate(fd, 0)/*@+unrecog@*/)
	    {
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle ((-1), FIL__, __LINE__, errno,
			       MSG_SUID_ERROR,
			       sh_error_message(errno, errbuf, sizeof(errbuf)));
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	      (void) sl_close_fd(FIL__, __LINE__, fd); 
	      return -1;
	    }
	}
      else
	{
	  if (-1 == retry_aud_unlink(FIL__, __LINE__, path))
	    {
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle ((-1), FIL__, __LINE__, errno,
			       MSG_SUID_ERROR,
			       sh_error_message(errno, errbuf, sizeof(errbuf)));
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	      (void) sl_close_fd(FIL__, __LINE__, fd); 
	      return -1;
	    }
	}
      (void) sl_close_fd (FIL__, __LINE__, fd);
      return (0);
    }
}

static int do_truncate (const char * path_in)
{
  volatile int    caperr;
  int    result;
  char * path;
  char errbuf[SH_ERRBUF_SIZE];

  if (0 != chdir("/"))
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, errno,
		       MSG_SUID_ERROR,
		       sh_error_message(errno, errbuf, sizeof(errbuf)));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }

  if (0 != (caperr = sl_get_cap_qdel()))
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle((-1), FIL__, __LINE__, caperr, MSG_E_SUBGEN,
		      sh_error_message (caperr, errbuf, sizeof(errbuf)), 
		      _("sl_get_cap_qdel"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }

  path   = sh_util_strdup  (path_in);
  result = do_truncate_int (path, 0);
  SH_FREE(path);

  if (0 != (caperr = sl_drop_cap_qdel()))
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle((-1), FIL__, __LINE__, caperr, MSG_E_SUBGEN,
		      sh_error_message (caperr, errbuf, sizeof(errbuf)), 
		      _("sl_drop_cap_qdel"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }

  if (0 != chdir("/"))
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, errno,
		       MSG_SUID_ERROR,
		       sh_error_message(errno, errbuf, sizeof(errbuf)));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }
  return result;
}

/* This variable is not used anywhere. It only exists
 * to assign &dirlist to it, which keeps gcc from
 * putting it into a register, and avoids the 'clobbered
 * by longjmp' warning. And no, 'volatile' proved insufficient.
 */
static void * sh_dummy_tmp = NULL;

static void sh_q_delete(const char * fullpath)
{
  int    status;
  char * msg;
  char * tmp;

  /* Take the address to keep gcc from putting it into a register. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_tmp = (void*) &tmp;

  if (do_truncate (fullpath) == -1)
    {
      status = errno;
      msg    = SH_ALLOC(SH_BUFSIZE);
      tmp    = sh_util_safe_name(fullpath);

      (void) sl_snprintf(msg, SH_BUFSIZE, 
			 _("Problem quarantining file.  File NOT quarantined.  errno = %ld"), 
			 status);
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle (ShSuidchkSeverity,
		       FIL__, __LINE__, 
		       status,
		       MSG_SUID_QREPORT, msg,
		       tmp );
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      SH_FREE(tmp);
      SH_FREE(msg);
    }
  else
    {
      tmp    = sh_util_safe_name(fullpath);
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle (ShSuidchkSeverity,
		       FIL__, __LINE__, 0,
		       MSG_SUID_QREPORT,
		       _("Quarantine method applied"),
		       tmp );
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      SH_FREE(tmp);
    }
  return;
}

/* This variable is not used anywhere. It only exists
 * to assign &dirlist to it, which keeps gcc from
 * putting it into a register, and avoids the 'clobbered
 * by longjmp' warning. And no, 'volatile' proved insufficient.
 */
static void * sh_dummy_mtmp = NULL;
static void * sh_dummy_mmsg = NULL;

static void sh_q_move(const char * fullpath, file_type * theFile, 
		      const char * timestrc, const char * timestra, 
		      const char * timestrm)
{
  volatile int  status;
  int           readFile  = -1;
  volatile int  writeFile = -1;
  struct stat   fileInfo;
  ssize_t       count;
  char        * msg;
  char        * tmp;
  char        * basetmp;
  char        * filetmp;
  char          buffer[1024];
  char        * dir = SH_ALLOC(PATH_MAX+1);
  mode_t        umask_old;
  FILE *        filePtr = NULL;

  /* Take the address to keep gcc from putting it into a register. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_mtmp = (void*) &tmp;
  sh_dummy_mmsg = (void*) &msg;

  (void) sl_strlcpy (dir, DEFAULT_QDIR, PATH_MAX+1);

  if (retry_stat (FIL__, __LINE__, dir, &fileInfo) != 0)
    {
      /* Quarantine directory does not exist,
       */
      status = errno;
      msg    = SH_ALLOC(SH_BUFSIZE);
      tmp    = sh_util_safe_name(fullpath);

      (void) sl_snprintf(msg, SH_BUFSIZE, 
			 _("Problem quarantining file.  File NOT quarantined.  errno = %ld (stat)"), 
			 status);
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle (ShSuidchkSeverity,
		       FIL__, __LINE__, 
		       status,
		       MSG_SUID_QREPORT, msg,
		       tmp );
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      SH_FREE(tmp);
      SH_FREE(msg);
    }
  else
    {
      if (retry_lstat (FIL__, __LINE__, 
		       fullpath, &fileInfo) == -1)
	{
	  status = errno;
	  msg    = SH_ALLOC(SH_BUFSIZE);
	  tmp    = sh_util_safe_name(fullpath);

	  (void) sl_snprintf(msg, SH_BUFSIZE, _("I/O error.  errno = %ld(stat)"), status);
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle (ShSuidchkSeverity,
			   FIL__, __LINE__, 
			   status,
			   MSG_SUID_QREPORT,
			   msg, tmp );
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  SH_FREE(tmp);
	  SH_FREE(msg);
	}
      else
	{
	  basetmp = sh_util_strdup(fullpath);
	  filetmp = SH_ALLOC(PATH_MAX+1);
	  tmp     = sh_util_basename(basetmp);

	  (void) sl_snprintf(filetmp, PATH_MAX+1, "%s/%s", 
			     DEFAULT_QDIR, tmp);
	  SH_FREE(tmp);
	  SH_FREE(basetmp);
	  
	  readFile  = open (fullpath, O_RDONLY);
	  if (readFile != -1)
	    writeFile = open (filetmp, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IXUSR);
	  
	  if ((readFile == -1) || (writeFile == -1))
	    {
	      status = errno;
	      msg    = SH_ALLOC(SH_BUFSIZE);
	      tmp    = sh_util_safe_name(fullpath);

	      (void) sl_snprintf(msg, SH_BUFSIZE, _("Problem quarantining file.  File NOT quarantined.  errno = %ld (open)"), status);
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle (ShSuidchkSeverity,
			       FIL__, __LINE__, status,
			       MSG_SUID_QREPORT,
			       msg, tmp );
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	      SH_FREE(tmp);
	      SH_FREE(msg);
	    }
	  else
	    { 
	      /* sizeof(buffer) is 1024 
	       */
	      while ((count = (int) read (readFile, buffer, sizeof (buffer))) > 0)
		{
		  if ((int) write (writeFile, buffer, (size_t) count) != count)
		    {
		      status = errno;
		      msg    = SH_ALLOC(SH_BUFSIZE);
		      tmp    = sh_util_safe_name(fullpath);

		      (void) sl_snprintf(msg, SH_BUFSIZE, 
					 _("I/O error.  errno = %ld (write)"), status);
		      SH_MUTEX_LOCK(mutex_thread_nolog);
		      sh_error_handle (ShSuidchkSeverity,
				       FIL__,
				       __LINE__,
				       status,
				       MSG_SUID_QREPORT,
				       msg, tmp );
		      SH_MUTEX_UNLOCK(mutex_thread_nolog);
		      SH_FREE(tmp);
		      SH_FREE(msg);
		    }
		}
	    }

	  (void) sl_close_fd (FIL__, __LINE__, readFile);
	  (void) fchmod(writeFile, S_IRUSR | S_IWUSR | S_IXUSR);
	  (void) sl_close_fd (FIL__, __LINE__, writeFile);

	  if (do_truncate (fullpath) == -1)
	    {
	      status = errno;
	      msg    = SH_ALLOC(SH_BUFSIZE);
	      tmp    = sh_util_safe_name(fullpath);

	      (void) sl_snprintf(msg, SH_BUFSIZE, 
				 _("Problem quarantining file.  File NOT quarantined.  errno = %ld"), 
				 status);
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle (ShSuidchkSeverity,
			       FIL__, __LINE__, status,
			       MSG_SUID_QREPORT,
			       msg, tmp );
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	      SH_FREE(tmp);
	      SH_FREE(msg);
	    }
	  else
	    {
	      tmp = sh_util_basename(fullpath);

	      (void) sl_snprintf(filetmp, PATH_MAX+1, "%s/%s.info", 
				 DEFAULT_QDIR, 
				 tmp);

	      SH_FREE(tmp);
	      /*
	       * avoid chmod by setting umask
	       */
	      umask_old = umask (0077);
	      filePtr   = fopen (filetmp, "w+");

	      /*@-usedef@*/
	      if (filePtr)
		{
		  fprintf(filePtr, 
			  _("File Info:\n filename=%s\n size=%lu\n owner=%s(%d)\n group=%s(%d)\n ctime=%s\n atime=%s\n mtime=%s\n"), 
			  fullpath, 
			  (unsigned long) theFile->size, 
			  theFile->c_owner, (int) theFile->owner, 
			  theFile->c_group, (int) theFile->group, 
			  timestrc, timestra, timestrm);
		  (void) sl_fclose (FIL__, __LINE__, filePtr);
		}
	      /*@+usedef@*/
	      umask (umask_old);
	      
	      tmp    = sh_util_safe_name(fullpath);
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle (ShSuidchkSeverity,
			       FIL__,__LINE__,
			       0, MSG_SUID_QREPORT,
			       _("Quarantine method applied"),
			       tmp );
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	      SH_FREE(tmp);
	    }
	  SH_FREE(filetmp);
	}
    }
  SH_FREE(dir);
  return;
}

/* This variable is not used anywhere. It only exists
 * to assign &dirlist to it, which keeps gcc from
 * putting it into a register, and avoids the 'clobbered
 * by longjmp' warning. And no, 'volatile' proved insufficient.
 */
static void * sh_dummy_ctmp = NULL;
static void * sh_dummy_cmsg = NULL;

static void sh_q_changeperm(const char * fullpath)
{
  volatile int    caperr;
  volatile int    status;
  char          * msg;
  char          * tmp;
  struct stat     fileInfo;
  struct stat     fileInfo_F;
  int             cperm_status = 0;
  volatile int    file_d       = -1;
  char errbuf[SH_ERRBUF_SIZE];

  /* Take the address to keep gcc from putting it into a register. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_ctmp = (void*) &tmp;
  sh_dummy_cmsg = (void*) &msg;

  if (retry_lstat(FIL__, __LINE__, fullpath, &fileInfo) == -1)
    {
      status = errno;
      msg    = SH_ALLOC(SH_BUFSIZE);
      tmp    = sh_util_safe_name(fullpath);

      (void) sl_snprintf(msg, SH_BUFSIZE, _("I/O error.  errno = %ld"), status);
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle (ShSuidchkSeverity,
		       FIL__, __LINE__, 
		       status,
		       MSG_SUID_QREPORT, msg,
		       tmp );
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      SH_FREE(tmp);
      SH_FREE(msg);
      cperm_status = -1;
    }
  
  if (cperm_status == 0)
    {
      if (0 != (caperr = sl_get_cap_qdel()))
	{
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle((-1), FIL__, __LINE__, 
			  caperr, MSG_E_SUBGEN,
			  sh_error_message (caperr, errbuf, sizeof(errbuf)), 
			  _("sl_get_cap_qdel"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  cperm_status = -1;
	}
    }
  
  if (cperm_status == 0)
    {
      file_d = aud_open (FIL__, __LINE__, SL_YESPRIV,
			 fullpath, O_RDONLY, 0);
      if (-1 == file_d)
	{
	  status = errno;
	  msg    = SH_ALLOC(SH_BUFSIZE);
	  tmp    = sh_util_safe_name(fullpath);

	  (void) sl_snprintf(msg, SH_BUFSIZE, _("I/O error.  errno = %ld"), status);
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle (ShSuidchkSeverity,
			   FIL__, __LINE__, 
			   status,
			   MSG_SUID_QREPORT, msg,
			   tmp );
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  SH_FREE(tmp);
	  SH_FREE(msg);
	  cperm_status = -1;
	}
    }
  
  if (cperm_status == 0)
    {
      if (retry_fstat(FIL__, __LINE__, file_d, &fileInfo_F) == -1)
	{
	  status = errno;
	  msg    = SH_ALLOC(SH_BUFSIZE);
	  tmp    = sh_util_safe_name(fullpath);

	  (void) sl_snprintf(msg, SH_BUFSIZE, 
			     _("I/O error.  errno = %ld"), status);
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle (ShSuidchkSeverity,
			   FIL__, __LINE__, 
			   status,
			   MSG_SUID_QREPORT, msg,
			   tmp );
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  SH_FREE(tmp);
	  SH_FREE(msg);
	  cperm_status = -1;
	}
    }
  
  if (cperm_status == 0)
    {
      if (fileInfo_F.st_ino  != fileInfo.st_ino ||
	  fileInfo_F.st_dev  != fileInfo.st_dev ||
	  fileInfo_F.st_mode != fileInfo.st_mode)
	{
	  status = errno;
	  msg    = SH_ALLOC(SH_BUFSIZE);
	  tmp    = sh_util_safe_name(fullpath);

	  (void) sl_snprintf(msg, SH_BUFSIZE, 
			     _("Race detected.  errno = %ld"), status);
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle (ShSuidchkSeverity,
			   FIL__, __LINE__, 
			   status,
			   MSG_SUID_QREPORT, msg,
			   tmp );
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  SH_FREE(tmp);
	  SH_FREE(msg);
	  cperm_status = -1;
	}
    }
  
  if ((fileInfo.st_mode & S_ISUID) > 0)
    fileInfo.st_mode -= S_ISUID;
  if ((fileInfo.st_mode & S_ISGID) > 0)
    fileInfo.st_mode -= S_ISGID;
  
  if (cperm_status == 0)
    {
      if (fchmod(file_d, fileInfo.st_mode) == -1)
	{
	  status = errno;
	  msg    = SH_ALLOC(SH_BUFSIZE);
	  tmp    = sh_util_safe_name(fullpath);

	  (void) sl_snprintf(msg, SH_BUFSIZE, 
			     _("Problem quarantining file.  File NOT quarantined.  errno = %ld"), 
			     status);
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle (ShSuidchkSeverity,
			   FIL__, __LINE__, 
			   status,
			   MSG_SUID_QREPORT,
			   msg, tmp );
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  SH_FREE(tmp);
	  SH_FREE(msg);
	}
      else
	{
	  tmp    = sh_util_safe_name(fullpath);
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle (ShSuidchkSeverity,
			   FIL__, __LINE__, 
			   0,
			   MSG_SUID_QREPORT,
			   _("Quarantine method applied"),
			   tmp );
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  SH_FREE(tmp);
	}
    }
  
  if (0 != (caperr = sl_drop_cap_qdel()))
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle((-1), FIL__, __LINE__, 
		      caperr, MSG_E_SUBGEN,
		      sh_error_message (caperr, errbuf, sizeof(errbuf)), 
		      _("sl_drop_cap_qdel"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }
  
  if (file_d != -1)
    {
      do {
	status = sl_close_fd (FIL__, __LINE__, file_d);
      } while (status == -1 && errno == EINTR);
      
      if (-1 == status)
	{
	  status = errno;
	  msg    = SH_ALLOC(SH_BUFSIZE);
	  tmp    = sh_util_safe_name(fullpath);

	  (void) sl_snprintf(msg, SH_BUFSIZE, 
			     _("I/O error.  errno = %ld"), status);
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle (ShSuidchkSeverity,
			   FIL__, __LINE__, 
			   status,
			   MSG_SUID_QREPORT, msg,
			   tmp );
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  SH_FREE(tmp);
	  SH_FREE(msg);
	}
    }
  return;
}

static void report_file (const char * tmpcat, file_type * theFile, 
			 char * timestrc, char * timestra, char * timestrm)
{
  char * msg = SH_ALLOC(SH_BUFSIZE);
  char * tmp = sh_util_safe_name(tmpcat);

  msg[0] = '\0';
  /*@-usedef@*/

#ifdef SH_USE_XML
  (void) sl_snprintf(msg, SH_BUFSIZE, _("owner_new=\"%s\" iowner_new=\"%ld\" group_new=\"%s\" igroup_new=\"%ld\" size_new=\"%lu\" ctime_new=\"%s\" atime_new=\"%s\" mtime_new=\"%s\""), 
		     theFile->c_owner, theFile->owner, 
		     theFile->c_group, theFile->group, 
		     (unsigned long) theFile->size, 
		     timestrc, timestra, timestrm);
#else
  (void) sl_snprintf(msg, SH_BUFSIZE, _("owner_new=<%s>, iowner_new=<%ld>, group_new=<%s>, igroup_new=<%ld>, filesize=<%lu>, ctime=<%s>, atime=<%s>, mtime=<%s>"), 
		     theFile->c_owner, theFile->owner, 
		     theFile->c_group, theFile->group, 
		     (unsigned long) theFile->size, 
		     timestrc, timestra, timestrm);
#endif
  /*@+usedef@*/
  
  SH_MUTEX_LOCK(mutex_thread_nolog);
  sh_error_handle (ShSuidchkSeverity, FIL__, __LINE__, 
		   0, MSG_SUID_POLICY,
		   _("suid/sgid file not in database"),
		   tmp, msg );
  SH_MUTEX_UNLOCK(mutex_thread_nolog);
  SH_FREE(tmp);
  SH_FREE(msg);
  return;
}

/* This variable is not used anywhere. It only exists
 * to assign &dirlist to it, which keeps gcc from
 * putting it into a register, and avoids the 'clobbered
 * by longjmp' warning. And no, 'volatile' proved insufficient.
 */
static void * sh_dummy_dirlist = NULL;
static void * sh_dummy_itmp    = NULL;


static
int sh_suidchk_check_internal (char * iname)
{
  DIR *           thisDir = NULL;
  struct dirent * thisEntry;
  char          * tmpcat;
  char          * tmp;
  char            timestrc[32];
  char            timestra[32];
  char            timestrm[32];
  struct stat     buf;
  volatile int    status;
  int             fflags;
  char          * fs;
  volatile long   sl_status;
  file_type     * theFile = NULL;
  char            fileHash[2*(KEY_LEN + 1)];

  struct sh_dirent * dirlist;
  struct sh_dirent * dirlist_orig;
  char errbuf[SH_ERRBUF_SIZE];

  SL_ENTER(_("sh_suidchk_check_internal"));

  /* Take the address to keep gcc from putting it into a register. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_dirlist = (void*) &dirlist;
  sh_dummy_itmp    = (void*) &tmp;

  if (iname == NULL)
    {
      TPT((0, FIL__, __LINE__ , _("msg=<directory name is NULL>\n")));
      SL_RETURN( (-1), _("sh_suidchk_check_internal"));
    }

  if (sig_urgent > 0) {
    SL_RETURN( (0), _("sh_suidchk_check_internal"));
  }

  thisDir = opendir (iname);

  if (thisDir == NULL)
    {
      status = errno;
      tmp = sh_util_safe_name(iname);
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle (ShDFLevel[SH_ERR_T_DIR], FIL__, __LINE__, status, 
		       MSG_E_OPENDIR,
		       sh_error_message (status, errbuf, sizeof(errbuf)), tmp);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      SH_FREE(tmp);
      SL_RETURN( (-1), _("sh_suidchk_check_internal"));
    }

  /* Loop over directory entries
   */
  SH_MUTEX_LOCK(mutex_readdir);

  dirlist      = NULL;
  dirlist_orig = NULL;

  do {

    thisEntry = readdir (thisDir);

    if (thisEntry != NULL) {

      if (sl_strcmp (thisEntry->d_name, ".") == 0)
	continue;

      if (sl_strcmp (thisEntry->d_name, "..") == 0)
	continue;

      dirlist = addto_sh_dirlist (thisEntry, dirlist);
    }

  } while (thisEntry != NULL);

  SH_MUTEX_UNLOCK(mutex_readdir);

  closedir(thisDir);

  dirlist_orig = dirlist;

  sl_status = SL_ENONE;

  do {

    /* If the directory is empty, dirlist = NULL
     */
    if (!dirlist)
      break;

    if (sig_urgent > 0) {
      SL_RETURN( (0), _("sh_suidchk_check_internal"));
    }

    tmpcat = SH_ALLOC(PATH_MAX);
    (void) sl_strlcpy(tmpcat, iname, PATH_MAX);
    
    if ((sl_strlen(tmpcat) != sl_strlen(iname)) || (tmpcat[0] == '\0'))
      {
	sl_status = SL_ETRUNC;
      }
    else
      {
	if (tmpcat[1] != '\0') 
	  sl_status = sl_strlcat(tmpcat, "/",                 PATH_MAX);
      }

    if (! SL_ISERROR(sl_status))
      sl_status = sl_strlcat(tmpcat, dirlist->sh_d_name,   PATH_MAX);

    if (SL_ISERROR(sl_status))
      {
	tmp = sh_util_safe_name(tmpcat);
	SH_MUTEX_LOCK(mutex_thread_nolog);
	sh_error_handle ((-1), FIL__, __LINE__, (int) sl_status, 
			 MSG_E_SUBGPATH,
			 _("path too long"),
			 _("sh_suidchk_check_internal"), tmp );
	SH_MUTEX_UNLOCK(mutex_thread_nolog);
	SH_FREE(tmp);
	SH_FREE(tmpcat);
	dirlist = dirlist->next;
	continue;
      }

    ++FileLimNum;
    ++FileLimTotal;

    /* Rate limit (Fps == Files per second)
     */
    if ((ShSuidchkFps > 0 && FileLimNum > ShSuidchkFps) &&
	(ShSuidchkYield == S_FALSE))
      {
	FileLimNum  = 0;
	FileLimNow  = time(NULL);
	
	if ( (FileLimNow  - FileLimStart) > 0 && 
	     FileLimTotal/(FileLimNow  - FileLimStart) > ShSuidchkFps )
	  (void) retry_msleep((int)((FileLimTotal/(FileLimNow-FileLimStart))/
				    ShSuidchkFps) , 0);
      }
	      
    status = (int) retry_lstat(FIL__, __LINE__, tmpcat, &buf);

    if (status != 0)
      {
	volatile int elevel = SH_ERR_ERR;
	size_t tlen;

	status = errno;
	tmp = sh_util_safe_name(tmpcat);
	tlen = strlen(tmp);
	if (tlen >= 6 && 0 == strcmp(&tmp[tlen-6], _("/.gvfs")))
	  elevel = SH_ERR_NOTICE;
	else if (tlen >= 5 && 0 == strcmp(&tmp[tlen-5], _("/gvfs")))
	  elevel = SH_ERR_NOTICE;

        /* If we are scanning a temporary directory where dirs and files
	 * can be created/deleted, an lstat() error is something which
	 * may occur frequently. As a missing dir/file is not an important
	 * problem for the suidcheck, the error level is only SH_ERR_NOTICE. 
	 */
        if (status == ENOENT)
          elevel = SH_ERR_NOTICE;

	SH_MUTEX_LOCK(mutex_thread_nolog);
	sh_error_handle (elevel, FIL__, __LINE__, status, MSG_ERR_LSTAT,
			 sh_error_message(status, errbuf, sizeof(errbuf)),
			 tmp );
	SH_MUTEX_UNLOCK(mutex_thread_nolog);
	SH_FREE(tmp);
      }
    else
      {
	if (/*@-usedef@*/S_ISDIR(buf.st_mode)/*@+usedef@*/ &&
	    (ShSuidchkExclude == NULL || 
	     NULL == zAVL_string_get(ShSuidchkExclude, tmpcat)))
	  {
	    /* fs is a STATIC string or NULL
	     */
	    fs = filesystem_type (tmpcat, tmpcat, &buf);
	    if (fs != NULL 
#ifndef SH_SUIDTESTDIR
		&& 
		0 != strncmp (_("afs"),     fs, 3) && 
		0 != strncmp (_("devfs"),   fs, 5) &&
		0 != strncmp (_("fdesc"),   fs, 5) &&
		0 != strncmp (_("iso9660"), fs, 7) &&
		0 != strncmp (_("cd9660"),  fs, 6) &&
		0 != strncmp (_("lustre"),  fs, 6) &&
		0 != strncmp (_("mmfs"),    fs, 4) && 
		0 != strncmp (_("msdos"),   fs, 5) &&
		0 != strncmp (_("nfs"),     fs, 3) &&
		0 != strncmp (_("proc"),    fs, 4) &&
		0 != strncmp (_("sysfs"),   fs, 5) &&
		0 != strncmp (_("vfat"),    fs, 4)
#endif 
		)
	      {
		if ((ShSuidchkNosuid == S_TRUE) || 
		    (0 != strncmp (_("nosuid"),  fs, 6)))
		  /* fprintf(stderr, "%s: %s\n", fs, tmpcat); */
		  (void) sh_suidchk_check_internal(tmpcat);
	      }
	  }
	else if (S_ISREG(buf.st_mode) &&
		 (0 !=(S_ISUID & buf.st_mode) ||
#if defined(HOST_IS_LINUX)
		  (0 !=(S_ISGID & buf.st_mode) && 
		   0 !=(S_IXGRP & buf.st_mode)) 
#else  
		  0 !=(S_ISGID & buf.st_mode)
#endif
		  )
		 )
	  {
	    int dummy;
	    int class;
	    unsigned long check_flags = 0;

	    theFile = SH_ALLOC(sizeof(file_type));

	    (void) sl_strlcpy (theFile->fullpath, tmpcat, PATH_MAX);
	    theFile->check_flags  = sh_files_maskof(SH_LEVEL_READONLY);
	    CLEAR_SH_FFLAG_REPORTED(theFile->file_reported);
	    theFile->attr_string = NULL;
	    theFile->link_path   = NULL;
	    
	    sh_files_search_file(tmpcat, &class,  &check_flags, &dummy);
	    if ((check_flags & MODI_PREL) != 0)
	      MODI_SET(theFile->check_flags, MODI_PREL);

	    status = sh_unix_getinfo (ShDFLevel[SH_ERR_T_RO], 
				      dirlist->sh_d_name,
				      theFile, fileHash, 0);
	    
	    tmp = sh_util_safe_name(tmpcat);
	    
	    if (status != 0)
	      {
		SH_MUTEX_LOCK(mutex_thread_nolog);
		sh_error_handle (ShSuidchkSeverity, FIL__, __LINE__, 
				 0, MSG_E_SUBGPATH,
				 _("Could not check suid/sgid file"),
				 _("sh_suidchk_check_internal"),
				 tmp);
		SH_MUTEX_UNLOCK(mutex_thread_nolog);
	      }
	    else
	      {
		
		if ( sh.flag.update   == S_TRUE && 
		     (sh.flag.checkSum == SH_CHECK_INIT  || 
		      sh.flag.checkSum == SH_CHECK_CHECK))
		  {
		    int compret;

		    /* Updating database. Report new files that
		     * are not in database already. Then compare
		     * to database and report changes.
		     */
		    if (-1 == sh_hash_have_it (tmpcat))
		      {
			SH_MUTEX_LOCK(mutex_thread_nolog);
			sh_error_handle ((-1), FIL__, __LINE__, 
					 0, MSG_SUID_FOUND, tmp );
			SH_MUTEX_UNLOCK(mutex_thread_nolog);
		      }
		    else
		      {
			SH_MUTEX_LOCK(mutex_thread_nolog);
			sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 
					 0, MSG_SUID_FOUND, tmp );
			SH_MUTEX_UNLOCK(mutex_thread_nolog);
		      }
		    
		    SH_MUTEX_LOCK(mutex_thread_nolog);
		    compret = sh_hash_compdata (SH_LEVEL_READONLY, 
						theFile, fileHash,
						_("[SuidCheck]"), 
						ShSuidchkSeverity);
		    SH_MUTEX_UNLOCK(mutex_thread_nolog);

		    if (compret == 0)
		      {
			sh_hash_pushdata_memory (theFile, fileHash); /* no call to sh_error_handle */
		      }
		    
		    sh_hash_set_flag(tmpcat, SH_FFLAG_SUIDCHK); /* no call to sh_error_handle */
		    
		  }
		
		else if (sh.flag.checkSum == SH_CHECK_INIT  && 
			 sh.flag.update == S_FALSE )
		  {
		    /* Running init. Report on files detected.
		     */
		    sh_dbIO_data_write (theFile, fileHash); /* no call to sh_error_handle */
		    SH_MUTEX_LOCK(mutex_thread_nolog);
		    sh_error_handle ((-1), FIL__, __LINE__, 
				     0, MSG_SUID_FOUND, tmp );
		    SH_MUTEX_UNLOCK(mutex_thread_nolog);
		  }
		
		else if (sh.flag.checkSum == SH_CHECK_CHECK )
		  {
		    /* Running file check. Report on new files
		     * detected, and quarantine them.
		     */
		    SH_MUTEX_LOCK(mutex_thread_nolog);
		    sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 
				     0, MSG_SUID_FOUND, tmp );
		    SH_MUTEX_UNLOCK(mutex_thread_nolog);
		    
		    fflags = sh_hash_getflags(tmpcat); /* no call to sh_error_handle */
		    
		    if ( (-1 == fflags) || (!SH_FFLAG_SUIDCHK_SET(fflags)))
		      {
			if (-1 == fflags)
			  {
			    (void) sh_unix_gmttime (theFile->ctime, timestrc, sizeof(timestrc)); 
			    (void) sh_unix_gmttime (theFile->atime, timestra, sizeof(timestra)); 
			    (void) sh_unix_gmttime (theFile->mtime, timestrm, sizeof(timestrm));

			    report_file(tmpcat, theFile, timestrc, timestra, timestrm);
			  }
			/* Quarantine file according to configured method
			 */
			if (ShSuidchkQEnable == S_TRUE)
			  {
			    switch (ShSuidchkQMethod)
			      {
			      case SH_Q_DELETE:
				sh_q_delete(theFile->fullpath);
				break;
			      case SH_Q_CHANGEPERM:
				sh_q_changeperm(theFile->fullpath);
				break;
			      case SH_Q_MOVE:
				sh_q_move(theFile->fullpath, theFile, timestrc, timestra, timestrm);
				break;
			      default:
				SH_MUTEX_LOCK(mutex_thread_nolog);
				sh_error_handle (ShSuidchkSeverity, FIL__,
						 __LINE__, 0, MSG_SUID_QREPORT,
						 _("Bad quarantine method"), tmp);
				SH_MUTEX_UNLOCK(mutex_thread_nolog);
				break;
			      }
			  }
			else
			  {
			    /* 1.8.1 push file to in-memory database
			     */
			    SH_MUTEX_LOCK(mutex_thread_nolog);
			    (void) sh_hash_compdata (SH_LEVEL_READONLY,
						     theFile, fileHash,
						     _("[SuidCheck]"),
						     ShSuidchkSeverity);
			    SH_MUTEX_UNLOCK(mutex_thread_nolog);
			    
			    sh_hash_set_flag(tmpcat, SH_FFLAG_SUIDCHK); /* no call to sh_error_handle */
			    
			  }
		      }
		    else
		      {
			/* File exists. Check for modifications.
			 */
			SH_MUTEX_LOCK(mutex_thread_nolog);
			(void) sh_hash_compdata (SH_LEVEL_READONLY, 
						 theFile, fileHash,
						 _("[SuidCheck]"),
						 ShSuidchkSeverity);
			SH_MUTEX_UNLOCK(mutex_thread_nolog);	
			sh_hash_set_flag(tmpcat, SH_FFLAG_SUIDCHK); /* no call to sh_error_handle */
			
		      }
		  }
	      }
	    SH_FREE(tmp);
	    if (theFile->attr_string) SH_FREE(theFile->attr_string);
	    if (theFile->link_path)   SH_FREE(theFile->link_path);
	    SH_FREE(theFile);
	  }
      }
    SH_FREE(tmpcat);

  
#ifdef HAVE_SCHED_YIELD
    if (ShSuidchkYield == S_TRUE)
      {
	if (sched_yield() == -1)
	  {
	    status = errno;
	    SH_MUTEX_LOCK(mutex_thread_nolog);
	    sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_SUBGEN,
			     _("Failed to release time slice"),
			     _("sh_suidchk_check_internal") );
	    SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  }
      }
#endif
  
    dirlist = dirlist->next;

  }  while (dirlist != NULL);


  kill_sh_dirlist (dirlist_orig);

  SL_RETURN( (0), _("sh_suidchk_check_internal"));
}

/*************
 *
 * module init
 *
 *************/
int sh_suidchk_init (struct mod_type * arg)
{
#ifndef HAVE_PTHREAD
  (void) arg;
#endif

  if (ShSuidchkActive == S_FALSE)
    return SH_MOD_FAILED;

#ifdef HAVE_PTHREAD
  if (arg != NULL && arg->initval < 0 &&
      (sh.flag.isdaemon == S_TRUE || sh.flag.loop == S_TRUE))
    {
      if (0 == sh_pthread_create(sh_threaded_module_run, (void *)arg))
	return SH_MOD_THREAD;
      else
	return SH_MOD_FAILED;
    }
  else if (arg != NULL && arg->initval == SH_MOD_THREAD &&
	   (sh.flag.isdaemon == S_TRUE || sh.flag.loop == S_TRUE))
    {
      return SH_MOD_THREAD;
    }
#endif

  return (0);
}


/*************
 *
 * module cleanup
 *
 *************/
int sh_suidchk_end ()
{
  return (0);
}


/*************
 *
 * module timer
 *
 *************/
int sh_suidchk_timer (time_t tcurrent)
{
  if (sh.flag.checkSum == SH_CHECK_INIT)
    return -1;

  /* One-shot (not daemon and not loop forever)
   */
  if (sh.flag.isdaemon != S_TRUE && sh.flag.loop == S_FALSE)
    return -1;

  if (ShSuidchkSched != NULL)
    {
      return test_sched(ShSuidchkSched);
    }
  if ((time_t) (tcurrent - lastcheck) >= ShSuidchkInterval)
    {
      lastcheck  = tcurrent;
      return (-1);
    }
  return 0;
}

/*************
 *
 * module check
 *
 *************/

int sh_suidchk_check ()
{
  volatile int status;

  SL_ENTER(_("sh_suidchk_check"));

  if (ShSuidchkActive == S_FALSE)
    SL_RETURN(-1, _("sh_suidchk_check"));

  SH_MUTEX_LOCK(mutex_thread_nolog);
  sh_error_handle (SH_ERR_INFO, FIL__, __LINE__, EINVAL, MSG_E_SUBGEN,
		   _("Checking for SUID programs"),
		   _("sh_suidchk_check") );
  SH_MUTEX_UNLOCK(mutex_thread_nolog);

  FileLimNow        = time(NULL);
  FileLimStart      = FileLimNow;
  FileLimNum        = 0;
  FileLimTotal      = 0;

#ifdef SH_SUIDTESTDIR
  status = sh_suidchk_check_internal (SH_SUIDTESTDIR);
#else
  status = sh_suidchk_check_internal ("/");
#endif

  SH_MUTEX_LOCK(mutex_thread_nolog);
  sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_SUID_SUMMARY,
		   FileLimTotal,
		   (long) (time(NULL) - FileLimStart) );
  SH_MUTEX_UNLOCK(mutex_thread_nolog);

  SL_RETURN(status, _("sh_suidchk_check"));
}

/*************
 *
 * module setup
 *
 *************/

int sh_suidchk_set_severity  (const char * c)
{
  int retval;
  char tmp[32];

  SL_ENTER(_("sh_suidchk_set_severity"));
  tmp[0] = '='; tmp[1] = '\0';
  (void) sl_strlcat (tmp, c, 32);
  retval = sh_error_set_level (tmp, &ShSuidchkSeverity);
  SL_RETURN(retval, _("sh_suidchk_set_severity"));
}

int sh_suidchk_set_exclude (const char * c)
{
  int ret = 0;
  SL_ENTER(_("sh_suidchk_set_exclude"));

  if (c == NULL || c[0] == '\0')
    {
      SL_RETURN(-1, _("sh_suidchk_set_exclude"));
    }

  if (0 == sl_strncmp(c, _("NULL"), 4))
    {
      if (ShSuidchkExclude != NULL)
	sh_suid_exclude_free();
      SL_RETURN(0, _("sh_suidchk_set_exclude"));
    }

  ret = sh_suid_exclude_add(c);

  SL_RETURN(ret, _("sh_suidchk_set_exclude"));
}

int sh_suidchk_set_timer (const char * c)
{
  volatile long val;

  SL_ENTER(_("sh_suidchk_set_timer"));

  val = strtol (c, (char **)NULL, 10);
  if (val <= 0)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS,
		       _("suidchk timer"), c);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }
  val = (val <= 0 ? 7200 : val);

  ShSuidchkInterval = (time_t) val;
  SL_RETURN( 0, _("sh_suidchk_set_timer"));
}


static void sh_suidchk_free_schedule (void)
{
  sh_schedule_t * current = ShSuidchkSched;
  sh_schedule_t * next    = NULL;

  while (current != NULL)
    {
      next = current->next;
      SH_FREE(current);
      current = next;
    }
  ShSuidchkSched = NULL;
  return;
}

int sh_suidchk_reconf ()
{
  SH_MUTEX_LOCK(mutex_suid_check);
  sh_suidchk_free_schedule();
  set_defaults();
  SH_MUTEX_UNLOCK(mutex_suid_check);
  return 0;
}

int sh_suidchk_set_schedule (const char * str)
{
  int status;
  sh_schedule_t * newSched = NULL;

  SL_ENTER(_("sh_suidchk_set_schedule"));

  /*
  if (ShSuidchkSched != NULL)
    {
      SH_FREE(ShSuidchkSched);
      ShSuidchkSched = NULL;
    }
  */

  if (0 == sl_strncmp(str, _("NULL"), 4))
    {
      (void) sh_suidchk_free_schedule ();
      return 0;
    }

  newSched = SH_ALLOC(sizeof(sh_schedule_t));
  status = create_sched(str, newSched);
  if (status != 0)
    {
      SH_FREE(newSched);
      newSched = NULL;
    }
  else
    {
      newSched->next = ShSuidchkSched;
      ShSuidchkSched = newSched;
    }
  SL_RETURN( status, _("sh_suidchk_set_schedule"));
}



int sh_suidchk_set_fps (const char * c)
{
  volatile long val;

  SL_ENTER(_("sh_suidchk_set_fps"));

  val = strtol (c, (char **)NULL, 10);
  if (val < 0)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS,
		       _("suidchk fps"), c);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }
  val = (val < 0 ? 0 : val);

  ShSuidchkFps = val;
  SL_RETURN( 0, _("sh_suidchk_set_fps"));
}

int sh_suidchk_set_yield (const char * c)
{
  int i;
  SL_ENTER(_("sh_suidchk_set_yield"));
#ifdef HAVE_SCHED_YIELD
  i = sh_util_flagval(c, &ShSuidchkYield);
#else
  (void) c; /* cast to void to avoid compiler warning */
  i = -1;
#endif
  SL_RETURN(i, _("sh_suidchk_set_yield"));
}

int sh_suidchk_set_activate (const char * c)
{
  int i;
  SL_ENTER(_("sh_suidchk_set_activate"));
  i = sh_util_flagval(c, &ShSuidchkActive);
  SL_RETURN(i, _("sh_suidchk_set_activate"));
}

int sh_suidchk_set_nosuid (const char * c)
{
  int i;
  SL_ENTER(_("sh_suidchk_set_nosuid"));
  i = sh_util_flagval(c, &ShSuidchkNosuid);
  SL_RETURN(i, _("sh_suidchk_set_nosuid"));
}

int sh_suidchk_set_quarantine (const char * c)
{
  int i;
  SL_ENTER(_("sh_suidchk_set_quarantine"));
  i = sh_util_flagval(c, &ShSuidchkQEnable);
  SL_RETURN(i, _("sh_suidchk_set_quarantine"));
}

int sh_suidchk_set_qdelete (const char * c)
{
  int i;
  SL_ENTER(_("sh_suidchk_set_qdelete"));
  i = sh_util_flagval(c, &ShSuidchkQDelete);
  SL_RETURN(i, _("sh_suidchk_set_qdelete"));
}

int sh_suidchk_set_qmethod (const char * c)
{
  volatile long val;
  volatile int  ret = 0;
  struct stat buf;

  SL_ENTER(_("sh_suidchk_set_qmethod"));

  val = strtol (c, (char **)NULL, 10);
  if (val < 0)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS,
		       _("suidchk qmethod"), c);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      ret = -1;
    }
  else
    {
      switch (val)
      {
        case SH_Q_DELETE:
          ShSuidchkQMethod = SH_Q_DELETE;
          break;
        case SH_Q_CHANGEPERM:
          ShSuidchkQMethod = SH_Q_CHANGEPERM;
          break;
        case SH_Q_MOVE:
          if (retry_stat (FIL__, __LINE__, DEFAULT_QDIR, &buf) != 0)
	    {
	      if (mkdir (DEFAULT_QDIR, 0750) == -1)
		{
		  SH_MUTEX_LOCK(mutex_thread_nolog);
		  sh_error_handle ((-1), FIL__, __LINE__, EINVAL,
				   MSG_SUID_ERROR,
				   _("Unable to create quarantine directory"));
		  SH_MUTEX_UNLOCK(mutex_thread_nolog);
		}
	    }
          ShSuidchkQMethod = SH_Q_MOVE;
          break;
        default:
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS,
			   _("suidchk qmethod"), c);
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
          ShSuidchkQMethod = -1;
	  ret = -1;
          break;
      }
    }

  SL_RETURN( ret, _("sh_suidchk_set_qmethod"));
}

#if defined(FSTYPE_STATFS) || defined(FSTYPE_AIX_STATFS)
/* dirname.c -- return all but the last element in a path
   Copyright (C) 1990 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

/* Return the leading directories part of PATH,
   allocated with malloc.  If out of memory, return 0.
   Assumes that trailing slashes have already been
   removed.  */

char * sh_dirname (const char * path)
{
  char *newpath;
  char *slash;
  int length;                   /* Length of result, not including NUL.  */

  slash = strrchr (path, '/');
  if (slash == NULL)
    {
      /* File is in the current directory.  */
      path = ".";
      length = 1;
    }
  else
    {
      /* Remove any trailing slashes from the result.  */
      while (slash > path && *slash == '/')
        --slash;

      length = slash - path + 1;
    }
  newpath = (char *) SH_ALLOC (length + 1);
  if (newpath == NULL)
    return NULL;
  strncpy (newpath, path, length);
  newpath[length] = '\0';
  return newpath;
}
/* #ifdef FSTYPE_STATFS */
#endif

/* fstype.c -- determine type of filesystems that files are on
   Copyright (C) 1990, 91, 92, 93, 94 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

/* Written by David MacKenzie <djm@gnu.ai.mit.edu>. */

/* Modified by R. Wichmann: 
   - replaced error()   by sh_error_handle()
   - replaced xstrdup() by sl_strdup()
   - replaced strstr()  by sl_strstr()
   - some additions to recognize nosuid fs
*/

/* modetype.h -- file type bits definitions for POSIX systems
   Requires sys/types.h sys/stat.h.
   Copyright (C) 1990 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

/* POSIX.1 doesn't mention the S_IFMT bits; instead, it uses S_IStype
   test macros.  To make storing file types more convenient, define
   them; the values don't need to correspond to what the kernel uses,
   because of the way we use them. */
#ifndef S_IFMT			/* Doesn't have traditional Unix macros. */
#define S_IFBLK 1
#define S_IFCHR 2
#define S_IFDIR 4
#define S_IFREG 8
#ifdef S_ISLNK
#define S_IFLNK 16
#endif
#ifdef S_ISFIFO
#define S_IFIFO 32
#endif
#ifdef S_ISSOCK
#define S_IFSOCK 64
#endif
#endif /* !S_IFMT */

#ifdef STAT_MACROS_BROKEN
#undef S_ISBLK
#undef S_ISCHR
#undef S_ISDIR
#undef S_ISREG
#undef S_ISFIFO
#undef S_ISLNK
#undef S_ISSOCK
#undef S_ISMPB
#undef S_ISMPC
#undef S_ISNWK
#endif

/* Do the reverse: define the POSIX.1 macros for traditional Unix systems
   that don't have them.  */
#if !defined(S_ISBLK) && defined(S_IFBLK)
#define	S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#endif
#if !defined(S_ISCHR) && defined(S_IFCHR)
#define	S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#endif
#if !defined(S_ISDIR) && defined(S_IFDIR)
#define	S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
#if !defined(S_ISREG) && defined(S_IFREG)
#define	S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif
#if !defined(S_ISFIFO) && defined(S_IFIFO)
#define	S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#endif
#if !defined(S_ISLNK) && defined(S_IFLNK)
#define	S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#endif
#if !defined(S_ISSOCK) && defined(S_IFSOCK)
#define	S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#endif
#if !defined(S_ISMPB) && defined(S_IFMPB) /* V7 */
#define S_ISMPB(m) (((m) & S_IFMT) == S_IFMPB)
#define S_ISMPC(m) (((m) & S_IFMT) == S_IFMPC)
#endif
#if !defined(S_ISNWK) && defined(S_IFNWK) /* HP/UX */
#define S_ISNWK(m) (((m) & S_IFMT) == S_IFNWK)
#endif


static char *filesystem_type_uncached (char *path, char *relpath, 
				       struct stat *statp);

#ifdef FSTYPE_MNTENT		/* 4.3BSD etc.  */
static int xatoi (const char *cp);
#endif

#ifdef FSTYPE_MNTENT		/* 4.3BSD, SunOS, HP-UX, Dynix, Irix.  */
#include <mntent.h>
#if !defined(MOUNTED)
# if defined(MNT_MNTTAB)	/* HP-UX.  */
#  define MOUNTED MNT_MNTTAB
# endif
# if defined(MNTTABNAME)	/* Dynix.  */
#  define MOUNTED MNTTABNAME
# endif
#endif
#endif

#ifdef FSTYPE_GETMNT		/* Ultrix.  */
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/fs_types.h>
#endif

#ifdef FSTYPE_USG_STATFS	/* SVR3.  */
#include <sys/statfs.h>
#include <sys/fstyp.h>
#endif

#ifdef FSTYPE_STATVFS		/* SVR4.  */
#include <sys/statvfs.h>
#include <sys/fstyp.h>
#endif

#ifdef FSTYPE_STATFS		/* 4.4BSD.  */
#include <sys/param.h>		/* NetBSD needs this.  */
#include <sys/mount.h>

#ifndef MFSNAMELEN		/* NetBSD defines this.  */
static char *
fstype_to_string (t)
     short t;
{
#ifdef INITMOUNTNAMES		/* Defined in 4.4BSD, not in NET/2.  */
  static char *mn[] = INITMOUNTNAMES;
  if (t >= 0 && t <= MOUNT_MAXTYPE)
    return mn[t];
  else
    return "?";
#else /* !INITMOUNTNAMES */
  switch (t)
    {
#ifdef MOUNT_UFS
    case MOUNT_UFS:
      return _("ufs");
#endif
#ifdef MOUNT_ISO9660
    case MOUNT_ISO9660:
      return _("iso9660fs");
#endif
#ifdef MOUNT_CD9660
    case MOUNT_CD9660:
      return _("cd9660");
#endif
#ifdef MOUNT_NFS
    case MOUNT_NFS:
      return _("nfs");
#endif
#ifdef MOUNT_PC
    case MOUNT_PC:
      return _("pc");
#endif
#ifdef MOUNT_MFS
    case MOUNT_MFS:
      return _("mfs");
#endif
#ifdef MOUNT_LO
    case MOUNT_LO:
      return _("lofs");
#endif
#ifdef MOUNT_TFS
    case MOUNT_TFS:
      return _("tfs");
#endif
#ifdef MOUNT_TMP
    case MOUNT_TMP:
      return _("tmp");
#endif
#ifdef MOUNT_MSDOS
    case MOUNT_MSDOS:
      return _("msdos");
#endif
#ifdef MOUNT_LFS
    case MOUNT_LFS:
      return _("lfs");
#endif
#ifdef MOUNT_LOFS
    case MOUNT_LOFS:
      return _("lofs");
#endif
#ifdef MOUNT_FDESC
    case MOUNT_FDESC:
      return _("fdesc");
#endif
#ifdef MOUNT_PORTAL
    case MOUNT_PORTAL:
      return _("portal");
#endif
#ifdef MOUNT_NULL
    case MOUNT_NULL:
      return _("null");
#endif
#ifdef MOUNT_UMAP
    case MOUNT_UMAP:
      return _("umap");
#endif
#ifdef MOUNT_KERNFS
    case MOUNT_KERNFS:
      return _("kernfs");
#endif
#ifdef MOUNT_PROCFS
    case MOUNT_PROCFS:
      return _("procfs");
#endif
#ifdef MOUNT_DEVFS
    case MOUNT_DEVFS:
      return _("devfs");
#endif
#ifdef MOUNT_EXT2FS
    case MOUNT_EXT2FS:
      return _("ext2fs");
#endif
#ifdef MOUNT_UNION
    case MOUNT_UNION:
      return _("union");
#endif
    default:
      return "?";
    }
#endif /* !INITMOUNTNAMES */
}
#endif /* !MFSNAMELEN */
#endif /* FSTYPE_STATFS */

#ifdef FSTYPE_AIX_STATFS	/* AIX.  */
#include <sys/vmount.h>
#include <sys/statfs.h>

#define FSTYPE_STATFS		/* Otherwise like 4.4BSD.  */
#define f_type f_vfstype

static char *
fstype_to_string (t)
     short t;
{
  switch (t)
    {
    case MNT_AIX:
      return _("aix");	/* AIX 4.3: NFS filesystems are actually MNT_AIX. */
#ifdef MNT_NAMEFS
    case MNT_NAMEFS:
      return _("namefs");
#endif
    case MNT_NFS:
      return _("nfs");
    case MNT_JFS:
      return _("jfs");
    case MNT_CDROM:
      return _("cdrom");
#ifdef MNT_PROCFS
    case MNT_PROCFS:
      return _("procfs");
#endif
#ifdef MNT_SFS
    case MNT_SFS:
      return _("sfs");
#endif
#ifdef MNT_CACHEFS
    case MNT_CACHEFS:
      return _("cachefs");
#endif
#ifdef MNT_NFS3
    case MNT_NFS3:
      return _("nfs3");
#endif
#ifdef MNT_AUTOFS
    case MNT_AUTOFS:
      return _("autofs");
#endif
#ifdef MNT_VXFS
    case MNT_VXFS:
      return _("vxfs");
#endif
#ifdef MNT_VXODM
    case MNT_VXODM:
      return _("veritasfs");
#endif
#ifdef MNT_UDF
    case MNT_UDF:
      return _("udfs");
#endif
#ifdef MNT_NFS4
    case MNT_NFS4:
      return _("nfs4");
#endif
#ifdef MNT_RFS4
    case MNT_RFS4:
      return _("nfs4");
#endif
#ifdef MNT_CIFS
    case MNT_CIFS:
      return _("cifs");
#endif
    default:
      return "?";
    }
}
#endif /* FSTYPE_AIX_STATFS */

#ifdef AFS
#include <netinet/in.h>
#include <afs/venus.h>
#if __STDC__
/* On SunOS 4, afs/vice.h defines this to rely on a pre-ANSI cpp.  */
#undef _VICEIOCTL
#define _VICEIOCTL(id)  ((unsigned int ) _IOW('V', id, struct ViceIoctl))
#endif
#ifndef _IOW
/* AFS on Solaris 2.3 doesn't get this definition.  */
#include <sys/ioccom.h>
#endif

static int
in_afs (path)
     char *path;
{
  static char space[2048];
  struct ViceIoctl vi;

  vi.in_size = 0;
  vi.out_size = sizeof (space);
  vi.out = space;

  if (pioctl (path, VIOC_FILE_CELL_NAME, &vi, 1)
      && (errno == EINVAL || errno == ENOENT))
	return 0;
  return 1;
}
#endif /* AFS */

/* Nonzero if the current filesystem's type is known.  */
static int fstype_known = 0;

/* Return a static string naming the type of filesystem that the file PATH,
   described by STATP, is on.
   RELPATH is the file name relative to the current directory.
   Return "unknown" if its filesystem type is unknown.  */

static char *
filesystem_type (char * path, char * relpath, struct stat * statp)
{
  static char *current_fstype = NULL;
  static dev_t current_dev;

  if (current_fstype != NULL)
    {
      if ((0 != fstype_known) && statp->st_dev == current_dev)
	return current_fstype;	/* Cached value.  */
      SH_FREE (current_fstype);
    }
  current_dev = statp->st_dev;
  current_fstype = filesystem_type_uncached (path, relpath, statp);
  return current_fstype;
}

/* Return a newly allocated string naming the type of filesystem that the
   file PATH, described by STATP, is on.
   RELPATH is the file name relative to the current directory.
   Return "unknown" if its filesystem type is unknown.  */

void * sh_dummy_2229_type;

static char *
filesystem_type_uncached (path, relpath, statp)
     char *path;
     char *relpath;
     struct stat *statp;
{
  char * type = NULL;
#ifdef MFSNAMELEN		/* NetBSD.  */
  static char my_tmp_type[64];
#endif

#ifdef FSTYPE_MNTENT		/* 4.3BSD, SunOS, HP-UX, Dynix, Irix.  */
  char *table = MOUNTED;
  FILE *mfp;
  struct mntent *mnt;

  /* Take the address to keep gcc from putting it into a register. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_2229_type = (void *) &type;

  if (path == NULL || relpath == NULL)
    return NULL;

  mfp = setmntent (table, "r");
  if (mfp == NULL)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
		       _("setmntent() failed"),
		       _("filesystem_type_uncached") );
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      return NULL;
    }

  /* Find the entry with the same device number as STATP, and return
     that entry's fstype. */
  while (type == NULL && (mnt = getmntent (mfp)) != NULL)
    {
      const char *devopt;
      dev_t dev;
      struct stat disk_stats;

#ifdef MNTTYPE_IGNORE
      if (0 == strcmp (mnt->mnt_type, MNTTYPE_IGNORE))
	continue;
#endif

      /* Newer systems like SunOS 4.1 keep the dev number in the mtab,
	 in the options string.	 For older systems, we need to stat the
	 directory that the filesystem is mounted on to get it.

	 Unfortunately, the HPUX 9.x mnttab entries created by automountq
	 contain a dev= option but the option value does not match the
	 st_dev value of the file (maybe the lower 16 bits match?).  */

#if !defined(hpux) && !defined(__hpux__)
      devopt = sl_strstr (mnt->mnt_opts, "dev=");
      if (devopt)
	{
	  if (devopt[4] == '0' && (devopt[5] == 'x' || devopt[5] == 'X'))
	    dev = (dev_t) xatoi (devopt + 6);
	  else
	    dev = (dev_t) xatoi (devopt + 4);
	}
      else
#endif /* not hpux */
	{
	  if (stat (mnt->mnt_dir, &disk_stats) == -1)
	    {
	      char errmsg[256];
	      volatile int  elevel = SH_ERR_ERR;
	      size_t tlen = strlen(mnt->mnt_dir);

	      if (tlen >= 6 && 0 == strcmp(&((mnt->mnt_dir)[tlen-6]), _("/.gvfs")))
		elevel = SH_ERR_NOTICE;
	      else if (tlen >= 5 && 0 == strcmp(&((mnt->mnt_dir)[tlen-5]), _("/gvfs")))
		elevel = SH_ERR_NOTICE;

	      sl_snprintf(errmsg, sizeof(errmsg), _("stat(%s) failed"),
			  mnt->mnt_dir);
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle (elevel, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			       errmsg,
			       _("filesystem_type_uncached") );
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	      return NULL;
	    }
	  dev = disk_stats.st_dev;
	}

      if (dev == statp->st_dev)
	{
	  /* check for the "nosuid" option
	   */
#ifdef HAVE_HASMNTOPT
	  if (NULL == hasmntopt(mnt, "nosuid") || (ShSuidchkNosuid == S_TRUE))
	    type = mnt->mnt_type;
	  else
	    type = _("nosuid"); /* hasmntopt (nosuid) */
#else
	  type = mnt->mnt_type;
#endif
	}
    }

  if (endmntent (mfp) == 0)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
		       _("endmntent() failed"),
		       _("filesystem_type_uncached") );
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }
#endif

#ifdef FSTYPE_GETMNT		/* Ultrix.  */
  int offset = 0;
  struct fs_data fsd;

  if (path == NULL || relpath == NULL)
    return NULL;

  /* Take the address to keep gcc from putting it into a register. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_2229_type = (void*) &type;

  while (type == NULL
	 && getmnt (&offset, &fsd, sizeof (fsd), NOSTAT_MANY, 0) > 0)
    {
      if (fsd.fd_req.dev == statp->st_dev)
	type = gt_names[fsd.fd_req.fstype];
    }
#endif

#ifdef FSTYPE_USG_STATFS	/* SVR3.  */
  struct statfs fss;
  char typebuf[FSTYPSZ];

  if (path == NULL || relpath == NULL)
    return NULL;

  /* Take the address to keep gcc from putting it into a register. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_2229_type = (void*) &type;

  if (statfs (relpath, &fss, sizeof (struct statfs), 0) == -1)
    {
      /* Don't die if a file was just removed. */
      if (errno != ENOENT)
	{
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
			   _("statfs() failed"),
			   _("filesystem_type_uncached") );
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  return NULL;
	}
    }
  else if (!sysfs (GETFSTYP, fss.f_fstyp, typebuf))
    type = typebuf;
#endif

#ifdef FSTYPE_STATVFS		/* SVR4.  */
  struct statvfs fss;

  if (path == NULL || relpath == NULL)
    return NULL;

  /* Take the address to keep gcc from putting it into a register. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_2229_type = (void*) &type;

  if (statvfs (relpath, &fss) == -1)
    {
      /* Don't die if a file was just removed. */
      if (errno != ENOENT)
	{
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
			   _("statvfs() failed"),
			   _("filesystem_type_uncached") );
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  return NULL;
	}
    }
  else
    {
       type = fss.f_basetype;

       /* patch by Konstantin Khrooschev <nathoo@co.ru> 
	*/
       if( (fss.f_flag & ST_NOSUID)  && (ShSuidchkNosuid == S_FALSE))
         type = _("nosuid");
    }
  (void) statp; /* fix compiler warning */
#endif

#ifdef FSTYPE_STATFS		/* 4.4BSD.  */
  struct statfs fss;
  char *p;
#if defined(MNT_VISFLAGMASK) && defined(HAVE_STRUCT_STATFS_F_FLAGS)
  int flags;
#endif
  /* char * sh_dirname(const char *path); */

  if (path == NULL || relpath == NULL)
    return NULL;

  /* Take the address to keep gcc from putting it into a register. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_2229_type = (void*) &type;

  if (S_ISLNK (statp->st_mode))
    p = sh_dirname (relpath);
  else
    p = relpath;

  if (statfs (p, &fss) == -1)
    {
      /* Don't die if symlink to nonexisting file, or a file that was
	 just removed. */
      if (errno != ENOENT)
	{
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle ((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN,
			   _("statfs() failed"),
			   _("filesystem_type_uncached") );
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  return NULL;
	}
    }
  else
    {

#ifdef MFSNAMELEN		/* NetBSD.  */
      /* MEMORY LEAK !!!
       *	 type = sh_util_strdup (fss.f_fstypename);
       */
      sl_strlcpy (my_tmp_type, fss.f_fstypename, 64);
      type = my_tmp_type;
#else
      type = fstype_to_string (fss.f_type);
#endif

#ifdef HAVE_STRUCT_STATFS_F_FLAGS
#ifdef MNT_VISFLAGMASK
      flags = fss.f_flags & MNT_VISFLAGMASK;
      if ((flags & MNT_NOSUID) && (ShSuidchkNosuid == S_FALSE))
#else 
      if ((fss.f_flags & MNT_NOSUID) && (ShSuidchkNosuid == S_FALSE)) 
#endif
         type = _("nosuid");
#endif
    }
  if (p != relpath)
    SH_FREE (p);
#endif

#ifdef AFS
  if ((!type || !strcmp (type, "xx")) && in_afs (relpath))
    type = "afs";
#endif

  /* An unknown value can be caused by an ENOENT error condition.
     Don't cache those values.  */
  fstype_known = (int)(type != NULL);

  return sh_util_strdup (type ? type : "unknown");
}

#ifdef FSTYPE_MNTENT		/* 4.3BSD etc.  */
/* Return the value of the hexadecimal number represented by CP.
   No prefix (like '0x') or suffix (like 'h') is expected to be
   part of CP. */

static int
xatoi (cp)
     const char *cp;
{
  int val;
  
  val = 0;
  while (*cp != '\0')
    {
      /*@+charint@*/
      if (*cp >= 'a' && *cp <= 'f')
	val = val * 16 + *cp - 'a' + 10;
      else if (*cp >= 'A' && *cp <= 'F')
	val = val * 16 + *cp - 'A' + 10;
      else if (*cp >= '0' && *cp <= '9')
	val = val * 16 + *cp - '0';
      else
	break;
      /*@-charint@*/
      cp++;
    }
  return val;
}
#endif



#endif


/* #ifdef SH_USE_UTMP */
#endif



