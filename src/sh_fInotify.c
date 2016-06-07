/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2011       Rainer Wichmann                                */
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

/***************************************************************************
 *
 * This file provides a module for samhain to use inotify for file checking.
 *
 */

#include "config_xor.h"

#if (defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)) 

#include "samhain.h"
#include "sh_utils.h"
#include "sh_modules.h"
#include "sh_pthread.h"
#include "sh_inotify.h"
#include "sh_unix.h"
#include "sh_hash.h"
#include "sh_dbIO.h"
#include "sh_files.h"
#include "sh_ignore.h"

#define FIL__  _("sh_fInotify.c")

sh_watches sh_file_watches = SH_INOTIFY_INITIALIZER;

#if defined(HAVE_SYS_INOTIFY_H) 

static sh_watches sh_file_missing = SH_INOTIFY_INITIALIZER;

#include <sys/inotify.h>

/* --- Configuration ------- */

static int ShfInotifyActive = S_FALSE;
static int ShfInotifyClose  = S_FALSE; /* for reconf, mark instance for closing */

static unsigned long ShfInotifyWatches = 0;

static int sh_fInotify_active(const char *s) 
{
  int value;
    
  SL_ENTER(_("sh_fInotify_active"));
  value = sh_util_flagval(s, &ShfInotifyActive);
  if (value == 0 && ShfInotifyActive != S_FALSE)
    {
      sh.flag.inotify |= SH_INOTIFY_USE;
      sh.flag.inotify |= SH_INOTIFY_DOSCAN;
      sh.flag.inotify |= SH_INOTIFY_NEEDINIT;
    }
  if (value == 0 && ShfInotifyActive == S_FALSE)
    {
      sh.flag.inotify = 0;
    }
  SL_RETURN((value), _("sh_fInotify_active"));
}

static int sh_fInotify_watches(const char *s) 
{
  int retval = -1;
  char * foo;
  unsigned long value;
    
  SL_ENTER(_("sh_fInotify_watches"));

  value = strtoul(s, &foo, 0);
  if (*foo == '\0')
    {
      ShfInotifyWatches = (value > 2147483647) ? 2147483647 /* MAX_INT_32 */: value;
      retval = 0;
    }
  SL_RETURN((retval), _("sh_fInotify_watches"));
}
  
  
sh_rconf sh_fInotify_table[] = {
    {
        N_("inotifyactive"),
        sh_fInotify_active,
    },
    {
        N_("inotifywatches"),
        sh_fInotify_watches,
    },
    {
        NULL,
        NULL
    }
};

/* --- End Configuration --- */

static int sh_fInotify_init_internal(void);
static int sh_fInotify_process(struct inotify_event * event);
static int sh_fInotify_report(struct inotify_event * event, char * filename,
			      int class, unsigned long check_flags, int ftype, int rdepth);

int sh_fInotify_init(struct mod_type * arg)
{
#ifndef HAVE_PTHREAD
  (void) arg;
  return SH_MOD_FAILED;
#else

  if (ShfInotifyActive == S_FALSE)
    return SH_MOD_FAILED;

  if (sh.flag.checkSum == SH_CHECK_INIT)
    return SH_MOD_FAILED;

  if (arg != NULL && arg->initval < 0 &&
      (sh.flag.isdaemon == S_TRUE || sh.flag.loop == S_TRUE))
    {
      /* Init from main thread */
      SH_INOTIFY_IFUSED( sh.flag.inotify |= SH_INOTIFY_DOSCAN;   );
      SH_INOTIFY_IFUSED( sh.flag.inotify |= SH_INOTIFY_NEEDINIT; );

      if (0 == sh_pthread_create(sh_threaded_module_run, (void *)arg))
	{
	  return SH_MOD_THREAD;
	}
      else
	{
	  sh.flag.inotify = 0;
	  return SH_MOD_FAILED;
	}
    }
  else if (arg != NULL && arg->initval < 0 &&
      (sh.flag.isdaemon != S_TRUE && sh.flag.loop != S_TRUE))
    {
      sh.flag.inotify = 0;
      return SH_MOD_FAILED;
    }
  else if (arg != NULL && arg->initval == SH_MOD_THREAD &&
	   (sh.flag.isdaemon == S_TRUE || sh.flag.loop == S_TRUE))
    {
      /* Reconfigure from main thread */

      SH_INOTIFY_IFUSED( sh.flag.inotify |= SH_INOTIFY_DOSCAN;   );
      SH_INOTIFY_IFUSED( sh.flag.inotify |= SH_INOTIFY_NEEDINIT; );
      return SH_MOD_THREAD;
    }

  /* Within thread, init */
  return sh_fInotify_init_internal();
#endif
}

int sh_fInotify_run()
{
  ssize_t len = -1;
  char *  buffer;
  static int count  = 0;
  static int count2 = 0;

  if (ShfInotifyActive == S_FALSE)
    {
      return SH_MOD_FAILED;
    }

  if (ShfInotifyClose == S_TRUE)
    {
      ShfInotifyClose = S_FALSE;
      sh_inotify_close();
    }

  if ( (sh.flag.inotify & SH_INOTIFY_DOSCAN) ||
       (sh.flag.inotify & SH_INOTIFY_NEEDINIT))
    {
      if (0 != sh_fInotify_init_internal())
	{
	  return SH_MOD_FAILED;
	}
    }

  buffer = SH_ALLOC(16384);

  /* Blocking read from inotify file descriptor.
   */
  len = sh_inotify_read_timeout(buffer, 16384, 1);
  
  if (len > 0)
    {
      struct inotify_event *event;
      int i = 0;
      
      while (i < len) 
	{
	  event = (struct inotify_event *) &(buffer[i]);
	  
	  sh_fInotify_process(event);
	  
	  i += sizeof (struct inotify_event) + event->len;
	}

      if ( (sh.flag.inotify & SH_INOTIFY_DOSCAN) ||
	   (sh.flag.inotify & SH_INOTIFY_NEEDINIT))
	{
	  if (0 != sh_fInotify_init_internal())
	    {
	      SH_FREE(buffer);
	      return SH_MOD_FAILED;
	    }
	}
     }

  /* Re-scan 'dormant' list of sh_file_missing. 
   */ 
  sh_inotify_recheck_watches (&sh_file_watches, &sh_file_missing);

  ++count; 
  ++count2;

  if (count >= 10)
    {
      count = 0; /* Re-expand glob patterns to discover added files. */
      SH_INOTIFY_IFUSED( sh.flag.inotify |= SH_INOTIFY_INSCAN; );
      sh_files_check_globFilePatterns();
      SH_INOTIFY_IFUSED( sh.flag.inotify &= ~SH_INOTIFY_INSCAN;  );
      SH_INOTIFY_IFUSED( sh.flag.inotify |= SH_INOTIFY_NEEDINIT; );
    }

  if (count2 >= 300)
    {
      count2 = 0; /* Update baseline database. */
      if (sh.flag.checkSum == SH_CHECK_CHECK && sh.flag.update == S_TRUE)
	sh_dbIO_writeout_update ();
    }

  SH_FREE(buffer);
  return 0;
}

/* We block in the read() call on the inotify descriptor,
 * so we always run.
 */
int sh_fInotify_timer(time_t tcurrent)
{
  (void) tcurrent;
  return 1;
}

int sh_fInotify_cleanup()
{
  sh_inotify_purge_dormant(&sh_file_watches);
  sh_inotify_remove(&sh_file_watches);
  sh_inotify_init(&sh_file_watches);
  return 0;
}

/* This runs in the main thread, so it won't close
 * the (threadspecific) inotify instance.
 */
int sh_fInotify_reconf()
{
  sh.flag.inotify   = 0;

  ShfInotifyWatches = 0;
  ShfInotifyActive  = 0;

  ShfInotifyClose   = S_TRUE;

  return sh_fInotify_cleanup();
}

#define PROC_WATCHES_MAX _("/proc/sys/fs/inotify/max_user_watches")

static void sh_fInotify_set_nwatches()
{
  static int fails = 0;

  if (ShfInotifyWatches == 0 || fails == 1)
    return;

  if (0 == access(PROC_WATCHES_MAX, R_OK|W_OK)) /* flawfinder: ignore */
    {
      FILE * fd;

      if (NULL != (fd = fopen(PROC_WATCHES_MAX, "r+")))
	{
	  char   str[128];
	  char * ret;
	  char * ptr;
	  unsigned long  wn;

	  str[0] = '\0';
	  ret = fgets(str, 128, fd);
	  if (ret && *str != '\0')
	    {
	      wn = strtoul(str, &ptr, 0);
	      if (*ptr == '\0' || *ptr == '\n')
		{
		  if (wn < ShfInotifyWatches)
		    {
		      sl_snprintf(str, sizeof(str), "%lu\n", ShfInotifyWatches);
		      (void) fseek(fd, 0L, SEEK_SET);
		      fputs(str, fd);
		    }
		  sl_fclose(FIL__, __LINE__, fd);
		  return;
		}
	    }
	  sl_fclose(FIL__, __LINE__, fd);
	}
    }
  SH_MUTEX_LOCK(mutex_thread_nolog);
  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN, 
		  _("Cannot set max_user_watches"), 
		  _("sh_fInotify_set_nwatches"));
  SH_MUTEX_UNLOCK(mutex_thread_nolog);
  fails = 1;
  return;
}

/* The watch fd is thread specific. To have it in the fInotify thread,
 * the main thread writes a list of files/dirs to watch, and here we
 * now pop files from the list to add watches for them.
 */
static int sh_fInotify_init_internal()
{
  char * filename;
  int    class;
  int    type;
  int    rdepth;
  unsigned long check_flags;
  int    retval;
  int    errnum;

  if (ShfInotifyActive == S_FALSE)
    return SH_MOD_FAILED;

  /* Wait until file scan is finished.
   */
  while((sh.flag.inotify & SH_INOTIFY_DOSCAN) != 0)
    {
      retry_msleep(1,0);

      if (ShfInotifyActive == S_FALSE)
	return SH_MOD_FAILED;
    }

  sh_fInotify_set_nwatches();

  while (NULL != (filename = sh_inotify_pop_dormant(&sh_file_watches, 
						    &class, &check_flags, 
						    &type, &rdepth)))
    {
      retval = sh_inotify_add_watch(filename, &sh_file_watches, &errnum,
				    class, check_flags, type, rdepth);

      if (retval < 0)
	{
	  char errbuf[SH_ERRBUF_SIZE];

	  sh_error_message(errnum, errbuf, sizeof(errbuf));

	  if ((errnum == ENOENT) || (errnum == EEXIST))
	    {
	      /* (1) Did it exist at init ? 
	       */
	      if (sh_hash_have_it (filename) >= 0)
		{
		  /* (2) Do we want to report on it ?
		   */
		  if (S_FALSE == sh_ignore_chk_del(filename))
		    {
		      char * epath = sh_util_safe_name (filename);

		      SH_MUTEX_LOCK(mutex_thread_nolog);
		      sh_error_handle( SH_ERR_ALL /* debug */,
				       FIL__, __LINE__, errnum, MSG_E_SUBGPATH, 
				       errbuf, _("sh_fInotify_init_internal"), epath);
		      SH_MUTEX_UNLOCK(mutex_thread_nolog);
		      SH_FREE(epath);
		    }
		}
	    }
	  else
	    {
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle((-1), FIL__, __LINE__, errnum, MSG_E_SUBGEN, 
			       errbuf, _("sh_fInotify_init_internal"));
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	    }
	}
      SH_FREE(filename);
    }

  /* Need this because mod_check() may run after
   * DOSCAN is finished, hence wouldn't call init().
   */
  SH_INOTIFY_IFUSED( sh.flag.inotify &= ~SH_INOTIFY_NEEDINIT; );

  return 0;
}

static void sh_fInotify_logmask(struct inotify_event * event)
{
  char dbgbuf[256];
  
  sl_strlcpy (dbgbuf, "inotify mask: ", sizeof(dbgbuf));
  
  if (event->mask & IN_ACCESS) sl_strlcat(dbgbuf, "IN_ACCESS ", sizeof(dbgbuf));
  if (event->mask & IN_ATTRIB) sl_strlcat(dbgbuf, "IN_ATTRIB ", sizeof(dbgbuf));
  if (event->mask & IN_CLOSE_WRITE) sl_strlcat(dbgbuf, "IN_CLOSE_WRITE ", sizeof(dbgbuf));
  if (event->mask & IN_CLOSE_NOWRITE) sl_strlcat(dbgbuf, "IN_CLOSE_NOWRITE ", sizeof(dbgbuf));
  if (event->mask & IN_CREATE) sl_strlcat(dbgbuf, "IN_CREATE ", sizeof(dbgbuf));
  if (event->mask & IN_DELETE) sl_strlcat(dbgbuf, "IN_DELETE ", sizeof(dbgbuf));
  if (event->mask & IN_DELETE_SELF) sl_strlcat(dbgbuf, "IN_DELETE_SELF ", sizeof(dbgbuf));
  if (event->mask & IN_MODIFY) sl_strlcat(dbgbuf, "IN_MODIFY ", sizeof(dbgbuf));
  if (event->mask & IN_MOVE_SELF) sl_strlcat(dbgbuf, "IN_MOVE_SELF ", sizeof(dbgbuf));
  if (event->mask & IN_MOVED_FROM) sl_strlcat(dbgbuf, "IN_MOVED_FROM ", sizeof(dbgbuf));
  if (event->mask & IN_MOVED_TO) sl_strlcat(dbgbuf, "IN_MOVED_TO ", sizeof(dbgbuf));
  if (event->mask & IN_OPEN) sl_strlcat(dbgbuf, "IN_OPEN ", sizeof(dbgbuf));
  if (event->mask & IN_IGNORED) sl_strlcat(dbgbuf, "IN_IGNORED ", sizeof(dbgbuf));
  if (event->mask & IN_ISDIR) sl_strlcat(dbgbuf, "IN_ISDIR ", sizeof(dbgbuf));
  if (event->mask & IN_Q_OVERFLOW) sl_strlcat(dbgbuf, "IN_Q_OVERFLOW ", sizeof(dbgbuf));
  if (event->mask & IN_UNMOUNT) sl_strlcat(dbgbuf, "IN_UNMOUNT ", sizeof(dbgbuf));
  
  SH_MUTEX_LOCK(mutex_thread_nolog);
  sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN, 
		  dbgbuf, _("sh_fInotify_process"));
  SH_MUTEX_UNLOCK(mutex_thread_nolog);
}

static int sh_fInotify_process(struct inotify_event * event)
{
  int class;
  int ftype;
  int rdepth;
  unsigned long check_flags;
  char * filename;
  extern int flag_err_debug;

  if (flag_err_debug == S_TRUE)
    {
      sh_fInotify_logmask(event);
    }

  if (event->wd >= 0)
    {
      filename = sh_inotify_search_item(&sh_file_watches, event->wd, 
					&class, &check_flags, &ftype, &rdepth);

      if (filename)
	{
	  sh_fInotify_report(event, filename, class, check_flags, ftype, rdepth);
	  SH_FREE(filename);
	}
      else if (sh.flag.inotify & SH_INOTIFY_NEEDINIT)
	{
	  return 1;
	}
      else if ((event->mask & IN_UNMOUNT) == 0 && (event->mask & IN_IGNORED) == 0)
	{
	  /* Remove watch ? Seems reasonable. */
	  sh_inotify_rm_watch(NULL, NULL, event->wd);

	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, event->wd, MSG_E_SUBGEN, 
			  _("Watch removed: file path unknown"), 
			  _("sh_fInotify_process"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	}
    }
  else if ((event->mask & IN_Q_OVERFLOW) != 0)
    {
      SH_INOTIFY_IFUSED( sh.flag.inotify |= SH_INOTIFY_DOSCAN;   );
      SH_INOTIFY_IFUSED( sh.flag.inotify |= SH_INOTIFY_NEEDINIT; );

      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, event->wd, MSG_E_SUBGEN, 
		      _("Inotify queue overflow"), 
		      _("sh_fInotify_process"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      return 1;
    }

  return 0;
}

void sh_fInotify_report_add(char * path, int class, unsigned long check_flags)
{
  if (S_FALSE == sh_ignore_chk_new(path))
    {
      int reported = 0;

      sh_files_clear_file_reported(path);
      
      sh_files_search_file(path, &class, &check_flags, &reported);
      
      sh_files_filecheck (class, check_flags, path, NULL,
			  &reported, 0);
      if (SH_FFLAG_REPORTED_SET(reported))
	sh_files_set_file_reported(path);
    }
  return;
}


static void sh_fInotify_report_miss(char * name, int level)
{
  char * tmp = sh_util_safe_name (name);

  SH_MUTEX_LOCK(mutex_thread_nolog);
  if (!sh_global_check_silent)
    sh_error_handle (level, FIL__, __LINE__, 0, MSG_FI_MISS, tmp);
  SH_MUTEX_UNLOCK(mutex_thread_nolog);
  ++sh.statistics.files_report;
  SH_FREE(tmp);
  return;
}

static int sh_fInotify_report_change (struct inotify_event * event, 
				      char * path, char * filename,
				      int class, unsigned long check_flags, int ftype)
{
  int    reported;
  int ret;


  if (S_FALSE == sh_ignore_chk_mod(path))
    {
      ret  = sh_files_search_file(path, &class, &check_flags, &reported);

      if ((ret == 0) && (event->len > 0) && (ftype == SH_INOTIFY_FILE))
	{
	  ; /* do nothing, watch was for directory monitored as file only */
	}
      else
	{
	  sh_files_filecheck (class, check_flags, filename,
			      (event->len > 0) ? event->name : NULL,
			      &reported, 0);
	}
    }
  return 0;
}


static int sh_fInotify_report_missing (struct inotify_event * event, 
				       char * path,
				       int class, unsigned long check_flags, int ftype)
{
  int    reported;
  int isdir = (event->mask & IN_ISDIR);
  int level = (class == SH_LEVEL_ALLIGNORE) ? 
    ShDFLevel[class] : 
    ShDFLevel[(isdir == 0) ? SH_ERR_T_FILE : SH_ERR_T_DIR];

  if (S_FALSE == sh_ignore_chk_del(path))
    {
      if (0 != hashreport_missing(path, level))
	{
	  int ret = sh_files_search_file(path, &class, &check_flags, &reported);
	  
	  if ((ret == 0) && (event->len > 0) && (ftype == SH_INOTIFY_FILE))
	    {
	      ; /* do nothing, watch was for directory monitored as file only */
	    }
	  else
	    {
	      /* Removal of a directory triggers:
	       * (1) IN_DELETE IN_ISDIR
	       * (2) IN_DELETE_SELF
	       */
	      if ((event->mask & IN_DELETE_SELF) == 0)
		sh_fInotify_report_miss(path, level);
	    }
	}
    }

  sh_hash_set_missing(path);

  if (sh.flag.reportonce == S_TRUE)
    sh_files_set_file_reported(path);

  /* Move to 'dormant' list, if not file within directory. 
   */
  if (event->len == 0)
    sh_inotify_rm_watch(&sh_file_watches, &sh_file_missing, event->wd);

  return 0;
}

static int sh_fInotify_report_added (struct inotify_event * event, 
				     char * path, char * filename,
				     int class, unsigned long check_flags, 
				     int ftype, int rdepth)
{
  if (S_FALSE == sh_ignore_chk_new(path))
    {
      int reported;
      int ret;
      int retD = 0;
      int rdepthD = rdepth;
      
      sh_files_clear_file_reported(path);
	  
      ret = sh_files_search_file(path, &class, &check_flags, &reported);
      
      if ((ret == 0) && (event->len > 0) && (ftype == SH_INOTIFY_FILE))
	{
	  ; /* do nothing, watch was for directory monitored as file only */
	}
      else
	{
	  int classD = class;
	  int reportedD = reported; 
	  unsigned long check_flagsD = check_flags;
	  
	  if (event->mask & IN_ISDIR)
	    {
	      retD = sh_files_search_dir(path, &classD, &check_flagsD, 
					 &reportedD, &rdepthD);

	      if (retD != 0)
		{
		  if (ret == 0) /* because checked as file below */
		    {
		      class      = classD;
		      check_flags = check_flagsD;
		    }
		}
	      rdepthD -= 1; if (rdepthD < -1) rdepthD = -1;
	    }
	  
	  sh_files_filecheck (class, check_flags, filename,
			      (event->len > 0) ? event->name : NULL,
			      &reported, 0);
	  
	  if (event->mask & IN_ISDIR)
	    {
	      SH_INOTIFY_IFUSED( sh.flag.inotify |= SH_INOTIFY_INSCAN;   );
	      /* Here we use classD because we check as directory now */
	      sh_files_checkdir (classD, check_flagsD, rdepthD, 
				 path, (event->len > 0) ? event->name : NULL);
	      SH_INOTIFY_IFUSED( sh.flag.inotify &= ~SH_INOTIFY_INSCAN;  );
	      SH_INOTIFY_IFUSED( sh.flag.inotify |= SH_INOTIFY_NEEDINIT; );
	      sh_dirs_reset  ();
	      sh_files_reset ();
	    }
	}
      
      if (SH_FFLAG_REPORTED_SET(reported))
	sh_files_set_file_reported(path);
      
      if ((ret != 0) || (event->mask & IN_ISDIR))
	{
	  int inotify_type = SH_INOTIFY_FILE;
	  
	  if ((event->mask & IN_ISDIR) && (rdepthD >= 0))
	    inotify_type = SH_INOTIFY_DIR;

	  sh_inotify_add_watch(path, &sh_file_watches, &ret,
			       class, check_flags, 
			       inotify_type, 
			       rdepthD);
	}
    }
  return 0;
}

static int sh_fInotify_report(struct inotify_event * event, char * filename,
			      int class, unsigned long check_flags, int ftype, int rdepth)
{
  char * fullpath = NULL;
  char * path;

  if (event->len > 0)
    {
      fullpath = sh_util_strconcat(filename, "/", event->name, NULL);
      path = fullpath;
    }
  else
    {
      path = filename;
    }

  if ( (event->mask & (IN_ATTRIB|IN_MODIFY)) != 0)
    {
      sh_fInotify_report_change (event, path, filename,
				 class, check_flags, ftype);
    }
  else if ((event->mask & (IN_DELETE|IN_DELETE_SELF|IN_MOVE_SELF|IN_MOVED_FROM)) != 0)
    {
      sh_fInotify_report_missing (event, path,
				  class, check_flags, ftype);
   }
  else if((event->mask & (IN_CREATE|IN_MOVED_TO)) != 0)
    {
      sh_fInotify_report_added (event, path, filename,
				class, check_flags, 
				ftype, rdepth);
    }

  if (fullpath)
    SH_FREE(fullpath);

  return 0;
}


#endif

#endif
