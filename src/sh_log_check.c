
#include "config_xor.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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

#if !defined(O_NONBLOCK)
#if defined(O_NDELAY)
#define O_NONBLOCK  O_NDELAY
#else
#define O_NONBLOCK  0
#endif
#endif

#ifdef USE_LOGFILE_MONITOR

#undef  FIL__
#define FIL__  _("sh_log_check.c")

/* Debian/Ubuntu: libpcre3-dev */
#ifdef HAVE_PCRE_PCRE_H
#include <pcre/pcre.h>
#else
#include <pcre.h>
#endif

#include "samhain.h"
#include "sh_pthread.h"
#include "sh_utils.h"
#include "sh_unix.h"
#include "sh_string.h"
#include "sh_log_check.h"
#include "sh_log_evalrule.h"
#include "sh_log_correlate.h"
#include "sh_log_mark.h"
#include "sh_log_repeat.h"
#include "sh_extern.h"

/* List of supported logfile types, format is
 * { 
 *   "TYPE_CODE", 
 *   Reader_Callback_Function, 
 *   Parser_Callback_function,
 *   Evaluate_Callback_Function 
 * }
 * If Reader_Callback_Function is NULL, the default (line-oriented
 * text file) reader is used.
 */
struct sh_logfile_type sh_logtypes_def[] = {
    {  "SYSLOG", NULL,            sh_parse_syslog, NULL },
    {  "SAMBA",  sh_read_samba,   sh_parse_samba,  NULL },
    {  "APACHE", NULL,            sh_parse_apache, sh_eval_fileinfo_apache },
#if defined(HAVE_SYS_ACCT_H)
    {  "PACCT",  sh_read_pacct,   sh_parse_pacct,  NULL },
#endif
    {  "SHELL",  sh_read_shell,   sh_parse_shell,  NULL },
};

/* -------------------------- Internal Stuff -------------------------- */

struct logfile_record {
  dev_t  device_id;
  ino_t  inode;
  fpos_t offset;
};

static int    do_checkpoint_cleanup = S_FALSE;

static char * save_dir = NULL;

static const char * get_save_dir(void)
{
  int retval;

  if (!save_dir)
    {
      save_dir = sh_util_strdup(DEFAULT_DATAROOT);

      SH_MUTEX_LOCK(mutex_thread_nolog);
      retval = tf_trust_check (save_dir, SL_YESPRIV);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);

      if (retval != 0)
	{
	  return(NULL);
	}
    }
  return save_dir;
}

static void clean_dir()
{
  DIR * dir;
  struct dirent * entry;

  const char * dirpath;

  if (S_FALSE == do_checkpoint_cleanup)
    return;

  dirpath = get_save_dir();

  if (dirpath)
    {
      dir = opendir(dirpath);
      if (dir)
	{
	  unsigned long a, b;
	  int retval;
	  char c;
	  size_t dlen = strlen(dirpath) + 1;
	  time_t now  = time(NULL);

	  while (NULL != (entry = readdir(dir)))
	    {
	      retval = sscanf(entry->d_name, "%lu_%lu%c", &a, &b, &c);

	      if (2 == retval)
		{
		  struct stat buf;
		  char * path;
		  size_t  plen = strlen(entry->d_name) + 1;

		  if (S_TRUE == sl_ok_adds(plen, dlen))
		    {
		      plen += dlen;
		      path = SH_ALLOC(plen);
		      (void) sl_snprintf(path, plen, "%s/%s", 
					 dirpath,entry->d_name);

		      if (0 == retry_lstat(FIL__, __LINE__, path, &buf) &&
			  S_ISREG(buf.st_mode))
			{
			  if (buf.st_mtime < now && 
			      (now - buf.st_mtime) > 2592000) /* 30 days */
			    {
			      if (0 == tf_trust_check (path, SL_YESPRIV))
				{
				  unlink(path);
				}
			    }
			}
		    }
		}
	    }
	  closedir(dir);
	}
    }
}

static char * build_path (struct sh_logfile * record)
{
  size_t plen;
  char * path = NULL;
  const char * dir = get_save_dir();

  if (dir)
    {
      plen = strlen(dir);

      if (S_TRUE == sl_ok_adds(plen, 130))
	{
	  plen += 130; /* 64 + 64 + 2 */
	  path = SH_ALLOC(plen);
	  (void) sl_snprintf(path, plen, "%s/%lu_%lu", dir,
			     (unsigned long) record->device_id, 
			     (unsigned long) record->inode);
	}
    }

  return path;
}

static void save_pos (struct sh_logfile * record)
{
  char * path;
  FILE * fd;
  mode_t mask;
  struct logfile_record save_rec;

  path = build_path(record);

  if (path)
    {
      if (0 != sh_unix_check_piddir (path))
	{
	  SH_FREE(path);
	  return;
	}

      mask = umask(S_IWGRP | S_IWOTH);
      fd = fopen(path, "wb");
      (void) umask(mask);

      if (fd)
	{
	  save_rec.device_id = record->device_id;
	  save_rec.inode     = record->inode;
	  memcpy(&(save_rec.offset), &(record->offset), sizeof(fpos_t));
	  if (1 != fwrite(&save_rec, sizeof(struct logfile_record), 1, fd))
	    {
	      (void) sl_fclose(FIL__, __LINE__, fd);
	      (void) remove(path);
	    }
	  else
	    {
	      (void) sl_fclose(FIL__, __LINE__, fd);
	    }
	}
      SH_FREE(path);
    }
  return;
}

static int read_pos (struct sh_logfile * record)
{
  int    retval = 0;
  char * path;
  FILE * fd;
  struct logfile_record save_rec;

  path = build_path(record);

  if (path)
    {
      fd = fopen(path, "rb");
      if (fd)
	{
	  if (1 == fread(&save_rec, sizeof(struct logfile_record), 1, fd))
	    {
	      if (save_rec.device_id == record->device_id &&
		  save_rec.inode     == record->inode)
		{
		  memcpy(&(record->offset),&(save_rec.offset),sizeof(fpos_t));
		  retval = 1;
		}
	    }
	  (void) sl_fclose(FIL__, __LINE__, fd);
	}
      SH_FREE(path);
    }
  return retval;
}

/*@null@*/ static struct sh_logfile * sh_watched_logs = NULL;

int sh_add_watch (const char * str)
{
  char * filename;

  unsigned int    i;
  unsigned int    defsize;
  struct sh_logfile_type * log_type = NULL;
  struct sh_logfile * thisfile;
  struct stat buf;

  unsigned int nfields = 3; /* logtype:path[:regex] */
  size_t       lengths[3];
  char *       new = sh_util_strdup(str);
  char **      splits = split_array(new, &nfields, ':', lengths);

  if (nfields < 2 || (lengths[0] == 0 || lengths[0] >= SH_MAX_LCODE_SIZE || lengths[1] == 0))
    {
      sh_string * msg =  sh_string_new(0);
      sh_string_add_from_char(msg, _("Format error: "));
      sh_string_add_from_char(msg, str);
      
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      sh_string_str(msg),
		      _("sh_add_watch"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      sh_string_destroy(&msg);

      SH_FREE(new);
      return -2;
    }

  defsize = 
    (unsigned int) (sizeof(sh_logtypes_def)/sizeof(struct sh_logfile_type));

  for (i = 0; i < defsize; ++i)
    {
      if (0 == strcmp(splits[0], sh_logtypes_def[i].code))
	{
	  log_type = &(sh_logtypes_def[i]);
	  break;
	}
    }

  if (log_type == NULL)
    {
      sh_string * msg =  sh_string_new(0);
      sh_string_add_from_char(msg, _("Unsupported log type: "));
      sh_string_add_from_char(msg, splits[0]);
      
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      sh_string_str(msg),
		      _("sh_add_watch"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      sh_string_destroy(&msg);

      SH_FREE(new);
      return -3;
    }

  if (splits[1][0] != '/' && 0 != strcmp(splits[0], _("SHELL")))
    {
      sh_string * msg =  sh_string_new(0);
      sh_string_add_from_char(msg, _("Logfile path not absolute: "));
      sh_string_add_from_char(msg, splits[1]);
      
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      sh_string_str(msg),
		      _("sh_add_watch"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      sh_string_destroy(&msg);

      SH_FREE(new);
      return -4;
    }

  filename = /*@i@*/sh_util_strdup(splits[1]);
  thisfile = SH_ALLOC(sizeof(struct sh_logfile));

  thisfile->filename     = filename;
  if (0 == strcmp(splits[0], _("SHELL")))
    thisfile->flags        = SH_LOGFILE_NOFILE;
  else
    thisfile->flags        = SH_LOGFILE_REWIND;
  thisfile->inode        = 0;
  thisfile->device_id    = 0;
  thisfile->fp           = NULL;
  if (log_type->get_record)
    thisfile->get_record   = log_type->get_record;
  else
    thisfile->get_record   = sh_default_reader;
  thisfile->parse_record = log_type->parse_record;

  /* An optional regex for parsing the file. The result
   * 'fileinfo' should contain info about host/time position.
   */
  if (log_type->eval_fileinfo)
    {
      if (nfields == 3 && lengths[2] > 0)
	{
	  thisfile->fileinfo     = log_type->eval_fileinfo(splits[2]);

	  if (thisfile->fileinfo == NULL)
	    {
	      sh_string * msg =  sh_string_new(0);
	      sh_string_add_from_char(msg, _("Logfile format description not recognized: "));
	      sh_string_add_from_char(msg, splits[2]);
	      
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			      sh_string_str(msg),
			      _("sh_add_watch"));
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	      sh_string_destroy(&msg);

	      SH_FREE(filename);
	      SH_FREE(thisfile);
	      SH_FREE(new);
	      return -1;
	    }
	}
      else
	{
	  sh_string * msg =  sh_string_new(0);
	  sh_string_add_from_char(msg, _("Logfile format description missing: "));
	  sh_string_add_from_char(msg, splits[1]);
	  
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			  sh_string_str(msg),
			  _("sh_add_watch"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  sh_string_destroy(&msg);

	  SH_FREE(filename);
	  SH_FREE(thisfile);
	  SH_FREE(new);
	  return -1;
	}
    }
  else
    {
      thisfile->fileinfo     = NULL;
    }
  thisfile->next         = sh_watched_logs;

  /* Try reading saved offset. On success clear rewind flag.
   */
  if ((thisfile->flags & SH_LOGFILE_NOFILE) == 0)
    {
      if (0 == stat(thisfile->filename, &buf))
	{
	  if (S_ISREG(buf.st_mode)
#ifdef S_ISLNK
	      || S_ISLNK(buf.st_mode)
#endif 
	      )
	    {
	      thisfile->inode     = buf.st_ino;
	      thisfile->device_id = buf.st_dev;
	      
	      if (0 != read_pos(thisfile))
		{
		  thisfile->flags &= ~SH_LOGFILE_REWIND;
		}
	    }
	  else if (S_ISFIFO(buf.st_mode))
	    {
	      thisfile->inode      = buf.st_ino;
	      thisfile->device_id  = buf.st_dev;
	      thisfile->flags     |= SH_LOGFILE_PIPE;
	    }
	}
      else
	{
	  sh_string * msg =  sh_string_new(0);
	  sh_string_add_from_char(msg, _("Logfile is not a regular file, link, or named pipe: "));
	  sh_string_add_from_char(msg, splits[1]);
	  
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			  sh_string_str(msg),
			  _("sh_add_watch"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  sh_string_destroy(&msg);
	  
	  SH_FREE(filename);
	  SH_FREE(thisfile);
	  SH_FREE(new);
	  return -1;
	}
    }

  sh_watched_logs        = thisfile;

  SH_FREE(new);
  return 0;
}

void sh_dump_watches()
{
  struct sh_logfile * thisfile;

  while (sh_watched_logs)
    {
      thisfile        = sh_watched_logs;
      sh_watched_logs = thisfile->next;

      if ((thisfile->flags & SH_LOGFILE_NOFILE) == 0 &&
	  (thisfile->flags & SH_LOGFILE_PIPE) == 0)
	{
	  save_pos(thisfile);
	}

      if ((thisfile->flags & SH_LOGFILE_NOFILE) == 0)
	{
	  if (thisfile->fp)
	    sl_fclose(FIL__, __LINE__, thisfile->fp);
	}

      if (thisfile->filename)
	SH_FREE(thisfile->filename);
      SH_FREE(thisfile);
    }
  return;
}

/* This variable is not used anywhere. It only exist
 * to assign &new to them, which keeps gcc from
 * putting it into a register, and avoids the 'clobbered
 * by longjmp' warning. And no, 'volatile' proved insufficient.
 */
void * sh_dummy_502_thisfile = NULL;

void sh_check_watches()
{
  struct sh_logrecord * logrecord;
  struct sh_logfile * thisfile = sh_watched_logs;
  sh_string * record = sh_string_new(0);
  char * tmp;

  /* Take the address to keep gcc from putting them into registers. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_502_thisfile = (void*) &thisfile;

  while (thisfile)
    {
      volatile size_t count = 0;

      SH_MUTEX_LOCK(mutex_thread_nolog);
      tmp = sh_util_safe_name (thisfile->filename);
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_LOGMON_CHKS,
		      tmp);
      SH_FREE(tmp);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);

      for (;;) {

	record = thisfile->get_record(record, thisfile);

	if (record)
	  {
	    logrecord = thisfile->parse_record(record, thisfile->fileinfo);
	    ++count;

	    if (logrecord)
	      {
		logrecord->filename = thisfile->filename;
		
		/* Don't report if 'init', just set file pointer
		 */
		if (sh.flag.checkSum != SH_CHECK_INIT)
		  {
		    sh_eval_process_msg(logrecord);
		  }

		if (logrecord->message) 
		  sh_string_destroy(&(logrecord->message));
		if (logrecord->host)
		  sh_string_destroy(&(logrecord->host));
		if (logrecord->timestr)
		  sh_string_destroy(&(logrecord->timestr));
		SH_FREE(logrecord);
	      }
	  }
	else
	  {
	    record = sh_string_new(0);
	    break;
	  }
      }

      SH_MUTEX_LOCK(mutex_thread_nolog);
      tmp = sh_util_safe_name (thisfile->filename);
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_LOGMON_CHKE,
		      tmp, (unsigned long)count);
      SH_FREE(tmp);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);

      thisfile = thisfile->next;
    }
  sh_string_destroy(&record);
  return;
}

/********************************************************
 * Search rotated logfile
 */
extern char * sh_rotated_log_search(const char * path, struct stat * buf);


/* Open file, position at stored offset
 */
int sh_open_for_reader (struct sh_logfile * logfile)
{
  struct stat buf;
  sh_string * filename;

  /* check whether file exists, get inode to check for
   * logfile rotation
   */
  if (0 != retry_stat(FIL__, __LINE__, logfile->filename, &buf))
    {
      char * tmp;

      SH_MUTEX_LOCK(mutex_thread_nolog);
      tmp = sh_util_safe_name (logfile->filename);
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_LOGMON_MISS,
		      tmp);
      SH_FREE(tmp);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);

      memset (&(logfile->offset), '\0', sizeof(fpos_t));
      logfile->flags |= SH_LOGFILE_REWIND;
      return 0;
    }

  filename = sh_string_new(0);
  (void) sh_string_set_from_char (filename, logfile->filename);

  /* detect and handle logfile rotation
   */
  if (logfile->inode != buf.st_ino && 
      logfile->inode != 0 &&
      !S_ISFIFO(buf.st_mode))
    {
      /* Case 1) We have dealt with the moved file already.
       *         Clear the moved flag, set the rewind flag,
       *         fix logfile->inode.
       */
      if ((logfile->flags & SH_LOGFILE_MOVED) != 0)
	{
	  /* done with rotated file, start with current file
	   */
	  memset (&(logfile->offset), '\0', sizeof(fpos_t));
	  logfile->flags    |= SH_LOGFILE_REWIND;
	  logfile->flags    &= ~SH_LOGFILE_MOVED;
	  logfile->inode     = buf.st_ino;
	  logfile->device_id = buf.st_dev;
	}

      /* Case 2) Searching for rotated file. 
       *         If found:     set the moved flag, fix path for fopen.
       *         If not found: set the rewind flag, fix logfile->inode.
       */
      else
	{
	  char *oldfile = sh_rotated_log_search(logfile->filename, &buf);

	  if (NULL != oldfile)
	    {
	      (void) sh_string_set_from_char (filename, oldfile);
	      SH_FREE(oldfile);
	      logfile->flags |= SH_LOGFILE_MOVED;
	    }
	  else
	    {
	      memset (&(logfile->offset), '\0', sizeof(fpos_t));
	      logfile->flags    |= SH_LOGFILE_REWIND;
	      logfile->inode     = buf.st_ino;
	      logfile->device_id = buf.st_dev;
	    }
	}
    }

  /* open file
   */
  if (!S_ISFIFO(buf.st_mode))
    {
      logfile->fp = fopen(filename->str, "r");
    }
  else
    {
      int fd_temp = open (filename->str, O_RDONLY|O_NONBLOCK);

      if (fd_temp >= 0)
	{
	  logfile->fp = fdopen(fd_temp, "r");
	}
    }

  if (!logfile->fp)
    {
      char * tmp;

      SH_MUTEX_LOCK(mutex_thread_nolog);
      tmp = sh_util_safe_name (logfile->filename);
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_LOGMON_EOPEN,
		      tmp);
      SH_FREE(tmp);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);

      sh_string_destroy(&filename);
      return 0;
    }

  sh_string_destroy(&filename);
  
  if ((logfile->flags & SH_LOGFILE_PIPE) == 0)
    {
      if ((logfile->flags & SH_LOGFILE_REWIND) != 0)
	{
	  rewind(logfile->fp);
	  fgetpos(logfile->fp, &(logfile->offset));
	  logfile->flags &= ~SH_LOGFILE_REWIND;
	}
      else
	{
	  /* file too short
	   */
	  if (0 != fsetpos(logfile->fp, &(logfile->offset)))
	    {
	      rewind(logfile->fp);
	      fgetpos(logfile->fp, &(logfile->offset));
	    }
	}
    }

  return 1;
}

/******************************************************
 *  Default reader for ascii text files 
 */
sh_string * sh_default_reader (sh_string * s, struct sh_logfile * logfile)
{
  volatile int         status;
  char * tmp;

 start_read:

  if (logfile->fp)
    {
      /* Result cannot be larger than 8192, thus cast is ok
       */
      status = (int) sh_string_read(s, logfile->fp, 8192);
      if (status <= 0)
	{
	  fgetpos(logfile->fp, &(logfile->offset));
	  sl_fclose(FIL__, __LINE__, logfile->fp);
	  logfile->fp = NULL;
	  sh_string_destroy(&s);
	  if (status == 0 || (logfile->flags & SH_LOGFILE_PIPE) != 0)
	    {
	      return NULL;
	    }

	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  tmp = sh_util_safe_name (logfile->filename);
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_LOGMON_EREAD,
			  tmp);
	  SH_FREE(tmp);
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);

	  return NULL;
	}
      return s;
    }

  if (0 != sh_open_for_reader(logfile))
    goto start_read;

  return NULL;
}

struct task_entry
{
  sh_tas_t task;
  struct task_entry * next;
};

static struct task_entry * tasklist = NULL;

static struct task_entry * task_find(FILE * fp)
{
  struct task_entry * entry = tasklist;
  while (entry)
    {
      if (entry->task.pipe == fp)
	return (entry);
      entry = entry->next;
    }
  return NULL;
}
 
static void task_remove(struct task_entry * task)
{
  struct task_entry * entry = tasklist;
  struct task_entry * prev  = tasklist;

  while (entry)
    {
      if (entry == task)
	{
	  if (entry == tasklist)
	    {
	      tasklist = entry->next;
	      SH_FREE(entry);
	      return;
	    }
	  else
	    {
	      prev->next = entry->next;
	      SH_FREE(entry);
	      return;
	    }
	}
      prev  = entry;
      entry = entry->next;
    }
  return;
}
 
static void task_add(struct task_entry * entry)
{
  entry->next = tasklist;
  tasklist    = entry;
  return;
}
 
sh_string * sh_command_reader (sh_string * s, struct sh_logfile * logfile)
{
  struct task_entry * entry;

  volatile int        status;
  char * tmp;

 start_read:

  if (logfile->fp)
    {
      /* Result cannot be larger than 8192, thus cast is ok
       */
      status = (int) sh_string_read(s, logfile->fp, 8192);

      if (status <= 0)
	{
	  entry = task_find(logfile->fp);
	  sh_ext_pclose (&(entry->task));
	  task_remove(entry);

	  logfile->fp = NULL;
	  sh_string_destroy(&s);

	  if (status == 0)
	    {
	      return NULL;
	    }

	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  tmp = sh_util_safe_name (logfile->filename);
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_LOGMON_EREAD,
			  tmp);
	  SH_FREE(tmp);
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);

	  return NULL;
	}
      return s;
    }

  entry = SH_ALLOC(sizeof(struct task_entry));

  status = sh_ext_popen_init (&(entry->task), logfile->filename, logfile->filename, NULL);
  if (0 == status)
    {
      task_add(entry);
      logfile->fp = entry->task.pipe;
      goto start_read;
    }
  else
    {
      SH_FREE(entry);
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, status, MSG_E_SUBGEN, 
                      _("Could not open pipe"), _("sh_command reader"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }

  return NULL;
}

/******************************************************
 *  Reader for continued text files 
 */
sh_string * sh_cont_reader (sh_string * s, struct sh_logfile * logfile, char*cont)
{
  int         status;
  char      * tmp;
  sh_string * str;
  int         remain = 8192;
  int         count  = 0;

  if (!sh_string_truncate(s, 0))
    return NULL;

 start_read:

  if (logfile->fp)
    {
      str = sh_string_new(0);

      /* Result cannot be larger than 8192, thus cast is ok
       */
      status = (int) sh_string_read(str, logfile->fp, 8192);

      if (status > 0)
	{
	  
	  do {
	    s       = sh_string_add (s, str);
	    count  += status;
	    remain -= status;

	    if (remain <= 0)
	      {
		return s;
	      }

	    status = (int) sh_string_read_cont(str, logfile->fp, count, cont);

	    if (status == 0)
	      {
		return s;
	      }
	  }
	  while (status > 0);
	}

      if (status <= 0)
	{
	  fgetpos(logfile->fp, &(logfile->offset));
	  sl_fclose(FIL__, __LINE__, logfile->fp);
	  logfile->fp = NULL;
	  sh_string_destroy(&s);
	  if (status == 0 || (logfile->flags & SH_LOGFILE_PIPE) != 0)
	    {
	      return NULL;
	    }

	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  tmp = sh_util_safe_name (logfile->filename);
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_LOGMON_EREAD,
			  tmp);
	  SH_FREE(tmp);
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);

	  return NULL;
	}

      return s;
    }

  if (0 != sh_open_for_reader(logfile))
    goto start_read;

  return NULL;
}

/******************************************************
 *  Reader for binary files 
 */
sh_string * sh_binary_reader (void * s, size_t size, 
			      struct sh_logfile * logfile)
{
  size_t         status;

 start_read:

  if (logfile->fp)
    {

      status = fread(s, size, 1, logfile->fp);

      if (status != 1)
	{
	  memset(s, '\0', size);
	  if (ferror(logfile->fp) && (logfile->flags & SH_LOGFILE_PIPE) == 0)
	    {
	      char * tmp;
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      tmp = sh_util_safe_name (logfile->filename);
	      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_LOGMON_EREAD,
			      tmp);
	      SH_FREE(tmp);
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	    }
	  fgetpos(logfile->fp, &(logfile->offset));
	  sl_fclose(FIL__, __LINE__, logfile->fp);
	  logfile->fp = NULL;
	  return NULL;
	}
      return s;
    }

  if (0 != sh_open_for_reader(logfile))
    goto start_read;

  return NULL;
}



/**********************************************************
 *
 * Utilities
 *
 **********************************************************/

/* Return current year, unless that would result
 * in a date far in the future. If that happens,
 * return last year.
 */
static int year_guess (struct tm * btime)
{
  int           year;
  struct tm     ts;
  time_t        now    = time(NULL);
  time_t        check;

  memcpy(&ts, localtime(&now), sizeof(struct tm));
  year = ts.tm_year;

  /* Check result to detect year wrap
   * (logfile entry from last year).
   */
  btime->tm_year = year;
  check = mktime(btime);
  if (check > (now + (86400*30)))
    --year;

  return year;
}

time_t conv_timestamp (struct tm * btime, 
		       struct tm * old_tm, time_t * old_time)
{
  time_t timestamp;
  long   offtime;

  /* timestamp - mktime is slooow, thus cache result
   */
  if (btime->tm_isdst == old_tm->tm_isdst &&
      btime->tm_year  == old_tm->tm_year  &&
      btime->tm_mon   == old_tm->tm_mon   &&
      btime->tm_mday  == old_tm->tm_mday)
    {
      offtime = 
	(btime->tm_hour - old_tm->tm_hour) * 3600 +
	(btime->tm_min  - old_tm->tm_min)  * 60   +
	(btime->tm_sec  - old_tm->tm_sec);

      *old_time += offtime;
      memcpy(old_tm, btime, sizeof(struct tm));
      timestamp = *old_time;
    }
  else
    {
      int year_btime = btime->tm_year;

      if (btime->tm_year == 0)
	btime->tm_year = year_guess(btime);
      timestamp = mktime(btime);
      btime->tm_year = year_btime;
      *old_time  = timestamp;
      memcpy(old_tm, btime, sizeof(struct tm));
    }
  return timestamp;
}

/*********************************************************
 *
 * MODULE STUFF
 *
 *********************************************************/
#include "sh_modules.h"

SH_MUTEX_STATIC(mutex_logmon_check, PTHREAD_MUTEX_INITIALIZER);

static int ShLogmonActive        = S_FALSE;
#define SH_LOGMON_INTERVAL 10
static time_t sh_logmon_interval = SH_LOGMON_INTERVAL;

int sh_log_check_init (struct mod_type * arg)
{
#if !defined(HAVE_PTHREAD)
  (void) arg;
#endif

  if (ShLogmonActive == S_FALSE)
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
  if (sh_watched_logs != NULL)
    return 0;

  return -1;
}

int sh_log_check_timer(time_t tcurrent) 
{
  static time_t lastcheck = 0;

  SL_ENTER(_("sh_log_check_timer"));
  if ((time_t) (tcurrent - lastcheck) >= sh_logmon_interval)
    {
      lastcheck  = tcurrent;
      SL_RETURN((-1), _("sh_log_check_timer"));
    }
  SL_RETURN(0, _("sh_log_check_timer"));
}


int sh_log_check_check(void) 
{
  int status = 0;

  SL_ENTER(_("sh_log_check_check"));

  SH_MUTEX_LOCK(mutex_logmon_check);

  status = 0;

  if( ShLogmonActive != S_FALSE )
    {
      sh_check_watches();
      sh_keep_match();
      sh_log_mark_check();
      clean_dir();
    }
  SH_MUTEX_UNLOCK(mutex_logmon_check);

  SL_RETURN(status, _("sh_log_check_check"));
}

int sh_log_check_reconf(void) 
{
  int status = 0;

  SL_ENTER(_("sh_log_check_check"));

  SH_MUTEX_LOCK(mutex_logmon_check);

  ShLogmonActive     = S_FALSE;
  sh_logmon_interval = SH_LOGMON_INTERVAL;
  sh_dump_watches();
  sh_eval_cleanup();

  SH_MUTEX_UNLOCK(mutex_logmon_check);

  SL_RETURN(status, _("sh_log_check_check"));
}

int sh_log_check_cleanup(void) 
{
  sh_log_mark_destroy();
  return sh_log_check_reconf();
}

/*********************  OPTIONS **********************/

static int sh_logmon_set_active  (const char *str);
static int sh_logmon_set_clean  (const char *str);
static int sh_logmon_set_interval(const char *str);
static int sh_logmon_add_watch (const char * str);
static int sh_logmon_add_group (const char * str);
static int sh_logmon_end_group (const char * str);
static int sh_logmon_add_host  (const char * str);
static int sh_logmon_end_host  (const char * str);
static int sh_logmon_add_queue (const char * str);
static int sh_logmon_add_rule  (const char * str);
extern int sh_set_hidepid(const char *s);
static int sh_logmon_set_save_dir(const char *s);

sh_rconf sh_log_check_table[] = {
    {
        N_("logmonactive"),
        sh_logmon_set_active,
    },
    {
        N_("logmoninterval"),
        sh_logmon_set_interval,
    },
    {
        N_("logmonclean"),
        sh_logmon_set_clean,
    },
    {
        N_("logmonwatch"),
        sh_logmon_add_watch,
    },
    {
        N_("logmonqueue"),
        sh_logmon_add_queue,
    },
    {
        N_("logmongroup"),
        sh_logmon_add_group,
    },
    {
        N_("logmonendgroup"),
        sh_logmon_end_group,
    },
    {
        N_("logmonhost"),
        sh_logmon_add_host,
    },
    {
        N_("logmonendhost"),
        sh_logmon_end_host,
    },
    {
        N_("logmonrule"),
        sh_logmon_add_rule,
    },
    {
        N_("logmonhidepid"),
        sh_set_hidepid,
    },
    {
        N_("logmonsavedir"),
        sh_logmon_set_save_dir,
    },
    {
        N_("logmonmarkseverity"),
        sh_log_set_mark_severity,
    },
    {
        N_("logmonburstthreshold"),
        sh_repeat_set_trigger,
    },
    {
        N_("logmonburstqueue"),
        sh_repeat_set_queue,
    },
    {
        N_("logmonburstcron"),
        sh_repeat_set_cron,
    },
    {
        N_("logmondeadtime"),
        sh_keep_deadtime,
    },
    {
        NULL,
        NULL
    }
};

/* Decide if we're active.
 */
static int sh_logmon_set_active(const char *str) 
{
  int value;
    
  SL_ENTER(_("sh_logmon_set_active"));

  value = sh_util_flagval(str, &ShLogmonActive);

  SL_RETURN((value), _("sh_logmon_set_active"));
}

/* Decide if we're active.
 */
static int sh_logmon_set_clean(const char *str) 
{
  int value;
    
  SL_ENTER(_("sh_logmon_set_active"));

  value = sh_util_flagval(str, &do_checkpoint_cleanup);

  SL_RETURN((value), _("sh_logmon_set_active"));
}

static int sh_logmon_set_save_dir(const char *str) 
{
  int retval = -1;
    
  SL_ENTER(_("sh_logmon_set_save_dir"));

  if (str && str[0] == '/')
    {
      if (save_dir)
	{
	  SH_FREE(save_dir);
	  save_dir = NULL;
	}
      save_dir = sh_util_strdup(str);
      retval = 0;
    }

  SL_RETURN((retval), _("sh_logmon_set_save_dir"));
}

static int sh_logmon_set_interval (const char * c)
{
  int retval = 0;
  long val;

  SL_ENTER(_("sh_logmon_set_interval"));
  val = strtol (c, (char **)NULL, 10);
  if (val <= 0)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS,
		       _("log monitoring interval"), c);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      retval = -1;
    }
  else
    {
      sh_logmon_interval = (time_t) val;
    }
  SL_RETURN(retval, _("sh_logmon_set_interval"));
}

/* Add a watch on a logfile.
 * Format: TYPE : Filename [: File_Format]
 */
static int sh_logmon_add_watch (const char * str)
{
  return sh_add_watch(str);
}

/* Add a host.
 * Format: Name_Regex
 */
static int sh_logmon_add_host (const char * str)
{
  return sh_eval_hadd(str);
}

/* End a host.
 * Format: Name
 */
static int sh_logmon_end_host (const char * str)
{
  (void) str;
  return sh_eval_hend(NULL);
}

/* Add a group of rules. 
 * Groups can be under hosts, but not vice versa.
 * Format: Name : Prefix_Regex
 */
static int sh_logmon_add_group (const char * str)
{
  return sh_eval_gadd(str);
}

/* End a group of rules.
 * Format: Name
 */
static int sh_logmon_end_group (const char * str)
{
  (void) str;
  return sh_eval_gend(NULL);
}

/* Define a reporting queue.
 * Format: Label : [Interval] : TYPE : Severity[:alias]
 * TYPE must be 'report' or 'sum'
 * Interval is ignored for TYPE='report'
 */
static int sh_logmon_add_queue (const char * str)
{
  return sh_eval_qadd(str);
}

/* Define a check rule.
 * Format: [KEEP(seconds,label):]Queue_Label : Regex
 * KEEP indicates that we keep the label, to perform
 *      correlation matching
 */
static int sh_logmon_add_rule (const char * str)
{
  return sh_eval_radd(str);
}


#if 0

/* >>>>>>>>>>>  MAIN <<<<<<<<<<<<<<<<<<< */

int main (int argc, char * argv[])
{
  int status, i;
  FILE * fp;
  sh_string * s = NULL;
  static char template[] = "/tmp/xtest.XXXXXX";

  /* pacct */
  status = sh_add_watch("PACCT:/var/log/account/pacct");
  sh_check_watches();
  sh_dump_watches();
  exit(0);

  /* apache log */
  sh_eval_gadd("four_o_four:404");
  sh_eval_qadd("test:1:sum:7");
  sh_eval_radd("test:^(\\d+.\\d+.\\d+.\\d+).*");
  sh_eval_gend(NULL);
  sh_eval_radd("trash:.*");
  status = sh_add_watch("APACHE:/var/log/apache2/access.log:combined");
  sh_check_watches();
  sh_dump_watches();
  exit(0);

  /* logfile */
  sh_set_hidepid(1);
  sh_eval_hadd("hslxmsrv1");
  sh_eval_gadd("postfix:postfix");
  sh_eval_qadd("test::report:7");
  sh_eval_radd("test:postfix/smtpd: disconnect from localhost.*");
  sh_eval_radd("trash:postfix/smtpd: disconnect.*");
  sh_eval_hadd("hspc05");
  sh_eval_gadd("cron:CRON");
  sh_eval_qadd("test:1:sum:7");
  sh_eval_radd("test:CRON: PAM adding faulty module: (/lib/security/.*.so)");
  sh_eval_radd("trash:.*");
  status = sh_add_watch("SYSLOG:/var/log/messages");
  sh_check_watches();

  sh_dump_watches();
  exit(0);

  printf("%d types\n",
	 (int) (sizeof(sh_logtypes_def)/sizeof(struct sh_logfile_type)));

  /* test sh_add_watch 
   */
  status = sh_add_watch("");
  printf("%2d: zero length, expect -1\n", status);
  status = sh_add_watch(NULL);
  printf("%2d: NULL, expect -2\n", status);
  status = sh_add_watch("0123456789012345:/var/log/messages");
  printf("%2d: long, expect -2\n", status);
  status = sh_add_watch("012345678901234:/var/log/messages");
  printf("%2d: exact length, expect -3\n", status);
  status = sh_add_watch("01234567890123:56789");
  printf("%2d: short length, expect -3\n", status);
  status = sh_add_watch("SYSLOG:var/log/messages");
  printf("%2d: short badpath, expect -4\n", status);
  status = sh_add_watch("SYSLOG:/var/log/messages");
  /* status = sh_add_watch("SYSLOG:/var/log/dpkg.log.1"); */
  printf("%2d: short path ok, expect 0\n", status);

  /* test sh_string_read 
   */
  s = sh_string_new();

  status = /*@i@*/mkstemp(template);

  if (status < 0) {
    fprintf(stderr, "error in mkstemp!\n"); exit(EXIT_FAILURE); }

  fp = fdopen(status, "r+");
  if (!fp) {
    fprintf(stderr, "error in fdopen!\n"); exit(EXIT_FAILURE); }

  for (i = 0; i <  80; ++i) { fputc ('a', fp); } fputc ('\n', fp); /* 0 */
  for (i = 0; i < 118; ++i) { fputc ('a', fp); } fputc ('\n', fp); /* 1 */
  for (i = 0; i < 119; ++i) { fputc ('a', fp); } fputc ('\n', fp); /* 2 */
  for (i = 0; i < 120; ++i) { fputc ('a', fp); } fputc ('\n', fp); /* 3 */
  for (i = 0; i < 121; ++i) { fputc ('a', fp); } fputc ('\n', fp); /* 4 */
  for (i = 0; i < 238; ++i) { fputc ('a', fp); } fputc ('\n', fp);
  for (i = 0; i < 239; ++i) { fputc ('a', fp); } fputc ('\n', fp);
  for (i = 0; i < 240; ++i) { fputc ('a', fp); } fputc ('\n', fp);
  for (i = 0; i < 241; ++i) { fputc ('a', fp); } fputc ('\n', fp);

  rewind(fp);

  for (i = 0; i < 9; ++i)
    {
      status = (int) sh_string_read(s, fp, 120);
      printf("%d: status = %d, len = %d, size = %d\n",
	     i, status, (int)s->len, (int)s->siz);
      if (status == -2)
	(void) sh_string_read(s, fp, 240);
      else
	printf("%s\n", s->str);
    }

  rewind(fp);

  (void) sh_string_truncate(s, 0);

  for (i = 0; i < 9; ++i)
    {
      status = (int) sh_string_read(s, fp, 240);
      printf("%d: status = %d, len = %d, size = %d\n",
	     i, status, (int)s->len, (int)s->siz);
      if (status == -2)
	(void) sh_string_read(s, fp, 240);
      else
	{
	  for (status = 0; status < (int)s->len; ++status)
	    {
	      if (s->str[status] != 'a')
		{
		  break;
		}
	    }
	  printf("%d %s\n", status, s->str);
	}
    }

  sl_fclose(FIL__, __LINE__, fp); remove(template);



  return 0;
}
#endif

/* #ifdef USE_LOGFILE_MONITOR */
#endif

