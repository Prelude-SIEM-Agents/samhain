/**************************************
 **
 ** PARSER RULES
 **
 ** (a) must set record->host 
 **     (eventually to dummy value)
 **
 ** (b) must set record->prefix
 **     (command) 
 **
 **
 **************************************/

/* Based on the GNU Accounting Utilities, which is distributed with the
 * following copyright: 
 */

/* Copyright (C) 1993, 1996, 1997, 2003, 2005 Free Software Foundation, Inc.
 *
 * This file is part of the GNU Accounting Utilities
 *
 * The GNU Accounting Utilities are free software; you can redistribute
 * them and/or modify them under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either version
 * 2, or (at your option) any later version.
 *
 * The GNU Accounting Utilities are distributed in the hope that they will
 * be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the GNU Accounting Utilities; see the file COPYING.  If
 * not, write to the Free Software Foundation, 675 Mass Ave, Cambridge,
 * MA 02139, USA.  */

#include "config_xor.h"

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <dirent.h>

#if defined(USE_LOGFILE_MONITOR) && defined(HAVE_SYS_ACCT_H)

#include <sys/acct.h>

#include "samhain.h"
#include "sh_pthread.h"
#include "sh_log_check.h"
#include "sh_utils.h"
#include "sh_string.h"

#undef  FIL__
#define FIL__  _("sh_log_parse_pacct.c")

extern int flag_err_debug;

#ifndef ACCT_COMM
#define ACCT_COMM 16
#endif
#ifndef AHZ
#define AHZ 100
#endif

#if defined(ACUTIME_COMPT) || defined(ACSTIME_COMPT) || defined(ACETIME_COMPT)
static double comp_t_2_double (comp_t ct)
{
  unsigned long out = 0;

  out = ct & 017777;
  ct >>= 13;

  while (ct) {
    ct--;
    out <<= 3;
  }
  
  return (double) out;
}
#endif

#ifdef ACUTIME_COMPT
# define ACUTIME_2_DOUBLE(x) (comp_t_2_double(x))
#else
# define ACUTIME_2_DOUBLE(x) ((double)(x))
#endif

#ifdef ACSTIME_COMPT
# define ACSTIME_2_DOUBLE(x) (comp_t_2_double(x))
#else
# define ACSTIME_2_DOUBLE(x) ((double)(x))
#endif

#ifdef ACETIME_COMPT
# define ACETIME_2_DOUBLE(x) (comp_t_2_double(x))
#else
# define ACETIME_2_DOUBLE(x) ((double)(x))
#endif


static void expand_flags(char flag, char * out)
{
  int i = 0;

#define	BIT(flg, ch)	if (flag & flg) out[i] = ch; else out[i] = ' '; ++i

  BIT(ASU, 'S');
  BIT(AFORK, 'F');
#ifdef ACOMPAT
  BIT(ACOMPAT, 'C');
#endif
#ifdef ACORE
  BIT(ACORE, 'D');
#endif
#ifdef AXSIG
  BIT(AXSIG, 'X');
#endif

  out[i] = '\0';
  return;
}

static char * uid_name (int uid)
{
  static int  userid   = 0;
  static char user[16] = "";

  if (uid == userid && user[0] != '\0')
    {
      return user;
    }
  else
    {
      struct passwd *thispw = getpwuid (uid);
      if (thispw)
	sl_strlcpy (user, thispw->pw_name, sizeof(user));
      else
	sl_snprintf(user, sizeof(user), "%d", uid);
      user[sizeof(user)-1] = '\0';
      userid = uid;
    }
  return user;
}

struct dev_struct {
  char * device;
  long   dev_id;
  struct dev_struct * next;
};
static struct dev_struct * devicelist = NULL;

static void add_devices(const char * dir)
{
  DIR *  mdir;
  char   dirl[256];

  sl_strlcpy(dirl, dir, sizeof(dirl));
  dirl[sizeof(dirl)-1] = '\0';

  mdir = opendir(dir);
  
  if (mdir)
    {
      char * path;
      size_t len;
      struct dirent * dent;
      struct stat buf;

      while (NULL != (dent = readdir(mdir)))
	{
	  if (0 == strcmp(dent->d_name, "."))
	    continue;
	  if (0 == strcmp(dent->d_name, ".."))
	    continue;
	  len = strlen(dir) + strlen(dent->d_name) + 2;
	  path = SH_ALLOC(len);
	  snprintf(path, len, "%s/%s", dir, dent->d_name);
	  if (0 == lstat(path, &buf) && S_ISCHR(buf.st_mode))
	    {
	      struct dev_struct * dstruct;
	      dstruct = SH_ALLOC(sizeof(struct dev_struct));
	      /* eliminate leading '/dev/' */
	      memmove(path, &path[5], strlen(path)-4); 
	      dstruct->device = path;
	      dstruct->dev_id = buf.st_rdev;
	      dstruct->next   = devicelist;
	      devicelist      = dstruct;
	    }
	  else
	    {
	      SH_FREE(path);
	    }
	}
      closedir(mdir);
    }
  return;
}

static char * dev_name(long tty)
{
  struct dev_struct * dstruct;

  if (!devicelist)
    {
      add_devices("/dev");
      add_devices("/dev/pts");
      add_devices("/dev/pty");
      add_devices("/dev/ptym");
    }

  dstruct = devicelist;
  while (dstruct)
    {
      if (dstruct->dev_id == tty)
	return dstruct->device;
      dstruct = dstruct->next;
    }
  return "??";
}

#if defined(__linux__) && defined(HAVE_ACCT_V3)
#  define STRUCT_ACCT struct acct_v3
#elif defined(__FreeBSD__) && defined(HAVE_ACCTV2)
#  define STRUCT_ACCT struct acctv2
#else
#  define STRUCT_ACCT struct acct
#endif

/* This looks strange, but it's real ANSI C. */
extern STRUCT_ACCT pacct_rd_never_used;
#define COMM_LEN ((int) sizeof (pacct_rd_never_used.ac_comm))

sh_string * sh_read_pacct (sh_string * record, struct sh_logfile * logfile)
{
  STRUCT_ACCT rec;

  if (NULL != sh_binary_reader ((void*) &rec, sizeof(STRUCT_ACCT), logfile))
    {
      time_t btime = (time_t) rec.ac_btime;
      double ut    = ACUTIME_2_DOUBLE (rec.ac_utime);
      double st    = ACSTIME_2_DOUBLE (rec.ac_stime);
      char   fl[6];
      char   comm[COMM_LEN+1];
      int    i;
      char   out[64+COMM_LEN+1+5+8+8+32+4+19+7]; /* see printf format below */
      
#if defined(ac_flagx)
      expand_flags(rec.ac_flagx, fl);
#else
      expand_flags(rec.ac_flag,  fl);
#endif
      
      /* ac_comm may not be null terminated
       */
      for (i = 0; i < COMM_LEN; i++)
	{
	  if (rec.ac_comm[i] == '\0')
	    {
	      comm[i] = '\0';
	      break;
	    }
	  if (! isprint (rec.ac_comm[i]))
	    comm[i] = '?';
	  else
	    comm[i] = rec.ac_comm[i];
	}
      comm[COMM_LEN] = '\0';

      sl_snprintf (out, sizeof(out),
		   "%ld:%-*.*s %5.5s %-8.8s %-8.8s %6.2f secs %-19.19s",
		   btime,
		   COMM_LEN, COMM_LEN, comm, fl, 
		   uid_name(rec.ac_uid), 
		   dev_name((long)rec.ac_tty),
		   ((ut + st) / (double) AHZ),
		   ctime (&btime));


      sh_string_set_from_char(record, out);
      return record;
    }

  if (record)
    sh_string_destroy(&record);
  return NULL;
}

void * sh_dummy_294_record = NULL;

struct sh_logrecord * sh_parse_pacct (sh_string * logline, void * fileinfo)
{
  char * p;
  char * endptr;
  unsigned long ltime;
  struct sh_logrecord * record = NULL;

  (void) fileinfo;

  sh_dummy_294_record = (void *) &record;

  if (sh_string_len(logline) > 0 && flag_err_debug == S_TRUE)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      sh_string_str(logline),
		      _("sh_parse_pacct"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }

  p = strchr(sh_string_str(logline), ':');

  if (!p || p == sh_string_str(logline))
    return NULL;

  ltime = strtoul(sh_string_str(logline), &endptr, 10);
  if (p != endptr)
    return NULL;
		  
  ++p; /* points to first char of pacct record */
  
  if (*p != '\0')
    {
      size_t lengths[7];
      unsigned int  fields = 7;
      char ** array;
      sh_string * message = sh_string_new_from_lchar(p, strlen(p));
      array = split_array_ws(p, &fields, lengths);

      if (fields == 7)
	{
	  record = SH_ALLOC(sizeof(struct sh_logrecord));

	  record->timestamp = ltime;
	  record->timestr   = sh_string_new_from_lchar(array[6], lengths[6]);
	  record->message   = message;
	  record->pid       = 0;
	  record->host      = sh_string_new_from_lchar(sh.host.name, strlen(sh.host.name));
	}
      else
	{
	  sh_string_destroy(&message);
	}
      SH_FREE(array);
    }
  return record;
}
/* USE_LOGFILE_MONITOR */
#endif
