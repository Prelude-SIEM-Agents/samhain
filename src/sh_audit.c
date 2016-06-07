/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2010 Rainer Wichmann                                      */
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

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "samhain.h"
#include "sh_error.h"

#undef  FIL__
#define FIL__  _("sh_audit.c")

#if !defined(SH_COMPILE_STATIC) && defined(__linux__) && defined(HAVE_AUPARSE_H) && defined(HAVE_AUPARSE_LIB)
#include <auparse.h>

#include "sh_extern.h"
#include "sh_utils.h"


#define REC_SIZE_SYSCALL 32
#define REC_SIZE_EXE     64
#define REC_SIZE_SUCCESS 32

struct recordState {
  char syscall[REC_SIZE_SYSCALL];
  char exe[REC_SIZE_EXE];
  char success[REC_SIZE_SUCCESS];
  unsigned int auid;
  unsigned int uid;
  unsigned int gid; 
  unsigned int euid; 
  unsigned int egid;
  unsigned int fsuid; 
  unsigned int fsgid;
  time_t time;
  unsigned int milli;
};

static int listRecords (auparse_state_t * au, struct recordState * state)
{
  if (auparse_first_record(au) != 1)
    return -1;

  state->time  = auparse_get_time(au);
  state->milli = auparse_get_milli(au);

  if (auparse_find_field(au, _("syscall")))
    sl_strlcpy(state->syscall, auparse_interpret_field(au), REC_SIZE_SYSCALL);

  if (auparse_find_field(au, _("success")))
    strncpy(state->success, auparse_interpret_field(au), REC_SIZE_SUCCESS);

  if (auparse_find_field(au, "uid"))
    state->uid = auparse_get_field_int(au);
  if (auparse_find_field(au, "gid"))
    state->gid = auparse_get_field_int(au);

  if (auparse_find_field(au, _("euid")))
    state->euid = auparse_get_field_int(au);
  if (auparse_find_field(au, _("fsuid")))
    state->fsuid = auparse_get_field_int(au);

  auparse_first_field(au);

  if (auparse_find_field(au, _("auid")))
    state->auid = auparse_get_field_int(au);

  auparse_first_field(au);

  if (auparse_find_field(au, _("egid")))
    state->egid = auparse_get_field_int(au);
  if (auparse_find_field(au, _("fsgid")))
    state->fsgid = auparse_get_field_int(au);

  auparse_first_field(au);

  if (auparse_find_field(au, "exe"))
    sl_strlcpy(state->exe, auparse_interpret_field(au), REC_SIZE_EXE);

  return 0;
}
    
static char * doAuparse (const char * file, time_t time, int tol, char * result, size_t rsize, int redo_flag)
{
  struct recordState state;
  struct recordState stateFetched;
  unsigned int       found_flag = 0;
  
  auparse_state_t * au = auparse_init(AUSOURCE_LOGS, NULL);

  if (!au)
    {
      char ebuf[SH_ERRBUF_SIZE];
      int  errnum = errno;

      sl_snprintf(ebuf, sizeof(ebuf), _("Error in auparse_init() - %s\n"), 
		  strerror(errnum));
      sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, errnum, MSG_E_SUBGEN,
		       ebuf,
		       _("doAuparse") );
      return NULL;
    }

  if (ausearch_add_interpreted_item(au, _("name"), "=", file, 
				    AUSEARCH_RULE_CLEAR) != 0)
    {
      goto err;
    }

  if (time != 0)
    {
      ausearch_add_timestamp_item(au, ">=", time-tol, 0, AUSEARCH_RULE_AND);
      ausearch_add_timestamp_item(au, "<=", time+tol, 0, AUSEARCH_RULE_AND);
    }

  if (ausearch_set_stop(au, AUSEARCH_STOP_RECORD) != 0)
    {
      sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		       _("Error in ausearch_set_stop\n"),
		       _("doAuparse") );
      goto err;
    }

  memset(&state, '\0', sizeof(state));

  while (ausearch_next_event(au) == 1) 
    {
      memset(&stateFetched, '\0', sizeof(state));
      listRecords(au, &stateFetched);
      if (0 == strcmp(stateFetched.success, "yes"))
	{
	  memcpy(&state, &stateFetched, sizeof(state));
	  ++found_flag;
	}
      auparse_next_event(au);
    }

  if (found_flag == 0 && redo_flag == S_FALSE)
    {
      size_t len = strlen(file);
      char * path = SH_ALLOC(len + 2);
      char * altres;
      
      sl_strlcpy(path, file, len+2);
      path[len] = '/'; path[len+1] = '\0';
      auparse_destroy(au);
      
      altres = doAuparse(path, time, tol, result, rsize, S_TRUE);

      SH_FREE(path);
      return altres;
    }
  
  if (0 == strcmp(state.success, "yes"))
    {
      char * tmp_exe = sh_util_safe_name(state.exe);
      sl_snprintf(result, rsize, 
		  _("time=%lu.%u, syscall=%s, auid=%u, uid=%u, gid=%u, euid=%u, egid=%u, fsuid=%u, fsgid=%u, exe=%s"),
		  (unsigned long) state.time, state.milli, 
		  state.syscall,
		  state.auid, state.uid, state.gid, state.euid, state.egid, 
		  state.fsuid, state.fsgid, tmp_exe);
      SH_FREE(tmp_exe);
      auparse_destroy(au);
      return result;
    }

 err:
  auparse_destroy(au);
  return NULL;
}

static int sh_audit_checkdaemon();
static int  actl_pnum = -1;
static char * actl_paths[4] = 
  { 
    N_("/sbin/auditctl"), 
    N_("/usr/sbin/auditctl"),
    N_("/bin/auditctl"), 
    N_("/usr/bin/auditctl") 
  };


/* Public function to fetch an audit record for path 'file', time 'time'
 * The 'result' array should be sized ~256 char. 
 */
char * sh_audit_fetch (char * file, time_t mtime, time_t ctime, char * result, size_t rsize)
{
  char * res = NULL;

  if (sh_audit_checkdaemon() >= 0)
    {
      time_t new;
      
      if (mtime >= ctime) { new = mtime; }
      else                { new = ctime; }

      res = doAuparse (file, new, 1, result, rsize, S_FALSE);

      if (!res)
	{
	  res = doAuparse (file, new, 3, result, rsize, S_FALSE);
	}

    }
  return res;
}

void sh_audit_delete_all ()
{
  int p = sh_audit_checkdaemon();

  if (p >= 0)
    {
      char ctl[64];

      sl_snprintf(ctl, sizeof(ctl), _("%s -D -k samhain"),
		  _(actl_paths[p]));
      sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 
		       0, MSG_E_SUBGEN,
		       _("Deleting audit daemon rules with key samhain"),
		       _("sh_audit_delete_all") );

      sl_strlcpy(ctl, _(actl_paths[p]), sizeof(ctl));
      sh_ext_system(ctl, ctl, "-D", "-k", _("samhain"), NULL);
    }
  return;
}

static int  sh_audit_isdir(const char * file)
{
  struct stat buf;

  if ( (0 == lstat (file, &buf)) && S_ISDIR(buf.st_mode))
    return S_TRUE;
  return S_FALSE;
}

static void sh_audit_mark_int (const char * file)
{
  static int flushRules = 0;

  int p = sh_audit_checkdaemon();

  /* Flush all rules at startup.
   */
  if (flushRules == 0)
    {
      sh_audit_delete_all ();
      flushRules = 1;
    }

  if (p >= 0)
    {
      size_t len = strlen(file) + 64;
      char * command = SH_ALLOC(len);
      char * safe;
      char   ctl[64];
      char   a1[32];
      char   a2[32];
      char   a3[32];

      sl_snprintf(command, len, _("%s -w %s -p wa -k samhain"),
		  _(actl_paths[p]),
		  file);

      safe = sh_util_safe_name_keepspace(command);
      sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 
		       0, MSG_E_SUBGEN,
		       safe,
		       _("sh_audit_mark") );

      SH_FREE(safe);

      sl_strlcpy(ctl, _(actl_paths[p]), sizeof(ctl));
      sl_strlcpy(command, file, len);

      sl_strlcpy(a3, _("samhain"), sizeof(a3));
      sh_ext_system(ctl, ctl, "-w", command, "-p", "wa", "-k", a3, NULL);

      /* Placing a watch on a directory will not place a watch on the
       * directory inode, so we do this explicitely. 
       */
      if (S_TRUE == sh_audit_isdir(file))
	{
	  safe = sh_util_safe_name(file);
	  sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 
			   0, MSG_E_SUBGPATH,
			   _("Add path watch for directory"),
			   _("sh_audit_mark_int"), safe );
	  SH_FREE(safe);
	  sl_strlcpy(command, _("path="), len);
	  sl_strlcat(command, file, len);
	  sl_strlcpy(a1, _("always,exit"), sizeof(a1));
	  sl_strlcpy(a2, _("perm=wa"), sizeof(a2));
	  sh_ext_system(ctl, ctl, "-a", a1, "-F", command, "-F", a2, "-k", a3, NULL);
	}
      SH_FREE(command);
    }
  return;
}

struct aud_list {
  char * file;
  struct aud_list * next;
};

struct aud_list * mark_these = NULL;

static void add_this (char * file)
{
  struct aud_list * this = SH_ALLOC(sizeof(struct aud_list));
  size_t len = strlen(file);

  this->file = sh_util_strdup(file);
  if ((len > 1) && (file[len-1] == '/'))
    this->file[len-1] = '\0';
  
  this->next = mark_these;
  mark_these = this;
  return;
}

/* Check whether it is already covered by a higher directory
 */
static int test_exchange (struct aud_list * this, char * file)
{
  size_t len0 = sl_strlen(this->file);
  size_t len1 = sl_strlen(file);
  int    ret  = -1;

  if (len0 == len1)
    {
      return strcmp(this->file, file);
    }
  else
    {
      char * s0 = SH_ALLOC(len0 + 2);
      char * s1 = SH_ALLOC(len1 + 2);

       sl_strlcpy(s0, this->file, len0 + 2); 
       sl_strlcpy(s1, file,       len1 + 2); 

       if (s0 < s1)
	 {
	   sl_strlcat(s0, "/", len0 + 2);
	   ret = strncmp(s0, s1, len0 + 1);
	 }
       else
	 {
	   sl_strlcat(s1, "/", len1 + 2);
	   if (0 == strncmp(s0, s1, len1 + 1))
	     {
	       size_t len = strlen(file);
	       SH_FREE(this->file);
	       this->file = sh_util_strdup(file);
	       if ((len > 1) && (file[len-1] == '/'))
		 this->file[len-1] = '\0';
	       ret = 0;
	     }
	 }
       SH_FREE(s0);
       SH_FREE(s1);
    }
  
  return ret;
}

/* Place a path on the list of of paths to be watched
 */
void sh_audit_mark (char * file)
{
  struct aud_list * this = mark_these;

  if (!mark_these) {
    add_this (file);
    return;
  }

  while (this)
    {
      /* Check whether it is already covered by a higher
       * directory 
       */
      if (0 == test_exchange(this, file))
	return;
      this = this->next;
    }

  add_this (file);
  return;
}

void sh_audit_commit ()
{
  struct aud_list * next;
  struct aud_list * this = mark_these;

  mark_these = NULL;

  while (this)
    {
      sh_audit_mark_int (this->file);
      next = this->next;
      SH_FREE(this->file);
      SH_FREE(this);
      this = next;
    }
  
}

static int sh_audit_checkdaemon()
{
  int  i;
  static int flag = 0;
  char command[64];
  char * p;

  if (flag != 0)
    return -1;

  if (actl_pnum >= 0)
    return actl_pnum;

  for (i = 0; i < 4; ++i)
    {
      if (0 == access(_(actl_paths[i]), F_OK))/* flawfinder: ignore */
	{
	  if (0 == access(_(actl_paths[i]), X_OK))/* flawfinder: ignore */
	    {
	      actl_pnum = i;
	      break;
	    }
	  else
	    {
	      char ebuf[SH_ERRBUF_SIZE];
	      int  errnum = errno;
	      
	      sl_snprintf(ebuf, sizeof(ebuf), 
			  _("Cannot execute auditctl - %s\n"), 
			  strerror(errnum));
	      sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, 
			       errnum, MSG_E_SUBGEN,
			       ebuf,
			       _("sh_audit_checkdaemon") );
	      flag = 1;
	      actl_pnum = -1;
	      return -1;
	    }
	}
    }

  if (actl_pnum == -1 && flag == 0)
    {
      char ebuf[SH_ERRBUF_SIZE];
      int  errnum = errno;
      
      sl_snprintf(ebuf, sizeof(ebuf), 
		  _("Cannot find auditctl - %s\n"), 
		  strerror(errnum));
      sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, 
		       errnum, MSG_E_SUBGEN,
		       ebuf,
		       _("sh_audit_checkdaemon") );
      flag = 1;
      actl_pnum = -1;
      return -1;
    }

  /* We found an executable auditctl */

  sl_snprintf(command, sizeof(command), _("%s -s"), _(actl_paths[actl_pnum]));
  sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 
		   0, MSG_E_SUBGEN,
		   command,
		   _("sh_audit_checkdaemon") );
  p = sh_ext_popen_str (command);

  if (p)
    {
      int retval = -1;
      if (strstr(p, _(" pid=0 ")))
	{
	  sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, 
			   0, MSG_E_SUBGEN,
			   _("Audit daemon for Linux kernel audit system is not running"),
			   _("sh_audit_checkdaemon") );
	  flag = 1;
	  actl_pnum = -1;
	}
      else
	{
	  retval = actl_pnum;
	  sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 
			   retval, MSG_E_SUBGEN,
			   _("Audit daemon is running"),
			   _("sh_audit_checkdaemon") );
	}
      SH_FREE(p);
      return retval;
    }

  sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, 
		   errno, MSG_E_SUBGEN,
		   _("No output from auditctl -s"),
		   _("sh_audit_checkdaemon") );
  flag = 1;
  actl_pnum = -1;
  return -1;
}

/* HAVE_AUPARSE_H */
#else
char * sh_audit_fetch (char * file, time_t mtime, time_t ctime, char * result, size_t rsize)
{
  (void) file;
  (void) mtime;
  (void) ctime;
  (void) result;
  (void) rsize;

  return 0;
}
void sh_audit_mark (const char * file)
{
  (void) file;
  sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		  _("Setting audit watch not supported"),
		  _("sh_audit_mark"));
  return;
}
void sh_audit_delete_all ()
{
  return;
}
void sh_audit_commit ()
{
  return;
}
#endif

/* client || standalone */
#endif

