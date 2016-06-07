/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2004 Rainer Wichmann                                      */
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

#include <string.h>
#include <sys/types.h>
#include <signal.h>

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)

#include "samhain.h"
#include "sh_tiger.h"
#include "sh_extern.h"
#include "sh_utils.h"
#include "sh_unix.h"

#undef  FIL__
#define FIL__  _("sh_prelink.c")

static char * prelink_path = NULL;
static char * prelink_hash = NULL;

int sh_prelink_set_path (const char * str)
{
  SL_ENTER(_("sh_prelink_set_path"));
  if (prelink_path != NULL)
    SH_FREE(prelink_path);
  if (str[0] != '/')
    {
      prelink_path = NULL;
      SL_RETURN((-1), _("sh_prelink_set_path")); 
    }
#ifdef SH_EVAL_SHELL
  prelink_path = sh_util_strdup(str);
  SL_RETURN(0, _("sh_prelink_set_path")); 
#else
  prelink_path = NULL;
  SL_RETURN((-1), _("sh_prelink_set_path"));
#endif
}

int sh_prelink_set_hash (const char * str)
{
  size_t len;
  SL_ENTER(_("sh_prelink_set_hash"));
  if (prelink_hash != NULL)
    SH_FREE(prelink_hash);
  len = sl_strlen (str);
  if (len != KEY_LEN)
    {
      prelink_hash = NULL;
      SL_RETURN((-1), _("sh_prelink_set_hash")); 
    }
  prelink_hash = SH_ALLOC(len+1);
  (void) sl_strlcpy(prelink_hash, str, len+1);
  SL_RETURN(0, _("sh_prelink_set_hash")); 
}

int sh_prelink_iself (SL_TICKET fd, off_t size, int alert_timeout, char * path)
{
  long   status;
  char   magic[4];
  char * tmp;

  /* 42 bytes is about the minimum an ELF binary might have
   * (with plenty of hacks to reduce the size, such as interleaving
   * the code with the header...)
   */
  if (size < 42)
    return S_FALSE;

  status = sl_read_timeout (fd, magic, 4, alert_timeout, S_FALSE);
  (void) sl_rewind(fd);
  if (status == 4)
    {
      /*@-usedef@*/
      if (magic[0] == (char) 0x7f &&
	  magic[1] == 'E'  &&
	  magic[2] == 'L'  &&
	  magic[3] == 'F')
	return S_TRUE;
      /*@+usedef@*/
    }
  else
    {
      tmp = sh_util_safe_name (path);
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, status, MSG_E_SUBGPATH, 
		      _("Error reading file"), _("sh_prelink_iself"), tmp);
      SH_FREE(path);
    }
  return S_FALSE;
}

extern int get_the_fd (SL_TICKET ticket);

static void sh_prelink_fd(sh_tas_t * task)
{
  SL_TICKET ticket;
  char * tmp;
  char hashbuf[KEYBUF_SIZE];

  if (task->com_ti != (-1))
    {
      (void) sl_close(task->com_ti);
      task->com_fd = -1;
      task->com_ti = -1;
    }
  ticket = sl_open_read(FIL__, __LINE__, task->command, 
			task->privileged == 0 ? SL_NOPRIV : SL_YESPRIV);
  if (SL_ISERROR(ticket))
    {
      char errbuf[SH_ERRBUF_SIZE];
      char errbuf2[SH_ERRBUF_SIZE];
      sh_error_message(errno, errbuf2, sizeof(errbuf2));
      sl_strlcpy(errbuf, sl_error_string(ticket), sizeof(errbuf));
      tmp = sh_util_safe_name (task->command);
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, ticket, MSG_E_READ, errbuf, errbuf2, tmp);
      SH_FREE(tmp);
      return;
    }

  if (*(task->checksum) == '\0' ||
      0 == sl_strcmp(task->checksum, 
		     sh_tiger_hash (task->command, ticket, TIGER_NOLIM, hashbuf, sizeof(hashbuf))))
    {
      task->com_fd = get_the_fd(ticket);
      task->com_ti = ticket;
    }
  else
    {
      tmp = sh_util_safe_name (task->command);
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, ticket, MSG_E_HASH, tmp);
      SH_FREE(tmp);
      (void) sl_close(ticket);
    }
  return;
}

/* returns static storage
 */
int sh_prelink_run (char * path, char * file_hash, int alert_timeout, unsigned long mask)
{
  static int      init = S_FALSE;
  static int      args_filled = 0;
  static sh_tas_t task;

  int    status = 0;
  char * p;

  SL_ENTER(_("sh_prelink_run"));

  /* reset if path == NULL
   */
  if (path == NULL)
    {
      if (init == S_FALSE)
	{
	   SL_RETURN (0, _("sh_prelink_run"));
	}
      sh_ext_tas_free(&task);
      init = S_FALSE;
      args_filled = 0;
      SL_RETURN (0, _("sh_prelink_run"));
    }

  /* initialize task structure
   */
  if (init == S_FALSE)
    {
      char dir[SH_PATHBUF];

      sh_ext_tas_init(&task);
      p = sh_unix_getUIDdir (SH_ERR_ERR, task.run_user_uid, dir, sizeof(dir));
      if (p)
	{
	  (void) sh_ext_tas_add_envv (&task, _("HOME"), p);
	}
      (void) sh_ext_tas_add_envv (&task, _("SHELL"), 
				  _("/bin/sh")); 
      (void) sh_ext_tas_add_envv (&task, _("PATH"),  
				  _("/sbin:/usr/sbin:/bin:/usr/bin")); 
      if (sh.timezone != NULL)
	{
	  (void) sh_ext_tas_add_envv(&task,  "TZ", sh.timezone);
	}
      if (prelink_path == NULL)
	{
	  sh_ext_tas_command(&task,  _("/usr/sbin/prelink"));
	  (void) sh_ext_tas_add_argv(&task,  _("/usr/sbin/prelink"));
	}
      else
	{
	  sh_ext_tas_command(&task,  prelink_path);
	  (void) sh_ext_tas_add_argv(&task,  prelink_path);
	}
      args_filled = sh_ext_tas_add_argv(&task,  _("--verify"));

      if (prelink_hash != NULL)
	{
	  (void) sl_strlcpy(task.checksum, prelink_hash, KEY_LEN+1);
	}
      task.rw = 'r';
      task.fork_twice = S_FALSE;

      sh_prelink_fd(&task);

      init = S_TRUE;
    }

  /* rm filename arg if set; fill in filename
   */
  if (args_filled == 3)
    args_filled = sh_ext_tas_rm_argv(&task);
  if (args_filled == 2)
    args_filled = sh_ext_tas_add_argv(&task, path);
  else
    {
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, args_filled, MSG_E_SUBGEN, 
		      _("Bad argument count"), _("sh_prelink_run"));
      SL_RETURN ((-1), _("sh_prelink_run"));
    }

  /* open pipe
   */
  status = sh_ext_popen(&task);
  if (status != 0)
    {
      sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, status, MSG_E_SUBGEN, 
		      _("Could not open pipe"), _("sh_prelink_run"));
      SL_RETURN ((-1), _("sh_prelink_run"));
    }

  if (SL_ISERROR(task.pipeTI))
    {
      sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, task.pipeTI, MSG_E_SUBGEN, 
		      _("No valid ticket"), _("sh_prelink_run"));
      SL_RETURN ((-1), _("sh_prelink_run"));
    }

  /* read from pipe
   */
  sl_read_timeout_prep (task.pipeTI);

  {
    char hashbuf[KEYBUF_SIZE];
    UINT64 length_nolim = TIGER_NOLIM;
    if (sh.flag.opts == S_TRUE) sh_tiger_set_hashtype_mask(mask);
    sl_strlcpy(file_hash,
	       sh_tiger_generic_hash (path, task.pipeTI, &length_nolim, alert_timeout,
				      hashbuf, sizeof(hashbuf)),
	       KEY_LEN+1);
  }

  /* close pipe and return exit status
   */
  status = sh_ext_pclose(&task);
  SL_RETURN ((status), _("sh_prelink_run"));
}
/* defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
 */
#endif
