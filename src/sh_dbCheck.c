/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2015 Rainer Wichmann                                      */
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

#include "samhain.h"
#include "sh_unix.h"
#include "sh_utils.h"
#include "sh_hash.h"
#include "sh_files.h"
#include "sh_tiger.h"

#include "sh_dbIO.h"
#include "sh_dbIO_int.h"
#include "sh_pthread.h"

#undef  FIL__
#define FIL__  _("sh_dbCheck.c")

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE) 

static void file_verify(sh_file_t * p)
{
  int reported = 0;
  unsigned long check_flags;
  char * dir_name;
  char * file_name;

  if (p->next != NULL)
    file_verify(p->next);
  if (p->fullpath == NULL || p->fullpath[0] != '/')
    return;

  check_flags = p->theFile.checkflags;

  if (!MODI_INITIALIZED(check_flags)) {
    MODI_SET(check_flags, MODI_INIT|MASK_READONLY_);
    sh_tiger_get_mask_hashtype(&check_flags);
  }

  dir_name   = sh_util_dirname(p->fullpath);
  file_name  = sh_util_basename(p->fullpath);

  if (SH_FILE_UNKNOWN == sh_files_filecheck (SH_LEVEL_READONLY, check_flags,
					     dir_name, file_name,
					     &reported, 0))
    ++sh.statistics.files_report;

  SH_FREE(dir_name);
  SH_FREE(file_name);
  return;
}

static void dbCheck_setup()
{
  sh_hash_set_initialized();
  sh.flag.isdaemon = S_FALSE; 
  sh.flag.loop     = S_FALSE;
  sh.flag.update   = S_FALSE;
  sh.flag.checkSum = SH_CHECK_CHECK;
  
  sh.statistics.files_report  = 0;
  ShDFLevel[SH_ERR_T_FILE]    = SH_ERR_SEVERE;
  ShDFLevel[SH_ERR_T_RO]      = SH_ERR_SEVERE;
  ShDFLevel[SH_ERR_T_NAME]    = SH_ERR_SEVERE;

  return;
}
#include <stddef.h>
int sh_dbCheck_verify (const char * db_file)
{
  unsigned int i;
  sh_file_t ** mtab = get_default_data_table();
  
  sh_error_only_stderr (S_TRUE);
  sh_error_setprint(_("none"));

  /* for sh.effective.home in open_tmp() */
  sh_unix_getUser (); 

  if (sh_dbIO_load_db_file(mtab, db_file) < 0)
    aud_exit (FIL__, __LINE__, EXIT_FAILURE);

  dbCheck_setup();

  /* Don't lock because:
   * (a) we are single-treaded, thus it's not required
   * (b) it will lead to deadlocking
   */
  for (i = 0; i < TABSIZE; ++i)
    {
      if (mtab[i] != NULL) 
	file_verify(mtab[i]);
    }
  
  sh_hash_unvisited (SH_ERR_INFO);
  
  if (0 != sh.statistics.files_report)
    aud_exit (FIL__, __LINE__, EXIT_FAILURE);
  aud_exit (FIL__, __LINE__, EXIT_SUCCESS);
  return 0;
}

#endif
