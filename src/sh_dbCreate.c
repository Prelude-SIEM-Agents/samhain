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

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "samhain.h"
#include "sh_utils.h"
#include "sh_hash.h"
#include "sh_files.h"

#include "sh_dbIO.h"
#include "sh_dbIO_int.h"
#include "sh_pthread.h"
#include "sh_guid.h"

#undef  FIL__
#define FIL__  _("sh_dbCreate.c")

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE) 

static int dbCreate_writeout()
{
  char   uuid[SH_UUID_BUF];
  char * path;
  int    retval;

  if (sh.outpath == NULL || sh.outpath[0] == '\0')
    {
      sh_uuid_generate_random(uuid, sizeof(uuid));
      path = sh_util_strconcat(_("file."), sh.host.name, ".", uuid, NULL);
    }
  else
    path = sh_util_strdup(sh.outpath);

  retval = sh_dbIO_writeout_to_path(path);
  SH_FREE(path);
  return retval;
}

static void  dbCreate_run_filecheck(unsigned long add_mask, char * str)
{
  int status;

  int reported = 0;
  unsigned long check_flags = (MASK_READONLY_ | MODI_INIT | add_mask);
  char * dir_name   = sh_util_dirname(str);
  char * file_name  = sh_util_basename(str);

  status = sh_files_filecheck (SH_LEVEL_READONLY, check_flags,
			       dir_name, file_name, &reported, 0);

  if (status == SH_FILE_UNKNOWN)
    {
      sh_hash_insert_null(str);
    }

  return;
}

static int dbCreate_filecheck(char * str)
{
  unsigned long add_mask = 0;

  if (*str == '+')
    {
      add_mask = MODI_TXT;
      ++str; while (isspace((int)*str)) ++str;
    }
  if (*str != '/')
    {
      char * tmp  = sh_util_safe_name (str);
      sh_error_handle((-1), FIL__, __LINE__, EINVAL, MSG_E_SUBGPATH,
		      _("Not an absolute path"), 
		      _("dbCreate_filecheck"), tmp);
      SH_FREE(tmp);
      return -1;
    }
  dbCreate_run_filecheck(add_mask, str);
  return 0;
}

char * rtrim(char * str)
{
  size_t len;

  if (!str)
    return str;

  len = strlen(str);
  while (len > 0)
    {
      --len;
      if (str[len] == '\n' || str[len] == '\r')
        str[len] = '\0';
      else
        break;
    }
    
  return str;
}

static int dbCreate_loop(FILE * fd)
{
  int  status, retval = 0;
  size_t linesize = MAX_PATH_STORE+2;
  char * line = SH_ALLOC(linesize);

  do {
    status = sh_dbIO_getline(fd, line, linesize);

    if (status > 0)
      {
	char * str = rtrim(line);   
	while (isspace((int)*str)) ++str;
	if (*str != '#')
	  {
	    int    fstatus = -1;
	    size_t len     = 0;
	    char * p       = sh_files_parse_input(str, &len);

	    if (p)
	      {
		fstatus = dbCreate_filecheck(p);
		SH_FREE(p);
	      }
	    if (fstatus != 0)
	      retval = -1;
	  }
      }
  } while (status != -1);

  SH_FREE(line);
  return retval;
}

static FILE * dbCreate_open (const char * path)
{
  FILE * fd = fopen(path, "r");
  if (!fd)
    {
      int error = errno;
      char * tmp  = sh_util_safe_name (path);
      sh_error_handle((-1), FIL__, __LINE__, error, MSG_E_SUBGPATH,
		      _("Cannot open file for read"), 
		      _("dbCreate_open"), tmp);
      SH_FREE(tmp);
      aud_exit (FIL__, __LINE__, EXIT_FAILURE);
    }
  return fd;
}

static void dbCreate_setup()
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

  sh_error_only_stderr (S_TRUE);
  sh_error_setprint(_("none"));

  return;
}


int sh_dbCreate (const char * path)
{
  FILE * fd;

  /* Initialize application status
   */
  dbCreate_setup();

  /* Open file list
   */
  fd = dbCreate_open(path);

  /* Load the database
   */
  sh_hash_init_and_checksum();

  /* Loop over file list to check files.
   */
  dbCreate_loop(fd);

  /* Close file list
   */
  fclose(fd);

  /* Write out database
   */
  if (0 != dbCreate_writeout())
    aud_exit(FIL__, __LINE__, EXIT_FAILURE);

  /* Exit on success.
   */
  aud_exit(FIL__, __LINE__, EXIT_SUCCESS);
  return 0;
}
    
#endif
