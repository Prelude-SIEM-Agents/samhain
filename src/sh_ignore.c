/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2003 Rainer Wichmann                                      */
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

#ifndef NULL
#if !defined(__cplusplus)
#define NULL ((void*)0)
#else
#define NULL (0)
#endif
#endif

#ifdef HAVE_REGEX_H
#include <sys/types.h>
#include <regex.h>
#endif

#include <string.h>

#include "samhain.h"
#include "sh_mem.h"
#include "sh_error.h"

#define FIL__ _("sh_ignore.c")

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)

struct sh_ignore_list {
#ifdef HAVE_REGEX_H
  regex_t                 preg;
#else
  char                  * path;
#endif
  struct sh_ignore_list * next;
};


static struct sh_ignore_list * sh_del_ign = NULL;
static struct sh_ignore_list * sh_new_ign = NULL;
static struct sh_ignore_list * sh_mod_ign = NULL;

static struct sh_ignore_list * sh_ignore_add_int(struct sh_ignore_list * list, 
						 const char * addpath)
{
  struct sh_ignore_list * new;
  char                  * reg_expr;
  size_t                  len;

#ifdef HAVE_REGEX_H
  int                     status = -1;
  char                  * errbuf;
#else
  size_t                  size;
#endif

  SL_ENTER(_("sh_ignore_add"));

  if ( (addpath == NULL) || (sl_ok_adds(2, strlen(addpath)) == S_FALSE) )
    {
      SL_RETURN(list, _("sh_ignore_add"));
    }

  new      = SH_ALLOC(sizeof(struct sh_ignore_list));

  len      = 2 + strlen(addpath);
  reg_expr = SH_ALLOC(len);
  sl_strlcpy(reg_expr,     "^", len);
  sl_strlcat(reg_expr, addpath, len);

#ifdef HAVE_REGEX_H
  status = regcomp(&(new->preg), reg_expr, REG_NOSUB|REG_EXTENDED);
  if (status != 0)  
    {
      errbuf = SH_ALLOC(BUFSIZ+2);
      (void) regerror(status, &(new->preg), errbuf, BUFSIZ); 
      errbuf[BUFSIZ] = '\0';
      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_REGEX,
                       errbuf, reg_expr);
      SH_FREE(errbuf);
      SH_FREE(new);
      SH_FREE(reg_expr);
      SL_RETURN(list, _("sh_ignore_add"));
    }
#else
  size = sl_strlen(addpath);
  new->path = SH_ALLOC(size + 1);
  sl_strlcpy(new->path, addpath, size+1);
#endif

  SH_FREE(reg_expr);
  new->next = list;

  SL_RETURN(new, _("sh_ignore_add"));
}

int sh_ignore_add_del (const char * addpath)
{
  if ((addpath == NULL) || (addpath[0] != '/'))
    {
      return -1;
    }
  sh_del_ign = sh_ignore_add_int (sh_del_ign, addpath);
  return 0;
}

int sh_ignore_add_new (const char * addpath)
{
  if ((addpath == NULL) || (addpath[0] != '/'))
    {
      return -1;
    }
  sh_new_ign = sh_ignore_add_int (sh_new_ign, addpath);
  return 0;
}

int sh_ignore_add_mod (const char * addpath)
{
  if ((addpath == NULL) || (addpath[0] != '/'))
    {
      return -1;
    }
  sh_mod_ign = sh_ignore_add_int (sh_mod_ign, addpath);
  return 0;
}

static int sh_ignore_chk_int (struct sh_ignore_list * list, 
			      const char * chkpath)
{
  struct sh_ignore_list * new = list;

  SL_ENTER(_("sh_ignore_chk"));

  if (chkpath == NULL)
    {
      SL_RETURN(S_FALSE, _("sh_ignore_add"));
    }

  while (new)
    {
#ifdef HAVE_REGEX_H
      if (0 == regexec(&(new->preg), chkpath, 0, NULL, 0))
	{
	  SL_RETURN(S_TRUE, _("sh_ignore_add"));
	} 
#else
      if (0 == sl_strcmp(new->path, chkpath))
	{
	  SL_RETURN(S_TRUE, _("sh_ignore_add"));
	}
#endif
      new = new->next;
    }

  SL_RETURN(S_FALSE, _("sh_ignore_add"));
}

int sh_ignore_chk_new (const char * chkpath)
{
  return (sh_ignore_chk_int(sh_new_ign, chkpath));
}

int sh_ignore_chk_del (const char * chkpath)
{
  return (sh_ignore_chk_int(sh_del_ign, chkpath));
}

int sh_ignore_chk_mod (const char * chkpath)
{
  return (sh_ignore_chk_int(sh_mod_ign, chkpath));
}

int sh_ignore_clean (void)
{
  struct sh_ignore_list * new;

  new = sh_new_ign;

  while (new)
    {
      sh_new_ign = new->next;
#ifdef HAVE_REGEX_H
      regfree (&(new->preg));
#else
      SH_FREE(new->path);
#endif
      SH_FREE(new);
      new        = sh_new_ign;
    }

  new = sh_del_ign;

  while (new)
    {
      sh_del_ign = new->next;
#ifdef HAVE_REGEX_H
      regfree (&(new->preg));
#else
      SH_FREE(new->path);
#endif
      SH_FREE(new);
      new        = sh_del_ign;
    }

  new = sh_mod_ign;

  while (new)
    {
      sh_mod_ign = new->next;
#ifdef HAVE_REGEX_H
      regfree (&(new->preg));
#else
      SH_FREE(new->path);
#endif
      SH_FREE(new);
      new        = sh_mod_ign;
    }

  return 0;
}
#endif

#ifdef SH_CUTEST
#include "CuTest.h"

void Test_ignore_ok (CuTest *tc) {
#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)

  int ret; 

  CuAssertTrue(tc, NULL == sh_del_ign);
  CuAssertTrue(tc, NULL == sh_new_ign);
  CuAssertTrue(tc, NULL == sh_mod_ign);
 
  ret = sh_ignore_add_del ("/var/log/foo/.*");
  CuAssertTrue(tc, 0 == ret);

  CuAssertPtrNotNull(tc, sh_del_ign);
  CuAssertTrue(tc, NULL == sh_new_ign);
  CuAssertTrue(tc, NULL == sh_mod_ign);

  ret = sh_ignore_chk_del ("/var/log/foo/test");
  CuAssertTrue(tc, S_TRUE == ret);
  
  ret = sh_ignore_chk_del ("/var/log/footest");
  CuAssertTrue(tc, S_FALSE == ret);

  ret = sh_ignore_chk_del ("/my/var/log/footest");
  CuAssertTrue(tc, S_FALSE == ret);

  ret = sh_ignore_chk_del ("/my/var/log/foo/test");
  CuAssertTrue(tc, S_FALSE == ret);

  sh_ignore_clean();
  CuAssertTrue(tc, NULL == sh_del_ign);
  CuAssertTrue(tc, NULL == sh_new_ign);
  CuAssertTrue(tc, NULL == sh_mod_ign);
 
  ret = sh_ignore_add_new ("/var/log/foo/.*");
  CuAssertTrue(tc, 0 == ret);

  CuAssertPtrNotNull(tc, sh_new_ign);
  CuAssertTrue(tc, NULL == sh_del_ign);
  CuAssertTrue(tc, NULL == sh_mod_ign);

  ret = sh_ignore_chk_new ("/var/log/foo/test");
  CuAssertTrue(tc, S_TRUE == ret);
  
  ret = sh_ignore_chk_new ("/var/log/footest");
  CuAssertTrue(tc, S_FALSE == ret);

  ret = sh_ignore_chk_new ("/my/var/log/footest");
  CuAssertTrue(tc, S_FALSE == ret);

  ret = sh_ignore_chk_new ("/my/var/log/foo/test");
  CuAssertTrue(tc, S_FALSE == ret);

  sh_ignore_clean();
  CuAssertTrue(tc, NULL == sh_new_ign);
  CuAssertTrue(tc, NULL == sh_del_ign);
  CuAssertTrue(tc, NULL == sh_mod_ign);

  ret = sh_ignore_add_mod ("/var/log/foo/.*");
  CuAssertTrue(tc, 0 == ret);

  CuAssertPtrNotNull(tc, sh_mod_ign);
  CuAssertTrue(tc, NULL == sh_del_ign);
  CuAssertTrue(tc, NULL == sh_new_ign);

  ret = sh_ignore_chk_mod ("/var/log/foo/test");
  CuAssertTrue(tc, S_TRUE == ret);
  
  ret = sh_ignore_chk_mod ("/var/log/footest");
  CuAssertTrue(tc, S_FALSE == ret);

  ret = sh_ignore_chk_mod ("/my/var/log/footest");
  CuAssertTrue(tc, S_FALSE == ret);

  ret = sh_ignore_chk_mod ("/my/var/log/foo/test");
  CuAssertTrue(tc, S_FALSE == ret);

  sh_ignore_clean();
  CuAssertTrue(tc, NULL == sh_new_ign);
  CuAssertTrue(tc, NULL == sh_del_ign);
  CuAssertTrue(tc, NULL == sh_mod_ign);

#else
  (void) tc; /* fix compiler warning */
#endif
  return;
}
/* #ifdef SH_CUTEST */
#endif

