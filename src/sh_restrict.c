/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2011 Rainer Wichmann                                      */
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

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)

#ifdef HAVE_REGEX_H
#include <sys/types.h>
#include <regex.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "samhain.h"
#include "sh_mem.h"
#include "sh_error_min.h"
#include "sh_string.h"
#include "sh_utils.h"
#include "sh_restrict.h"

#define FIL__ _("sh_restrict.c")

#define SH_COND_NOT    (1 << 0)
#define SH_COND_PREFIX (1 << 1)
#define SH_COND_REGEX  (1 << 2)
#define SH_COND_SIZE   (1 << 3)
#define SH_COND_PERM   (1 << 4)
#define SH_COND_FTYPE  (1 << 5)
#define SH_COND_PINCL  (1 << 6)

#define SH_COND_MAX 6

struct sh_restrict_cond {

  unsigned char cond_type[SH_COND_MAX];

#ifdef HAVE_REGEX_H
  regex_t *     cond_preg[SH_COND_MAX];
#endif

  char  *       cond_str[SH_COND_MAX];

  UINT64        cond_int[SH_COND_MAX];

  struct sh_restrict_cond * next;
};

static struct sh_restrict_cond * sh_restrict_list = NULL;

extern int matches_filetype(SL_TICKET ft, char * test_type);

#ifdef HAVE_REGEX_H
static int matches_regex (const char * path, const regex_t * regex)
{
  SL_ENTER(_("matches_regex"));

  if (0 == regexec(regex, path, 0, NULL, 0))
    {
      SL_RETURN(1, _("matches_regex"));
    }
  SL_RETURN(0, _("matches_regex"));
}
#else
static int matches_string (const char * path, const char * string)
{
  SL_ENTER(_("matches_string"));
  
  if (NULL == strstr(path, string))
    {
      SL_RETURN(0, _("matches_string"));
    }
  SL_RETURN(1, _("matches_string"));
}
#endif

static int matches_prefix (const char * path, const char * prefix)
{
  size_t path_len;
  size_t pref_len;

  SL_ENTER(_("matches_prefix"));

  if (path && prefix)
    {
      path_len = sl_strlen(path);
      pref_len = sl_strlen(prefix);
      
      if (path_len >= pref_len)
	{
	  if (0 == strncmp(path, prefix, pref_len))
	    {
	      SL_RETURN(1, _("matches_prefix"));
	    }
	}
    }
  SL_RETURN(0, _("matches_prefix"));
}

static int exceeds_size (UINT64 size, UINT64 maxsize)
{
  SL_ENTER(_("exceeds_size"));

  if (size > maxsize)
    {
      SL_RETURN(1, _("exceeds_size"));
    }
  SL_RETURN(0, _("exceeds_size"));
}

static int matches_perm (UINT64 perm, UINT64 needed_perm)
{
  SL_ENTER(_("matches_perm"));

  if (needed_perm == (perm & 07777))
    {
      SL_RETURN(1, _("matches_perm"));
    }
  SL_RETURN(0, _("matches_perm"));
}

static int includes_perm (UINT64 perm, UINT64 needed_perm)
{
  UINT64 tmp = perm & 07777;

  SL_ENTER(_("includes_perm"));

  if (needed_perm == (tmp & needed_perm))
    {
      SL_RETURN(1, _("includes_perm"));
    }
  SL_RETURN(0, _("includes_perm"));
}

static int sh_restrict_test(const char * path, 
			    UINT64 size, UINT64 perm, SL_TICKET fh,
			    struct sh_restrict_cond * current)
{
  int i;
  unsigned char flag;
  int res = 0;

  (void) fh;

  SL_ENTER(_("sh_restrict_test"));

  for (i = 0; i < SH_COND_MAX; ++i)
    {
      flag = current->cond_type[i];

      if (flag != 0)
	{
	  if      ((flag & (SH_COND_PREFIX)) != 0) {
	    res = matches_prefix(path, current->cond_str[i]);
	  }
	  else if ((flag & (SH_COND_REGEX)) != 0) {
#ifdef HAVE_REGEX_H
	    res = matches_regex(path, current->cond_preg[i]);
#else
	    res = matches_string(path, current->cond_str[i]);
#endif
	  }
	  else if ((flag & (SH_COND_SIZE)) != 0) {
	    res = exceeds_size(size, current->cond_int[i]);
	  }
	  else if ((flag & (SH_COND_PERM)) != 0) {
	    res = matches_perm(perm, current->cond_int[i]);
	  }
	  else if ((flag & (SH_COND_PINCL)) != 0) {
	    res = includes_perm(perm, current->cond_int[i]);
	  }
	  else if ((flag & (SH_COND_FTYPE)) != 0) {
	    res = matches_filetype(fh, current->cond_str[i]);
	  }

	  /* Does condition hold?
	   */
	  if ((flag & (SH_COND_NOT)) != 0) {
	    /* 
	     * Condition negated, ok if false (res == 0)
	     */
	    if (0 != res) {
	      SL_RETURN(0, _("sh_restrict_this"));
	    }
	  }
	  else {
	    /* Condition ok if true (res != 0) */
	    if (0 == res) {
	      SL_RETURN(0, _("sh_restrict_this"));
	    }
	  }
	}
      else
	{
	  break;
	}
    }

  /* All conditions true, restricted 
   */
  SL_RETURN(1, _("sh_restrict_this"));
}

/* >>>>>>>>>> Evaluate the list <<<<<<<<<< */

int sh_restrict_this(const char * path, UINT64 size, UINT64 perm, SL_TICKET fh)
{
  struct sh_restrict_cond * current = sh_restrict_list;

  SL_ENTER(_("sh_restrict_this"));

  if (!current) 
    {
      SL_RETURN(0, _("sh_restrict_this"));
    }

  while (current) 
    {
      if (0 != sh_restrict_test(path, size, perm, fh, current))
	{
	  /* The current conditions are true, restricted
	   */
	  SL_RETURN(1, _("sh_restrict_this"));
	}
      current = current->next;
    }

  SL_RETURN(0, _("sh_restrict_this"));
}


/* >>>>>>>>>> Purge the list <<<<<<<<<< */

static void sh_restrict_delete (struct sh_restrict_cond * current)
{
  int i;

  if (current->next)
    {
      sh_restrict_delete(current->next);
    }

  for (i = 0; i < SH_COND_MAX; ++i)
    {
      if (current->cond_str[i]) {
	SH_FREE(current->cond_str[i]);
      }
#ifdef HAVE_REGEX_H
      if (current->cond_preg[i]) {
	regfree(current->cond_preg[i]);
	SH_FREE(current->cond_preg[i]);
      }
#endif
    }
  SH_FREE(current);
  return;
}

void sh_restrict_purge ()
{
  struct sh_restrict_cond * current = sh_restrict_list;

  sh_restrict_list = NULL;
  if (current)
    sh_restrict_delete(current);

  sh_restrict_add_ftype(NULL);

  return;
}

/* >>>>>>>>>> Create the list <<<<<<<<<< */

static char * get_com(char * str)
{
  char * s;
  char * e;

  /* skip leading WS 
   */
  for (s = str; *s && isspace((int)*s); ++s) /* nothing */;

  e = strchr(s, '(');
  if (e && (e != s))
    {
      *e = '\0'; --e;
      while ( (e != s) && isspace((int)*e) )
	{
	  *e = '\0'; --e;
	}
      if (e != s)
	return s;
    }
  return NULL;
}

static char * get_arg(char * str)
{
  char * s;
  char * e;

  s = strchr(str, '(');

  if (s)
    {
      ++s;
      
      /* skip leading WS 
       */
      for (; *s && isspace((int)*s); ++s) /* nothing */;

      e = strrchr(s, ')');
      if (e && (e != s))
	{
	  /* check that nothing follows */
	  char * u = e;
	  ++u; for (; *u && isspace((int)*u); ++u) /* nothing */;
	  if (*u != '\0') return NULL;
	  
	  /* strip trailing space */
	  *e = '\0'; --e;
	  while ( (e != s) && isspace((int)*e) )
	    {
	      *e = '\0'; --e;
	    }
	  
	  if (e != s)
	    return s;
	}
    }
  return NULL;
}

static int set_cond(struct sh_restrict_cond * current, int i, 
		    char * com, char * arg)
{
  if (!com || !arg || (i >= SH_COND_MAX))
    return -1;

  if      (0 == strcmp(com, _("match_prefix")))
    {
      current->cond_str[i] = sh_util_strdup(arg);
      current->cond_type[i] |= SH_COND_PREFIX;
    }
  else if (0 == strcmp(com, _("match_regex")))
    {
#ifdef HAVE_REGEX_H
      regex_t * preg = SH_ALLOC(sizeof(regex_t)); 

      if (0 != regcomp(preg, arg, REG_NOSUB|REG_EXTENDED))
	{
	  SH_FREE(preg);
	  return (-1);
	}
      current->cond_preg[i] = preg;
#else
      current->cond_str[i] = sh_util_strdup(arg);
#endif
      current->cond_type[i] |= SH_COND_REGEX;
    }
  else if (0 == strcmp(com, _("size_exceeds")))
    {
      current->cond_int[i] = (UINT64) strtoul(arg, (char **) NULL, 0);
      current->cond_type[i] |= SH_COND_SIZE;
    }
  else if (0 == strcmp(com, _("match_permission")))
    {
      current->cond_int[i] = (UINT64) strtoul(arg, (char **) NULL, 8);
      current->cond_type[i] |= SH_COND_PERM;
    }
  else if (0 == strcmp(com, _("have_permission")))
    {
      current->cond_int[i] = (UINT64) strtoul(arg, (char **) NULL, 8);
      current->cond_type[i] |= SH_COND_PINCL;
    }
  else if (0 == strcmp(com, _("match_filetype")))
    {
      current->cond_str[i] = sh_util_strdup(arg);
      current->cond_type[i] |= SH_COND_FTYPE;
    }
  else
    {
      return (-1);
    }
  return 0;
}

/* Format is [!]cond1(arg), cond2(arg), ... 
 */
int sh_restrict_define(const char * str)
{
  SL_ENTER(_("sh_restrict_define"));

  if (str) 
    {
      size_t lengths[SH_COND_MAX];
      unsigned int nfields = SH_COND_MAX;
      char ** array;
      sh_string * def = sh_string_new_from_lchar(str, strlen(str));

      array = split_array_list(sh_string_str(def), &nfields, lengths);

      if (array && nfields > 0)
	{
	  char * p;
	  char * q;
	  unsigned int i;
	  struct sh_restrict_cond * current = 
	    SH_ALLOC(sizeof(struct sh_restrict_cond));

	  current->next = NULL;
	  for (i = 0; i < SH_COND_MAX; ++i)
	    {
	      current->cond_int[i]  = 0; 
	      current->cond_type[i] = 0;
	      current->cond_str[i] = NULL;
#ifdef HAVE_REGEX_H
	      current->cond_preg[i] = NULL;
#endif
	    }
      
	  for (i = 0; i < nfields; ++i) 
	    {
	      if (i == SH_COND_MAX)
		{
		  sh_restrict_delete (current);
		  sh_string_destroy(&def);
		  SH_FREE(array);
		  SL_RETURN((-1), _("sh_restrict_define"));
		}
	      
	      p = array[i];

	      if (*p == '!')
		{
		  current->cond_type[i] |= SH_COND_NOT;
		  ++p;
		}

	      q = get_arg(p);
	      p = get_com(p);

	      if (!q || !p || (0 != set_cond(current, i, p, q)))
		{
		  sh_restrict_delete (current);
		  sh_string_destroy(&def);
		  SH_FREE(array);
		  SL_RETURN((-1), _("sh_restrict_define"));
		}
	    }

	  SH_FREE(array);

	  current->next = sh_restrict_list;
	  sh_restrict_list = current;
	}

      sh_string_destroy(&def);
      SL_RETURN(0, _("sh_restrict_define"));
    }

  SL_RETURN((-1), _("sh_restrict_define"));
}


/* #if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE) */
#endif

#ifdef SH_CUTEST
#include "CuTest.h"

void Test_restrict (CuTest *tc) {

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)

  char str[256];
  char * p;
  char * q;
  int  res;
  SL_TICKET fd;
  char buf[1024];

  strcpy(str, "match(this)");
  p = get_arg(str);
  q = get_com(str);
  CuAssertPtrNotNull(tc, p);
  CuAssertPtrNotNull(tc, q);
  CuAssertStrEquals(tc, "match", q);
  CuAssertStrEquals(tc, "this",  p);
  
  strcpy(str, "  match( this)");
  p = get_arg(str);
  q = get_com(str);
  CuAssertPtrNotNull(tc, p);
  CuAssertPtrNotNull(tc, q);
  CuAssertStrEquals(tc, "match", q);
  CuAssertStrEquals(tc, "this",  p);
  
  strcpy(str, "  match ( this ) ");
  p = get_arg(str);
  q = get_com(str);
  CuAssertPtrNotNull(tc, p);
  CuAssertPtrNotNull(tc, q);
  CuAssertStrEquals(tc, "match", q);
  CuAssertStrEquals(tc, "this",  p);
  
  strcpy(str, "  match   (this   ) ");
  p = get_arg(str);
  q = get_com(str);
  CuAssertPtrNotNull(tc, p);
  CuAssertPtrNotNull(tc, q);
  CuAssertStrEquals(tc, "match", q);
  CuAssertStrEquals(tc, "this",  p);
  
  strcpy(str, "size_exceeds(800), match_prefix(/home), match_regex(.*\\.mpg) ");
  CuAssertTrue(tc, sh_restrict_list == NULL);
  res = sh_restrict_define(str);
  CuAssertIntEquals(tc,0,res);
  CuAssertPtrNotNull(tc, sh_restrict_list);

  sh_restrict_purge();
  CuAssertTrue(tc, sh_restrict_list == NULL);

  strcpy(str, "size_exceeds(800), match_prefix(/home), match_regex(.*\\.mpg), match_permission(0755) ");
  CuAssertTrue(tc, sh_restrict_list == NULL);
  res = sh_restrict_define(str);
  CuAssertIntEquals(tc,0,res);
  CuAssertPtrNotNull(tc, sh_restrict_list);

  strcpy(str, "size_exceeds(800), match_prefix(/foo), have_permission(0100)");
  res = sh_restrict_define(str);
  CuAssertIntEquals(tc,0,res);
  CuAssertPtrNotNull(tc, sh_restrict_list);

  strcpy(str, "size_exceeds(800); match_prefix(/foo), have_permission(0100)");
  res = sh_restrict_define(str);
  CuAssertIntEquals(tc,-1,res);
  CuAssertPtrNotNull(tc, sh_restrict_list);
  
  res = sh_restrict_this("/home/foo.mpg", 1000, 0755, 0);
  CuAssertIntEquals(tc,1,res);

  res = sh_restrict_this("/foo.mpg",      1000, 0755, 0);
  CuAssertIntEquals(tc,1,res);

  /* size too small */
  res = sh_restrict_this("/foo.mpg",       600, 0755, 0);
  CuAssertIntEquals(tc,0,res);

  /* no execute permission */
  res = sh_restrict_this("/foo.mpg",       600, 0644, 0);
  CuAssertIntEquals(tc,0,res);

  /* regex does not match */
   res = sh_restrict_this("/home/foo",     1000, 0755, 0);
  CuAssertIntEquals(tc,0,res);

  /* wrong permission */
  res = sh_restrict_this("/home/foo.mpg", 1000, 0705, 0);
  CuAssertIntEquals(tc,0,res);
  
  /* size too small */
  res = sh_restrict_this("/home/foo.mpg",  600, 0755, 0);
  CuAssertIntEquals(tc,0,res);
  
  /* wrong prefix */
  res = sh_restrict_this("/hoff/foo.mpg", 1000, 0755, 0);
  CuAssertIntEquals(tc,0,res);
  
  sh_restrict_purge();
  CuAssertTrue(tc, sh_restrict_list == NULL);

  fd = sl_open_fastread(FIL__, __LINE__, "/bin/sh", SL_NOPRIV);
  CuAssertTrue(tc, fd > 0);

  strcpy(str, "match_prefix(/bin), match_filetype(EXECUTABLE:UNIX:ELF)");
  res = sh_restrict_define(str);
  CuAssertIntEquals(tc,0,res);
  CuAssertPtrNotNull(tc, sh_restrict_list);

#if !defined(HOST_IS_CYGWIN)
  res = sh_restrict_this("/bin/sh", 1000, 0755, fd);
  CuAssertIntEquals(tc,1,res);
#endif

  sl_close(fd);

  sh_restrict_purge();
  CuAssertTrue(tc, sh_restrict_list == NULL);

  strcpy(str, "match_filetype(FILE:TEXT:COPYING)");
  res = sh_restrict_define(str);
  CuAssertIntEquals(tc,0,res);
  CuAssertPtrNotNull(tc, sh_restrict_list);

  p = getcwd(buf, sizeof(buf));
  CuAssertPtrNotNull(tc, p);

  strcpy(str, "0:0:0:FILE:TEXT:COPYING:Copying:=0a=53=41=4d=48=41=49=4e");
  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);

  sl_strlcat(buf, "/COPYING", sizeof(buf));
  fd = sl_open_fastread(FIL__, __LINE__, buf, SL_NOPRIV);
  CuAssertTrue(tc, fd > 0);

  res = sh_restrict_this(buf, 1000, 0755, fd);
  CuAssertIntEquals(tc,1,res);

  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);
  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);
  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);

  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);
  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);
  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);
  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);

  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);
  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);
  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);
  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);

  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);
  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);
  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);
  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);

  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,-1,res);

  sh_restrict_purge();
  CuAssertTrue(tc, sh_restrict_list == NULL);

  res = sh_restrict_add_ftype(str);
  CuAssertIntEquals(tc,0,res);
  
#else
  (void) tc;
/* #if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE) */
#endif

}
#endif


