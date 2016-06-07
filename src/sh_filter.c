/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2009 Rainer Wichmann                                      */
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
#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#include "samhain.h"
#include "sh_utils.h"
#include "sh_mem.h"
#include "sh_filter.h"

#undef  FIL__
#define FIL__  _("sh_filter.c")


void sh_filter_free (sh_filter_type * filter)
{
  int i;

  if (filter)
    {
      for (i = 0; i < filter->for_c; ++i) {
#ifdef HAVE_REGEX_H
	if (filter->for_v[i])
	  regfree(filter->for_v[i]);
#else
	if (filter->for_v[i])
	  SH_FREE(filter->for_v[i]);
#endif
	filter->for_v[i] = NULL; 
      }
      filter->for_c = 0;

      for (i = 0; i < filter->fand_c; ++i) {
#ifdef HAVE_REGEX_H
	if (filter->fand_v[i])
	  regfree(filter->fand_v[i]);
#else
	if (filter->fand_v[i])
	  SH_FREE(filter->fand_v[i]);
#endif
	filter->fand_v[i] = NULL; 
      }
      filter->fand_c = 0;

      for (i = 0; i < filter->fnot_c; ++i) {
#ifdef HAVE_REGEX_H
	if (filter->fnot_v[i])
	  regfree(filter->fnot_v[i]);
#else
	if (filter->fnot_v[i])
	  SH_FREE(filter->fnot_v[i]);
#endif
	filter->fnot_v[i] = NULL; 
      }
      filter->fnot_c = 0;
    }
}


int sh_filter_add (const char * str, sh_filter_type * filter, int type)
{
  int     i = 0;
  int     flag = 0;
  size_t  s;

  char  * dupp;
  char  * p;
  char  * end;
  int   * ntok;
  void ** stok;

  SL_ENTER(_("sh_filter_filteradd"));

  if (NULL == str || NULL == filter)
    {
      SL_RETURN((-1), _("sh_filter_filteradd")); 
    }

  if (type == SH_FILT_OR) {
    ntok = &(filter->for_c);
    stok = filter->for_v;
  }
  else if (type == SH_FILT_AND) {
    ntok = &(filter->fand_c);
    stok = filter->fand_v;
  }
  else if (type == SH_FILT_NOT) {
    ntok = &(filter->fnot_c);
    stok = filter->fnot_v;
  }
  else {
    SL_RETURN((-1), _("sh_filter_filteradd")); 
  }

  i = *ntok;
  if (i == SH_FILT_NUM) {
    SL_RETURN((-1), _("sh_filter_filteradd")); 
  }

  dupp = sh_util_strdup(str);
  p   = dupp;

  do
    {
      while (*p == ',' || *p == ' ' || *p == '\t')
	++p;
      if (*p == '\0')
	break;

      end = p; ++end;
      if (*end == '\0')
	break;

      if (*p == '\'')
	{
	  ++p; end = p; if (*end != '\'') ++end;
	  if (*p == '\0' || *end == '\0')
	    break;
	  while (*end != '\0' && *end != '\'')
	    ++end;
	}
      else if (*p == '"')
	{
	  ++p; end = p; if (*end != '"') ++end;
	  if (*p == '\0' || *end == '\0')
	    break;
	  while (*end != '\0' && *end != '"')
	    ++end;
	}
      else
	{
	  while (*end != '\0' && *end != ',' && *end != ' ' && *end != '\t')
	    ++end;
	}
      if (*end == '\0')
	flag = 1;
      else
	*end = '\0';

      s = strlen(p);
      if (s > 0) 
	{
	  ++s;
#ifdef HAVE_REGEX_H
	  if (stok[i] != NULL)
	    regfree((regex_t *) stok[i]);
	  {
	    int status;

	    stok[i] = SH_ALLOC(sizeof(regex_t));

	    status = regcomp((regex_t *) stok[i], p, 
				 REG_NOSUB|REG_EXTENDED);
	    if (status != 0) 
	      {
		char * errbuf = SH_ALLOC(BUFSIZ);
		(void) regerror(status, (regex_t *) stok[i], 
				errbuf, BUFSIZ); 
		errbuf[BUFSIZ-1] = '\0';
		sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_REGEX,
				 errbuf, p);
		SH_FREE(errbuf);
	      }
	  }
#else
	  if (stok[i] != NULL)
	    SH_FREE(stok[i]);

	  stok[i] = SH_ALLOC(s);
	  (void) sl_strlcpy((char *) stok[i], p, s);
#endif
	  ++i;
	}

      p = end; ++p;

      if (i == SH_FILT_NUM)
	break;
    }
  while (p != NULL && *p != '\0' && flag == 0);

  *ntok = i;
  SH_FREE(dupp);

  SL_RETURN (0, _("sh_filter_filteradd"));
}

#ifdef HAVE_REGEX_H
static int sh_filter_cmp(const char * message, void * pattern)
{
  int result;

  result = regexec((regex_t *)pattern, message, 0, NULL, 0);

  if (result != 0)
    return -1;

  /* Successful match. */
  return 0;
}
#else
static int sh_filter_cmp(const char * message, void * pattern)
{
  if (NULL == sl_strstr(message, (char *)pattern))
    return -1;

  /* Successful match. */
  return 0;
}
#endif

/*
 * -- Check filters. Returns 0 if message passes.
 */ 
int sh_filter_filter (const char * message, sh_filter_type * filter)
{
  int i;

  SL_ENTER(_("sh_filter_filter"));

  if (filter)
    {

      /* Presence of any of these keywords prevents execution.
       */
      if (filter->fnot_c > 0)
	{
	  for (i = 0; i < filter->fnot_c; ++i)
	    {
	      if (0 == sh_filter_cmp(message, filter->fnot_v[i]))
		{
		  SL_RETURN ((-1), _("sh_filter_filter"));
		}
	    }
	}
      
      /* Presence of all of these keywords is required for execution.
       */
      if (filter->fand_c > 0)
	{
	  for (i = 0; i < filter->fand_c; ++i)
	    {
	      if (0 != sh_filter_cmp(message, filter->fand_v[i]))
		{
		  SL_RETURN ((-1), _("sh_filter_filter"));
		}
	    }
	}
      
      /* Presence of at least one of these keywords is required for execution.
       */
      if (filter->for_c > 0)
	{
	  for (i = 0; i < filter->for_c; ++i)
	    {
	      if (0 == sh_filter_cmp(message, filter->for_v[i]))
		{
		  goto isok;
		}
	    }
	  SL_RETURN ((-1), _("sh_filter_filter"));
	}
    }

 isok:
  SL_RETURN ((0), _("sh_filter_filter"));
}

sh_filter_type * sh_filter_alloc(void)
{
  sh_filter_type * filter = SH_ALLOC(sizeof(sh_filter_type));

  memset(filter, '\0', sizeof(sh_filter_type));
  filter->for_c  = 0; 
  filter->fand_c = 0; 
  filter->fnot_c = 0;
  return filter;
}
