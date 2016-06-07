/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999, 2000 Rainer Wichmann                                */
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#undef  FIL__
#define FIL__  _("sh.fifo.c")


#include "samhain.h"
#include "sh_mem.h"
#include "sh_unix.h"
#include "sh_utils.h"
#include "sh_string.h"
#include "sh_fifo.h"

#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
#include <sys/mman.h>
#endif

#define SH_FIFO_TAGGED 1
#define SH_FIFO_M_FAIL 2
#define SH_FIFO_MARKED 4

/* Prepare an email message and return it. Iterate over list on stack and
 * check for each if it is valid for recipient 'tag'. If yes, add to the
 * returned string.
 * okNull == False means that item->s_xtra must be defined
 */
sh_string * tag_list (SH_FIFO * fifo, char * tag,
		      int(*valid)(int, const char*, const char*, const void*),
		      const void * info, int okNull)
{
  struct dlist * item;
  sh_string * result = NULL;

  if (fifo && fifo->fifo_cts > 0)
    {
      item = fifo->head_ptr;

      while (item)
	{
	  /* Same recipient, or no recipient ( := all )
	   */
	  if ( (tag && item->s_xtra && 0 == strcmp(item->s_xtra, tag)) ||
	       ((okNull == S_TRUE) && !(item->s_xtra)) )
	    {
	      if (valid == NULL)
		{
		  item->transact |= SH_FIFO_TAGGED;
		}
	      else
		{
		  /* level, message, recipient, list */
		  if (!valid(item->i_xtra, item->data, tag, info))
		    goto skipped;
		  item->transact |= SH_FIFO_TAGGED;
		}
	      if (!result)
		{
		  result = sh_string_new_from_lchar(item->data, strlen(item->data));
		}
	      else
		{
		  result = sh_string_cat_lchar(result, "\r\n", 2);
		  result = sh_string_add_from_char(result, item->data);
		}
	    }
	skipped:
	  item = item->next;
	}
    }
  return result;
}

void rollback_list (SH_FIFO * fifo)
{
  struct dlist * item;

  if (fifo && fifo->fifo_cts > 0)
    {
      item = fifo->head_ptr;

      while (item && 0 != (item->transact & SH_FIFO_TAGGED))
	{
	  item->transact |= SH_FIFO_M_FAIL;
	  item = item->next;
	}
    }
}

void mark_list (SH_FIFO * fifo)
{
  struct dlist * item;

  if (fifo && fifo->fifo_cts > 0)
    {
      item = fifo->head_ptr;

      while (item && 0 != (item->transact & SH_FIFO_TAGGED))
	{
	  item->transact |= SH_FIFO_MARKED;
	  item = item->next;
	}
    }
}

void reset_list (SH_FIFO * fifo)
{
  struct dlist * item;

  if (fifo && fifo->fifo_cts > 0)
    {
      item = fifo->head_ptr;

      while (item)
	{
	  item->transact = 0;
	  item = item->next;
	}
    }
}

int commit_list (SH_FIFO * fifo)
{
  struct dlist * item;
  struct dlist * getit;
  int    retval = 0;

  if (fifo && fifo->fifo_cts > 0)
    {
      item = fifo->head_ptr;

      while (item)
	{
	  getit = NULL;

	  if ( 0 != (item->transact & SH_FIFO_MARKED) && /* sent              */
	       0 == (item->transact & SH_FIFO_M_FAIL) )  /* no recipient fail */
	    {
	      if (item == fifo->head_ptr)
		fifo->head_ptr   = item->next;
	      if (item == fifo->tail_ptr)
		fifo->tail_ptr   = item->prev;
	      if (item->prev)
		item->prev->next = item->next;
	      if (item->next)
		item->next->prev = item->prev;
	      --(fifo->fifo_cts);
	      getit = item;
	    }
	  item  = item->next;

	  /* Delete it
	   */
	  if (getit)
	    {
	      size_t len = sl_strlen(getit->data);
	      memset(getit->data, 0, len);
	      if (NULL != sl_strstr (getit->data, _("LOGKEY")))
		MUNLOCK(getit->data, (len+1));
	      if (getit->s_xtra)
		SH_FREE(getit->s_xtra);
	      SH_FREE(getit->data);
	      SH_FREE(getit);
	      ++retval;
	    }
	}
    }
  return retval;
}

/* push an item on the head of the list
 */
int push_list (SH_FIFO * fifo, const char * indat, int in_i, const char * in_str)
{
  struct dlist * item;
  size_t         len;

  SL_ENTER(_("push_list"));

  if (indat == NULL || fifo == NULL)
    {
      SL_RETURN((-1), _("push_list"));
    }

  if (fifo->fifo_cts > SH_FIFO_MAX)
    {
      SL_RETURN((-1), _("push_list"));
    }

  len             = sl_strlen(indat);

  if (len == 0)
    {
      SL_RETURN((-1), _("push_list"));
    }
  item            = SH_ALLOC(sizeof(struct dlist));
  item->data      = SH_ALLOC(len+1);
  
  if (NULL != sl_strstr (indat, _("LOGKEY")))
    MLOCK(item->data, (len+1));

  sl_strlcpy (item->data, indat, len+1);
  item->data[len] = '\0';

  item->i_xtra = in_i;
  if (in_str)
    item->s_xtra = sh_util_strdup(in_str);
  else
    item->s_xtra = NULL;
  item->transact = 0;

  if (fifo->tail_ptr == NULL)
    {
      fifo->tail_ptr = item;
      item->prev     = NULL;
    }
  else
    {
      fifo->head_ptr->prev = item;
      item->prev           = NULL;
    }

  item->next      = fifo->head_ptr;
  fifo->head_ptr  = item;

  ++(fifo->fifo_cts);

  SL_RETURN((fifo->fifo_cts), _("push_list"));
}

/* push an item on the tail of the list
 */
int push_tail_list (SH_FIFO * fifo, const char * indat, int in_i, const char * in_str)
{
  struct dlist * item;
  size_t         len;

  SL_ENTER(_("push_tail_list"));

  if (indat == NULL || fifo == NULL)
    {
      SL_RETURN((-1), _("push_tail_list"));
    }

  if (fifo->fifo_cts > SH_FIFO_MAX)
    {
      SL_RETURN((-1), _("push_tail_list"));
    }

  len = sl_strlen(indat);
  if (len == 0)
    {
      SL_RETURN((-1), _("push_list"));
    }

  item            = SH_ALLOC(sizeof(struct dlist));
  item->data      = SH_ALLOC(len+1);

  if (NULL != sl_strstr (indat, _("LOGKEY")))
    MLOCK(item->data, (len+1));

  sl_strlcpy (item->data, indat, len+1);
  item->data[len] = '\0';

  item->i_xtra = in_i;
  if (in_str)
    item->s_xtra = sh_util_strdup(in_str);
  else
    item->s_xtra = NULL;
  item->transact = 0;

  if (fifo->head_ptr == NULL)
    {
      item->next     = NULL;
      fifo->head_ptr = item;
    }
  else
    {
      item->next           = NULL;
      fifo->tail_ptr->next = item;
    }

  item->prev     = fifo->tail_ptr;
  fifo->tail_ptr = item;

  ++(fifo->fifo_cts);

  SL_RETURN((fifo->fifo_cts), _("push_tail_list"));
}

/* pop an item from the tail of the list
 */
/*@null@*/ char * pop_list (SH_FIFO * fifo)
{
  size_t         len;
  struct dlist * getit;
  char         * retval;

  SL_ENTER(_("pop_list"));

  if (fifo == NULL || fifo->tail_ptr == NULL)
    {
      SL_RETURN (NULL, _("pop_list"));
    }

  getit       = fifo->tail_ptr;

  if (getit->prev == NULL) /* last element */
    {
      fifo->tail_ptr = NULL;
      fifo->head_ptr = NULL;
    } 
  else
    {
      fifo->tail_ptr        = getit->prev;
      fifo->tail_ptr->next  = getit->next;
    } 
  
  len         = sl_strlen(getit->data);
  retval      = SH_ALLOC(len+1);
  sl_strlcpy (retval, getit->data, len+1);
 
  memset(getit->data, 0, len);

  if (NULL != sl_strstr (retval, _("LOGKEY")))
    MUNLOCK(getit->data, (len+1));

  if (getit->s_xtra)
    SH_FREE(getit->s_xtra);
  SH_FREE(getit->data);
  SH_FREE(getit);

  --(fifo->fifo_cts);

  SL_RETURN (retval, _("pop_list"));
}


#ifdef SH_CUTEST
#include "CuTest.h"

void Test_fifo (CuTest *tc) {

  SH_FIFO ff;
  int ret;
  char * p;

  fifo_init(&ff);

  p = sh_fifo_pop(&ff);
  CuAssertPtrEquals(tc, NULL, p);

  /* first sequence */
  ret = sh_fifo_push(&ff, "one");
  CuAssertIntEquals(tc,1,ret);
  ret = sh_fifo_push(&ff, "two");
  CuAssertIntEquals(tc,2,ret);
  ret = sh_fifo_push(&ff, "three");
  CuAssertIntEquals(tc,3,ret);

  p = sh_fifo_pop(&ff);
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc,"one", p);
  p = sh_fifo_pop(&ff);
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc,"two", p);
  p = sh_fifo_pop(&ff);
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc,"three", p);
  p = sh_fifo_pop(&ff);
  CuAssertPtrEquals(tc, NULL, p);

  /* second sequence */
  ret = sh_fifo_push(&ff, "one");
  CuAssertIntEquals(tc,1,ret);
  p = sh_fifo_pop(&ff);
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc,"one", p);
  ret = sh_fifo_push_tail(&ff, "one");
  CuAssertIntEquals(tc,1,ret);
  p = sh_fifo_pop(&ff);
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc,"one", p);
  p = sh_fifo_pop(&ff);
  CuAssertPtrEquals(tc, NULL, p);

  /* third sequence */
  ret = sh_fifo_push(&ff, "one");
  CuAssertIntEquals(tc,1,ret);
  ret = sh_fifo_push(&ff, "two");
  CuAssertIntEquals(tc,2,ret);
  ret = sh_fifo_push(&ff, "three");
  CuAssertIntEquals(tc,3,ret);

  p = sh_fifo_pop(&ff);
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc,"one", p);
  ret = sh_fifo_push_tail(&ff, p);
  CuAssertIntEquals(tc,3,ret);

  p = sh_fifo_pop(&ff);
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc,"one", p);
  p = sh_fifo_pop(&ff);
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc,"two", p);
  p = sh_fifo_pop(&ff);
  CuAssertPtrNotNull(tc, p);
  CuAssertStrEquals(tc,"three", p);
  p = sh_fifo_pop(&ff);
  CuAssertPtrEquals(tc, NULL, p);
}

#endif




