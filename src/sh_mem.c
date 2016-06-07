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

#if defined(HAVE_PTHREAD_MUTEX_RECURSIVE)
#define _XOPEN_SOURCE 500
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>


#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

#define SH_REAL_SET

#include "samhain.h"
#include "sh_error.h"
#include "sh_utils.h"
#include "sh_mem.h"
#include "sh_pthread.h"

extern int safe_logger (int thesignal, int method, char * details);

#undef  FIL__
#define FIL__  _("sh_mem.c")

#ifdef MEM_DEBUG

#define CHECKBYTE 0x7F

/* Memory alignment; should be 16 bytes on 64 bit machines.
 * -> 32 bytes overhead/allocation 
 */
#define SH_MEMMULT 16


typedef struct mem_struct {
  struct mem_struct *next;        /* link to next struct    */
  char * real_address;            /* address assigned       */
  char * address;                 /* address returned       */
  unsigned long size;             /* size allocated         */
  char file[20];                  /* Allocation file name   */
  int line;                       /* Allocation line number */
} memlist_t;

memlist_t   * memlist       = NULL;

int           Free_Count  = 0, Alloc_Count = 0;
int           Now_Alloc_Count = 0, Max_Alloc_Count = 0;
unsigned long Mem_Current = 0, Mem_Max = 0;

#ifdef HAVE_PTHREAD
SH_MUTEX_RECURSIVE(mutex_mem);
#endif

/* define MEM_LOG to an absolute filename to enable this */
#ifdef MEM_LOG
void sh_mem_dump ()
{
  memlist_t   * this = memlist;
  FILE * fd;

  SH_MUTEX_RECURSIVE_INIT(mutex_mem);
  SH_MUTEX_RECURSIVE_LOCK(mutex_mem);

  fd = fopen(MEM_LOG, "w");
  if (!fd)
    {
      perror(MEM_LOG);
      _exit(EXIT_FAILURE);
    }

  while (this != NULL)
    {
      fprintf (fd, "## %20s %5d %ld\n",  this->file, this->line, this->size);
      fprintf (fd, "%10p %8ld\n", (void *)this->address, this->size);
      this = this->next;
    }
  sl_fclose(FIL__, __LINE__, fd);

  SH_MUTEX_RECURSIVE_UNLOCK(mutex_mem);
  _exit(EXIT_SUCCESS);
}
#else
void sh_mem_dump ()
{
  return;
}
#endif

memlist_t ** sh_dummy_114_merrlist;

void sh_mem_stat ()
{
  memlist_t   * this;
  memlist_t   * merrlist = NULL;

  SL_ENTER(_("sh_mem_stat"));

  sh_dummy_114_merrlist = (memlist_t **) &merrlist;

  if (Alloc_Count == Free_Count) 
    {
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_MSTAMP,
		       Mem_Max, Mem_Current);
      SL_RET0(_("sh_mem_stat"));
    }
    
  sh_error_handle (SH_ERR_INFO, FIL__, __LINE__, 0, MSG_MSTAMP2,
		   Alloc_Count, Free_Count, Max_Alloc_Count);
  sh_error_handle (SH_ERR_INFO, FIL__, __LINE__, 0, MSG_MSTAMP,
		   Mem_Max, Mem_Current);

  SH_MUTEX_RECURSIVE_INIT(mutex_mem);
  SH_MUTEX_RECURSIVE_LOCK(mutex_mem);

  this = memlist;

  while (this != NULL) 
    {
      memlist_t   * merr = calloc(1,sizeof(memlist_t));

      memcpy(merr, this, sizeof(memlist_t));
      merr->next = merrlist;
      merrlist   = merr;

      this = this->next;
    }

  SH_MUTEX_RECURSIVE_UNLOCK(mutex_mem);

  while (merrlist != NULL) 
    {
      memlist_t   * tmp = merrlist;
      merrlist = merrlist->next;
      
      sh_error_handle (SH_ERR_WARN, FIL__, __LINE__, 0, MSG_E_NOTFREE,
		       tmp->size, tmp->file, tmp->line);
      free(tmp);
    }

  SL_RET0(_("sh_mem_stat"));
}

memlist_t ** sh_dummy_168_merrlist;

void sh_mem_check ()
{
  memlist_t * this;
  memlist_t * merrlist = NULL;
  memlist_t * merr;
  long        nerr = 0;

  SL_ENTER(_("sh_mem_check"));

  sh_dummy_168_merrlist = (memlist_t **) &merrlist;

  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_MSTAMP,
		   Mem_Max, Mem_Current);

  SH_MUTEX_RECURSIVE_INIT(mutex_mem);
  SH_MUTEX_RECURSIVE_LOCK(mutex_mem);

  this = memlist;

  while (this != NULL) 
    {
      if ( this->address == NULL )
	{
	  merr = calloc (1,sizeof(memlist_t));

	  memcpy(merr, this, sizeof(memlist_t));
	  merr->size = 2;

	  merr->next = merrlist;
	  merrlist   = merr;
	  ++nerr;
	}
      else
	{
	  if ( this->address[this->size]        != CHECKBYTE )
	    {
	      merr = calloc(1, sizeof(memlist_t));
	      
	      memcpy(merr, this, sizeof(memlist_t));
	      merr->size = 1;
	      
	      merr->next = merrlist;
	      merrlist   = merr;
	      ++nerr;
	    }
	  if ( this->real_address[SH_MEMMULT-1] != CHECKBYTE )
	    {
	      merr = calloc(1, sizeof(memlist_t));
	      
	      memcpy(merr, this, sizeof(memlist_t));
	      merr->size = 0;
	      
	      merr->next = merrlist;
	      merrlist   = merr;
	      ++nerr;
	    }
	}
      this = this->next;
    }


  SH_MUTEX_RECURSIVE_UNLOCK(mutex_mem);

  while (merrlist != NULL) 
    {
      memlist_t   * tmp = merrlist;
      merrlist = merrlist->next;
      
      if (tmp->size == 2)
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_E_MNULL,
			   tmp->file, tmp->line, FIL__, __LINE__);
      if (tmp->size == 1)
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_E_MOVER,
			   tmp->file, tmp->line, FIL__, __LINE__);
      else
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_E_MUNDER,
			   tmp->file, tmp->line, FIL__, __LINE__);
      free(tmp);
      SH_ABORT;
      _exit (EXIT_FAILURE);
    }

  SL_RET0(_("sh_mem_check"));
}

void * sh_mem_malloc (size_t size, char * file, int line)
{
  void      * the_realAddress;
  void      * theAddress;
  memlist_t * this;

  SL_ENTER(_("sh_mem_malloc"));

  SH_MUTEX_RECURSIVE_INIT(mutex_mem);
  SH_MUTEX_RECURSIVE_LOCK(mutex_mem);

  the_realAddress = calloc(1,size + 2 * SH_MEMMULT);
  
  if ( the_realAddress  == NULL ) 
    {
      (void) safe_logger (0, 0, NULL);

      /* use _exit() rather than exit() - we malloc() in atexit() functions 
       */
      _exit (EXIT_FAILURE);
    }
  
  /* --- Set check bytes. --- 
   */
  theAddress = ((char *) the_realAddress + SH_MEMMULT);

  memset(the_realAddress, CHECKBYTE, SH_MEMMULT);
  memset(theAddress,      CHECKBYTE, size + 1);
  memset(theAddress,      0,         1);

  ++Alloc_Count;
  ++Now_Alloc_Count;

  if (Max_Alloc_Count < Now_Alloc_Count)
    Max_Alloc_Count = Now_Alloc_Count;

  Mem_Current += size;
  Mem_Max = ( (Mem_Current > Mem_Max) ? Mem_Current : Mem_Max);

  this = calloc(1,sizeof(memlist_t));

  if ( this == NULL) 
    {
      (void) safe_logger(0, 0, NULL);

      _exit(EXIT_FAILURE);
    }
  else
    {
      /* make list entry */

      this->real_address = the_realAddress;
      this->address      = theAddress;
      this->size         = size;
      this->line         = line;
      sl_strlcpy(this->file, file, 20);

      this->next = memlist;
      memlist = this;
    }

  SH_MUTEX_RECURSIVE_UNLOCK(mutex_mem);
  SL_RETURN( theAddress, _("sh_mem_malloc"));
}

static void ** sh_mem_dummy_a;
static memlist_t ** sh_mem_merr_3;

void sh_mem_free (void * aa, char * file, int line)
{
  memlist_t * this;
  memlist_t * before;
  memlist_t * merr;
  memlist_t * merrlist = NULL;
  unsigned long        size   = 0;
  void      * a;
  volatile int         flag = 0;

  SL_ENTER(_("sh_mem_free"));

  a      = aa;
  sh_mem_dummy_a = &a;
  sh_mem_merr_3  = (memlist_t **) &merrlist;


  if ( a == NULL ) 
    {
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_E_MNULL,
		       file, line, FIL__, __LINE__);
      SH_ABORT;
      _exit (EXIT_FAILURE);
      SL_RET0(_("sh_mem_free"));
    }
    
  SH_MUTEX_RECURSIVE_INIT(mutex_mem);
  SH_MUTEX_RECURSIVE_LOCK(mutex_mem);

  this   = memlist;
  before = memlist;
  
  /* -- Find record. -- 
   */
  while (this != NULL) 
    {
      if (this->address == a) 
	break;
      before = this;
      this   = this->next;
    }

  if (this == NULL) 
    {
      flag = 1;
      goto out;
    } 
  else 
    {
      a = this->real_address;

      if ( this->address[this->size]        != CHECKBYTE )
	{
	  merr = calloc(1, sizeof(memlist_t));

	  memcpy(merr, this, sizeof(memlist_t));
	  merr->size = 1;

	  merr->next = merrlist;
	  merrlist = merr;
	}

      if ( this->real_address[SH_MEMMULT-1] != CHECKBYTE )
	{
	  merr = calloc(1,sizeof(memlist_t));

	  memcpy(merr, this, sizeof(memlist_t));
	  merr->size = 0;

	  merr->next = merrlist;
	  merrlist = merr;
	}

      size = this->size;

      if (this == memlist) 
	memlist = this->next;
      else 
	before->next = this->next;
    }

  free(a);
  if (this)
    free(this);

  ++Free_Count;
  --Now_Alloc_Count;

  Mem_Current -= size;
 out:
  ; /* label at end of compound statement */
  SH_MUTEX_RECURSIVE_UNLOCK(mutex_mem);

  while (merrlist != NULL) 
    {
      memlist_t   * tmp = merrlist;
      merrlist = merrlist->next;
      
      if (tmp->size == 1)
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_E_MOVER,
			   tmp->file, tmp->line, file, line);
      else
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_E_MUNDER,
			   tmp->file, tmp->line, file, line);
      free(tmp);
      SH_ABORT;
      _exit (EXIT_FAILURE);
    }

  if (flag != 0)
    sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_E_MREC,
		     file, line);

  SL_RET0(_("sh_mem_free"));
}

#else

void sh_mem_free (void * a)
{
  SL_ENTER(_("sh_mem_free"));

  if (a)
    {
      free(a);
    }
  else
    {
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_E_MNULL);
      SH_ABORT;
    }
  SL_RET0(_("sh_mem_free"));
}

void * sh_mem_malloc (size_t size)
{
  void * theAddress;

  SL_ENTER(_("sh_mem_malloc"));

  theAddress = calloc(1,size);

  if ( theAddress != NULL ) 
    {
      SL_RETURN( theAddress, _("sh_mem_malloc"));
    }
  else
    {
      (void) safe_logger(0, 0, NULL);

      /* use _exit() rather than exit() - we malloc() in atexit()  
       */
      SH_ABORT;
      _exit (EXIT_FAILURE);
    }
}
#endif
