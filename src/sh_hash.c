/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999, 2000, 2001, 2002 Rainer Wichmann                    */
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
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

#ifdef MAJOR_IN_MKDEV
#include <sys/mkdev.h>
#else
#ifdef MAJOR_IN_SYSMACROS
#include <sys/sysmacros.h>
#endif
#endif

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif


#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)

#include "samhain.h"
#include "sh_utils.h"
#include "sh_unix.h"
#include "sh_dbIO_int.h"
#include "sh_dbIO.h"
#include "sh_hash.h"
#include "sh_error.h"
#include "sh_tiger.h"
#include "sh_gpg.h"
#include "sh_unix.h"
#include "sh_files.h"
#include "sh_ignore.h"
#include "sh_pthread.h"

#if defined(SH_WITH_CLIENT)
#include "sh_xfer.h"
#endif


#define SH_KEY_NULL _("000000000000000000000000000000000000000000000000")


#undef  FIL__
#define FIL__  _("sh_hash.c")

SH_MUTEX_INIT(mutex_hash,PTHREAD_MUTEX_INITIALIZER);

static char * all_items (file_type * theFile, char * fileHash, int is_new);

static const char  *policy[] = {
  N_("[]"),
  N_("[ReadOnly]"),
  N_("[LogFiles]"),
  N_("[GrowingLogs]"),
  N_("[IgnoreNone]"),
  N_("[IgnoreAll]"),
  N_("[Attributes]"),
  N_("[User0]"),
  N_("[User1]"),
  N_("[User2]"),
  N_("[User3]"),
  N_("[User4]"),
  N_("[Prelink]"),
  NULL
};

static int report_checkflags = S_FALSE;
int set_report_checkflags(const char * c)
{
  return sh_util_flagval(c, &report_checkflags);
}
int get_report_checkflags()
{
  return report_checkflags;
}



const char * sh_hash_getpolicy(int class)
{
  if (class > 0 && class < SH_ERR_T_DIR)
    return _(policy[class]);
  return _("[indef]");
}

/**********************************
 *
 * hash table functions
 *
 **********************************
 */

#include "sh_hash.h"


/**************************************************************
 *
 * create a file_type from a sh_file_t
 *
 **************************************************************/
file_type * sh_hash_create_ft (const sh_file_t * p, char * fileHash)
{
  file_type * theFile;

  SL_ENTER(_("sh_hash_create_ft"));

  theFile = SH_ALLOC(sizeof(file_type));

  sl_strlcpy(theFile->c_mode, p->theFile.c_mode, 11);
  theFile->mode  =  p->theFile.mode;
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  sl_strlcpy(theFile->c_attributes, p->theFile.c_attributes, ATTRBUF_SIZE);
  theFile->attributes =  p->theFile.attributes;
#endif

  sl_strlcpy(theFile->fullpath, p->fullpath, PATH_MAX);
  if (p->linkpath != NULL /* && theFile->c_mode[0] == 'l' */)
    {
      theFile->link_path = sh_util_strdup(p->linkpath);
    }
  else
    {
      theFile->link_path = NULL;
    }
  sl_strlcpy(fileHash, p->theFile.checksum, KEY_LEN+1);
  
  theFile->mtime =  p->theFile.mtime;
  theFile->ctime =  p->theFile.ctime;
  theFile->atime =  p->theFile.atime;
  
  theFile->size  =  p->theFile.size;
  
  sl_strlcpy(theFile->c_group, p->theFile.c_group, GROUP_MAX+2);
  theFile->group =  p->theFile.group;
  sl_strlcpy(theFile->c_owner, p->theFile.c_owner, USER_MAX+2);
  theFile->owner =  p->theFile.owner;
  
  theFile->ino   =  p->theFile.ino;
  theFile->rdev  =  p->theFile.rdev;
  theFile->dev   =  p->theFile.dev;
  theFile->hardlinks = p->theFile.hardlinks;
  theFile->check_flags = p->theFile.checkflags;

  if (p->attr_string)
    theFile->attr_string = sh_util_strdup(p->attr_string);
  else
    theFile->attr_string = NULL;

  SL_RETURN((theFile), _("sh_hash_create_ft"));
}

struct two_sh_file_t {
  sh_file_t * prev;
  sh_file_t * this;
};

static sh_file_t * hashsearch (const char * s);
static int hashsearch_prev (const char * s, struct two_sh_file_t * a, int * index); 


/**************************************************************
 *
 * >>>> The internal database <<<
 *
 **************************************************************/

static sh_file_t * tab[TABSIZE];

sh_file_t ** get_default_data_table()
{
  return tab;
}

/**************************************************************
 *
 * compute hash function
 *
 **************************************************************/

static int hashfunc(const char *s) 
{
  unsigned int n = 0; 

  for ( ; *s; s++) 
    n = 31 * n + *s; 

  return n & (TABSIZE - 1); /* % TABSIZE */; 
} 


int hashreport_missing( char *fullpath, int level)
{
  sh_file_t * p;
  char * tmp;
  char   fileHash[KEY_LEN + 1];
  file_type * theFile;
  char * str;
  char hashbuf[KEYBUF_SIZE];
  volatile int  retval;

  /* --------  find the entry for the file ----------------       */

  SH_MUTEX_LOCK(mutex_hash);

  retval = 0;

  if (sl_strlen(fullpath) <= MAX_PATH_STORE) 
    p = hashsearch(fullpath);
  else 
    p = hashsearch( sh_tiger_hash(fullpath, 
				  TIGER_DATA, 
				  sl_strlen(fullpath),
				  hashbuf, sizeof(hashbuf))
		    );
  if (p == NULL)
    {
      retval = -1;
      goto unlock_and_return;
    }

  theFile = sh_hash_create_ft (p, fileHash);
  str = all_items(theFile, fileHash, 0);
  tmp = sh_util_safe_name(fullpath);

  SH_MUTEX_LOCK(mutex_thread_nolog);
  if (!sh_global_check_silent)
    sh_error_handle (level, FIL__, __LINE__, 0, 
		     MSG_FI_MISS2, tmp, str);
  SH_MUTEX_UNLOCK(mutex_thread_nolog);
  ++sh.statistics.files_report;

  SH_FREE(tmp);
  SH_FREE(str);
  if (theFile->attr_string) SH_FREE(theFile->attr_string);
  if (theFile->link_path)   SH_FREE(theFile->link_path);
  SH_FREE(theFile);

 unlock_and_return:
  ; /* 'label at end of compound statement */
  SH_MUTEX_UNLOCK(mutex_hash);

  /* remove here to avoid second message from hash_unvisited */
  if (retval == 0)
    sh_hash_remove (fullpath);

  return retval;
}


/**************************************************************
 *
 * search for files not visited, and check whether they exist
 *
 **************************************************************/
static sh_file_t * delete_db_entry(sh_file_t *p)
{
  if (p->fullpath)
    {
      SH_FREE(p->fullpath);
      p->fullpath = NULL;
    }
  if (p->linkpath)
    {
      SH_FREE(p->linkpath);
      p->linkpath = NULL;
    }
  if (p->attr_string)
    {
      SH_FREE(p->attr_string);
      p->attr_string = NULL;
    }
  SH_FREE(p);
  return NULL;
}

static void hash_unvisited (int j, 
			    sh_file_t *prev, sh_file_t *p, ShErrLevel level)
{
  struct stat buf;
  int i;
  char * tmp;
  char * ptr;
  char   fileHash[KEY_LEN + 1];
  file_type * theFile;
  char * str;

  SL_ENTER(_("hash_unvisited"));

  if (p->next != NULL)
    hash_unvisited (j, p, p->next, level);

  if (p->fullpath == NULL)
    {
      SL_RET0(_("hash_unvisited"));
    }

  /* Not a fully qualified path, i.e. some info stored by some module
   */
  if (p->fullpath[0] != '/')
    {
      SL_RET0(_("hash_unvisited"));
    }

  /* visited   flag not set: not seen; 
   * checked   flag     set: not seen (i.e. missing), and already checked 
   * reported  flag not set: not reported yet
   * allignore flag not set: not under IgnoreAll
   *
   * Files/directories under IgnoreAll are noticed as missing already
   * during the file check.
   */
  if (((!SH_FFLAG_VISITED_SET(p->fflags)) || SH_FFLAG_CHECKED_SET(p->fflags)) 
      && (!SH_FFLAG_REPORTED_SET(p->fflags))
      /* && (!SH_FFLAG_ALLIGNORE_SET(p->fflags)) */)
    {
      i = retry_lstat(FIL__, __LINE__, p->fullpath, &buf);

     /* if file does not exist
       */
      if (0 != i)
	{
	  ptr = sh_util_dirname (p->fullpath);
	  if (ptr)
	    {
	      /* If any of the parent directories is under IgnoreAll
	       */
	      if ((0 != sh_files_is_allignore(ptr)) || SH_FFLAG_ALLIGNORE_SET(p->fflags))
		level = ShDFLevel[SH_LEVEL_ALLIGNORE];
	      SH_FREE(ptr);
	    }

	  /* Only report if !SH_FFLAG_CHECKED_SET
	   */
	  if (!SH_FFLAG_CHECKED_SET(p->fflags))
	    {
	      if (S_FALSE == sh_ignore_chk_del(p->fullpath))
		{
		  tmp = sh_util_safe_name(p->fullpath);

		  theFile = sh_hash_create_ft (p, fileHash);
		  str = all_items(theFile, fileHash, 0);
		  if (!sh_global_check_silent)
		    sh_error_handle (level, FIL__, __LINE__, 0, 
				     MSG_FI_MISS2, tmp, str);
		  ++sh.statistics.files_report;
		  SH_FREE(str);
		  if (theFile->attr_string) SH_FREE(theFile->attr_string);
		  if (theFile->link_path)   SH_FREE(theFile->link_path);
		  SH_FREE(theFile);

		  SH_FREE(tmp);
		}
	    }

	  /* We rewrite the db on update, thus we need to keep this
	   * if the user does not want to purge it from the db.
	   */

	  if ((sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE) || 
	      (S_TRUE == sh.flag.update && S_TRUE == sh_util_ask_update(p->fullpath)))
	    {
	      /* Remove the old entry
	       */
	      if (prev == p)
		tab[j] = p->next;
	      else
		prev->next = p->next;

	      delete_db_entry(p);

	      SL_RET0(_("hash_unvisited"));
	    }
	}
    }

  else if (SH_FFLAG_VISITED_SET(p->fflags) && SH_FFLAG_REPORTED_SET(p->fflags) 
	   && (!SH_FFLAG_ALLIGNORE_SET(p->fflags)))
    {
      if (S_FALSE == sh_ignore_chk_new(p->fullpath))
	{
	  tmp = sh_util_safe_name(p->fullpath);

	  theFile = sh_hash_create_ft (p, fileHash);
	  str = all_items(theFile, fileHash, 0);
	  if (!sh_global_check_silent)
	    sh_error_handle (level, FIL__, __LINE__, 0, 
			     MSG_FI_MISS2, tmp, str);
	  ++sh.statistics.files_report;
	  SH_FREE(str);
	  if (theFile->attr_string)
	    SH_FREE(theFile->attr_string);
	  SH_FREE(theFile);

	  SH_FREE(tmp);
	}

      CLEAR_SH_FFLAG_REPORTED(p->fflags);
    }

  if (sh.flag.reportonce == S_FALSE)
    CLEAR_SH_FFLAG_REPORTED(p->fflags);

  CLEAR_SH_FFLAG_VISITED(p->fflags);
  CLEAR_SH_FFLAG_CHECKED(p->fflags);
  SET_SH_FFLAG_ENOENT(p->fflags);

  SL_RET0(_("hash_unvisited"));
}



/*********************************************************************
 *
 * Search for files in the database that have been deleted from disk.
 *
 *********************************************************************/
void sh_hash_unvisited (ShErrLevel level)
{
  int i;

  SL_ENTER(_("sh_hash_unvisited"));

  SH_MUTEX_LOCK(mutex_hash);
  for (i = 0; i < TABSIZE; ++i)
    {
      if (tab[i] != NULL) 
	hash_unvisited (i, tab[i], tab[i], level);
    }
  SH_MUTEX_UNLOCK(mutex_hash);

  SL_RET0(_("hash_unvisited"));
}

/*********************************************************************
 *
 * Remove a single file from the database.
 *
 *********************************************************************/
void sh_hash_remove_unconditional (const char * path)
{
  struct two_sh_file_t entries;
  int index;

  SL_ENTER(_("sh_hash_remove_unconditional"));

  SH_MUTEX_LOCK(mutex_hash);
  if (0 == hashsearch_prev (path, &entries, &index))
    {
      sh_file_t * p = entries.this;
      
      /* Remove the old entry
       */
      if (entries.prev == p)
	tab[index] = p->next;
      else
	entries.prev->next = p->next;
      
      delete_db_entry(p);
    }
  SH_MUTEX_UNLOCK(mutex_hash);

  SL_RET0(_("sh_hash_remove_unconditional"));
}

void sh_hash_remove (const char * path)
{
  SL_ENTER(_("sh_hash_remove"));

  if ((sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE) || 
      (S_TRUE == sh.flag.update && S_TRUE == sh_util_ask_update(path)))
    {
      sh_hash_remove_unconditional (path);
    }
  SL_RET0(_("sh_hash_remove"));
}


/*********************************************************************
 *
 * Search for unvisited entries in the database, custom error handler.
 *
 *********************************************************************/
void sh_hash_unvisited_custom (char prefix, void(*handler)(const char * key))
{
  int i;
  sh_file_t *p    = NULL;
  sh_file_t *prev = NULL;
  sh_file_t *next = NULL;

  SL_ENTER(_("sh_hash_unvisited_custom"));

  SH_MUTEX_LOCK(mutex_hash);
  for (i = 0; i < TABSIZE; ++i)
    {
      if (tab[i] != NULL)
	{
	  p = tab[i]; prev = p;

	  do 
	    {
	      next = p->next;

	      if (p->fullpath && 
		  prefix == p->fullpath[0])
		{
		  if ((!SH_FFLAG_VISITED_SET(p->fflags)) 
		      && (!SH_FFLAG_REPORTED_SET(p->fflags)))
		    {
		      handler(p->fullpath);

		      if (!SH_FFLAG_CHECKED_SET(p->fflags))
			{
			  /* delete */
			  if (tab[i] == p)
			    {
			      tab[i] = p->next;
			      prev   = tab[i];
			      next   = prev;
			    }
			  else
			    {
			      prev->next = p->next;
			      next       = prev->next;
			    }

			  p = delete_db_entry(p);
			}
		    }
		  if (p)
		    {
		      CLEAR_SH_FFLAG_VISITED(p->fflags);
		      CLEAR_SH_FFLAG_CHECKED(p->fflags);
		    }
		}
	      if (p)
		prev = p;
	      p    = next;
	    } 
	  while (p);
	}
    }
  SH_MUTEX_UNLOCK(mutex_hash);

  SL_RET0(_("hash_unvisited_custom"));
}


/**********************************************************************
 *
 * delete hash array
 *
 **********************************************************************/
static void hash_kill (sh_file_t *p)
{
  SL_ENTER(_("hash_kill"));

  if (p == NULL)
    SL_RET0(_("hash_kill"));

  if (p->next != NULL)
    hash_kill (p->next);

  if (p->fullpath)
    {
      SH_FREE(p->fullpath);
      p->fullpath = NULL;
    }
  if (p->linkpath)
    {
      SH_FREE(p->linkpath);
      p->linkpath = NULL;
    }
  if (p->attr_string)
    {
      SH_FREE(p->attr_string);
      p->attr_string = NULL;
    }
  SH_FREE(p);
  p = NULL;
  SL_RET0(_("hash_kill"));
}


/***********************************************************************
 *
 * get info out of hash array
 *
 ***********************************************************************/
static sh_file_t * hashsearch (const char * s) 
{
  sh_file_t * p;

  SL_ENTER(_("hashsearch"));

  if (s)
    {
      for (p = tab[hashfunc(s)]; p; p = p->next)
	if ((p->fullpath != NULL) && (0 == strcmp(s, p->fullpath))) 
	  SL_RETURN( p, _("hashsearch"));
    } 
  SL_RETURN( NULL, _("hashsearch"));
} 

static int hashsearch_prev (const char * s, struct two_sh_file_t * a, int * index) 
{
  sh_file_t * this;
  sh_file_t * prev = NULL;

  SL_ENTER(_("hashsearch_prev"));

  if (s)
    {
      *index = hashfunc(s);
      this   = tab[*index];
      prev   = this;

      if (this)
	{
	  do {
	    if ((this->fullpath != NULL) && (0 == strcmp(s, this->fullpath)))
	      {
		a->prev = prev;
		a->this = this;	
		SL_RETURN( 0, _("hashsearch_prev"));
	      }
	    prev = this;
	    this = this->next;
	  } while(this);
	} 
    }
  SL_RETURN( -1, _("hashsearch"));
} 


/***********************************************************************
 *
 * insert into hash array
 *
 ***********************************************************************/
void hashinsert (sh_file_t * mtab[TABSIZE], sh_file_t * s) 
{
  sh_file_t * p;
  sh_file_t * q;
  int key;

  SL_ENTER(_("hashinsert"));

  key = hashfunc(s->fullpath);

  if (mtab[key] == NULL) 
    {
      mtab[key] = s;
      mtab[key]->next = NULL;
      SL_RET0(_("hashinsert"));
    } 
  else 
    {
      p = mtab[key];
      while (1) 
	{
	  if (p && p->fullpath && 0 == strcmp(s->fullpath, p->fullpath))
	    {
	      q = p->next;
	      SH_FREE(p->fullpath);
	      if(p->linkpath)    SH_FREE(p->linkpath);
	      if(p->attr_string) SH_FREE(p->attr_string);
	      memcpy(p, s, sizeof(sh_file_t));
	      p->next = q;
	      SH_FREE(s); s = NULL;
	      SL_RET0(_("hashinsert"));
	    }
	  else if (p && p->next == NULL) 
	    {
	      p->next = s;
	      p->next->next = NULL;
	      SL_RET0(_("hashinsert"));
	    }
	  if (p)
	    p = p->next;
	  else /* cannot really happen, but llvm/clang does not know */
	    break;
	}
    }
  /* notreached */
}



/******************************************************************
 *
 * ------- Check functions -------
 *
 ******************************************************************/

static int IsInit = 0;

void sh_hash_set_initialized()
{
  IsInit = 1;
  return;
}

int sh_hash_get_initialized()
{
  return IsInit;
}


/******************************************************************
 *
 * Initialize
 *
 ******************************************************************/
void sh_hash_init ()
{
  volatile int  retval  = 0;
  volatile int  exitval = EXIT_SUCCESS;

  SL_ENTER(_("sh_hash_init"));

  if ( sh.flag.checkSum == SH_CHECK_INIT )
    {
      dlog(1, FIL__, __LINE__, 
	   _("Attempt to load the baseline database during initialisation. This is an internal error, please report it to the developer.\n"));
      SH_ABORT;
      aud_exit (FIL__, __LINE__, EXIT_FAILURE);
    }

  SH_MUTEX_LOCK(mutex_hash);

  if (IsInit == 1)
    { 
      goto unlock_and_return;
    }

  /* Initialization completed.
   */
  retval = sh_dbIO_load_db(tab);

  if (0 == retval)
    IsInit = 1;
  else
    exitval = EXIT_FAILURE;

 unlock_and_return:
  ; /* 'label at end of compound statement */
  SH_MUTEX_UNLOCK(mutex_hash);
  if (retval == 0)
    {
      SL_RET0(_("sh_hash_init"));
    }
  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_EXIT_ABORT1, sh.prg_name);
  aud_exit (FIL__, __LINE__, exitval);
}

void sh_hash_init_and_checksum()
{
  TPT((0, FIL__, __LINE__, _("msg=<Get checksum of the database.>\n")))
  if (sh.flag.checkSum == SH_CHECK_CHECK) 
    {
      if (0 != sl_strcmp(file_path('D', 'R'), _("REQ_FROM_SERVER")))
	{
	  char hashbuf[KEYBUF_SIZE];
	  (void) sl_strlcpy(sh.data.hash,
			    sh_tiger_hash (file_path('D', 'R'), 
					   TIGER_FILE, TIGER_NOLIM, 
					   hashbuf, sizeof(hashbuf)), 
			    KEY_LEN+1);
	}

      /* this eventually fetches the file from server to get checksum
       */
      sh_hash_init ();
    }
  return;
}
  
/*****************************************************************
 *
 * delete hash array
 *
 *****************************************************************/
void sh_hash_hashdelete ()
{
  int i;

  SL_ENTER(_("sh_hash_hashdelete"));

  /* need deadlock detection here if called from exit handler 
   */
  SH_MUTEX_TRYLOCK(mutex_hash);

  if (IsInit == 0) 
    goto unlock_and_exit;

  for (i = 0; i < TABSIZE; ++i) 
    if (tab[i] != NULL)
      { 
	hash_kill (tab[i]);
	tab[i] = NULL;
      }
  IsInit = 0;

 unlock_and_exit:
  ; /* 'label at end of compound statement */
  SH_MUTEX_TRYLOCK_UNLOCK(mutex_hash);

  SL_RET0(_("sh_hash_hashdelete"));
}

static int sh_loosedircheck = S_FALSE;

int sh_hash_loosedircheck(const char * str)
{
  return sh_util_flagval(str, &sh_loosedircheck);
}




/*********************************************************************
 *
 * Check whether a file is present in the database.
 *
 *********************************************************************/
static sh_file_t *  sh_hash_have_it_int (const char * newname)
{
  sh_file_t * p;
  char hashbuf[KEYBUF_SIZE];

  SL_ENTER(_("sh_hash_have_it_int"));

  if (newname == NULL)
    SL_RETURN( (NULL), _("sh_hash_have_it_int"));

  if (sl_strlen(newname) <= MAX_PATH_STORE) 
    p = hashsearch(newname);
  else 
    p = hashsearch ( sh_tiger_hash(newname, TIGER_DATA, sl_strlen(newname),
				   hashbuf, sizeof(hashbuf)) );
  if (p == NULL) 
     SL_RETURN( (NULL), _("sh_hash_have_it_int"));

  SL_RETURN( (p), _("sh_hash_have_it_int"));
}

int sh_hash_have_it (const char * newname)
{
  sh_file_t * p;
  int retval;

  if (IsInit != 1) 
    sh_hash_init();

  SH_MUTEX_LOCK(mutex_hash);

  retval = 0;

  p = sh_hash_have_it_int (newname);

  if (!p) 
    retval = (-1);
  else if ((!SH_FFLAG_ALLIGNORE_SET(p->fflags)) && 
	   (p->modi_mask & MODI_CHK) != 0 &&
	   (p->modi_mask & MODI_MOD) != 0)
    retval = 1;
  SH_MUTEX_UNLOCK(mutex_hash);

  return retval;
}

int sh_hash_get_it (const char * newname, file_type * tmpFile, char * fileHash)
{
  sh_file_t * p;
  int retval;

  if (IsInit != 1) 
    sh_hash_init();

  tmpFile->link_path   = NULL;
  tmpFile->attr_string = NULL;

  SH_MUTEX_LOCK(mutex_hash);

  retval = (-1);

  p = sh_hash_have_it_int (newname);
  if (p)
    {
      sl_strlcpy(tmpFile->fullpath,  p->fullpath, PATH_MAX);
      if (p->linkpath)
	tmpFile->link_path = sh_util_strdup (p->linkpath);
      tmpFile->size  = p->theFile.size;
      tmpFile->mtime = p->theFile.mtime;
      tmpFile->ctime = p->theFile.ctime;
      tmpFile->atime = p->theFile.atime;

      if (NULL != fileHash)
	sl_strlcpy(fileHash, p->theFile.checksum, KEY_LEN+1);

      tmpFile->attr_string = NULL;
      retval = 0;
    }
  SH_MUTEX_UNLOCK(mutex_hash);

  return retval;
}

int sh_hash_getflags (char * filename)
{
  sh_file_t * p;
  int retval = 0;

  if ( sh.flag.checkSum != SH_CHECK_INIT )
    {
      if (IsInit != 1) 
	sh_hash_init();
      
      SH_MUTEX_LOCK(mutex_hash);
      p = sh_hash_have_it_int (filename);
      if (p)
	retval = p->fflags;
      else
	retval = -1;
      SH_MUTEX_UNLOCK(mutex_hash);
    }
  return retval;
}

int sh_hash_setflags (char * filename, int flags)
{
  sh_file_t * p;
  int retval = 0;

  if ( sh.flag.checkSum != SH_CHECK_INIT )
    {
      if (IsInit != 1) 
	sh_hash_init();
      
      SH_MUTEX_LOCK(mutex_hash);
      p = sh_hash_have_it_int (filename);
      if (p)
	{
	  p->fflags = flags;
	  retval = 0;
	}
      else
	retval = -1;
      SH_MUTEX_UNLOCK(mutex_hash);
    }
  return retval;
}

/* needs lock to be threadsafe
 */
void sh_hash_set_flag (char * filename, int flag_to_set)
{
  sh_file_t * p;

  if ( sh.flag.checkSum != SH_CHECK_INIT )
    {
      if (IsInit != 1) 
	sh_hash_init();
      
      SH_MUTEX_LOCK(mutex_hash);
      p = sh_hash_have_it_int (filename);
      if (p)
	{
	  p->fflags |= flag_to_set;
	}
      SH_MUTEX_UNLOCK(mutex_hash);
    }
  return;
}

/* needs lock to be threadsafe
 */
void sh_hash_clear_flag (char * filename, int flag_to_clear)
{
  sh_file_t * p;

  if ( sh.flag.checkSum != SH_CHECK_INIT )
    {
      if (IsInit != 1) 
	sh_hash_init();
      
      SH_MUTEX_LOCK(mutex_hash);
      p = sh_hash_have_it_int (filename);
      if (p)
	{
	  p->fflags &= ~flag_to_clear;
	}
      SH_MUTEX_UNLOCK(mutex_hash);
    }
  return;
}


/*****************************************************************
 *
 * Set a file's status to 'visited'. This is required for
 * files that should be ignored, and may be present in the
 * database, but not on disk.
 *
 *****************************************************************/
static int sh_hash_set_visited_int (char * newname, int flag)
{
  sh_file_t * p;
  char hashbuf[KEYBUF_SIZE];
  int  retval;

  SL_ENTER(_("sh_hash_set_visited_int"));

  if (newname == NULL)
    SL_RETURN((-1), _("sh_hash_set_visited_int"));

  if (IsInit != 1) 
    sh_hash_init();

  SH_MUTEX_LOCK(mutex_hash);

  if (sl_strlen(newname) <= MAX_PATH_STORE) 
    p = hashsearch(newname);
  else 
    p = hashsearch (sh_tiger_hash(newname, TIGER_DATA, sl_strlen(newname),
				  hashbuf, sizeof(hashbuf)));
  
  if (p)
    {
      if (flag == SH_FFLAG_CHECKED)
	{
	  CLEAR_SH_FFLAG_REPORTED(p->fflags);
	  CLEAR_SH_FFLAG_VISITED(p->fflags);
	  SET_SH_FFLAG_CHECKED(p->fflags);
	}
      else
	{
	  SET_SH_FFLAG_VISITED(p->fflags);
	  CLEAR_SH_FFLAG_CHECKED(p->fflags);
	  if (flag == SH_FFLAG_REPORTED)
	    SET_SH_FFLAG_REPORTED(p->fflags);
	  else
	    CLEAR_SH_FFLAG_REPORTED(p->fflags);
	}
      retval = 0;
    }
  else
    retval = -1;

  SH_MUTEX_UNLOCK(mutex_hash);
  SL_RETURN((retval), _("sh_hash_set_visited_int"));
}


/* cause the record to be deleted without a 'missing' message
 */
int sh_hash_set_missing (char * newname)
{
  int i;
  SL_ENTER(_("sh_hash_set_missing"));

  i = sh_hash_set_visited_int(newname, SH_FFLAG_CHECKED);

  if (sh.flag.checkSum != SH_CHECK_INIT) {
    sh_hash_remove(newname);
  }

  SL_RETURN(i, _("sh_hash_set_missing"));
}

/* mark the file as visited and reported
 */
int sh_hash_set_visited (char * newname)
{
  int i;
  SL_ENTER(_("sh_hash_set_visited"));
  i = sh_hash_set_visited_int(newname, SH_FFLAG_REPORTED);
  SL_RETURN(i, _("sh_hash_set_visited"));
}

/* mark the file as visited and NOT reported
 * used to avoid deletion of file from internal database
 */
int sh_hash_set_visited_true (char * newname)
{
  int i;
  SL_ENTER(_("sh_hash_set_visited_true"));
  i = sh_hash_set_visited_int(newname, 0);
  SL_RETURN(i, _("sh_hash_set_visited_true"));
}


/******************************************************************
 *
 * Data entry for arbitrary data into database
 *
 ******************************************************************/

void sh_hash_push2db (const char * key, struct store2db * save)
{
  int         i = 0;
  char      * p;
  char        i2h[2];
  file_type * tmpFile = SH_ALLOC(sizeof(file_type));

  int size            = save->size;
  unsigned char * str = save->str;


  tmpFile->attr_string = NULL;
  tmpFile->link_path   = NULL;

  sl_strlcpy(tmpFile->fullpath, key, PATH_MAX);
  tmpFile->size  = save->val0;
  tmpFile->mtime = save->val1;
  tmpFile->ctime = save->val2;
  tmpFile->atime = save->val3;

  tmpFile->mode  = 0;
  tmpFile->owner = 0;
  tmpFile->group = 0;
  sl_strlcpy(tmpFile->c_owner, _("root"), 5);
  sl_strlcpy(tmpFile->c_group, _("root"), 5);

  tmpFile->check_flags = 0;

  if ((str != NULL) && (size < (PATH_MAX/2)-1))
    {
      tmpFile->c_mode[0] = 'l';  
      tmpFile->c_mode[1] = 'r'; tmpFile->c_mode[2]  = 'w';
      tmpFile->c_mode[3] = 'x'; tmpFile->c_mode[4]  = 'r'; 
      tmpFile->c_mode[5] = 'w'; tmpFile->c_mode[6]  = 'x'; 
      tmpFile->c_mode[7] = 'r'; tmpFile->c_mode[8]  = 'w'; 
      tmpFile->c_mode[9] = 'x'; tmpFile->c_mode[10] = '\0';
      tmpFile->link_path = SH_ALLOC((size * 2) + 2);
      for (i = 0; i < size; ++i)
	{
	  p = sh_util_charhex (str[i],i2h);
	  tmpFile->link_path[2*i]   = p[0];
	  tmpFile->link_path[2*i+1] = p[1];
	  tmpFile->link_path[2*i+2] = '\0';
	}
    }
  else
    {
      for (i = 0; i < 10; ++i) 
	tmpFile->c_mode[i] = '-';
      tmpFile->c_mode[10] = '\0';
      tmpFile->link_path = sh_util_strdup("-");
    }

  if (sh.flag.checkSum == SH_CHECK_INIT)
    sh_dbIO_data_write (tmpFile, 
			(save->checksum[0] == '\0') ? SH_KEY_NULL : save->checksum);
  else
    sh_hash_pushdata_memory (tmpFile, 
			     (save->checksum[0] == '\0') ? SH_KEY_NULL : save->checksum);

  if (tmpFile->link_path) SH_FREE(tmpFile->link_path);
  SH_FREE(tmpFile);
  return;
}

extern int sh_util_hextobinary (char * binary, char * hex, int bytes);

char * sh_hash_db2pop (const char * key, struct store2db * save)
{
  size_t      len;
  char      * p;
  int         i;
  char      * retval = NULL;
  char        fileHash[KEY_LEN+1];
  file_type * tmpFile = SH_ALLOC(sizeof(file_type));
  
  save->size = 0;

  if (0 == sh_hash_get_it (key, tmpFile, fileHash))
    {
      save->val0 = tmpFile->size;
      save->val1 = tmpFile->mtime;
      save->val2 = tmpFile->ctime;
      save->val3 = tmpFile->atime;

      sl_strlcpy(save->checksum, fileHash, KEY_LEN+1);

      if (tmpFile->link_path && tmpFile->link_path[0] != '-')
	{
	  len = strlen(tmpFile->link_path);

	  p = SH_ALLOC((len/2)+1);
	  i = sh_util_hextobinary (p, tmpFile->link_path, len);

	  if (i == 0)
	    {
	      save->size = (len/2);
	      p[save->size] = '\0';
	      retval = p;
	    }
	  else
	    {
	      SH_FREE(p);
	      save->size = 0;
	    }
	}
      else
	{
	  save->size = 0;
	}
    }
  else
    {
      save->size = -1;
      save->val0 = 0;
      save->val1 = 0;
      save->val2 = 0;
      save->val3 = 0;
    }
  if (tmpFile->link_path) SH_FREE(tmpFile->link_path);
  SH_FREE(tmpFile);
  return retval;
}




/******************************************************************
 *
 * Data entry in hash table
 *
 ******************************************************************/
sh_file_t * sh_hash_push_int (file_type * buf, char * fileHash)
{
  sh_file_t    * fp;
  sh_filestore_t p;

  size_t len;
  char * fullpath;
  char * linkpath;
  char * attr_string = NULL;
  char hashbuf[KEYBUF_SIZE];

  SL_ENTER(_("sh_hash_push_int"));

  fp = SH_ALLOC(sizeof(sh_file_t));

  p.mark = REC_MAGIC;
  if (buf->attr_string)
    p.mark |= REC_FLAGS_ATTR;
  sl_strlcpy(p.c_mode,   buf->c_mode,   11);
  sl_strlcpy(p.c_group,  buf->c_group,  GROUP_MAX+1);
  sl_strlcpy(p.c_owner,  buf->c_owner,  USER_MAX+1);
  sl_strlcpy(p.checksum, fileHash,      KEY_LEN+1);
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  sl_strlcpy(p.c_attributes, buf->c_attributes, 13);
#endif

#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  p.attributes  = (UINT32) buf->attributes;
#endif
  p.linkmode    = (UINT32) buf->linkmode;
  p.hardlinks   = (UINT32) buf->hardlinks;
  p.dev   = (UINT64) buf->dev;
  p.rdev  = (UINT64) buf->rdev;
  p.mode  = (UINT32) buf->mode;
  p.ino   = (UINT32) buf->ino;
  p.size  = (UINT64) buf->size;
  p.mtime = (UINT64) buf->mtime;
  p.atime = (UINT64) buf->atime;
  p.ctime = (UINT64) buf->ctime;
  p.owner = (UINT32) buf->owner;
  p.group = (UINT32) buf->group;

  p.checkflags = (UINT32) buf->check_flags;

  memcpy( &(*fp).theFile, &p, sizeof(sh_filestore_t) );
  fp->fflags    = 0;  /* init fflags */
  fp->modi_mask = 0L;

  if (buf->attr_string)
    attr_string = sh_util_strdup(buf->attr_string);
  fp->attr_string = attr_string;

  len = sl_strlen(buf->fullpath);
  if (len <= MAX_PATH_STORE) 
    {
      fullpath = SH_ALLOC(len+1);
      sl_strlcpy(fullpath, buf->fullpath, len+1);
    } 
  else 
    {
      fullpath = SH_ALLOC(KEY_LEN + 1);
      sl_strlcpy(fullpath, 
		 sh_tiger_hash (buf->fullpath, TIGER_DATA, len,
				hashbuf, sizeof(hashbuf)), 
		 KEY_LEN+1);
    }
  fp->fullpath  = fullpath;

  if (buf->link_path)
    {  
      len = sl_strlen(buf->link_path);
      if (len <= MAX_PATH_STORE) 
	{
	  linkpath = SH_ALLOC(len+1);
	  sl_strlcpy(linkpath, buf->link_path, len+1);
	} 
      else 
	{
	  linkpath = SH_ALLOC(KEY_LEN + 1);
	  sl_strlcpy(linkpath, 
		     sh_tiger_hash (buf->link_path, TIGER_DATA, len,
				    hashbuf, sizeof(hashbuf)), 
		     KEY_LEN+1);
	}
      fp->linkpath  = linkpath;
    }
  else
    fp->linkpath  = NULL;

  SL_RETURN( fp, _("sh_hash_push_int"));
}

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#else
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#endif

#ifndef PRIu64
#ifdef  HAVE_LONG_32
#define PRIu64 "llu"
#else
#define PRIu64 "lu"
#endif
#endif

char * sh_hash_size_format()
{
  static char form_rval[81];

  SL_ENTER(_("sh_hash_size_format"));


#ifdef SH_USE_XML
  sl_snprintf(form_rval, 80, _("%s%s%s%s%s"), 
	      _("size_old=\"%"), PRIu64, _("\" size_new=\"%"), PRIu64, "\" ");
#else
  sl_snprintf(form_rval, 80, _("%s%s%s%s%s"), 
	      _("size_old=<%"), PRIu64, _(">, size_new=<%"), PRIu64, ">, ");
#endif

  SL_RETURN( form_rval, _("sh_hash_size_format"));
}


#ifdef SH_USE_XML
static char * all_items (file_type * theFile, char * fileHash, int is_new)
{
  char timstr1c[32];
  char timstr1a[32];
  char timstr1m[32];

  char * tmp_lnk;
  char * format;

  char * tmp = SH_ALLOC(SH_MSG_BUF);
  char * msg = SH_ALLOC(SH_MSG_BUF);

  tmp[0] = '\0';
  msg[0] = '\0';

  if (report_checkflags != S_FALSE)
    {
      if (is_new)
	format = _("checkflags_new=\"0%lo\" ");
      else
	format = _("checkflags_old=\"0%lo\" ");
      sl_snprintf(tmp, SH_MSG_BUF, format,
		  (unsigned long) theFile->check_flags);
      sl_strlcat(msg, tmp, SH_MSG_BUF); 
    }

#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  if (is_new)
    format = _("mode_new=\"%s\" attr_new=\"%s\" imode_new=\"%ld\" iattr_new=\"%ld\" ");
  else 
    format = _("mode_old=\"%s\" attr_old=\"%s\" imode_old=\"%ld\" iattr_old=\"%ld\" ");
  sl_snprintf(tmp, SH_MSG_BUF, format,
	      theFile->c_mode,
	      theFile->c_attributes,
	      (long) theFile->mode,
	      (long) theFile->attributes
	      );
#else
  if (is_new)
    format = _("mode_new=\"%s\" imode_new=\"%ld\" ");
  else
    format = _("mode_old=\"%s\" imode_old=\"%ld\" ");

  sl_snprintf(tmp, SH_MSG_BUF, format,
	      theFile->c_mode,
	      (long) theFile->mode
	      );
#endif
  sl_strlcat(msg, tmp, SH_MSG_BUF);

  if (is_new)
    format = _("hardlinks_new=\"%lu\" ");
  else
    format = _("hardlinks_old=\"%lu\" ");
  sl_snprintf(tmp, SH_MSG_BUF, format,
	      (unsigned long) theFile->hardlinks);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  if (is_new)
    format = _("idevice_new=\"%lu\" ");
  else
    format = _("idevice_old=\"%lu\" ");
  sl_snprintf(tmp, SH_MSG_BUF, format, (unsigned long) theFile->rdev);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  if (is_new)
    format = _("inode_new=\"%lu\" ");
  else
    format = _("inode_old=\"%lu\" ");
  sl_snprintf(tmp, SH_MSG_BUF, format, (unsigned long) theFile->ino);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  /* 
   * also report device for prelude
   */
#if defined(HAVE_LIBPRELUDE)
  if (is_new)
    format = _("dev_new=\"%lu,%lu\" ");
  else
    format = _("dev_old=\"%lu,%lu\" ");
  sl_snprintf(tmp, SH_MSG_BUF, format,		      
	      (unsigned long) major(theFile->dev),
	      (unsigned long) minor(theFile->dev));
  sl_strlcat(msg, tmp, SH_MSG_BUF);
#endif


  if (is_new)
    format = _("owner_new=\"%s\" iowner_new=\"%ld\" ");
  else
    format = _("owner_old=\"%s\" iowner_old=\"%ld\" ");
  sl_snprintf(tmp, SH_MSG_BUF, format,
	      theFile->c_owner, (long) theFile->owner);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  if (is_new)
    format = _("group_new=\"%s\" igroup_new=\"%ld\" ");
  else
    format = _("group_old=\"%s\" igroup_old=\"%ld\" ");
  sl_snprintf(tmp, SH_MSG_BUF, format,
	      theFile->c_group, (long) theFile->group);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, sh_hash_size_format(),
		(UINT64) 0, (UINT64) theFile->size);
  else
    sl_snprintf(tmp, SH_MSG_BUF, sh_hash_size_format(),
		(UINT64) theFile->size, (UINT64) 0);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  (void) sh_unix_gmttime (theFile->ctime, timstr1c,  sizeof(timstr1c));
  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, _("ctime_new=\"%s\" "), timstr1c);
  else
    sl_snprintf(tmp, SH_MSG_BUF, _("ctime_old=\"%s\" "), timstr1c);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  (void) sh_unix_gmttime (theFile->atime, timstr1a,  sizeof(timstr1a));
  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, _("atime_new=\"%s\" "), timstr1a);
  else
    sl_snprintf(tmp, SH_MSG_BUF, _("atime_old=\"%s\" "), timstr1a);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  (void) sh_unix_gmttime (theFile->mtime, timstr1m,  sizeof(timstr1m));
  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, _("mtime_new=\"%s\" "), timstr1m);
  else
    sl_snprintf(tmp, SH_MSG_BUF, _("mtime_old=\"%s\" "), timstr1m);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, _("chksum_new=\"%s\" "), fileHash);
  else
    sl_snprintf(tmp, SH_MSG_BUF, _("chksum_old=\"%s\" "), fileHash);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  if (theFile->c_mode[0] == 'l' || 
      (theFile->link_path != NULL && theFile->link_path[0] != '-'))
    {
      tmp_lnk     = sh_util_safe_name(theFile->link_path);
      if (tmp_lnk)
	{
	  if (is_new)
	    sl_snprintf(tmp, SH_MSG_BUF, _("link_new=\"%s\" "), tmp_lnk);
	  else
	    sl_snprintf(tmp, SH_MSG_BUF, _("link_old=\"%s\" "), tmp_lnk);
	  SH_FREE(tmp_lnk);
	  sl_strlcat(msg, tmp, SH_MSG_BUF);
	} 
    }

  if (theFile->attr_string)
    {
      tmp_lnk     = sh_util_safe_name(theFile->attr_string);
      if (tmp_lnk)
	{
	  if (is_new)
	    sl_snprintf(tmp, SH_MSG_BUF, _("acl_new=\"%s\" "), tmp_lnk);
	  else
	    sl_snprintf(tmp, SH_MSG_BUF, _("acl_old=\"%s\" "), tmp_lnk);
	  SH_FREE(tmp_lnk);
	  sl_strlcat(msg, tmp, SH_MSG_BUF);
	} 
    }

  
  SH_FREE(tmp);
  return (msg);
}
#else
static char * all_items (file_type * theFile, char * fileHash, int is_new)
{
  char timstr1c[32];
  char timstr1a[32];
  char timstr1m[32];

  char * tmp_lnk;
  char * format;

  char * tmp = SH_ALLOC(SH_MSG_BUF);
  char * msg = SH_ALLOC(SH_MSG_BUF);

  tmp[0] = '\0';
  msg[0] = '\0';

  if (report_checkflags == S_TRUE)
    {
      if (is_new)
	format = _("checkflags_new=<0%lo> ");
      else
	format = _("checkflags_old=<0%lo> ");
      sl_snprintf(tmp, SH_MSG_BUF, format,
		  (unsigned long) theFile->check_flags);
      sl_strlcat(msg, tmp, SH_MSG_BUF); 
    }


#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  if (is_new)
    format = _("mode_new=<%s>, attr_new=<%s>, imode_new=<%ld>, iattr_new=<%ld>, ");
  else 
    format = _("mode_old=<%s>, attr_old=<%s>, imode_old=<%ld>, iattr_old=<%ld>, ");
  sl_snprintf(tmp, SH_MSG_BUF, format,
	      theFile->c_mode,
	      theFile->c_attributes,
	      (long) theFile->mode,
	      (long) theFile->attributes
	      );
#else
  if (is_new)
    format = _("mode_new=<%s>, imode_new=<%ld>, ");
  else
    format = _("mode_old=<%s>, imode_old=<%ld>, ");

  sl_snprintf(tmp, SH_MSG_BUF, format,
	      theFile->c_mode,
	      (long) theFile->mode
	      );
#endif
  sl_strlcat(msg, tmp, SH_MSG_BUF);

  if (is_new)
    format = _("hardlinks_new=<%lu>, ");
  else
    format = _("hardlinks_old=<%lu>, ");
  sl_snprintf(tmp, SH_MSG_BUF, format,
	      (unsigned long) theFile->hardlinks);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  if (is_new)
    format = _("idevice_new=<%lu>, ");
  else
    format = _("idevice_old=<%lu>, ");
  sl_snprintf(tmp, SH_MSG_BUF, format, (unsigned long) theFile->rdev);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  if (is_new)
    format = _("inode_new=<%lu>, ");
  else
    format = _("inode_old=<%lu>, ");
  sl_snprintf(tmp, SH_MSG_BUF, format, (unsigned long) theFile->ino);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  /* 
   * also report device for prelude
   */
#if defined(HAVE_LIBPRELUDE)
  if (is_new)
    format = _("dev_new=<%lu,%lu>, ");
  else
    format = _("dev_old=<%lu,%lu>, ");
  sl_snprintf(tmp, SH_MSG_BUF, format,		      
	      (unsigned long) major(theFile->dev),
	      (unsigned long) minor(theFile->dev));
  sl_strlcat(msg, tmp, SH_MSG_BUF);
#endif

  if (is_new)
    format = _("owner_new=<%s>, iowner_new=<%ld>, ");
  else
    format = _("owner_old=<%s>, iowner_old=<%ld>, ");
  sl_snprintf(tmp, SH_MSG_BUF, format,
	      theFile->c_owner, (long) theFile->owner);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  if (is_new)
    format = _("group_new=<%s>, igroup_new=<%ld>, ");
  else
    format = _("group_old=<%s>, igroup_old=<%ld>, ");
  sl_snprintf(tmp, SH_MSG_BUF, format,
	      theFile->c_group, (long) theFile->group);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, sh_hash_size_format(),
		(UINT64) 0, (UINT64) theFile->size);
  else
    sl_snprintf(tmp, SH_MSG_BUF, sh_hash_size_format(),
		(UINT64) theFile->size, (UINT64) 0);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 


  (void) sh_unix_gmttime (theFile->ctime, timstr1c,  sizeof(timstr1c));
  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, _("ctime_new=<%s>, "), timstr1c);
  else
    sl_snprintf(tmp, SH_MSG_BUF, _("ctime_old=<%s>, "), timstr1c);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  (void) sh_unix_gmttime (theFile->atime, timstr1a,  sizeof(timstr1a));
  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, _("atime_new=<%s>, "), timstr1a);
  else
    sl_snprintf(tmp, SH_MSG_BUF, _("atime_old=<%s>, "), timstr1a);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  (void) sh_unix_gmttime (theFile->mtime, timstr1m,  sizeof(timstr1m));
  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, _("mtime_new=<%s>, "), timstr1m);
  else
    sl_snprintf(tmp, SH_MSG_BUF, _("mtime_old=<%s>, "), timstr1m);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  if (is_new)
    sl_snprintf(tmp, SH_MSG_BUF, _("chksum_new=<%s>"), fileHash);
  else
    sl_snprintf(tmp, SH_MSG_BUF, _("chksum_old=<%s>"), fileHash);
  sl_strlcat(msg, tmp, SH_MSG_BUF); 

  if (theFile->c_mode[0] == 'l' || 
      (theFile->link_path != NULL && theFile->link_path[0] != '-'))
    {
      tmp_lnk     = sh_util_safe_name(theFile->link_path);
      if (tmp_lnk)
	{
	  if (is_new)
	    sl_snprintf(tmp, SH_MSG_BUF, _(", link_new=<%s> "), tmp_lnk);
	  else
	    sl_snprintf(tmp, SH_MSG_BUF, _(", link_old=<%s> "), tmp_lnk);
	  SH_FREE(tmp_lnk);
	  sl_strlcat(msg, tmp, SH_MSG_BUF);
	} 
    }
  
  if (theFile->attr_string)
    {
      tmp_lnk     = sh_util_safe_name(theFile->attr_string);
      if (tmp_lnk)
	{
	  if (is_new)
	    sl_snprintf(tmp, SH_MSG_BUF, _(", acl_new=<%s> "), tmp_lnk);
	  else
	    sl_snprintf(tmp, SH_MSG_BUF, _(", acl_old=<%s> "), tmp_lnk);
	  SH_FREE(tmp_lnk);
	  sl_strlcat(msg, tmp, SH_MSG_BUF);
	} 
    }

  SH_FREE(tmp);
  return (msg);
}
#endif

void sh_hash_pushdata_memory (file_type * theFile, char * fileHash)
{
  sh_file_t * p;

  SL_ENTER(_("sh_hash_pushdata_memory"));

  p = sh_hash_push_int(theFile, fileHash);
  if (p) 
    {
      SH_MUTEX_LOCK(mutex_hash);
      hashinsert (tab, p);
      p->modi_mask = theFile->check_flags;
      SH_MUTEX_UNLOCK(mutex_hash);
    }

  SL_RET0(_("sh_hash_pushdata_memory"));
}

int sh_hash_is_null_file(file_type * theFile)
{
  if (theFile->hardlinks == SH_DEADFILE && theFile->mode  == 0 &&
      theFile->ino == 0                 && theFile->ctime == 0)
    {
      return S_TRUE;
    }
  return S_FALSE;
}

int sh_hash_is_null_record(sh_filestore_t * theFile)
{
  if (theFile->hardlinks == SH_DEADFILE && theFile->mode  == 0 &&
      theFile->ino == 0                 && theFile->ctime == 0)
    {
      return S_TRUE;
    }
  return S_FALSE;
}

void sh_hash_insert_null(char * str)
{
  file_type theFile = { 0, 0, {'\0'}, 0, 0, 0, 0, 0, 
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
			0, {'\0'},
#endif
			{'\0'}, 0, {'\0'}, 0, {'\0'}, 
			0, 0, 0, 0, 0, 0, 0, NULL,  0, {'\0'}, 0, NULL
  }; /* clang compiler bails out on standard conforming init with just {0} */
  char      fileHash[KEY_LEN+1];
  char      hashbuf[KEYBUF_SIZE];

  sl_strlcpy(fileHash, SH_KEY_NULL, sizeof(fileHash));
  theFile.hardlinks = SH_DEADFILE;

  if (sl_strlen(str) < PATH_MAX)
    sl_strlcpy(theFile.fullpath, str, PATH_MAX);
  else 
     sl_strlcpy(theFile.fullpath, 
		sh_tiger_hash(str, TIGER_DATA, sl_strlen(str),
			      hashbuf, sizeof(hashbuf)),
		PATH_MAX);

  sh_hash_pushdata_memory(&theFile, fileHash);
  return;
}

static int handle_notfound(int  log_severity, int class,
			   file_type * theFile, char * fileHash)
{
  sh_file_t * p;
  int         retval = 0;

  if (S_FALSE == sh_ignore_chk_new(theFile->fullpath))
    {
      char * tmp = sh_util_safe_name(theFile->fullpath);
      char * str;

      sh_files_fixup_mask(class, &(theFile->check_flags));
      str = all_items (theFile, fileHash, 1);
      
      if (!sh_global_check_silent)
	sh_error_handle (log_severity, FIL__, __LINE__, 0, 
			 MSG_FI_ADD2, 
			 tmp, str);
      ++sh.statistics.files_report;
      SH_FREE(str);
      SH_FREE(tmp);
    }
  
  if (sh.flag.reportonce == S_TRUE)
    SET_SH_FFLAG_REPORTED(theFile->file_reported);
  
  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
    {
      p = sh_hash_push_int(theFile, fileHash);
      if (p)
	{
	  hashinsert (tab, p);
	  p->modi_mask = theFile->check_flags;
	  p->theFile.checkflags = p->modi_mask;
	}
    }
  
  else if (S_TRUE == sh.flag.update)
    {
      if (S_TRUE == sh_util_ask_update (theFile->fullpath))
	{
	  p = sh_hash_push_int(theFile, fileHash);
	  if (p)
	    {
	      hashinsert (tab, p);
	      p->modi_mask = theFile->check_flags;
	      p->theFile.checkflags = p->modi_mask;
	    }
	}
      else
	retval = 1;
    }
  return retval;
}

/*****************************************************************
 *
 * Compare a file with the database status.
 *
 *****************************************************************/
int sh_hash_compdata (int class, file_type * theFile, char * fileHash,
		      char * policy_override, int severity_override)
{
  char * msg;
  sh_file_t * p;
  char * tmp;
  char * tmp_path;
  char * tmp_lnk;
  char * tmp_lnk_old;

  char timstr1c[32];
  char timstr2c[32];
  char timstr1a[32];
  char timstr2a[32];
  char timstr1m[32];
  char timstr2m[32];
  char linkHash[KEY_LEN+1];
  char * linkComp;
  int  maxcomp;
  volatile int  checksum_flag = 0;

  char change_code[16];
  int  i;

  unsigned long modi_mask;

  char log_policy[32];
  volatile int  log_severity;
  char hashbuf[KEYBUF_SIZE];
  struct {
    unsigned long oldflags;
    unsigned long newflags;
  } cf_report;

  int  retval;

  SL_ENTER(_("sh_hash_compdata"));

  if (IsInit != 1) sh_hash_init();

  if (severity_override < 0)
    log_severity = ShDFLevel[class];
  else
    log_severity = severity_override;

  if (policy_override != NULL)
    sl_strlcpy (log_policy, policy_override, 32);

  /* --------  find the entry for the file ----------------       */

  SH_MUTEX_LOCK(mutex_hash);

  modi_mask = 0;
  retval    = 0;

  if (sl_strlen(theFile->fullpath) <= MAX_PATH_STORE) 
    p = hashsearch(theFile->fullpath);
  else 
    p = hashsearch( sh_tiger_hash(theFile->fullpath, 
				  TIGER_DATA, 
				  sl_strlen(theFile->fullpath),
				  hashbuf, sizeof(hashbuf))
		    );


  /* --------- Not found in database. ------------
   */

  if (p == NULL) 
    {
      retval = handle_notfound(log_severity, class, theFile, fileHash);
      goto unlock_and_return;
    }

  /* ---------  Skip if we don't want to report changes. ------------
   */
  
  if (S_TRUE == sh_ignore_chk_mod(theFile->fullpath))
    {
      MODI_SET(theFile->check_flags, MODI_NOCHECK);
      p->modi_mask = theFile->check_flags;
      p->theFile.checkflags = p->modi_mask;
      goto unlock_and_return;
    }

  cf_report.oldflags = p->theFile.checkflags;
  cf_report.newflags = theFile->check_flags;

  p->modi_mask = theFile->check_flags;
  p->theFile.checkflags = p->modi_mask;

  /* initialize change_code */
  for (i = 0; i < 15; ++i)
    change_code[i] = '-';
  change_code[15] = '\0';

  TPT ((0, FIL__, __LINE__, _("file=<%s>, cs_old=<%s>, cs_new=<%s>\n"),
	theFile->fullpath, fileHash, p->theFile.checksum));

  if ( (fileHash != NULL) &&
       (strncmp (fileHash, p->theFile.checksum, KEY_LEN) != 0) && 
       (theFile->check_flags & MODI_CHK) != 0)
    {
      checksum_flag = 1;
      
      if ((theFile->check_flags & MODI_SGROW) == 0)
	{
	  modi_mask |= MODI_CHK;
	  change_code[0] = 'C';
	  TPT ((0, FIL__, __LINE__, _("mod=<checksum>")));
	}
      else
	{
	  if (0 != strncmp (&fileHash[KEY_LEN + 1], p->theFile.checksum, KEY_LEN))
	    {
	      if (S_FALSE == sh_check_rotated_log (theFile->fullpath, (UINT64) p->theFile.size, 
						   (UINT64) p->theFile.ino, p->theFile.checksum,
						   p->theFile.checkflags))
		{
		  modi_mask |= MODI_CHK;
		  change_code[0] = 'C';
		  TPT ((0, FIL__, __LINE__, _("mod=<checksum>")));
		}
	      else
		{
		  /* logfile has been rotated */
		  p->theFile.size  = theFile->size;
		  p->theFile.ino   = theFile->ino;
		  sl_strlcpy(p->theFile.checksum, fileHash, KEY_LEN+1);
		}
	    }
	  else
	    {
	      p->theFile.size  = theFile->size;
	      sl_strlcpy(p->theFile.checksum, fileHash, KEY_LEN+1);
	    }
	}
    } 

  if (p->theFile.c_mode[0] == 'l') 
    {
      if (!(theFile->link_path) &&
	  (theFile->check_flags & MODI_LNK) != 0)
	{
	  linkComp = NULL;
	  modi_mask |= MODI_LNK;
	  change_code[1] = 'L';
	  TPT ((0, FIL__, __LINE__, _("mod=<link>")));
	}
      else
	{
	  if (sl_strlen(theFile->link_path) >= MAX_PATH_STORE) 
	    {
	      sl_strlcpy(linkHash, 
			 sh_tiger_hash(theFile->link_path, 
				       TIGER_DATA,
				       sl_strlen(theFile->link_path),
				       hashbuf, sizeof(hashbuf)), 
			 MAX_PATH_STORE+1);
	      linkComp = linkHash;
	      maxcomp  = KEY_LEN;
	    } 
	  else 
	    {
	      linkComp = theFile->link_path;
	      maxcomp  = MAX_PATH_STORE;
	    }
	  
	  if ( sl_strncmp (linkComp, p->linkpath, maxcomp) != 0 &&
	       (theFile->check_flags & MODI_LNK) != 0)
	    {
	      modi_mask |= MODI_LNK;
	      change_code[1] = 'L';
	      TPT ((0, FIL__, __LINE__, _("mod=<link>")));
	    } 
	}
    }

  if (p->theFile.c_mode[0] == 'c' || p->theFile.c_mode[0] == 'b') 
    {
      if ( ( major(theFile->rdev) != major((dev_t)p->theFile.rdev) || 
	     minor(theFile->rdev) != minor((dev_t)p->theFile.rdev) ) &&
	   (theFile->check_flags & MODI_RDEV) != 0)
	{
	  modi_mask |= MODI_RDEV;
	  change_code[2] = 'D';
	  TPT ((0, FIL__, __LINE__, _("mod=<rdev>")));
	} 
    }
      
  /* cast to UINT32 in case ino_t is not 32bit
   */
  if ( (UINT32) theFile->ino != (UINT32) p->theFile.ino  &&
       (theFile->check_flags & MODI_INO) != 0)
    {
      if ((theFile->check_flags & MODI_SGROW) == 0)
	{
	  modi_mask |= MODI_INO;
	  change_code[3] = 'I';
	  TPT ((0, FIL__, __LINE__, _("mod=<inode>")));
	}
      else
	{
	  /* growing log, checksum ok but inode changed 
	   */
	  if (checksum_flag == 0)
	    {
	      if (S_FALSE == sh_check_rotated_log (theFile->fullpath, (UINT64) p->theFile.size, 
						   (UINT64) p->theFile.ino, p->theFile.checksum,
						   p->theFile.checkflags))
		{
		  modi_mask |= MODI_INO;
		  change_code[3] = 'I';
		  TPT ((0, FIL__, __LINE__, _("mod=<inode>")));
		}
	      else
		{
		  /* logfile has been rotated */
		  p->theFile.size  = theFile->size;
		  p->theFile.ino   = theFile->ino;
		  sl_strlcpy(p->theFile.checksum, fileHash, KEY_LEN+1);
		}
	    }
	  else
	    {
	      modi_mask |= MODI_INO;
	      change_code[3] = 'I';
	      TPT ((0, FIL__, __LINE__, _("mod=<inode>")));
	    }
	}
    } 
    
  if ( theFile->hardlinks != (nlink_t) p->theFile.hardlinks &&
       (theFile->check_flags & MODI_HLN) != 0)
    {
      modi_mask |= MODI_HLN;
      change_code[4] = 'H';
      TPT ((0, FIL__, __LINE__, _("mod=<hardlink>")));
    } 


  if ( (  (theFile->mode != p->theFile.mode)
#if defined(USE_ACL) || defined(USE_XATTR)
	  || ( (sh_unix_check_selinux|sh_unix_check_acl) &&
	       ( 
		(theFile->attr_string == NULL && p->attr_string != NULL) ||
		(theFile->attr_string != NULL && p->attr_string == NULL) ||
		(theFile->attr_string != NULL && 0 != strcmp(theFile->attr_string, p->attr_string))
		)
	       )
#endif
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
          || (theFile->attributes != p->theFile.attributes)
#endif
	  )
       && (theFile->check_flags & MODI_MOD) != 0)
    {
      modi_mask |= MODI_MOD;
      change_code[5] = 'M';
      TPT ((0, FIL__, __LINE__, _("mod=<mode>")));
      /* 
       * report link path if switch link/no link 
       */
      if ((theFile->check_flags & MODI_LNK) != 0 &&
	  (theFile->c_mode[0] != p->theFile.c_mode[0]) &&
	  (theFile->c_mode[0] == 'l' || p->theFile.c_mode[0] == 'l'))
	{
	  modi_mask |= MODI_LNK;
	  change_code[1] = 'L';
	  TPT ((0, FIL__, __LINE__, _("mod=<link>")));
	}
    } 

  if ( theFile->owner != (uid_t) p->theFile.owner &&
       (theFile->check_flags & MODI_USR) != 0)
    {
      modi_mask |= MODI_USR;
      change_code[6] = 'U';
      TPT ((0, FIL__, __LINE__, _("mod=<user>")));
    } 

  if ( theFile->group != (gid_t) p->theFile.group &&
       (theFile->check_flags & MODI_GRP) != 0)
    {
      modi_mask |= MODI_GRP;
      change_code[7] = 'G';
      TPT ((0, FIL__, __LINE__, _("mod=<group>")));
    } 

  
  if ( theFile->mtime != (time_t) p->theFile.mtime &&
       (theFile->check_flags & MODI_MTM) != 0)
    {
      modi_mask |= MODI_MTM;
      change_code[8] = 'T';
      TPT ((0, FIL__, __LINE__, _("mod=<mtime>")));
    } 
  
  if ( (theFile->check_flags & MODI_ATM) != 0 &&
       theFile->atime != (time_t) p->theFile.atime)
    {
      modi_mask |= MODI_ATM;
      change_code[8] = 'T';
      TPT ((0, FIL__, __LINE__, _("mod=<atime>")));
    } 

  
  /* Resetting the access time will set a new ctime. Thus, either we ignore
   * the access time or the ctime for NOIGNORE
   */
  if ( theFile->ctime != (time_t) p->theFile.ctime &&
       (theFile->check_flags & MODI_CTM) != 0)
    {
      modi_mask |= MODI_CTM;
      change_code[8] = 'T';
      TPT ((0, FIL__, __LINE__, _("mod=<ctime>")));
    } 

  if ( theFile->size != (off_t) p->theFile.size &&
       (theFile->check_flags & MODI_SIZ) != 0)
    {
      if ((theFile->check_flags & MODI_SGROW) == 0 || 
	  theFile->size < (off_t) p->theFile.size)
	{
	  modi_mask |= MODI_SIZ;
	  change_code[9] = 'S';
	  TPT ((0, FIL__, __LINE__, _("mod=<size>")));
	}
    }
  change_code[10] = '\0';

  /* --- Directories special case ---
   */
  if (p->theFile.c_mode[0] == 'd'                               &&
      0 == (modi_mask & ~(MODI_SIZ|MODI_ATM|MODI_CTM|MODI_MTM)) && 
      sh_loosedircheck == S_TRUE)
    {
      modi_mask = 0;
    }

  /* --- Report full details. ---
   */
  if (modi_mask != 0 && sh.flag.fulldetail == S_TRUE)
    {
      if ((theFile->check_flags & MODI_ATM) == 0)
	modi_mask = MASK_READONLY_;
      else
	modi_mask = MASK_NOIGNORE_;
    }

  /* --- Report on modified files. ---
   */
  if (modi_mask != 0 && (!SH_FFLAG_REPORTED_SET(p->fflags)))
    { 
      tmp = SH_ALLOC(SH_MSG_BUF);
      msg = SH_ALLOC(SH_MSG_BUF);
      msg[0] = '\0';

      sh_files_fixup_mask(class, &(cf_report.newflags));

      if ( (report_checkflags != S_FALSE) && (cf_report.oldflags != cf_report.newflags))
	{
	  sl_snprintf(tmp, SH_MSG_BUF,
#ifdef SH_USE_XML
		      _("checkflags_old=\"0%lo\" checkflags_new=\"0%lo\" "),
#else
		      _("checkflags_old=<0%lo>, checkflags_new=<0%lo>, "),
#endif
		      cf_report.oldflags,  cf_report.newflags);
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 
	}

      if (   ((modi_mask & MODI_MOD) != 0)
#if defined(HAVE_LIBPRELUDE)
	     || ((modi_mask & MODI_USR) != 0)
	     || ((modi_mask & MODI_GRP) != 0)
#endif
	     )
	{
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
	  sl_snprintf(tmp, SH_MSG_BUF, 
#ifdef SH_USE_XML
		      _("mode_old=\"%s\" mode_new=\"%s\" attr_old=\"%s\" attr_new=\"%s\" imode_old=\"%ld\" imode_new=\"%ld\" iattr_old=\"%ld\" iattr_new=\"%ld\" "),
#else
		      _("mode_old=<%s>, mode_new=<%s>, attr_old=<%s>, attr_new=<%s>, "),
#endif
		      p->theFile.c_mode, theFile->c_mode,
		      p->theFile.c_attributes, theFile->c_attributes
#ifdef SH_USE_XML
		      , (long) p->theFile.mode, (long) theFile->mode,
		      (long) p->theFile.attributes, 
		      (long) theFile->attributes
#endif
		      );
#else
#ifdef SH_USE_XML
	  sl_snprintf(tmp, SH_MSG_BUF, 
		      _("mode_old=\"%s\" mode_new=\"%s\" imode_old=\"%ld\" imode_new=\"%ld\" "),
		      p->theFile.c_mode, theFile->c_mode,
		      (long) p->theFile.mode, (long) theFile->mode);
#else
	  sl_snprintf(tmp, SH_MSG_BUF, _("mode_old=<%s>, mode_new=<%s>, "),
		      p->theFile.c_mode, theFile->c_mode);
#endif
#endif
	  sl_strlcat(msg, tmp, SH_MSG_BUF);

#if defined(USE_ACL) || defined(USE_XATTR)
	  if (theFile->attr_string != NULL || p->attr_string != NULL)
	    {
	      sl_snprintf(tmp, SH_MSG_BUF, 
#ifdef SH_USE_XML
			  _("acl_old=\"%s\" acl_new=\"%s\" "),
#else
			  _("acl_old=<%s>, acl_new=<%s>, "),
#endif
			  (p->attr_string)       ? p->attr_string       : _("none"), 
			  (theFile->attr_string) ? theFile->attr_string : _("none"));
	      
	      sl_strlcat(msg, tmp, SH_MSG_BUF);
	    }
#endif

	  if ((modi_mask & MODI_MOD) != 0)
	    {
	      /*
	       * We postpone update if sh.flag.update == S_TRUE because
	       * in interactive mode the user may not accept the change.
	       */
	      if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
		{
		  sl_strlcpy(p->theFile.c_mode, theFile->c_mode, 11);
		  p->theFile.mode = theFile->mode;
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
		  sl_strlcpy(p->theFile.c_attributes,theFile->c_attributes,16);
		  p->theFile.attributes = theFile->attributes;
#endif
#if defined(USE_ACL) || defined(USE_XATTR)
		  if      (p->attr_string == NULL && theFile->attr_string != NULL)
		    { p->attr_string = sh_util_strdup (theFile->attr_string); }
		  else if (p->attr_string != NULL && theFile->attr_string == NULL)
		    { SH_FREE(p->attr_string); p->attr_string = NULL; }
		  else if (theFile->attr_string != NULL && p->attr_string != NULL)
		    { 
		      if (0 != strcmp(theFile->attr_string, p->attr_string))
			{
			  SH_FREE(p->attr_string);
			  p->attr_string = sh_util_strdup (theFile->attr_string);
			}
		    }
#endif
		}
	    }

	}

      if ((modi_mask & MODI_HLN) != 0)
	{
	  sl_snprintf(tmp, SH_MSG_BUF, 
#ifdef SH_USE_XML
		      _("hardlinks_old=\"%lu\" hardlinks_new=\"%lu\" "),
#else
		      _("hardlinks_old=<%lu>, hardlinks_new=<%lu>, "),
#endif
		      (unsigned long) p->theFile.hardlinks, 
		      (unsigned long) theFile->hardlinks);
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 

	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    p->theFile.hardlinks = theFile->hardlinks;
	}

      if ((modi_mask & MODI_RDEV) != 0)
	{
	  sl_snprintf(tmp, SH_MSG_BUF,
#ifdef SH_USE_XML 
		      _("device_old=\"%lu,%lu\" device_new=\"%lu,%lu\" idevice_old=\"%lu\" idevice_new=\"%lu\" "),
#else
		      _("device_old=<%lu,%lu>, device_new=<%lu,%lu>, "),
#endif
		      (unsigned long) major(p->theFile.rdev), 
		      (unsigned long) minor(p->theFile.rdev), 
		      (unsigned long) major(theFile->rdev),
		      (unsigned long) minor(theFile->rdev)
#ifdef SH_USE_XML 
		      , (unsigned long) p->theFile.rdev, 
		      (unsigned long) theFile->rdev
#endif
		      );
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 

	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    p->theFile.rdev = theFile->rdev;
	}

      if ((modi_mask & MODI_INO) != 0)
	{
	  sl_snprintf(tmp, SH_MSG_BUF,
#ifdef SH_USE_XML 
		      _("inode_old=\"%lu\" inode_new=\"%lu\" "),
#else
		      _("inode_old=<%lu>, inode_new=<%lu>, "),
#endif
		      (unsigned long) p->theFile.ino, 
		      (unsigned long) theFile->ino);
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 

	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    {
	      p->theFile.ino = theFile->ino;
	      p->theFile.dev = theFile->dev;
	    }
	}


      /* 
       * also report device for prelude
       */
#if defined(HAVE_LIBPRELUDE)
      if ((modi_mask & MODI_INO) != 0)
	{
	  sl_snprintf(tmp, SH_MSG_BUF,
#ifdef SH_USE_XML 
		      _("dev_old=\"%lu,%lu\" dev_new=\"%lu,%lu\" "),
#else
		      _("dev_old=<%lu,%lu>, dev_new=<%lu,%lu>, "),
#endif
		      (unsigned long) major(p->theFile.dev),
		      (unsigned long) minor(p->theFile.dev),
		      (unsigned long) major(theFile->dev),
		      (unsigned long) minor(theFile->dev)
		      );
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 

	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    p->theFile.dev = theFile->dev;
	}
#endif

      if (   ((modi_mask & MODI_USR) != 0)
#if defined(HAVE_LIBPRELUDE)
	  || ((modi_mask & MODI_MOD) != 0)
#endif
	  )
	{
#ifdef SH_USE_XML
	  sl_snprintf(tmp, SH_MSG_BUF, 
		      _("owner_old=\"%s\" owner_new=\"%s\" iowner_old=\"%ld\" iowner_new=\"%ld\" "),
#else
	  sl_snprintf(tmp, SH_MSG_BUF, 
		      _("owner_old=<%s>, owner_new=<%s>, iowner_old=<%ld>, iowner_new=<%ld>, "),
#endif
		      p->theFile.c_owner, theFile->c_owner, 
		      (long) p->theFile.owner, (long) theFile->owner
		      );
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 

	  if ((modi_mask & MODI_USR) != 0) {
	    if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	      {
		sl_strlcpy(p->theFile.c_owner, theFile->c_owner, USER_MAX+2);
		p->theFile.owner = theFile->owner;
	      }
	  }
	}

      if (   ((modi_mask & MODI_GRP) != 0)
#if defined(HAVE_LIBPRELUDE)
	  || ((modi_mask & MODI_MOD) != 0)
#endif
	  )
	{
#ifdef SH_USE_XML
	  sl_snprintf(tmp, SH_MSG_BUF, 
		      _("group_old=\"%s\" group_new=\"%s\" igroup_old=\"%ld\" igroup_new=\"%ld\" "),
		      p->theFile.c_group, theFile->c_group,
		      (long) p->theFile.group, (long) theFile->group);
#else
	  sl_snprintf(tmp, SH_MSG_BUF, 
		      _("group_old=<%s>, group_new=<%s>, igroup_old=<%ld>, igroup_new=<%ld>, "),
		      p->theFile.c_group, theFile->c_group,
		      (long) p->theFile.group, (long) theFile->group);
#endif

	  sl_strlcat(msg, tmp, SH_MSG_BUF); 

          if ((modi_mask & MODI_GRP) != 0) {
	    if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	      {
		sl_strlcpy(p->theFile.c_group, theFile->c_group, GROUP_MAX+2);
		p->theFile.group = theFile->group;
	      }
	  }
	}

      if ((modi_mask & MODI_SIZ) != 0)
	{
	  sl_snprintf(tmp, SH_MSG_BUF, sh_hash_size_format(),
		      (UINT64) p->theFile.size, 
		      (UINT64) theFile->size);
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 

	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    p->theFile.size = theFile->size;
	}

      if ((modi_mask & MODI_CTM) != 0)
	{
	  (void) sh_unix_gmttime (p->theFile.ctime, timstr1c, sizeof(timstr1c));
	  (void) sh_unix_gmttime (theFile->ctime,   timstr2c, sizeof(timstr2c));
#ifdef SH_USE_XML
	  sl_snprintf(tmp, SH_MSG_BUF, _("ctime_old=\"%s\" ctime_new=\"%s\" "),
		      timstr1c, timstr2c);
#else
	  sl_snprintf(tmp, SH_MSG_BUF, _("ctime_old=<%s>, ctime_new=<%s>, "),
		      timstr1c, timstr2c);
#endif
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 

	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    p->theFile.ctime = theFile->ctime;
	}

      if ((modi_mask & MODI_ATM) != 0)
	{
	  (void) sh_unix_gmttime (p->theFile.atime, timstr1a, sizeof(timstr1a));
	  (void) sh_unix_gmttime (theFile->atime,   timstr2a, sizeof(timstr2a));
#ifdef SH_USE_XML
	  sl_snprintf(tmp, SH_MSG_BUF, _("atime_old=\"%s\" atime_new=\"%s\" "),
		      timstr1a, timstr2a);
#else
	  sl_snprintf(tmp, SH_MSG_BUF, _("atime_old=<%s>, atime_new=<%s>, "),
		      timstr1a, timstr2a);
#endif
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 

	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    p->theFile.atime = theFile->atime;
	}

      if ((modi_mask & MODI_MTM) != 0)
	{
	  (void) sh_unix_gmttime (p->theFile.mtime, timstr1m, sizeof(timstr1m));
	  (void) sh_unix_gmttime (theFile->mtime,   timstr2m, sizeof(timstr2m));
#ifdef SH_USE_XML
	  sl_snprintf(tmp, SH_MSG_BUF, _("mtime_old=\"%s\" mtime_new=\"%s\" "),
		      timstr1m, timstr2m);
#else
	  sl_snprintf(tmp, SH_MSG_BUF, _("mtime_old=<%s>, mtime_new=<%s>, "),
		      timstr1m, timstr2m);
#endif
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 

	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    p->theFile.mtime = theFile->mtime;
	}


      if ((modi_mask & MODI_CHK) != 0)
	{
	  sl_snprintf(tmp, SH_MSG_BUF, 
#ifdef SH_USE_XML
		      _("chksum_old=\"%s\" chksum_new=\"%s\" "),
#else
		      _("chksum_old=<%s>, chksum_new=<%s>, "),
#endif
		      p->theFile.checksum, fileHash);
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 

	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    {
	      sl_strlcpy(p->theFile.checksum, fileHash, KEY_LEN+1);
	      if ((theFile->check_flags & MODI_SGROW) != 0)	      
		p->theFile.size  = theFile->size;
	    }


	  if (theFile->c_mode[0] != 'l' && theFile->link_path &&
	      strlen(theFile->link_path) > 2)
	    modi_mask |= MODI_LNK;
	}


      if ((modi_mask & MODI_LNK) != 0 /* && theFile->c_mode[0] == 'l' */)
	{
	  if (theFile->link_path)
	    tmp_lnk     = sh_util_safe_name(theFile->link_path);
	  else
	    tmp_lnk     = sh_util_strdup("-");
	  if (p->linkpath)
	    tmp_lnk_old = sh_util_safe_name(p->linkpath);
	  else
	    tmp_lnk_old = sh_util_strdup("-");
#ifdef SH_USE_XML
	  sl_snprintf(tmp, SH_MSG_BUF, _("link_old=\"%s\" link_new=\"%s\" "),
		      tmp_lnk_old, tmp_lnk);
#else
	  sl_snprintf(tmp, SH_MSG_BUF, _("link_old=<%s>, link_new=<%s>, "),
		      tmp_lnk_old, tmp_lnk);
#endif
	  SH_FREE(tmp_lnk);
	  SH_FREE(tmp_lnk_old);
	  sl_strlcat(msg, tmp, SH_MSG_BUF); 

	  if (sh.flag.reportonce == S_TRUE && sh.flag.update == S_FALSE)
	    {
	      if (p->linkpath != NULL)
		SH_FREE(p->linkpath);
	      if (!(theFile->link_path))
		p->linkpath = sh_util_strdup("-");
	      else
		p->linkpath = sh_util_strdup(theFile->link_path);
	    }
	}

      if (MODI_AUDIT_ENABLED(theFile->check_flags))
	{
	  char result[256];
	  
	  sh_error_handle (SH_ERR_INFO, FIL__, __LINE__, 
			   0, MSG_E_SUBGPATH,
			   _("Fetching audit record"),
			   _("sh_hash"),  theFile->fullpath );

	  if (NULL != sh_audit_fetch (theFile->fullpath, theFile->mtime, theFile->ctime, result, sizeof(result)))
	    {
#ifdef SH_USE_XML
	      sl_strlcat(msg, _("obj=\""), SH_MSG_BUF);
#else
	      sl_strlcat(msg, _("obj=<"), SH_MSG_BUF);
#endif

	      sl_strlcat(msg, result, SH_MSG_BUF);

#ifdef SH_USE_XML
	      sl_strlcat(msg, _("\" "), SH_MSG_BUF);
#else
	      sl_strlcat(msg, _(">"), SH_MSG_BUF);
#endif
	    } 
	}

      /****************************************************
       *
       * REPORT on file change
       *
       ****************************************************/
      tmp_path = sh_util_safe_name(theFile->fullpath);
      if (!sh_global_check_silent)
	sh_error_handle(log_severity, FIL__, __LINE__, 
			(long) modi_mask, MSG_FI_CHAN,
			(policy_override == NULL) ? _(policy[class]):log_policy,
			change_code, tmp_path, msg);
      ++sh.statistics.files_report;

      SH_FREE(tmp_path);
      SH_FREE(tmp);
      SH_FREE(msg);

      if (S_TRUE  == sh.flag.update)
	{
	  if (S_FALSE == sh_util_ask_update(theFile->fullpath))
	    {
	      /* user does not want to update, thus we replace
	       * with data from the baseline database
	       */
	      sl_strlcpy(theFile->c_mode, p->theFile.c_mode, 11);
	      theFile->mode  =  p->theFile.mode;
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
	      sl_strlcpy(theFile->c_attributes, p->theFile.c_attributes, 16);
	      theFile->attributes =  p->theFile.attributes;
#endif
#if defined(USE_ACL) || defined(USE_XATTR)
	      if      (theFile->attr_string == NULL && p->attr_string != NULL)
		{ theFile->attr_string = sh_util_strdup (p->attr_string); }
	      else if (theFile->attr_string != NULL && p->attr_string == NULL)
		{ SH_FREE(theFile->attr_string); theFile->attr_string = NULL; }
	      else if (theFile->attr_string != NULL && p->attr_string != NULL)
		{ 
		  if (0 != strcmp(theFile->attr_string, p->attr_string))
		    {
		      SH_FREE(theFile->attr_string);
		      theFile->attr_string = sh_util_strdup (p->attr_string);
		    }
		}
#endif
	      
	      if (theFile->c_mode[0] == 'l') /* c_mode is already copied */
		{
		  if (theFile->link_path)
		    SH_FREE(theFile->link_path);
		  if (p->linkpath)
		    theFile->link_path = sh_util_strdup(p->linkpath);
		  else
		    theFile->link_path = sh_util_strdup("-");
		}
	      else
		{
		  if (theFile->link_path)
		    SH_FREE(theFile->link_path);
		  if (p->linkpath)
		    theFile->link_path = sh_util_strdup(p->linkpath);
		  else
		    theFile->link_path = NULL;
		}
	      
	      sl_strlcpy(fileHash, p->theFile.checksum, KEY_LEN+1);
	      
	      theFile->mtime =  p->theFile.mtime;
	      theFile->ctime =  p->theFile.ctime;
	      theFile->atime =  p->theFile.atime;
	      
	      theFile->size  =  p->theFile.size;
	      
	      sl_strlcpy(theFile->c_group, p->theFile.c_group, GROUP_MAX+2);
	      theFile->group =  p->theFile.group;
	      sl_strlcpy(theFile->c_owner, p->theFile.c_owner, USER_MAX+2);
	      theFile->owner =  p->theFile.owner;
	      
	      theFile->ino   =  p->theFile.ino;
	      theFile->rdev  =  p->theFile.rdev;
	      theFile->dev   =  p->theFile.dev;
	      theFile->hardlinks = p->theFile.hardlinks;
	      
	      SET_SH_FFLAG_VISITED(p->fflags);
	      CLEAR_SH_FFLAG_CHECKED(p->fflags);
	      retval = 1;
	      goto unlock_and_return;
	    }
	  else /* if (sh.flag.reportonce == S_TRUE) */
	    {
	      /* we replace the data in the in-memory copy of the
	       * baseline database, because otherwise we would get
	       * another warning if the suidcheck runs
	       */
	      sl_strlcpy(p->theFile.c_mode, theFile->c_mode, 11);
	      p->theFile.mode  =  theFile->mode;
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
	      sl_strlcpy(p->theFile.c_attributes, theFile->c_attributes, 16);
	      p->theFile.attributes = theFile->attributes;
#endif
#if defined(USE_ACL) || defined(USE_XATTR)
	      if      (p->attr_string == NULL && theFile->attr_string != NULL)
		{ p->attr_string = sh_util_strdup (theFile->attr_string); }
	      else if (p->attr_string != NULL && theFile->attr_string == NULL)
		{ SH_FREE(p->attr_string); p->attr_string = NULL; }
	      else if (theFile->attr_string != NULL && p->attr_string != NULL)
		{ 
		  if (0 != strcmp(theFile->attr_string, p->attr_string))
		    {
		      SH_FREE(p->attr_string);
		      p->attr_string = sh_util_strdup (theFile->attr_string);
		    }
		}
#endif
	      
	      if (theFile->c_mode[0] == 'l' || theFile->link_path)
		{
                  if (p->linkpath != NULL)
		    SH_FREE(p->linkpath);
		  p->linkpath = sh_util_strdup(theFile->link_path);
		}
	      else
		{
	          if (p->linkpath != NULL)
		    SH_FREE(p->linkpath);
		  p->linkpath = sh_util_strdup("-");
		}
	      
	      sl_strlcpy(p->theFile.checksum, fileHash, KEY_LEN+1);
	      
	      p->theFile.mtime = theFile->mtime;
	      p->theFile.ctime = theFile->ctime;
	      p->theFile.atime = theFile->atime;
	      
	      p->theFile.size  = theFile->size;
	      
	      sl_strlcpy(p->theFile.c_group, theFile->c_group, GROUP_MAX+2);
	      p->theFile.group =  theFile->group;
	      sl_strlcpy(p->theFile.c_owner, theFile->c_owner, USER_MAX+2);
	      p->theFile.owner =  theFile->owner;
	      
	      p->theFile.ino  = theFile->ino;
	      p->theFile.rdev = theFile->rdev;
	      p->theFile.dev  = theFile->dev;
	      p->theFile.hardlinks = theFile->hardlinks;
	    }
	}
    }

  SET_SH_FFLAG_VISITED(p->fflags);
  CLEAR_SH_FFLAG_CHECKED(p->fflags);

 unlock_and_return:
  ; /* 'label at end of compound statement */
  SH_MUTEX_UNLOCK(mutex_hash);
  SL_RETURN(retval, _("sh_hash_compdata"));
}

int hash_full_tree () 
{
  sh_file_t * p;
  int         i;

  SL_ENTER(_("hash_full_tree"));

  if (IsInit != 1) 
    SL_RETURN(0, _("hash_full_tree"));

  SH_MUTEX_LOCK_UNSAFE(mutex_hash);
  for (i = 0; i < TABSIZE; ++i)
    {
      for (p = tab[i]; p; p = p->next)
	CLEAR_SH_FFLAG_ALLIGNORE(p->fflags);
    }
  SH_MUTEX_UNLOCK_UNSAFE(mutex_hash);
  SL_RETURN (0, _("hash_full_tree"));
} 

#if !defined(SH_CUTEST)
static 
#endif
int hash_remove_tree_test(char * s, char * fullpath, size_t len_s)
{
  size_t       len_p;
  char      *  test;

  len_p = strlen(fullpath);
  
  if (len_p >= len_s)
    {
      if (0 == strncmp(s, fullpath, len_s)) 
	{ 
	  if (len_p > len_s)
	    {
	      /* continue if not inside directory;
	       * len_s > 1 because everything is inside '/' 
	       */
	      if ((len_s > 1) && (fullpath[len_s] != '/'))
		return S_FALSE;

	      test = sh_files_find_mostspecific_dir(fullpath);
	      
	      if (test && 0 != strcmp(test, s)) {
		/* There is a more specific directory, continue */
		return S_FALSE;
	      }
	      
	      if (NULL == sh_files_findfile(fullpath)) {
		/* SET_SH_FFLAG_ALLIGNORE(p->fflags); */
		return S_TRUE;
	      }
	    }
	  else /* len_p == len */
	    {
	      /* it is 's' itself, mark and continue 
	       * unless there is a policy for the inode itself
	       */
	      if (NULL == sh_files_findfile(fullpath)) {
		/* SET_SH_FFLAG_ALLIGNORE(p->fflags); */
		return S_TRUE;
	      }
	      else {
		return S_FALSE;
	      }
	    }

	} /* if path is in tree */
    } /* if path is possibly in tree */
  return S_FALSE;
}


int hash_remove_tree (char * s) 
{
  sh_file_t *  p;
  size_t       len_s;
  unsigned int i;

  SL_ENTER(_("hash_remove_tree"));

  if (!s || *s == '\0')
    SL_RETURN ((-1), _("hash_remove_tree"));

  len_s = sl_strlen(s);

  if (IsInit != 1) 
    sh_hash_init();

  SH_MUTEX_LOCK_UNSAFE(mutex_hash);
  for (i = 0; i < TABSIZE; ++i)
    {
      for (p = tab[i]; p; p = p->next)
	{
	  if (p->fullpath)
	    {
	      /* if (0 == strncmp(s, p->fullpath, len_s)) *//* old */
	      if (S_TRUE == hash_remove_tree_test(s, p->fullpath, len_s)) {
		SET_SH_FFLAG_ALLIGNORE(p->fflags);
		MODI_SET(p->theFile.checkflags, MODI_ALLIGNORE);
	      }
	    } /* if path is not null */

	}
    }
  SH_MUTEX_UNLOCK_UNSAFE(mutex_hash);
  SL_RETURN ((0), _("hash_remove_tree"));
} 

#if TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

static int ListFullDetail    = S_FALSE;
static int ListWithDelimiter = S_FALSE;
static char * ListFile       = NULL;

int set_list_file (const char * c)
{
  ListFile = sh_util_strdup(c);
  return 0;
}
char * get_list_file()
{
  return ListFile;
}

int set_full_detail (const char * c)
{
  (void) c;
  ListFullDetail = S_TRUE;
  return 0;
}
 
int set_list_delimited (const char * c)
{
  (void) c;
  ListFullDetail = S_TRUE;
  ListWithDelimiter = S_TRUE;
  return 0;
}

/* Always quote the string, except if it is empty. Quote quotes by
 * doubling them.
 */
char * csv_escape(const char * str)
{
  const  char * p = str;
  const  char * q;

  size_t size       = 0;
  size_t flag_quote = 0;

  char * new;
  char * pnew;

  if (p)
    {

      while (*p) 
	{
	  if (*p == '"')
	    ++flag_quote;
	  
	  ++size; ++p;
	}

      if (sl_ok_adds(size, flag_quote))
	size += flag_quote;      /* double each quote */
      else
	return NULL;

      if (sl_ok_adds(size, 3))
	size += 3; /* two quotes and terminating null */
      else
	return NULL;
      
      new = SH_ALLOC(size);
      
      if (flag_quote != 0)
	{
	  new[0] = '"';
	  pnew = &new[1];
	  q    = str;
	  while (*q)
	    {
	      *pnew = *q;
	      if (*pnew == '"')
		{
		  ++pnew; *pnew = '"';
		}
	      ++pnew; ++q;
	    }
	  *pnew = '"'; ++pnew;
	  *pnew = '\0';
	}
      else
	{
	  if (size > 3) 
	    {
	      new[0] = '"';
	      sl_strlcpy (&new[1], str, size-1);
	      new[size-2] = '"';
	      new[size-1] = '\0';
	    }
	  else
	    {
	      new[0] = '\0';
	    }
	}

      return new;
    }
  return NULL;
}

int isHexKey(char * s)
{
  int i;
  
  for (i = 0; i < KEY_LEN; ++i)
    {
      if (*s)
	{
	  if ((*s >= '0' && *s <= '9') ||
	      (*s >= 'A' && *s <= 'F') ||
	      (*s >= 'a' && *s <= 'f'))
	    {
	      ++s;
	      continue;
	    }
	}
      return S_FALSE;
    }
  return S_TRUE;
}
 
#include "sh_checksum.h"

static char * KEYBUFtolower (char * s, char * result)
{
  char * r = result;
  if (s)
    {
      for (; *s; ++s)
	{ 
	  *r = tolower((unsigned char) *s); ++r;
	}
      *r = '\0';
    }
  return result;
}

void sh_hash_list_db_entry_full_detail (sh_file_t * p)
{
  char * tmp;
  char * esc;
  char   str[81];
  char   hexdigest[SHA256_DIGEST_STRING_LENGTH];
  char   keybuffer[KEYBUF_SIZE];

  if (ListWithDelimiter == S_TRUE)
    {
      printf(_("%7ld, %7ld, %10s, %5d, %12s, %5d, %3d, %-8s, %5d, %-8s, %5d, "),
	     (unsigned long) p->theFile.ino, (unsigned long) p->theFile.dev,
	     p->theFile.c_mode, (int) p->theFile.mode,
	     p->theFile.c_attributes, (int) p->theFile.attributes,
	     (int) p->theFile.hardlinks,
	     p->theFile.c_owner, (int) p->theFile.owner, 
	     p->theFile.c_group, (int) p->theFile.group);
    }
  else
    {
      printf(_("%7ld %7ld %10s %5d %12s %5d %3d %-8s %5d %-8s %5d "),
	     (unsigned long) p->theFile.ino, (unsigned long) p->theFile.dev,
	     p->theFile.c_mode, (int) p->theFile.mode,
	     p->theFile.c_attributes, (int) p->theFile.attributes,
	     (int) p->theFile.hardlinks,
	     p->theFile.c_owner, (int) p->theFile.owner, 
	     p->theFile.c_group, (int) p->theFile.group);
    }

  if ('c' == p->theFile.c_mode[0] || 'b' == p->theFile.c_mode[0])
    sl_snprintf(str, sizeof(str), "%"PRIu64, p->theFile.rdev);
  else
    sl_snprintf(str, sizeof(str), "%"PRIu64, p->theFile.size);

  printf( _(" %8s"), str);
  if (ListWithDelimiter == S_TRUE)
    putchar(',');

  printf( _(" %s"), sh_unix_gmttime (p->theFile.ctime, str, sizeof(str)));
  if (ListWithDelimiter == S_TRUE)
    putchar(',');
  printf( _(" %s"), sh_unix_gmttime (p->theFile.mtime, str, sizeof(str)));
  if (ListWithDelimiter == S_TRUE)
    putchar(',');
  printf( _(" %s"), sh_unix_gmttime (p->theFile.atime, str, sizeof(str)));
  if (ListWithDelimiter == S_TRUE)
    putchar(',');

  if (isHexKey(p->theFile.checksum))
    printf( _(" %s"), KEYBUFtolower(p->theFile.checksum, keybuffer));
  else
    printf( _(" %s"), SHA256_Base2Hex(p->theFile.checksum, hexdigest));
  if (ListWithDelimiter == S_TRUE)
    putchar(',');

  tmp = sh_util_safe_name(p->fullpath);
  if (ListWithDelimiter != S_TRUE)
    {
      printf( _(" %s"), tmp);
    }
  else
    {
      esc = csv_escape(tmp);
      printf( _(" %s,"), (esc != NULL) ? esc : _("(null)"));
      if (esc)
	SH_FREE(esc);
    }
  SH_FREE(tmp);

  if ('l' == p->theFile.c_mode[0])
    {
      tmp = sh_util_safe_name(p->linkpath);
      if (ListWithDelimiter != S_TRUE)
	{
	  printf(_(" -> %s"), tmp);
	}
      else
	{
	  esc = csv_escape(tmp);
	  printf( _(" %s,"), (esc != NULL) ? esc : _("(null)"));
	  if (esc)
	    SH_FREE(esc);
	}
      SH_FREE(tmp);
    }

  if (p->attr_string)
    {
      tmp = sh_util_safe_name(p->attr_string);
      if (ListWithDelimiter != S_TRUE) 
	{
	  printf(_(" %s"), tmp);
	}
      else
	{
	  esc = csv_escape(tmp);
	  printf( _(" %s"), (esc != NULL) ? esc : _("(null)"));
	  if (esc)
	    SH_FREE(esc);
	}
      SH_FREE(tmp);
    }
  else
    {
      if (ListWithDelimiter == S_TRUE)
	printf("%s",_(" no_attr"));
    }
  putchar('\n');

  return;
}

void sh_hash_list_db_entry (sh_file_t * p)
{
  char nowtime[128];
  char thetime[128];
  char * tmp;
  time_t now  = time(NULL);
  time_t then = (time_t) p->theFile.mtime;
  struct tm   * time_ptr;

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GMTIME_R)
  struct tm     time_tm;
#endif

  if (ListFullDetail != S_FALSE)
    {
      sh_hash_list_db_entry_full_detail (p);
      return;
    }

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GMTIME_R)
  time_ptr = gmtime_r(&then, &time_tm);
  if (!time_ptr)
    return;
  strftime(thetime, 127, _("%b %d  %Y"), time_ptr);
  time_ptr = gmtime_r(&now,  &time_tm);
  if (!time_ptr)
    return;
  strftime(nowtime, 127, _("%b %d  %Y"), time_ptr);
  if (0 == strncmp(&nowtime[7], &thetime[7], 4))
    {
      time_ptr = gmtime_r(&then, &time_tm);
      if (!time_ptr)
	return;
      strftime(thetime, 127, _("%b %d %H:%M"), time_ptr);
    }
#else
  time_ptr = gmtime(&then);
  if (!time_ptr)
    return;
  strftime(thetime, 127, _("%b %d  %Y"), time_ptr);
  time_ptr = gmtime(&now);
  if (!time_ptr)
    return;
  strftime(nowtime, 127, _("%b %d  %Y"), time_ptr);
  if (0 == strncmp(&nowtime[7], &thetime[7], 4))
    {
      time_ptr = gmtime(&then);
      if (!time_ptr)
	return;
      strftime(thetime, 127, _("%b %d %H:%M"), time_ptr);
    }
#endif

  tmp = sh_util_safe_name(p->fullpath);
  if ('c' == p->theFile.c_mode[0] || 'b' == p->theFile.c_mode[0])
    printf(_("%10s %3d %-8s %-8s %3d,%4d %s %s"),
	   p->theFile.c_mode, (int) p->theFile.hardlinks,
	   p->theFile.c_owner, p->theFile.c_group, 
	   (int) major((dev_t)p->theFile.rdev), 
	   (int) minor((dev_t)p->theFile.rdev),
	   thetime, 
	   tmp);
  else
    printf(_("%10s %3d %-8s %-8s %8ld %s %s"),
	   p->theFile.c_mode, (int) p->theFile.hardlinks,
	   p->theFile.c_owner, p->theFile.c_group, (long) p->theFile.size,
	   thetime, 
	   tmp);
  SH_FREE(tmp);

  if ('l' == p->theFile.c_mode[0])
    {
      tmp = sh_util_safe_name(p->linkpath);
      printf(_(" -> %s\n"), tmp);
      SH_FREE(tmp);
    }
  else
    printf("\n");
	  
  return;
}

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif    

int sh_hash_printcontent(char * linkpath)
{
#ifdef HAVE_LIBZ
  unsigned char * decoded;
  unsigned char * decompressed = NULL;
  size_t dlen;
  unsigned long clen;
  unsigned long clen_o;
  int    res;

  if (linkpath && *linkpath != '-')
    {
      dlen = sh_util_base64_dec_alloc (&decoded, 
				       (unsigned char *)linkpath, 
				       strlen(linkpath));

      clen = dlen * 2 + 1;

      do {
	if (decompressed)
	  SH_FREE(decompressed);
	clen += dlen; clen_o = clen;
	decompressed = SH_ALLOC(clen);
	res = uncompress(decompressed, &clen, decoded, dlen);
	if (res == Z_MEM_ERROR)
	  { fprintf(stderr, "%s",_("Error: Not enough memory\n")); return -1; }
	if (res == Z_DATA_ERROR)
	  { fprintf(stderr, "%s",_("Error: Data corrupt or incomplete\n")); return -1; }
      } while (res == Z_BUF_ERROR || clen == clen_o);

      decompressed[clen] = '\0';
      fputs( (char*) decompressed, stdout);
      SH_FREE(decompressed);
      return 0;
    }
#else
  (void) linkpath;
#endif
  fprintf(stderr, "%s",_("Error: No data available\n")); 
  return -1;
}

/* if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE) */
#endif
