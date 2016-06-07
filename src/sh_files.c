/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999 Rainer Wichmann                                      */
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
#include <ctype.h>
#include <limits.h>

#include <errno.h>

/* Must be before <utime.h> on FreeBSD
 */
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#if !defined(O_NOATIME)
#if defined(__linux__) && (defined(__i386__) || defined(__x86_64__) || defined(__PPC__))
#define O_NOATIME 01000000
#endif
#endif

#include <utime.h>

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#define NAMLEN(dirent) sl_strlen((dirent)->d_name)
#else
#define dirent direct
#define NAMLEN(dirent) (dirent)->d_namlen
#ifdef HAVE_SYS_NDIR_H
#include <sys/ndir.h>
#endif
#ifdef HAVE_SYS_DIR_H
#include <sys/dir.h>
#endif
#ifdef HAVE_NDIR_H
#include <ndir.h>
#endif
#endif
#define NEED_ADD_DIRENT

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif
#ifdef HAVE_FNMATCH_H
#include <fnmatch.h>
#endif


#include "samhain.h"

#if (defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)) 

#include "sh_pthread.h"
#include "sh_error.h"
#include "sh_utils.h"
#include "sh_unix.h"
#include "sh_files.h"
#include "sh_tiger.h"
#include "sh_hash.h"
#include "sh_ignore.h"
#include "sh_inotify.h"
#include "zAVLTree.h"
#include "sh_dbIO.h"

#undef  FIL__
#define FIL__  _("sh_files.c")

extern sh_watches sh_file_watches;

static char * sh_files_C_dequote (char * s, size_t * length)
{
  size_t i, len = *length;
  int    flag = 0;
  char  *p, *q, *po, *pend;
  
  /* search for backslash
   */
  for (i = 0; i < len; ++i)
    {
      if (s[i] == '\\')
	{
	  flag = 1;
	  break;
	}
    }

  if (flag == 0 || *s == '\0')
    return s;

  po = SH_ALLOC(len+1); *po = '\0'; p = po; pend = &po[len];

  q = s;

  do
    {
      if (*q == '\\')
	{
	  ++q;

	  if (*q == '\0')
	    { *p = *q; flag = 0; break; }
	  else if (*q == 'a')
	    { *p = '\a'; ++p; ++q; }
	  else if (*q == 'b')
	    { *p = '\b'; ++p; ++q; }
	  else if (*q == 'f')
	    { *p = '\f'; ++p; ++q; }
	  else if (*q == 'n')
	    { *p = '\n'; ++p; ++q; }
	  else if (*q == 'r')
	    { *p = '\r'; ++p; ++q; }
	  else if (*q == 't')
	    { *p = '\t'; ++p; ++q; }
	  else if (*q == 'v')
	    { *p = '\v'; ++p; ++q; }
	  else if (*q == '\\')
	    { *p = '\\'; ++p; ++q; }
	  else if (*q == '\'')
	    { *p = '\''; ++p; ++q; }
	  else if (*q == '"')
	    { *p = '"';  ++p; ++q; }
	  else if (*q == 'x')
	    {
	      if (isxdigit((int) q[1]) && isxdigit((int) q[2]))
		{
		  /* hexadecimal value following */
		  unsigned char cc = (16 * sh_util_hexchar(q[1])) 
		    + sh_util_hexchar(q[2]);
		  *p = (char) cc;
		  ++p; q += 3;
		}
	      else
		{
		  *p = '\0'; flag = 0; break;
		}
	    }
	  else if (isdigit((int)*q))
	    {
	      if (isdigit((int) q[1]) && q[1] < '8' && 
		  isdigit((int) q[2]) && q[2] < '8')
		{
		  /* octal value following */
		  char tmp[4];  unsigned char cc;
		  tmp[0] = *q; ++q; tmp[1] = *q; ++q; tmp[2] = *q; ++q; 
		  tmp[3] = '\0';
		  cc = strtol(tmp, NULL, 8);
		  *p = (char) cc; ++p;
		}
	      else
		{
		  *p = '\0'; flag = 0; break;
		}
	    }
	  else
	    {
	      /* invalid escape sequence */
	      *p = '\0'; flag = 0; break;
	    }
	}
      else
	{
	  *p = *q; 
	  ++p; ++q;
	}
    } while (*q && p <= pend);

  SL_REQUIRE (p <= pend, _("p <= pend"));

  if (flag)
    {
      *p = '\0';
      *length = strlen(po);
    }
  else
    {
      SH_FREE(po);
      po = NULL;
      *length = 0;
    }

  SL_REQUIRE (*length <= len, _("*length <= len"));

  SH_FREE(s);
  return po;
}

char * sh_files_parse_input(const char * str_s, size_t * len)
{
  char  * p;

  if (!str_s || *str_s == '\0')
    return NULL;

  *len = sl_strlen(str_s);

  if ( (str_s[0] == '"'  && str_s[*len-1] == '"' ) ||
       (str_s[0] == '\'' && str_s[*len-1] == '\'') )
    {
      if (*len < 3)
	return NULL;
      --(*len);
      p = sh_util_strdup_l(&str_s[1], *len);
      p[*len-1] = '\0';
      --(*len);
    }
  else
    {
      p = sh_util_strdup_l(str_s, *len);
    }

  p = sh_files_C_dequote(p, len);

  return p;
}


extern int flag_err_debug;
extern int flag_err_info;

int sh_files_reportonce(const char * c)
{
  int i;
  SL_ENTER(_("sh_files_reportonce"));
  i = sh_util_flagval(c, &(sh.flag.reportonce));

  SL_RETURN(i, _("sh_files_reportonce"));
}
    
int sh_files_fulldetail(const char * c)
{
  int i;
  SL_ENTER(_("sh_files_fulldetail"));
  i = sh_util_flagval(c, &(sh.flag.fulldetail));

  SL_RETURN((i), _("sh_files_fulldetail"));
}
    

typedef struct dir_struct {
  long    NumRegular;
  long    NumDirs;
  long    NumSymlinks;
  long    NumFifos;
  long    NumSockets;
  long    NumCDev;
  long    NumBDev;
  long    NumDoor;
  long    NumPort;
  long    NumAll;
  long    TotalBytes;
  char    DirPath[PATH_MAX];
} dir_type;

typedef struct dirstack_entry {
  char                  * name;
  int                     class;
  unsigned long           check_flags;
  int                     rdepth;
  short                   checked;
  short                   childs_checked;
  short                   is_reported;
  /* struct dirstack_entry * next; */
} dirstack_t;


/* the destructor
 */
void free_dirstack (void * inptr)
{
  dirstack_t * here;

  SL_ENTER(_("free_dirstack"));
  if (inptr == NULL)
    SL_RET0(_("free_dirstack"));
  else
    here = (dirstack_t *) inptr;

  if (here->name != NULL)
    SH_FREE(here->name);
  SH_FREE(here);
  SL_RET0(_("free_dirstack"));
}

/* Function to return the key for indexing
 * the argument 
 */
zAVLKey zdirstack_key (void const * arg)
{
  const dirstack_t * sa = (const dirstack_t *) arg;
  return (zAVLKey) sa->name;
}

#define SH_LIST_FILE 0
#define SH_LIST_DIR1 1
#define SH_LIST_DIR2 2


static int which_dirList = SH_LIST_DIR1;

static zAVLTree * zdirListOne   = NULL;
static zAVLTree * zdirListTwo   = NULL;
static zAVLTree * zfileList     = NULL;

SH_MUTEX_STATIC(mutex_zfiles,      PTHREAD_MUTEX_INITIALIZER);
SH_MUTEX_STATIC(mutex_zglob,       PTHREAD_MUTEX_INITIALIZER);
SH_MUTEX_RECURSIVE(mutex_zdirs);

static int        sh_files_fullpath  (const char * testdir, 
				      const char * d_name, 
				      char * statpath);
static int        sh_files_pushdir   (int class, const char * str_s);
static int        sh_files_pushfile  (int class, const char * str_s);

static long MaxRecursionLevel = 0;

/* set default recursion level
 */
int sh_files_setrecursion (const char * flag_s)
{
  long flag = 0;
  static int reject = 0;

  SL_ENTER( _("sh_files_setrecursion"));

  if (reject == 1)
    SL_RETURN((-1), _("sh_files_setrecursion"));

  if (sh.flag.opts == S_TRUE)  
    reject = 1;

  if (flag_s != NULL) 
    flag = (int)(atof(flag_s));

  if (flag >= 0 && flag <= 99)
    MaxRecursionLevel = flag;
  else
    SL_RETURN((-1), _("sh_files_setrecursion"));

  SL_RETURN((0), _("sh_files_setrecursion"));
}

static int handle_filecheck_ret(dirstack_t * ptr, char * tmp_in, int status)
{
  int fcount = 0;
  char * tmp;

  if (!tmp_in)
    tmp = sh_util_safe_name (ptr->name);
  else
    tmp = tmp_in;

  if (status == SH_FILE_UNKNOWN && (!SH_FFLAG_REPORTED_SET(ptr->is_reported)))
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<file: %s> status=<%d>\n"), 
	    tmp, status));
      
      if ( sh.flag.checkSum == SH_CHECK_INIT  || 
	   sh_hash_have_it (ptr->name) >= 0)
	{
	  if (S_FALSE == sh_ignore_chk_del(ptr->name))
	    {
	      if (0 != hashreport_missing(ptr->name, 
					  (ptr->class == SH_LEVEL_ALLIGNORE) ? 
					  ShDFLevel[ptr->class] : 
					  ShDFLevel[SH_ERR_T_FILE])) {
		if (tmp == NULL) 
		  tmp = sh_util_safe_name (ptr->name);
		if (!sh_global_check_silent)
		  sh_error_handle ((ptr->class == SH_LEVEL_ALLIGNORE) ? 
				   ShDFLevel[ptr->class] : 
				   ShDFLevel[SH_ERR_T_FILE],
				   FIL__, __LINE__, 0, MSG_FI_MISS,
				   tmp);
		++sh.statistics.files_report;
	      }
	    }
	}
      else /* not there at init, and still missing */
	{
	  if (tmp == NULL) 
	    tmp = sh_util_safe_name (ptr->name);
	  sh_error_handle (SH_ERR_NOTICE,
			   FIL__, __LINE__, 0,
			   MSG_FI_FAIL,
			   tmp);
	}

      if (sh.flag.checkSum != SH_CHECK_INIT) 
	sh_hash_set_missing(ptr->name);

      if (sh.flag.reportonce == S_TRUE)
	SET_SH_FFLAG_REPORTED(ptr->is_reported);
    }
  else 
    {
      /* exists (status >= 0), but was missing (reported == TRUE)
       */
      if (status != SH_FILE_UNKNOWN && SH_FFLAG_REPORTED_SET(ptr->is_reported))
	{
	  CLEAR_SH_FFLAG_REPORTED(ptr->is_reported);
	  sh_hash_clear_flag(ptr->name, SH_FFLAG_ENOENT);
	}
      
      /* Catchall
       */
      else if (status == SH_FILE_UNKNOWN)
	{
	  /* Thu Mar  7 15:09:40 CET 2002 Make sure missing file
	   * is reported if ptr->reported == S_TRUE because the
	   * file has been added.
	   */
	  if (sh_hash_have_it (ptr->name) >= 0 && 
	      !SH_FFLAG_REPORTED_SET(ptr->is_reported))
	    {
	      if (S_FALSE == sh_ignore_chk_del(ptr->name))
		{
		  if (0 != hashreport_missing(ptr->name, 
					      (ptr->class == SH_LEVEL_ALLIGNORE) ? 
					      ShDFLevel[ptr->class] : 
					      ShDFLevel[SH_ERR_T_FILE])) {
		    if (tmp == NULL) 
		      tmp = sh_util_safe_name (ptr->name);
		    if (!sh_global_check_silent)
		      sh_error_handle ((ptr->class == SH_LEVEL_ALLIGNORE)? 
				       ShDFLevel[ptr->class] : 
				       ShDFLevel[SH_ERR_T_FILE],
				       FIL__, __LINE__, 0, MSG_FI_MISS,
				       tmp);
		    ++sh.statistics.files_report;
		  }
		}

	      /* delete from database
	       */
	      if (sh.flag.checkSum != SH_CHECK_INIT) 
		sh_hash_set_missing(ptr->name);
	    }
	  else
	    {
	      if (tmp == NULL) 
		tmp = sh_util_safe_name (ptr->name);
	      sh_error_handle (SH_ERR_INFO, FIL__, __LINE__, 0,
			       MSG_FI_FAIL,
			       tmp);
	      if (sh.flag.checkSum != SH_CHECK_INIT)
		sh_hash_set_visited_true(ptr->name);
	    }
	}
      
      ++fcount;
    }
  if (!tmp_in)
    SH_FREE(tmp);

  return fcount;
}


unsigned long sh_files_chk ()
{
  zAVLCursor    cursor;
  ShFileType    status;
  unsigned long fcount = 0;

  char       * tmp = NULL;

  dirstack_t * ptr;
  char       * dir;
  char       * file;
  int          tmp_reported;
  
  SL_ENTER(_("sh_files_chk"));

  for (ptr = (dirstack_t *) zAVLFirst(&cursor, zfileList); ptr;
       ptr = (dirstack_t *) zAVLNext(&cursor))
    {

      if (sig_urgent > 0) {
	SL_RETURN(fcount, _("sh_files_chk"));
      }

      if (ptr->checked == S_FALSE)
	{
	  dir  = sh_util_dirname (ptr->name);
	  file = sh_util_basename (ptr->name);
#if defined(WITH_TPT)
	  tmp = sh_util_safe_name (ptr->name);
#endif

	  
	  if (flag_err_info == S_TRUE)
	    {
	      char pstr[32];
#if !defined(WITH_TPT)
	      tmp = sh_util_safe_name (ptr->name);
#endif
	      sl_strlcpy(pstr, sh_hash_getpolicy(ptr->class), sizeof(pstr));
	      sh_error_handle ((-1),  FIL__, __LINE__, 0, 
			       MSG_FI_CHK, pstr, tmp);
	    }

	  if ((sh.flag.inotify & SH_INOTIFY_INSCAN) != 0)
	    {
	      sh_inotify_add_watch_later(ptr->name, &sh_file_watches, NULL,
					 ptr->class, ptr->check_flags, 
					 SH_INOTIFY_FILE, 0);
	    }

	  BREAKEXIT(sh_files_filecheck);
	  tmp_reported = ptr->is_reported; /* fix aliasing warning */ 
	  status = sh_files_filecheck (ptr->class, ptr->check_flags, dir, file, 
				       &tmp_reported, 0);
	  ptr->is_reported = tmp_reported;
	  
	  TPT(( 0, FIL__, __LINE__, 
		_("msg=<filecheck complete: %s> status=<%d> reported=<%d>\n"), 
		tmp, status, ptr->is_reported));

	  fcount += handle_filecheck_ret(ptr, tmp, status);
	  
	  if (tmp != NULL)
	    {
	      SH_FREE(tmp);
	      tmp = NULL;
	    }
	  if (file)
	    SH_FREE(file);
	  if (dir)
	    SH_FREE(dir);

	  ptr->checked = S_TRUE;
	}
    }

  SL_RETURN(fcount, _("sh_files_chk"));
}

static zAVLTree * fileTree = NULL;
static zAVLTree * dirTree  = NULL;

static void clear_lists()
{
  if (fileTree) {
    zAVL_string_reset(fileTree);
    fileTree  = NULL;
  }
  if (dirTree) {
    zAVL_string_reset(dirTree);
    dirTree  = NULL;
  }
  return;
}

static void add_to_filelist(zAVLTree * tree)
{
  dirstack_t * ptr;
  zAVLCursor   avlcursor;

  SL_ENTER(_("add_to_filelist"));

  SH_MUTEX_LOCK(mutex_zfiles);
  for (ptr = (dirstack_t *) zAVLFirst(&avlcursor, tree); ptr;
       ptr = (dirstack_t *) zAVLNext(&avlcursor))
    zAVL_string_set (&fileTree, ptr->name);
  SH_MUTEX_UNLOCK(mutex_zfiles);
  SL_RET0(_("add_to_filelist"));
}
static void add_to_dirlist(zAVLTree * tree)
{
  dirstack_t * ptr;
  zAVLCursor   avlcursor;

  SL_ENTER(_("add_to_dirlist"));

  SH_MUTEX_LOCK(mutex_zfiles);
  for (ptr = (dirstack_t *) zAVLFirst(&avlcursor, tree); ptr;
       ptr = (dirstack_t *) zAVLNext(&avlcursor))
    zAVL_string_set (&dirTree, ptr->name);
  SH_MUTEX_UNLOCK(mutex_zfiles);
  SL_RET0(_("add_to_dirlist"));
}
char * sh_files_findfile(const char * path)
{
  return zAVL_string_get (fileTree, path);
}

void * sh_dummy_621_candidate;

static char * intern_find_morespecific_dir(zAVLTree * tree, 
					   const char * path, size_t * len)
{
  dirstack_t * ptr;
  zAVLCursor   avlcursor;
  size_t       l_path = strlen(path);
  size_t       l_name;
  char *       candidate = NULL;
  size_t       l_candidate = 0;
  
  if (NULL == tree)
    return NULL;

  sh_dummy_621_candidate = (void *) &candidate;

  SH_MUTEX_LOCK(mutex_zfiles);
  for (ptr = (dirstack_t *) zAVLFirst(&avlcursor, tree); ptr;
       ptr = (dirstack_t *) zAVLNext(&avlcursor))
    {
      l_name = strlen(ptr->name);
      if (l_name <= l_path)
	{
	  if (0 == strncmp(ptr->name, path, l_name))
	    {
	      if ((l_name == l_path) || (path[l_name] == '/'))
		{
		  if (!candidate || (l_candidate < l_name))
		    {
		      candidate = ptr->name;
		      l_candidate = l_name;
		      *len = l_candidate;
		    }
		}
	    }
	}
    }
  SH_MUTEX_UNLOCK(mutex_zfiles);
  return candidate;
}
char * sh_files_find_mostspecific_dir(const char * path)
{
  size_t l_one = 0;
  size_t l_two = 0;
  char * one;
  char * two;

  one = intern_find_morespecific_dir(zdirListOne, path, &l_one);
  two = intern_find_morespecific_dir(zdirListTwo, path, &l_two);

  if      (l_one > l_two) return one;
  else                    return two;
}

int sh_files_delfilestack ()
{
  SL_ENTER(_("sh_files_delfilestack"));

  SH_MUTEX_LOCK(mutex_zfiles);
  zAVLFreeTree (zfileList, free_dirstack);
  zfileList = NULL;
  SH_MUTEX_UNLOCK(mutex_zfiles);

  SL_RETURN(0, _("sh_files_delfilestack"));
}
  
int sh_files_setrec_int (zAVLTree * tree)
{
  dirstack_t * ptr;
  zAVLCursor   avlcursor;

  SL_ENTER(_("sh_files_setrec"));
  if (tree != NULL) {
    for (ptr = (dirstack_t *) zAVLFirst(&avlcursor, tree); ptr;
	 ptr = (dirstack_t *) zAVLNext(&avlcursor))
      {
	if (ptr->rdepth < (-1) || ptr->rdepth > 99)
	  {
	    ptr->rdepth = MaxRecursionLevel;
	  }

	if ( (ptr->rdepth      == (-1)) && 
	     (ptr->class       == SH_LEVEL_ALLIGNORE) && 
	     (sh.flag.checkSum != SH_CHECK_INIT))
	  hash_remove_tree (ptr->name);
      }
  }
  SL_RETURN(0, _("sh_files_setrec"));
}

int sh_files_setrec ()
{
  volatile int ret;
  SH_MUTEX_RECURSIVE_INIT(mutex_zdirs);
  SH_MUTEX_RECURSIVE_LOCK(mutex_zdirs);
  clear_lists();
  add_to_dirlist(zdirListOne);
  add_to_dirlist(zdirListTwo);
  add_to_filelist(zfileList);
  sh_files_setrec_int(zdirListOne);
  ret = sh_files_setrec_int(zdirListTwo);
  SH_MUTEX_RECURSIVE_UNLOCK(mutex_zdirs);

  return ret;
}

zAVLTree * sh_files_deldirstack_int (zAVLTree * ptr)
{
  SL_ENTER(_("sh_files_deldirstack"));

  zAVLFreeTree (ptr, free_dirstack);

  SL_RETURN(NULL, _("sh_files_deldirstack"));
}

int sh_files_deldirstack ()
{
  SH_MUTEX_RECURSIVE_INIT(mutex_zdirs);
  SH_MUTEX_RECURSIVE_LOCK(mutex_zdirs);
  zdirListOne = sh_files_deldirstack_int(zdirListOne);
  zdirListTwo = sh_files_deldirstack_int(zdirListTwo);
  SH_MUTEX_RECURSIVE_UNLOCK(mutex_zdirs);
  return 0;
}

void sh_files_reset()
{
  dirstack_t * ptr;
  zAVLCursor   avlcursor;

  SL_ENTER(_("sh_files_reset"));

  SH_MUTEX_LOCK(mutex_zfiles);
  for (ptr = (dirstack_t *) zAVLFirst(&avlcursor, zfileList); ptr;
       ptr = (dirstack_t *) zAVLNext(&avlcursor))
    ptr->checked = 0;
  SH_MUTEX_UNLOCK(mutex_zfiles);
  SL_RET0(_("sh_files_reset"));
}

void sh_dirs_reset()
{
  dirstack_t * ptr;
  zAVLCursor   avlcursor1;
  zAVLCursor   avlcursor2;

  SL_ENTER(_("sh_dirs_reset"));

  SH_MUTEX_RECURSIVE_INIT(mutex_zdirs);
  SH_MUTEX_RECURSIVE_LOCK(mutex_zdirs);
  for (ptr = (dirstack_t *) zAVLFirst(&avlcursor1, zdirListOne); ptr;
       ptr = (dirstack_t *) zAVLNext(&avlcursor1))
    ptr->checked = 0;

  for (ptr = (dirstack_t *) zAVLFirst(&avlcursor2, zdirListTwo); ptr;
       ptr = (dirstack_t *) zAVLNext(&avlcursor2))
    ptr->checked = 0;
  SH_MUTEX_RECURSIVE_UNLOCK(mutex_zdirs);

  SL_RET0(_("sh_dirs_reset"));
}


int sh_files_pushfile_prelink (const char * str_s)
{
  return (sh_files_pushfile (SH_LEVEL_PRELINK, str_s));
}

int sh_files_pushfile_user0 (const char * str_s)
{
  return (sh_files_pushfile (SH_LEVEL_USER0, str_s));
}

int sh_files_pushfile_user1 (const char * str_s)
{
  return (sh_files_pushfile (SH_LEVEL_USER1, str_s));
}

int sh_files_pushfile_user2 (const char * str_s)
{
  return (sh_files_pushfile (SH_LEVEL_USER2, str_s));
}

int sh_files_pushfile_user3 (const char * str_s)
{
  return (sh_files_pushfile (SH_LEVEL_USER3, str_s));
}

int sh_files_pushfile_user4 (const char * str_s)
{
  return (sh_files_pushfile (SH_LEVEL_USER4, str_s));
}


int sh_files_pushfile_ro (const char * str_s)
{
  return (sh_files_pushfile (SH_LEVEL_READONLY, str_s));
}

int sh_files_pushfile_attr (const char * str_s)
{
  return (sh_files_pushfile (SH_LEVEL_ATTRIBUTES, str_s));
}

int sh_files_pushfile_log (const char * str_s)
{
  return (sh_files_pushfile (SH_LEVEL_LOGFILES, str_s));
}

int sh_files_pushfile_glog (const char * str_s)
{
  return (sh_files_pushfile (SH_LEVEL_LOGGROW, str_s));
}

int sh_files_pushfile_noig (const char * str_s)
{
  return (sh_files_pushfile (SH_LEVEL_NOIGNORE, str_s));
}

int sh_files_pushfile_allig (const char * str_s)
{
  return (sh_files_pushfile (SH_LEVEL_ALLIGNORE, str_s));
}


static void sh_files_set_mask (unsigned long * mask, 
			       unsigned long val, int act)
{
  SL_ENTER(_("sh_files_set_mask"));

  if       (act == 0)
    (*mask)  = val;
  else if  (act > 0)
    (*mask) |= val;
  else 
    (*mask) &= ~val;

  SL_RET0(_("sh_files_set_mask"));
}

/* set mask(class)
 */
static int sh_files_parse_mask (unsigned long * mask, const char * str)
{
  int l, i = 0, act = 0, k = 0;
  char  myword[64];
  
  SL_ENTER(_("sh_files_parse_mask"));

  myword[0] = '\0';

  if (str == NULL)
    {
      SL_RETURN ( (-1), _("sh_files_parse_mask"));
    }
  else
    l = sl_strlen(str);

  while (i < l) {

    if (str[i] == '\0')
      break;

    if (str[i] == ' ' || str[i] == '\t' || str[i] == ',')
      {
	++i;
	continue;
      }

    if (str[i] == '+')
      {
	act = +1; ++i;
	myword[0] = '\0';
	goto getword;
      }
    else if (str[i] == '-')
      {
	act = -1; ++i;
	myword[0] = '\0';
	goto getword;
      }
    else /* a word */
      {
      getword:
	k = 0;
	while (k < 63 && str[i] != ' ' && str[i] != '\t' && str[i] != ','
	       && str[i] != '+' && str[i] != '-' && str[i] != '\0') {
	  myword[k] = str[i]; 
	  ++i; ++k;
	}
	myword[k] = '\0';

	if (sl_strlen(myword) == 0)
	  {
	    SL_RETURN ( (-1), _("sh_files_parse_mask"));
	  }

/* checksum     */
	if      (0 == strcmp(myword, _("CHK")))
	  sh_files_set_mask (mask, MODI_CHK, act);
/* link         */
	else if (0 == strcmp(myword, _("LNK")))
	  sh_files_set_mask (mask, MODI_LNK, act);
/* inode        */
	else if (0 == strcmp(myword, _("RDEV")))
	  sh_files_set_mask (mask, MODI_RDEV, act);
/* inode        */
	else if (0 == strcmp(myword, _("INO")))
	  sh_files_set_mask (mask, MODI_INO, act);
/* user         */
	else if (0 == strcmp(myword, _("USR")))
	  sh_files_set_mask (mask, MODI_USR, act);
/* group        */
	else if (0 == strcmp(myword, _("GRP")))
	  sh_files_set_mask (mask, MODI_GRP, act);
/* mtime        */
	else if (0 == strcmp(myword, _("MTM")))
	  sh_files_set_mask (mask, MODI_MTM, act);
/* ctime        */
	else if (0 == strcmp(myword, _("CTM")))
	  sh_files_set_mask (mask, MODI_CTM, act);
/* atime        */
	else if (0 == strcmp(myword, _("ATM")))
	  sh_files_set_mask (mask, MODI_ATM, act);
/* size         */
	else if (0 == strcmp(myword, _("SIZ")))
	  sh_files_set_mask (mask, MODI_SIZ, act);
/* file mode    */
	else if (0 == strcmp(myword, _("MOD")))
	  sh_files_set_mask (mask, MODI_MOD, act);
/* hardlinks    */
	else if (0 == strcmp(myword, _("HLN")))
	  sh_files_set_mask (mask, MODI_HLN, act);
/* size may grow */
	else if (0 == strcmp(myword, _("SGROW")))
	  sh_files_set_mask (mask, MODI_SGROW, act);
/* use prelink */
	else if (0 == strcmp(myword, _("PRE")))
	  sh_files_set_mask (mask, MODI_PREL, act);
/* get content */
	else if (0 == strcmp(myword, _("TXT")))
	  sh_files_set_mask (mask, MODI_TXT, act);
/* get audit report */
	else if (0 == strcmp(myword, _("AUDIT")))
	  sh_files_set_mask (mask, MODI_AUDIT, act);
	else
	  {
	    SL_RETURN ( (-1), _("sh_files_parse_mask"));
	  }
	act       = 0;
	myword[0] = '\0';
      }
  }
  SL_RETURN ( (0), _("sh_files_parse_mask"));
}

int sh_files_redef_prelink(const char * str)
{
  return (sh_files_parse_mask(&mask_PRELINK, str));
} 
int sh_files_redef_user0(const char * str)
{
  return (sh_files_parse_mask(&mask_USER0, str));
} 
int sh_files_redef_user1(const char * str)
{
  return (sh_files_parse_mask(&mask_USER1, str));
} 
int sh_files_redef_user2(const char * str)
{
  return (sh_files_parse_mask(&mask_USER2, str));
} 
int sh_files_redef_user3(const char * str)
{
  return (sh_files_parse_mask(&mask_USER3, str));
} 
int sh_files_redef_user4(const char * str)
{
  return (sh_files_parse_mask(&mask_USER4, str));
} 
int sh_files_redef_readonly(const char * str)
{
  return (sh_files_parse_mask(&mask_READONLY, str));
} 
int sh_files_redef_loggrow(const char * str)
{
  return (sh_files_parse_mask(&mask_LOGGROW, str));
} 
int sh_files_redef_logfiles(const char * str)
{
  return (sh_files_parse_mask(&mask_LOGFILES, str));
} 
int sh_files_redef_attributes(const char * str)
{
  return (sh_files_parse_mask(&mask_ATTRIBUTES, str));
} 
int sh_files_redef_noignore(const char * str)
{
  return (sh_files_parse_mask(&mask_NOIGNORE, str));
} 
int sh_files_redef_allignore(const char * str)
{
  return (sh_files_parse_mask(&mask_ALLIGNORE, str));
} 

unsigned long sh_files_maskof (int class)
{
  switch (class)
    {
    case SH_LEVEL_READONLY:
      return (unsigned long) (mask_READONLY | MODI_INIT);
    case SH_LEVEL_ATTRIBUTES:
      return (unsigned long) (mask_ATTRIBUTES | MODI_INIT);
    case SH_LEVEL_LOGFILES:
      return (unsigned long) (mask_LOGFILES | MODI_INIT);
    case SH_LEVEL_LOGGROW:
      return (unsigned long) (mask_LOGGROW | MODI_INIT);
    case SH_LEVEL_ALLIGNORE:
      return (unsigned long) (mask_ALLIGNORE | MODI_INIT);
    case SH_LEVEL_NOIGNORE:
      return (unsigned long) (mask_NOIGNORE | MODI_INIT);
    case SH_LEVEL_USER0:
      return (unsigned long) (mask_USER0 | MODI_INIT);
    case SH_LEVEL_USER1:
      return (unsigned long) (mask_USER1 | MODI_INIT);
    case SH_LEVEL_USER2:
      return (unsigned long) (mask_USER2 | MODI_INIT);
    case SH_LEVEL_USER3:
      return (unsigned long) (mask_USER3 | MODI_INIT);
    case SH_LEVEL_USER4:
      return (unsigned long) (mask_USER4 | MODI_INIT);
    case SH_LEVEL_PRELINK:
      return (unsigned long) (mask_PRELINK | MODI_INIT);
    default:
      return (unsigned long) 0;
    }
}

#ifdef HAVE_GLOB_H
int sh_files_has_metachar (const char * str)
{
  SL_ENTER(_("sh_files_has_metachar"));
  if      (NULL != strchr(str, '*'))
    SL_RETURN(1, _("sh_files_has_metachar"));
  else if (NULL != strchr(str, '?'))
    SL_RETURN(1, _("sh_files_has_metachar"));
  else if (NULL != (strchr(str, '[')))
    SL_RETURN(1, _("sh_files_has_metachar"));
  else
    SL_RETURN(0, _("sh_files_has_metachar"));
}


int sh_files_globerr (const char * epath, int errnum)
{
  char * p;
  char errbuf[SH_ERRBUF_SIZE];

  SL_ENTER(_("sh_files_globerr"));

  if (errnum == ENOTDIR || errnum == ENOENT)
    {
      SL_RETURN(0, _("sh_files_globerr"));
    }

  p = sh_util_safe_name (epath);
  sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, errnum, MSG_FI_GLOB,
		   sh_error_message (errnum, errbuf, sizeof(errbuf)), p);
  SH_FREE(p);

  SL_RETURN(0, _("sh_files_globerr"));
}

/* #ifdef HAVE_GLOB_H 
 */
#endif

int sh_files_push_file_int (int class, const char * str_s, size_t len, 
			    unsigned long check_flags)
{
  dirstack_t * new_item_ptr;
  char  * fileName;
  int     ret;
  volatile int     count = 0;

  SL_ENTER(_("sh_files_push_file_int"));

  fileName = SH_ALLOC(len+1);
  sl_strlcpy(fileName, str_s, len+1);

  new_item_ptr = (dirstack_t *) SH_ALLOC (sizeof(dirstack_t));

  new_item_ptr->name           = fileName;
  new_item_ptr->class          = class;
  new_item_ptr->check_flags     = check_flags;
  new_item_ptr->rdepth         = 0;
  new_item_ptr->checked        = S_FALSE;
  new_item_ptr->is_reported    = 0;
  new_item_ptr->childs_checked = S_FALSE;

  SH_MUTEX_LOCK(mutex_zfiles);
  if (zfileList == NULL)
    {
      zfileList = zAVLAllocTree (zdirstack_key, zAVL_KEY_STRING);
      if (zfileList == NULL) 
	{
	  (void) safe_logger (0, 0, NULL);
	  aud__exit(FIL__, __LINE__, EXIT_FAILURE);
	}
    }

  ret = zAVLInsert (zfileList, new_item_ptr);
  SH_MUTEX_UNLOCK(mutex_zfiles);

  if (-1 == ret)
    {
      (void) safe_logger (0, 0, NULL);
      aud__exit(FIL__, __LINE__, EXIT_FAILURE);
    }
  else if (3 == ret)
    { 
      if (sh.flag.started != S_TRUE)
	sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_FI_DOUBLE,
			 fileName);
      SH_FREE(fileName);
      SH_FREE(new_item_ptr);
      new_item_ptr = NULL;
    }
  else
    {
      int           reported;
      unsigned long check_flags = sh_files_maskof(class);

      if ((sh.flag.inotify & SH_INOTIFY_INSCAN) != 0)
	{
	  sh_files_filecheck (class, check_flags, str_s, NULL,
			      &reported, 0);
	  if (SH_FFLAG_REPORTED_SET(reported))
	    sh_files_set_file_reported(str_s);
	  sh_inotify_add_watch_later(str_s, &sh_file_watches, NULL,
				     class, check_flags, 
				     SH_INOTIFY_FILE, 0);
	}

      if (MODI_AUDIT_ENABLED(check_flags))
	{
	  sh_error_handle(SH_ERR_INFO, FIL__, __LINE__, 0, MSG_E_SUBGPATH,
			  _("Setting audit watch"),
			  _("sh_files_push_file_int"), str_s);
	  sh_audit_mark(str_s);
	}
      ++count;
    }
  SL_RETURN(count, _("sh_files_push_file_int"));
}

int sh_files_push_dir_int (int class, char * tail, size_t len, int rdepth, unsigned long check_flags);

#ifdef HAVE_GLOB_H

typedef struct globstack_entry {
  char                  * name;
  char                  * type_name;
  int                     class;
  unsigned long           check_flags;
  int                     rdepth;
  short                   type;
  /* struct dirstack_entry * next; */
} sh_globstack_t;

static zAVLTree * zglobList   = NULL;

zAVLKey zglobstack_key (void const * arg)
{
  const sh_globstack_t * sa = (const sh_globstack_t *) arg;
  return (zAVLKey) sa->type_name;
}


static int sh_files_pushglob (int class, int type, const char * p, int rdepth,
			       unsigned long check_flags_in, int flag)
{
  int     globstatus = -1;
  unsigned int     gloop;
  glob_t  pglob;

  volatile int     count = 0;
  volatile unsigned long check_flags = (flag == 0) ? sh_files_maskof(class) : check_flags_in;
  
  SL_ENTER(_("sh_files_pushglob"));

  pglob.gl_offs = 0;
  globstatus    = glob (p, 0, sh_files_globerr, &pglob);
  
  if (sh.flag.checkSum != SH_CHECK_INIT)
    {
      sh_globstack_t * new_item_ptr;
      char  * fileName;
      char  * typeName;
      int     ret;
      
      SH_MUTEX_TRYLOCK(mutex_zfiles);
      fileName = sh_util_strdup (p);
      typeName = sh_util_strconcat ((type == SH_LIST_FILE) ? "F" : "D", p, NULL);
      
      new_item_ptr = (sh_globstack_t *) SH_ALLOC (sizeof(sh_globstack_t));
      
      new_item_ptr->name           = fileName;
      new_item_ptr->type_name      = typeName;
      new_item_ptr->class          = class;
      new_item_ptr->check_flags    = check_flags;
      new_item_ptr->rdepth         = rdepth;
      new_item_ptr->type           = type;
      
      if (zglobList == NULL)
	{
	  zglobList = zAVLAllocTree (zglobstack_key, zAVL_KEY_STRING);
	  if (zglobList == NULL) 
	    {
	      (void) safe_logger (0, 0, NULL);
	      aud__exit(FIL__, __LINE__, EXIT_FAILURE);
	    }
	}
      
      ret = zAVLInsert (zglobList, new_item_ptr);
      
      if (ret != 0) /* already in list */
	{
	  SH_FREE(fileName);
	  SH_FREE(typeName);
	  SH_FREE(new_item_ptr);
	}
      SH_MUTEX_TRYLOCK_UNLOCK(mutex_zfiles);
    }


  if (globstatus == 0 && pglob.gl_pathc > 0)
    {
      for (gloop = 0; gloop < (unsigned int) pglob.gl_pathc; ++gloop)
	{
	  if (type == SH_LIST_FILE)
	    {
	      count += sh_files_push_file_int (class, pglob.gl_pathv[gloop], 
					       sl_strlen(pglob.gl_pathv[gloop]), check_flags);
	    }
	  else
	    {
	      which_dirList = type;

	      count += sh_files_push_dir_int  (class, pglob.gl_pathv[gloop], 
					       sl_strlen(pglob.gl_pathv[gloop]), rdepth, check_flags);
	    }
	}
    }
  else
    {
      char * tmp = sh_util_safe_name (p);
      
      if (pglob.gl_pathc == 0
#ifdef GLOB_NOMATCH
	  || globstatus == GLOB_NOMATCH
#endif
	  )
	sh_error_handle ((sh.flag.started != S_TRUE) ? SH_ERR_ERR : SH_ERR_NOTICE, 
			 FIL__, __LINE__, 
			 globstatus, MSG_FI_GLOB,
			 _("No matches found"), tmp);
#ifdef GLOB_NOSPACE
      else if (globstatus == GLOB_NOSPACE)
	sh_error_handle (SH_ERR_ERR, FIL__, __LINE__,
			 globstatus, MSG_FI_GLOB,
			 _("Out of memory"), tmp);
#endif
#ifdef GLOB_ABORTED
      else if (globstatus == GLOB_ABORTED)
	sh_error_handle (SH_ERR_ERR, FIL__, __LINE__,
			 globstatus, MSG_FI_GLOB,
			 _("Read error"), tmp);
#endif
      else 
	sh_error_handle (SH_ERR_ERR, FIL__, __LINE__,
			 globstatus, MSG_FI_GLOB,
			 _("Unknown error"), tmp);
      
      SH_FREE(tmp);
      
    }
  
  globfree(&pglob);
  SL_RETURN(count, _("sh_files_pushglob"));
  return count;
}

void sh_files_check_globFilePatterns()
{
  sh_globstack_t * testPattern;
  zAVLCursor   cursor;

  SL_ENTER(_("sh_files_check_globPatterns"));

  SH_MUTEX_LOCK(mutex_zglob);
  for (testPattern = (sh_globstack_t *) zAVLFirst (&cursor, zglobList); 
       testPattern;
       testPattern = (sh_globstack_t *) zAVLNext  (&cursor))
    {
      if (testPattern->type == SH_LIST_FILE)
	{
	  sh_files_pushglob(testPattern->class, testPattern->type, 
			    testPattern->name, testPattern->rdepth,
			    testPattern->check_flags, 1);
	}
    }
  SH_MUTEX_UNLOCK(mutex_zglob);
  SL_RET0(_("sh_files_check_globPatterns"));
}

void sh_files_check_globPatterns()
{
  sh_globstack_t * testPattern;
  zAVLCursor   cursor;

  SL_ENTER(_("sh_files_check_globPatterns"));

  SH_MUTEX_LOCK(mutex_zglob);
  for (testPattern = (sh_globstack_t *) zAVLFirst (&cursor, zglobList); 
       testPattern;
       testPattern = (sh_globstack_t *) zAVLNext  (&cursor))
    {
      sh_files_pushglob(testPattern->class, testPattern->type, 
			testPattern->name, testPattern->rdepth,
			testPattern->check_flags, 1);
    }
  SH_MUTEX_UNLOCK(mutex_zglob);
  SL_RET0(_("sh_files_check_globPatterns"));
}

/* the destructor
 */
void free_globstack (void * inptr)
{
  sh_globstack_t * here;

  SL_ENTER(_("free_globstack"));
  if (inptr == NULL)
    SL_RET0(_("free_globstack"));
  else
    here = (sh_globstack_t *) inptr;

  if (here->name != NULL)
    SH_FREE(here->name);
  if (here->type_name != NULL)
    SH_FREE(here->type_name);
  SH_FREE(here);
  SL_RET0(_("free_globstack"));
}

int sh_files_delglobstack ()
{
  SL_ENTER(_("sh_files_delglobstack"));

  SH_MUTEX_LOCK(mutex_zglob);
  zAVLFreeTree (zglobList, free_globstack);
  zglobList = NULL;
  SH_MUTEX_UNLOCK(mutex_zglob);

  SL_RETURN(0, _("sh_files_delglobstack"));
}
  

#else
void sh_files_check_globPatterns()
{
  return;
}
int sh_files_delglobstack ()
{
  return 0;
}
#endif

static int sh_files_pushfile (int class, const char * str_s)
{
  size_t  len;
  char  * tmp;
  char  * p;

  static int reject = 0;

  SL_ENTER(_("sh_files_pushfile"));

  if (reject == 1)
    SL_RETURN((-1),_("sh_files_pushfile"));

  /* if we push a filename from the command line, make sure it
   * is the only one -- and will stay the only one
   */
  if (sh.flag.opts == S_TRUE) 
    {
      sh_files_delfilestack ();
      sh_files_deldirstack ();
      sh_files_delglobstack ();
      reject = 1;
    }

  p = sh_files_parse_input(str_s, &len);
  if (!p || len == 0)
    SL_RETURN((-1), _("sh_files_pushfile"));

  if (len >= PATH_MAX) 
    {
      /* Name too long
       */
      tmp = sh_util_safe_name (p);
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_FI_2LONG,
		       tmp);
      SH_FREE(tmp);
      SL_RETURN((-1),_("sh_files_pushfile"));
    } 
  else if (p[0] != '/') 
    {
      /* Not an absolute path
       */
      tmp = sh_util_safe_name (p);
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_FI_NOPATH,
		       tmp);
      SH_FREE(tmp);
      SL_RETURN((-1),_("sh_files_pushfile"));
    } 
  else 
    {
      /* remove a terminating '/', take care of the 
       * special case of the root directory.
       */
      if (p[len-1] == '/' && len > 1)
	{
	  p[len-1] = '\0';
	  --len;
	}
    } 

#ifdef HAVE_GLOB_H
  if (0 == sh_files_has_metachar(p))
    {
      sh_files_push_file_int (class, p, len, sh_files_maskof(class));
    }
  else
    {
      sh_files_pushglob (class, SH_LIST_FILE, p, 0, 0, 0);
    }

#else
  sh_files_push_file_int (class, p, len, sh_files_maskof(class));
#endif

  SH_FREE(p);
  SL_RETURN((0),_("sh_files_pushfile"));
}


/* ------ directories ----- */

int sh_files_is_allignore_int (char * str, zAVLTree * tree)
{
  dirstack_t * ptr;

  SL_ENTER(_("sh_files_is_allignore"));

  if (tree)
    {
      ptr = zAVLSearch(tree, str);
      if (ptr)
	{
	  if (ptr->class == SH_LEVEL_ALLIGNORE)
	    SL_RETURN( 1, _("sh_files_is_allignore"));
	  else
	    SL_RETURN( 0, _("sh_files_is_allignore"));
	}
    }
  SL_RETURN( 0, _("sh_files_is_allignore"));
}

int sh_files_is_allignore (char * str)
{
  int retval = 0;

  SH_MUTEX_RECURSIVE_INIT(mutex_zdirs);
  SH_MUTEX_RECURSIVE_LOCK(mutex_zdirs);
  retval = sh_files_is_allignore_int(str, zdirListOne);

  if (NULL != zdirListTwo && retval == 0)
    {
      retval = sh_files_is_allignore_int(str, zdirListTwo);
    }
  SH_MUTEX_RECURSIVE_UNLOCK(mutex_zdirs);
  return retval;
}

void * sh_dummy_1493_ptr;

unsigned long sh_dirs_chk (int which)
{
  zAVLTree   * tree;
  zAVLCursor   cursor;
  dirstack_t * ptr;
  dirstack_t * dst_ptr;
  int          status;
  int          tmp_reported;
  volatile int          filetype = SH_FILE_UNKNOWN;
  volatile unsigned long dcount = 0;
  char       * tmp;
  
  SL_ENTER(_("sh_dirs_chk"));

  sh_dummy_1493_ptr = (void *) &ptr;
  
  SH_MUTEX_RECURSIVE_INIT(mutex_zdirs);
  SH_MUTEX_RECURSIVE_LOCK(mutex_zdirs);
  if (which == 1)
    tree = zdirListOne;
  else
    tree = zdirListTwo;

  for (ptr = (dirstack_t *) zAVLFirst(&cursor, tree); ptr;
       ptr = (dirstack_t *) zAVLNext(&cursor))
    {
      if (sig_urgent > 0) {
	goto out;
      }

      if (ptr->checked == S_FALSE)
	{
	  SH_MUTEX_LOCK(mutex_zfiles);
	  /* 28 Aug 2001 check the top level directory
	   */
	  status        = S_FALSE;
	  dst_ptr       = zAVLSearch(zfileList, ptr->name);
	  if (dst_ptr) 
	    {
	      if (dst_ptr->checked == S_FALSE)
		{
		  BREAKEXIT(sh_files_filecheck);
		  tmp_reported = dst_ptr->is_reported;
		  filetype = sh_files_filecheck (dst_ptr->class, dst_ptr->check_flags, 
						 ptr->name,  
						 NULL,  &tmp_reported, 0);
		  dst_ptr->is_reported = tmp_reported;
		  (void) handle_filecheck_ret(dst_ptr, NULL, filetype);

		  dst_ptr->checked = S_TRUE;
		  status           = S_TRUE;
		}
	      else
		{
		  status           = S_TRUE;
		}
	    }
	  SH_MUTEX_UNLOCK(mutex_zfiles);

	  if (status == S_FALSE)
	    {
	      tmp_reported = ptr->is_reported;
	      filetype = sh_files_filecheck (ptr->class,  ptr->check_flags, 
					     ptr->name,  NULL,  &tmp_reported, 0);
	      ptr->is_reported = tmp_reported;
	      (void) handle_filecheck_ret(ptr, NULL, filetype);
	    }

	  BREAKEXIT(sh_files_checkdir);
	  status = sh_files_checkdir (ptr->class, ptr->check_flags, 
				      ptr->rdepth, ptr->name, 
				      ptr->name);

	  if (status < 0 && (!SH_FFLAG_REPORTED_SET(ptr->is_reported))) 
	    {
	      /* directory is missing
	       */
	      if (S_FALSE == sh_ignore_chk_del(ptr->name))
		{
		  if (0 != hashreport_missing(ptr->name, 
					      (ptr->class == SH_LEVEL_ALLIGNORE) ? 
					      ShDFLevel[ptr->class] : 
					      ShDFLevel[SH_ERR_T_DIR])) {
		    tmp = sh_util_safe_name (ptr->name);
		    if (!sh_global_check_silent)
		      sh_error_handle ((ptr->class == SH_LEVEL_ALLIGNORE) ? 
				       ShDFLevel[ptr->class] : 
				       ShDFLevel[SH_ERR_T_DIR], FIL__, __LINE__,
				       0, MSG_FI_MISS, tmp);
		    ++sh.statistics.files_report;
		    SH_FREE(tmp);
		  }
		}
	      if (sh.flag.reportonce == S_TRUE)
		SET_SH_FFLAG_REPORTED(ptr->is_reported);
	    } 
	  else 
	    {
	      /* exists (status >= 0), but was missing (reported == TRUE)
	       */
	      if (status >= 0 && SH_FFLAG_REPORTED_SET(ptr->is_reported))
		{
		  CLEAR_SH_FFLAG_REPORTED(ptr->is_reported);
		  sh_hash_clear_flag(ptr->name, SH_FFLAG_ENOENT);
#if 0
		  /* obsoleted (really?) by the mandatory sh_files_filecheck()
		   * above, which will catch missing directories anyway
		   */
		  tmp = sh_util_safe_name (ptr->name);
		  if (!sh_global_check_silent)
		    sh_error_handle ((ptr->class == SH_LEVEL_ALLIGNORE) ? 
				     ShDFLevel[ptr->class] : 
				     ShDFLevel[SH_ERR_T_DIR],
				     FIL__, __LINE__, 0, MSG_FI_ADD,
				     tmp);
		  ++sh.statistics.files_report;
		  SH_FREE(tmp);
#endif
		}
	      else if (status == SH_FILE_UNKNOWN)
		{
		  /* catchall
		   */
		  tmp = sh_util_safe_name (ptr->name);
		  sh_error_handle (SH_ERR_INFO, FIL__, __LINE__, 0,
				   MSG_FI_FAIL,
				   tmp);
		  SH_FREE(tmp);
		  if (sh.flag.checkSum != SH_CHECK_INIT)
		    sh_hash_set_visited_true(ptr->name);
		}

	      ++dcount;
	    }
	  ptr->checked        = S_TRUE;
	  ptr->childs_checked = S_TRUE;
	}

      if (sig_urgent > 0) {
	goto out;
      }

    }
 out:
  ; /* 'label at end of compound statement' */
  SH_MUTEX_RECURSIVE_UNLOCK(mutex_zdirs);

  SL_RETURN(dcount, _("sh_dirs_chk"));
}

int sh_files_pushdir_prelink (const char * str_s)
{
  return (sh_files_pushdir (SH_LEVEL_PRELINK, str_s));
}

int sh_files_pushdir_user0 (const char * str_s)
{
  return (sh_files_pushdir (SH_LEVEL_USER0, str_s));
}

int sh_files_pushdir_user1 (const char * str_s)
{
  return (sh_files_pushdir (SH_LEVEL_USER1, str_s));
}

int sh_files_pushdir_user2 (const char * str_s)
{
  return (sh_files_pushdir (SH_LEVEL_USER2, str_s));
}

int sh_files_pushdir_user3 (const char * str_s)
{
  return (sh_files_pushdir (SH_LEVEL_USER3, str_s));
}

int sh_files_pushdir_user4 (const char * str_s)
{
  return (sh_files_pushdir (SH_LEVEL_USER4, str_s));
}

int sh_files_pushdir_attr (const char * str_s)
{
  return (sh_files_pushdir (SH_LEVEL_ATTRIBUTES, str_s));
}

int sh_files_pushdir_ro (const char * str_s)
{
  return (sh_files_pushdir (SH_LEVEL_READONLY, str_s));
}

int sh_files_pushdir_log (const char * str_s)
{
  return (sh_files_pushdir (SH_LEVEL_LOGFILES, str_s));
}

int sh_files_pushdir_glog (const char * str_s)
{
  return (sh_files_pushdir (SH_LEVEL_LOGGROW, str_s));
}

int sh_files_pushdir_noig (const char * str_s)
{
  return (sh_files_pushdir (SH_LEVEL_NOIGNORE, str_s));
}

int sh_files_pushdir_allig (const char * str_s)
{
  return (sh_files_pushdir (SH_LEVEL_ALLIGNORE, str_s));
}

int set_dirList (int which)
{
  if (which == 2)
    which_dirList = SH_LIST_DIR2;
  else
    which_dirList = SH_LIST_DIR1;
  return 0;
}

int sh_files_push_dir_int (int class, char * tail, size_t len, int rdepth, unsigned long check_flags)
{
  zAVLTree   * tree;
  dirstack_t * new_item_ptr;
  char       * dirName;
  int          ret;

  SL_ENTER(_("sh_files_push_dir_int"));

  dirName = SH_ALLOC(len+1);
  sl_strlcpy(dirName, tail, len+1);

  new_item_ptr = (dirstack_t * ) SH_ALLOC (sizeof(dirstack_t));

  new_item_ptr->name           = dirName;
  new_item_ptr->class          = class;
  new_item_ptr->check_flags     = check_flags;
  new_item_ptr->rdepth         = rdepth;
  new_item_ptr->checked        = S_FALSE;
  new_item_ptr->is_reported    = 0;
  new_item_ptr->childs_checked = S_FALSE;

  SH_MUTEX_RECURSIVE_INIT(mutex_zdirs);
  SH_MUTEX_RECURSIVE_LOCK(mutex_zdirs);
  if (which_dirList == SH_LIST_DIR1)
    {
      tree = zdirListOne;
    }
  else
    {
      tree = zdirListTwo;
    }

  if (tree == NULL)
    {
      tree = zAVLAllocTree (zdirstack_key, zAVL_KEY_STRING);
      if (tree == NULL) 
	{
	  (void) safe_logger (0, 0, NULL);
	  aud__exit(FIL__, __LINE__, EXIT_FAILURE);
	}
      if (which_dirList == SH_LIST_DIR1)
	zdirListOne = tree;
      else
	zdirListTwo = tree;
    }

  ret = zAVLInsert (tree, new_item_ptr);
  SH_MUTEX_RECURSIVE_UNLOCK(mutex_zdirs);

  if (-1 == ret)
    {
      (void) safe_logger (0, 0, NULL);
      aud__exit(FIL__, __LINE__, EXIT_FAILURE);
    }
  if (3 == ret)
    { 
      if (sh.flag.started != S_TRUE)
	sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_FI_DOUBLE,
			 dirName);
      SH_FREE(dirName);
      SH_FREE(new_item_ptr);
      new_item_ptr = NULL;
    }
  else
    {
      if (MODI_AUDIT_ENABLED(check_flags))
	{
	  sh_error_handle(SH_ERR_INFO, FIL__, __LINE__, 0, MSG_E_SUBGPATH,
			  _("Setting audit watch"),
			  _("sh_files_push_file_int"), tail);
	  sh_audit_mark(tail);
	}
    }
  SL_RETURN(0, _("sh_files_push_dir_int"));
}

static int sh_files_pushdir (int class, const char * str_s)
{
  char  * tmp;
  size_t  len;
  int     rdepth = 0;
  char  * tail = NULL;
  char  * p;

  SL_ENTER(_("sh_files_pushdir"));

  if (sh.flag.opts == S_TRUE) {
    sh_files_delfilestack ();
    sh_files_deldirstack ();
    sh_files_delglobstack ();
  }

  p = sh_files_parse_input(str_s, &len);
  if (!p || len == 0)
    SL_RETURN((-1),_("sh_files_pushdir"));

  if (p[0] != '/')
    {
      rdepth = strtol(p, &tail, 10);
      if (tail == p)
	{
	  SH_FREE(p);
	  SL_RETURN((-1), _("sh_files_pushdir"));
	}
    }
  else
    tail   = p;
  

  if (tail == p)
    {
      /* Setting to an invalid number will force MaxRecursionLevel,
       * see sh_files_setrec_int()
       */
      rdepth = (-2);
    }
  else if ( (rdepth < (-1) || rdepth > 99) || 
	    ((rdepth == (-1)) && (class != SH_LEVEL_ALLIGNORE)) )
    {
      SH_FREE(p);
      SL_RETURN((-1), _("sh_files_pushdir"));
    }

  len = sl_strlen(tail);

  if (len >= PATH_MAX) 
    {
      tmp = sh_util_safe_name (tail);
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_FI_2LONG,
		       tmp);
      SH_FREE(tmp);
      SH_FREE(p);
      SL_RETURN((-1), _("sh_files_pushdir"));
    } 
  else if (len < 1) 
    {
      SH_FREE(p);
      SL_RETURN((-1), _("sh_files_pushdir"));
    } 
  else if (tail[0] != '/') 
    {
      tmp = sh_util_safe_name (tail);
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_FI_NOPATH,
		       tmp);
      SH_FREE(tmp);
      SH_FREE(p);
      SL_RETURN((-1), _("sh_files_pushdir"));
    } 
  else 
    {
      if (tail[len-1] == '/' && len > 1)
	{
	  tail[len-1] = '\0';
	  --len;
	}
    } 

#ifdef HAVE_GLOB_H
  if (0 == sh_files_has_metachar(tail))
    {
      sh_files_push_dir_int (class, tail, len, rdepth, sh_files_maskof(class));
    }
  else
    {
      sh_files_pushglob (class, which_dirList, tail, rdepth, 0, 0);
    }
#else  
  sh_files_push_dir_int (class, tail, len, rdepth, sh_files_maskof(class));
#endif

  SH_FREE(p);
  SL_RETURN((0), _("sh_files_pushdir"));
}

/**
struct sh_dirent {
  char             * sh_d_name;
  struct sh_dirent * next;
};
**/

void kill_sh_dirlist (struct sh_dirent * dirlist)
{
  struct sh_dirent * this;

  while (dirlist)
    {
      this    = dirlist->next;
      SH_FREE(dirlist->sh_d_name);
      SH_FREE(dirlist);
      dirlist = this;
    }
  return;
}
  
/* -- add an entry to a directory listing
 */
struct sh_dirent * addto_sh_dirlist (struct dirent * thisEntry, 
				     struct sh_dirent * dirlist)
{
  struct sh_dirent * this;
  size_t len;

  if (thisEntry == NULL)
    return dirlist;
  
  len = sl_strlen(thisEntry->d_name);
  if (len == 0)
    return dirlist;
  ++len;
  
  this = SH_ALLOC(sizeof(struct sh_dirent));
  if (!this)
    return dirlist;

  this->sh_d_name = SH_ALLOC(len);
  sl_strlcpy(this->sh_d_name, thisEntry->d_name, len);

  this->next = dirlist;
  return this;
}

static int sh_check_hardlinks = S_TRUE;

/* Simply sets our boolean as to whether this check is active 
 */
int sh_files_check_hardlinks (const char * opt)
{
  int i;
  SL_ENTER(_("sh_files_check_hardlinks"));
  i = sh_util_flagval(opt, &sh_check_hardlinks);
  SL_RETURN(i, _("sh_files_check_hardlinks"));
}

struct sh_hle_struct {
  long   offset;
  char * path;
  struct sh_hle_struct * next;
};

static struct sh_hle_struct * sh_hl_exc = NULL;

int sh_files_hle_reg (const char * str)
{
  long   offset;
  size_t len;
  char * path;
  
  struct sh_hle_struct * tmp = sh_hl_exc;

  SL_ENTER(_("sh_files_hle_reg"));

  /* Free the linked list if called with NULL argument
   */
  if (str == NULL)
    {
      while (tmp)
	{
	  sh_hl_exc = tmp->next;
	  SH_FREE(tmp->path);
	  SH_FREE(tmp);
	  tmp = sh_hl_exc;
	}
      sh_hl_exc = NULL;
      SL_RETURN(0, _("sh_files_hle_reg"));
    }

  /* We expect 'offset:/path'
   */
  offset = strtol(str, &path, 0);
  if ((path == NULL) || (*path == '\0') || (*path != ':') || (path[1] != '/'))
    {
      SL_RETURN(-1, _("sh_files_hle_reg"));
    }
  ++path;
  len = 1 + sl_strlen(path);

  tmp         = SH_ALLOC(sizeof(struct sh_hle_struct));
  tmp->path   = SH_ALLOC(len);
  sl_strlcpy (tmp->path, path, len);
  tmp->offset = offset;
  tmp->next   = sh_hl_exc;
  sh_hl_exc   = tmp;

  SL_RETURN(0, _("sh_files_hle_reg"));
}

#if !defined(HOST_IS_DARWIN)
static int sh_files_hle_test (int offset, char * path)
{
  struct sh_hle_struct * tmp = sh_hl_exc;

  SL_ENTER(_("sh_files_hle_reg"));

  while(tmp)
    {
      if ((offset == tmp->offset) && (0 == strcmp(path, tmp->path)))
	{
	  SL_RETURN(0, _("sh_files_hle_test"));
	}
      tmp = tmp->next;
    }
#ifdef HAVE_FNMATCH_H
  if ( (offset == 1) && (0 == fnmatch(_("/run/user/*"), path, FNM_PATHNAME)) )
    {
      /* gvfs directory in /run/user/username/ */
      SL_RETURN(0, _("sh_files_hle_test"));
    }
#endif

  SL_RETURN(-1, _("sh_files_hle_test"));
}
#endif

static void * sh_dummy_dirlist;
static void * sh_dummy_tmpcat;

/* -- Check a single directory and its content. Does not
 *    check the directory inode itself.
 */
int sh_files_checkdir (int iclass, unsigned long check_flags, 
		       int idepth, char * iname, 
		       char * relativeName)
{
  struct sh_dirent * dirlist;
  struct sh_dirent * dirlist_orig;

  DIR *           thisDir = NULL;
  struct dirent * thisEntry;
  int             status;
  int             dummy = S_FALSE;
  dir_type      * theDir;
  ShFileType      checkit;
  static unsigned int state = 1;

  file_type     * theFile;
  char          * tmpname;
  char          * tmpcat;
  char errbuf[SH_ERRBUF_SIZE];

  int             rdepth = 0;
  int             class  = 0;
  volatile int    rdepth_next;
  volatile int    class_next;
  volatile int    file_class_next;
  volatile unsigned long   check_flags_next;
  volatile unsigned long   file_check_flags_next;

  volatile int    checked_flag  = S_FALSE;
  volatile int    cchecked_flag = S_FALSE;

  dirstack_t *    dst_ptr;
  dirstack_t *    tmp_ptr;

  int             hardlink_num = 0;
#if !defined(HOST_IS_DARWIN)
  size_t          len;
#endif

  SL_ENTER(_("sh_files_checkdir"));

  if (sig_urgent > 0) {
    SL_RETURN((0), _("sh_files_checkdir"));
  }

  if (iname == NULL || idepth < (-1))
    SL_RETURN((-1), _("sh_files_checkdir"));
  
  if (idepth < 0)
    {
      /* hash_remove_tree (iname); */
      SL_RETURN((0), _("sh_files_checkdir"));
    }
  
  rdepth = idepth;
  class  = iclass;
  
  tmpname = sh_util_safe_name (iname);

  /* ---- check for obscure name ----
   */
  if (iclass != SH_LEVEL_ALLIGNORE)
    {
      sh_util_obscurename (ShDFLevel[SH_ERR_T_NAME], iname, S_TRUE);
    }

  if (flag_err_info == S_TRUE)
    {
      char pstr[32];

      sl_strlcpy(pstr, sh_hash_getpolicy(iclass), sizeof(pstr));
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_FI_CHK, pstr, tmpname);
    }

  /* ---- check input ----
   */
  if ( sl_strlen(iname) >= PATH_MAX) 
    {
      sh_error_handle (ShDFLevel[SH_ERR_T_DIR], FIL__, __LINE__, 0, 
		       MSG_FI_2LONG,
		       tmpname);
      SH_FREE(tmpname);
      SL_RETURN((-1), _("sh_files_checkdir"));
    }
  
  /* ---- check for absolute path ---- */
  if ( iname[0] != '/') 
    {
      sh_error_handle (ShDFLevel[SH_ERR_T_DIR], FIL__, __LINE__, 0, 
		       MSG_FI_NOPATH,
		       tmpname);
      SH_FREE(tmpname);
      SL_RETURN((-1), _("sh_files_checkdir"));
    }

  /* ---- stat the directory ----
   */
  theFile = SH_ALLOC(sizeof(file_type));
  sl_strlcpy (theFile->fullpath, iname, PATH_MAX);
  theFile->attr_string = NULL;
  theFile->link_path   = NULL;
  theFile->check_flags  = check_flags;

  (void) relativeName;
  status = sh_unix_getinfo (ShDFLevel[SH_ERR_T_DIR], 
			    iname,
			    theFile, NULL, iclass);

  if ((sig_termfast == 1) || (sig_terminate == 1)) 
    {
      if (theFile->attr_string) SH_FREE(theFile->attr_string);
      if (theFile->link_path)   SH_FREE(theFile->link_path);
      SH_FREE(theFile);
      SH_FREE(tmpname);
      SL_RETURN((0), _("sh_files_checkdir"));
    }

  if (status == -1)
    {
      if (theFile->attr_string) SH_FREE(theFile->attr_string);
      if (theFile->link_path)   SH_FREE(theFile->link_path);
      SH_FREE(theFile);
      SH_FREE(tmpname);
      SL_RETURN((-1), _("sh_files_checkdir"));
    }

  if (theFile->c_mode[0] != 'd') 
    { 
      if (!sh_global_check_silent)
	sh_error_handle (ShDFLevel[SH_ERR_T_DIR], FIL__, __LINE__, 0,
			 MSG_FI_NODIR,
			 tmpname);
      ++sh.statistics.files_nodir;
      if (theFile->attr_string) SH_FREE(theFile->attr_string);
      if (theFile->link_path)   SH_FREE(theFile->link_path);
      SH_FREE(theFile);
      SH_FREE(tmpname);
      SL_RETURN((-1), _("sh_files_checkdir"));
    }

  if ((sh.flag.inotify & SH_INOTIFY_INSCAN) != 0)
    {
      sh_inotify_add_watch_later(iname, &sh_file_watches, &status,
				 iclass, check_flags, SH_INOTIFY_DIR, idepth);
    }
   
  hardlink_num = theFile->hardlinks;

  if (theFile->attr_string) SH_FREE(theFile->attr_string);
  if (theFile->link_path)   SH_FREE(theFile->link_path);
  SH_FREE(theFile);

  /* ---- open directory for reading ---- 
   *
   * opendir() will fail with ENOTDIR if the path has been changed
   * to a non-directory in between lstat() and opendir().
   */
  thisDir = opendir (iname);

  if (thisDir == NULL) 
    {
      status = errno;
      sh_error_handle (ShDFLevel[SH_ERR_T_DIR], FIL__, __LINE__, 0, 
		       MSG_E_OPENDIR,
		       sh_error_message (status, errbuf, sizeof(errbuf)), tmpname);
      SH_FREE(tmpname); 
      SL_RETURN((-1), _("sh_files_checkdir"));
    }

  theDir = SH_ALLOC(sizeof(dir_type));

  theDir->NumRegular  = 0;
  theDir->NumDirs     = 0;
  theDir->NumSymlinks = 0;
  theDir->NumFifos    = 0;
  theDir->NumSockets  = 0;
  theDir->NumCDev     = 0;
  theDir->NumBDev     = 0;
  theDir->NumDoor     = 0;
  theDir->NumPort     = 0;
  theDir->NumAll      = 0;
  theDir->TotalBytes  = 0;
  sl_strlcpy (theDir->DirPath, iname, PATH_MAX); 


  sh_dummy_dirlist = (void *) &dirlist;
  sh_dummy_tmpcat  = (void *) &tmpcat;

  /* ---- read ----
   */
  SH_MUTEX_LOCK(mutex_readdir);

  dirlist = NULL;
  dirlist_orig = NULL;

  do {
      thisEntry = readdir (thisDir);
      if (thisEntry != NULL) 
	{
	  ++theDir->NumAll;
	  if (sl_strcmp (thisEntry->d_name, ".") == 0)
	    { 
	      ++theDir->NumDirs;
	      continue;
	    }
	  if (sl_strcmp (thisEntry->d_name, "..") == 0)
	    {
	      ++theDir->NumDirs;
	      continue;
	    }
	  dirlist = addto_sh_dirlist (thisEntry, dirlist);
	}
  } while (thisEntry != NULL);

  SH_MUTEX_UNLOCK(mutex_readdir);

  closedir (thisDir);

  ++sh.statistics.dirs_checked;

  dirlist_orig = dirlist;

  do {

    /* If the directory is empty, dirlist = NULL
     */
    if (!dirlist)
      break;

    if (sig_termfast == 1) 
      {
	SH_FREE(theDir);
	SH_FREE(tmpname);
	SL_RETURN((0), _("sh_files_checkdir"));
      }

    BREAKEXIT(sh_derr);

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_RAND_R)
    if (0 == (rand_r(&state) % 5)) (void) sh_derr();
#else
    if (0 == state * (rand() % 5)) (void) sh_derr();
#endif
    
    /* ---- Check the file. ---- 
     */
    tmpcat = SH_ALLOC(PATH_MAX);
    sl_strlcpy(tmpcat, iname,                   PATH_MAX);
    if (sl_strlen(tmpcat) > 1 || tmpcat[0] != '/')
      sl_strlcat(tmpcat, "/",                   PATH_MAX);
    sl_strlcat(tmpcat, dirlist->sh_d_name,      PATH_MAX);
    
    rdepth_next     = rdepth - 1;
    class_next      = class;
    check_flags_next = check_flags;
    file_class_next = class;
    file_check_flags_next = check_flags;
    checked_flag    = -1;
    cchecked_flag   = -1;

    /* Wed Aug 24 2005 compare against dirListOne, dirListTwo
     * this fixes the problem that the directory special file
     * is checked with the policy of the parent directory
     */
    SH_MUTEX_RECURSIVE_INIT(mutex_zdirs);
    SH_MUTEX_RECURSIVE_LOCK(mutex_zdirs);
    dst_ptr         = (dirstack_t *) zAVLSearch(zdirListOne, tmpcat);

    if (dst_ptr) 
      {
	/* Tue Aug  6 22:13:27 CEST 2002 introduce file_class_next
	 * this fixes the problem that a policy for the directory
	 * inode erroneously becomes a policy for the directory itself.
	 */
	file_class_next    = dst_ptr->class;
	file_check_flags_next = dst_ptr->check_flags;
	checked_flag       = dst_ptr->checked;
	cchecked_flag      = dst_ptr->childs_checked;
      }

    if (checked_flag == -1)
      {
	dst_ptr         = (dirstack_t *) zAVLSearch(zdirListTwo, tmpcat);

	if (dst_ptr) 
	  {
	    /* Tue Aug  6 22:13:27 CEST 2002 introduce file_class_next
	     * this fixes the problem that a policy for the directory
	     * inode erroneously becomes a policy for the directory itself.
	     */
	    file_class_next    = dst_ptr->class;
	    file_check_flags_next = dst_ptr->check_flags;
	    checked_flag       = dst_ptr->checked;
	    cchecked_flag      = dst_ptr->childs_checked;
	  }
      }
    SH_MUTEX_RECURSIVE_UNLOCK(mutex_zdirs);

    SH_MUTEX_LOCK_UNSAFE(mutex_zfiles);
    dst_ptr         = (dirstack_t *) zAVLSearch(zfileList, tmpcat);

    if (dst_ptr) 
      {
	/* Tue Aug  6 22:13:27 CEST 2002 introduce file_class_next
	 * this fixes the problem that a policy for the directory
	 * inode erroneously becomes a policy for the directory itself.
	 */
	file_class_next    = dst_ptr->class;
	file_check_flags_next = dst_ptr->check_flags;
	checked_flag       = dst_ptr->checked;
	/* not set, hence always FALSE                   */
	/* cchecked_flag      = dst_ptr->childs_checked; */

	if (checked_flag != S_TRUE)
	  {
	    /* -- need to check the file itself --
	     */
	    if (sh.flag.reportonce == S_TRUE)
	      dummy = dst_ptr->is_reported;
	  }
      }
    SH_MUTEX_UNLOCK_UNSAFE(mutex_zfiles);
    
    /* ---- Has been checked already. ----
     */
    if (checked_flag == S_TRUE && cchecked_flag == S_TRUE)
      {
	/* Mar 11 2004 get ftype for complete directory count
	 */
	checkit = sh_unix_get_ftype(tmpcat);
	if (checkit == SH_FILE_DIRECTORY) 
	  {
	    ++theDir->NumDirs;
	  }
	SH_FREE(tmpcat);
	dirlist = dirlist->next;
	continue;
      }
    
    /* --- May be true, false, or not found. --- 
     */
    if (checked_flag == S_TRUE)
      {
	/* -- need only the file type --
	 */
	checkit = sh_unix_get_ftype(tmpcat);
      }
    else
      {
	/* -- need to check the file itself --
	 */
	/* -- moved up -- 
	 * if (dst_ptr && sh.flag.reportonce == S_TRUE)
	 *   dummy = dst_ptr->is_reported;
	 */

	checkit = sh_files_filecheck (file_class_next, file_check_flags_next, 
				      iname, 
				      dirlist->sh_d_name,
				      &dummy, 0);

	
	SH_MUTEX_LOCK_UNSAFE(mutex_zfiles);
	dst_ptr         = (dirstack_t *) zAVLSearch(zfileList, tmpcat);

	if (dst_ptr && checked_flag == S_FALSE)
	  dst_ptr->checked = S_TRUE;

	/* Thu Mar  7 15:09:40 CET 2002 Propagate the 'reported' flag
	 */
	if (dst_ptr && sh.flag.reportonce == S_TRUE)
	  dst_ptr->is_reported = dummy;

	if (dst_ptr)
	  dst_ptr->childs_checked = S_TRUE;
	SH_MUTEX_UNLOCK_UNSAFE(mutex_zfiles);
      }
    
    if      (checkit == SH_FILE_REGULAR)   
      ++theDir->NumRegular;
    
    else if (checkit == SH_FILE_DIRECTORY) 
      {
	++theDir->NumDirs;

	if (rdepth_next >= 0 && cchecked_flag != S_TRUE) 
	  {
	    rdepth_next = rdepth - 1;
	    
	    /* check whether the new directory is in the
	     * list with a recursion depth already defined
	     */
	    checked_flag  = -1;
	    cchecked_flag = -1;
	    
	    SH_MUTEX_RECURSIVE_INIT(mutex_zdirs);
	    SH_MUTEX_RECURSIVE_LOCK(mutex_zdirs);
	    tmp_ptr     = (dirstack_t *) zAVLSearch(zdirListOne, tmpcat);

	    if (tmp_ptr) 
	      {
		TPT((0, FIL__, __LINE__, 
		     _("msg=<%s -> recursion depth %d\n>"),
		     tmp_ptr->name, tmp_ptr->rdepth));
		rdepth_next   = tmp_ptr->rdepth;
		class_next    = tmp_ptr->class;
		check_flags_next = tmp_ptr->check_flags;
		/* 28. Aug 2001 reversed
		 */
		cchecked_flag = tmp_ptr->childs_checked;
		checked_flag  = tmp_ptr->checked;
	      }
	    
	    if (checked_flag == -1)
	      {
		tmp_ptr     = (dirstack_t *) zAVLSearch(zdirListTwo, tmpcat);

		if (tmp_ptr) 
		  {
		    TPT((0, FIL__, __LINE__, 
			 _("msg=<%s -> recursion depth %d\n>"),
			 tmp_ptr->name, tmp_ptr->rdepth));
		    rdepth_next   = tmp_ptr->rdepth;
		    class_next    = tmp_ptr->class;
		    check_flags_next = tmp_ptr->check_flags;
		    /* 28. Aug 2001 reversed
		     */
		    cchecked_flag = tmp_ptr->childs_checked;
		    checked_flag  = tmp_ptr->checked;
		  }
	      }

	    if (tmp_ptr && cchecked_flag == S_FALSE)
	      {
		tmp_ptr->childs_checked = S_TRUE;
		/*
		 * 04. Feb 2006 avoid double checking
		 */
		tmp_ptr->checked        = S_TRUE;
	      }
	    SH_MUTEX_RECURSIVE_UNLOCK(mutex_zdirs);

	    if (cchecked_flag == S_FALSE)
	      {
		sh_files_checkdir (class_next, check_flags_next, rdepth_next, 
				   tmpcat, dirlist->sh_d_name);
		/*
		  tmp_ptr->childs_checked = S_TRUE;
		  tmp_ptr->checked        = S_TRUE;
		*/
	      }
	    else if (checked_flag == -1)
	      sh_files_checkdir (class_next, check_flags_next, rdepth_next, 
				 tmpcat, dirlist->sh_d_name);
	    
	  }
      }
    
    else if (checkit == SH_FILE_SYMLINK)   ++theDir->NumSymlinks;
    else if (checkit == SH_FILE_FIFO)      ++theDir->NumFifos;
    else if (checkit == SH_FILE_SOCKET)    ++theDir->NumSockets;
    else if (checkit == SH_FILE_CDEV)      ++theDir->NumCDev;
    else if (checkit == SH_FILE_BDEV)      ++theDir->NumBDev;
    else if (checkit == SH_FILE_DOOR)      ++theDir->NumDoor;
    else if (checkit == SH_FILE_PORT)      ++theDir->NumPort;
    
    SH_FREE(tmpcat);
    
    if ((sig_termfast == 1) || (sig_terminate == 1)) 
      {
	SH_FREE(theDir);
	sh_dummy_dirlist = NULL;
	SH_FREE(tmpname);
	SL_RETURN((0), _("sh_files_checkdir"));
      }
    
    dirlist = dirlist->next;

    /* -- moved up, only affects zfileList anyway
     * if (dst_ptr)
     *   dst_ptr->childs_checked = S_TRUE;
     */

  } while (dirlist != NULL);

  if (flag_err_info == S_TRUE)
    {
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_FI_DSUM,
		       theDir->NumDirs,
		       theDir->NumRegular,
		       theDir->NumSymlinks,
		       theDir->NumFifos,
		       theDir->NumSockets,
		       theDir->NumCDev,
		       theDir->NumBDev);
    }

  kill_sh_dirlist (dirlist_orig);

#if !defined(HOST_IS_DARWIN)
  /* 
   * Hardlink check; not done on MacOS X because of resource forks
   */
  if ((sh_check_hardlinks == S_TRUE) && (hardlink_num != theDir->NumDirs)) 
    {
      if (0 != sh_files_hle_test(hardlink_num-theDir->NumDirs, iname))
	{
	  len = strlen(tmpname);
	  if (sl_ok_adds(len, 256)) 
	    len += 256;
	  tmpcat = SH_ALLOC(len);
	  sl_snprintf(tmpcat, len, 
		      _("%s: subdirectory count (%d) != hardlinks (%d)"),
		      tmpname, theDir->NumDirs, hardlink_num);
	  sh_error_handle (ShDFLevel[SH_ERR_T_DIR], FIL__, __LINE__, 0, 
			   MSG_E_SUBGEN, tmpcat, _("sh_files_checkdir"));
	  SH_FREE(tmpcat);
	}
    }
#endif

  SH_FREE(tmpname);
  SH_FREE(theDir);

  sh_dummy_dirlist = NULL;

  SL_RETURN((0), _("sh_files_checkdir"));
}

void sh_files_fixup_mask (int class, unsigned long * check_flags)
{
  if (class == SH_LEVEL_ALLIGNORE)
    MODI_SET((*check_flags), MODI_ALLIGNORE);
  sh_tiger_get_mask_hashtype(check_flags);
  return;
}

int get_the_fd (SL_TICKET ticket);

static int sh_use_rsrc = S_FALSE;

int sh_files_use_rsrc(const char * str)
{
  return sh_util_flagval(str, &sh_use_rsrc);
}

static void * sh_dummy_fileName;
static void * sh_dummy_tmpname;
static void * sh_dummy_tmpdir;

ShFileType sh_files_filecheck (int class, unsigned long check_flags,
			       const char * dirName, 
			       const char * infileName,
			       int * reported, 
			       int rsrcflag)
{
  /* 28 Aug 2001 allow NULL fileName
   */
  char          * fullpath;
  char            fileHash[2*(KEY_LEN + 1)];
  int             status;
  file_type     * theFile;
  char          * tmpdir;
  char          * tmpname;
  const char    * fileName;
#if !defined(O_NOATIME)
  struct utimbuf  utime_buf;
#endif
  static unsigned int state = 1;
  char            sc;

  SL_ENTER(_("sh_files_filecheck"));

  fullpath = SH_ALLOC(PATH_MAX);
  theFile  = SH_ALLOC(sizeof(file_type));

  /* Take the address to keep gcc from putting it into a register. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_fileName = (void *) &fileName;
  sh_dummy_tmpname  = (void *) &tmpname;
  sh_dummy_tmpdir   = (void *) &tmpdir;

  BREAKEXIT(sh_derr);

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_RAND_R)
  if (0 == (rand_r(&state) % 2)) (void) sh_derr();
#else
  if (0 == state * (rand() % 2)) (void) sh_derr();
#endif

  if (dirName && infileName && (dirName[0] == '/') && (dirName[1] == '\0')
      && (infileName[0] == '/') && (infileName[1] == '\0'))
    {
      fileName = NULL;
    }
  else
    {
      fileName = infileName;
    }

  /* fileName may be NULL if this is a directory
   */
  if (dirName == NULL /* || fileName == NULL */)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_FI_NULL);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      SH_FREE(fullpath);
      SH_FREE(theFile);
      SL_RETURN(SH_FILE_UNKNOWN, _("sh_files_filecheck"));
    }

  if ((fileName != NULL) && (class != SH_LEVEL_ALLIGNORE) && 
      (0 != sh_util_obscurename (ShDFLevel[SH_ERR_T_NAME], 
				 fileName, S_FALSE))) 
    {
      if ((dirName != NULL) && (dirName[0] == '/') && (dirName[1] == '\0')) 
	{
	  tmpname = sh_util_safe_name (fileName);
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle (ShDFLevel[SH_ERR_T_NAME], FIL__, __LINE__, 0,
			   MSG_FI_OBSC2,
			   "", tmpname);
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  SH_FREE(tmpname);
	}
      else
	{
	  tmpdir  = sh_util_safe_name (dirName);
	  tmpname = sh_util_safe_name (fileName);
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle (ShDFLevel[SH_ERR_T_NAME], FIL__, __LINE__, 0,
			   MSG_FI_OBSC2,
			   tmpdir, tmpname);
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  SH_FREE(tmpname);
	  SH_FREE(tmpdir);
	}
    }    

  /* sh_files_fullpath accepts NULL fileName
   */
  if (0 != sh_files_fullpath (dirName, fileName, fullpath)) 
    { 
      tmpdir  = sh_util_safe_name (dirName);
      tmpname = sh_util_safe_name (fileName);
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle (ShDFLevel[SH_ERR_T_FILE],  FIL__, __LINE__, 0,
		       MSG_FI_2LONG2,
		       tmpdir, tmpname);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      SH_FREE(tmpname);
      SH_FREE(tmpdir);
      SH_FREE(fullpath);
      SH_FREE(theFile);
      SL_RETURN(SH_FILE_UNKNOWN, _("sh_files_filecheck"));
    } 

  /* stat the file and determine checksum (if a regular file)
   */
  sl_strlcpy (theFile->fullpath, fullpath, PATH_MAX);
  theFile->check_flags    = check_flags /* sh_files_maskof(class) */;
  theFile->file_reported = (*reported);
  theFile->attr_string   = NULL;
  theFile->link_path     = NULL;

  TPT(( 0, FIL__, __LINE__, _("msg=<checking file: %s>\n"),  fullpath));

  status = sh_unix_getinfo ( (class == SH_LEVEL_ALLIGNORE) ? 
			     ShDFLevel[class] : ShDFLevel[SH_ERR_T_FILE], 
			     fileName,
			     theFile, fileHash, class);

  if (status != 0)
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<file: %s> status=<%d>\n"), 
	    fullpath, status));
      if (class == SH_LEVEL_ALLIGNORE && sh.flag.checkSum != SH_CHECK_INIT)
	sh_hash_set_visited_true (fullpath);
      if (theFile->attr_string) SH_FREE(theFile->attr_string);
      if (theFile->link_path)   SH_FREE(theFile->link_path);
      SH_FREE(fullpath);
      SH_FREE(theFile);
      SL_RETURN(SH_FILE_UNKNOWN, _("sh_files_filecheck"));
    }
  
  if (sig_termfast == 1) {
    goto ret_point;
  }

  /* report
   */
  if ((flag_err_debug == S_TRUE) && (theFile->c_mode[0] == '-'))
    {
      tmpname = sh_util_safe_name (fullpath); /* fixed in 1.5.4 */
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_FI_CSUM,
		       fileHash, tmpname);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      SH_FREE(tmpname);
    } 
  ++sh.statistics.files_checked;
      
  if ( sh.flag.checkSum == SH_CHECK_INIT) 
    {
      if (class == SH_LEVEL_ALLIGNORE)
	MODI_SET(theFile->check_flags, MODI_ALLIGNORE);
      if (S_TRUE == sh_ignore_chk_mod(theFile->fullpath))
	MODI_SET(theFile->check_flags, MODI_NOCHECK);
      sh_tiger_get_mask_hashtype(&(theFile->check_flags));
      sh_dbIO_data_write (theFile, fileHash);
    }
  else if (sh.flag.checkSum == SH_CHECK_CHECK 
	   /* && theFile.c_mode[0] == '-' */
	   /* && class != SH_LEVEL_ALLIGNORE */
	   ) 
    {
      if (sh.flag.update == S_TRUE)
	{
	  if (class == SH_LEVEL_ALLIGNORE)
	    MODI_SET(theFile->check_flags, MODI_ALLIGNORE);
	  if (S_TRUE == sh_ignore_chk_mod(theFile->fullpath))
	    MODI_SET(theFile->check_flags, MODI_NOCHECK);
	  sh_tiger_get_mask_hashtype(&(theFile->check_flags));
	}
      sh_hash_compdata (class, theFile, fileHash, NULL, -1);
    }
  
  (*reported) = theFile->file_reported;

  /* reset the access time 
   */
#if !defined(O_NOATIME)
  if (class == SH_LEVEL_NOIGNORE && (theFile->check_flags & MODI_ATM) != 0)
    {
      utime_buf.actime   = (time_t) theFile->atime;
      utime_buf.modtime  = (time_t) theFile->mtime;

      retry_aud_utime (FIL__, __LINE__, fullpath, &utime_buf);
    }
#endif
  
#if defined(HOST_IS_DARWIN)
  /*
   * Check for resource fork
   */
  if ( (sh_use_rsrc == S_TRUE) && (theFile->c_mode[0] != 'd') && (rsrcflag == 0) )
    {
      int  dummy;
      static int rsrc_init = 0;
      static char rsrc[17];
      char * testpath = SH_ALLOC(PATH_MAX);

      if (rsrc_init == 0) {
	sl_strlcpy(rsrc, _("..namedfork/rsrc"), 17);
	rsrc_init = 1;
      }
      sl_strlcpy (testpath, fullpath, PATH_MAX);
      sl_strlcat (testpath,      "/", PATH_MAX);
      sl_strlcat (testpath,     rsrc, PATH_MAX);

      if (sl_strlen(testpath) == (17 + sl_strlen(fullpath)))
	{
	  if (S_TRUE == sh_unix_file_exists (testpath))
	    {
	      sh_files_filecheck (class, check_flags, fullpath, rsrc, &dummy, 1);
	    }
	}
      SH_FREE(testpath);
    }
#else
  (void) rsrcflag; /* avoid compiler warning */
#endif

 ret_point:

  sc = theFile->c_mode[0];

  if (theFile->attr_string) SH_FREE(theFile->attr_string);
  if (theFile->link_path)   SH_FREE(theFile->link_path);
  SH_FREE(fullpath);
  SH_FREE(theFile);

  switch (sc) 
    {
    case '-': SL_RETURN(SH_FILE_REGULAR, _("sh_files_filecheck"));   
    case 'l': SL_RETURN(SH_FILE_SYMLINK, _("sh_files_filecheck"));   
    case 'd': SL_RETURN(SH_FILE_DIRECTORY, _("sh_files_filecheck")); 
    case 'c': SL_RETURN(SH_FILE_CDEV, _("sh_files_filecheck"));      
    case 'b': SL_RETURN(SH_FILE_BDEV, _("sh_files_filecheck"));      
    case '|': SL_RETURN(SH_FILE_FIFO, _("sh_files_filecheck"));      
    case 'D': SL_RETURN(SH_FILE_DOOR, _("sh_files_filecheck"));    
    case 'P': SL_RETURN(SH_FILE_PORT, _("sh_files_filecheck"));    
    case 's': SL_RETURN(SH_FILE_SOCKET, _("sh_files_filecheck"));    
    default:  SL_RETURN(SH_FILE_UNKNOWN, _("sh_files_filecheck"));   
    }
  
  /* notreached */
}

/* concatenate statpath = testdir"/"d_name
 */
static int sh_files_fullpath (const char * testdir, const char * d_name, 
			      char * statpath)
{
  int llen = 0;

  SL_ENTER(_("sh_files_fullpath"));

  if (testdir != NULL) 
    {
      if ( (llen = sl_strlen(testdir)) > (PATH_MAX-2) ) 
	SL_RETURN((-1),_("sh_files_fullpath"));
      sl_strlcpy(statpath, testdir,    PATH_MAX - 1);
    }
  if (d_name != NULL) 
    {
      if (llen > 1 || statpath[0] != '/')
	sl_strlcat(statpath, "/",   PATH_MAX);
      if ((sl_strlen(d_name) + sl_strlen(statpath)) >= PATH_MAX)
	SL_RETURN((-1),_("sh_files_fullpath"));
      sl_strlcat(statpath, d_name,   PATH_MAX);
    }
  if (statpath == NULL) 
    SL_RETURN((-1),_("sh_files_fullpath"));
  SL_RETURN((0),_("sh_files_fullpath"));
}

/* -----------------------------------
 * Routines required for inotify 
 * -----------------------------------
 */
int sh_files_search_dir(char * name, int * class, 
			unsigned long *check_flags, int *reported,
			int * rdepth)
{
  volatile int retval = 0;
#if defined(HAVE_GLOB_H) && defined(HAVE_FNMATCH_H)
  sh_globstack_t * testPattern;
  zAVLCursor   cursor;
#endif
  dirstack_t * item;

  SH_MUTEX_RECURSIVE_INIT(mutex_zdirs);
  SH_MUTEX_RECURSIVE_LOCK(mutex_zdirs);

  item = zAVLSearch(zdirListOne, name);

  if (item)
    {
      *check_flags = item->check_flags;
      *class      = item->class;
      *reported   = item->is_reported;
      *rdepth     = item->rdepth;
      item->checked        = S_FALSE;
      item->childs_checked = S_FALSE;
      item->is_reported    = S_FALSE;
      retval = 1;
      goto out;
    }

  item = zAVLSearch(zdirListTwo, name);

  if (item)
    {
      *check_flags = item->check_flags;
      *class      = item->class;
      *reported   = item->is_reported;
      *rdepth     = item->rdepth;
      item->checked        = S_FALSE;
      item->childs_checked = S_FALSE;
      item->is_reported    = S_FALSE;
      retval = 1;
      goto out;
    }

#if defined(HAVE_GLOB_H) && defined(HAVE_FNMATCH_H)
  SH_MUTEX_LOCK(mutex_zglob);
  for (testPattern = (sh_globstack_t *) zAVLFirst (&cursor, zglobList); 
       testPattern;
       testPattern = (sh_globstack_t *) zAVLNext  (&cursor))
    {
      if (testPattern->type == SH_LIST_DIR1 || 
	  testPattern->type == SH_LIST_DIR2)
	{
	  if (0 == fnmatch(testPattern->name, name, FNM_PATHNAME|FNM_PERIOD))
	    {
	      *check_flags = testPattern->check_flags;
	      *class      = testPattern->class;
	      *rdepth     = testPattern->rdepth;
	      retval = 1;
	      break;
	    }
	
	}
    }
  SH_MUTEX_UNLOCK(mutex_zglob);
#endif
 out:
  ; /* 'label at end of compound statement' */
  SH_MUTEX_RECURSIVE_UNLOCK(mutex_zdirs);
  return retval;
}

int sh_files_search_file(char * name, int * class, 
			 unsigned long *check_flags, int *reported)
{
  volatile int retval = 0;
#if defined(HAVE_GLOB_H) && defined(HAVE_FNMATCH_H)
  sh_globstack_t * testPattern;
  zAVLCursor   cursor;
#endif
  dirstack_t * item;

  SH_MUTEX_LOCK(mutex_zfiles);
  item = zAVLSearch(zfileList, name);

  if (item)
    {
      *check_flags = item->check_flags;
      *class      = item->class;
      *reported   = item->is_reported;
      retval = 1;
    }
  SH_MUTEX_UNLOCK(mutex_zfiles);

#if defined(HAVE_GLOB_H) && defined(HAVE_FNMATCH_H)
  if (retval == 0)
    {
      SH_MUTEX_LOCK(mutex_zglob);
      for (testPattern = (sh_globstack_t *) zAVLFirst (&cursor, zglobList); 
	   testPattern;
	   testPattern = (sh_globstack_t *) zAVLNext  (&cursor))
	{
	  if (testPattern->type == SH_LIST_FILE)
	    {
	      if (0 == fnmatch(testPattern->name, name, 
			       FNM_PATHNAME|FNM_PERIOD))
		{
		  *check_flags = testPattern->check_flags;
		  *class      = testPattern->class;
		  retval = 1;
		  break;
		}
	      
	    }
	}
      SH_MUTEX_UNLOCK(mutex_zglob);
    }
#endif

  return retval;
}

void sh_files_set_file_reported(const char * name)
{
  dirstack_t * item;

  SH_MUTEX_LOCK_UNSAFE(mutex_zfiles);
  item = zAVLSearch(zfileList, name);

  if (item)
    {
      if (sh.flag.reportonce == S_TRUE)
	SET_SH_FFLAG_REPORTED(item->is_reported);
    }
  SH_MUTEX_UNLOCK_UNSAFE(mutex_zfiles);
  return;
}

void sh_files_clear_file_reported(const char * name)
{
  dirstack_t * item;

  SH_MUTEX_LOCK_UNSAFE(mutex_zfiles);
  item = zAVLSearch(zfileList, name);

  if (item)
    {
      CLEAR_SH_FFLAG_REPORTED(item->is_reported);
    }
  SH_MUTEX_UNLOCK_UNSAFE(mutex_zfiles);
  return;
}

/* -----------------------------------
 * 
 *  The following two routines serve to
 *  verify that the user has selected
 *  a proper setup for file policies.
 *
 * -----------------------------------
 */
static int check_file(char * name)
{
  dirstack_t * pfilL;
  zAVLCursor   cursor;
  volatile int retval = -1;

  SL_ENTER(_("check_file"));

  if (SH_FILE_DIRECTORY == sh_unix_get_ftype(name))
    SL_RETURN(0, _("check_file"));

  for (pfilL = (dirstack_t *) zAVLFirst (&cursor, zfileList); pfilL;
       pfilL = (dirstack_t *) zAVLNext  (&cursor))
    {
      if (0 == strcmp(name, pfilL->name) &&
	  (pfilL->check_flags & MODI_ATM) == 0 &&
	  (pfilL->check_flags & MODI_CTM) == 0 &&
	  (pfilL->check_flags & MODI_MTM) == 0)
	{
	  retval = 0;
	  break;
	}
    }

  SL_RETURN(retval, _("check_file"));
}

static void * sh_dummy_pdirL;

int sh_files_test_setup_int (zAVLTree * tree)
{
  int dlen, flen;
  zAVLCursor   cursor1;
  zAVLCursor   cursor2;

  dirstack_t * pdirL; 
  dirstack_t * pfilL;

  SL_ENTER(_("sh_files_test_setup"));

  sh_dummy_pdirL = (void *) &pdirL;

  for (pdirL = (dirstack_t *) zAVLFirst (&cursor1, tree); pdirL;
       pdirL = (dirstack_t *) zAVLNext  (&cursor1))
    {
      dlen = strlen(pdirL->name);

      SH_MUTEX_LOCK(mutex_zfiles);
      for (pfilL = (dirstack_t *) zAVLFirst (&cursor2, zfileList); pfilL;
	   pfilL = (dirstack_t *) zAVLNext  (&cursor2))
	{
	  flen = strlen(pfilL->name);

	  /* check whether file is in tree of dir
	   */
	  if ((pfilL->class == SH_LEVEL_READONLY) ||
	      (pfilL->class == SH_LEVEL_NOIGNORE))
	    {
	      ;  /* do nothing */
	    }
	  else
	    {
	      if ((flen > (dlen+1)) && 
		  (pfilL->name[dlen] == '/') &&
                  (NULL == strchr(&(pfilL->name[dlen+1]), '/')) && /*30-5-01*/
		  (0 == strncmp(pfilL->name, pdirL->name, dlen)))
		{
		  if ((pdirL->check_flags & MODI_ATM) != 0  ||
		      (pdirL->check_flags & MODI_MTM) != 0  ||
		      (pdirL->check_flags & MODI_CTM) != 0)
		    {
		      if (check_file (pdirL->name) != 0)
			sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_FI_COLL,
					 pdirL->name, pfilL->name);
		    }
		}
	    }
	}
      SH_MUTEX_UNLOCK(mutex_zfiles);
    }

  SL_RETURN((0), _("sh_files_test_setup"));
}
      
int sh_files_test_double (zAVLTree * firstList, zAVLTree * secondList)
{
  int          retval = 0;
  zAVLCursor   cursor;
  dirstack_t * first;

  for (first = (dirstack_t *) zAVLFirst (&cursor, firstList); first;
       first = (dirstack_t *) zAVLNext  (&cursor))
    {

      if (NULL != zAVLSearch(secondList, first->name))
	{
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_FI_DOUBLE,
			   first->name);
	  retval = 1;
	}
    }
  return retval;
}

extern void     aud_exit   (const char * file, int line, int fd);
      
int sh_files_test_setup ()
{
  int retval;

  SH_MUTEX_RECURSIVE_INIT(mutex_zdirs);
  SH_MUTEX_RECURSIVE_LOCK(mutex_zdirs);
  /* Test for modifications allowed in ReadOnly directory
   */  
  sh_files_test_setup_int (zdirListOne);
  sh_files_test_setup_int (zdirListTwo);

  /* Test for files/dirz defined twice
   */  
  retval = sh_files_test_double (zdirListOne, zdirListTwo);
  if (retval != 0)
    aud_exit(FIL__, __LINE__, EXIT_FAILURE);

  retval = sh_files_test_double (zdirListTwo, zdirListOne);
  if (retval != 0)
    aud_exit(FIL__, __LINE__, EXIT_FAILURE);
  SH_MUTEX_RECURSIVE_UNLOCK(mutex_zdirs);

  return 0;
}

#endif

#ifdef SH_CUTEST
#include "CuTest.h"

void Test_file_lists (CuTest *tc)
{
#if (defined (SH_WITH_CLIENT) || defined (SH_STANDALONE))

  extern int hash_remove_tree_test(char * s, char * fullpath, size_t len_s);

  char * test;
  int ret;

  sh_files_pushfile_ro("/usr/test");
  sh_files_pushfile_ro("/usr/bin/test");
  sh_files_pushfile_ro("/usr/bin/foo/test");

  sh_files_pushdir_ro("/usr");
  sh_files_pushdir_attr("/usr/bin");
  sh_files_pushdir_ro("/usr/bin/foo");

  add_to_dirlist(zdirListOne);
  add_to_dirlist(zdirListTwo);
  add_to_filelist(zfileList);

  test = sh_files_findfile("/usr/tes");
  CuAssertTrue(tc, test == NULL);
  test = sh_files_findfile("/usr/test");
  CuAssertPtrNotNull(tc, test);
  test = sh_files_findfile("/usr/testi");
  CuAssertTrue(tc, test == NULL);
  test = sh_files_findfile("/test");
  CuAssertTrue(tc, test == NULL);

  test = sh_files_find_mostspecific_dir("/usr/bin/foo/test");
  CuAssertStrEquals(tc, "/usr/bin/foo", test);
  test = sh_files_find_mostspecific_dir("/usr/bin/test");
  CuAssertStrEquals(tc, "/usr/bin", test);
  test = sh_files_find_mostspecific_dir("/usr/test");
  CuAssertStrEquals(tc, "/usr", test);
  test = sh_files_find_mostspecific_dir("/test");
  CuAssertTrue(tc, test == NULL);
  test = sh_files_find_mostspecific_dir("/usr/foo/test");
  CuAssertStrEquals(tc, "/usr", test);

  test = sh_files_find_mostspecific_dir("/usr/bin");
  CuAssertStrEquals(tc, "/usr/bin", test);

  ret = hash_remove_tree_test("/usr", "/usr/test", strlen("/usr"));
  CuAssertIntEquals(tc, S_FALSE, ret);
  ret = hash_remove_tree_test("/usr", "/usr/testi", strlen("/usr"));
  CuAssertIntEquals(tc, S_TRUE, ret);
  ret = hash_remove_tree_test("/usr", "/usr/tes", strlen("/usr"));
  CuAssertIntEquals(tc, S_TRUE, ret);

  ret = hash_remove_tree_test("/usr/bin", "/usr/test", strlen("/usr/bin"));
  CuAssertIntEquals(tc, S_FALSE, ret);
  ret = hash_remove_tree_test("/usr/bin", "/usr/testi", strlen("/usr/bin"));
  CuAssertIntEquals(tc, S_FALSE, ret);
  ret = hash_remove_tree_test("/usr/bin", "/usr/tes", strlen("/usr/bin"));
  CuAssertIntEquals(tc, S_FALSE, ret);

  ret = hash_remove_tree_test("/usr/bin", "/usr/bin/test", strlen("/usr/bin"));
  CuAssertIntEquals(tc, S_FALSE, ret);
  ret = hash_remove_tree_test("/usr/bin", "/usr/bin/testi", strlen("/usr/bin"));
  CuAssertIntEquals(tc, S_TRUE, ret);
  ret = hash_remove_tree_test("/usr/bin", "/usr/bin/tes", strlen("/usr/bin"));
  CuAssertIntEquals(tc, S_TRUE, ret);

  ret = hash_remove_tree_test("/usr/bin", "/usr/bin", strlen("/usr/bin"));
  CuAssertIntEquals(tc, S_TRUE, ret);
  ret = hash_remove_tree_test("/usr", "/usr", strlen("/usr"));
  CuAssertIntEquals(tc, S_TRUE, ret);
  ret = hash_remove_tree_test("/usr", "/usrbin", strlen("/usr"));
  CuAssertIntEquals(tc, S_FALSE, ret);
  ret = hash_remove_tree_test("/", "/usrbin", strlen("/"));
  CuAssertIntEquals(tc, S_TRUE, ret);
  ret = hash_remove_tree_test("/", "/usr", strlen("/"));
  CuAssertIntEquals(tc, S_FALSE, ret);

#else
  (void) tc; /* fix compiler warning */
  return;
#endif
}

void Test_file_dequote (CuTest *tc)
{
#if (defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)) 

  char str1[]  = "1234567890";
  char str1a[] = "123456\\\"789\\r";
  char str1b[] = "12345678\\r9";
  char str1c[] = "12345678\\x0a_9";
  char str1d[] = "12345678\\007_9";
  char str1e[] = "123456789\\\\";

  char str2[] = "1234567890\\xw";
  char str3[] = "1234567890\\xw99";
  char str4[] = "1234567890\\0ww";
  char str5[] = "12345\\g67890";
  char str6[] = "1234567890\\009a";

  char *s, *p, *q;
  size_t lo, lr;

  s = SH_ALLOC(64); sl_strlcpy(s, str1, 64); p = s; lo = strlen(s); lr = lo;
  q = sh_files_C_dequote(s, &lr);
  CuAssertPtrNotNull(tc, q);
  CuAssertTrue(tc, p  == q);
  CuAssertTrue(tc, lr == lo);

  s = SH_ALLOC(64); sl_strlcpy(s, str1a, 64); p = s; lo = strlen(s); lr = lo;
  q = sh_files_C_dequote(s, &lr);
  CuAssertPtrNotNull(tc, q);
  CuAssertTrue(tc, p  != q);
  CuAssertTrue(tc, 0 == strcmp(q, "123456\"789\r"));
  CuAssertTrue(tc, lr == (lo-2));

  s = SH_ALLOC(64); sl_strlcpy(s, str1b, 64); p = s; lo = strlen(s); lr = lo;
  q = sh_files_C_dequote(s, &lr);
  CuAssertPtrNotNull(tc, q);
  CuAssertTrue(tc, p  != q);
  CuAssertTrue(tc, 0 == strcmp(q, "12345678\r9"));
  CuAssertTrue(tc, lr == (lo-1));

  s = SH_ALLOC(64); sl_strlcpy(s, str1c, 64); p = s; lo = strlen(s); lr = lo;
  q = sh_files_C_dequote(s, &lr);
  CuAssertPtrNotNull(tc, q);
  CuAssertTrue(tc, p  != q);
  CuAssertTrue(tc, 0 == strcmp(q, "12345678\x0a_9"));
  CuAssertTrue(tc, lr == (lo-3));

  s = SH_ALLOC(64); sl_strlcpy(s, str1d, 64); p = s; lo = strlen(s); lr = lo;
  q = sh_files_C_dequote(s, &lr);
  CuAssertPtrNotNull(tc, q);
  CuAssertTrue(tc, p  != q);
  CuAssertTrue(tc, 0 == strcmp(q, "12345678\007_9"));
  CuAssertTrue(tc, lr == (lo-3));

  s = SH_ALLOC(64); sl_strlcpy(s, str1e, 64); p = s; lo = strlen(s); lr = lo;
  q = sh_files_C_dequote(s, &lr);
  CuAssertPtrNotNull(tc, q);
  CuAssertTrue(tc, p  != q);
  CuAssertTrue(tc, 0 == strcmp(q, "123456789\\"));
  CuAssertTrue(tc, lr == (lo-1));

  s = SH_ALLOC(64); sl_strlcpy(s, str2, 64); p = s; lo = strlen(s); lr = lo;
  q = sh_files_C_dequote(s, &lr);
  CuAssertTrue(tc, q == NULL);
  CuAssertTrue(tc, lr == 0);

  s = SH_ALLOC(64); sl_strlcpy(s, str3, 64); p = s; lo = strlen(s); lr = lo;
  q = sh_files_C_dequote(s, &lr);
  CuAssertTrue(tc, q == NULL);
  CuAssertTrue(tc, lr == 0);

  s = SH_ALLOC(64); sl_strlcpy(s, str4, 64); p = s; lo = strlen(s); lr = lo;
  q = sh_files_C_dequote(s, &lr);
  CuAssertTrue(tc, q == NULL);
  CuAssertTrue(tc, lr == 0);

  s = SH_ALLOC(64); sl_strlcpy(s, str5, 64); p = s; lo = strlen(s); lr = lo;
  q = sh_files_C_dequote(s, &lr);
  CuAssertTrue(tc, q == NULL);
  CuAssertTrue(tc, lr == 0);

  s = SH_ALLOC(64); sl_strlcpy(s, str6, 64); p = s; lo = strlen(s); lr = lo;
  q = sh_files_C_dequote(s, &lr);
  CuAssertTrue(tc, q == NULL);
  CuAssertTrue(tc, lr == 0);

  return;
#else
  (void) tc; /* fix compiler warning */
  return;
#endif
}
#endif

