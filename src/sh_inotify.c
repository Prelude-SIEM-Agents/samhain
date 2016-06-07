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

#if defined(HAVE_SYS_INOTIFY_H)

#if defined(GCC_VERSION_MAJOR) && !defined(__clang__)
#if (GCC_VERSION_MAJOR > 4) || ((GCC_VERSION_MAJOR == 4) && (GCC_VERSION_MINOR > 8))
#pragma GCC diagnostic ignored "-Wclobbered"
#endif
#endif

#undef  FIL__
#define FIL__  _("sh_inotify.c")

/* printf */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "samhain.h"
#include "sh_pthread.h"
#include "sh_calls.h"
#include "sh_inotify.h"
#include "sh_mem.h"
#include "sh_utils.h"
#include "slib.h"

/**************************************************
 *
 * Make the inotify fd thread-specific by 
 * encapsulating it in get/set functions:
 * sh_get_inotify_fd() / sh_set_inotify_fd()
 *
 **************************************************/

#if defined(HAVE_PTHREAD)

SH_MUTEX_STATIC(mutex_list_dormant, PTHREAD_MUTEX_INITIALIZER);
SH_MUTEX_STATIC(mutex_watches,      PTHREAD_MUTEX_INITIALIZER);

static pthread_key_t  inotify_key;
static pthread_once_t inotify_key_once = PTHREAD_ONCE_INIT;

static void make_inotify_key()
{
    (void) pthread_key_create(&inotify_key, free);
}

static int sh_get_inotify_fd()
{
  void * ptr;
  int  * fp;

  (void) pthread_once(&inotify_key_once, make_inotify_key);
 
  if ((ptr = pthread_getspecific(inotify_key)) == NULL) 
    {
      ptr = calloc(1,sizeof(int));
      if (ptr)
	{
	  fp  = (int*) ptr;
	  *fp = -1;
	  (void) pthread_setspecific(inotify_key, ptr);
	}
      else
	{
	  return -1;
	}
    }
  else 
    {
      fp  = (int*) ptr;
    }
  return *fp;
}

static void sh_set_inotify_fd(int fd)
{
  int  * fp;

  fp = (int*) pthread_getspecific(inotify_key);
  if (fp)
    *fp = fd;
  return;
}

/* !defined(HAVE_PTHREAD) */
#else

static int sh_inotify_fd = -1;

static inline int sh_get_inotify_fd()
{
  return sh_inotify_fd;
}

static inline void sh_set_inotify_fd(int fd)
{
  sh_inotify_fd = fd;
}

#endif

/*--- nothing thread-related below this point --- */

#include "zAVLTree.h"

typedef struct 
{
  int    watch;
  short  flag;
  short  type;
  int    class;
  int    rdepth;
  unsigned long check_flags;
  char * file;
} sh_watch;

/**************************************************
 *
 * Get inotify fd, initialize inotify if necessary
 *
 **************************************************/
#define SH_INOTIFY_FAILED -2

static int sh_inotify_getfd()
{
  int ifd = sh_get_inotify_fd();

  if (ifd >= 0)
    {
      return ifd;
    }

  else if (ifd == SH_INOTIFY_FAILED)
    {
      return -1;
    }

  else /* if (ifd == -1) */
    {
#if defined(HAVE_INOTIFY_INIT1)
      ifd = inotify_init1(IN_CLOEXEC);
#else
      ifd = inotify_init();
      if (ifd >= 0)
	{
	  long sflags;

	  sflags = retry_fcntl(FIL__, __LINE__, ifd, F_GETFD, 0);
	  retry_fcntl(FIL__, __LINE__, ifd, F_SETFD, sflags|FD_CLOEXEC);
	}
#endif

      if (ifd < 0)
	{
	  sh_set_inotify_fd(SH_INOTIFY_FAILED);
	  return -1;
	}

      sh_set_inotify_fd(ifd);
      return ifd;
    }
}

/**************************************************
 *
 * Public function:
 *  int sh_inotify_wait_for_change(char * filename,
 *                                 int watch,
 *                                 int * errnum,
 *                                 int   waitsec);
 * Returns: watch, if nonnegative
 *          -1 on error or reopen required
 *             (check errnum != 0)
 *
 * Caller needs to keep track of watch descriptor
 *
 **************************************************/

#define SH_INOTIFY_REOPEN 0
#define SH_INOTIFY_MODIFY 1

void sh_inotify_init(sh_watches * watches)
{
  SH_MUTEX_LOCK_UNSAFE(mutex_watches);
  watches->list_of_watches = NULL;
  watches->count           = 0;
  watches->max_count       = 0;
  SH_MUTEX_UNLOCK_UNSAFE(mutex_watches);

  SH_MUTEX_LOCK_UNSAFE(mutex_list_dormant);
  watches->dormant_watches = NULL;
  SH_MUTEX_UNLOCK_UNSAFE(mutex_list_dormant);

  return;
}

ssize_t sh_inotify_read(char * buffer, size_t count)
{
  ssize_t len = -1;
  int     ifd = sh_inotify_getfd();

  do {
    len = read (ifd, buffer, count);
  } while (len < 0 && (errno == EINTR || errno == EAGAIN));

  return len;
}

ssize_t sh_inotify_read_timeout(char * buffer, size_t count, int timeout)
{
  ssize_t len;
  int     ifd = sh_inotify_getfd();

  len = sl_read_timeout_fd (ifd, buffer, count, timeout, S_FALSE);

  return len;
}


static void sh_inotify_free_watch(void * item)
{
  sh_watch * this = (sh_watch *) item;

  if (this->file)
    SH_FREE(this->file);
  SH_FREE(this);
  return;
}

static sh_watch * sh_inotify_create_watch(const char * file, 
					  int nwatch, int flag)
{
  sh_watch * this = SH_ALLOC(sizeof(sh_watch));

  this->file  = sh_util_strdup_track(file, __FILE__, __LINE__);
  this->watch = nwatch;
  this->flag  = flag;
  return this;
}

/********** List Handling ******************/

struct sh_inotify_litem
{
  sh_watch * watch;
  struct sh_inotify_litem * next;
};

static void sh_inotify_listitem_destroy(struct sh_inotify_litem * this)
{
  if (this)
    SH_FREE(this);
  return;
}

/* No Mutex in the list cursor functions, must be in the caller
 * function...
 */
typedef struct {
  struct sh_inotify_litem *prenode;
  struct sh_inotify_litem *curnode;
} sh_inotify_listCursor;

static sh_watch * sh_inotify_list_first(sh_inotify_listCursor * listcursor, 
					sh_watches * watches)
{
  listcursor->prenode = watches->dormant_watches;
  listcursor->curnode = watches->dormant_watches;

  if (listcursor->curnode)
    return listcursor->curnode->watch;
  return NULL;
}

static sh_watch * sh_inotify_list_next(sh_inotify_listCursor * listcursor, 
				       sh_watches * watches)
{
  (void) watches;

  listcursor->prenode = listcursor->curnode;

  if (listcursor->curnode)
    {
      listcursor->curnode = listcursor->curnode->next;
      if (listcursor->curnode)
	return listcursor->curnode->watch;
      else
	return NULL;
    }

  return NULL;
}

static sh_watch * sh_inotify_list_del_cur(sh_inotify_listCursor * listcursor, 
					  sh_watches * watches)
{
  sh_watch * ret = NULL;

  if (listcursor->curnode)
    {
      struct sh_inotify_litem * this = listcursor->curnode;

      if (listcursor->prenode == this)
	{
	  watches->dormant_watches = this->next;

	  listcursor->prenode = watches->dormant_watches;
	  listcursor->curnode = watches->dormant_watches;
	}
      else
	{
	  listcursor->prenode->next = this->next;
	  listcursor->curnode       = this->next;
	}
      if (listcursor->curnode)
	ret = listcursor->curnode->watch;
      else
	ret = NULL;
      sh_inotify_listitem_destroy(this);
    }
  return ret;
}

static int sh_inotify_add_dormant(sh_watches * watches, sh_watch * item)
{
  struct sh_inotify_litem * this;

  SH_MUTEX_LOCK(mutex_list_dormant);
  this = SH_ALLOC(sizeof(struct sh_inotify_litem));

  this->watch = item;
  this->next  = (struct sh_inotify_litem *) watches->dormant_watches;
  
  watches->dormant_watches = this;
  SH_MUTEX_UNLOCK(mutex_list_dormant);
  return 0;
}

static void * sh_dummy_popret = NULL;

char * sh_inotify_pop_dormant(sh_watches * watches, 
			      int * class, unsigned long * check_flags, 
			      int * type, int * rdepth)
{
  char * popret = NULL;
  struct sh_inotify_litem * this;

  /* Take the address to keep gcc from putting it into a register. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_popret = (void *) &popret;

  SH_MUTEX_LOCK(mutex_list_dormant);

  this = (struct sh_inotify_litem *) watches->dormant_watches;

  if (this)
    {
      *class  = this->watch->class;
      *type   = this->watch->type;
      *rdepth = this->watch->rdepth;
      *check_flags = this->watch->check_flags;
      popret  = sh_util_strdup_track(this->watch->file, __FILE__, __LINE__);

      watches->dormant_watches = this->next;

      sh_inotify_free_watch(this->watch);
      SH_FREE(this);
    }
  SH_MUTEX_UNLOCK(mutex_list_dormant);

  sh_dummy_popret = NULL;
  return popret;
}

void sh_inotify_purge_dormant(sh_watches * watches)
{
  struct sh_inotify_litem * this;

  SH_MUTEX_LOCK(mutex_list_dormant);
  this = (struct sh_inotify_litem *) watches->dormant_watches;

  watches->dormant_watches = NULL;

  while (this)
    {
      struct sh_inotify_litem * cur = this;
      
      this = this->next;

      sh_inotify_free_watch(cur->watch);
      SH_FREE(cur);
    }
  SH_MUTEX_UNLOCK(mutex_list_dormant);
  return;
}

/********** End List Handling **************/

static zAVLKey sh_inotify_getkey(void const *item)
{
  return (&((const sh_watch *)item)->watch);
}

void sh_inotify_close()
{
  int     ifd = sh_inotify_getfd();

  if (ifd >= 0)
    close(ifd);
  sh_set_inotify_fd(-1);

  return;
}

  
/* This function removes all watches from the list,
 * and closes the inode file descriptor in this thread.
 */
void sh_inotify_remove(sh_watches * watches)
{
  zAVLTree   * all_watches;

  SH_MUTEX_LOCK(mutex_watches);
  all_watches = (zAVLTree *)(watches->list_of_watches);

  if (all_watches)
    zAVLFreeTree(all_watches, sh_inotify_free_watch);

  watches->list_of_watches = NULL;
  watches->count = 0;
  SH_MUTEX_UNLOCK(mutex_watches);

  sh_inotify_close();
  return;
}

static int index_watched_file(char * filename, sh_watches * watches)
{
  sh_watch   * item;
  zAVLCursor   avlcursor;
  zAVLTree   * all_watches = (zAVLTree *)(watches->list_of_watches);

  if (all_watches)
    {
      for (item = (sh_watch *) zAVLFirst(&avlcursor, all_watches); item;
	   item = (sh_watch *) zAVLNext(&avlcursor))
	{
	  if (item->file)
	    {
	      if (0 == strcmp(filename, item->file))
		return item->watch;
	    }
	}
    }
  return -1;
}

#if !defined(IN_DONT_FOLLOW)
#define IN_DONT_FOLLOW 0
#endif

#define SH_INOTIFY_FILEFLAGS \
  (IN_ATTRIB|IN_MODIFY|IN_DELETE_SELF|IN_MOVE_SELF|IN_UNMOUNT|IN_DONT_FOLLOW)
#define SH_INOTIFY_DIRFLAGS \
  (SH_INOTIFY_FILEFLAGS|IN_DELETE|IN_CREATE|IN_MOVED_FROM|IN_MOVED_TO)

#define SH_INOTIFY_FLAGS (SH_INOTIFY_FILEFLAGS|SH_INOTIFY_DIRFLAGS)


/* Create an item and put it on the 'dormant' list for later watch creation 
 */
int sh_inotify_add_watch_later(const char * filename, sh_watches * watches, 
			       int * errnum,
			       int class, unsigned long check_flags, int type, 
			       int rdepth)
{
  sh_watch   * item;

  item = sh_inotify_create_watch(filename, -1, /* flag */ 0);

  item->class      = class;
  item->type       = (short) type;
  item->rdepth     = (short) rdepth;
  item->check_flags = check_flags;

  sh_inotify_add_dormant(watches, item);
  if (errnum)
    *errnum = 0;

  return 0;
}
	  
int sh_inotify_rm_watch (sh_watches * watches, sh_watches * save, int wd)
{
  int ifd = sh_get_inotify_fd();

  if (watches)
    {
      sh_watch   * item;
  
      SH_MUTEX_LOCK(mutex_watches);
      item = zAVLSearch(watches->list_of_watches, &wd);
      
      if (item)
	{
	  zAVLDelete(watches->list_of_watches, &wd);
	  if (save) /* optionally save the item */
	    {
	      item->watch = -1;
	      sh_inotify_add_dormant(save, item);
	    }
	  else
	    {
	      sh_inotify_free_watch(item);
	    }
	}
      SH_MUTEX_UNLOCK(mutex_watches);
    }
  return inotify_rm_watch(ifd, wd);
}

#if (defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)) 
static void * sh_dummy_litem;

int sh_inotify_recheck_watches (sh_watches * watches, sh_watches * save)
{
  sh_watch   * litem;
  sh_inotify_listCursor listcursor;
  int ifd = sh_get_inotify_fd();

  extern void sh_fInotify_report_add(char * path, 
				     int class, unsigned long check_flags);

  sh_dummy_litem = (void*) &litem;

  /* -- Check dormant watches for reopening.
   */
  SH_MUTEX_LOCK(mutex_list_dormant);
  
  litem = sh_inotify_list_first(&listcursor, save);

  while (litem)
    {
    have_next:

      /* sh_inotify_list_del_cur may return NULL */
      if (litem && litem->file && litem->watch == -1)
	{
	  litem->watch = inotify_add_watch (ifd, litem->file, 
					    SH_INOTIFY_FLAGS);
	  
	  if (litem->watch >= 0)
	    {
	      SH_MUTEX_LOCK(mutex_watches);
	      if (watches->list_of_watches)
		zAVLInsert(watches->list_of_watches, litem);
	      SH_MUTEX_UNLOCK(mutex_watches);

	      sh_fInotify_report_add(litem->file, litem->class, litem->check_flags);

	      litem = sh_inotify_list_del_cur(&listcursor, save);
	      
	      goto have_next;
	    }
	}
      litem = sh_inotify_list_next(&listcursor, save);
    }
  SH_MUTEX_UNLOCK(mutex_list_dormant);
  return 0;
}
#endif

/* This function is idempotent; it will add the watch only once 
 */
int sh_inotify_add_watch(char * filename, sh_watches * watches, int * errnum,
			 int class, unsigned long check_flags, int type, int rdepth)
{
  volatile int retval = 0;

  SH_MUTEX_LOCK(mutex_watches);

  *errnum = 0;

  if (filename)
    {
      int nwatch;
      sh_watch   * item;
      int index = index_watched_file(filename, watches);
      
      if (index < 0)
	{
	  int     ifd = sh_inotify_getfd();

	  /*************************************

	  if (watches->count == SH_INOTIFY_MAX)
	    {
#ifdef EMFILE
	      *errnum = EMFILE;
#else
	      *errnum = 24;
#endif
	      return -1;
	    }
	  **************************************/

	  nwatch = inotify_add_watch (ifd, filename, 
				      SH_INOTIFY_FLAGS);
	  if (nwatch < 0)
	    {
	      *errnum = errno;
	      retval = -1;
	      goto retpoint;
	    }

	  item = sh_inotify_create_watch(filename, nwatch, /* flag */ 0);

	  item->class      = class;
	  item->type       = type;
	  item->rdepth     = rdepth;
	  item->check_flags = check_flags;
	  
	  if (NULL == watches->list_of_watches)
	    watches->list_of_watches = zAVLAllocTree (sh_inotify_getkey, 
						      zAVL_KEY_INT);
 
	  if (watches->list_of_watches)
	    {
	      *errnum =  zAVLInsert((zAVLTree *)(watches->list_of_watches), 
				    item);

	      if (*errnum != 0)
		{
		  /* zAVLInsert returns -1 on malloc() error and 3 if
		   * the node already exists. 
		   */
		  *errnum = (*errnum == -1) ? ENOMEM : EEXIST;
		  sh_inotify_free_watch(item);
		  retval = -1;
		  goto retpoint;
		}
	    }
	  else
	    {
	      *errnum = ENOMEM;
	      sh_inotify_free_watch(item);
	      retval = -1;
	      goto retpoint;
	    }

	  ++(watches->count);
	}
      else if (type == SH_INOTIFY_DIR) /* watch exists */
	{
	  /* This covers the case that a directory has been added,
	   * but is watched as file at first because it is also
	   * specified as file in the config.
	   */
	  item = zAVLSearch(watches->list_of_watches, &index);

	  if (item && item->type == SH_INOTIFY_FILE)
	    {
	      item->type = SH_INOTIFY_DIR;
	    }
	}
    }
 retpoint:
  ; /* 'label at end of compound statement' */
  SH_MUTEX_UNLOCK(mutex_watches);
  return retval;
}

static void * sh_dummy_sret = NULL;

char * sh_inotify_search_item(sh_watches * watches, int watch, 
			      int * class, unsigned long * check_flags, 
			      int * type, int * rdepth)
{
  sh_watch * item;
  char     * sret = NULL;

  /* Take the address to keep gcc from putting it into a register. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_sret = (void *) &sret;

  SH_MUTEX_LOCK(mutex_watches);
  item = zAVLSearch(watches->list_of_watches, &watch);

  if (item)
    {
      *class      = item->class;
      *check_flags = item->check_flags;
      *type       = item->type;
      *rdepth     = item->rdepth;
      sret = sh_util_strdup_track(item->file, __FILE__, __LINE__);
    }
  SH_MUTEX_UNLOCK(mutex_watches);
  return sret;
}

static void * sh_dummy_litem = NULL;

int sh_inotify_wait_for_change(char * filename, sh_watches * watches, 
			       int  * errnum, int waitsec)
{
  sh_watch   * litem;
  sh_watch   * zitem;
  int          ifd = sh_inotify_getfd();

  /* Take the address to keep gcc from putting it into a register. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_litem = (void*) &litem;

  *errnum = 0;

 start_it:

  if (ifd >= 0)
    {
      volatile ssize_t  i  = 0;
      ssize_t len = -1;
      int  flag = 0;
      char buffer[1024];

      sh_inotify_listCursor listcursor;

      /* -- Add watch if required 
       */
      if (filename)
	{
	  if (sh_inotify_add_watch(filename, watches, errnum, 
				   0, 0, SH_INOTIFY_FILE, 0) < 0)
	    {
	      retry_msleep(waitsec, 0);
	      return -1;
	    }
	}

      /* -- Check dormant watches for reopening.
       */
      SH_MUTEX_LOCK(mutex_list_dormant);

      for (litem = sh_inotify_list_first(&listcursor, watches); litem;
	   litem = sh_inotify_list_next(&listcursor, watches))
	{
	have_next:
	  /* sh_inotify_list_del_cur may return NULL */
	  if (litem && litem->file && litem->watch == -1)
	    {
	      litem->watch = inotify_add_watch (ifd, litem->file, 
						SH_INOTIFY_FLAGS);

	      if (litem->watch >= 0)
		{
		  SH_MUTEX_LOCK(mutex_watches);
		  if (watches->list_of_watches)
		    zAVLInsert(watches->list_of_watches, litem);
		  SH_MUTEX_UNLOCK(mutex_watches);
		  litem = sh_inotify_list_del_cur(&listcursor, watches);
		  goto have_next;
		}
	    }
	}
      SH_MUTEX_UNLOCK(mutex_list_dormant);


      /* -- Blocking read on inotify file descriptor
       */
      len = sh_inotify_read(buffer, sizeof(buffer));

      if (len > 0)
	{
	  struct inotify_event *event;

	  i = 0;
	  
	  while (i < len) {

	    event = (struct inotify_event *) &buffer[i];

	    SH_MUTEX_LOCK(mutex_watches);
	    zitem = zAVLSearch(watches->list_of_watches, &(event->wd));

	    if (zitem)
	      {
		if (event->mask & IN_MODIFY)
		  {
		    zitem->flag |= SH_INOTIFY_MODIFY;
		    flag |= SH_INOTIFY_MODIFY;
		  }
		else if (event->mask & IN_DELETE_SELF || 
			 event->mask & IN_UNMOUNT     || 
			 event->mask & IN_MOVE_SELF   )
		  {
		    zitem->flag |= SH_INOTIFY_REOPEN;
		    (void) inotify_rm_watch(ifd, zitem->watch);
		    zAVLDelete(watches->list_of_watches, zitem);
		    sh_inotify_add_dormant(watches, zitem);
		    zitem->watch    = -1;
		    flag |= SH_INOTIFY_REOPEN;
		  }
	      }
	    SH_MUTEX_UNLOCK(mutex_watches);
	    
	    i += sizeof (struct inotify_event) + event->len;
	  }
	}
      else if (len == -1)
	{
	  *errnum = errno;
	  retry_msleep(waitsec, 0);

	  return -1;
	}

      if (flag & SH_INOTIFY_REOPEN)
	{
	  if (flag & SH_INOTIFY_MODIFY)
	    return 0;
	  else
	    goto start_it;
	}

      return 0;
    }

  /* Inotify not working, sleep
   */
  retry_msleep(waitsec, 0);

  *errnum = 0;
  return -1;
}


/* !defined(HAVE_SYS_INOTIFY_H) */
#else

#include "sh_calls.h"
#include "sh_inotify.h"

void sh_inotify_remove(sh_watches * watches)
{
  (void) watches;
  return;
}

int sh_inotify_wait_for_change(char * filename, sh_watches * watches,
			       int *  errnum, int waitsec)
{
  (void) filename;
  (void) watches;

  /* Inotify not working, sleep for waitsec seconds
   */
  retry_msleep(waitsec, 0);

  if (errnum)
    *errnum = 0;
  return -1;
}

int sh_inotify_add_watch(char * filename, sh_watches * watches, int  * errnum,
			 int class, unsigned long check_flags, int type, int rdepth)
{
  (void) filename;
  (void) watches;
  (void) class;
  (void) check_flags;
  (void) type;
  (void) rdepth;

  if (errnum)
    *errnum = 0;
  return 0;
}

int sh_inotify_add_watch_later(const char * filename, sh_watches * watches, 
			       int  * errnum,
			       int class, unsigned long check_flags, int type, int rdepth)
{
  (void) filename;
  (void) watches;
  (void) class;
  (void) check_flags;
  (void) type;
  (void) rdepth;

  if (errnum)
    *errnum = 0;
  return 0;
}

#endif

#ifdef SH_CUTEST
#include "CuTest.h"
void Test_inotify(CuTest *tc) {
#if defined(HAVE_SYS_INOTIFY_H) && (defined(SH_WITH_CLIENT) || defined(SH_STANDALONE))

  int          ret;
  sh_watches   twatch = SH_INOTIFY_INITIALIZER;
  sh_watch   * litem;
  sh_inotify_listCursor listcursor;
  char * p;
  int class;
  int type;
  int rdepth;
  unsigned long check_flags;
  int           nrun = 0;

  sh_watch aw1 = { -1, 0, 0, 1, 99, 1, "a1" };
  sh_watch aw2 = { -1, 0, 0, 2, 99, 1, "a2" };
  sh_watch aw3 = {  2, 0, 0, 3, 99, 1, "a3" };
  sh_watch aw4 = { -1, 0, 0, 4, 99, 1, "a4" };
  sh_watch aw5 = {  5, 0, 0, 5, 99, 1, "a5" };

  do {

    int          count = 0;

    sh_watch * w1 = SH_ALLOC(sizeof(sh_watch));
    sh_watch * w2 = SH_ALLOC(sizeof(sh_watch));
    sh_watch * w3 = SH_ALLOC(sizeof(sh_watch));
    sh_watch * w4 = SH_ALLOC(sizeof(sh_watch));
    sh_watch * w5 = SH_ALLOC(sizeof(sh_watch));

    memcpy(w1, &aw1, sizeof(sh_watch));
    w1->file = sh_util_strdup(aw1.file);
    memcpy(w2, &aw2, sizeof(sh_watch));
    w2->file = sh_util_strdup(aw2.file);
    memcpy(w3, &aw3, sizeof(sh_watch));
    w3->file = sh_util_strdup(aw3.file);
    memcpy(w4, &aw4, sizeof(sh_watch));
    w4->file = sh_util_strdup(aw4.file);
    memcpy(w5, &aw5, sizeof(sh_watch));
    w5->file = sh_util_strdup(aw5.file);
    
    ret = sh_inotify_add_dormant(&twatch, w1);
    CuAssertIntEquals(tc, ret, 0);
    ret = sh_inotify_add_dormant(&twatch, w2);
    CuAssertIntEquals(tc, ret, 0);
    ret = sh_inotify_add_dormant(&twatch, w3);
    CuAssertIntEquals(tc, ret, 0);
    ret = sh_inotify_add_dormant(&twatch, w4);
    CuAssertIntEquals(tc, ret, 0);
    ret = sh_inotify_add_dormant(&twatch, w5);
    CuAssertIntEquals(tc, ret, 0);
    
    /* -- Check dormant watches for reopening.
     */
    for (litem = sh_inotify_list_first(&listcursor, &twatch); litem;
	 litem = sh_inotify_list_next(&listcursor, &twatch))
      {
      have_next:
	
	/* sh_inotify_list_del_cur may return NULL */
	if (litem)
	  {
	    ++count;
	    
	    if (litem->file && litem->watch == -1)
	      {
		
		switch (litem->class)
		  {
		  case 1:
		    CuAssertStrEquals(tc, litem->file, "a1");
		    break;
		  case 2:
		    CuAssertStrEquals(tc, litem->file, "a2");
		    break;
		  case 3:
		    CuAssertStrEquals(tc, litem->file, "deadbeef");
		    break;
		  case 4:
		    CuAssertStrEquals(tc, litem->file, "a4");
		    break;
		  case 5:
		    CuAssertStrEquals(tc, litem->file, "deadbeef");
		    break;
		  default:
		    CuAssertStrEquals(tc, litem->file, "deadbeef");
		  }
		litem = sh_inotify_list_del_cur(&listcursor, &twatch);
		goto have_next;
	      }
	    switch (litem->class)
	      {
	      case 3:
		CuAssertStrEquals(tc, litem->file, "a3");
		break;
	      case 5:
		CuAssertStrEquals(tc, litem->file, "a5");
		break;
	      default:
		CuAssertStrEquals(tc, litem->file, "foobar");
	      }      
	  }
      }
    
    CuAssertIntEquals(tc, count, 5);
    
    p = sh_inotify_pop_dormant(&twatch, &class, &check_flags, &type, &rdepth);
    CuAssertStrEquals(tc, p, "a5");
    
    p = sh_inotify_pop_dormant(&twatch, &class, &check_flags, &type, &rdepth);
    CuAssertStrEquals(tc, p, "a3");
    CuAssertIntEquals(tc, class, 3);
    
    p = sh_inotify_pop_dormant(&twatch, &class, &check_flags, &type, &rdepth);
    CuAssertTrue(tc, NULL == p);
    CuAssertTrue(tc, NULL == twatch.dormant_watches);

    ++nrun;

  } while (nrun < 100);

#else
  (void) tc;
#endif

  return;
}
#endif
