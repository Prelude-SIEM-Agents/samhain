/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2008 Rainer Wichmann                                      */
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

#if defined(GCC_VERSION_MAJOR) && !defined(__clang__)
#if (GCC_VERSION_MAJOR > 4) || ((GCC_VERSION_MAJOR == 4) && (GCC_VERSION_MINOR > 8))
#pragma GCC diagnostic ignored "-Wclobbered"
#endif
#endif

#include <string.h>
#include <time.h>

#if defined(SH_WITH_MAIL)

#undef  FIL__
#define FIL__  _("sh_nmail.c")

#include "samhain.h"
#include "sh_pthread.h"
#include "sh_mem.h"
#include "sh_mail.h"
#include "sh_tiger.h"
#include "sh_string.h"
#include "sh_utils.h"
#include "sh_fifo.h"
#include "sh_filter.h"
#include "sh_mail_int.h"

SH_MUTEX_INIT(mutex_listall, PTHREAD_MUTEX_INITIALIZER);
SH_MUTEX_INIT(mutex_flush_l, PTHREAD_MUTEX_INITIALIZER);

/* Pointer to last address */

static struct alias * last = NULL;

/* List of mail recipients */

static struct alias * recipient_list = NULL;

static struct alias * compiled_recipient_list = NULL;
static sh_filter_type compiled_mail_filter = SH_FILT_INIT;

/* List of mail aliases */

static struct alias * alias_list = NULL;

/* List of all recipients */

struct alias * all_recipients = NULL;

/* Check if addr is in list. If list is all_recipients,
 * must iterate over ->all_next instead of ->next
 */
static int check_double (const char * str, struct alias * list, int isAll)
{
  if (str && list)
    {
      struct alias * item = list;

      while (item)
	{
	  if (0 == strcmp(sh_string_str(item->recipient), str))
	    return -1;
	  if (isAll)
	    item = item->all_next;
	  else
	    item = item->next;
	}
    }
  return 0;
}

/* Add recipient to 'list' AND to all_recipients. If
 * it already is in all_recipients, mark it as an alias
 * (isAlias = 1).
 */
struct alias * add_recipient_intern(const char * str, 
				    struct alias * list)
{
  if (str)
    {
      struct alias * new  = SH_ALLOC(sizeof(struct alias));
      new->next           = list;
      new->mx_list        = NULL;
      new->mail_filter    = NULL;
      new->recipient_list = NULL;
      new->severity       = (-1);
      new->send_mail      = 0;
      new->isAlias        = 0;
      new->recipient      = sh_string_new_from_lchar(str, strlen(str));
      list                = new;

      SH_MUTEX_LOCK_UNSAFE(mutex_listall);
      if (0 != check_double(str, all_recipients, S_TRUE))
	{
	  new->isAlias    = 1;
	}
      new->all_next       = all_recipients;
      all_recipients      = new;
      SH_MUTEX_UNLOCK_UNSAFE(mutex_listall);
    }
  return list;
}

int sh_nmail_close_recipient(const char * str)
{
  (void) str;

  if (last)
    {
      last = NULL;
      return 0;
    }
  return -1;
}

/* Add a single recipient. Must not be in in
 * recipient_list already, and not in all_recipients.
 */
int sh_nmail_add_recipient(const char * str)
{
  /* return error if duplicate, or 
   * already defined within an alias list.
   */
  if (0 == check_double(str,  recipient_list, S_FALSE) &&
      0 == check_double(str,  all_recipients, S_TRUE))
    {
      recipient_list = add_recipient_intern(str, recipient_list);
      last           = recipient_list;
      return 0;
    }
  return -1;
}

/* Add a compiled-in address. These share the compiled_mail_filter
 */
int sh_nmail_add_compiled_recipient(const char * str)
{
  if (0 == check_double(str,  compiled_recipient_list, S_FALSE))
    {
      compiled_recipient_list = 
	add_recipient_intern(str, compiled_recipient_list);
      if (compiled_recipient_list)
	compiled_recipient_list->mail_filter = &compiled_mail_filter;
      last           = compiled_recipient_list;
      return 0;
    }
  return -1;
}

/* Add an alias; format is name ":" comma-delimited_list_of_recipients
 */
int sh_nmail_add_alias(const char * str)
{
#define SH_ALIASES_RECP_NUM 256
  size_t lengths[SH_ALIASES_RECP_NUM];
  unsigned int    nfields = SH_ALIASES_RECP_NUM;
  char * new = sh_util_strdup(str);
  char * p   = strchr(new, ':');
  char * q;

  if (p && strlen(p) > 1)
    {
      unsigned int     i;
      char ** array;

      *p = '\0'; q = p; ++p;
      if (strlen(new) > 0)
	{
	  /* strip trailing space
	   */
	  --q; while ((q != new) && *q == ' ') { *q = '\0'; --q; }
	}
      else
	{
	  goto err;
	}

      if (0 == check_double(new, alias_list, S_FALSE))
	{
	  array = split_array_list(p, &nfields, lengths);

	  if (array && nfields > 0)
	    {
	      struct alias * newalias = NULL;

	      /* Enforce that all list members are defined already
	       */
	      int                nflag = 0;

	      for (i = 0; i < nfields; ++i) {
		if (0 == check_double(array[i],  all_recipients, S_TRUE))
		  nflag = 1; /* not in all_recipients --> bad */
	      }

	      if (nflag == 0)
		{
		  newalias                 = SH_ALLOC(sizeof(struct alias));
		  newalias->recipient_list = NULL;
		  newalias->mail_filter    = NULL;
		  newalias->mx_list        = NULL;
		  newalias->severity       = (-1);
		  
		  /* This is the alias */
		  newalias->recipient = sh_string_new_from_lchar(new, strlen(new));
		  
		  for (i = 0; i < nfields; ++i)
		    {
		      if (lengths[i] > 0 && 
			  0 == check_double(array[i], newalias->recipient_list, S_FALSE))
			{
			  newalias->recipient_list = 
			    add_recipient_intern(array[i], newalias->recipient_list);
			}
		    }
		}

	      SH_FREE(array);

	      if (newalias == NULL || newalias->recipient_list == NULL)
		{
		  if (newalias)
		    SH_FREE(newalias);
		  goto err;
		}
      
	      newalias->next = alias_list;
	      alias_list     = newalias;
	      last           = alias_list;

	      SH_FREE(new);
	      return 0;
	    }
	}
    }
 err:
  SH_FREE(new);
  return -1;
}


/* <<<<<<<<<<<<<<< Recipient List >>>>>>>>>>>>>>>>>>>>>> */

static struct alias * find_list (const char * alias, int * single)
{
  struct alias * list   = NULL;

  *single = 0;

  if (!alias)
    {
      list = all_recipients;
    }
  else
    {
      struct alias * test = alias_list;
      
      while (test)
	{
	  if (0 == strcmp(alias, sh_string_str(test->recipient)))
	    {
	      list = test->recipient_list;
	      break;
	    }
	  test = test->next;
	}
      
      if (!list)
	{
	  test = recipient_list;
	  while (test)
	    {
	      if (0 == strcmp(alias, sh_string_str(test->recipient)))
		{
		  list   = test;
		  *single = 1;
		  break;
		}
	      test = test->next;
	    }
	}
      
      if (!list)
	{
	  test = compiled_recipient_list;
	  while (test)
	    {
	      if (0 == strcmp(alias, sh_string_str(test->recipient)))
		{
		  list   = test;
		  *single = 1;
		  break;
		}
	      test = test->next;
	    }
	}
    }
  return list;
}

/* Returns zero (no) or one (yes). Used to tag messages that are
 * valid for a given recipient (or mailing list alias).
 */
int sh_nmail_valid_message_for_alias (int level, 
				      const char * message, 
				      const char * alias, 
				      const void * rcv_info)
{
  const struct alias * rcv = (const struct alias *) rcv_info;

  if (!alias || 0 == strcmp(alias, sh_string_str(rcv->recipient)))
    {
      if ((level & rcv->severity) == 0)
	{
	  return 0;
	}

      if (rcv->mail_filter)
	{
	  if (0 != sh_filter_filter(message, rcv->mail_filter))
	    {
	      return 0;
	    }
	}
    }

  return 1;
}

/* Returns number of recipients */

static
int sh_nmail_compute_recipients (int level, const char * message, 
				 const char * alias, int flagit)
{
  struct alias * list   = NULL;
  int            single = 0;
  int            retval = 0;

  if (flagit)
    {
      list = all_recipients;
      while (list)
	{
	  list->send_mail = 0;
	  list = list->all_next;
	}
      list = NULL;
    }

  if (message)
    {
      int flag = 0;

      list = find_list (alias, &single);
      if (list == all_recipients)
	flag = 1;

      while (list)
	{
	  /* Check severity 
	   */
	  if ((list->severity & level) == 0)
	    {
	      if (single) break;
	      if (flag)
		list = list->all_next;
	      else
		list = list->next;
	      continue;
	    }

	  /* Check filter
	   */
	  if (list->mail_filter &&
	      0 != sh_filter_filter(message, list->mail_filter))
	    {
	      if (single) break;
	      if (flag)
		list = list->all_next;
	      else
		list = list->next;
	      continue;
	    }
	  
	  /* Mark the entry
	   */
	  if (flag)
	    {
	      /* Don't mark aliases
	       */
	      if (flagit && list->isAlias == 0)
		{
		  list->send_mail = 1;
		}
	      list = list->all_next;
	    }
	  else
	    {
	      if (flagit)
		  list->send_mail = 1;
	      list = list->next;
	    }
	  ++retval;
	}
    }
  return retval;
}

/* Is not called from same(recursively) or different thread
 */
static
int sh_nmail_flag_recipients (int level, const char * message, 
			      const char * alias)
{
  int retval = 0;

  if (message)
    {
      SH_MUTEX_LOCK_UNSAFE(mutex_listall);
      retval = sh_nmail_compute_recipients (level, message, alias, 1);
      SH_MUTEX_UNLOCK_UNSAFE(mutex_listall);
    }
  return retval;
}

/* Can be called from same thread with mutex_listall held via sh_nmail_flush()
 */
static
int sh_nmail_test_recipients (int level, const char * message, 
			      const char * alias)
{
  int retval = 0;

  if (message)
    {
      if (0 == SH_MUTEX_TRYLOCK_UNSAFE(mutex_flush_l))
	{
	  SH_MUTEX_LOCK_UNSAFE(mutex_listall);
	  retval = sh_nmail_compute_recipients (level, message, alias, 0);
	  SH_MUTEX_UNLOCK_UNSAFE(mutex_listall);
	  SH_MUTEX_UNLOCK_UNSAFE(mutex_flush_l);
	}
    }
  return retval;
}

/* <<<<<<<<<<<<<<<<<<<  Mail the message  >>>>>>>>>>>>>>>>>>>>>> */

SH_MUTEX_RECURSIVE(mutex_nmail_msg);
SH_MUTEX_STATIC(nmail_lock, PTHREAD_MUTEX_INITIALIZER);

/*
 * First test list of recipients, then call sh_mail_pushstack().
 */
int sh_nmail_pushstack (int level, const char * message, 
			const char * alias)
{
  int retval = 0;

  if (0 != sh_nmail_test_recipients (level, message, alias))
    {
      retval = sh_mail_pushstack(level, message, alias);
    }
  return retval;
}

static int nmail_count = 0;

/*
 * First mark list of recipients, then call sh_mail_msg().
 */
int sh_nmail_msg (int level, const char * message, 
		  const char * alias)
{
  volatile int retval = 0;

  /* Need to:
   *   -- wait if different thread, and
   *   -- fail if same thread. */
  SH_MUTEX_RECURSIVE_INIT(mutex_nmail_msg);
  SH_MUTEX_RECURSIVE_LOCK(mutex_nmail_msg);

  /* Only same thread beyond this point. We fail
   * if count > 0 already. */
  if (0 == SH_MUTEX_TRYLOCK_UNSAFE(nmail_lock))
    {
      ++nmail_count;
      if (nmail_count != 1)
	{
	  --nmail_count;
	  SH_MUTEX_UNLOCK_UNSAFE(nmail_lock);
	  goto cleanup;
	}
      SH_MUTEX_UNLOCK_UNSAFE(nmail_lock);

      if (0 != sh_nmail_flag_recipients (level, message, alias))
	{
	  /* Need to keep info for sh_nmail_pushstack() 
	   */
	  SH_MUTEX_LOCK(mutex_listall);
	  retval = sh_mail_msg(message);
	  SH_MUTEX_UNLOCK(mutex_listall);

	  if (retval != 0)
	    {
	      sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 
			       retval, MSG_E_SUBGEN,
			       _("could not mail immediately"),
			       _("sh_nmail_msg") );
	      sh_mail_pushstack(level, message, alias);
	    }
	}
      SH_MUTEX_LOCK_UNSAFE(nmail_lock);
      --nmail_count;
      SH_MUTEX_UNLOCK_UNSAFE(nmail_lock);
    }
 cleanup:
  ; /* label at end of compound statement */
  SH_MUTEX_RECURSIVE_UNLOCK(mutex_nmail_msg);
  return retval;
}

static int sh_nmail_flush_int (void);

int sh_nmail_flush ()
{
  int                retval = 0;

  if (0 == SH_MUTEX_TRYLOCK_UNSAFE(nmail_lock))
    {
      ++nmail_count;
      if (nmail_count != 1)
	{
	  --nmail_count;
	  SH_MUTEX_UNLOCK_UNSAFE(nmail_lock);
	  return retval;
	}
      SH_MUTEX_UNLOCK_UNSAFE(nmail_lock);

      retval = sh_nmail_flush_int ();

      SH_MUTEX_LOCK_UNSAFE(nmail_lock);
      --nmail_count;
      SH_MUTEX_UNLOCK_UNSAFE(nmail_lock);
    }
  return retval;
}

/* warning: variable ‘list’ might be clobbered by ‘longjmp’ or ‘vfork’*/
static struct alias ** list_dummy;

/*
 * Loop over all recipients in stack. 
 * For each distinct one, mark all messages for sending. 
 * Then call sh_mail_msg().
 */

static int sh_nmail_flush_int ()
{
  int                retval = 0;
  sh_string *        msg    = NULL;
  sh_string *        smsg   = NULL;
  struct alias     * list;
  struct alias     * dlist;

  /* warning: variable ‘list’ might be clobbered by ‘longjmp’ or ‘vfork’*/
  list_dummy = &list;

  SH_MUTEX_LOCK(mutex_listall);

  /* Reset recipient list
   */
  list = all_recipients;
  while (list)
    {
      list->send_mail = 0;
      list = list->all_next;
    }

  /* Check (i) compiled recipients, (b) aliases, (c) single recipients.
   * For each, tag all messages, then call sh_mail_msg with
   *  appropriate address list.
   */

  reset_list(fifo_mail);

  /* Compiled recipients. These share threshold and filter,
   * hence only the first recipient needs to be tested.
   */
  list  = compiled_recipient_list;

  if (list)
    {
      msg   = tag_list(fifo_mail, sh_string_str(list->recipient),
		       sh_nmail_valid_message_for_alias, list, S_TRUE);
    }

  if (msg)
    {
      while (list)
	{
	  list->send_mail = 1;
	  list = list->next;
	}
      
      list = compiled_recipient_list;
      
      SH_MUTEX_LOCK(mutex_flush_l);
      (void) sh_mail_msg(sh_string_str(msg));
      SH_MUTEX_UNLOCK(mutex_flush_l);

      sh_string_destroy(&msg);
      
      list = compiled_recipient_list;
      while (list)
	{
	  list->send_mail = 0;
	  list = list->next;
	}
    }

  /* Aliases
   */
  list  = alias_list;

  while (list) {

    /* Work through the recipient list. As smsg stores last msg,
     * we send a batch whenever msg != smsg, and continue from
     * that point in the recipient list.
     */
    struct alias     * lnew;

    while (list)
      {
	msg   = tag_list(fifo_mail, sh_string_str(list->recipient),
			 sh_nmail_valid_message_for_alias, list, S_FALSE);

	if (msg)
	  {
	    if (!smsg) /* init */
	      {
		smsg      = sh_string_copy(msg);
	      }
	    else
	      {
		if (0 != strcmp(sh_string_str(smsg), sh_string_str(msg)))
		  {
		    /*
		     * Don't set list = list->next here, since we want
		     * to continue with this recipient in the next batch.
		     */
		    sh_string_destroy(&msg);
		    break;
		  }
	      }
	    lnew = list->recipient_list;
	    while (lnew)
	      {
		lnew->send_mail = 1;
		lnew= lnew->next;
	      }
	    sh_string_destroy(&msg);
	  }
	list      = list->next;
      }

    /* Continue here if smsg != msg */

    if (smsg)
      {
	SH_MUTEX_LOCK(mutex_flush_l);
	(void) sh_mail_msg(sh_string_str(smsg));
	SH_MUTEX_UNLOCK(mutex_flush_l);
	sh_string_destroy(&smsg);
      }

    /* Reset old list of recipients (up to current point in list)
     * and then continue with list from current point on.
     */
    dlist  = alias_list;
    while (dlist)
      {
	lnew = dlist->recipient_list;
	while (lnew)
	  {
	    lnew->send_mail = 0;
	    lnew = lnew->next;
	  }
	dlist = dlist->next;
      }
  }


  /* Single recipients
   */
  list  = recipient_list;

  while (list) {

    /* Work through the recipient list. As smsg stores last msg,
     * we send a batch whenever msg != smsg, and continue from
     * that point in the recipient list.
     */

    while (list)
      {
	msg   = tag_list(fifo_mail, sh_string_str(list->recipient),
			 sh_nmail_valid_message_for_alias, list, S_TRUE);

	if (msg)
	  {
	    if (!smsg) /* init */
	      {
		smsg = sh_string_copy(msg);
	      }
	    else
	      {
		if (0 != strcmp(sh_string_str(smsg), sh_string_str(msg)))
		  {
		    /*
		     * Don't set list = list->next here, since we want
		     * to continue with this recipient in the next batch.
		     */
		    sh_string_destroy(&msg);
		    break;
		  }
	      }
	    list->send_mail = 1;
	    sh_string_destroy(&msg);
	  }
	list = list->next;
      }

    /* Continue here if smsg != msg */

    if (smsg)
      {
	SH_MUTEX_LOCK(mutex_flush_l);
	(void) sh_mail_msg(sh_string_str(smsg));
	SH_MUTEX_UNLOCK(mutex_flush_l);
	sh_string_destroy(&smsg);
      }

    /* Reset old list of recipients (up to current point in list)
     * and then continue with list from current point on.
     */
    dlist  = recipient_list;
    while (dlist)
      {
	dlist->send_mail = 0;
	dlist = dlist->next;
      }
  }

  /* Remove all mails for which no recipient failed
   */

  sh.mailNum.alarm_last -= commit_list(fifo_mail);
  SH_MUTEX_UNLOCK(mutex_listall);

  return retval;
}



/* <<<<<<<<<<<<<<<<<<<  Severity  >>>>>>>>>>>>>>>>>>>>>> */

/* 
 * -- set severity threshold for recipient or alias
 */
int sh_nmail_set_severity (const char * str)
{
  if (last == recipient_list || last == alias_list)
    {
      if (0 == sh_error_set_level(str, &(last->severity)))
	{
	  /* All recipients in alias share the severity
	   */
	  if (last == alias_list)
	    {
	      struct alias * ptr = last->recipient_list;

	      while (ptr)
		{
		  ptr->severity = last->severity;
		  ptr = ptr->next;
		}
	    }
	  return 0;
	}
    }
  return (-1);
}

/* <<<<<<<<<<<<<<<<<<<  Filters >>>>>>>>>>>>>>>>>>>>>> */


int sh_nmail_add_generic (const char * str, int flag)
{
  if (last)
    {
      if (NULL == last->mail_filter)
	last->mail_filter = sh_filter_alloc();

      /* All recipients in alias share the mail filter
       */
      if (last == alias_list)
	{
	  struct alias * ptr = last->recipient_list;
	  
	  while (ptr)
	    {
	      ptr->mail_filter = last->mail_filter;
	      ptr = ptr->next;
	    }
	}

      return (sh_filter_add (str, last->mail_filter, flag));
    }
  return (-1);
}

/*
 * -- add keywords to the OR filter
 */
int sh_nmail_add_or (const char * str)
{
  return sh_nmail_add_generic(str, SH_FILT_OR);
}

/*
 * -- add keywords to the AND filter
 */
int sh_nmail_add_and (const char * str)
{
  return sh_nmail_add_generic(str, SH_FILT_AND);
}

/*
 * -- add keywords to the NOT filter
 */
int sh_nmail_add_not (const char * str)
{
  return sh_nmail_add_generic(str, SH_FILT_NOT);
}


/* <<<<<<<<<<<<<<<<<<<  Mailkey per Alias >>>>>>>>>>>>>>>>>>>>>>>>> */

#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
#include <sys/mman.h>
#endif

#include "zAVLTree.h"

zAVLTree        * mailkeys = NULL;

struct alias_mailkey {
  char * alias;
  unsigned int mailcount;
  time_t       id_audit;
  char   mailkey_old[KEY_LEN+1];
  char   mailkey_new[KEY_LEN+1];
};

static zAVLKey sh_nmail_getkey(void const *item)
{
  const struct alias_mailkey * t = (const struct alias_mailkey *) item;
  return (zAVLKey) t->alias;
}

/* Return mailkey for alias. If there's no key yet, create it and
 * store it in the AVL tree.
 * This is called from sh_mail_msg, 
 *    which is called from sh_nmail_msg,
 *        which is protected by a mutex.
 */
int sh_nmail_get_mailkey (const char * alias, char * buf, size_t bufsiz,
			  time_t * id_audit)
{
  char hashbuf[KEYBUF_SIZE];

 start:

  if (mailkeys)
    {
      struct alias_mailkey * t;

      if (!alias)
	t = (struct alias_mailkey *) zAVLSearch (mailkeys, _("(null)"));
      else
	t = (struct alias_mailkey *) zAVLSearch (mailkeys, alias);

      if (t)
	{
	  /* iterate the key
	   */
	  (void) sl_strlcpy(t->mailkey_new,
			    sh_tiger_hash (t->mailkey_old, TIGER_DATA, KEY_LEN,
					   hashbuf, sizeof(hashbuf)),
			    KEY_LEN+1);
	  (void) sl_strlcpy(buf, t->mailkey_new, bufsiz);
	  ++(t->mailcount);
	}
      else
	{
	  t = SH_ALLOC(sizeof(struct alias_mailkey));

	  MLOCK(t, sizeof(struct alias_mailkey));

	  if (!alias)
	    t->alias = sh_util_strdup(_("(null)"));
	  else
	    t->alias = sh_util_strdup(alias);

	  t->mailcount = 0;
	  t->id_audit  = time(NULL);

	  BREAKEXIT(sh_util_keyinit);
	  (void) sh_util_keyinit (t->mailkey_old, KEY_LEN+1);

	  /* iterate the key
	   */
	  (void) sl_strlcpy(t->mailkey_new,
			    sh_tiger_hash (t->mailkey_old, TIGER_DATA, KEY_LEN,
					   hashbuf, sizeof(hashbuf)),
			    KEY_LEN+1);
	  (void) sl_strlcpy(buf, t->mailkey_new, bufsiz);
	  (void) zAVLInsert(mailkeys, t);
	}

      /* X(n) -> X(n-1)
       */
      (void) sl_strlcpy (t->mailkey_old, t->mailkey_new, KEY_LEN+1);

      *id_audit = t->id_audit;

      return (t->mailcount);
    }

  mailkeys = zAVLAllocTree (sh_nmail_getkey, zAVL_KEY_STRING);
  goto start;
}

/* <<<<<<<<<<<<<<<<<<<  Free for Reconfigure >>>>>>>>>>>>>>>>>>>>>> */


static void free_recipient_list(struct alias * list)
{
  struct alias * new;
  sh_filter_type * p = NULL;

  while (list)
    {
      new  = list;
      list = new->next;
      if (new->mx_list)
	free_mx(new->mx_list);
      if (new->mail_filter)
	{
	  sh_filter_free(new->mail_filter);
	  if (!p || p != new->mail_filter)
	    {
	      p = new->mail_filter;
	      SH_FREE(new->mail_filter);
	    }
	}
      sh_string_destroy(&(new->recipient));
      SH_FREE(new);
    }
}

/* Free everything to prepare for reconfigure
 */
void sh_nmail_free()
{
  SH_MUTEX_LOCK_UNSAFE(mutex_listall);
  all_recipients = NULL;
  SH_MUTEX_UNLOCK_UNSAFE(mutex_listall);

  free_recipient_list(recipient_list);
  recipient_list = NULL;

  sh_filter_free(&compiled_mail_filter);

  while (alias_list) 
    {
      struct alias * item = alias_list;

      alias_list = item->next;

      sh_string_destroy(&(item->recipient));
      free_recipient_list(item->recipient_list);
      if (item->mail_filter)
	{
	  sh_filter_free(item->mail_filter);
	  /* SH_FREE(item->mail_filter); */
	}
      SH_FREE(item);
    }
  alias_list = NULL;

  last = compiled_recipient_list;
  return;
}

/* defined(SH_WITH_MAIL) */
#endif
