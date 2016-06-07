/*
 * File: sh_userfiles.c
 * Desc: A module for Samhain; adds files in user directories to the check list
 * Auth: Jerry Connolly <jerry.connolly@eircom.net>
 */
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
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>

#include "samhain.h"
#include "sh_modules.h"
#include "sh_userfiles.h"
#include "sh_utils.h"
#include "sh_schedule.h"
#include "sh_error.h"
#include "sh_hash.h"
#include "sh_files.h"
#define SH_NEED_PWD_GRP 1
#include "sh_static.h"
#include "sh_pthread.h"

#ifdef SH_USE_USERFILES

#define FIL__  _("sh_userfiles.c")

/* We won't want to build this into yule */
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)

static int    ShUserfilesActive   = S_TRUE;

struct userfileslist {
    char filename[PATH_MAX];
    int level;

    struct userfileslist *next;
};

struct userhomeslist {
    char *pw_dir;
    
    struct userhomeslist *next;
};

struct useruidlist {
  unsigned long lower;
  unsigned long upper;
  struct useruidlist *next;
};

static struct userfileslist *userFiles = NULL;
static struct userhomeslist *userHomes = NULL;
static struct useruidlist   *userUids  = NULL;

static void sh_userfiles_free_fileslist(struct userfileslist *head);
static void sh_userfiles_free_homeslist(struct userhomeslist *head);
static void sh_userfiles_free_uidslist (struct useruidlist   *head);

sh_rconf sh_userfiles_table[] = {
    {
        N_("userfilesname"),
        sh_userfiles_add_file,
    },
    {
        N_("userfilesactive"),
        sh_userfiles_set_active,
    },
    {
        N_("userfilescheckuids"),
        sh_userfiles_set_uid,
    },
    {
        NULL,
        NULL
    }
};

static int sh_userfiles_check_uid (unsigned long uid)
{
  struct useruidlist * uids = userUids;

  /* default is to include all
   */
  if (userUids == NULL)
    return 1;

  while (uids)
    {
      if ((uids->upper != 0) && (uid >= uids->lower) && (uid <= uids->upper))
	return 1;
      if ((uids->upper == 0) && (uid == uids->lower))
	return 1;
      uids = uids->next;
    }
  return 0;
}
  
int sh_userfiles_set_uid (const char * str)
{
  char * end;
  const  char * p = str;
  unsigned long lower;
  unsigned long upper = 0;
  struct useruidlist * uids;

  while ((p != NULL) && (*p != '\0'))
    {
      lower = strtoul(p, &end, 10);
      if ( (lower == ULONG_MAX) || (end == p))
	return -1;
      p = end;
      if (*p == '-')
	{ 
	  ++p;
	  if (*p == '\0')
	    {
	      upper = ULONG_MAX;
	      p     = NULL;
	    }
	  else
	    {
	      upper = strtoul(p, &end, 10);
	      if ( (upper == ULONG_MAX) || (end == p))
		return -1;
	      p = end;
	      if ( (*p != ',') && (*p != '\0'))
		return -1;
	      if (*p != '\0') 
		++p;
	    }
	}
      else if (*p == '\0')
	{
	  upper = 0;
	  p     = NULL;
	}
      else if ((*p == ',') || (*p == ' ') || (*p == '\t'))
	{
	  upper = 0;
	  ++p;
	}
      else
	{
	  upper = strtoul(p, &end, 10);
	  if ( (upper == ULONG_MAX) || (end == p))
	    return -1;
	  p = end;
	  if ( (*p != ',') && (*p != ' ') && (*p != '\t') && (*p != '\0') )
	    return -1;
	  if (*p != '\0') 
	    ++p;
	}
      uids = SH_ALLOC(sizeof(struct useruidlist));
      uids->lower = lower;
      uids->upper = upper;
      uids->next  = userUids;
      userUids = uids;
      /* fprintf(stderr, "range %lu %lu\n", lower, upper); */
    }
  return 0;
}

/* Add 'c' to the list of files (userFiles) relative to any given HOME
 * directory that should be checked. */

int sh_userfiles_add_file(const char *c) {
    struct userfileslist *new;
    char *s, *orig;
    char *user_filename;

    int  default_level = SH_LEVEL_NOIGNORE;
    char *separator = " ";
    
    SL_ENTER(_("sh_userfiles_add_file"));

    if( c == NULL )
      SL_RETURN(-1, _("sh_userfiles_add_file") );

    s = sh_util_strdup(c); /* Maybe c is needed elsewhere */
    orig = s; 

    user_filename = sh_util_strsep(&s, separator);
	
    if( user_filename == NULL || strlen(user_filename) > PATH_MAX )
      SL_RETURN(-1, _("sh_userfiles_add_file") );
    
    new = SH_ALLOC(sizeof(struct userfileslist));

    (void) sl_strlcpy(new->filename, user_filename, PATH_MAX);
    new->next = userFiles;
    userFiles = new;

    /* order is important here, since 'log' would match on 'glog'
     * So, compare longest strings first */
    if( s == NULL ) /* The default */          new->level = default_level;
    else if ( strstr(s, _("attributes"))!= NULL ) new->level = SH_LEVEL_ATTRIBUTES;
    else if ( strstr(s, _("allignore")) != NULL ) new->level = SH_LEVEL_ALLIGNORE;
    else if ( strstr(s, _("noignore"))  != NULL ) new->level = SH_LEVEL_NOIGNORE;
    else if ( strstr(s, _("logfiles"))  != NULL ) new->level = SH_LEVEL_LOGFILES;
    else if ( strstr(s, _("readonly"))  != NULL ) new->level = SH_LEVEL_READONLY;
    else if ( strstr(s, _("loggrow"))   != NULL ) new->level = SH_LEVEL_LOGGROW;
    else if ( strstr(s, _("user0"))     != NULL ) new->level = SH_LEVEL_USER0;
    else if ( strstr(s, _("user1"))     != NULL ) new->level = SH_LEVEL_USER1;
    else if ( strstr(s, _("user2"))     != NULL ) new->level = SH_LEVEL_USER2;
    else if ( strstr(s, _("user3"))     != NULL ) new->level = SH_LEVEL_USER3;
    else if ( strstr(s, _("user4"))     != NULL ) new->level = SH_LEVEL_USER4;
    else if ( strstr(s, _("prelink"))   != NULL ) new->level = SH_LEVEL_PRELINK;
    else            /* The default */          new->level = default_level;

    SH_FREE(orig);

    SL_RETURN(0, _("sh_userfiles_add_file") );
}

/* Decide if we're active. 
 */
int sh_userfiles_set_active(const char *c) {
    int value;
    
    SL_ENTER(_("sh_userfiles_set_active"));
    value = sh_util_flagval(c, &ShUserfilesActive);
    SL_RETURN((value), _("sh_userfiles_set_active"));
}

/* Build the list of users, then use this to construct the filenames to
 * be checked. */
int sh_userfiles_init(struct mod_type * arg) {
    struct passwd *cur_user;
    struct userhomeslist *end;
    struct userhomeslist *new;
    struct userhomeslist *homes;
    char * filepath;
    (void) arg;

    SL_ENTER(_("sh_userfiles_init"));

    /* We need to free anything allocated by the configuration functions if
     * we find that the module is to be left inactive - otherwise _reconf()
     * won't quite work. */
    if( ShUserfilesActive == S_FALSE ) {
      sh_userfiles_free_homeslist(userHomes);
      sh_userfiles_free_fileslist(userFiles);
      userHomes = NULL;
      userFiles = NULL;
      SL_RETURN(-1, _("sh_userfiles_init"));
    }

    /* We build a list in here because the samhain internals want to use
     * getpwent() too */
    SH_MUTEX_LOCK(mutex_pwent);
    /*@-unrecog@*/
    sh_setpwent();
    /*@+unrecog@*/
    while( ( cur_user = /*@-unrecog@*/sh_getpwent()/*@+unrecog@*/ ) != NULL ) {
        int found = 0;

	if (0 == sh_userfiles_check_uid( (unsigned long) cur_user->pw_uid))
	  continue;

        for( end = userHomes; end != NULL; end = end->next ) {
            if( sl_strcmp( end->pw_dir, cur_user->pw_dir) == 0 ) {
                found = 1; /* Found a match, so flag it and stop searching */
                break;
            }
        }

        if( found == 0 ) {
            /* Didn't find it, so add to the front of the list */
            new = SH_ALLOC(sizeof(struct userhomeslist) );
            new->next = userHomes;
            new->pw_dir = sh_util_strdup(cur_user->pw_dir);

            userHomes = new;
        }
    }
    sh_endpwent();
    SH_MUTEX_UNLOCK(mutex_pwent);

    filepath = SH_ALLOC(PATH_MAX);

    for (homes = userHomes; homes != NULL; homes = homes->next ) {
        struct userfileslist *file_ptr;

        for (file_ptr = userFiles; file_ptr != NULL; file_ptr = file_ptr->next) {
            (void) sl_strncpy(filepath, homes->pw_dir, PATH_MAX);
            (void) sl_strncat(filepath, "/", PATH_MAX);
            (void) sl_strncat(filepath, file_ptr->filename, PATH_MAX);

            switch(file_ptr->level) {
                case SH_LEVEL_READONLY:
                    (void) sh_files_pushfile_ro(filepath);
                    break;
                case SH_LEVEL_LOGFILES:
                    (void) sh_files_pushfile_log(filepath);
                    break;
                case SH_LEVEL_LOGGROW:
                    (void) sh_files_pushfile_glog(filepath);
                    break;
                case SH_LEVEL_NOIGNORE:
                    (void) sh_files_pushfile_noig(filepath);
                    break;
                case SH_LEVEL_ALLIGNORE:
                    (void) sh_files_pushfile_allig(filepath);
                    break;
                case SH_LEVEL_ATTRIBUTES:
                    (void) sh_files_pushfile_attr(filepath);
                    break;
                case SH_LEVEL_USER0:
                    (void) sh_files_pushfile_user0(filepath);
                    break;
                case SH_LEVEL_USER1:
                    (void) sh_files_pushfile_user1(filepath);
                    break;
                case SH_LEVEL_USER2:
                    (void) sh_files_pushfile_user2(filepath);
                    break;
                case SH_LEVEL_USER3:
                    (void) sh_files_pushfile_user3(filepath);
                    break;
                case SH_LEVEL_USER4:
                    (void) sh_files_pushfile_user4(filepath);
                    break;
                case SH_LEVEL_PRELINK:
                    (void) sh_files_pushfile_prelink(filepath);
                    break;
                default: /* Should not reach here */
                    break;
            }
        }
    }

    SH_FREE(filepath);

    SL_RETURN(0, _("sh_userfiles_init"));
}

/* This is pretty much NULL; we don't do anything in our checking routine,
 * so we never need to run it. Just use tcurrent to avoid compiler warnings. */
int sh_userfiles_timer(time_t tcurrent) {
    SL_ENTER(_("sh_userfiles_timer"));
    tcurrent = 0;
    SL_RETURN((int)tcurrent, _("sh_userfiles_timer"));
}

int sh_userfiles_check(void) {
    SL_ENTER(_("sh_userfiles_check"));
    SL_RETURN(0, _("sh_userfiles_check"));
}

/* Free our lists and the associated memory */

int sh_userfiles_cleanup(void) {
    SL_ENTER(_("sh_userfiles_cleanup"));

    sh_userfiles_free_homeslist(userHomes);
    sh_userfiles_free_fileslist(userFiles);
    sh_userfiles_free_uidslist (userUids);

    SL_RETURN(0, _("sh_userfiles_cleanup"));
}

/* As with sh_userfiles_cleanup, but in preparation for re-reading the
 * configuration files */

int sh_userfiles_reconf(void) {
  SL_ENTER(_("sh_userfiles_reconf"));

    sh_userfiles_free_homeslist(userHomes);
    sh_userfiles_free_fileslist(userFiles);
    sh_userfiles_free_uidslist (userUids);

    userHomes = NULL;
    userFiles = NULL;
    userUids  = NULL;

    ShUserfilesActive   = S_TRUE;

    SL_RETURN(0, _("sh_userfiles_reconf"));
}

/* Recurse to the end of the list and then free the data as we return
 * back up towards the start, making sure to free any strdupped strings
 */

static void sh_userfiles_free_homeslist(struct userhomeslist *head) {
    if( head != NULL ) {
        sh_userfiles_free_homeslist(head->next);
        SH_FREE(head->pw_dir);
        SH_FREE(head);
    }
}

/* Recurse to the end of the list and then free the data as we return
 * back up towards the start */

static void sh_userfiles_free_fileslist(struct userfileslist *head) {
    if( head != NULL ) {
        sh_userfiles_free_fileslist(head->next);
        SH_FREE(head);
    }
}

/* Recurse to the end of the list and then free the data as we return
 * back up towards the start */

static void sh_userfiles_free_uidslist(struct useruidlist *head) {
    if( head != NULL ) {
        sh_userfiles_free_uidslist(head->next);
        SH_FREE(head);
    }
}

/* #if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) */
#endif

/* #ifdef SH_USE_USERFILES */
#endif
