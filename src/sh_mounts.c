/*
 * File: sh_mounts.c
 * Desc: A module for Samhain; checks for mounts present and options on them.
 * Auth: Cian Synnott <cian.synnott@eircom.net>
 *
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


/* Used in the call tracing macros to keep track of where we are in the code */
#undef  FIL__
#define FIL__  _("sh_mounts.c")


#include "samhain.h"
#include "sh_utils.h"
#include "sh_error.h"
#include "sh_modules.h"
#include "sh_mounts.h"

#ifdef SH_USE_MOUNTS
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 

/*
 * #ifdef HAVE_STRING_H
 * #include <string.h>
 * #endif
 */

#ifdef TM_IN_SYS_TIME
#include <sys/time.h>
#else
#include <time.h>
#endif

/* Prototypes for configuration functions */
int sh_mounts_config_activate (const char * opt);
int sh_mounts_config_timer    (const char * opt);
int sh_mounts_config_mount    (const char * opt);
int sh_mounts_config_sevmnt   (const char * opt);
int sh_mounts_config_sevopt   (const char * opt);

/* Prototype for the function to read info on mounted filesystems */
static struct sh_mounts_mnt *readmounts(void);

/* Table for configuration options, and pointers to the functions that will
 * configure them. Each function is passed the string resulting from stripping
 * the option and the "equals" from the config file; e.g. MountCheckActive=1 in
 * the configuration file will result in the string "1" being passed to
 * sh_mounts_config_activate() */
sh_rconf sh_mounts_table[] = {
  {
    N_("mountcheckactive"),
    sh_mounts_config_activate
  },
  {
    N_("mountcheckinterval"),
    sh_mounts_config_timer
  },
  {
    N_("checkmount"),
    sh_mounts_config_mount
  },
  {
    N_("severitymountmissing"),
    sh_mounts_config_sevmnt
  },
  {
    N_("severityoptionmissing"),
    sh_mounts_config_sevopt
  },
  {
    NULL,
    NULL
  },
};

/* Structures for storing my configuration information, and functions for
 * manipulating them */
struct sh_mounts_mnt {
  char *                 path;
  struct sh_mounts_opt * opts;
  struct sh_mounts_mnt * next;
};

struct sh_mounts_opt {
  char *                 opt;
  struct sh_mounts_opt * next;
};

/* Return the mount structure whose path matches 'mnt' or NULL if not found */
static
struct sh_mounts_mnt *sh_mounts_mnt_member(struct sh_mounts_mnt *m, char *mnt)
{
  struct sh_mounts_mnt *it;

  for (it = m; it != NULL; it = it->next) {
    if (0 == sl_strcmp(it->path, mnt)) {
      return it;
    }
  }
  return NULL;
}

/* Return the opt structure whose option matches 'opt' or NULL if not found */
static
struct sh_mounts_opt *sh_mounts_opt_member(struct sh_mounts_opt *o, char *opt)
{
  struct sh_mounts_opt *it;

  for (it = o; it != NULL; it = it->next) {
    /* if (!strcmp(it->opt, opt)) { */
    if (0 == sl_strcmp(it->opt, opt)) {
      return it;
    }
  }
  return NULL;
}

static
void sh_mounts_opt_free(struct sh_mounts_opt *o) {
  if (o != NULL) {
    sh_mounts_opt_free(o->next);
    SH_FREE(o->opt);
    SH_FREE(o);
  }
}

static
void sh_mounts_mnt_free(struct sh_mounts_mnt *m) {
  if (m != NULL) {
    sh_mounts_mnt_free(m->next);
    sh_mounts_opt_free(m->opts);
    SH_FREE(m->path);
    SH_FREE(m);
  }
}

/* Some configuration variables I'll be using */
static time_t lastcheck         = (time_t) 0;
static int    ShMountsActive    = S_FALSE;
static time_t ShMountsInterval  = 86400;
static int    ShMountsSevMnt    = SH_ERR_ERR;
static int    ShMountsSevOpt    = SH_ERR_ERR;

static struct sh_mounts_mnt *mountlist = NULL;

/* Module initialisation
 * This is called once at the start of each samhain run.
 * Non-configuration setup code should be placed here. */
int sh_mounts_init (struct mod_type * arg)
{
  (void) arg;
  SL_ENTER(_("sh_mounts_init"));

  /* This is a little odd. Because we've built the configured mount list at
   * this point, if we've set the module inactive, we need to free the list -
   * otherwise when we reconf() with it set active, we'll end up with a
   * duplicated list. Interesting. */
  if (ShMountsActive == S_FALSE) {
    sh_mounts_mnt_free(mountlist);
    mountlist = NULL;
    SL_RETURN(-1, _("sh_mounts_init"));
  }

  SL_RETURN(0, _("sh_mounts_init"));
}

/* Module timer
 * This timer function is called periodically with the current time to see if
 * it is time to run the module's "check" function. On nonzero return, the
 * check is run. */
int sh_mounts_timer (time_t tcurrent)
{
  SL_ENTER(_("sh_mounts_timer"));

  if ((time_t) (tcurrent - lastcheck) >= ShMountsInterval) {
    lastcheck = tcurrent;
    SL_RETURN(-1, _("sh_mounts_timer"));
  }
 
  SL_RETURN(0, _("sh_mounts_timer"));
}

/* Module check
 * The business end of things. This is the actual check code for this module.
 * Everything you want to do periodically should go here. */
int sh_mounts_check ()
{
  struct sh_mounts_mnt *memlist;
  struct sh_mounts_mnt *cfgmnt, *mnt;
  struct sh_mounts_opt *cfgopt, *opt;

  SL_ENTER(_("sh_mounts_check"));
    
  /* Log the check run. For each message type you want, you need to define it
   * as an enum in sh_cat.h, and then set it up in terms of priority and format
   * string in sh_cat.c */
  sh_error_handle(-1, FIL__, __LINE__, 0, MSG_MNT_CHECK);

  /* Read the list of mounts from memory */
  memlist = readmounts();

  if (memlist == NULL) {
    sh_error_handle(-1, FIL__, __LINE__, 0, MSG_MNT_MEMLIST);
  }

  /* For each mount we are configured to check, run through the list of mounted
   * filesystems and compare the pathnames */
  for (cfgmnt = mountlist; cfgmnt != NULL; cfgmnt = cfgmnt->next) {
    mnt = sh_mounts_mnt_member(memlist, cfgmnt->path);

    if (mnt) {
      for (cfgopt = cfgmnt->opts; cfgopt != NULL; cfgopt = cfgopt->next) {
        opt = sh_mounts_opt_member(mnt->opts, cfgopt->opt);

        if (!opt) {
          sh_error_handle(ShMountsSevOpt, FIL__, __LINE__, 0, MSG_MNT_OPTMISS, 
                          cfgmnt->path, cfgopt->opt);
        }
      }
    } 

    else {
      sh_error_handle(ShMountsSevMnt, FIL__, __LINE__, 0, MSG_MNT_MNTMISS,
                      cfgmnt->path);
    }
  }

  /* Make sure to clean up after ourselves */
  sh_mounts_mnt_free(memlist);

  SL_RETURN(0, _("sh_mounts_check"));
}

/* Module cleanup
 * The end of the tour - when samhain is shutting down, this is run. */
int sh_mounts_cleanup ()
{
  SL_ENTER(_("sh_mounts_cleanup"));
  sh_mounts_mnt_free(mountlist);
  mountlist = NULL;
  SL_RETURN( (0), _("sh_mounts_cleanup"));
}

/* Module reconfiguration
 * Run on receipt of a HUP.
 */
int sh_mounts_reconf()
{
  SL_ENTER(_("sh_mounts_null"));
  sh_mounts_mnt_free(mountlist);
  mountlist = NULL;

  /* re-set defaults
   */
  ShMountsActive    = S_FALSE;
  ShMountsInterval  = 86400;
  ShMountsSevMnt    = 7;
  ShMountsSevOpt    = 7;

  SL_RETURN( (0), _("sh_mounts_null"));
}

/* Module configuration
 * These functions are called when the configuration file is being parsed. */

/* Configure to check a particular mount */
int sh_mounts_config_mount (const char * opt_in)
{
  struct sh_mounts_mnt *m;
  struct sh_mounts_opt *o;
  char *sp, *temp, *opt;

  SL_ENTER(_("sh_mounts_config_mount"));

  /* It's probably best to make a copy of opt before messing about with it
   * via string functions. Good practice and all that. */
  temp = sh_util_strdup(opt_in);

  /* Since we're going to "consume" this new buffer, it'll be good to have a
   * reference to it's allocated memory so we can free it later. Let's use
   * temp for that, and "opt" for consumption */
  opt = temp;
  
  m = (struct sh_mounts_mnt *) SH_ALLOC(sizeof(struct sh_mounts_mnt));

  /* First, strip out the mount path. */
  m->path = sh_util_strdup(sh_util_strsep(&opt, " \t"));
  m->opts = NULL;

  /* Now get all of the mount options - they can be delimited by comma or
   * whitespace */
  while (opt != NULL) {
    sp = sh_util_strsep(&opt, ", \t");

    /* This just catches multiple separators appearing together */
    if (*sp == '\0') {
	continue;
    }

    o = (struct sh_mounts_opt *) SH_ALLOC(sizeof(struct sh_mounts_opt));
    o->next = m->opts;
    m->opts = o;

    o->opt = sh_util_strdup(sp);
  }
  
  /* Add to the list of configured mounts */
  m->next = mountlist;
  mountlist = m;

  /* Free the string buffer we allocated earlier */
  SH_FREE(temp);

  SL_RETURN(0, _("sh_mounts_config_mount"));
}

/* Simply sets our boolean as to whether this module is active */
int sh_mounts_config_activate (const char * opt)
{
  int i;
  SL_ENTER(_("sh_mounts_config_activate"));
  i = sh_util_flagval(opt, &ShMountsActive);
  SL_RETURN(i, _("sh_mounts_config_activate"));
}

/* Sets up our timer */
int sh_mounts_config_timer (const char * opt)
{
  long val;
  int retval = 0;

  SL_ENTER(_("sh_mounts_config_timer"));
  val = strtol (opt, (char **)NULL, 10);
  if (val <= 0)
    {
      sh_error_handle (-1, FIL__, __LINE__, EINVAL, MSG_EINVALS,
		       _("mounts timer"), opt);
      retval = -1;
    }
  val = (val <= 0 ? 86400 : val);

  ShMountsInterval = (time_t) val;

  SL_RETURN(retval, _("sh_mounts_config_timer"));
}

/* Configure severity for "mount missing" messages */
int sh_mounts_config_sevmnt  (const char * opt)
{
  int retval = 0;
  char tmp[32];
  

  SL_ENTER(_("sh_mounts_config_sevmnt"));
  tmp[0] = '='; tmp[1] = '\0';
  (void) sl_strlcat (tmp, opt, 32);
  retval = sh_error_set_level (tmp, &ShMountsSevMnt);
  SL_RETURN(retval, _("sh_mounts_config_sevmnt"));
}

int sh_mounts_config_sevopt  (const char * opt)
{
  int retval = 0;
  char tmp[32];
  
  SL_ENTER(_("sh_mounts_config_sevopt"));
  tmp[0] = '='; tmp[1] = '\0';
  (void) sl_strlcat (tmp, opt, 32);
  retval = sh_error_set_level (tmp, &ShMountsSevOpt);
  SL_RETURN(retval, _("sh_mounts_config_sevopt"));
}


/*
 * Below here we have the code for actually reading options on mounted fs's
 * I've just got code here to work on FreeBSD, Linux and Solaris. I'm sure
 * others could be added. Note that some small bits of the OS-specific code
 * are from mountlist.c in GNU fileutils.
 */

/* FreeBSD includes */
#if defined(HOST_IS_FREEBSD) || defined(HOST_IS_OPENBSD) 
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#endif

/* Linux includes */
#ifdef HOST_IS_LINUX
#include <stdio.h>
#include <mntent.h>
#endif

/* Solaris includes */
#ifdef HOST_IS_SOLARIS
#include <stdio.h>
#include <sys/mnttab.h>
#endif

/* HP_UX includes */
#ifdef HOST_IS_HPUX
#include <stdio.h>
#include <mntent.h>
#endif

/* AIX includes and helper routines (from gnome-vfs-unix-mounts.c */
#if 0
#ifdef HOST_IS_AIX
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* gnome-vfs-unix-mounts.c - read and monitor fstab/mtab

   Copyright (C) 2003 Red Hat, Inc

   The Gnome Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Alexander Larsson <alexl@redhat.com>
*/

/* read character, ignoring comments (begin with '*', end with '\n' */
static int aix_fs_getc (FILE *fd)
{
  int c;
  
  while ((c = getc (fd)) == '*') {
    while (((c = getc (fd)) != '\n') && (c != EOF)) {} /* do nothing */
  }
}

/* eat all continuous spaces in a file */
static int aix_fs_ignorespace (FILE *fd)
{
  int c;
  
  while ((c = aix_fs_getc (fd)) != EOF) {
    if (! (isascii(c) && isspace (c)) ) {
      ungetc (c,fd);
      return c;
    }
  }
  
  return EOF;
}

/* read one word from file */
static int aix_fs_getword (FILE *fd, char *word, int len)
{
  int c;
  int i = 0;

  --len;

  aix_fs_ignorespace (fd);

  while (((c = aix_fs_getc (fd)) != EOF) && !( isascii(c) && isspace(c) )) 
    {
      if (c == '"') 
	{
	  while (((c = aix_fs_getc (fd)) != EOF) && (c != '"')) 
	    {
	      *word++ = c; ++i;
	      if (i == len)
		break;
	    }
	} 
      else 
	{
	  *word++ = c; ++i;
	}
      if (i == len)
	break;
    }
  *word = 0;
  
  return c;
}

/* PATH_MAX is in sys/limits.h, included via stdio.h
 */
typedef struct {
  char mnt_mount[PATH_MAX];
  char mnt_special[PATH_MAX];
  char mnt_fstype[16];
  char mnt_options[128];
} AixMountTableEntry;

/* read mount points properties */
static int aix_fs_get (FILE *fd, AixMountTableEntry *prop)
{
  /* Need space for PATH_MAX + ':'   (terminating '\0' is in PATH_MAX; SUSv3)
   */
  static char word[PATH_MAX+1] = { 0 };
  char value[PATH_MAX];

  /* reset */

  if (fd == NULL)
    {
      word[0] = '\0';
      return 0;
    }

  /* read stanza */

  if (word[0] == 0) {
    if (aix_fs_getword (fd, word, (PATH_MAX+1)) == EOF)
      return EOF;
  }

  word[strlen(word) - 1] = 0;
  sl_strlcpy (prop->mnt_mount, word, PATH_MAX);

  /* read attributes and value */

  while (aix_fs_getword (fd, word, (PATH_MAX+1)) != EOF) {
    /* test if is attribute or new stanza */

    if (word[strlen(word) - 1] == ':') {
      return 0;
    }

    /* read "=" */
    aix_fs_getword (fd, value, PATH_MAX);

    /* read value */
    aix_fs_getword (fd, value, PATH_MAX);

    if (strcmp (word, "dev") == 0) {
      sl_strlcpy (prop->mnt_special, value, PATH_MAX);
    } else if (strcmp (word, "vfs") == 0) {
      sl_strlcpy (prop->mnt_fstype, value, 16);
    } else if (strcmp (word, "options") == 0) {
      sl_strlcpy(prop->mnt_options, value, 128);
    }
  }

  return 0;
}

/* end AIX helper routines */
#endif
#endif

#if defined(HOST_IS_FREEBSD) || defined(HOST_IS_OPENBSD)

/* FreeBSD returns flags instead of strings as mount options, so we'll convert
 * them here. */
static
struct sh_mounts_opt * getoptlist(int flags) {
	struct sh_mounts_opt *list, *o;
	int i;

	struct {char *opt; int flag;} table[] = {
#ifdef MNT_RDONLY
		{"ro",		MNT_RDONLY},
#endif
#ifdef MNT_NOEXEC
		{"noexec",	MNT_NOEXEC},
#endif
#ifdef MNT_NOSUID
		{"nosuid",	MNT_NOSUID},
#endif
#ifdef MNT_NODEV
		{"nodev",	MNT_NODEV},
#endif
#ifdef MNT_SYNCHRONOUS
		{"sync",	MNT_SYNCHRONOUS},
#endif
#ifdef MNT_ASYNC
		{"async",	MNT_ASYNC},
#endif
#ifdef MNT_LOCAL
		{"local",	MNT_LOCAL},
#endif
#ifdef MNT_QUOTA
		{"quota",	MNT_QUOTA},
#endif
#ifdef MNT_NOATIME
		{"noatime",	MNT_NOATIME},
#endif
		{"bound",	-1}
	};
  	
	SL_ENTER(_("getoptlist"));
	
	list = NULL;

	/* Add any flags found to the list */
	for (i = 0; table[i].flag != -1; i++) {
		if (flags & table[i].flag) {
			o = (struct sh_mounts_opt *) SH_ALLOC(sizeof(struct sh_mounts_opt));
			o->opt = sh_util_strdup(table[i].opt);
			o->next = list;
			list = o;
		}
	}

  	SL_RETURN(list, _("getoptlist"));
}

/* Solaris & Linux return identical option string formats */
#else

/* We just separate the options out by parsing for commas */
static
struct sh_mounts_opt * getoptlist(char *opt) 
{
  struct sh_mounts_opt *list, *o;
  char *sp, *temp;

  SL_ENTER(_("getoptlist"));

  /* See the comments in sh_mounts_config_mount() above for the reasons for
   * this arcane little zig-zag */
  temp = sh_util_strdup(opt);
  opt  = temp;

  list = NULL;

  /* For each option, add to the list */
  while (opt != NULL) {
    sp = sh_util_strsep(&opt, ", \t");

    if (*sp == '\0') {
	continue;
    }

    o = (struct sh_mounts_opt *) SH_ALLOC(sizeof(struct sh_mounts_opt));
    o->next = list;
    list = o;

    o->opt = sh_util_strdup(sp);
  }

  SH_FREE(temp);

  SL_RETURN(list, _("getoptlist"));
}

#endif

/* Read the list of mounts from whereever is appropriate to the OS and return
 * it. Return NULL on error. */
static struct sh_mounts_mnt * readmounts(void) {
	struct sh_mounts_mnt *list, *m;

  	SL_ENTER(_("readmounts"));
	m    = NULL; /* use it to avoid compiler warning */
	list = m;

/* The Open/FreeBSD way */
#if defined(HOST_IS_FREEBSD) || defined(HOST_IS_OPENBSD)
{
	struct statfs *fsp;
	int entries;

	entries = getmntinfo(&fsp, MNT_NOWAIT);
	if (entries < 0) {
	  SL_RETURN((NULL), _("readmounts"));
	}

	for (; entries-- > 0; fsp++) {
		m = (struct sh_mounts_mnt *) SH_ALLOC(sizeof (struct sh_mounts_mnt));
		m->path = sh_util_strdup(fsp->f_mntonname);
		m->opts = getoptlist(fsp->f_flags);

		m->next = list;
		list = m;
	}
}
#endif

/* The Linux way */
#ifdef HOST_IS_LINUX
{
	struct mntent *mp;
	FILE *tab = setmntent(_PATH_MOUNTED, "r");

	if (tab == NULL) {
	  SL_RETURN((NULL), _("readmounts"));
	}

	mp = getmntent(tab);
	while (mp != NULL) {
		m = (struct sh_mounts_mnt *) SH_ALLOC(sizeof (struct sh_mounts_mnt));
		m->path = sh_util_strdup(mp->mnt_dir);
		m->opts = getoptlist(mp->mnt_opts);

		m->next = list;
		list = m;

		mp = getmntent(tab);
	}

	(void) endmntent(tab);
}
#endif

/* The Solaris way */
#ifdef HOST_IS_SOLARIS
{
	struct mnttab mp;
	FILE *tab = fopen(MNTTAB, "r");

	if (tab == NULL) {
	  SL_RETURN((NULL), _("readmounts"));
	}

	while (!getmntent(tab, &mp)) {
		m = (struct sh_mounts_mnt *) SH_ALLOC(sizeof (struct sh_mounts_mnt));
		m->path = sh_util_strdup(mp.mnt_mountp);
		m->opts = getoptlist(mp.mnt_mntopts);

		m->next = list;
		list = m;
	}

	sl_fclose(FIL__, __LINE__, tab);
}
#endif


/* The HP-UX way */
#ifdef HOST_IS_HPUX
{
        struct mntent *mp;
        FILE *tab = setmntent(MNT_MNTTAB, "r");

        if (tab == NULL) {
          SL_RETURN((NULL), _("readmounts"));
        }

        mp = getmntent(tab);
        while (mp != NULL) {
                m = (struct sh_mounts_mnt *) SH_ALLOC(sizeof (struct sh_mounts_mnt));
                m->path = sh_util_strdup(mp->mnt_dir);
                m->opts = getoptlist(mp->mnt_opts);

                m->next = list;
                list = m;

                mp = getmntent(tab);
        }

        (void) endmntent(tab);
}
#endif

/* The AIX way */
#if 0
#ifdef HOST_IS_AIX
{
        AixMountTableEntry mntent;
        FILE *tab = fopen("/etc/filesystems", "r");

        if (tab == NULL) {
          SL_RETURN((NULL), _("readmounts"));
        }

	while (!aix_fs_get (tab, &mntent)) 
	  {
                m = (struct sh_mounts_mnt *) SH_ALLOC(sizeof (struct sh_mounts_mnt));
                m->path = sh_util_strdup(mntent.mnt_mount);
                m->opts = getoptlist(mntent.mnt_options);

                m->next = list;
                list = m;

		mntent.mnt_mount[0]   = '\0';
		mntent.mnt_special[0] = '\0';
		mntent.mnt_fstype[0]  = '\0';
		mntent.mnt_options[0] = '\0';
        }

        (void) sl_fclose(FIL__, __LINE__, tab);
	aix_fs_get (NULL, NULL); /* reset */
}
#endif
#endif

  	SL_RETURN((list), _("readmounts"));

}


/* #if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) */
#endif

/* #ifdef SH_USE_MOUNTS */
#endif

