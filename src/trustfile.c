/* debug problems        */
/* #define TRUST_DEBUG   */

/* switch off full check */
/* #define TEST_ONLY     */

/* standalone            */
/* #define TRUST_MAIN    */
/* $(CC) -DTRUST_MAIN -DSL_ALWAYS_TRUSTED=...  */

/* LINTLIBRARY */
/*
 * This is the file with all the library routines in it
 *
 * Author information:
 * Matt Bishop
 * Department of Computer Science
 * University of California at Davis
 * Davis, CA  95616-8562
 * phone (916) 752-8060
 * email bishop@cs.ucdavis.edu
 *
 * This code is placed in the public domain.  I do ask that
 * you keep my name associated with it, that you not represent
 * it as written by you, and that you preserve these comments.
 * This software is provided "as is" and without any guarantees
 * of any sort.
 *
 * Compilation notes:
 * * this does NOT use malloc(3), but fixed storage.  this means we
 *   do lots of bounds checking, but it still is faster, and smaller,
 *   than forcing inclusion of malloc.  All buffers etc. are of size
 *   MAXFILENAME (defined in trustfile.h); to get more room, recompile
 *   with this set larger.
 * * if you support the following directory semantics, define STICKY;
 *   otherwise, undefine it
 *	"if a directory is both world-writeable AND has the sticky bit
 *	 set, then ONLY the owner of an existing file may delete it"
 *   On some systems (eg, IRIX), you can delete the file under these
 *   conditions if the file is world writeable.  Foor our purposes,
 *   this is irrelevant since if the file is world-writeable it is
 *   untrustworthy; either it can be replaced with another file (the
 *   IRIX version) or it can be altered (all versions).
 *   if this is true and STICKY is not set, the sticky bit is ignored
 *   and the directory will be flagged as untrustworthy, even when only
 *   a trusted user could delete the file
 * * this uses a library call to get the name of the current working
 *   directory.  Define the following to get the various versions:
 *   GETCWD	for Solaris 2.x, SunOS 4.1.x, IRIX 5.x
 *			char *getcwd(char *buf, int bufsz);
 *		where buf is a buffer for the path name, and bufsz is
 *		the size of the buffer; if the size if too small, you
 *		get an error return (NULL)
 *   GETWD	for Ultrix 4.4
 *			char *getwd(char *buf)
 *		where buf is a buffer for the path name, and it is
 *		assumed to be at lease as big as MAXPATHLEN.
 *		*** IMPORTANT NOTE ***
 *		Ultrix supports getcwd as well, but it uses popen to
 *		run the command "pwd" (according to the manual).  This
 *		means it's vulnerable to a number of attacks if used
 *		in a privileged program.  YOU DON'T WANT THIS.
 * * the debugging flag DEBUG prints out each step of the file name
 *   checking, as well as info on symbolic links (if S_IFLNK defined),
 *   file name canonicalization, and user, group, and permission for
 *   each file or directory; this is useful if you want to be sure
 *   you're checking the right file
 *
 * Version information:
 * 1.0		December 28, 1995	Matt Bishop
 *
 * 2.0          March    26, 2000       Rainer Wichmann -- adapted for slib.
 */

/* --- Why strcpy is safe here: ----                                  */

/* The input path is checked once, and then either shortened [in dirz()], 
 * or safely expanded (symlinks) with bound checking.
 * I.e., the path length can never exceed (MAXFILENAME-1), while the path
 * is always copied between buffers of length MAXFILENAME.
 */

#ifndef  TRUST_MAIN
#include "config_xor.h"
#include "sh_calls.h"
#else
#define UID_CAST long
#define HAVE_GETPWENT
#define SH_MUTEX_LOCK(a)   ((void)0)
#define SH_MUTEX_UNLOCK(a) ((void)0)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>


#if !defined(TRUST_MAIN)

#include "slib.h"
#define SH_NEED_PWD_GRP 1
#include "sh_static.h"
#include "sh_pthread.h"

#else

#define sh_getgrgid   getgrgid
#define sh_getgrgid_r getgrgid_r
#define sh_getpwnam   getpwnam
#define sh_getpwnam_r getpwnam_r
#define sh_getpwuid   getpwuid
#define sh_getpwuid_r getpwuid_r
#define sh_getpwent   getpwent
#define sh_endpwent   endpwent

#define TRUST_DEBUG
#define S_FALSE 0
#define S_TRUE  1
#define SL_ENTER(string)
#define SL_IRETURN(a, b)  return a
#define retry_lstat(a,b,c,d) lstat(c,d)
#define _(string)  string 
#define N_(string) string
#define MAXFILENAME     4096
static int sl_errno = 0;
#define SL_ENONE         0
#define SL_ENULL     -1024     /* Invalid use of NULL pointer.         */
#define SL_ERANGE    -1025     /* Argument out of range.               */
#define SL_ETRUNC    -1026     /* Result truncated.                    */
#define SL_EINTERNAL -1028     /* Internal error.                      */
#define SL_EBADFILE  -1030     /* File access error. Check errno.      */
#define SL_EMEM      -1032     /* Out of memory.                       */
#define SL_EBADNAME  -1040     /* Invalid name.                        */
#define SL_ESTAT     -1041     /* stat of file failed. Check errno.    */
#define SL_EBADUID   -1050	/* Owner not trustworthy.              */
#define SL_EBADGID   -1051	/* Group writeable and not trustworthy.*/
#define SL_EBADOTH   -1052	/* World writeable.                    */

#endif


#if defined(__linux__) || defined(__FreeBSD__)
#define STICKY
#endif

#undef  FIL__
#define FIL__  _("trustfile.c")

/*
 * the get current working directory function
 * every version of UNIX seems to have its own
 * idea of how to do this, so we group them by
 * arguments ...
 * all must return a pointer to the right name
 */


#ifndef TRUST_MAIN

#if defined(HAVE_GETCWD) && !defined(HAVE_BROKEN_GETCWD)
#define CURDIR(buf,nbuf)	getcwd((buf), (nbuf))
#elif defined(HAVE_GETWD)
#define CURDIR(buf,nbuf)	getwd((buf))
#endif

#else

#define CURDIR(buf,nbuf)	getcwd((buf), (nbuf))

#endif



/*
 * this checks to see if there are symbolic links
 * assumes the link bit in the protection mask is called S_IFLNK
 * (seems to be true on all UNIXes with them)
 */
#ifndef S_IFLNK
#define	lstat	stat
#endif


/*
 * these are useful global variables
 *
 * first set: who you gonna trust, by default?
 * 	if the user does not specify a trusted or untrusted set of users,
 *	all users are considered untrusted EXCEPT:
 *	UID 0 -- root	as root can do anything on most UNIX systems, this
 *			seems reasonable
 *	tf_euid -- programmer-selectable UID
 *			if the caller specifies a specific UID by putting
 *			it in this variable, it will be trusted; this is
 *			typically used to trust the effective UID of the
 *			process (note: NOT the real UID, which will cause all
 *			sorts of problems!)  By default, this is set to -1,
 *			so if it's not set, root is the only trusted user
 */

/* modified Tue Feb 22 10:36:44 NFT 2000 Rainer Wichmann                */


#ifndef SL_ALWAYS_TRUSTED
#define SL_ALWAYS_TRUSTED  0
#endif
uid_t test_rootonly[] = { SL_ALWAYS_TRUSTED };

#define tf_uid_neg ((uid_t)-1)

uid_t rootonly[] = { SL_ALWAYS_TRUSTED, 
		    tf_uid_neg, tf_uid_neg, tf_uid_neg, tf_uid_neg, 
		    tf_uid_neg, tf_uid_neg, tf_uid_neg, tf_uid_neg, 
		    tf_uid_neg, tf_uid_neg, tf_uid_neg, tf_uid_neg, 
		    tf_uid_neg, tf_uid_neg, tf_uid_neg, tf_uid_neg };

uid_t tf_euid = tf_uid_neg;
unsigned int EUIDSLOT = sizeof(test_rootonly)/sizeof(uid_t);
unsigned int ORIG_EUIDSLOT = sizeof(test_rootonly)/sizeof(uid_t);

char  tf_path[MAXFILENAME];		/* error path for trust function */
uid_t tf_baduid;
gid_t tf_badgid;

static 
int dirz(char *path)
{
  register char *p = path;/* points to rest of path to clean up */
  register char *q;	/* temp pointer for skipping over stuff */

  static   char swp[MAXFILENAME];

  SL_ENTER(_("dirz"));
  /*
   * standard error checking
   */
  if (path == NULL)
    SL_IRETURN(SL_ENULL, _("dirz"));
  if (path[0] == '.')
    SL_IRETURN(SL_EINTERNAL, _("dirz"));
  
  
  /*
   * loop over the path name until everything is checked
   */
  while(*p)
    {
      /* skip 
       */
      if (*p != '/')
	{
	  p++;
	  continue;
	}

      /* "/./" or "/." 
       */
      if (p[1] == '.' && (p[2] == '/' || p[2] == '\0'))
	{
	  /* yes -- delete "/." 
	   */
	  (void) strcpy(swp, &p[2]);                     /* known to fit  */
	  (void) strcpy(p, swp);                         /* known to fit  */

	  /* special case "/." as full path name 
	   */
	  if (p == path && *p == '\0')
	    {
	    *p++ = '/';
	    *p = '\0';
	  }
      }

      /* "//" 
       */
      else if (p[1] == '/')
	{
	  /* yes -- skip 
	   */
	  for(q = &p[2]; *q == '/'; q++)
	    ;
	  (void) strcpy(swp, q);                         /* known to fit  */
	  (void) strcpy(&p[1], swp);                     /* known to fit  */
	}

      /* "/../" or "/.." 
       */
      else if (p[1] == '.' && p[2] == '.' && (p[3] == '/' || p[3] == '\0'))
	{
	  /* yes -- if it's root, delete .. only 
	   */
	  if (p == path)
	    {
	      (void) strcpy(swp, &p[3]);                 /* known to fit  */
	      (void) strcpy(p, swp);                     /* known to fit  */
	    }
	  else
	    {
	      /* back up over previous component 
	       */
	      q = p - 1;
	      while(q != path && *q != '/')
		q--;
	      /* now wipe it out 
	       */
	      (void) strcpy(swp, &p[3]);                 /* known to fit  */
	      (void) strcpy(q, swp);                     /* known to fit  */
	      p = q;
	    }
	}
      else
	p++;
    }
  SL_IRETURN(SL_ENONE, _("dirz"));
}
			


/* not static to circumvent stupid gcc 4 bug */ 
int getfname(const char *fname, char *rbuf, int rsz)
{
#ifndef TRUST_MAIN
  register int status;
#endif

  SL_ENTER(_("getfname"));
  /*
   * do the initial checking
   * NULL pointer
   */
  if (fname == NULL || rbuf == NULL)
    SL_IRETURN(SL_ENULL, _("getfname"));
  if (rsz <= 0)
    SL_IRETURN(SL_ERANGE, _("getfname"));
  
  
  /* already a full path name */
  if (*fname == '/')
    rbuf[0] = '\0';
  else
    {
      if (CURDIR(rbuf, rsz)  == NULL)
	{
#ifdef TRUST_DEBUG
	  fprintf(stderr, "trustfile: getcwd failed\n");
#endif 
	  SL_IRETURN(SL_EBADNAME, _("getfname"));
	}
    }
  
  /*
   * append the file name and reduce
   */
  if (fname != NULL && *fname != '\0')
    {
#ifndef TRUST_MAIN
      status = sl_strlcat(rbuf, "/", rsz);
      if (status == SL_ENONE)
	status = sl_strlcat(rbuf, fname, rsz);
      if (status != SL_ENONE)
	SL_IRETURN(status, _("getfname"));
#else
      strncat(rbuf, "/",   rsz-strlen(rbuf)-1);
      rbuf[rsz-1] = '\0';
      strncat(rbuf, fname, rsz-strlen(rbuf)-1);
      rbuf[rsz-1] = '\0';
#endif
    }
  SL_IRETURN(dirz(rbuf), _("getfname"));
}

static 
int isin(uid_t n, uid_t *list)
{
  SL_ENTER(_("isin"));
  if (list == NULL)
    SL_IRETURN(S_FALSE, _("isin"));

  while(*list != tf_uid_neg && *list != n)
    {
#ifdef TRUST_DEBUG
      fprintf (stderr, 
	       "trustfile: owner_uid=%ld, trusted uid=%ld, no match\n", 
	       (UID_CAST) n, (UID_CAST) *list);
#endif 
      list++;
    }

  if (*list == tf_uid_neg)
    {
#ifdef TRUST_DEBUG
      fprintf (stderr, 
	       "trustfile: owner_uid=%ld, no match with any trusted user --> ERROR\n", 
	       (UID_CAST) n);
#endif 
      SL_IRETURN(S_FALSE, _("isin"));
    }

#ifdef TRUST_DEBUG
  fprintf (stderr, 
	   "trustfile: owner_uid=%ld, trusted_uid=%ld, match found --> OK\n", 
	   (UID_CAST)n, (UID_CAST)*list);
#endif 
  SL_IRETURN(S_TRUE, _("isin"));
}

/* comment added by R. Wichmann
 *  RETURN TRUE if ANYONE in ulist is group member
 */
/* not static to circumvent stupid gcc 4 bug */ 
int isingrp(gid_t grp, uid_t *ulist, int * errval)
{
  struct passwd *w;	        /* info about group member */
  register uid_t *u;		/* points to current ulist member */
  register char **p;		/* points to current group member */
  struct group *g;	        /* pointer to group information */

  int status;
  
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
  struct group    gr;
  char          * buffer = NULL;
  struct passwd   pwd;
  char          * pbuffer = NULL;
#endif

  SL_ENTER(_("isingrp"));

  *errval = 0;

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
  buffer = calloc(1,SH_GRBUF_SIZE);
  status = sh_getgrgid_r(grp, &gr, buffer, SH_GRBUF_SIZE, &g);
#else
  errno = 0;
  g = sh_getgrgid(grp);
  status = errno;
#endif

  if (g == NULL)
    {
      if (status == ERANGE)
	*errval = status;

      goto end_false;
    }

  /* this will return at the first match
   */
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
  pbuffer = calloc(1,SH_PWBUF_SIZE);
#endif

  for(p = g->gr_mem; *p != NULL; p++)
    {
      for(u = ulist; *u != tf_uid_neg; u++)
	{
	  /* map user name to UID and compare */
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
	  sh_getpwnam_r(*p, &pwd, pbuffer, SH_PWBUF_SIZE, &w);
#else
	  w = sh_getpwnam(*p);
#endif

#ifdef TRUST_MAIN
	  if (w != NULL && *u == (uid_t)(w->pw_uid) )
	    goto end_true;
#else
	  if (w != NULL && *u == (uid_t)(w->pw_uid) )
	    {
	      goto end_true;
	    }
#endif
	}
    }
  /* added by R. Wichmann Fri Mar 30 08:16:14 CEST 2001: 
   * a user can have a GID but no entry in /etc/group
   */
  for(u = ulist; *u != tf_uid_neg; u++)
    {
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWUID_R)
      sh_getpwuid_r(*u, &pwd, pbuffer, SH_PWBUF_SIZE, &w);
#else
      w = sh_getpwuid(*u);
#endif
#ifdef TRUST_MAIN
      if (w != NULL && grp == (gid_t)(w->pw_gid) )
	goto end_true;
#else
      if (w != NULL && grp == (gid_t)(w->pw_gid) )
	{
	  goto end_true;
	}
#endif
    }

 end_false:
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
  if (buffer)  free(buffer);
  if (pbuffer) free(pbuffer);
#endif
  SL_IRETURN(S_FALSE, _("isingrp"));

 end_true:
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
  if (buffer)  free(buffer);
  if (pbuffer) free(pbuffer);
#endif
  SL_IRETURN(S_TRUE, _("isingrp"));
}

/* added by R. Wichmann Fri Mar 30 08:16:14 CEST 2001
 *  RETURN TRUE only if ALL group members are trusted
 */
/* not static to circumvent stupid gcc 4 bug */ 
int onlytrustedingrp(gid_t grp, uid_t *ulist, int * errval)
{
  struct passwd *w;	        /* info about group member */
  register uid_t *u;		/* points to current ulist member */
  register char **p;		/* points to current group member */
  struct group *g;	        /* pointer to group information */
  register int flag = -1;       /* group member found */

  int status;

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
  struct group    gr;
  char          * buffer  = NULL;
  struct passwd   pw;
  char          * pbuffer = NULL;
#endif

  int retval = S_FALSE;

  SL_ENTER(_("onlytrustedingrp"));

  *errval = 0;

#ifdef TRUST_DEBUG
  fprintf(stderr, "trustfile: group writeable, group_gid: %ld\n", 
	  (UID_CAST)grp); 
#endif

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
  buffer = calloc(1,SH_GRBUF_SIZE);
  status = sh_getgrgid_r(grp, &gr, buffer, SH_GRBUF_SIZE, &g);
#else
  errno = 0;
  g = sh_getgrgid(grp);
  status = errno;
#endif

  if (g == NULL)
    {
      if (status == ERANGE)
	*errval = status;

#ifdef TRUST_DEBUG
      fprintf(stderr, 
	      "trustfile: group_gid: %ld, no such group --> ERROR\n", 
	      (UID_CAST)grp); 
#endif
      retval = S_FALSE;
      goto end_retval;
    }

  /* empty group -> no problem
   
  if(g->gr_mem == NULL || g->gr_mem[0] == NULL )
    SL_IRETURN(S_TRUE, _("onlytrustedingrp") );
  */

  /* check for untrusted members of the group
   */
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
  pbuffer = calloc(1,SH_PWBUF_SIZE);
#endif

  for(p = g->gr_mem; *p != NULL; p++)
    {
      flag = -1;
#ifdef TRUST_DEBUG
      fprintf(stderr, "trustfile: group_member: %s\n", *p); 
#endif
      /* map user name to UID and compare 
       */
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
      sh_getpwnam_r(*p, &pw, pbuffer, SH_PWBUF_SIZE, &w);
#else
      w = sh_getpwnam(*p);
#endif

      if (w == NULL)    /* not a valid user, ignore    */
	{
	  flag = 0; 
	}
      else              /* check list of trusted users */
	{
#ifdef TRUST_DEBUG
	  fprintf (stderr, 
		   "trustfile: uid=%ld, checking whether it is trusted\n",
		   (UID_CAST)(w->pw_uid));
#endif 
	  for(u = ulist; *u != tf_uid_neg; u++)
	    {
	      if (*u == (w->pw_uid) )
		{
#ifdef TRUST_DEBUG
		  fprintf (stderr, 
			   "trustfile: uid=%ld, trusted_uid=%ld, match found --> OK\n", 
			   (UID_CAST)(w->pw_uid), (UID_CAST)*u);
#endif 
		  flag = 0;
		  break;
		}
	      else
		{
#ifdef TRUST_DEBUG
		  fprintf (stderr, 
			   "trustfile: uid=%ld, trusted_uid=%ld, no match\n", 
			   (UID_CAST)(w->pw_uid), (UID_CAST)*u);
#endif 
		  ;
		}
	    }
	}
      /* not found 
       */
      if (flag == -1)
	{
#ifdef TRUST_DEBUG
	  fprintf (stderr, 
		   "trustfile: user=%s (gid %ld), not a trusted user --> ERROR\n", *p, (UID_CAST)grp);
#endif 
	  tf_baduid = w->pw_uid;
	  retval = S_FALSE;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
	  if (pbuffer) free(pbuffer);
#endif
	  goto end_retval;
	}
    }

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
  if (pbuffer) free(pbuffer);
#endif

#ifndef TEST_ONLY	
#ifdef HAVE_GETPWENT
  /* now check ALL users for their GID !!!
   */
  SH_MUTEX_LOCK(mutex_pwent);

  while (NULL != (w = sh_getpwent())) 
    {
      if (grp == (gid_t)(w->pw_gid))
	{
#ifdef TRUST_DEBUG
	  fprintf(stderr, "trustfile: checking group member %s, uid %ld\n", 
		  w->pw_name, (UID_CAST)w->pw_uid); 
#endif
	  /* is it a trusted user ?
	   */
	  flag = -1;
	  for(u = ulist; *u != tf_uid_neg; u++)
	    {
	      if (*u == (uid_t)(w->pw_uid))
		{
#ifdef TRUST_DEBUG
		  fprintf (stderr, 
			   "trustfile: uid=%ld, trusted_uid=%ld, match found --> OK\n", 
			   (UID_CAST)(w->pw_uid), (UID_CAST)(*u));
#endif 
		  flag = 0;
		  break;
		}
	      else
		{
#ifdef TRUST_DEBUG
		  fprintf (stderr, 
			   "trustfile: uid=%ld, trusted_uid=%ld, no match\n", 
			   (UID_CAST)(w->pw_uid), (UID_CAST)*u);
#endif 
		  ;
		}
	    }
	  /* not found */
	  if (flag == -1)
	    {
#ifdef TRUST_DEBUG
	      fprintf(stderr,"trustfile: group member %s not found in trusted users --> ERROR\n", w->pw_name); 
#endif
	      tf_baduid = w->pw_uid;
	      retval = S_FALSE;
	      goto out;
	      /* SL_IRETURN(S_FALSE, _("onlytrustedingrp")); */
	    }
	}
    }
  retval = S_TRUE;

 out:

#ifdef HAVE_ENDPWENT
  sh_endpwent();
#endif

  SH_MUTEX_UNLOCK(mutex_pwent);

  /* TEST_ONLY */
#endif
  /* #ifdef HAVE_GETPWENT */
#endif

#ifdef TRUST_DEBUG
  if (retval == S_TRUE)
    fprintf(stderr,
	    "trustfile: group %ld:  all members are trusted users --> OK\n", 
	    (UID_CAST)grp);
#endif
  /* all found
   */
 end_retval:
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETGRGID_R)
  if (buffer)  free(buffer);
#endif
  SL_IRETURN(retval, _("onlytrustedingrp"));
}

int sl_trustfile(const char *fname, uid_t *okusers, uid_t *badusers)
{
  char * fexp = NULL;	        /* file name fully expanded        */
  register char *p;             /* used to hold name to be checked */
  struct stat stbuf;	        /* used to check file permissions  */
  char c;			/* used to hold temp char          */
  
  int errgrp = 0;

  SL_ENTER(_("sl_trustfile"));
  if (fname == NULL)
    SL_IRETURN(SL_EBADFILE, _("sl_trustfile"));

  fexp = calloc(1, MAXFILENAME );
  if (!fexp)
    SL_IRETURN(SL_EMEM, _("sl_trustfile"));

  p = fexp;

  /*
   * next expand to the full file name
   * getfname sets sl_errno as appropriate
   */
#ifdef TRUST_MAIN
  sl_errno = getfname(fname, fexp, MAXFILENAME);
  if (sl_errno != 0)
    {
      free(fexp);
      return sl_errno;
    }
#else
  if (SL_ISERROR(getfname(fname, fexp, MAXFILENAME)))
    {
      free(fexp);
      SL_IRETURN(sl_errno, _("sl_trustfile"));
    }
#endif

  if (okusers == NULL && badusers == NULL)
    {
      okusers = rootonly;
      rootonly[EUIDSLOT] = tf_euid;
    }

  /*
   * now loop through the path a component at a time
   * note we have to special-case root
   */
  while(*p)
    {
      /*
       * get next component
       */
      while(*p && *p != '/')
	p++;

      /* save where you are 
       */
      if (p == fexp)
	{
	  /* keep the / if it's the root dir 
	   */
	  c    = p[1];
	  p[1] = '\0';
	}
      else
	{
	  /* clobber the / if it isn't the root dir 
	   */
	  c  = *p;
	  *p = '\0';
	}

      /*
       * now get the information
       */
      if (retry_lstat(FIL__, __LINE__, fexp, &stbuf) < 0)
	{
	  (void) strncpy(tf_path, fexp, sizeof(tf_path));
	  tf_path[sizeof(tf_path)-1] = '\0';
#ifdef TRUST_MAIN
	  fprintf(stderr, "---------------------------------------------\n");
	  fprintf(stderr, "trustfile: ESTAT: stat(%s) failed,\n", fexp);
	  fprintf(stderr, "maybe the file does not exist\n");
	  fprintf(stderr, "---------------------------------------------\n");
#endif
	  free(fexp);
	  SL_IRETURN(SL_ESTAT, _("sl_trustfile"));
	}

#ifdef S_IFLNK
      /* 
       * if it's a symbolic link, recurse
       */
      if ((stbuf.st_mode & S_IFLNK) == S_IFLNK)
	{
	  /*
	   * this is tricky
	   * if the symlink is to an absolute path
	   * name, just call trustfile on it; but
	   * if it's a relative path name, it's 
	   * interpreted WRT the current working
	   * directory AND NOT THE FILE NAME!!!!!
	   * so, we simply put /../ at the end of
	   * the file name, then append the symlink
	   * contents; trustfile will canonicalize
	   * this, and the /../ we added "undoes"
	   * the name of the symlink to put us in
	   * the current working directory, at
	   * which point the symlink contents (appended
	   * to the CWD) are interpreted correctly.
	   * got it?
	   */
	  char * csym;	                /* contents of symlink file  */
	  char * full;	                /* "full" name of symlink    */
	  char *b;                      /* used to copy stuff around */
	  const char *t;	        /* used to copy stuff around */
	  int lsym;	                /* num chars in symlink ref  */
	  int i;		        /* trustworthy or not?       */
	  const char * t_const;
	  char *end;

	  /*
	   * get what the symbolic link points to
	   *
	   * The original code does not check the return code of readlink(),
	   * and has an off-by-one error 
	   * (MAXFILENAME instead of MAXFILENAME-1)
	   * R.W. Tue May 29 22:05:16 CEST 2001
	   */
	  csym = calloc(1, MAXFILENAME );
	  if (!csym)
	    {
	      free(fexp);
	      SL_IRETURN(SL_EMEM, _("sl_trustfile"));
	    }

	  lsym = readlink(fexp, csym, MAXFILENAME-1);
	  if (lsym >= 0) 
	    csym[lsym] = '\0';
	  else
	    {
#ifdef TRUST_MAIN
	      fprintf(stderr, "---------------------------------------------\n");
	      fprintf(stderr, "trustfile: EBADNAME: readlink(%s) failed\n",
		      fexp);
	      fprintf(stderr, "---------------------------------------------\n");
#endif
	      free(csym);
	      free(fexp);
	      SL_IRETURN(SL_EBADNAME, _("sl_trustfile"));
	    }

	  full = calloc(1, MAXFILENAME );
	  if (!full)
	    {
	      free(csym);
	      free(fexp);
	      SL_IRETURN(SL_EMEM, _("sl_trustfile"));
	    }

	  /*
	   * relative or absolute referent?
	   */
	  if (csym[0] != '/')
	    {
	      /* pointer to one above last element
	       */
	      end = &full[MAXFILENAME-1]; ++end;

	      /* initialize pointers 
	       */
	      b = full;

	      /* copy in base path 
	       */
	      t = fexp;
	      while(*t && b < end)
		*b++ = *t++;

	      /* smack on the /../ 
	       */
	      t_const = "/../"; t = (const char *)t_const;
	      while(*t && b < end)
		*b++ = *t++;

	      /* append the symlink referent 
	       */
	      t = csym;
	      while(*t && b < end)
		*b++ = *t++;

	      /* see if we're too big 
	       */
	      if (*t || b == end)
		{
		  /* yes -- error 
		   */
		  (void) strncpy(tf_path, fexp, sizeof(tf_path));
		  tf_path[sizeof(tf_path)-1] = '\0';
#ifdef TRUST_MAIN
		  fprintf(stderr, "---------------------------------------------\n");
		  fprintf(stderr, 
			  "trustfile: ETRUNC: normalized path too long (%s)\n",
			  fexp);
		  fprintf(stderr, "---------------------------------------------\n");
#endif
		  free(full);
		  free(csym);
		  free(fexp);
		  SL_IRETURN(SL_ETRUNC, _("sl_trustfile"));
		}
	      *b = '\0';
	    }
	  else
	    {
	      /* absolute -- just copy                */
	      /* overflow can't occur as the arrays   */
	      /* are the same size		      */
	      (void) strcpy(full, csym);                 /* known to fit  */
	    }
	  /*
	   * now check out this file and its ancestors
	   */
	  if ((i = sl_trustfile(full, okusers, badusers)) != SL_ENONE)
	    {
	      free(full);
	      free(csym);
	      free(fexp);
	      SL_IRETURN(i, _("sl_trustfile"));
	    }

	  /*
	   * okay, this part is valid ... let's check the rest
	   * put the / back
	   */
	  if (p == fexp)
	    {
	      /* special case for root */
	      p[1] = c;
	      p++;
	    }
	  else
	    {
	      /* ordinary case for everything else */
	      *p = c;
	      if (*p)
		p++;
	    }
	  free(full);
	  free(csym);
	  continue;
	}
#endif

			
#ifdef TRUST_DEBUG
      fprintf(stderr, "\ntrustfile: checking path=%s\n", fexp); 
#endif 
      /*
       * if the owner is not trusted then -- as the owner can
       * change protection modes -- he/she can write to the
       * file regardless of permissions, so bomb
       */
      if (((okusers != NULL && S_FALSE == isin((uid_t)stbuf.st_uid,okusers))||
	   (badusers != NULL && S_TRUE == isin((uid_t)stbuf.st_uid,badusers))))
	{
#ifdef TRUST_DEBUG
	  fprintf(stderr, "---------------------------------------------\n");
	  fprintf(stderr, "trustfile: EBADUID %s (owner not trusted)\n", 
		  fexp); 
	  fprintf(stderr, "The owner of this file/directory is not in samhains\n"); 
	  fprintf(stderr, "list of trusted users.\n");
	  fprintf(stderr, "Please run ./configure again with the option\n");
	  fprintf(stderr, " ./configure [more options] --with-trusted=0,...,UID\n"); 
	  fprintf(stderr, "where UID is the UID of the (yet) untrusted user.\n"); 
	  fprintf(stderr, "---------------------------------------------\n");
#endif 
	  (void) strncpy(tf_path, fexp, sizeof(tf_path));
	  tf_path[sizeof(tf_path)-1] = '\0';

	  tf_baduid = (uid_t) stbuf.st_uid;
	  free(fexp);
	  SL_IRETURN(SL_EBADUID, _("sl_trustfile"));
	}

      /*
       * if a group member can write but the
       * member is not trusted, bomb; but if
       * sticky bit semantics are honored, it's
       * okay
       */
      /* Thu Mar 29 21:10:28 CEST 2001 Rainer Wichmann
       * replace !isingrp() with onlytrustedingrp(), as isingrp()
       * will return at the first trusted user, even if there are additional
       * (untrusted) users in the group
       */
      if (((stbuf.st_mode & S_IWGRP) == S_IWGRP) &&
	  ((okusers != NULL && !onlytrustedingrp((gid_t)stbuf.st_gid,okusers,&errgrp))||
	   (badusers != NULL && isingrp((gid_t)stbuf.st_gid, badusers,&errgrp)))
#ifdef STICKY
	  && ((stbuf.st_mode&S_IFDIR) != S_IFDIR ||
	      (stbuf.st_mode&S_ISVTX) != S_ISVTX)
#endif
	  )
	{
#ifdef TRUST_DEBUG
	  fprintf(stderr, "---------------------------------------------\n");
	  fprintf(stderr, 
		  "trustfile: EBADGID %ld %s (group member not trusted)\n", 
		  (UID_CAST)stbuf.st_gid, fexp);
	  fprintf(stderr, "This file/directory is group writeable, and one of the group members\n");
	  fprintf(stderr, "is not in samhains list of trusted users.\n"); 
	  fprintf(stderr, "Please run ./configure again with the option\n");
	  fprintf(stderr, " ./configure [more options] --with-trusted=0,...,UID\n"); 
	  fprintf(stderr, "where UID is the UID of the (yet) untrusted user.\n"); 
	  fprintf(stderr, "---------------------------------------------\n");
#endif 
	  (void) strncpy(tf_path, fexp, sizeof(tf_path));
	  tf_path[sizeof(tf_path)-1] = '\0';

	  tf_badgid = (gid_t) stbuf.st_gid;
	  free(fexp);
	  SL_IRETURN((errgrp == ERANGE) ? SL_ERANGE : SL_EBADGID, _("sl_trustfile"));
	}
      /*
       * if other can write, bomb; but if the sticky
       * bit semantics are honored, it's okay
       */
      if (((stbuf.st_mode & S_IWOTH) == S_IWOTH)
#ifdef STICKY
	  && ((stbuf.st_mode&S_IFDIR) != S_IFDIR ||
	      (stbuf.st_mode&S_ISVTX) != S_ISVTX)
#endif
	  )
	{
#ifdef TRUST_DEBUG
	  fprintf(stderr, "---------------------------------------------\n");
	  fprintf(stderr, "trustfile: EBADOTH (world writeable): %s\n", 
		  fexp);
	  fprintf(stderr, "This file/directory is world writeable.\n");
	  fprintf(stderr, "---------------------------------------------\n");
#endif 
	  (void) strncpy(tf_path, fexp, sizeof(tf_path));
	  tf_path[sizeof(tf_path)-1] = '\0';

	  free(fexp);
	  SL_IRETURN(SL_EBADOTH, _("sl_trustfile"));
	}
      /*
       * put the / back
       */
      if (p == fexp)
	{
	  /* special case for root */
	  p[1] = c;
	  p++;
	}
      else
	{
	  /* ordinary case for everything else */
	  *p = c;
	  if (*p)
	    p++;
	}
    }
  /*
   * yes, it can be trusted
   */
  (void) strncpy(tf_path, fexp, sizeof(tf_path));
  tf_path[sizeof(tf_path)-1] = '\0';

  free(fexp);
  SL_IRETURN(SL_ENONE, _("sl_trustfile"));
}

#ifdef TRUST_MAIN

#if defined(HOST_IS_CYGWIN) || defined(__cygwin__) || defined(__CYGWIN32__) || defined(__CYGWIN__)
int main()
{
  return 0;
}
#else
int main (int argc, char * argv[])
{
  int status;
#if defined(SH_WITH_SERVER)
  struct passwd * pass;
#endif

  if (argc < 2) {
    fprintf(stderr, "%s: Usage: %s <fullpath>\n", argv[0], argv[0]);
    return 1;
  }

  tf_path[0] = '\0';
#if defined(SH_WITH_SERVER)
  pass = sh_getpwnam(SH_IDENT);  /* TESTONLY */
  if (pass != NULL)
    tf_euid = pass->pw_uid;
  else
    {
      fprintf(stderr, "trustfile: ERROR: getpwnam(%s) failed\n",
	      SH_IDENT);
      return 1;
    }
#else
  tf_euid = geteuid();
#endif

  status = sl_trustfile(argv[1], NULL, NULL);
  if (status != SL_ENONE)
    {
      fprintf(stderr, "trustfile: ERROR: not a trusted path: %s\n",
	      argv[1]);
      return 1;
    }
  return 0;
}
#endif
#endif



