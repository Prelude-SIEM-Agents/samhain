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

#include <stdio.h>
#include <string.h>

#include <sys/types.h>

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

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


#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/wait.h>


#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <sys/types.h>



#include "samhain.h"
#include "sh_utils.h"
#include "sh_unix.h"
#include "sh_tiger.h"
#include "sh_calls.h"

#undef  FIL__
#define FIL__  _("sh_entropy.c")

#if defined (HAVE_EGD_RANDOM)
/* rndegd.c  -  interface to the EGD
 *      Copyright (C) 1999, 2000, 2001 Free Software Foundation, Inc.
 */
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>

static int
do_write( int fd, void *buf, size_t nbytes )
{
    size_t nleft = nbytes;
    int nwritten;

    while( nleft > 0 ) {
        nwritten = write( fd, buf, nleft);
        if( nwritten < 0 ) {
            if( errno == EINTR )
                continue;
            return -1;
        }
        nleft -= nwritten;
        buf = (char*)buf + nwritten;
    }
    return 0;
}

static int
do_read( int fd, void *buf, int nbytes )
{
    int n, nread = 0;

    if (nbytes < 0)
      return 0;

    do {
        do {
            n = read(fd, (char*)buf + nread, nbytes );
        } while( n == -1 && errno == EINTR );
        if( n == -1 )
            return -1;
        nread += n;
    } while( nread < nbytes );
    return nbytes;
}


int sh_entropy(int getbytes, char * nbuf)
{
    int fd = -1;
    int n;
    byte buffer[256+2];
    int nbytes;
    int do_restart = 0;
    int myerror = 0;
    int length;
    char * p = nbuf;
    int i;

    SL_ENTER(_("sh_entropy"));

    if( getbytes <= 0)
        SL_RETURN( -1, _("sh_entropy"));
    if (getbytes > KEY_BYT)
      getbytes = KEY_BYT;
    length = getbytes;

  restart:
    if( do_restart ) {
        if( fd != -1 ) {
            sl_close_fd(FIL__, __LINE__,  fd );
            fd = -1;
        }
    }
    if( fd == -1 ) {
        const char *bname = NULL;
        char *name;
        struct sockaddr_un addr;
        int addr_len;
	int retval;

#ifdef EGD_SOCKET_NAME
        bname = EGD_SOCKET_NAME;
#endif
        if ( !bname || !*bname )
            bname = _("=entropy");

        if ( *bname == '=' && bname[1] )
            name = sh_util_strconcat ( DEFAULT_DATAROOT, "/", bname+1 , NULL );
        else
            name = sh_util_strconcat ( bname , NULL );

        if ( strlen(name)+1 >= sizeof(addr.sun_path) )
	  {
	    sh_error_handle ((-1), FIL__, __LINE__, ENAMETOOLONG, MSG_E_SUBGEN,
			     _("EGD socketname is too long"),
			     _("sh_entropy") ); 
	    SH_FREE(name);
	    SL_RETURN( -1, _("sh_entropy") );
	  }

        memset( &addr, 0, sizeof(addr) );
        addr.sun_family = AF_UNIX;
        sl_strlcpy( addr.sun_path, name, sizeof(addr.sun_path) );
        addr_len = offsetof( struct sockaddr_un, sun_path )
                   + strlen( addr.sun_path );

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if( fd == -1 )
	  {
	    myerror = errno;
	    sh_error_handle ((-1), FIL__, __LINE__, myerror, MSG_E_SUBGEN,
			     _("cannot create unix domain socket"),
			     _("sh_entropy") ); 
	    SH_FREE(name);
	    SL_RETURN( -1, _("sh_entropy") );
	  }
	do {
	  retval = connect(fd, (struct sockaddr *) &sinr, sizeof(sinr));
	} while (retval < 0 && (errno == EINTR || errno == EINPROGRESS));
        if( retval == -1 )
	  {
	    myerror = errno;
	    sh_error_handle ((-1), FIL__, __LINE__, myerror, MSG_E_SUBGEN,
			     _("cannot connect to unix domain socket"),
			     _("sh_entropy") ); 
	    SH_FREE(name);
	    sl_close_fd(FIL__, __LINE__, fd);
	    SL_RETURN( -1, _("sh_entropy") );
	  }
        SH_FREE(name);
    }
    do_restart = 0;

    nbytes = length < 255? length : 255;
    /* first time we do it with a non blocking request */
    buffer[0] = 1; /* non blocking */
    buffer[1] = nbytes;
    if( do_write( fd, buffer, 2 ) == -1 )
	  {
	    myerror = errno;
	    sh_error_handle ((-1), FIL__, __LINE__, myerror, MSG_E_SUBGEN,
			     _("cannot write to EGD"),
			     _("sh_entropy") );
	    sl_close_fd(FIL__, __LINE__, fd);
	    SL_RETURN( -1, _("sh_entropy") );
	  }
    n = do_read( fd, buffer, 1 );
    if( n == -1 ) {
        myerror = errno;
        sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, myerror, MSG_E_SUBGEN,
			 _("read error on EGD"),
			 _("sh_entropy") ); 
        do_restart = 1;
        goto restart;
    }
    n = buffer[0];
    if( n ) {
        n = do_read( fd, buffer, n );
        if( n == -1 ) {
            myerror = errno;
            sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, myerror,MSG_E_SUBGEN,
			     _("read error on EGD"),
			     _("sh_entropy") ); 
            do_restart = 1;
            goto restart;
        }
	for (i = 0; i < n; ++i)
	  {
	    if (getbytes >= 0)
	      { *p = buffer[i]; ++p; --getbytes; }
	  }
        length -= n;
    }

    while( length ) {
        nbytes = length < 255? length : 255;

        buffer[0] = 2; /* blocking */
        buffer[1] = nbytes;
        if( do_write( fd, buffer, 2 ) == -1 )
	  {
	    myerror = errno;
	    sh_error_handle ((-1), FIL__, __LINE__, myerror, MSG_E_SUBGEN,
			     _("cannot write to EGD"),
			     _("sh_entropy") );
	    sl_close_fd(FIL__, __LINE__, fd);
	    SL_RETURN( -1, _("sh_entropy") );
	  }
        n = do_read( fd, buffer, nbytes );
        if( n == -1 ) {
            myerror = errno;
            sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, myerror,MSG_E_SUBGEN,
			     _("read error on EGD"),
			     _("sh_entropy") ); 
            do_restart = 1;
            goto restart;
        }
	for (i = 0; i < n; ++i)
	  {
	    if (getbytes >= 0)
	      { *p = buffer[i]; ++p; --getbytes; }
	  }
        length -= n;
    }
    memset(buffer, 0, sizeof(buffer) );
    sl_close_fd(FIL__, __LINE__, fd);
    SL_RETURN( 0, _("sh_entropy") ); /* success */
}

/* HAVE_EGD_RANDOM */
#endif

#if defined (HAVE_URANDOM)

#include "sh_pthread.h"

int read_mbytes(int timeout_val, const char * path, char * nbuf, int nbytes)
{
  int m_count;
  int fd2;

  SL_ENTER(_("read_mbytes"));

  if ((fd2 = aud_open (FIL__, __LINE__, SL_NOPRIV, path, O_RDONLY, 0)) >= 0) 
    {
      /* Test whether file is a character device, and is 
       * readable.
       */
      if (0 == sh_unix_device_readable(fd2)) 
	{
	  m_count = sl_read_timeout_fd(fd2, nbuf, nbytes, 
				       timeout_val, S_FALSE);
	  if (m_count < 0)
	    m_count = 0;
	}
      else
	m_count = 0;
    }
  else
    m_count = 0;

  sl_close_fd(FIL__, __LINE__, fd2);

  TPT((0, FIL__, __LINE__, _("msg=<read_mbytes: OK>\n"))); 
  SL_RETURN(m_count, _("read_mbytes"));
}

/* Read nbytes bytes from /dev/random, mix them with 
 * previous reads using a hash function, and give out
 * nbytes bytes from the result.
 */
int sh_entropy(int nbytes, char * nbuf)
{
  int    i, m_count = 0;
  char * keybuf;
  UINT32 kbuf[KEY_BYT/sizeof(UINT32)];
  char   addbuf[2 * KEY_BYT];

  SL_ENTER(_("sh_entropy"));

  ASSERT((nbytes <= KEY_BYT), _("nbytes <= KEY_BYT"))

  if (nbytes > KEY_BYT)
    nbytes = KEY_BYT;

  memset(nbuf, '\0', nbytes);

#ifdef NAME_OF_DEV_URANDOM
  m_count = read_mbytes ( 10, NAME_OF_DEV_URANDOM, nbuf, nbytes);
#else
  m_count = read_mbytes (300, NAME_OF_DEV_RANDOM,  nbuf, nbytes);
#endif

  if (m_count == 0)
    {
#ifdef NAME_OF_DEV_URANDOM
      sh_error_handle (SH_ERR_NOTICE, FIL__, __LINE__, EIO, MSG_NODEV, 
		       (long) sh.real.uid, NAME_OF_DEV_URANDOM);
#else
      sh_error_handle ((-1), FIL__, __LINE__, EIO, MSG_NODEV, 
		       (long) sh.real.uid, NAME_OF_DEV_RANDOM);
#endif
    }

#ifdef NAME_OF_DEV_RANDOM
  if (m_count < nbytes)
    {
      i = read_mbytes(300, NAME_OF_DEV_RANDOM, &nbuf[m_count], nbytes-m_count);
      if (i == 0)
	sh_error_handle ((-1), FIL__, __LINE__, EIO, MSG_NODEV, 
			 (long) sh.real.uid, NAME_OF_DEV_RANDOM);
      else
	m_count += i;
    }
#endif


  if (m_count > 0)
    {
      /* -- Add previous entropy into the new pool. --
       */
      memset(addbuf, '\0', sizeof(addbuf));
      for (i = 0; i < m_count; ++i)
	addbuf[i]         = nbuf[i];
      for (i = 0; i < KEY_BYT; ++i)
	addbuf[i+KEY_BYT] = skey->poolv[i];
      keybuf = (char *) sh_tiger_hash_uint32 (addbuf, 
					      TIGER_DATA, 2 * KEY_BYT,
					      kbuf, KEY_BYT/sizeof(UINT32));
      memset(addbuf, '\0', sizeof(addbuf));
      
      /* -- Give out nbytes bytes from the new pool. --
       */
      SH_MUTEX_LOCK_UNSAFE(mutex_skey);
      for (i = 0; i < KEY_BYT; ++i)
	{
	  skey->poolv[i] = keybuf[i];
	  if (i < nbytes) 
	    nbuf[i] = keybuf[i];
	}
      SH_MUTEX_UNLOCK_UNSAFE(mutex_skey);
      memset (keybuf, '\0', KEY_BYT);
      memset (kbuf,   '\0', sizeof(kbuf));
      
      SL_RETURN(0, _("sh_entropy"));
    }
  else
    {
      SL_RETURN((-1), _("sh_entropy"));
    }
}

/* HAVE_URANDOM */
#endif

#ifdef HAVE_UNIX_RANDOM

#ifndef FD_SET
#define NFDBITS         32
#define FD_SET(n, p)    ((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define FD_CLR(n, p)    ((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define FD_ISSET(n, p)  ((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#endif /* !FD_SET */
#ifndef FD_SETSIZE
#define FD_SETSIZE      32
#endif
#ifndef FD_ZERO
#define FD_ZERO(p)      memset((char *)(p), '\0', sizeof(*(p)))
#endif

#include "sh_static.h"
#include "sh_pthread.h"

static
char   * com_path[] = {
  N_("/usr/bin/xpg4/"),
  N_("/usr/ucb/"),
  N_("/bin/"),
  N_("/sbin/"),
  N_("/usr/bin/"),
  N_("/usr/sbin/"),
  N_("/usr/local/bin/"),
  N_("/opt/local/bin/"),
  NULL
};


typedef struct {
  char   * command;
  char   * arg;
  int      pipeFD;
  pid_t    pid;
  int      isset;
  FILE   * pipe;
} sourcetable_t;

static
sourcetable_t source_template[] = {
  { N_("w"),
    N_("w"),
    0,
    0,
    0,
    NULL },
  { N_("netstat"),
    N_("netstat -n"),
    0,
    0,
    0,
    NULL },
  { N_("ps"),
    N_("ps -ef"),
    0,
    0,
    0,
    NULL },
  { N_("arp"),
    N_("arp -a"),
    0,
    0,
    0,
    NULL },
  { N_("free"),
    N_("free"),
    0,
    0,
    0,
    NULL },
  { N_("uptime"),
    N_("uptime"),
    0,
    0,
    0,
    NULL },
  { N_("procinfo"),
    N_("procinfo -a"),
    0,
    0,
    0,
    NULL },
  { N_("vmstat"),
    N_("vmstat"),
    0,
    0,
    0,
    NULL },
  { N_("w"), /* Play it again, Sam. */
    N_("w"),
    0,
    0,
    0,
    NULL },
  { NULL,
    NULL,
    0,
    0,
    0,
    NULL }
};


static FILE * sh_popen (sourcetable_t  *source, char * command)
{
  int i;
  int pipedes[2];
  FILE *outf = NULL;
  char * arg[4];
  char * envp[2];
  size_t len;
  char   arg0[80];
  char   arg1[80];

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
  struct passwd    pwd;
  char           * buffer;
  struct passwd *  tempres;
#else
  struct passwd * tempres;
#endif

  SL_ENTER(_("sh_popen"));

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
  buffer = SH_ALLOC(SH_PWBUF_SIZE);
  sh_getpwnam_r(DEFAULT_IDENT, &pwd, buffer, SH_PWBUF_SIZE, &tempres);
#else
  tempres = sh_getpwnam(DEFAULT_IDENT);
#endif

  strncpy (arg0, _("/bin/sh"), sizeof(arg0));
  arg[0] = arg0;
  strncpy (arg1, _("-c"), sizeof(arg1));
  arg[1] = arg1;
  arg[2] = command;
  arg[3] = NULL;

  if (sh.timezone != NULL)
    {
      len = sl_strlen(sh.timezone) + 4;
      envp[0] = calloc(1, len);     /* free() ok     */
      if (envp[0] != NULL)
	sl_snprintf (envp[0], len, "TZ=%s", sh.timezone);
      else
	envp[0] = NULL;
      envp[1] = NULL;
    }
  else
    {
      envp[0] = NULL;
    }

  
  /* Create the pipe 
   */
  if (aud_pipe(FIL__, __LINE__, pipedes) < 0) {
    if (envp[0] != NULL) free(envp[0]);
    SL_RETURN(NULL, _("sh_popen"));
  }
  
  fflush (NULL);

  source->pid = aud_fork(FIL__, __LINE__);
  
  /* Failure
   */
  if (source->pid == (pid_t) - 1) {
    sl_close_fd(FIL__, __LINE__, pipedes[0]);
    sl_close_fd(FIL__, __LINE__, pipedes[1]);
    if (envp[0] != NULL) free(envp[0]);
    SL_RETURN(NULL, _("sh_popen"));
  }

  if (source->pid == (pid_t) 0) 
    {
      int val_return;

      /* child - make read side of the pipe stdout 
       */
      do {
	val_return = dup2 (pipedes[STDOUT_FILENO], STDOUT_FILENO);
      } while (val_return < 0 && errno == EINTR);

      if (val_return < 0)
	_exit(EXIT_FAILURE);
      
      /* close the pipe descriptors 
       */
      sl_close_fd   (FIL__, __LINE__, pipedes[STDIN_FILENO]);
      sl_close_fd   (FIL__, __LINE__, pipedes[STDOUT_FILENO]);

      /* don't leak file descriptors
       */
      sh_unix_closeall (3, -1, S_TRUE); /* in child process */

      /* zero priv info
       */
      memset(skey, 0, sizeof(sh_key_t));

      /* drop root privileges
       */
      i = 0; 
      if (0 == geteuid()) 
	{
  
	  if (NULL != tempres) {
	    i = setgid(tempres->pw_gid);

	    /*** locks up in dnmalloc ***/
	    /*
	     * if (i == 0)
	     *   i = sh_unix_initgroups(DEFAULT_IDENT ,tempres->pw_gid);
	     */

	    if (i == 0) 
	      i = setuid(tempres->pw_uid);
	    /* make sure we cannot get root again
	     */
	    if ((tempres->pw_uid != 0) && 
		(setuid(0) >= 0))
	      i = -1;
	  } else {
	    i = -1;
	  }
	}
      
      /* some problem ...
       */
      if (i == -1) {
	_exit(EXIT_FAILURE);
      }
      
      /* cppcheck-suppress leakNoVarFunctionCall */
      if (NULL != freopen (_("/dev/null"), "r+", stderr))
	{
      
	  /* exec the program */
	  do {
	    val_return = execve (_("/bin/sh"), arg, envp);
	  } while (val_return < 0 && errno == EINTR);
	}

      /* failed 
       */
      _exit(EXIT_FAILURE);
    }

  /* parent
   */
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
  SH_FREE(buffer);
#endif

  if (envp[0] != NULL) 
    free(envp[0]);
  
  sl_close_fd (FIL__, __LINE__, pipedes[STDOUT_FILENO]);
  retry_fcntl (FIL__, __LINE__, pipedes[STDIN_FILENO], F_SETFD, FD_CLOEXEC);
  
  outf = fdopen (pipedes[STDIN_FILENO], "r");
  
  if (outf == NULL) 
    {
      aud_kill (FIL__, __LINE__, source->pid, SIGKILL);
      sl_close_fd (FIL__, __LINE__, pipedes[STDOUT_FILENO]);
      waitpid (source->pid, NULL, 0);
      source->pid = 0;
      SL_RETURN(NULL, _("sh_popen"));
    }
  
  SL_RETURN(outf, _("sh_popen"));
}


static int sh_pclose (sourcetable_t *source)
{
    int status = 0;
    int retval;
    char msg[128];
    char errbuf[SH_ERRBUF_SIZE];

    SL_ENTER(_("sh_pclose"));

    retval = sl_fclose(FIL__, __LINE__, source->pipe);
    if (retval)
      {
	sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, retval, 
			 MSG_E_SUBGEN,
			 sh_error_message(retval, errbuf, sizeof(errbuf)),
                         _("sh_pclose"));
	SL_RETURN((-1), _("sh_pclose"));
      }

    retval = waitpid(source->pid, &status, 0);
    if (retval != source->pid)
      {
	sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, retval, 
			 MSG_E_SUBGEN,
			 sh_error_message(retval, errbuf, sizeof(errbuf)),
                         _("sh_pclose"));

	status = -1;
      }
#if !defined(USE_UNO)
    else if (WIFSIGNALED(status))
      {
	sl_snprintf(msg, sizeof(msg), _("Subprocess terminated by signal %d"),
		    WTERMSIG(status));
	sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, retval, 
			 MSG_E_SUBGEN,
			 msg,
                         _("sh_pclose"));
	status = -1;
      }
#endif

    source->pipe = NULL;
    source->pid = 0;
    SL_RETURN(status, _("sh_pclose"));
}

#define BUF_ENT 32766

/* Poll the system for randomness, mix results with 
 * previous reads using a hash function, and give out
 * nbytes bytes from the result.
 */
int sh_entropy(int nbytes, char * nbuf)
{
  int    caperr;
  char   combuf[80];
  char * buffer;
  int    i, j, icount;
  int    bufcount = 0;
  int    count;

  char * keybuf;
  UINT32 kbuf[KEY_BYT/sizeof(UINT32)];
  char   addbuf[2 * KEY_BYT];

  struct timeval tv;
  fd_set fds;
  unsigned long select_now = 0;
  int    maxFD = 0;
  int    imax, selcount;
  char errbuf[SH_ERRBUF_SIZE];

  sourcetable_t  *source = NULL;
  
  SL_ENTER(_("sh_entropy"));

  ASSERT((nbytes <= KEY_BYT), _("nbytes <= KEY_BYT"))

  if (nbytes > KEY_BYT)
    nbytes = KEY_BYT;


  /* --- If there is entropy in the pool, return it. ---
   */
  SH_MUTEX_LOCK_UNSAFE(mutex_skey);
  if (skey->poolc >= nbytes)
    {
      j = KEY_BYT - skey->poolc;
      for (i = 0; i < nbytes; ++i)
	{
	  nbuf[i] = skey->poolv[i+j];
	  --skey->poolc;
	}
      SH_MUTEX_UNLOCK_UNSAFE(mutex_skey); /* alternative path */
      SL_RETURN(0, _("sh_entropy"));
    }
  SH_MUTEX_UNLOCK_UNSAFE(mutex_skey);


  FD_ZERO(&fds);   

  i = 0; icount = 0;
  buffer = SH_ALLOC(BUF_ENT+2);

  if (0 != (caperr = sl_get_cap_sub()))
    {
      sh_error_handle((-1), FIL__, __LINE__, caperr, MSG_E_SUBGEN,
		      sh_error_message (caperr, errbuf, sizeof(errbuf)), 
		      _("sl_get_cap_sub"));
    }

  while (source_template[i].command != NULL) {
    ++i;
  }
  source = SH_ALLOC(i * sizeof(sourcetable_t));
  for (j = 0; j < i;++j)
    memcpy(&source[j], &source_template[j], sizeof(sourcetable_t));
  i = 0;

  while (source_template[i].command != NULL) {

    j = 0;
    while (com_path[j] != NULL)
      {
	sl_strlcpy(combuf, _(com_path[j]),       80);
	sl_strlcat(combuf, _(source[i].command), 80);

	/* flawfinder: ignore */
	if ( access (combuf, X_OK) == 0) 
	  {
	    sl_strlcpy(combuf, _(com_path[j]),       80);
	    sl_strlcat(combuf, _(source[i].arg),     80);
	    sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_ENSTART,
			     combuf);
	    break;
	  }
	++j;
      }

    /* Not found, try next command. 
     */
    if (com_path[j] == NULL) 
      { 
	++i;
	continue;
      }

    /* Source exists
     */
    source[i].pipe   = sh_popen  ( &source[i], combuf );
    if (NULL != source[i].pipe)
      { 
	source[i].pipeFD = fileno ( source[i].pipe    );
	sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_ENEXEC,
			 combuf, (long) source[i].pipeFD);

	maxFD = (source[i].pipeFD > maxFD) ? source[i].pipeFD : maxFD;
	retry_fcntl( FIL__, __LINE__, source[i].pipeFD, F_SETFL, O_NONBLOCK);
	FD_SET( source[i].pipeFD, &fds );
	source[i].isset = 1;
	++icount;
      }
    else
      {
	sh_error_handle ((-1), FIL__, __LINE__, EIO, MSG_ENFAIL,
			 combuf);
      }

    ++i;
  }

  imax       = i;
  tv.tv_sec  = 1;
  tv.tv_usec = 0;
  bufcount   = 0;

  while ( (icount > 0) && (bufcount < BUF_ENT) ) {

    if ( (selcount = select (maxFD+1, &fds, NULL, NULL, &tv)) == -1) 
      break;

    /* reset timeout for select()
     */
    tv.tv_sec  = 1;
    tv.tv_usec = 0;

    /* timeout - let's not hang on forever
     */
    if (selcount == 0) 
      {
	++select_now;
	sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_ENTOUT,
			 (unsigned long) select_now);
	if ( select_now > 9 ) 
	  break;
      }
    
    for (i = 0; i < imax; ++i) {

      if ( FD_ISSET (source[i].pipeFD, &fds) ) {
	count = fread (&buffer[bufcount], 
		       1, 
		       BUF_ENT-bufcount, 
		       source[i].pipe );
	if (count == 0) 
	  {
	    if (0 != feof(source[i].pipe))
	      sh_error_handle ((-1), FIL__, __LINE__, EIO, MSG_ENCLOS,
			       (long) source[i].pipeFD);
	    else
	      sh_error_handle ((-1), FIL__, __LINE__, EIO, MSG_ENCLOS1,
			       (long) source[i].pipeFD);
	    source[i].isset = 0;
	    sh_pclose ( &source[i] );
	    --icount;
	  }
	else
	  {
	    sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_ENREAD,
			     (long) source[i].pipeFD, (long) count);
	  }
	bufcount += count;

      } 
    }

    maxFD = 0;
    FD_ZERO(&fds);   
    
    for (i = 0; i < imax; ++i)
      {
	if (source[i].isset == 1)
	  { 
	    FD_SET( source[i].pipeFD, &fds );
	    maxFD = (source[i].pipeFD > maxFD) ? source[i].pipeFD : maxFD;
	  }
      }
  }

  for (i = 0; i < imax; ++i) 
    {
      if (source[i].isset == 1)
	{
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_ENCLOS1,
			     (long) source[i].pipeFD);
	  sh_pclose ( &source[i] );
	}
    }
  buffer[bufcount] = '\0';
  
  SH_FREE(source);

  if (0 != (caperr = sl_drop_cap_sub()))
    {
      sh_error_handle((-1), FIL__, __LINE__, caperr, MSG_E_SUBGEN,
		      sh_error_message (caperr, errbuf, sizeof(errbuf)), 
		      _("sl_drop_cap_sub"));
    }

#ifdef HAVE_GETTIMEOFDAY
  {
    unsigned short tseed[3];

    gettimeofday(&tv, 0);
    tseed[0] = tv.tv_sec & 0xFFFF;
    tseed[1] = tv.tv_usec & 0xFFFF;
    tseed[2] = (tv.tv_sec ^ tv.tv_usec) >> 16;
    keybuf = (char *) sh_tiger_hash_uint32 ((char *) tseed, 
					    TIGER_DATA, sizeof(tseed),
					    kbuf, KEY_BYT/sizeof(UINT32));
    memset(addbuf, '\0', sizeof(addbuf));
    for (i = 0; i < KEY_BYT; ++i)
      {
	addbuf[i]         = keybuf[i];
	addbuf[i+KEY_BYT] = skey->poolv[i];
      }
    SH_MUTEX_LOCK_UNSAFE(mutex_skey);
    for (i = 0; i < KEY_BYT; ++i)
      skey->poolv[i] ^= keybuf[i];
    SH_MUTEX_UNLOCK_UNSAFE(mutex_skey);
  }
#endif

  if (bufcount > 0) 
    {
      keybuf = (char *) sh_tiger_hash_uint32 (buffer, 
					      TIGER_DATA, sl_strlen(buffer),
					      kbuf, KEY_BYT/sizeof(UINT32));

      /* add previous entropy into the new pool
       */
      memset(addbuf, '\0', sizeof(addbuf));
      for (i = 0; i < KEY_BYT; ++i)
	{
	  addbuf[i]         = keybuf[i];
	  addbuf[i+KEY_BYT] = skey->poolv[i];
	}
      keybuf = (char *) sh_tiger_hash_uint32 (addbuf, 
					      TIGER_DATA, sizeof(addbuf),
					      kbuf, KEY_BYT/sizeof(UINT32));
      memset(addbuf, '\0', sizeof(addbuf));
      
      /* store in system pool
       */
      SH_MUTEX_LOCK_UNSAFE(mutex_skey);
      for (i = 0; i < KEY_BYT; ++i)
	skey->poolv[i] = keybuf[i];
      skey->poolc = KEY_BYT;
      SH_MUTEX_UNLOCK_UNSAFE(mutex_skey);
      memset (buffer, '\0', BUF_ENT+2);
      memset (keybuf, '\0', KEY_BYT);
      SH_FREE(buffer);
    } 
  else 
    {
      SH_FREE(buffer);
      SL_RETURN((-1), _("sh_entropy"));
    }

  /* give out nbytes Bytes from the entropy pool
   */
  SH_MUTEX_LOCK_UNSAFE(mutex_skey);
  for (i = 0; i < nbytes; ++i)
    {
      nbuf[i] = skey->poolv[i];
      --skey->poolc;
    }
  SH_MUTEX_UNLOCK_UNSAFE(mutex_skey);

  SL_RETURN(0, _("sh_entropy"));
}

/* HAVE_UNIX_RANDOM */
#endif

#ifdef SH_CUTEST
#include "CuTest.h"

void Test_entropy (CuTest *tc)
{
  char                 bufx[9 * sizeof(UINT32) + 1];
  char                 bufy[9 * sizeof(UINT32) + 1];
  int                  status;
  int                  count;

  for (count = 0; count < 20; ++count)
    {
      memset(skey->poolv, '\0', KEY_BYT);
      skey->poolc = 0;

      status = sh_entropy (24, bufx);
      CuAssertTrue(tc, 0 == status);
      
      memset(skey->poolv, '\0', KEY_BYT);
      skey->poolc = 0;

      status = sh_entropy (24, bufy);
      CuAssertTrue(tc, 0 == status);
      
      CuAssertTrue(tc, 0 != memcmp(bufx, bufy, 24));
    }
}
#endif








