/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2000 Rainer Wichmann                                      */
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
#include <unistd.h>
#include <time.h>

#include "samhain.h"
#include "sh_error.h"
#include "sh_utils.h"
#include "sh_tiger.h"

#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
#include <sys/mman.h>
#endif


#undef  FIL__
#define FIL__  _("sh_err_log.c")

#undef  FIX_XML
#define FIX_XML 1 

#define MYSIGLEN (2*KEY_LEN + 32)

typedef struct _sh_log_buf {
  char   signature[KEY_LEN+1];
  char   timestamp[KEY_LEN+1];
#ifdef SH_USE_XML
  char   sig[MYSIGLEN];
#endif
  char * msg;
} sh_sh_log_buf;

extern struct  _errFlags  errFlags;

#define CHK_KEY 0
#define CHK_FIL 1
#define CHK_NON 2

static int get_key_from_file(char * path, char * keyid, char * key)
{
  SL_TICKET  fd;
  char * buf;
  char * bufc;

  if (path[strlen(path)-1] == '\n')
    path[strlen(path)-1] = '\0';

  /* open the file, then check it 
   */
  if ( SL_ISERROR(fd = sl_open_read (FIL__, __LINE__, path, SL_NOPRIV)))
    {
      fprintf(stderr, _("Could not open file <%s>\n"), path);
      _exit (EXIT_FAILURE);
    }

  buf     = SH_ALLOC( (size_t)(SH_BUFSIZE+1));
  bufc    = SH_ALLOC( (size_t)(SH_MAXBUF+1));

  while (1 == 1)
    {
      buf[0]  = '\0';
      bufc[0] = '\0';

      /* find start of next key
       */
      while (0 != sl_strncmp(buf, _("-----BEGIN LOGKEY-----"),
			     sizeof("-----BEGIN LOGKEY-----")-1)) 
	{
	  (void) sh_unix_getline (fd, buf, SH_BUFSIZE);
	  if (buf[0] == '\0')
	    {
	      /* End of file reached, return. 
	       */
	      (void) fflush(stdout);
	      (void) sl_close(fd);
	      return -1; 
	    }
	}

      /* read key
       */
      (void) sh_unix_getline (fd, buf, SH_BUFSIZE);

      if (0 == sl_strncmp(keyid, &buf[KEY_LEN], strlen(keyid)))
	{
	  (void) sl_strlcpy(key, buf, KEY_LEN+1);
	  (void) sl_close(fd);
	  return 0;
	}
    }
	  
  /*@notreached@*/
}

static int just_list = S_FALSE;

int sh_error_logverify_mod (const char * s)
{
  just_list = S_TRUE;
  if (s)      /* compiler warning (unused var) fix */
    return 0;
  else
    return 0;
} 

int sh_error_logverify (const char * s)
{
  SL_TICKET fd;
  int len;
  int status;
  int count =  0;
  int start = -1;
  char * buf;
  char * bufc;
#ifdef SH_USE_XML
  char * ptr;
  int fixed_xml = S_TRUE;
  char c_start;
#endif
  char signature[64];
  char key[KEY_LEN+2];
  char path[KEY_LEN+1];
  char timestamp[64];
  char c_cont;
  int  chk_mode = CHK_KEY;
  char hashbuf[KEYBUF_SIZE];

  sh_error_logoff();

  if (s == NULL || sl_strlen(s) >= PATH_MAX)
    {
      fprintf(stderr, _("FAIL: msg=\"Invalid input\", path=\"%s\"\n"), s);
      _exit (EXIT_FAILURE);
    }

  /* Open the file, then check it. 
   */
  if (0 != sl_is_suid())
    {
      fprintf(stderr, _("Cannot open file %s in suid mode\n"), s);
      _exit (EXIT_FAILURE);
    }

  if ( SL_ISERROR(fd = sl_open_read (FIL__, __LINE__, s, SL_NOPRIV)) )
    {
      fprintf(stderr, 
	      _("FAIL: msg=\"File not accessible\", error=\"%ld\", path=\"%s\"\n"), fd, s);
      _exit (EXIT_FAILURE);
    }

  /* Find space value.
   */
  c_cont  = ' ';
#ifdef SH_STEALTH
  c_cont ^= XOR_CODE;
#endif

#ifdef SH_USE_XML
  c_start  = '<';
#ifdef SH_STEALTH
  c_start ^= XOR_CODE;
#endif
#endif

  buf  = (char *) SH_ALLOC( 2*SH_MSG_BUF+1 );
  bufc = (char *) SH_ALLOC( 2*SH_MSG_BUF+1 );

  while (1 == 1) 
    {
      /* get the log message
       */
      if (sh_unix_getline (fd, buf, (2*SH_MSG_BUF)) < 0) 
	break;

      len = (int) sl_strlen(buf);

#ifdef SH_USE_XML
#ifdef SH_STEALTH
      if (0 == sl_strncmp (buf, N_("<trail>"), 7)) 
#else
      if (0 == sl_strncmp (buf, _("<trail>"),  7)) 
#endif
#else 
#ifdef SH_STEALTH
      if (0 == sl_strncmp (buf, N_("[SOF]"), 5)) 
#else
      if (0 == sl_strncmp (buf, _("[SOF]"),  5)) 
#endif
#endif
	{
	  if (just_list == S_TRUE)
	    {
#ifdef SH_STEALTH
	      sh_do_decode (buf, sl_strlen(buf));
#endif
	      fprintf (stdout, _("%s\n"), buf);
	    }

	  /* Found start of audit trail, read first line. 
	   */
	  start = 1;
	  do {
	    if ( sh_unix_getline (fd, buf, (2*SH_MSG_BUF)) < 0)
	      break;
	  } while (buf[0] == '\0' || buf[0] == '\n');
	  len = (int) sl_strlen(buf);

	  if (just_list == S_TRUE)
	    {
#ifdef SH_STEALTH
	      if (buf[0] != '\n') 
		sh_do_decode (buf, sl_strlen(buf));
#endif
	      fprintf (stdout, _("%s\n"), buf);
	      start = 0;
	    }

	  ++count;
	}
      else if (buf[0] == '\n'
#ifdef SH_USE_XML
	       ||
#ifdef SH_STEALTH
	       0 == sl_strncmp(buf, N_("</trail>"), 7)
#else
	       0 == sl_strncmp(buf,  _("</trail>"), 7)
#endif
#endif
	       )
	{
	  if (just_list == S_TRUE)
	    {
#ifdef SH_STEALTH
	      if (buf[0] != '\n') 
		sh_do_decode (buf, sl_strlen(buf));
#endif
	      fprintf (stdout, _("%s\n"), buf);
	    }

	  /* A newline.
	   */
	  ++count;
	  continue;
	}
      else if (start == 0)
	{
	  /* We are inside an audit trail. 
	   */
	  ++count;
	  if (just_list == S_TRUE)
	    {
#ifdef SH_STEALTH
	      sh_do_decode (buf, sl_strlen(buf));
#endif
	      fprintf (stdout, _("%s\n"), buf);
	      continue;
	    }
	}
      else
	{
	  /* No start-of-file found yet. 
	   */
	  continue;
	}

      if (just_list == S_TRUE)
	continue;

      /* Check for a continuation line.
       */
      while (1 == 1)
	{
	  do {
	    if ( sh_unix_getline (fd, bufc, (2*SH_MSG_BUF)) < 0)
	      break;
	  } while (bufc[0] == '\0' || bufc[0] == '\n');
	  ++count;
	  if (bufc[0] == c_cont) 
	    {
	      /* A continuation line. Add the newline. 
	       */
	      (void) sl_strlcat(buf, "\n", 2*SH_MSG_BUF+1);
	      ++len;
	      (void) sl_strlcat(buf, bufc, 2*SH_MSG_BUF+1);
	      len += (int) sl_strlen(bufc);
	    }
	  else
	    {
	      /* No continuation line. Use it as signature. 
	       * A48014C05604EF7C9472330E85453E704024943E556163C2
	       */
#ifdef SH_USE_XML
#ifdef SH_STEALTH
	      if (bufc[0] == c_start) /* FIX XML */
#else
	      if (bufc[0] == c_start)
#endif
		{
		  (void) sl_strlcpy(signature, &bufc[5], KEY_LEN+1);
		  fixed_xml = S_TRUE;
		}
	      else
		{
		  (void) sl_strlcpy(signature, &bufc[4], KEY_LEN+1);
		  fixed_xml = S_FALSE;
		}
	      if (sl_strlen(bufc) > (KEY_LEN+18))
		{
#ifdef SH_STEALTH
		  if (bufc[0] == c_start) /* FIX XML */
#else
		  if (bufc[0] == c_start)
#endif
		    (void) sl_strlcpy(timestamp, &bufc[KEY_LEN+5], 64);
		  else
		    (void) sl_strlcpy(timestamp, &bufc[KEY_LEN+4], 64);
#ifdef SH_STEALTH
		  ptr = strchr(timestamp, c_start);
#else
		  ptr = strchr(timestamp, c_start);
#endif
		  if (ptr) *ptr = '\0';
		}
	      break;
#else
	      sl_strlcpy(signature, bufc, KEY_LEN+1);
	      if (sl_strlen(bufc) > KEY_LEN)
		sl_strlcpy(timestamp, &bufc[KEY_LEN], 64);
	      break;
#endif
	    }
	}
      
      /* Get starting key from command line. 
       */    
      if (start == 1) 
	{
	  
	  /* Get the timestamp.
	   */
	  
#ifdef SH_STEALTH
	  sh_do_decode (timestamp, sl_strlen(timestamp));
#endif
	  key[0] = '\0';
	  
	findKey:
	  
	  if (chk_mode != CHK_FIL)
	    {
	      /* Ask for the key.
	       */
	      chk_mode = CHK_KEY;
	      fprintf(stdout, _("\nNew audit trail (%s), enter key|keyfile: "),
		      /*@-usedef@*/timestamp/*@+usedef@*/);
	      key[0] = '\0';
	      
	      while (strlen(key) < KEY_LEN ) 
		{ 
		  if (key[0] != '\n' && key[0] != '\0')
		    fprintf(stdout, "%s",_("New audit trail, enter key: "));
		  else if (key[0] == '\n')
		    {
		      (void) sl_strlcpy(key, 
					sh_tiger_hash(NULL, TIGER_DATA, 0, 
						      hashbuf, sizeof(hashbuf)), 
					KEY_LEN+1);
		      chk_mode = CHK_NON;
		      break;
		    }
		  (void) fflush(stdout); 
		  key[0] = '\0';
		  if (NULL != fgets(key, sizeof(key), stdin))
		    {
		      if (key[0] != '\n') 
			{
			  if (key[strlen(key) - 1] == '\n')
			    key[strlen(key) - 1] = '\0';
			}
		      if (key[0] == '/')
			{
			  chk_mode = CHK_FIL;
			  (void) sl_strlcpy(path, key, KEY_LEN+1); 
			  break;
			}
		    }
		}
	    }
	  /* we now have either a key (chk_mode == CHK_NON|CHK_KEY)
	   * or a file (chk_mode == CHK_FIL)
	   */
	  if (chk_mode == CHK_FIL)
	    {
	      fprintf(stdout, _("\nAudit trail (%s), searching file %s\n"), 
		      /*@-usedef@*/timestamp, path/*@+usedef@*/);
	      if (-1 == get_key_from_file(path, timestamp, key))
		{
		  chk_mode = CHK_KEY;
		  fprintf(stdout, "%s",_("Key not found in file\n"));
		  goto findKey;
		}
	    }
	  
	  
	  sh_util_encode(key, buf, 1, 'B');
	  start = 0;
	} 
      else
	{ 
	  /* Iterate the key.
	   */
	  (void) sl_strlcpy (key, 
			     sh_tiger_hash (key, TIGER_DATA, KEY_LEN,
					    hashbuf, sizeof(hashbuf)), 
			     KEY_LEN+1);
	}
      
      (void) sl_strlcat ( buf, key, 2*SH_MSG_BUF + 1);
      
#ifdef SH_STEALTH
      sh_do_decode (signature, sl_strlen(signature));
#endif
      
      status = sl_strncmp (signature, 
			   sh_tiger_hash (buf, TIGER_DATA, 
					  (unsigned long) sl_strlen(buf),
					  hashbuf, sizeof(hashbuf)),
			   KEY_LEN);
      
      buf[len] = '\0';    /* do not print out the key */
#ifdef SH_STEALTH
      sh_do_decode (buf, sl_strlen(buf));
#endif
      
      if (status != 0) 
	{
#ifdef SH_USE_XML
	  if (chk_mode == CHK_NON)
	    {
	      if (fixed_xml == S_FALSE)
		fprintf (stdout, _("XFAIL: line=%05d %s/log>\n"), 
			 count-1, buf);
	      else
		fprintf (stdout, _("XFAIL: line=%05d %s</log>\n"), 
			 count-1, buf);
	    }
	  else
	    {
	      if (fixed_xml == S_FALSE)
		fprintf (stdout, _("FAIL:  line=%05d %s/log>\n"), 
			 count-1, buf);
	      else
		fprintf (stdout, _("FAIL:  line=%05d %s</log>\n"), 
			 count-1, buf);
	    }
#else
	  if (chk_mode == CHK_NON)
	    fprintf (stdout, _("XFAIL: line=%5d %s\n"), count-1, buf);
	  else
	    fprintf (stdout, _("FAIL:  line=%5d %s\n"), count-1, buf);
#endif
	}
      else
	{
#ifdef SH_USE_XML 
	  if (fixed_xml == S_FALSE)
	    fprintf (stdout, _("PASS:  line=%05d %s/log>\n"),  count-1, buf);
	  else
	    fprintf (stdout, _("PASS:  line=%05d %s</log>\n"), count-1, buf);
#else
	  fprintf (stdout, _("PASS:  line=%5d %s\n"), count-1, buf);
#endif    
	}
    }

  /* Cleanup and exit.
   */
  (void) sl_close (fd);
  SH_FREE  (buf);
  SH_FREE  (bufc);
  (void) fflush   (stdout);
  _exit    (EXIT_SUCCESS);

  /* Make compilers happy. 
   */
  /*@notreached@*/
  return 0; 
}

/********************************************************************
 *
 *  Runtime code
 *
 ********************************************************************/
static
int sh_log_open (char * inet_peer, 
                 char * logfile, int * service_failure, SL_TICKET * fildesc)
{
  SL_TICKET            fd = -1;
  long int             status;
  char               * tmp = NULL;
  uid_t                uid;
  size_t               len;
  char               * lockfile = NULL;

  SL_ENTER(_("sh_log_open"));

  /* open/create the file, then check it 
   */

  if (  0 !=  (status = tf_trust_check (logfile, SL_YESPRIV))
        && (*service_failure) == 0)
    {
      tmp  = sh_util_safe_name (logfile);
      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_TRUST,
                      (long) sh.effective.uid, tmp);
    }

  if (status == 0)
    {
      fd = sl_open_write (FIL__, __LINE__, logfile, SL_YESPRIV);
      if (SL_ISERROR(fd))
        {
	  tmp  = sh_util_safe_name (logfile);
	  (void) sl_get_euid(&uid);
          if ((*service_failure) == 0)
            sh_error_handle ((-1), FIL__, __LINE__, fd, MSG_E_ACCESS,
                             (long) uid, tmp);
          status = -1;
        }
    }


  if (status == 0 && inet_peer == NULL )
    {
      status = sh_unix_write_lock_file(logfile);
      if (status < 0)
        {
	  tmp  = sh_util_safe_name (logfile);
	  len      = sl_strlen(tmp);
	  if (sl_ok_adds (6, len))
	    len += 6;
	  lockfile = SH_ALLOC(len);
	  (void) sl_strlcpy(lockfile,        tmp, len);
	  (void) sl_strlcat(lockfile, _(".lock"), len);
          (void) sl_get_euid(&uid);
          if ((*service_failure) == 0)
            sh_error_handle ((-1), FIL__, __LINE__, status, MSG_LOCKED,
                             (long) uid, tmp, lockfile);
          status = -1;
	  SH_FREE(lockfile);
          (void) sl_close(fd);
        }
    }

  if (status == 0)
    {
      status = sl_forward(fd); 
      if (SL_ISERROR(status))
        {
	  tmp  = sh_util_safe_name (logfile);
          (void) sl_get_euid(&uid);
          if ((*service_failure) == 0)
            sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_ACCESS,
                             (long) uid, tmp);
          status = -1;
          (void) sl_close(fd);
        }
    }
  
  if (status < 0)
    {
      if ((*service_failure) == 0) {
        sh_error_handle ((-1), FIL__, __LINE__, status, MSG_SRV_FAIL,
                         _("logfile"), tmp);
        (*service_failure) = 1;
      }
      if (tmp)
	SH_FREE(tmp);
      SL_RETURN(-1, _("sh_log_open"));
    }

  *fildesc         = fd;
  *service_failure = 0;
  SL_RETURN(0, _("sh_log_open"));
}

typedef struct lfstc {
  char          * logfile;
  int             service_failure;
  int             log_start;
  char            sigkey_old[KEY_LEN+1];
  char            sigkey_new[KEY_LEN+1];
  char            crypto[KEY_LEN+1];
  struct  lfstc * next;
} open_logfile;

static open_logfile * logfile_list = NULL;

static int flag_sep_log = S_FALSE;

#ifdef SH_WITH_SERVER
int set_flag_sep_log (const char * str)
{
  return sh_util_flagval(str, &flag_sep_log);
}
#endif

/*
 *   --- Log error message to log file. ---
 */
int  sh_log_file (/*@null@*/char *errmsg, /*@null@*/char * inet_peer)
{
  int                  store1;
  int                  store2;
  int                  store3;
  int                  store4;
  int                  store5;
  int                  store6;
  int                  store7;
  int                  store8;

  SL_TICKET            fd = -1;
  size_t               status;
  struct _sh_log_buf   log_msg;

  char                 logfile[SH_PATHBUF+SH_MINIBUF+2];
  open_logfile       * current = logfile_list;  
  open_logfile       * next    = NULL;
  char               * sigkey_new;
  char               * sigkey_old;
  char               * crypto;
  char                 hashbuf[KEYBUF_SIZE];

  SL_ENTER(_("sh_log_file"));

  if (errFlags.HaveLog == BAD)  /* paranoia */ 
    SL_RETURN((-1), _("sh_log_file"));

#ifdef SH_USE_XML
  if (NULL == errmsg)
    {
      while (current != NULL)
        {
	  /* don't write second EOF mark
	   */
	  if (current->log_start != S_TRUE && sh.flag.islocked == GOOD)
	    {
	      /* Don't use inet_peer == NULL, userwise a lock file will
	       * be created.
	       */
	      (void) sh_log_open ("\0", 
				  current->logfile, 
				  &(current->service_failure), &fd);
          
#ifdef SH_STEALTH
	      (void) sl_write_line (fd, N_("</trail>"), 7);
	      (void) sl_write (fd, "\n", 1);
	      (void) sl_sync(fd);
#else
	      (void) sl_write_line (fd, _("</trail>\n"),  8);
	      (void) sl_sync(fd);
#endif
	      (void) sl_close(fd);
	      /* sh_unix_rm_lock_file (current->logfile); */
	    }
	  next    = current->next;
	  SH_FREE(current->logfile);
	  SH_FREE(current);
	  current = next;
	}
      logfile_list = NULL;
      SL_RETURN( 0, _("sh_log_file"));
    }
#else
  if (NULL == errmsg)
    {
      while (current != NULL)
        {
	  /* sh_unix_rm_lock_file (current->logfile); */
	  next    = current->next;
          SH_FREE(current->logfile);
          SH_FREE(current);
          current = next;
        }
      logfile_list = NULL;
      SL_RETURN( 0, _("sh_log_file"));
    }
#endif

  (void) sl_strlcpy (logfile, sh.srvlog.name, sizeof(logfile));
  if (inet_peer != NULL && flag_sep_log == S_TRUE)
    {
      (void) sl_strlcat (logfile, ".",       sizeof(logfile));
      (void) sl_strlcat (logfile, inet_peer, sizeof(logfile));
    }

  if (sh.flag.log_start == S_TRUE)
    {
      while (current != NULL)
        {
          current->log_start = S_TRUE;
          current = current->next;
        }
      sh.flag.log_start    = S_FALSE;
      current = logfile_list;
    }

  while (current != NULL)
    {
      if (strcmp(logfile, current->logfile) == 0)
        break;
      current = current->next;
    }

  if (current == NULL)
    {
      current                  = SH_ALLOC(sizeof(open_logfile));
      current->logfile         = SH_ALLOC(strlen(logfile) + 1);
      (void) sl_strlcpy(current->logfile, logfile, strlen(logfile) + 1);
      current->service_failure = 0;
      current->log_start       = S_TRUE;
      memset(current->sigkey_old, (int)'\0', KEY_LEN+1);
      memset(current->sigkey_new, (int)'\0', KEY_LEN+1);
      memset(current->crypto,     (int)'\0', KEY_LEN+1);
      current->next            = logfile_list;
      logfile_list             = current;
    }

  if (0 != sh_log_open (inet_peer, current->logfile, 
                        &(current->service_failure), &fd))
    {
      SL_RETURN ((-1), _("sh_log_file"));
    }


  /* --- Allocate storage and mlock it. ---
   */

  status      =  sl_strlen (errmsg);
  if (!sl_ok_adds(status, (2*KEY_LEN)) || !sl_ok_adds((2*KEY_LEN + status),32))
    {
      sl_close(fd);
      SL_RETURN ((-1), _("sh_log_file"));
    }
      
  log_msg.msg = (char *) SH_ALLOC ((size_t) (2*KEY_LEN + status + 32)); 

#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
  if (skey->mlock_failed == S_FALSE) 
    {
      if ( (-1) == sh_unix_mlock( FIL__, __LINE__, log_msg.msg, 
				  (size_t)(2*KEY_LEN + status + 32) ) ) 
	{
	  skey->mlock_failed = S_TRUE;
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)
	  sh_error_handle ((-1), FIL__, __LINE__, EPERM, MSG_MLOCK); 
#endif
	}
    }
#else
  if (skey->mlock_failed == S_FALSE) 
    {
      skey->mlock_failed = S_TRUE;
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)
      sh_error_handle ((-1), FIL__, __LINE__, EPERM, MSG_MLOCK);
#endif
    }
#endif

  /* --- Write the start marker. --- 
   */

  if (current->log_start == S_TRUE) 
    {
#ifdef SH_USE_XML
#ifdef SH_STEALTH
      (void) sl_write (fd, "\n", 1);
      (void) sl_write_line (fd, N_("<trail>"), 7);
      (void) sl_sync(fd);
#else
      (void) sl_write_line (fd, _("\n<trail>"),  8);
      (void) sl_sync(fd);
#endif
#else
#ifdef SH_STEALTH
      (void) sl_write (fd, "\n", 1);
      (void) sl_write_line (fd, N_("[SOF]"), 5);
      (void) sl_sync(fd);
#else
      (void) sl_write_line (fd, _("\n[SOF]"),  6);
      (void) sl_sync(fd);
#endif
#endif
    }

  /* reserve KEY_LEN chars at end for key 
   */
  (void) sl_strlcpy (log_msg.msg, errmsg, (size_t) status+1 );


#ifdef SH_USE_XML
  /* cut the trailing "/>"
   */
  if (log_msg.msg[status-2] == '/')
    {
#ifdef FIX_XML
      log_msg.msg[status-2] = ' '; /* ' ' FIX XML */
      log_msg.msg[status-1] = '>'; /* '>' FIX XML */
#else
      log_msg.msg[status-2] = '>'; /* ' ' FIX XML */
      log_msg.msg[status-1] = '<'; /* '>' FIX XML */
#endif
      log_msg.msg[status]   = '\0';
    }
  else if (status >= 6 && log_msg.msg[status-5] == '/' && 
	   log_msg.msg[status-6] == '<')
    {
#ifdef FIX_XML
      log_msg.msg[status-6]   = '\0';
      status -= 6;
#else
      log_msg.msg[status-5]   = '\0';
      status -= 5;
#endif
    }
#endif


#ifdef SH_STEALTH
  sh_do_encode (log_msg.msg, status);
#endif

  if (flag_sep_log == S_TRUE && inet_peer != NULL)
    {
      sigkey_old = current->sigkey_old;
      sigkey_new = current->sigkey_new;
      crypto     = current->crypto;
    }
  else
    {
      sigkey_old = skey->sigkey_old;
      sigkey_new = skey->sigkey_new;
      crypto     = skey->crypt;      /* flawfinder: ignore */
    }

  /* write the signature 
   */
  if (current->log_start == S_TRUE) 
    {
      if (sh.real.user[0] == '\0') 
	(void) sh_unix_getUser();

      /* Initialize the key.
       */
      (void) sh_util_keyinit(sigkey_old, KEY_LEN+1);

      /* Hash the key to make sure it has the correct format.
       */
      (void) sl_strlcpy(sigkey_new, 
			sh_tiger_hash (sigkey_old, TIGER_DATA, KEY_LEN,
				       hashbuf, sizeof(hashbuf)), 
			KEY_LEN+1);

      /* Copy it to 'crypt' for encryption.
       */
      (void) sl_strlcpy(crypto, sigkey_new, KEY_LEN+1);

      /* Use message and compiled-in key to encrypt.
       */
      BREAKEXIT(sh_util_encode);
      sh_util_encode(crypto, log_msg.msg, 0, 'B');

      /* Send out the key.
       */
      (void) sh_unix_time(0, log_msg.timestamp, KEY_LEN+1); 

      store1               = errFlags.loglevel;
      store2               = errFlags.sysloglevel;
      store3               = errFlags.printlevel;
      store4               = errFlags.exportlevel;
      store5               = errFlags.maillevel;
      store6               = errFlags.externallevel;
      store7               = errFlags.databaselevel;
      store8               = errFlags.preludelevel;

      /* mail the key
       */
      errFlags.loglevel       = SH_ERR_NOT;
      errFlags.sysloglevel    = SH_ERR_NOT;
      errFlags.printlevel     = SH_ERR_NOT;
      errFlags.exportlevel    = SH_ERR_NOT;
      errFlags.externallevel  = SH_ERR_NOT;
      errFlags.databaselevel  = SH_ERR_NOT;
      errFlags.preludelevel   = SH_ERR_NOT;

      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_START_KEY_MAIL,
		       sh.prg_name, crypto, 
		       crypto, log_msg.timestamp);

      /* send to other allowed channels
       */
      errFlags.maillevel      = SH_ERR_NOT;
      /* errFlags.printlevel     = store3; */
      errFlags.exportlevel    = store4;
      errFlags.externallevel  = store6;
      errFlags.databaselevel  = store7;
      errFlags.preludelevel   = store8;

      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_START_KEY,
		       sh.prg_name, crypto);

      /* Cleanup.
       */
      errFlags.loglevel       = store1;
      errFlags.sysloglevel    = store2;
      errFlags.printlevel     = store3;
      errFlags.exportlevel    = store4;
      errFlags.maillevel      = store5;
      errFlags.externallevel  = store6;
      errFlags.databaselevel  = store7;


      memset (crypto, (int) '\0', KEY_LEN);
      sh.flag.log_start    = S_FALSE;  
      current->log_start   = S_FALSE;
    } 
  else 
    {
      log_msg.timestamp[0] = '\0';
      (void) sl_strlcpy (sigkey_new, 
			 sh_tiger_hash (sigkey_old, TIGER_DATA, KEY_LEN, 
					hashbuf, sizeof(hashbuf)),
			 KEY_LEN+1);
    }

  /* --- Sign the message with the signature key. ---
   */
  sh_tiger_hash (log_msg.msg, TIGER_DATA,
		 (unsigned long)(status + KEY_LEN), 
		 (char *) hashbuf, (size_t) sizeof(hashbuf));

  (void) sl_strlcat (log_msg.msg, sigkey_new, (size_t)(status + KEY_LEN + 2));
  (void) sl_strlcpy (log_msg.signature,
		     sh_tiger_hash (log_msg.msg, (TigerType) TIGER_DATA,
				    (unsigned long)(status + KEY_LEN), 
				    hashbuf, sizeof(hashbuf)),
		     KEY_LEN+1);
  (void) sl_strlcpy (sigkey_old, sigkey_new, KEY_LEN+1); 

  /*@-usedef@*/
#ifdef SH_USE_XML
  if (log_msg.timestamp[0] != '\0')
    sl_snprintf(log_msg.sig, sizeof(log_msg.sig),
#ifdef FIX_XML
		_("\n<sig>%s%s</sig></log>\n"),          /* <sig> FIX XML */
#else
		_("\nsig>%s%s</sig></log>\n"),          /* <sig> FIX XML */
#endif
		log_msg.signature, log_msg.timestamp);
  else
    sl_snprintf(log_msg.sig, sizeof(log_msg.sig),
#ifdef FIX_XML
		_("\n<sig>%s</sig></log>\n"),            /* <sig> FIX XML */
#else
		_("\nsig>%s</sig></log>\n"),            /* <sig> FIX XML */
#endif
		log_msg.signature);
  /*@+usedef@*/

#ifdef SH_STEALTH
  /* don't encode the line breaks (0 + last char)
   */
  sh_do_encode (&log_msg.sig[1], (sl_strlen(log_msg.sig)-2) );
#endif
#else
#ifdef SH_STEALTH
  sh_do_encode (log_msg.signature, KEY_LEN);
  sh_do_encode (log_msg.timestamp, sl_strlen(log_msg.timestamp));
#endif
#endif
  
#ifdef SH_USE_XML
  log_msg.msg[status] = '\0';
  (void) sl_strlcat (log_msg.msg,   log_msg.sig, 
		     (size_t)(status + 2*KEY_LEN + 32));
#ifdef SH_STEALTH
  if (NULL != sl_strstr(log_msg.msg, N_("EXIT")) &&
      NULL == sl_strstr(log_msg.msg, N_("remote_host")))
    {
      (void) sl_strlcat (log_msg.msg,  N_("</trail>"), 
			 (size_t)(status + 2*KEY_LEN + 32)); 
#else
  if (NULL != sl_strstr(log_msg.msg,  _("msg=\"EXIT\"")) &&
      NULL == sl_strstr(log_msg.msg,  _("remote_host")))
    {
      (void) sl_strlcat (log_msg.msg,   _("</trail>"), 
			 (size_t)(status + 2*KEY_LEN + 32)); 
#endif
      
      (void) sl_strlcat (log_msg.msg,   _("\n"), 
			 (size_t)(status + 2*KEY_LEN + 32)); 
      current->log_start = S_TRUE;
    }
#else
  log_msg.msg[status] = '\0';
  (void) sl_strlcat (log_msg.msg,              "\n", 
		     (size_t)(status + KEY_LEN + 2));
  (void) sl_strlcat (log_msg.msg, log_msg.signature, 
		     (size_t)(status + KEY_LEN + 2));
  if (log_msg.timestamp[0] != '\0')
    (void) sl_strlcat (log_msg.msg, log_msg.timestamp, 
		       (size_t)(status + 2*KEY_LEN + 2));
  (void) sl_strlcat (log_msg.msg,              "\n", 
		     (size_t)(status + 2*KEY_LEN + 3));
#endif
  
  /* --- Write out the record. ---
   */
  (void) sl_write (fd, log_msg.msg, (long) strlen(log_msg.msg));
  (void) sl_sync  (fd);
  (void) sl_close (fd);

  /* --- Clean up and free record. ---
   */
  memset (log_msg.msg,       (int)'\0', (size_t)(status + 2*KEY_LEN + 32));
  memset (log_msg.signature, (int)'\0', KEY_LEN);
  (void) sh_unix_munlock (log_msg.msg,  
			  (size_t)(status + 2*KEY_LEN + 32));
  SH_FREE(log_msg.msg);

  SL_RETURN (0, _("sh_log_file"));
}

/* >>>>>>>>>>>>>>>>>>>>>>>>>>>> efile <<<<<<<<<<<<<<<<<< */

static char * gEfile = NULL;
static int    gFail  = 0;
static long   gGid   = 0;

int sh_efile_group(const char * str)
{
  int  fail;
  long gid = sh_group_to_gid(str, &fail);

  if (fail < 0)
    {
      return -1;
    }
  gGid = gid;
  return 0;
}


int sh_efile_path(const char * str) 
{
  if (!str || !strcmp(str, _("none")))
    {
      if (gEfile)
	SH_FREE(gEfile);
      gEfile = NULL;
    }
  else if (str[0] != '/')
    {
      return -1;
    }
  else
    {
      if (gEfile)
	SH_FREE(gEfile);
      gEfile = sh_util_strdup(str);
    }
  gFail = 0;
  return 0;
}

/* write lock for filename
 */
static int sh_efile_lock (char * filename, int flag)
{
  extern int get_the_fd (SL_TICKET ticket);
  size_t len;
  int    res = -1;
  char myPid[64];
  SL_TICKET  fd;
  char * lockfile;
  int    status;

  sprintf (myPid, "%ld\n", (long) sh.pid);             /* known to fit  */

  if (filename == NULL)
    return res;

  len = sl_strlen(filename);
  if (sl_ok_adds(len, 6))
    len += 6;
  lockfile = SH_ALLOC(len);
  sl_strlcpy(lockfile, filename,   len);
  sl_strlcat(lockfile, _(".lock"), len);

  if (  0 !=  (status = tf_trust_check (lockfile, SL_YESPRIV))
	&& gFail == 0)
    {
      char * tmp  = sh_util_safe_name (lockfile);
      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_TRUST,
			   (long) sh.effective.uid, tmp);
      ++gFail;
      SH_FREE(tmp);
    }

  if (status == 0)
    {
      if (flag == 0)
	{
	  /* --- Delete the lock file. --- 
	   */
	  res = retry_aud_unlink (FIL__, __LINE__, lockfile);
	}
      else
	{
	  unsigned int count = 0;

	  /* fails if file exists 
	   */
	  do {
	    fd = sl_open_safe_rdwr (FIL__, __LINE__, 
				    lockfile, SL_YESPRIV);
	    if (SL_ISERROR(fd))
	      {
		retry_msleep(0, 100);
		++count;
	      }

	  } while (SL_ISERROR(fd) && count < 3);
      
	  if (!SL_ISERROR(fd))
	    {
	      int filed;

	      res = sl_write (fd, myPid, sl_strlen(myPid));
	      filed = get_the_fd(fd);
	      fchmod (filed, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	      sl_close (fd);
	    }
	  else
	    {
	      static int nFail = 0;

	      if (nFail == 0)
		{
		  char errmsg[1024];
		  char * tmp  = sh_util_safe_name (lockfile);
		  
		  sl_snprintf(errmsg, sizeof(errmsg), 
			      _("Error creating lockfile %s"),
			      tmp);
		  
		  sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, 
				   0, MSG_E_SUBGEN,
				   errmsg, _("sh_efile_lock"));
		  ++nFail;
		  SH_FREE(tmp);
		}
	    }
	}
    }

  SH_FREE(lockfile);
  return res;
}

static size_t gSave[6] = { 0 };

static void sh_efile_clear()
{
  int i;

  for (i = 0; i < 6; ++i)
    gSave[i] = 0;
  return;
}

static void sh_efile_load(size_t * tmp)
{
  int i;

  if (S_TRUE == sl_ok_adds (gSave[0], sh.statistics.bytes_hashed))
    gSave[0] += sh.statistics.bytes_hashed;
  if (S_TRUE == sl_ok_adds (gSave[1], sh.statistics.dirs_checked))
    gSave[1] += sh.statistics.dirs_checked;
  if (S_TRUE == sl_ok_adds (gSave[2], sh.statistics.files_checked))
    gSave[2] += sh.statistics.files_checked;
  if (S_TRUE == sl_ok_adds (gSave[3], sh.statistics.files_report))
    gSave[3] += sh.statistics.files_report;
  if (S_TRUE == sl_ok_adds (gSave[4], sh.statistics.files_error))
    gSave[4] += sh.statistics.files_error;
  if (S_TRUE == sl_ok_adds (gSave[5], sh.statistics.files_nodir))
    gSave[5] += sh.statistics.files_nodir;

  for (i = 0; i < 6; ++i)
    tmp[i] = gSave[i];
  return;
}

void sh_efile_report()
{
  extern int get_the_fd (SL_TICKET ticket);
  SL_TICKET     fd;
  char         *efile;
  int           status = -1;

  if (gEfile)
    {
      size_t tmp[6];

      sh_efile_load(tmp);

      efile = sh_util_strdup(gEfile);
      
      if (sh_efile_lock (efile, 1) < 0)
	goto end;

      if (  0 !=  (status = tf_trust_check (efile, SL_YESPRIV))
	    && gFail == 0)
	{
	  char * tmp  = sh_util_safe_name (efile);
	  sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_TRUST,
			   (long) sh.effective.uid, tmp);
	  ++gFail;
	  SH_FREE(tmp);
	}
      
      if (status == 0)
	{
	  fd = sl_open_write (FIL__, __LINE__, efile, SL_YESPRIV);

	  if (!SL_ISERROR(fd))
	    {
	      char report[511];
	      char tstamp[TIM_MAX];

	      time_t now = time(NULL);
	      int  filed = get_the_fd(fd);

	      (void) sh_unix_time (now, tstamp, sizeof(tstamp));
#ifdef HAVE_LONG_LONG
	      sl_snprintf(report, sizeof(report), 
			  _("%s %lld %ld %ld %ld %ld %ld %ld\n"),
			  tstamp,
			  (long long) now,
			  (long) tmp[0], (long) tmp[1], (long) tmp[2], 
			  (long) tmp[3], (long) tmp[4], (long) tmp[5]);
#else
	      sl_snprintf(report, sizeof(report), 
			  _("%s %ld %ld %ld %ld %ld %ld %ld\n"),
			  tstamp,
			  (long) now,
			  (long) tmp[0], (long) tmp[1], (long) tmp[2], 
			  (long) tmp[3], (long) tmp[4], (long) tmp[5]);
#endif
			  
	      status = sl_forward(fd);
	      if (!SL_ISERROR(status))
		status = sl_write (fd, report,  strlen(report));
	      (void) sl_sync(fd);

	      /* make group writeable, such that nagios can truncate */
	      fchmod (filed, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);
	      status = fchown (filed, -1, gGid);
	      if (status < 0)
		{
		  int  errnum = errno;
		  static int nFail = 0;
		  if (nFail == 0)
		    {
		      char errmsg[1024];
		      char buf[256];
		      char * tmp  = sh_util_safe_name (efile);

		      sl_snprintf(errmsg, sizeof(errmsg), 
				  _("Error changing group of %s to %ld: %s"),
				  tmp, gGid, 
				  sh_error_message (errnum, buf, sizeof(buf)));
		      sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, 
				       errnum, MSG_E_SUBGEN,
				       errmsg, _("sh_efile_report"));
		      ++nFail;
		      SH_FREE(tmp);
		    }
		}

	      (void) sl_close(fd);
	    }
	  else
	    {
	      status = -1;
	    }
	}
  
      (void) sh_efile_lock (efile, 0);
    end:
      SH_FREE(efile);

      if (!SL_ISERROR(status))
	{
	  sh_efile_clear();
	}
    }
  return;
}
