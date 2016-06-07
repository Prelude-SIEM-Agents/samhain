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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>

#if defined(SH_WITH_MAIL)

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


#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

#include "samhain.h"
#include "sh_error.h"
#include "sh_unix.h"
#include "sh_tiger.h"
#include "sh_mail.h"
#include "sh_utils.h"
#include "sh_fifo.h"
#include "sh_tools.h"
#include "sh_pthread.h"
#include "sh_filter.h"
#include "sh_mail_int.h"
#include "sh_nmail.h"
#include "sh_ipvx.h"

#undef  FIL__
#define FIL__  _("sh_mail.c")
#undef  GOOD
#undef  BAD

static int failedMail = S_FALSE;

static dnsrep * return_mx (char *domain);

/*********************************************
 *  utility function for verifying mails
 *********************************************/

typedef struct mail_trail_struct {
  char                     trail_id[2*SH_MINIBUF];
  char                     trail_key[KEY_LEN+1];
  struct mail_trail_struct * next;
} mail_trail_type;

static mail_trail_type * mail_trail = NULL;

int sh_mail_sigverify (const char * s)
{
  SL_TICKET  fd;
  long   i;
  char * buf;
  char * bufc;
  char   key[81];
  char   number[2*SH_MINIBUF];
  char   audit_id[2 * SH_MINIBUF];
  long   numsig;
  char   key2[KEY_LEN+1];

  char * theSig;

  mail_trail_type * mail_trail_ptr = NULL;

  sh_error_logoff();

  ASSERT((s != NULL && sl_strlen(s) < PATH_MAX), 
	 _("(s != NULL && sl_strlen(s) < PATH_MAX)"));

  if (s == NULL || sl_strlen(s) >= PATH_MAX) 
    _exit (EXIT_FAILURE);

  /* open the file, then check it 
   */
  if (0 != sl_is_suid())
    {
      fprintf(stderr, _("Cannot open file %s in suid mode\n"), s);
      _exit (EXIT_FAILURE);
    }
  if ( SL_ISERROR(fd = sl_open_read (FIL__, __LINE__, s, SL_NOPRIV)))
    {
      fprintf(stderr, _("Could not open file %s\n"), s);
      _exit (EXIT_FAILURE);
    }

  buf     = SH_ALLOC( (size_t)(SH_MSG_BUF+SH_BUFSIZE+1));
  bufc    = SH_ALLOC( (size_t)(SH_MSG_BUF+SH_MAXBUF+1));

  while (1 == 1)
    {
      buf[0]  = '\0';
      bufc[0] = '\0';

      /* find start of next message
       */
      while (0 != sl_strncmp(buf, _("-----BEGIN MESSAGE-----"),
			     sizeof("-----BEGIN MESSAGE-----")-1)) 
	{
	  (void) sh_unix_getline (fd, buf, SH_MSG_BUF+SH_BUFSIZE);
	  if (buf[0] == '\0')
	    {
	      /* End of mailbox reached, exit. 
	       */
	      (void) fflush(stdout);
	      _exit (EXIT_SUCCESS);

	      /* Fix for AIX cc complaint. 
	       */
	      /*@notreached@*/
	      return 0; 
	    }
	}
      
      /* Read message, compress into bufc.
       */
      while (1 == 1)
	{
	  (void) sh_unix_getline (fd, buf, SH_MSG_BUF+SH_BUFSIZE);
	  if (0 == sl_strncmp(buf, _("-----BEGIN SIGNATURE-----"),
			      sizeof("-----BEGIN SIGNATURE-----")-1))
	    break;
	  if (buf[0] == '\0') 
	    _exit (EXIT_FAILURE);
	  (void) sh_util_compress(bufc, buf, SH_MSG_BUF+SH_MAXBUF-KEY_LEN);
	}
      
      /* get signature and number 
       */
      (void) sh_unix_getline (fd, key, (int)sizeof(key));
      key[KEY_LEN] = '\0';

      (void) sh_unix_getline (fd, number, (int)sizeof(number));
      number[(2*SH_MINIBUF) - 2]   = '\0';
      numsig = atol (number);
      (void) sl_strlcpy (audit_id, &number[7], 2*SH_MINIBUF);
      
      fprintf(stderr, _("Message %06ld  Trail %s\n"), 
	      numsig, /*@-usedef@*/ audit_id /*@+usedef@*/);

      mail_trail_ptr = mail_trail;
      while (mail_trail_ptr)
	{
	  if (0 == sl_strcmp(mail_trail_ptr->trail_id, audit_id))
	    break;
	  mail_trail_ptr = mail_trail_ptr->next;
	}

      if (!mail_trail_ptr)
	{
	  if (numsig > 0)
	    {
	      fprintf (stderr, "%s",_("ERROR (no key -- cannot check)\n"));
	      continue;
	    }
	  else
	    {
	      mail_trail_ptr = SH_ALLOC (sizeof(mail_trail_type));
	      mail_trail_ptr->next = mail_trail;
	      mail_trail = mail_trail_ptr;
	      (void) sl_strlcpy (mail_trail_ptr->trail_id,  
				 audit_id, 2*SH_MINIBUF);
	    }
	}
      else if (numsig == 0)
	{
	  fprintf (stderr, "%s",_("ERROR (repeated audit trail)\n"));
	  continue;
	}
	

      if (numsig == 0)
	{
	  sh_util_encode(key, bufc, 1, 'A');
	  (void) sl_strlcpy (mail_trail_ptr->trail_key, key, KEY_LEN+1);
	  fprintf (stderr, "%s",_("(unchecked)\n"));
	}
      else
	{
	  char sigbuf[KEYBUF_SIZE];

	  /* iterate key
	   */
	  (void) sl_strlcpy(key2, mail_trail_ptr->trail_key, KEY_LEN+1); 
	  for (i = 0; i < numsig; ++i) 
	    {
	      char hashbuf[KEYBUF_SIZE];
	      (void) sl_strlcpy (key2, 
				 sh_tiger_hash (key2, TIGER_DATA, KEY_LEN,
						hashbuf, sizeof(hashbuf)), 
				 KEY_LEN+1);
	    }
	  
	  theSig = sh_util_siggen (key2, bufc, sl_strlen(bufc), 
				   sigbuf, sizeof(sigbuf));

	  if (sl_strncmp (key, 
			  theSig,
			  KEY_LEN) != 0) 
	    {
	      fprintf (stderr, "%s",_("(FAILED)\n"));
	    } 
	  else 
	    { 
	      fprintf (stderr, "%s",_("(passed)\n"));
	    }

	}

    } /* end scan mailbox */

  /*@notreached@*/
}

int sh_mail_setNum (const char * str)
{
  int i = atoi (str);

  SL_ENTER(_("sh_mail_setNum"));

  if (i >= 0 && i < SH_FIFO_MAX) 
    sh.mailNum.alarm_interval = (time_t) i;
  else 
    SL_RETURN ((-1), _("sh_mail_setNum"));
  SL_RETURN( (0), _("sh_mail_setNum"));
}


int sh_mail_all_in_one = S_FALSE;

int sh_mail_setFlag (const char * str)
{
  int i;
  SL_ENTER(_("sh_mail_setFlag"));
  i = sh_util_flagval(str, &sh_mail_all_in_one);
  SL_RETURN(i, _("sh_mail_setFlag"));
}

static char * mail_subject = NULL;

int set_mail_subject (const char * str)
{
  SL_ENTER(_("set_mail_subject"));
  if (!str)
    SL_RETURN( (-1), _("set_mail_subject"));

  if (mail_subject != NULL)
    SH_FREE(mail_subject);

  if (0 == sl_strncmp(str, _("NULL"), 4))
    {
      mail_subject = NULL;
      SL_RETURN( 0, _("set_mail_subject"));
    }

  mail_subject = sh_util_strdup(str);
  SL_RETURN( (0), _("set_mail_subject"));
}

SH_MUTEX_INIT(mutex_fifo_mail, PTHREAD_MUTEX_INITIALIZER);

SH_FIFO * fifo_mail = NULL;

static
void sh_mail_emptystack (void)
{
  char * msg;
  size_t len;

  SL_ENTER(_("sh_mail_emptystack"));

  if (fifo_mail == NULL)
    SL_RET0(_("sh_mail_emptystack"));

  SH_MUTEX_LOCK(mutex_fifo_mail);
  while (NULL != (msg = pop_list(fifo_mail)))
    {
      len = sl_strlen(msg);
      memset(msg, 0, len);
      SH_FREE(msg);
    }
  SH_MUTEX_UNLOCK(mutex_fifo_mail);

  SL_RET0(_("sh_mail_emptystack"));
}

/* insert "\r\n" after each 998 char
 */
static char * split_string(const char * str);

/* fixes warning: variable ‘p’ might be clobbered by ‘longjmp’ or ‘vfork’*/
static char ** p_dummy;

int sh_mail_pushstack (int severity, const char * msg, const char * alias)
{
  char * p;
  volatile int    retval = 0;
  int    status;

  SL_ENTER(_("sh_mail_pushstack"));

  if (msg == NULL || failedMail == S_TRUE /* || sh.srvmail.name[0] == '\0' */) 
    SL_RETURN((0), (_("sh_mail_pushstack")));

  p = split_string(msg);
  /* fixes "variable ‘p’ might be clobbered by ‘longjmp’ or ‘vfork’" */
  p_dummy = &p;

  SH_MUTEX_LOCK(mutex_fifo_mail);

  if (fifo_mail == NULL)
    {
      fifo_mail = SH_ALLOC(sizeof(SH_FIFO));
      fifo_init(fifo_mail);
    }
  status = push_list (fifo_mail, p, severity, alias);
  SH_MUTEX_UNLOCK(mutex_fifo_mail);

  if (status >= 0)
    ++sh.mailNum.alarm_last;

  SH_FREE(p);

  if (sh.mailNum.alarm_last >= sh.mailNum.alarm_interval)
    {
      BREAKEXIT(sh_nmail_flush);
      retval = sh_nmail_flush ();
    }

  if (status == SH_FIFO_MAX)
    retval = -2;
  SL_RETURN(retval, (_("sh_mail_pushstack")));
}


/* The mailer.
 */
static int sh_mail_end_conn (FILE * connfile, int fd);
static FILE * sh_mail_start_conn (struct alias * address, int * fd, int * anum);

static
void sh_mail_get_subject(const char * message,
			 char * mheader, size_t len)
{
  st_format rep_serv_tab[] = {
    { 'T', S_FMT_TIME,    0, 0, NULL},
    { 'H', S_FMT_STRING,  0, 0, NULL},
    { 'M', S_FMT_STRING,  0, 0, NULL},
    { 'S', S_FMT_STRING,  0, 0, NULL},
    {'\0', S_FMT_ULONG,   0, 0, NULL},
  };

  char * p;
  char * mptr;
  char   sev[8];
  char * msg;

  SL_ENTER(_("sh_mail_get_subject"));

  (void) sl_strlcpy(mheader, _("Subject: "), len);
  if (NULL == strchr(mail_subject, '%'))
    {
      (void) sl_strlcat(mheader, mail_subject, len);
      SL_RET0(_("sh_mail_get_subject"));
    }


  rep_serv_tab[0].data_ulong = (unsigned long) time(NULL);
  rep_serv_tab[1].data_str   = sh.host.name;

  /* fast forward to the important part
   */
  msg  = sh_util_strdup(message);

  mptr = sl_strstr(msg, _("msg="));
  if (mptr)
    {
      mptr += 4;
      rep_serv_tab[2].data_str   = mptr;
    }
  else
    rep_serv_tab[2].data_str   = msg;

  mptr = sl_strstr(msg, _("sev="));
  if (mptr)
    {
      mptr += 5;
      sev[0] = *mptr; ++mptr;
      sev[1] = *mptr; ++mptr;
      sev[2] = *mptr; ++mptr;
      sev[3] = *mptr; ++mptr;
      sev[4] = '\0';
    }
  else
    {
      mptr = msg;
      sev[0] = *mptr; ++mptr;
      sev[1] = *mptr; ++mptr;
      sev[2] = *mptr; ++mptr;
      sev[3] = *mptr; ++mptr;
      if (*mptr == ' ') {
	sev[4] = '\0';
      } else {
	sev[4] = *mptr; ++mptr;
	if (*mptr == ' ') {
	  sev[5] = '\0';
	} else {
	  sev[5] = *mptr;
	  sev[6] = '\0';
	}
      }
    }
  rep_serv_tab[3].data_str   = sev;


  p = sh_util_formatted(mail_subject, rep_serv_tab);
  (void) sl_strlcat(mheader, p, len);
  SH_FREE(p);
  SH_FREE(msg);
  SL_RET0(_("sh_mail_get_subject"));
}

sh_string * sh_mail_signature_block (sh_string  * sigMsg, char * recipient,
				     char * bufcompress)
{
  time_t         id_audit;
  char         * theSig;
  char ibuf[80];
  unsigned int count;

  /* ------ signature block ------------------------------------ */
  
  sigMsg = sh_string_add_from_char(sigMsg, 
				   _("-----BEGIN SIGNATURE-----\r\n"));
  
  count  = sh_nmail_get_mailkey (recipient, skey->mailkey_new, KEY_LEN+1,
				 &id_audit);
  
  if (count != 0)
    {
      char sigbuf[KEYBUF_SIZE];
      
      /* Sign the message with the signature key.
       */
      theSig = sh_util_siggen (skey->mailkey_new, 
			       bufcompress, sl_strlen(bufcompress),
			       sigbuf, sizeof(sigbuf));
      sigMsg = sh_string_add_from_char(sigMsg, theSig);
    }
  else
    {
       /* reveal first signature key
       */
      /* flawfinder: ignore */
      (void) sl_strlcpy(skey->crypt, skey->mailkey_new, KEY_LEN+1); 
      
      BREAKEXIT(sh_util_encode);
      /* flawfinder: ignore */
      sh_util_encode(skey->crypt, bufcompress, 0, 'A');
      
      /* flawfinder: ignore */
      sigMsg     = sh_string_add_from_char(sigMsg, skey->crypt);
      
      /* flawfinder: ignore */
      memset (skey->crypt, 0, KEY_LEN);
    }

    sigMsg     = sh_string_add_from_char(sigMsg, "\r\n");

    sl_snprintf(ibuf, sizeof(ibuf), _("%06u %010lu::%s\r\n"),
		count, (unsigned long) id_audit, sh.host.name);

    sigMsg     = sh_string_add_from_char(sigMsg, ibuf);
    sigMsg     = sh_string_add_from_char(sigMsg, _("-----END MESSAGE-----"));

    return sigMsg;
}

int sh_mail_msg (const char * message)
{
    char         subject[32+32+SH_MINIBUF+2+3+SH_PATHBUF];
    char         mheader[32+32+SH_MINIBUF+2+3];

    sh_string  * mailMsg;
    sh_string  * compMsg;
    int          status = 0;
    volatile int errcount;
    size_t       wrlen;
    volatile int retval = -1;  

    char       * bufcompress;
    size_t       compressed;

    static int   failcount = 0;
    FILE       * connfile  = NULL;

    static  time_t fail_time = 0;
    static  time_t success_time = 0;

    int       ma_socket = -1;

    int            address_num = 0;
    sh_string    * theMsg = NULL;

    /* #define SH_MAILBUF (256)    */
#define SH_MAILBUF 4096 

    char      timebuf[81];

    SL_ENTER(_("sh_mail_msg"));

    /* 
     * Return if we cannot mail.
     */
    if (failedMail == S_TRUE) 
      SL_RETURN((-1), _("sh_mail_msg"));

    /*
     * Final failure, can't mail for SH_MAX_FAIL hours.
     */
    if ( (success_time > 0) && (fail_time > 0) &&
	 (time(NULL) - success_time) > 3600*SH_MAX_FAIL)
      {
	sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_SRV_FAIL,
			 _("mail"), 
			 sh_string_str(all_recipients->recipient));
	sh_mail_emptystack();
	sh.mailNum.alarm_last = 0;
	failedMail = S_TRUE;
	SL_RETURN((-1), _("sh_mail_msg"));
      }

    /*
     * Try at most every three seconds to mail if there was a failure.
     */
    if ((fail_time > 0) && (time(NULL) - fail_time) < 3/*600*/)
      {
	if (failcount > 3)
	  {
	    /* -- Save for later. Changed: done by caller. -- 
	     *	    sh_nmail_pushstack (severity, message, alias);
	     */
	    ++failcount;
	    
	    SL_RETURN((-2), _("sh_mail_msg"));
	  }
	else
	  {
	    (void) retry_msleep(2, 0);
	    ++failcount;
	  }
      }

    /* -- Reset time of last failure. --
     */
    fail_time = 0;


    /* ---------  Build complete message. ------------------------ */

    /* Don't flush the queue here, because tag_list doesn't know
     * how to filter messages. */

    theMsg = sh_string_new_from_lchar(message, sl_strlen(message));
    if (!theMsg)
      {
	SL_RETURN((-1), _("sh_mail_msg"));
      }

    /* ---------- Header  ---------------------------------------- */

    if (mail_subject == NULL)
      {
	(void) sl_strlcpy(mheader, _("Subject: "),       sizeof(mheader)-5);
	(void) sl_strlcat(mheader, 
			  sh_unix_time (0, timebuf, sizeof(timebuf)),
			  sizeof(mheader)-5);
	(void) sl_strlcat(mheader, " ",                  sizeof(mheader)-5);
	(void) sl_strlcat(mheader, sh.host.name,         sizeof(mheader)-5);
      }
    else
      {
	
	if (message)
	  {
	    sh_mail_get_subject(message, mheader, sizeof(mheader)-5);
	  }
	else
	  {
	    (void) sl_strlcpy(mheader, _("Subject: "),     sizeof(mheader)-5);
	    (void) sl_strlcat(mheader, 
			      sh_unix_time (0, timebuf, sizeof(timebuf)),
			      sizeof(mheader)-5);
	    (void) sl_strlcat(mheader, " ",                sizeof(mheader)-5);
	    (void) sl_strlcat(mheader, sh.host.name,       sizeof(mheader)-5);
	  }
      }

    /* RFC 821: Header is terminated by an empty line
     */
    (void) sl_strlcat(mheader, "\015\012\015\012",        sizeof(mheader));

    /* ---------- Message  --------------------------------------- */

    (void) sl_strlcpy(subject, sh_unix_time (0, timebuf, sizeof(timebuf)),
		      sizeof(subject));
    (void) sl_strlcat(subject, " ",                       sizeof(subject));
    (void) sl_strlcat(subject, sh.host.name,              sizeof(subject));
    (void) sl_strlcat(subject, "\r\n",                    sizeof(subject));


    mailMsg     = sh_string_new (SH_MAILBUF);
    compMsg     = sh_string_new (SH_MAILBUF);

    mailMsg     = sh_string_add_from_char(mailMsg, mheader);
    mailMsg     = sh_string_add_from_char(mailMsg, 
					  _("-----BEGIN MESSAGE-----\r\n"));

    mailMsg     = sh_string_add_from_char(mailMsg, subject);
    mailMsg     = sh_string_add          (mailMsg, theMsg);
    mailMsg     = sh_string_add_from_char(mailMsg, "\r\n");

    /* ---------- Compressed Message  ---------------------------- */

    compMsg     = sh_string_add_from_char(compMsg, subject);
    compMsg     = sh_string_add          (compMsg, theMsg);
    compMsg     = sh_string_add_from_char(compMsg, "\r\n");

    bufcompress = SH_ALLOC(sh_string_len(compMsg) + KEY_LEN + 1);
    bufcompress[0] = '\0';

    compressed = sh_util_compress (bufcompress, 
				   sh_string_str(compMsg), 
				   sh_string_len(compMsg) + 1);

    /* ---------- Connect ---------------------------------------- */

    errcount = 0;

    if (sh_mail_all_in_one == S_FALSE)
      {
	struct alias * address_list;

	address_list = all_recipients;

	while (address_list)
	  {
	    if (address_list->send_mail == 1)
	      {
		connfile = sh_mail_start_conn (address_list, 
					       &ma_socket, &address_num);
	    
		if (NULL != connfile)
		  {
		    wrlen = fwrite (sh_string_str(mailMsg), 1, 
				    sh_string_len(mailMsg), connfile);
		    wrlen -= sh_string_len(mailMsg);

		    if (wrlen == 0)
		      {
			sh_string  * sigMsg  = sh_string_new (0);

			sigMsg = sh_mail_signature_block (sigMsg, 
							  sh_string_str(address_list->recipient),
							  bufcompress);

			wrlen = fwrite (sh_string_str(sigMsg), 1, 
					sh_string_len(sigMsg), connfile);
			wrlen -= sh_string_len(sigMsg);

			sh_string_destroy(&sigMsg);
		      }

		    if (wrlen == 0) 
		      status = sh_mail_end_conn (connfile, ma_socket);
		    else
		      status = -1;
		  }
		if (NULL == connfile ||  status != 0)
		  {
		    sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_SRV_FAIL,
				     _("mail"), 
				     sh_string_str(address_list->recipient));
		    ++errcount;
		    ++sh.statistics.mail_failed;
		  }
		else
		  {
		    ++sh.statistics.mail_success;
		  }
		
		if (connfile != NULL)
		  {
		    (void) sl_fclose (FIL__, __LINE__, connfile);
		    connfile = NULL;
		  }
	      }
	    address_list = address_list->all_next;
	  }
      }
    else
      {
	connfile = sh_mail_start_conn (NULL, &ma_socket, &address_num);

	if (NULL != connfile)
	  {
	    wrlen = fwrite (sh_string_str(mailMsg), 1, 
			    sh_string_len(mailMsg), connfile);
	    wrlen -= sh_string_len(mailMsg);

	    if (wrlen == 0)
	      {
		sh_string  * sigMsg  = sh_string_new (0);
		
		sigMsg  = sh_mail_signature_block (sigMsg, 
						   NULL,
						   bufcompress);
		
		wrlen = fwrite (sh_string_str(sigMsg), 1, 
				sh_string_len(sigMsg), connfile);
		wrlen -= sh_string_len(sigMsg);
		
		sh_string_destroy(&sigMsg);
	      }

	    if (wrlen == 0)
	      status = sh_mail_end_conn (connfile, ma_socket);
	    else
	      status = -1;
	  }

	if (NULL == connfile || status != 0)
	  {
	    struct alias* ma_address = all_recipients;

	    while (ma_address)
	      {
		if (ma_address->send_mail == 1)
		  break;
		ma_address = ma_address->all_next;
	      }

	    if (ma_address)
	      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_SRV_FAIL,
			       _("mail"), 
			       sh_string_str(ma_address->recipient));
	    errcount = address_num;
	    ++sh.statistics.mail_failed;
	  }
	else
	  {
	    ++sh.statistics.mail_success;
	  }

	if (connfile != NULL)
	  {
	    (void) sl_fclose (FIL__, __LINE__, connfile);
	    connfile = NULL;
	  }
      }
    
    memset (bufcompress, 0, compressed);
    SH_FREE(bufcompress);

    memset (sh_string_str(mailMsg), 0, sh_string_len(mailMsg));
    memset (sh_string_str(compMsg), 0, sh_string_len(compMsg));
    memset (sh_string_str(theMsg),  0, sh_string_len(theMsg));

    sh_string_destroy(&mailMsg);
    sh_string_destroy(&compMsg);
    sh_string_destroy(&theMsg);

    /* --- Stay responsible for delivery in case of failure --- */

    if (errcount == address_num)
      {
	rollback_list(fifo_mail);
	retval = -3;
      }
    else
      {
	mark_list(fifo_mail);
      }

    if (errcount == address_num)
      {
	fail_time = time(NULL);
	SL_RETURN((retval), _("sh_mail_msg"));
      }

    success_time = time(NULL);
    failcount = 0;

    SL_RETURN((0), _("sh_mail_msg"));
}


/*
 *
 * SMTP CODE BELOW
 *
 *
 */

#include <ctype.h>
#ifdef  HOST_IS_HPUX
#define _XOPEN_SOURCE_EXTENDED
#endif
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifndef S_SPLINT_S
#include <arpa/inet.h>
#else
#define AF_INET 2
#endif

#define SH_NEED_GETHOSTBYXXX
#include "sh_static.h"

/* missing on HP-UX 10.20 */
#ifndef IPPORT_SMTP
#define IPPORT_SMTP 25
#endif

static int sh_mail_wait(int code, int ma_socket);

static char * relay_host = NULL;

int sh_mail_set_relay (const char * str_s)
{
  SL_ENTER(_("sh_mail_set_relay"));

  if (str_s == NULL)
    SL_RETURN( -1, _("sh_mail_set_relay"));

  if (relay_host != NULL)
    {
      SH_FREE (relay_host);
      relay_host = NULL;
    }

  if (0 == sl_strncmp(str_s, _("NULL"), 4))
    {
      SL_RETURN( 0, _("sh_mail_set_relay"));
    }

  relay_host = sh_util_strdup(str_s);

  SL_RETURN( 0, _("sh_mail_set_relay"));
}

static char * mail_sender = NULL;

int sh_mail_set_sender (const char *str)
{
  if (mail_sender != NULL) 
    {
      SH_FREE (mail_sender);
      mail_sender = NULL;
    }
  if (str != NULL)
    {
      mail_sender = sh_util_strdup (str);
    }
  if (mail_sender == NULL)
    {
      return -1;
    }
  return 0;
}

static int sh_mail_port = IPPORT_SMTP;

int sh_mail_set_port (const char * str)
{
  int i = atoi (str);
  
  SL_ENTER(_("sh_mail_set_port"));
  
  if (i >= 0 && i < 65535)
    { 
      sh_mail_port = i;
    }
  else
    {
      sh_mail_port = IPPORT_SMTP;
      SL_RETURN ((-1), _("sh_mail_set_port"));
    }
  
  SL_RETURN( (0), _("sh_mail_set_port"));
}

/*************************
 *
 * start connection
 * for details on SMTP, see RFC 821
 *
 * If ma_address == NULL, will send to all marked with
 * send_mail=1 in recipient list, else to ma_address.   
 */

static time_t time_wait = 300;
static void report_smtp (char * reply);

static FILE * sh_mail_start_conn (struct alias * ma_address, 
				  int * ma_socket, int * anum)
{
  char       * address;
  int          aFlag = 0;

  int          ecount;

  char         this_address[256];
  char         ma_machine[256];
  char         ma_user[256];
  char         error_msg[256];
  char         error_call[SH_MINIBUF];
  int          error_num = 0;
  register int i, j, k;
  FILE       * connFile = NULL;
  struct tm  * my_tm;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_LOCALTIME_R)
  struct tm    time_tm;
#endif
  time_t       my_time;
  char         my_tbuf[128];

  int          fd;

  dnsrep     * answers;
  mx         * result;

  SL_ENTER(_("sh_mail_start_conn"));

  *ma_socket = -1;
  time_wait  = 300;

  if (ma_address == NULL)
    {
      aFlag = 1;
      ma_address = all_recipients;

      while (ma_address)
	{
	  if (ma_address->send_mail == 1)
	    break;
	  ma_address = ma_address->all_next;
	}
    }

  if (!ma_address)
    {
      SL_RETURN( NULL, _("sh_mail_start_conn"));
    } 

  address = sh_string_str(ma_address->recipient);

  TPT(( 0, FIL__, __LINE__, _("msg=<address %s>\n"), 
	address)); 

  /* -------   split adress ------------------  */

  if (strchr (address, '@') == NULL) {
    (void) sl_strlcpy(ma_user,    address,     256);
    (void) sl_strlcpy(ma_machine, _("localhost"), 256);
  } else {
    i = 0;
    while (i < 255 && address[i] != '@') {
      ma_user[i] = address[i];
      ++i;
    }
    
    /* adress[i] = '@' 
     */
    ma_user[i] = '\0';
    j = i + 1; k = i; i = 0;
    while (i < 255 && address[i+j] != '\0') {
      ma_machine[i] = address[i+j];
      ++i;
    }
    ma_machine[i] = '\0';
    if (address[k] != '@' || address[k+i+1] != '\0') 
      {
	SL_RETURN( NULL, _("sh_mail_start_conn"));
      } 
  }


  if (relay_host != NULL) 
    {
      (void) sl_strlcpy (ma_machine, relay_host, sizeof(ma_machine));
      TPT((0, FIL__, __LINE__, _("msg=<user %s machine %s>\n"), 
	   ma_user, ma_machine)); 
      fd = connect_port (ma_machine, sh_mail_port, 
			 error_call, &error_num, error_msg, 256);
    }
  else
    {
      answers = ma_address->mx_list;
      if (!answers)
	{
	  answers = return_mx (ma_machine);
	  ma_address->mx_list = answers;
	}

      if (answers)
	{
	  result = answers->reply;
	  fd     = -1;
 	  for (i = 0; i < answers->count; ++i)
	    {
	      (void) sl_strlcpy(ma_machine, result[i].address, 
				sizeof(ma_machine));
	      TPT((0, FIL__, __LINE__, 
		   _("msg=<user %s mx %s pref %d>\n"), 
		   ma_user, ma_machine, result[i].pref));
	      fd = connect_port (ma_machine, sh_mail_port, 
				 error_call, &error_num, error_msg, 256);
	      if (fd >= 0)
		break;
	    }
	}
      else
	{
	  (void) sl_strlcpy(error_call, _("return_mx"), SH_MINIBUF);
	  (void) sl_strlcpy(error_msg, _("The specified host is unknown: "), 
			    256);
	  (void) sl_strlcat(error_msg, ma_machine, 256); 
	  fd = -1;
	}
    }

  
  if (fd < 0)
    {
      sh_error_handle ((-1), FIL__, __LINE__, error_num, 
		       MSG_E_NET, error_msg, error_call,
		       _("email"), ma_machine);
      SL_RETURN( NULL, _("sh_mail_start_conn"));
    }

  /* associate a FILE structure with it
   */
  connFile = fdopen (fd, "r+");
  if (connFile == NULL) 
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<fdopen() failed>\n")));
      (void) sl_close_fd(FIL__, __LINE__, fd);
      SL_RETURN( NULL, _("sh_mail_start_conn"));
    }


  /* say HELO to the other socket
   */
  if (0 == sh_mail_wait (220, fd)) 
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_NET, 
		      _("Timeout on SMTP session init"), 
		      _("sh_mail_start_conn"), 
		      _("mail"), sh.host.name);
      TPT(( 0, FIL__, __LINE__, _("msg=<Timeout>\n")));
      (void) sl_fclose(FIL__, __LINE__, connFile);
      SL_RETURN( NULL, _("sh_mail_start_conn"));
    }

  (void) fflush(connFile);

  if (0 != sh_ipvx_is_numeric(sh.host.name))
    {
      sl_snprintf(error_msg, sizeof(error_msg), "HELO [%s]", 
		  sh.host.name);
    }
  else
    {
      sl_snprintf(error_msg, sizeof(error_msg), "HELO %s", 
		  sh.host.name);
    }
  report_smtp(error_msg);

  if (0 != sh_ipvx_is_numeric(sh.host.name))
    fprintf(connFile, _("HELO [%s]%c%c"), sh.host.name, 13, 10);
  else
    fprintf(connFile, _("HELO %s%c%c"), sh.host.name, 13, 10);

  (void) fflush(connFile);

  if (0 == sh_mail_wait(250, fd)) 
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_NET, 
		      _("HELO failed"), _("sh_mail_start_conn"), 
		      _("mail"), sh.host.name);

      TPT(( 0, FIL__, __LINE__, _("msg=<Timeout.>\n")));
      (void) sl_fclose(FIL__, __LINE__, connFile);
      SL_RETURN( NULL, _("sh_mail_start_conn"));
    }

  /* tell them who we are
   */
  (void) sl_strlcpy (this_address, 
		     mail_sender ? mail_sender : DEFAULT_SENDER, 256);
  if (NULL == strchr(this_address, '@'))
    {
      (void) sl_strlcat (this_address, "@", 256);
      if (0 != sh_ipvx_is_numeric(sh.host.name))
	(void) sl_strlcat (this_address, _("example.com"), 256);
      else
	(void) sl_strlcat (this_address, sh.host.name, 256);
    }

  sl_snprintf(error_msg, sizeof(error_msg), "MAIL FROM:<%s>", 
	      this_address);
  report_smtp(error_msg);

  (void) fflush(connFile);
  /*@-usedef@*/
  fprintf(connFile, _("MAIL FROM:<%s>%c%c"), this_address, 13, 10);
  /*@+usedef@*/
  (void) fflush(connFile);

  if (0 == sh_mail_wait(250, fd)) 
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_NET, 
		      _("MAIL FROM failed"), _("sh_mail_start_conn"), 
		      _("mail"), this_address);
      TPT(( 0, FIL__, __LINE__, _("msg=<Timeout.>\n")));
      (void) sl_fclose(FIL__, __LINE__, connFile);
      SL_RETURN( NULL, _("sh_mail_start_conn"));
    }

  /* tell them who to send mail to
   */
  if (aFlag == 0)
    {
      sl_snprintf(error_msg, sizeof(error_msg), "RCPT TO:<%s>", 
		  address);
      report_smtp(error_msg);

      (void) fflush(connFile);
      fprintf(connFile, _("RCPT TO:<%s>%c%c"), address, 13, 10); 
      (void) fflush(connFile);

      if (0 == sh_mail_wait(250, fd)) 
	{
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_NET, 
			  _("RCPT TO failed"), _("sh_mail_start_conn"), 
			  _("mail"), address);
	  TPT(( 0, FIL__, __LINE__, _("msg=<Timeout.>\n")));
	  (void) sl_fclose(FIL__, __LINE__, connFile);
	  SL_RETURN( NULL, _("sh_mail_start_conn"));
	}
      *anum = 1;
    }
  else
    {
      int address_num = 0;
      ecount      = 0;

      ma_address = all_recipients;

      while (ma_address)
	{
	  if (ma_address->send_mail != 1)
	    {
	      ma_address = ma_address->next;
	      continue;
	    }

	  ++address_num;

	  sl_snprintf(error_msg, sizeof(error_msg), "RCPT TO:<%s>", 
		      sh_string_str(ma_address->recipient));
	  report_smtp(error_msg);
	  
	  (void) fflush(connFile);
	  fprintf(connFile, _("RCPT TO:<%s>%c%c"), 
		  sh_string_str(ma_address->recipient), 13, 10); 
	  (void) fflush(connFile);
	  
	  if (0 == sh_mail_wait(250, fd)) 
	    {
	      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_NET, 
			      _("RCPT TO failed"), _("sh_mail_start_conn"), 
			      _("mail"), sh_string_str(ma_address->recipient));

	      TPT(( 0, FIL__, __LINE__, _("msg=<Timeout.>\n")));
	      ++ecount;
	    }
	  ma_address = ma_address->next;
	}

      *anum += address_num;

      if (ecount == address_num)
	{
	  (void) sl_fclose(FIL__, __LINE__, connFile);
	  SL_RETURN( NULL, _("sh_mail_start_conn"));
	}
    }

  /* Send the message 
   */
  report_smtp(_("DATA"));

  (void) fflush(connFile);
  fprintf(connFile, _("DATA%c%c"), 13, 10);      
  (void) fflush(connFile);

  if (0 == sh_mail_wait(354, fd)) 
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_NET, 
		      _("DATA failed"), _("sh_mail_start_conn"), 
		      _("mail"), address);
      TPT(( 0, FIL__, __LINE__, _("msg=<Timeout.>\n")));
      (void) sl_fclose(FIL__, __LINE__, connFile);
      SL_RETURN( NULL, _("sh_mail_start_conn"));
    }


  my_time = time(NULL);
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_LOCALTIME_R)
  my_tm = localtime_r(&my_time, &time_tm);
#else
  my_tm = localtime(&my_time);
#endif
  
  if (!my_tm) 
    {
      sl_strlcpy(my_tbuf, _("Thu, 01 Jan 1970 00:00:00 +00:00"), sizeof(my_tbuf));
    }
  else
    {
#if defined(HAVE_STRFTIME_Z)
      (void) strftime(my_tbuf, 127, _("%a, %d %b %Y %H:%M:%S %z"), my_tm);
#else
      (void) strftime(my_tbuf, 127, _("%a, %d %b %Y %H:%M:%S %Z"), my_tm);
#endif
    }

  TPT(( 0, FIL__, __LINE__,  _("msg=<From: <%s>%c%cTo: <%s>%c%cDate: %s>%c%c"),
	this_address, 13, 10, address, 13, 10, my_tbuf, 13, 10));

  report_smtp(_("sending data.."));

  (void) fflush(connFile);
  fprintf(connFile,
	  _("From: <%s>%c%c"\
	    "To: <%s>%c%c"\
	    "Date: %s%c%c"),
	  this_address, 13, 10,
	  address, 13, 10,
	  my_tbuf, 13, 10);

  *ma_socket = fd;
  SL_RETURN( connFile, _("sh_mail_start_conn"));
}

/*************************
 *
 * end connection
 *
 */

static int sh_mail_end_conn (FILE * connFile, int fd)
{
  SL_ENTER(_("sh_mail_end_conn"));

  time_wait = 300;

  report_smtp(_("."));

  (void) fflush(connFile);
  fprintf(connFile, _("%c%c.%c%c"), 13, 10, 13, 10);   
  (void) fflush(connFile);

  if (0 != sh_mail_wait(250, fd))
    {  
      (void) fflush(connFile);
      fprintf(connFile, _("QUIT%c%c"), 13, 10);
      (void) fflush(connFile);
      TPT(( 0, FIL__, __LINE__, _("msg=<exit>\n")));

      SL_RETURN (0, _("sh_mail_end_conn"));
    }
    
  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_NET, 
		  _("QUIT failed"), _("sh_mail_end_conn"), 
		  _("mail"), _("SMTP server"));

  TPT(( 0, FIL__, __LINE__, _("msg=<abnormal exit>\n")));

  SL_RETURN ((-1), _("sh_mail_end_conn"));
}



/****************************
 *
 * Handle server replies
 *
 *
 */
extern int flag_err_debug;

static void report_smtp (char * reply)
{
  char * tmp;

  if (flag_err_debug == S_TRUE)
    {
      tmp = sh_util_safe_name_keepspace(reply);

      sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		       tmp,
		       _("report_smtp") );
      SH_FREE(tmp);
    }
  return;
}


static int sh_mail_wait(int code, int ma_socket)
{
  int rcode, g;

  char c;

  char errmsg[194];
  char reply[128];
  unsigned int  ireply = 0;

  enum { 
    WAIT_CODE_START, 
    WAIT_CODE, 
    WAIT_NL, 
    WAIT_NL_CONT 
  } state;

  time_t waited_time;

  SL_ENTER(_("mail_wait"));
  
  waited_time = time(NULL);

  /* timeout after 5 minutes
   */

  rcode    = 0;
  state    = WAIT_CODE_START;
  reply[0] = '\0';

  while (sl_read_timeout_fd (ma_socket, &c, 1, time_wait, S_FALSE) > 0) {

    if (ireply < (sizeof(reply) - 1))
      {
	if (c != '\n' && c != '\r')
	  {
	    reply[ireply] = c;
	    ++ireply;
	    reply[ireply] = '\0';
	  }
      }

    g = (int) c;

    /*
    if (g == EOF)
      {
	TPT((0, FIL__, __LINE__, _("msg=<mail_wait: EOF>\n"))); 
	SL_RETURN( 0, _("mail_wait")); 
      }
    */

    switch(state) {

      /* wait for start of a numerical code
       */
    case WAIT_CODE_START:
      if (0 != isspace(g))
	break;             /* Skip white space                    */
      if (0 == isdigit(g)) 
	{
	  report_smtp(reply);
	  SL_RETURN( 0, _("mail_wait")); /* No leading number     */
	}
      rcode = g-(int)'0';  /* convert to number                   */
      state = WAIT_CODE;
      break;
      
      /* wait for completion of numerical code
       */
    case WAIT_CODE:
      if (0 != isdigit(g)) {
	rcode = rcode * 10 + (g-(int)'0'); /* next digit          */
	break;
      }
      /*@+charintliteral@*/
      state = ((g == '-') ?  WAIT_NL_CONT :  WAIT_NL); 
      /*@-charintliteral@*/
      break;
      
      /* wait for newline, then return with status code
       */
    case WAIT_NL:
      /*@+charintliteral@*/
      if (g != '\n')
	break;
      /*@-charintliteral@*/

      TPT((0, FIL__, __LINE__, 
	   _("msg=<mail_wait: OK got %d (%d) need %d (%d)>\n"),
	   rcode, (int)(rcode/100), code, (int)(code/100) ));
      g = ((int)(rcode/100) == (int)(code/100)) ? 1 : 0;
      if (g != 1)
	{
	  char * tmp = sh_util_safe_name_keepspace(reply);
          sl_snprintf(errmsg, sizeof(errmsg),
		      _("Bad response (%s), expected %d"), tmp, code);
	  SH_FREE(tmp);

	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_NET, 
			  errmsg, _("sh_mail_wait"), 
			  _("mail"), _("SMTP server"));
	}
      else
	{
	  report_smtp(reply);
	}
      waited_time = time(NULL) - waited_time;
      time_wait -= waited_time;
      TPT((0, FIL__, __LINE__, 
	   _("msg=<mail_wait: time_wait reduced to %d sec>\n"),
	   (int) time_wait));
      SL_RETURN( (g), _("mail_wait")) ;

      /* wait for continuation line
       */
      /*@fallthrough@*//* no, but splint doesn't understand */
    case WAIT_NL_CONT:
      /*@+charintliteral@*/
      if (g == '\n')
	state = WAIT_CODE_START;  /* There is a continuation line */
      /*@-charintliteral@*/
      break; 
      
    default:

      TPT((0, FIL__, __LINE__, _("msg=<mail_wait: bad>\n"))); 
      report_smtp(reply);
      SL_RETURN( 0, _("mail_wait")); 
      
    }
  }

  TPT((0, FIL__, __LINE__, _("msg=<mail_wait: failed>\n"))); 

  /* Failed, EOF or error on socket */
  report_smtp(reply);
  SL_RETURN( 0, _("mail_wait")); 
}

/* -- function to insert "\r\n" after each 998 chars --
 */

#define SPLIT_AT 998

static char * split_string(const char * str)
{
  size_t size;
  size_t blocks;
  int    count = 0;

  char * p, * p0;
  const char * q;

  if (!str)
    return NULL;

  size   = strlen(str) + 1;
  blocks = 1 + (size / SPLIT_AT);
  
  if (sl_ok_muls(2, blocks) && sl_ok_adds(size, (2*blocks)))
    {
      size   = size + (2*blocks);
    }
  else
    {
      /* integer overflow, do not split */
      p = sh_util_strdup(str);
      return p;
    }

  p = SH_ALLOC(size);
  memset(p, 0, size);

  p0 = p;

  q = str;
  while (*q != '\0') {
    *p = *q;
    ++p;
    ++q;
    ++count;
    if (0 == (count % SPLIT_AT)) {
      count = 0;
      *p = '\r';
      ++p;
      *p = '\n';
      ++p;
    }
  }
  /* fprintf(stderr, "used = %d\n", strlen(p0)); */

  return p0;
}



/*****************************************************************
 *
 * MX Resolver Routines
 *
 *****************************************************************/

#if defined(HAVE_ARPA_NAMESER_H)

#include <netinet/in.h>
#ifdef __APPLE__
#define BIND_8_COMPAT 1
#endif
#ifndef S_SPLINT_S
#include <arpa/nameser.h>
#include <resolv.h>
#endif
#include <netdb.h>
#include <sys/socket.h>
#ifndef S_SPLINT_S
#include <arpa/inet.h>
#endif

#include "sh_tools.h"

#ifndef HFIXEDSZ
#define HFIXEDSZ 12
#endif
#ifndef QFIXEDSZ
#define QFIXEDSZ  4
#endif

/*@unused@*//* used in get_mx() which is not parsed by splint */
static unsigned int get_short (unsigned char * loc)
{
  unsigned int retval = 0;
  if (loc)
    {
      /* byte order: MSB first
       */
      /*@+charint@*/
      retval = (((unsigned char) * loc) * 256) | ((unsigned char) * (loc + 1));
      /*@-charint@*/
    }
  return (retval);
}

/* parser errors with splint */
#ifndef S_SPLINT_S
static dnsrep * get_mx (char *hostname)
{
  int  ret, length, status;
  mx * result;
  size_t len;

  typedef union
  {
    HEADER head;
    unsigned char buffer[4096];
  } querybuf;

  querybuf * reply;
  char expanded[1024];
  unsigned char * comp_dn, * eom;
  HEADER * header;
  int      type, rdlength, pref;
  unsigned int count, theindex;
  dnsrep * retval;

  SL_ENTER(_("get_mx"));

  if (0 != res_init ())
    SL_RETURN (NULL, _("get_mx"));

  reply = SH_ALLOC(sizeof(querybuf));

  errno = 0;
  length = res_query (hostname, C_IN, T_MX, 
		      (unsigned char *) reply, 4095);

  if (length < 1)
    {
      char errbuf[SH_ERRBUF_SIZE];

      /* error handling
       */
      if (length == -1)
	{
	  if (errno == ECONNREFUSED)
	    status = ECONNREFUSED;
	  else
	    status = h_errno;

#ifdef FIL__
	  sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, status, MSG_E_SUBGEN,
			   (errno == ECONNREFUSED) ? 
			   sh_error_message (status, errbuf, sizeof(errbuf)) : 
			   sh_tools_errmessage(status, errbuf, sizeof(errbuf)),
			   _("res_query"));
#else
	  if (errno == ECONNREFUSED)
	    fprintf(stderr, " ERROR: %s: \n", strerror(errno)); /* TESTONLY */
	  else
	    fprintf(stderr, "HERROR: %s\n", hstrerror(h_errno));/* TESTONLY */
#endif
	}
      SH_FREE(reply);
      SL_RETURN (NULL, _("get_mx"));
    }


  header  = (HEADER *) reply;

  /* start of data section
   */
  comp_dn = (unsigned char *) reply + HFIXEDSZ;

  /* end-of-message
   */
  eom     = (unsigned char *) reply + length;

  /* HEADER NAME  -- must be skipped or decompressed
   * TYPE         -- type of data we got back, 16 bit integer
   * CLASS        -- class we got back, also a 16 bit integer 
   * TTL          -- 32 bit time-to-live. just skip this 
   * RDLENGTH     -- length of the data to follow 
   * RDATA        -- the data:
   *                 PREF  -- 16 bit preference 
   *                 MX    -- name of mail exchanger, must be decompressed
   */

  /* Skip the query data. 
   * QDCOUNT is the number of entries (unsigned 16 bit int). 
   */
  count = ntohs (header->qdcount); 
  for (theindex = 0; theindex < count; ++theindex)
    {
      ret = dn_skipname (comp_dn, eom);
      comp_dn += ret + QFIXEDSZ;
      if (ret < 1 || comp_dn >= eom)
	{
	  SH_FREE(reply);
	  SL_RETURN (NULL, _("get_mx"));
	}
    }

  count         = ntohs (header->ancount);
  if (count < 1)
    {
      SH_FREE(reply);
      SL_RETURN (NULL, _("get_mx"));
    }

  retval        = SH_ALLOC (sizeof (dnsrep));
  if (!retval)
    {
      SH_FREE(reply);
      SL_RETURN (NULL, _("get_mx"));
    }

  retval->count = count;

  /* allocate space for the results */

  if (!sl_ok_muls(count, sizeof (mx)))
    {
      SH_FREE(reply);
      SH_FREE   (retval);
      SL_RETURN (NULL, _("get_mx"));
    }

  result        = SH_ALLOC (count * sizeof (mx));
  
  if (!result)
    {
      SH_FREE(reply);
      SH_FREE   (retval);
      SL_RETURN (NULL, _("get_mx"));
    }
  retval->reply = result;

  do
    {
      /* HEADER NAME 
       */
      ret = dn_expand ((unsigned char *) reply, eom, comp_dn, 
		       (char *) expanded, 1023);
      comp_dn += ret;
      if (ret < 1 || comp_dn >= eom)
	{
	  SH_FREE(reply);
	  SH_FREE (result);
	  SH_FREE (retval);
	  SL_RETURN (NULL, _("get_mx"));
	}

      /* TYPE
       */
      type = get_short (comp_dn);
      comp_dn += 2;
      if (type != T_MX || comp_dn >= eom)
	{
	  SH_FREE(reply);
	  SH_FREE (result);
	  SH_FREE (retval);
	  SL_RETURN (NULL, _("get_mx"));
	}


      /* CLASS (re-use 'type' var)
       */
      /* type = get_short (comp_dn); *//* don't care */
      comp_dn += 2;
      if (comp_dn >= eom)
	{
	  SH_FREE(reply);
	  SH_FREE (result);
	  SH_FREE (retval);
	  SL_RETURN (NULL, _("get_mx"));
	}


      /* TTL
       */
      comp_dn += 4;
      if (comp_dn >= eom)
	{
	  SH_FREE(reply);
	  SH_FREE (result);
	  SH_FREE (retval);
	  SL_RETURN (NULL, _("get_mx"));
	}

      /* RDLENGTH
       */
      rdlength = get_short (comp_dn);
      comp_dn += 2;
      if (rdlength < 1 || comp_dn >= eom)
	{
	  SH_FREE(reply);
	  SH_FREE (result);
	  SH_FREE (retval);
	  SL_RETURN (NULL, _("get_mx"));
	}

      /* RDATA
       */
      pref = get_short (comp_dn);
      comp_dn += 2;
      if (comp_dn >= eom)
	{
	  SH_FREE(reply);
	  SH_FREE (result);
	  SH_FREE (retval);
	  SL_RETURN (NULL, _("get_mx"));
	}

      ret = dn_expand ((unsigned char *) reply, eom, comp_dn, 
		       (char *) expanded, 1023);
      comp_dn += ret;
      if (ret < 1)
	{
	  SH_FREE(reply);
	  SH_FREE (result);
	  SH_FREE (retval);
	  SL_RETURN (NULL, _("get_mx"));
	}
      count--;

      /* fill in the struct 
       */
      result[count].pref = pref;
      len = strlen (expanded) + 1;
      result[count].address = SH_ALLOC (len);
      sl_strlcpy (result[count].address, expanded, len);
    }
  while (ret > 0 && comp_dn < eom && count);

  SH_FREE(reply);
  SL_RETURN (retval, _("get_mx"));
}
/* ifndef S_SPLINT_S */
#endif

/* #if defined(HAVE_ARPA_NAMESER_H) */
#endif


static int comp_mx_pref (const void * a, const void * b)
{
  const mx * ax = (const mx *) a;
  const mx * bx = (const mx *) b;
  
  if      (ax->pref > bx->pref)
    return 1;
  else if (ax->pref < bx->pref)
    return -1;
  else
    return 0;
}

/*
 * return_mx returns a list of valid mail exchangers for domain
 */
static dnsrep * return_mx (char *domain)
{
  dnsrep * answers = NULL;
  mx     * result;
  dnsrep * retval;
  char   * address = NULL;
  char     errmsg[128];

  SL_ENTER(_("return_mx"));

#if defined(HAVE_ARPA_NAMESER_H)
  if (domain != NULL)
    answers = /*@-unrecog@*/get_mx (domain)/*@+unrecog@*/;
#endif

  if (answers != NULL && answers->count > 0)
    {
      qsort(answers->reply, (size_t) answers->count, sizeof(mx),
            comp_mx_pref);
      SL_RETURN (answers, _("return_mx"));
    }
  else
    {
      char numeric[SH_IP_BUF];

      if (domain != NULL)
	{
#if defined(HAVE_ARPA_NAMESER_H)
#ifdef FIL__
	  (void) sl_strlcpy (errmsg, _("No MX record for domain "), 127);
	  (void) sl_strlcat (errmsg, domain, 127);
	  sh_error_handle (SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			   errmsg,
			   _("get_mx"));
#else
	  /* flawfinder: ignore *//* test code only */
	  strcpy  (errmsg,                               /* known to fit  */
		   _("No MX record for domain "));
	  strncat (errmsg, domain, 100);
	  errmsg[122] = '\0';
	  fprintf(stderr, "Warning: %s\n", errmsg);
#endif
#endif
	}

      retval = NULL;

      if (domain != NULL)
	address = sh_ipvx_canonical(domain, numeric, sizeof(numeric));

      if (address)
	{
	  result       = SH_ALLOC (sizeof (mx));
	  retval       = SH_ALLOC (sizeof (dnsrep));
	  retval->reply = result;
	  retval->count = 1;
	  result->pref  = 0;

	  result->address = address;
	}
      else
	{
#ifdef FIL__
	  (void) sl_strlcpy (errmsg, _("Unknown host "), 127);
	  (void) sl_strlcat (errmsg, domain, 127);
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
			   errmsg,
			   _("return_mx"));
#endif
	  SL_RETURN (NULL, _("return_mx"));
	}

      SL_RETURN (retval, _("return_mx"));
    }
}

int free_mx (dnsrep * answers)
{
  mx     * result;
  int      i;

  SL_ENTER(_("free_mx"));
  if (!answers)
    SL_RETURN (0, _("return_mx"));

  result = answers->reply;  
  for (i = 0;  i < answers->count; ++i)
    {
      SH_FREE (result[i].address);
    }
  SH_FREE(result);
  SH_FREE(answers);
  SL_RETURN (0, _("return_mx"));
}

#ifdef TEST_ONLY
int main(int argc, char * argv[])
{
  int      i;
  dnsrep * answers;
  mx     * result;

  if (argc < 2)
    {
      fprintf(stderr, "Usage: dns <hostname>\n");
      return -1;
    }
  answers = return_mx(argv[1]);

  if (!answers)
    {
      fprintf(stderr, "No answer\n");
      return -1;
    }

  if (answers->count > 0)
    {
      result = answers->reply;
      for (i = 0; i < answers->count; ++i)
	{
	  fprintf(stderr, "Record %3d: [%3d] %s\n", i, 
		  result[i].pref, result[i].address);
	}	  
    }
  else
    {
      fprintf(stderr, "No answer\n");
      free_mx(answers);
      return -1;
    }
  free_mx(answers);
  return (0);
}
#endif

  

/* if defined(SH_WITH_MAIL) */
#endif



