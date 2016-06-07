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

#include <string.h>

#include "samhain.h"
#include "sh_error.h"
#include "sh_utils.h"
#include "sh_sem.h"

#undef  FIL__
#define FIL__  _("sh_err_console.c")

#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

extern int  OnlyStderr;
 
#if !defined(O_NONBLOCK)
#if defined(O_NDELAY)
#define O_NONBLOCK  O_NDELAY
#else
#define O_NONBLOCK  0
#endif
#endif

#if defined(WITH_MESSAGE_QUEUE) 

#if defined(HAVE_SYS_MSG_H)

#include <sys/ipc.h>
#include <sys/msg.h>

#if !defined(EIDRM)
#define EIDRM (EINVAL)
#endif

struct sh_msgbuf {
  long mtype;
  char mtext[1];  /* <-- sizeof(mtext) will be  1+MY_MAX_MSG */
};

static int msgq_enabled = S_FALSE;

/* The identifier of the message queue
 */
static int msgid = -1;

/* Open the SysV message queue, creating it when neccesary
 */
static int open_queue(void)
{
  key_t            key;
#if defined(WITH_TPT) 
  char errbuf[SH_ERRBUF_SIZE];
#endif

  SL_ENTER(_("open_queue"));

  /* get key
   */
  key = ftok (DEFAULT_DATAROOT, '#');

  if (key == (key_t) -1)
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<ftok: %s> errno=<%d>\n"), 
	    sh_error_message(errno, errbuf, sizeof(errbuf)), errno));
      SL_RETURN(-1, _("open_queue"));
    }

  /* get message identifier
   */
  msgid = msgget (key, IPC_CREAT|MESSAGE_QUEUE_MODE);

  if (msgid < 0)
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<msgget: %s> errno=<%d>\n"), 
	    sh_error_message(errno, errbuf, sizeof(errbuf)), errno));
      SL_RETURN(-1, _("open_queue"));
    }

  SL_RETURN(0, _("open_queue"));
}

/* Close the SysV message queue and/or semaphore
 */
void close_ipc (void)
{
  if (msgid != (-1))
    (void) msgctl (msgid, IPC_RMID, NULL);
  sh_sem_close();
  return;
}

/* Enable the message queue
 */
int enable_msgq(const char * foo)
{
  int i;

  SL_ENTER(_("enable_msgq"));
  i = sh_util_flagval(foo, &msgq_enabled);
  SL_RETURN(i, _("enable_msgq"));
}

#define MY_MAX_MSG    1022

static void remove_message()
{
  int rc;
  struct {
    long    mtype;       /* Message type. */
    char    mtext[128];  /* Message text. */
  } recv_msg;

  recv_msg.mtype = 1;
  do {
    rc = msgrcv(msgid, &recv_msg, sizeof(recv_msg.mtext), 1, 
		MSG_NOERROR|IPC_NOWAIT);
  } while (rc < 0 && errno == EINTR);

  memset(&recv_msg, '\0', sizeof(recv_msg));
  return;
}

static int push_message_queue (const char * msg)
{
  struct sh_msgbuf*   recv_msg = NULL;
  int              rc       = -1;
  static int       status   = -1;
  int              count    = 0;
#if defined(WITH_TPT) 
  char errbuf[SH_ERRBUF_SIZE];
#endif

  SL_ENTER(_("push_message_queue"));

  if (msgq_enabled == -1)
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<msg_queue not enabled>\n"))); 
      SL_RETURN(0, _("push_message_queue"));
    }

  if (status < 0)
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<msg_queue not open>\n"))); 
      status = open_queue();
    }

  if (status < 0)
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<open_queue() failed>\n"))); 
      SL_RETURN(-1, _("push_message_queue"));
    }

  /* struct msgbuf {
   *   long mtype;
   *   char mtext[1];  <-- sizeof(mtext) will be  1+MY_MAX_MSG
   * } */

  recv_msg = (struct sh_msgbuf*) SH_ALLOC(sizeof(struct sh_msgbuf)+MY_MAX_MSG);
  recv_msg->mtype = 1;
  sl_strlcpy (recv_msg->mtext, msg, MY_MAX_MSG+1);

  count = 0;

 send_it:

  if (count > 1)
    {
      memset(recv_msg, '\0', MY_MAX_MSG+1);
      SH_FREE(recv_msg);
      SL_RETURN(-1, _("push_message_queue"));
    }

  do { errno = 0;
    rc = msgsnd(msgid, recv_msg, strlen(recv_msg->mtext)+1, IPC_NOWAIT);

    if (rc == -1 && errno == EAGAIN)
      remove_message();
  } while (rc < 0 && (errno == EINTR && errno == EAGAIN));
  
  if (rc == -1 && errno != EAGAIN) 
    {
      /* EIDRM is not in OpenBSD */
      if (errno == EINVAL || errno == EIDRM) {
	TPT(( 0, FIL__, __LINE__, _("msg=<msg_queue not open>\n"))); 
	status = open_queue();
	if (status == 0) {
	  ++count;
	  goto send_it; }
      } else {
	TPT(( 0, FIL__, __LINE__, _("msg=<msgsnd: %s> errno=<%d>\n"), 
	      sh_error_message(errno, errbuf, sizeof(errbuf)), errno));
	memset(recv_msg, '\0', MY_MAX_MSG+1);
	SH_FREE(recv_msg);
	SL_RETURN(-1, _("push_message_queue"));
      }
    }

  memset(recv_msg, '\0', MY_MAX_MSG+1);
  SH_FREE(recv_msg);

  SL_RETURN(0, _("push_message_queue"));
}
/* if defined(HAVE_SYS_MSG_H) */
#else

#error **********************************************
#error
#error The sys/msg.h header was not found, 
#error cannot compile with --enable-message-queue
#error
#error **********************************************

#endif

#else /* no message queue */

void close_ipc() { sh_sem_close(); return; }

#endif

static int count_dev_console = 0;

void reset_count_dev_console(void)
{
  count_dev_console = 0;
  return;
}

/* ---- Set the console device. ----
 */
int sh_log_set_console (const char * address)
{
  SL_ENTER(_("sh_log_set_console"));
  if (address != NULL && count_dev_console < 2 
      && sl_strlen(address) < SH_PATHBUF)
    {
      if (count_dev_console == 0)
        (void) sl_strlcpy (sh.srvcons.name, address, SH_PATHBUF);
      else
        (void) sl_strlcpy (sh.srvcons.alt,  address, SH_PATHBUF);

      ++count_dev_console;
      SL_RETURN(0, _("sh_log_set_console"));
    }
  SL_RETURN((-1), _("sh_log_set_console"));
}

#if defined(WITH_TRACE) || defined(WITH_TPT)
char *  sh_log_console_name (void)
{
  if (sh.srvcons.name[0] == '\0' ||
      0 == strcmp(sh.srvcons.name, _("NULL")))
    return (_("/dev/console"));
  return sh.srvcons.name;
}
#endif

#ifndef STDERR_FILENO 
#define STDERR_FILENO   2
#endif

/* ---- Print out a message. ----
 */
int  sh_log_console (const /*@null@*/char *errmsg)
{
  static int service_failure[2] = { 0, 0};
  int    fd[2] = { -1, -1};
  int    cc;
  size_t len;
  int    ccMax = 1;
  int    retval = -1;
  /* static int logkey_seen = 0; */
  int    error;
  static int blockMe = 0;
  int    val_return;

  SL_ENTER(_("sh_log_console"));

  if (errmsg == NULL || blockMe == 1)
    {
      SL_RETURN(0, _("sh_log_console"));
    }
  else
    blockMe = 1;


#ifdef WITH_MESSAGE_QUEUE
  if (0 != push_message_queue (errmsg))
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<push_message_queue() failed>\n"))); 
    }
#endif

  if (sh.flag.isdaemon == S_FALSE || OnlyStderr == S_TRUE)
    {
      len = strlen(errmsg);
      do {
	val_return = write(STDERR_FILENO, errmsg, len);
      } while (val_return < 0 && errno == EINTR); 
      do {
	val_return = write(STDERR_FILENO, "\n", 1);
      } while (val_return < 0 && errno == EINTR); 
      /* 
       * fprintf (stderr, "%s\n", errmsg); 
       */
      blockMe = 0;
      SL_RETURN(0, _("sh_log_console"));
    }

  /* --- daemon && initialized ---
   */
  if ( OnlyStderr == S_FALSE ) 
    {
      fd[0] = open ( sh.srvcons.name, O_WRONLY|O_APPEND|O_NOCTTY|O_NONBLOCK);

      if (sh.srvcons.alt[0] != '\0')
	{
	  fd[1] = open (sh.srvcons.alt, O_WRONLY|O_APPEND|O_NOCTTY|O_NONBLOCK);
	  ccMax = 2;
	}

      for (cc = 0; cc < ccMax; ++cc)
	{
      
	  if (fd[cc] < 0 && service_failure[cc] == 0)
	    {
	      error = errno;
	      sh_error_handle ((-1), FIL__, __LINE__, error, MSG_SRV_FAIL,
			       _("console"), 
			       (cc == 0) ? sh.srvcons.name : sh.srvcons.alt);
	      service_failure[cc] = 1;
	    }

	  if (fd[cc] >= 0)
	    {
	      do {
		val_return = write(fd[cc], errmsg, strlen(errmsg));
	      } while (val_return < 0 && errno == EINTR);
	      do {
		val_return = write(fd[cc], "\r\n",              2);
	      } while (val_return < 0 && errno == EINTR);
	      (void) sl_close_fd(FIL__, __LINE__, fd[cc]);
	      service_failure[cc] = 0;
	    }
	}
    }
  else
    retval = 0;

  blockMe = 0;
  SL_RETURN(retval, _("sh_log_console"));
}


