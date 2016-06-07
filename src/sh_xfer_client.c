/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999, 2000, 2015 Rainer Wichmann                          */
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
#include <stdio.h>
#include <stdlib.h>


/* Must be early on FreeBSD
 */
#include <sys/types.h>

/* must be .le. than (1020 * 64)
 * (see sh_tools.c -- put_header)
 *
 * also: must be  (N * 16), otherwise
 * binary files cannot be transferred encrypted
 *
 * 65280 = (1020*64)
 * #define TRANS_BYTES 8000  V0.8
 */
#ifdef  SH_ENCRYPT
#define TRANS_BYTES 65120
#else
#define TRANS_BYTES 65280
#endif

/* timeout for session key
 */
#define TIMEOUT_KEY 7200

/* max time between connection attempts
 */
#define TIMEOUT_CON 2048 

/* #undef  SRP_DEBUG */
/* #define SRP_DEBUG */

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

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef  HAVE_UNISTD_H
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

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

#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
#include <sys/mman.h>
#endif


#include <netdb.h> 
#include <sys/types.h> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#ifndef S_SPLINT_S
#include <arpa/inet.h>
#endif

#include "sh_ipvx.h"
#include "samhain.h"
#include "sh_tiger.h"
#include "sh_utils.h"
#include "sh_unix.h"
#include "sh_xfer.h"
#include "sh_srp.h"
#include "sh_fifo.h"
#include "sh_tools.h"
#include "sh_entropy.h"
#include "sh_html.h"
#include "sh_nmail.h"
#include "sh_socket.h"
#define SH_NEED_GETHOSTBYXXX
#include "sh_static.h"

#ifdef SH_ENCRYPT
#include "rijndael-api-fst.h"
char * sh_tools_makePack (unsigned char * header, int flag,
			  char * payload, unsigned long payload_size,
			  keyInstance * keyInstE);
char * sh_tools_revertPack (unsigned char * header, int flag, char * message,
			    keyInstance * keyInstE, 
			    unsigned long message_size);
#endif

/* define this if you want to debug the client/server communication */
/* #define SH_DBG_PROT 1 */

#ifdef  SH_DBG_PROT
#define SH_SHOWPROT(c,d) sh_tools_show_header((c), (d))
#else
#define SH_SHOWPROT(c,d) 
#endif

/* the port client will be connecting to 
 */
#ifndef SH_DEFAULT_PORT
#define SH_DEFAULT_PORT 49777    
#endif

#ifndef SH_SELECT_REPEAT
#define SH_SELECT_REPEAT 60
#endif

#ifndef SH_HEADER_SIZE
#define SH_HEADER_SIZE 7
#endif

#ifndef SH_CHALLENGE_SIZE
#define SH_CHALLENGE_SIZE 9
#endif

#undef  FIL__
#define FIL__  _("sh_xfer_client.c")

extern int flag_err_debug;
extern int flag_err_info;

#ifndef SH_STANDALONE

#if defined(WITH_TRACE) || defined(WITH_TPT) 
char * hu_trans(const char * ihu)
{
  static char ohu[17];
  sprintf(ohu, _("%c%03o"), '\\',                   /* known to fit  */
	  (unsigned char) ihu[0]);
  sprintf(&(ohu[4]), _("%c%03o"), '\\',             /* known to fit  */
	  (unsigned char) ihu[1]);
  sprintf(&(ohu[8]), _("%c%03o"), '\\',             /* known to fit  */
	  (unsigned char) ihu[2]);
  sprintf(&(ohu[12]), _("%c%03o"), '\\',            /* known to fit  */
	  (unsigned char) ihu[3]);
  ohu[16] = '\0';
  return ohu;
}
#endif
/* #ifndef SH_STANDALONE */
#endif

#if !defined(USE_SRP_PROTOCOL)
void sh_passwd (char * salt, char * password, char * nounce, char *hash)
{

  char           *combi;
  size_t          len;
  unsigned char * tmp = NULL;
  char hashbuf[KEYBUF_SIZE];

  if (password == NULL)
    {
      tmp = (unsigned char *) &(skey->pw[0]);
      memcpy(skey->vernam, tmp, PW_LEN);
      sl_strlcpy (skey->vernam,
		  sh_tiger_hash(skey->vernam, TIGER_DATA, PW_LEN,
				hashbuf, sizeof(hashbuf)), 
		  KEY_LEN+1);
    }
  else if (sl_strlen(password) < PW_LEN)
    {
      fprintf(stderr, _("Password has less than %d chars !\n"),
		   PW_LEN);
      _exit(EXIT_FAILURE);
    }
  else
    {
      sl_strlcpy (skey->vernam, password, KEY_LEN+1);
    }

  len = sl_strlen(salt) + 1;
  if (sl_ok_adds(len, sl_strlen(skey->vernam)))
    len += sl_strlen(skey->vernam);
  if (nounce != NULL && sl_ok_adds(len, sl_strlen(nounce))) 
    len += sl_strlen(nounce);
  
  /* H(s,P)
   */
  combi = SH_ALLOC(len);
  (void) sl_strlcpy (combi, salt, len);
  (void) sl_strlcat (combi, skey->vernam, len);
  if (nounce != NULL)
    (void) sl_strlcat (combi, nounce, len);
  (void) sl_strlcpy (hash, 
		     sh_tiger_hash(combi, TIGER_DATA, 
				   (unsigned long) sl_strlen(combi),
				   hashbuf, sizeof(hashbuf)),
		     KEY_LEN+1);
  SH_FREE (combi);
  hash[KEY_LEN] = '\0';
  return;
}
#endif

#if defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER)

/* Server addresses in use
 */
static int count_dev_server = 0;

void reset_count_dev_server(void)
{
  count_dev_server = 0;
  return;
}

int sh_xfer_set_logserver (const char * address)
{
  SL_ENTER(_("sh_xfer_set_logserver"));

  if (address != NULL && count_dev_server < 2 
      && sl_strlen(address) < SH_PATHBUF && sl_strlen(address) > 0) 
    {
      if (count_dev_server == 0)
	(void) sl_strlcpy (sh.srvexport.name, address, SH_PATHBUF);
      else
	(void) sl_strlcpy (sh.srvexport.alt,  address, SH_PATHBUF);

      ++count_dev_server;
      SL_RETURN (0, _("sh_xfer_set_logserver"));
    }
  SL_RETURN (-1, _("sh_xfer_set_logserver"));
}

static
int xfer_send_intern (int mysocket, const int protocol, char * micro, 
		      char * msgbuf, unsigned long length, int docrypt)
{
  unsigned long           numbytes, countbytes;
  int                     flag_err = 0;
  unsigned char           head[SH_HEADER_SIZE];
  char                  * outbuf;
#ifdef SH_ENCRYPT
  char                  * msg2buf = NULL;
#else
  (void) docrypt;
#endif

  SL_ENTER(_("xfer_send_intern"));

#ifdef SH_ENCRYPT
  if  ((S_TRUE == docrypt) && ((protocol & SH_PROTO_ENC) != 0))
    {
      put_header (head, protocol, &length, micro);
      msg2buf  = sh_tools_makePack (head, 0, msgbuf, length, 
				    &(skey->keyInstE));
      length   = (unsigned long) (256 * (unsigned int)head[1] + 
				  (unsigned int)head[2]);
      outbuf   = msg2buf;
    }
  else
    {
      outbuf = msgbuf;
      put_header (head, protocol, &length, micro);
    }
#else
  outbuf = msgbuf;
  put_header (head, protocol, &length, micro);
#endif

  SH_SHOWPROT(head,'>');
  
  numbytes     = SH_HEADER_SIZE;
  countbytes   = write_port (mysocket, (char *)head, numbytes, &flag_err, 300);

  if (countbytes == numbytes && outbuf != NULL)
    {
      numbytes     = length;
      countbytes   = write_port (mysocket, outbuf, numbytes, &flag_err, 300);
    }

#ifdef SH_ENCRYPT
  if (msg2buf != NULL)
    SH_FREE(msg2buf);
#endif

  if (countbytes == numbytes)
    SL_RETURN( 0, _("xfer_send_intern"));
  else
    SL_RETURN( flag_err, _("xfer_send_intern"));
}

static
int xfer_send (int mysocket, const int protocol, char * micro, 
		     char * msgbuf, unsigned long length)
{
  int i;
  SL_ENTER(_("xfer_send"));
  TPT(( 0, FIL__, __LINE__, _("msg=<Send.>\n")));
  i =  xfer_send_intern (mysocket, protocol, micro, 
			       msgbuf, length, S_FALSE);
  SL_RETURN(i, _("xfer_send"));
}
static
int xfer_send_crypt (int mysocket, const int protocol, char * micro, 
			   char * msgbuf, unsigned long length)
{
  int i;
  SL_ENTER(_("xfer_send_crypt"));
#ifdef SH_ENCRYPT
  TPT(( 0, FIL__, __LINE__, _("msg=<Send encrypted.>\n")));
#else
  TPT(( 0, FIL__, __LINE__, _("msg=<Send.>\n")));
#endif
  i = xfer_send_intern (mysocket, protocol, micro, 
			      msgbuf, length, S_TRUE);
  SL_RETURN(i, _("xfer_send_crypt"));
}


/* receive answer, add a trailing NULL to terminate string
 * decrypt answer
 */
static
long xfer_receive_intern (int mysocket, const int protocol, char * micro,     
			  char *  msgbuf, unsigned long length, 
			  int docrypt)
{
  unsigned long numbytes, countbytes;
  int           flag_err = -1;
  unsigned char head[SH_HEADER_SIZE];
#ifndef SH_ENCRYPT
  (void) docrypt;
#endif

  SL_ENTER(_("xfer_receive_intern"));

#ifdef SH_ENCRYPT
  /* make sure length is not multiple of B_SIZ, see below 
   */
  ASSERT_RET((length % B_SIZ != 0), _("length % 16 != 0"), flag_err);
#endif

  if (micro != NULL)
    micro[4]     = '\0';
  if (msgbuf != NULL)
    msgbuf[0]     = '\0';

  numbytes     = SH_HEADER_SIZE;
  countbytes   = read_port (mysocket, (char *)head, numbytes, &flag_err, 300);

  if (countbytes != numbytes)
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<countbytes != numbytes>\n")));
      SL_RETURN(flag_err, _("xfer_receive_intern"));
    }
  else if (msgbuf == NULL)
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      _("msgbuf is NULL"), _("xfer_receive_intern"));
      SL_RETURN((-1), _("xfer_receive_intern"));
    }
  else if (head[0] != protocol && (head[0] & SH_PROTO_SRP) == 0)
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_MISMATCH);
      SL_RETURN((-1), _("xfer_receive_intern"));
    }
  else
    {
      get_header (head, &numbytes, micro);
      SH_SHOWPROT(head, '<');

      if (numbytes > 0)
	{
	  numbytes = (numbytes > length ? length : numbytes);

	  countbytes = read_port (mysocket, msgbuf, numbytes, &flag_err, 300);

	  if (countbytes < length)
	    msgbuf[countbytes] = '\0';
	  else
	    msgbuf[length-1] = '\0';

	  if (flag_err != 0)
	    {
	      TPT(( 0, FIL__, __LINE__, _("msg=<read error>\n")));
	      SL_RETURN((-1), _("xfer_receive_intern"));
	    }
	}
    }

#ifdef SH_ENCRYPT
  if      ((S_TRUE == docrypt) && ((protocol & SH_PROTO_ENC) != 0))
    {
      unsigned long head_length;
      char * tmp = SH_ALLOC((size_t)length);

      memcpy(tmp, msgbuf, (size_t)length);
      tmp = sh_tools_revertPack (head, 0, tmp, &(skey->keyInstD), countbytes);

      head_length = (unsigned long) (256 * (unsigned int)head[1] + 
				     (unsigned int)head[2]);

      /* 
       * revertPack returns header with length <= (original_length-16), so
       * the following msgbuf[length] = '\0' is always safe.
       * Nevertheless, check for proper length.
       */
      if (head_length <= (length-1))
	length      = head_length;
      else
	--length;

      memcpy(msgbuf, tmp, (size_t)length);
      msgbuf[length] = '\0';
      SH_FREE(tmp);
      if (countbytes == numbytes) 
	countbytes = length; /* to avoid error on return, see below */
      numbytes = length;
    }
#endif

  if (countbytes == numbytes)
    SL_RETURN(((long)numbytes), _("xfer_receive_intern"));
  else
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<short read>\n")));
      SL_RETURN(flag_err, _("xfer_receive_intern"));
    }
}

static
long xfer_receive (int mysocket, const int protocol, char * micro,     
		   char * msgbuf, unsigned long length)
{
  long i;
  SL_ENTER(_("xfer_receive"));
  TPT(( 0, FIL__, __LINE__, _("msg=<Receive.>\n")));
  i = xfer_receive_intern (mysocket, protocol, micro, 
			   msgbuf, length, S_FALSE);
  SL_RETURN(i, _("xfer_receive"));
}

static
long xfer_receive_crypt (int mysocket, const int protocol, char * micro,     
			 char * msgbuf, unsigned long length)
{
  long i;
  SL_ENTER(_("xfer_receive_crypt"));
#ifdef SH_ENCRYPT
  TPT(( 0, FIL__, __LINE__, _("msg=<Receive encrypted.>\n")));
#else
  TPT(( 0, FIL__, __LINE__, _("msg=<Receive.>\n")));
#endif
  i = xfer_receive_intern (mysocket, protocol, micro, 
			   msgbuf, length, S_TRUE);
  SL_RETURN(i, _("xfer_receive_crypt"));
}

/**************************************************
 *
 *
 *  C L I E N T  
 *
 *
 ***************************************************/


#include <time.h>

static SH_FIFO * fifo = NULL;

static long xfer_try_report (char * errmsg);

unsigned int ServerPort = SH_DEFAULT_PORT;

int sh_xfer_server_port (const char * str)
{
  unsigned long l;
  char * endptr;

  SL_ENTER(_("sh_xfer_server_port"));

  l = strtoul (str, &endptr, 0);
  if (l > 65535 || endptr == str)
    {
      SL_RETURN (-1, _("sh_xfer_server_port"));
    }
  ServerPort = (unsigned int) l;
  SL_RETURN (0, _("sh_xfer_server_port"));
}

long sh_xfer_report (char * errmsg)
{
  static int have_server = S_TRUE;
  long   status;
  char * popmsg;
  static int nofail = S_TRUE;

  SL_ENTER(_("sh_xfer_report"));

  /* --- No log server available. ---
   */
  if (have_server == S_TRUE && sh.srvexport.name[0] == '\0')
    {
      have_server = S_FALSE;
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_NONAME);
      SL_RETURN (-1, _("sh_xfer_report"));
    }
  else if (have_server == BAD)
    {
      SL_RETURN (-1, _("sh_xfer_report"));
    }

  /* --- Allocate fifo. ---
   */
  if (fifo == NULL)
    {
      fifo = SH_ALLOC(sizeof(SH_FIFO));
      fifo_init(fifo);
    }

  /* --- Check for messages on the queue, and send them first. ---
   */
  while (NULL != (popmsg = pop_list(fifo)) )
    {
      status = xfer_try_report (popmsg);
      if (status != 0)
	{
	  (void) push_tail_list (fifo, popmsg, 0, NULL); 
	  SH_FREE(popmsg);
	  if (SH_FIFO_MAX == push_list (fifo, errmsg, 0,NULL))
	    SL_RETURN (-2, _("sh_xfer_report"));
	  SL_RETURN (-1, _("sh_xfer_report"));
	}
      SH_FREE(popmsg);
    }

  /* --- Now send the error message. ---
   */ 
  status = xfer_try_report (errmsg);
  if (status != 0)
    {
      if (nofail == S_TRUE)
	sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_SRV_FAIL,
			 _("log server"), sh.srvexport.name);
      nofail = S_FALSE;
      if (SH_FIFO_MAX == push_list (fifo, errmsg, 0, NULL))
	SL_RETURN (-2, _("sh_xfer_report"));
      SL_RETURN (-1, _("sh_xfer_report"));
    }

  nofail = S_TRUE;
  SL_RETURN (0, _("sh_xfer_report"));  
}

static long xfer_try_report_int (char * errmsg, const int what);

static long xfer_try_report (char * errmsg)
{
  long i;
  SL_ENTER(_("xfer_try_report"));
  i = xfer_try_report_int (errmsg, SH_PROTO_MSG);
  SL_RETURN(i, _("xfer_try_report")); 
}

long sh_xfer_request_file (const char * file)
{
  long i;
  char tmp_file[64];
  SL_ENTER(_("sh_xfer_request_file"));
  sl_strlcpy(tmp_file, file, sizeof(tmp_file));
  i = xfer_try_report_int (tmp_file, SH_PROTO_BIG);
  SL_RETURN(i, _("sh_xfer_request_file")); 
}

static unsigned long sh_throttle_delay = 0;

int sh_xfer_set_throttle_delay (const char * c)
{
  long val;

  SL_ENTER(_("sh_xfer_set_throttle_delay"));
  val = strtol (c, (char **)NULL, 10);
  if (val < 0)
    SL_RETURN( (-1), _("sh_xfer_set_throttle_delay"));

  val = (val > 1000) ? 1000 : val;

  sh_throttle_delay = (unsigned long) val;
  SL_RETURN( (0), _("sh_xfer_set_throttle_delay"));
}

static time_t xfer_timeout_val =  1;

static int xfer_conn_state(int initialized, int conn_state)
{
  static time_t time_now  = 1200;
  static time_t time_last =    0;

  if (initialized == S_FALSE || conn_state == S_FALSE)
    {
      xfer_timeout_val = 
	((xfer_timeout_val > TIMEOUT_CON) ? TIMEOUT_CON : xfer_timeout_val);

      /* --- Retry bad attempt only after some time. ---
       */
      time_now  = time (NULL);
      if ((time_now - time_last) < xfer_timeout_val) 
	{
	  TPT(( 0, FIL__, __LINE__, _("msg=<Within deadtime, no retry.>\n")));
	  return -1;
	}
      TPT(( 0, FIL__, __LINE__, _("msg=<Retry.>\n")));
    }
  time_last  = time (NULL);
  return 0;
}

static int xfer_connect(int * conn_state)
{
  char         error_msg[256];
  char         error_call[SH_MINIBUF] = { 0 };
  int          error_num = 0;

  int sockfd = connect_port_2 (sh.srvexport.name, sh.srvexport.alt, ServerPort, 
			       error_call, &error_num, error_msg, 256);

  if (sockfd < 3)
    {
      *conn_state = S_FALSE;
      xfer_timeout_val *= 2;
      sh_error_handle ((-1), FIL__, __LINE__, error_num, 
		       MSG_E_NET, error_msg, error_call,
		       _("export"), sh.srvexport.name);
      return -1;
    }

  *conn_state = S_TRUE;
  return sockfd;
}

int xfer_greet_server(int sockfd, char * answer)
{
  int    flag_err;
  char   head_u[5];
  int    theProto = SH_PROTO_SRP;
  
  TPT(( 0, FIL__, __LINE__, _("msg=<c/r: entry>\n")));
  
  sl_strlcpy (answer, sh.host.name, 512);
      
  flag_err = xfer_send (sockfd, theProto, _("SALT"), 
			answer,  (unsigned long)sl_strlen(answer));
      
  TPT(( 0, FIL__, __LINE__, _("msg=<c/r: sent SALT, flag_err = %d>\n"), 
	flag_err));
      
  /* get nonce from server
   */
  if (flag_err == 0)
    {
      flag_err = xfer_receive (sockfd, (char)theProto, head_u, 
				   answer,  511);
      flag_err = (flag_err < 0) ? flag_err : 0;
      TPT(( 0, FIL__, __LINE__, 
	    _("msg=<c/r: rcvt nonce, flag_err = %d>\n"), 
	    flag_err));
    }
  
  if ( 0 != check_request (head_u, _("INIT")) )
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<srp: u = %03o-%03o-%03o-%03o>\n"), head_u[0], head_u[1], head_u[2], head_u[3]));
      flag_err = -1;
    }
  return flag_err;
}
  

#if !defined(USE_SRP_PROTOCOL)

static int xfer_auth(int is_reinit, int * initialized, 
		     int sockfd, char * answer)
{
  /**************************************************
   *
   * --- challenge/response authentication ---
   *
   **************************************************/

  int                  flag_err = 0;
  int                  theProto = 0;
  char   nounce[KEY_LEN+1];
  char   temp[2*KEY_LEN+1];
  char   nonce_u[KEY_LEN+1];
  UINT32 ticks;

  char   head_u[5];
  char   foo_M1[KEY_LEN+1];
  char   hashbuf[KEYBUF_SIZE];
#ifdef SH_ENCRYPT
  int err_num;
  char expbuf[SH_ERRBUF_SIZE];
#endif

  SL_REQUIRE((sockfd > 2), _("sockfd > 2"));

  if (is_reinit == S_FALSE)
    flag_err = xfer_greet_server(sockfd, answer);
  else
    sh_tools_probe_reset();

  /* entry point for jump from message forward if session key must
   * be re-initialized
   */	 

  if ( flag_err == 0 && sl_strlen(answer) >  KEY_LEN )
    (void) sl_strlcpy(nounce, &answer[KEY_LEN], KEY_LEN+1);
  else
    flag_err = (-1);
  
  TPT(( 0, FIL__, __LINE__, _("msg=<c/r: rcvt INIT, flag_err = %d>\n"), 
	flag_err));
  
  /* verify random nonce v from server H(v, P)v
   */
  sh_passwd (nounce, NULL, NULL, temp);
  if ( 0 != sl_strncmp(temp, answer, KEY_LEN))
    flag_err = (-1);
  
  TPT(( 0, FIL__, __LINE__, _("msg=<c/r: vrfy nonce, flag_err = %d>\n"), 
	flag_err));
  
  
  /* --- Create own nonce. ---
   */
  ticks = (UINT32) taus_get ();
  
  (void) sl_strlcpy(nonce_u, 
		    sh_tiger_hash((char *) &ticks, 
				  TIGER_DATA, 
				  (unsigned long)sizeof(UINT32), 
				  hashbuf, sizeof(hashbuf)),
		    KEY_LEN+1);
  
  /* --- Form the message H(H(u,v),P)u ---
   */
  (void) sl_strlcpy(temp, nonce_u, 2*KEY_LEN+1); 
  (void) sl_strlcat(temp,  nounce, 2*KEY_LEN+1); 
  (void) sl_strlcpy(temp, 
		    sh_tiger_hash(temp, 
				  TIGER_DATA, 
				  (unsigned long)sl_strlen(temp), 
				  hashbuf, sizeof(hashbuf)),
		    KEY_LEN+1);
  sh_passwd (temp, NULL, NULL, foo_M1);
  (void) sl_strlcpy(temp, foo_M1, 2*KEY_LEN+1);
  (void) sl_strlcat(temp, nonce_u, 2*KEY_LEN+1);
  
  /* --- Send it to server. ---
   */
  if (flag_err == 0)
    {
      flag_err = xfer_send (sockfd, 
			    (theProto|SH_PROTO_SRP), 
			    _("PASS"), temp, 
			    (unsigned long)sl_strlen(temp));
      TPT(( 0, FIL__, __LINE__, _("msg=<c/r: sent PASS, flag_err = %d>\n"),
	    flag_err));
    }
  
  if (flag_err == 0)
    {
      flag_err = xfer_receive (sockfd,
			       (theProto|SH_PROTO_SRP), 
			       head_u, answer,  511);  
      sh_passwd (nounce, NULL, nonce_u, foo_M1);
      (void) sl_strlcpy (skey->session, foo_M1, KEY_LEN+1);
#ifdef SH_ENCRYPT
      err_num = rijndael_makeKey(&(skey->keyInstE), 
				 (BYTE)DIR_ENCRYPT, 192, skey->session);
      if (err_num < 0)
	sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
			errorExplain(err_num, expbuf, sizeof(expbuf)), 
			_("xfer_try_report_int: makeKey"));
      
      err_num = rijndael_makeKey(&(skey->keyInstD), 
				 (BYTE)DIR_DECRYPT, 192, skey->session);
      if (err_num < 0)
	sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
			errorExplain(err_num, expbuf, sizeof(expbuf)), 
			_("xfer_try_report_int: make_key"));
#endif
      *initialized = S_TRUE;
    }
  
  if (*initialized == S_FALSE)
    {
      xfer_timeout_val *= 2;
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_NOAUTH);
      memset(answer, 0, 512);
      MUNLOCK(answer, 512);
      SH_FREE(answer);
      return -1;
    }
  else
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_AUTH);
    }
  return 0;
}    
#else

static void noise()
{
  UINT32 n = taus_get();
  retry_msleep(0, (n & 0x0000007F));
  return;
}
  

static int xfer_auth(int is_reinit, int * initialized, 
		     int sockfd, char * answer)
{
  /* This is the SRP authenticated key exchange protocol.
   * Produces a session key skey->session.
   */
  
  int                  flag_err = 0;
  int                  theProto = 0;

  char   head_u[5];
  char   u_real[SH_CHALLENGE_SIZE];
  char * foo_A;
  char * foo_Sc;
  char * M;
  char   foo_M1[KEY_LEN+1];
  char   hashbuf[KEYBUF_SIZE];
#ifdef SH_ENCRYPT
  int err_num;
  char expbuf[SH_ERRBUF_SIZE];
#endif

  SL_REQUIRE((sockfd > 2), _("sockfd > 2"));

  if (is_reinit == S_FALSE)
    flag_err = xfer_greet_server(sockfd, answer);
  else
    sh_tools_probe_reset();

  /* Entry point for jump from message forward if session key must
   * be re-initialized.
   */	 
  TPT(( 0, FIL__, __LINE__, _("msg=<srp: INIT>\n")));
  
  if ( flag_err == 0 )
    {
      if (0 != sh_srp_init())
	sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_EBGN);
      else 
	{
	  TPT(( 0, FIL__, __LINE__, _("msg=<srp: bignum initialized>\n")));

	  sh_srp_x (answer, NULL);  /* x        password      */
	  sh_srp_make_a ();         /* a        random number */
	  foo_A = sh_srp_A();       /* g^a                    */

	  TPT(( 0, FIL__, __LINE__, _("msg=<srp: A = %s>\n"), foo_A));

	  if (foo_A == NULL)
	    flag_err = (-1);

	  noise();

	  if (flag_err == 0)
	    flag_err = xfer_send (sockfd, 
				  (theProto|SH_PROTO_SRP), 
				  _("PC01"),
				  foo_A, sl_strlen(foo_A)+1); 
	  if (flag_err == 0)
	    {
	      flag_err = xfer_receive (sockfd, 
				       (theProto|SH_PROTO_SRP),
				       head_u,
				       answer, 511);
	      flag_err = (flag_err < 0) ? flag_err : 0;
	      TPT(( 0, FIL__, __LINE__, _("msg=<srp: B = %s>\n"), answer));
	      TPT(( 0, FIL__, __LINE__, _("msg=<srp: u = %03o-%03o-%03o-%03o>\n"), head_u[0], head_u[1], head_u[2], head_u[3]));
	    }

	  /*                     u        nounce        */
	  /*                     B        answer        */
	  /*                     S = (B-g^x)^(a+ux)     */
	  
    
	  if (flag_err == 0)
	    { 
	      noise();

	      if (0 != sh_srp_check_zero (answer))
		sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_EZERO);
	      else 
		{
		  sl_strlcpy(u_real, sh_tiger_hash(head_u, TIGER_DATA, 4, 
						   hashbuf, sizeof(hashbuf)), 
			     SH_CHALLENGE_SIZE);
		  foo_Sc = sh_srp_S_c (u_real, answer);
		  
		  TPT(( 0, FIL__, __LINE__, _("msg=<srp: U = %s>\n"), 
			u_real));
		  TPT(( 0, FIL__, __LINE__, _("msg=<srp:Sc = %s>\n"), 
			foo_Sc));
		  
		  /* --- Now send H(A,B,H(Sc)) and check. --- 
		   */
		  if (foo_Sc != NULL && 0 == sh_srp_check_zero (foo_Sc))
		    {
		      sh_srp_M(foo_A, 
			       answer, 
			       sh_tiger_hash(foo_Sc, 
					     TIGER_DATA, 
					     sl_strlen(foo_Sc), 
					     hashbuf, sizeof(hashbuf)),
			       foo_M1, KEY_LEN+1);
		      
		      
		      TPT(( 0, FIL__, __LINE__, _("msg=<srp:M1 = %s>\n"), 
			    foo_M1));
		      
		      flag_err = xfer_send(sockfd, 
					   (theProto|SH_PROTO_SRP), 
					   _("PC02"),
					   foo_M1, KEY_LEN+1);
		    }
		  else
		    flag_err = (-1);
		  
		  if (flag_err == 0)
		    {
		      flag_err = xfer_receive(sockfd, 
					      (theProto|SH_PROTO_SRP),
					      head_u, 
					      answer, 511);
		      flag_err = (flag_err < 0) ? flag_err : 0;
		      TPT(( 0, FIL__, __LINE__, _("msg=<srp: M = %s>\n"), 
			    answer));
		    }
		  
		  if (flag_err == 0   && 0 == check_request (head_u, _("PARP")) )
		    {
		      /* ------  verify M2 = H(A, M1, K) --------
		       */
		      char M_buf[KEY_LEN+1];
		      M = sh_srp_M (foo_A, foo_M1,
				    sh_tiger_hash(foo_Sc,
						  TIGER_DATA,
						  sl_strlen(foo_Sc), 
						  hashbuf, sizeof(hashbuf)),
				    M_buf, sizeof(M_buf)
				    );
		      if (M != NULL && 
			  0 == sl_strncmp (answer, M, KEY_LEN+1))
			{
			  sl_strlcpy (skey->session, 
				      sh_tiger_hash(foo_Sc, 
						    TIGER_DATA,
						    sl_strlen(foo_Sc), 
						    hashbuf, sizeof(hashbuf)),
				      KEY_LEN+1);
			  TPT(( 0, FIL__, __LINE__, 
				_("msg=<srp: Key = %s>\n"), 
				skey->session));

#ifdef SH_ENCRYPT
			  err_num = rijndael_makeKey(&(skey->keyInstE), 
						     DIR_ENCRYPT, 
						     192, skey->session);
			  if (err_num < 0)
			    sh_error_handle((-1), FIL__, __LINE__, -1, 
					    MSG_E_SUBGEN,
					    errorExplain(err_num, expbuf, sizeof(expbuf)), 
					    _("xfer_try_report_int: makeKey"));
			  err_num = rijndael_makeKey(&(skey->keyInstD), 
						     DIR_DECRYPT, 
						     192, skey->session);
			  if (err_num < 0)
			    sh_error_handle((-1), FIL__, __LINE__, -1, 
					    MSG_E_SUBGEN,
					    errorExplain(err_num, expbuf, sizeof(expbuf)), 
					    _("xfer_try_report_int: makeKey"));
#endif
			  *initialized = S_TRUE;
			  noise();
			}
		    }
		  if (foo_Sc != NULL)
		    SH_FREE(foo_Sc);
		}
	    }
	  if (foo_A != NULL)
	    SH_FREE(foo_A);
	  sh_srp_exit();
	}
    }

  if (*initialized == S_FALSE)
    {
      xfer_timeout_val *= 2;
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_NOAUTH);
      memset(answer, '\0', 512);
      MUNLOCK(answer, 512);
      SH_FREE(answer);
      return -1;
    }
  else
    {
      if (flag_err_info == S_TRUE)
	sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_AUTH);
    }
  return 0;
}
#endif

int xfer_check_server_cmd(char * answer, char * buffer)
{
  int    flag_err;
  size_t pos;
  char   sigbuf[KEYBUF_SIZE];

  /* --- SERVER CMD --- */
  if (answer[KEY_LEN] != '\0' && 
      sl_strlen(answer) > (2*KEY_LEN))
    {
      pos = sl_strlen(answer) - (2*KEY_LEN);
      /*
       * buffer is  >= 256
       * answer has <= 255 bytes
       */
      (void) sl_strlcpy(buffer, &answer[KEY_LEN], 
			pos+1);
      flag_err = 
	sl_strncmp(&answer[KEY_LEN+pos],
		   sh_util_siggen(skey->session, 
				  buffer,
				  pos,
				  sigbuf, sizeof(sigbuf)),
		   KEY_LEN);
      
      TPT((0, FIL__, __LINE__, 
	   _("CONF RECV <%d> <%s>\n"),
	   flag_err, &answer[KEY_LEN]));
      
      if (flag_err != 0) {
	sh_error_handle((-1), FIL__, __LINE__, 
			flag_err,
			MSG_TCP_NOCONF);
      } 
#ifdef SH_WITH_CLIENT
      else {
	sh_socket_server_cmd(buffer);
      }
#endif
      flag_err = 0;
      
    } else {
    
    TPT((0, FIL__, __LINE__, 
	 _("CONF RECV <0> <[null]>\n")));
    
  }
  /* --- SERVER CMD END --- */
  return 0;
}



int xfer_send_message(char * errmsg, int sockfd, char * answer)
{
  char   hash[KEY_LEN+1];
  size_t len;
  char * buffer;
  char   nsrv[KEY_LEN+1];
  char   sigbuf[KEYBUF_SIZE];
  char   head_u[5];
  int    flag_err;

  SL_REQUIRE((sockfd > 2), _("sockfd > 2"));

  /* --- Save the challenge. ---  
   */
  (void) sl_strlcpy(nsrv, answer, KEY_LEN + 1);
  
  /* --- Hash(msg,challenge,sessionkey). ---  
   */
  len    = sl_strlen(errmsg) + sl_strlen(answer) 
    + KEY_LEN + 1;
  len = (size_t)((len < 256) ? 256 : len);
  buffer = SH_ALLOC(len);
  MLOCK(buffer, len);
  (void) sl_strlcpy(buffer, errmsg, len);
  (void) sl_strlcat(buffer, answer, len);
  (void) sl_strlcpy(hash, 
		    sh_util_siggen (skey->session, 
				    buffer, 
				    sl_strlen(buffer),
				    sigbuf, sizeof(sigbuf)), 
		    KEY_LEN+1);
  TPT((0, FIL__, __LINE__, _("msg=<sign %s.>\n"),
       sh_util_siggen(skey->session, buffer, 
		      sl_strlen(buffer), sigbuf, sizeof(sigbuf))));
  
  (void) sl_strlcpy(buffer, errmsg, len);
  (void) sl_strlcat(buffer, hash,   len);
  
  flag_err = 
    xfer_send_crypt (sockfd, 
#ifdef SH_ENCRYPT
		     (char)(SH_PROTO_MSG|SH_PROTO_ENC),
#else
		     (char)(SH_PROTO_MSG),
#endif
		     _("MESG"),
		     buffer, 
		     (unsigned long)(sl_strlen(buffer)+1));
  TPT(( 0, FIL__, __LINE__, 
	_("msg=<Sent %s, status %d.>\n"), 
	answer, flag_err));

  /* --- Get confirmation. ---
   */
  if (flag_err == 0)
    {
      flag_err = (int)
	xfer_receive_crypt (sockfd, 
#ifdef SH_ENCRYPT
			    (char)(SH_PROTO_MSG|SH_PROTO_ENC|SH_PROTO_END),
#else
			    (char)(SH_PROTO_MSG|SH_PROTO_END),
#endif
			    head_u, 
			    answer, 255);   
      TPT(( 0, FIL__, __LINE__, 
	    _("msg=<Rcvt %s, u %s, status %d.>\n"), 
	    answer, hu_trans(head_u), flag_err));
      flag_err = (flag_err < 0) ? flag_err : 0;
    }

  
  /* --- Check confirmation. ---
   */
  if (flag_err == 0)
    {
      /*   CLIENT CONF RECV
       * 
       *   first KEY_LEN bytes must be
       *   sig(skey->session (errmsg nsrv))
       *
       */
      (void) sl_strlcpy(buffer, errmsg, len);
      (void) sl_strlcat(buffer, nsrv,   len);
      flag_err = sl_strncmp(answer,
			    sh_util_siggen(skey->session, 
					   buffer,
					   sl_strlen(buffer),
					   sigbuf, sizeof(sigbuf)),
			    KEY_LEN);
      TPT((0, FIL__, __LINE__, _("msg=<sign %s.>\n"),
	   sh_util_siggen(skey->session, buffer, 
			  sl_strlen(buffer), sigbuf, sizeof(sigbuf))));
      
      if (flag_err != 0)
	{
#ifdef ENOMSG
	  flag_err = ENOMSG;
#else
	  flag_err = EIO;
#endif
	  sh_error_handle((-1), FIL__, __LINE__, flag_err,
			  MSG_TCP_NOCONF);
	}
      else
	{
#ifdef SH_ENCRYPT
	  flag_err = xfer_check_server_cmd(answer, buffer);
#endif
	  if (flag_err_debug == S_TRUE)
	    sh_error_handle((-1), FIL__, __LINE__, 0,
			    MSG_TCP_CONF);
	}
    }
  
  memset(buffer, 0, len);
  MUNLOCK(buffer, len);
  SH_FREE(buffer);

  if (flag_err != 0)
    return -1;
  return 0;
}


static SL_TICKET xfer_get_file(int sockfd, char * answer, 
			       char * nclt, char * foo_M1, const int theProto)
{
  /* --- Open a temporary file. ---
   */
  int flag_err = 0;
  SL_TICKET sfd;

  SL_REQUIRE((sockfd > 2), _("sockfd > 2"));

  if ( (sfd = open_tmp ()) < 0)
    {
      flag_err = (-1);
      sh_error_handle((-1), FIL__, __LINE__, flag_err, MSG_TCP_EFIL);
    }
  else
    {
      /* --- Read from socket into tmp file. ---
       */
      int    transfercount = 0;
      char   head_u[5];

      do {
	flag_err = (int)
	  xfer_receive_crypt (sockfd, 
#ifdef SH_ENCRYPT
			      (char)(SH_PROTO_BIG|SH_PROTO_ENC),
#else
			      (char)(SH_PROTO_BIG),
#endif
			      head_u, 
			      answer, 
			      TRANS_BYTES + 255);
	
	TPT(( 0, FIL__, __LINE__, 
	      _("msg=<Received: %d bytes, marked %s.>\n"),
	      flag_err, hu_trans(head_u)));

	if (flag_err > 0 && 0 == check_request_nerr(head_u, _("FILE")))
	  {
	    if (0 == hash_check (foo_M1, answer, flag_err))
	      {
		(void) sl_write(sfd, &answer[KEY_LEN], 
				flag_err-KEY_LEN);
		++transfercount;

		/*  Delay for throughput throttling
		 */
		if (sh_throttle_delay > 0)
		  retry_msleep(sh_throttle_delay/1000, sh_throttle_delay % 1000);

		flag_err = xfer_send_crypt (sockfd, theProto, 
					    _("RECV"),
					    nclt, 
					    (unsigned long)sl_strlen(nclt));
		
	      }
	    else
	      {
		TPT(( 0, FIL__, __LINE__, 
		      _("msg=<File transfer: Hash check failed.>\n")));
		break;
	      }
	  }
	else
	  {
	    TPT(( 0, FIL__, __LINE__, 
		  _("msg=<File transfer: No more data.>\n")));
	    break;
	  }
      } while (transfercount < 32000); /* 64 Mbyte */
      
      if (0 == check_request_nerr(head_u, _("EEOT")) &&
	  0 <  flag_err                              &&
	  0 == hash_check (foo_M1, answer, (int)sl_strlen(answer)))
	{
	  flag_err = xfer_send_crypt (sockfd, theProto, 
				      _("EOTE"),
				      nclt, 
				      (unsigned int) sl_strlen(nclt));
	  
	  (void) rewind_tmp (sfd);
	  (void) sl_sync(sfd);
	  if (flag_err_info == S_TRUE)
	    sh_error_handle((-1), FIL__, __LINE__, flag_err, MSG_TCP_FOK);
	}
      else
	{
	  (void) sl_close (sfd);
	  sfd = (-1);
	}
    }

  return sfd;
}

static  long xfer_try_report_int (char * errmsg, const int what)
{
  static int           initialized = S_FALSE;
  static int           conn_state  = S_TRUE;
  int                  sockfd;
  int                  flag_err = 0;
  char               * answer;
  int                  theProto = 0;

  UINT32 ticks;
  char   head_u[5];
  char * buffer;
  char   nsrv[KEY_LEN+1];
  char   nclt[KEY_LEN+1];
  char   foo_M1[KEY_LEN+1];

  char hashbuf[KEYBUF_SIZE];
  char sigbuf[KEYBUF_SIZE];

  SL_ENTER(_("xfer_try_report_int"));

  /* --- No message to transmit. ---
   */
  if (errmsg == NULL && initialized == S_TRUE)
    SL_RETURN( 0, _("xfer_try_report_int"));
  
  /* --- Connection in bad state. ---
   */
  if (xfer_conn_state(initialized, conn_state) < 0)
    SL_RETURN( (-1), _("xfer_try_report_int"));

  /* --- Try to connect to log server. ---
   */
  sockfd = xfer_connect(&conn_state);
  if (sockfd < 0)
    SL_RETURN( (-1), _("xfer_try_report_int"));
  

  /*************************
   *
   *  initialization
   * 
   */
  flag_err = 0;
  answer   = SH_ALLOC(512);
  MLOCK(answer, 512);

  if (initialized == S_FALSE)
    {
      if (xfer_auth(S_FALSE, &initialized, sockfd, answer) < 0)
	SL_RETURN( (-1), _("xfer_try_report_int"));
    }

 retry_send:

  /* no message, just session key negotiated
   */
  if (errmsg == NULL)
    {
      xfer_timeout_val = 1;
      memset(answer, 0, 512);
      MUNLOCK(answer, 512);
      SH_FREE(answer);
      TPT(( 0, FIL__, __LINE__, _("msg=<No message.>\n")));
      SL_RETURN( (0), _("xfer_try_report_int"));
    }
  else if (what == SH_PROTO_BIG)
    {
      MUNLOCK(answer, 512);
      SH_FREE (answer);
      answer   = SH_ALLOC(TRANS_BYTES + 256);
      MLOCK(answer, TRANS_BYTES + 256);
      TPT(( 0, FIL__, __LINE__, _("msg=<File transfer.>\n")));
    }

  sl_strlcpy (answer, 
	      sh_util_siggen(skey->session,
			     sh.host.name,
			     sl_strlen(sh.host.name),
			     sigbuf, sizeof(sigbuf)), 
	      KEY_LEN+1);

  TPT((0, FIL__, __LINE__, _("msg=<host %s>\n"), sh.host.name));
  TPT((0, FIL__, __LINE__, _("msg=<ckey %s>\n"), skey->session));
  TPT((0, FIL__, __LINE__, _("msg=<sign %s>\n"), answer));
    
  sl_strlcat (answer, sh.host.name, 512);

  TPT((0, FIL__, __LINE__, _("msg=<mesg %s>\n"), answer));

  /***********************************************
   *
   * send the message
   *
   */

  if (what == SH_PROTO_MSG)
    theProto = SH_PROTO_MSG;
  else if (what == SH_PROTO_BIG)
    theProto = SH_PROTO_BIG;

  /* --- Say HELO  ---       
   */
  flag_err = xfer_send    (sockfd, theProto, _("HELO"),
			   answer, sl_strlen(answer));
  TPT(( 0, FIL__, __LINE__, _("msg=<Sent %s, status %d.>\n"), 
	answer, flag_err));

  if (flag_err == 0)
    { 
      /* --- Get NSRV. ---  
       */
      flag_err = (int) xfer_receive (sockfd, theProto, head_u, answer, 255);
      TPT(( 0, FIL__, __LINE__, _("msg=<Rcvt %s, u %s, status %d.>\n"), 
	    answer, hu_trans(head_u), flag_err));
      flag_err = (flag_err < 0) ? flag_err : 0;
    }   

  if (what == SH_PROTO_MSG)
    {
      if (flag_err == 0)
	{
	  /* --- Re-negotiate key. ---
	   */
	  if (0 == check_request_nerr(head_u, _("INIT")))
	    {
	      flag_err    = 0;
	      initialized = S_FALSE;
	      if (xfer_auth(S_TRUE, &initialized, sockfd, answer) == 0)
		goto retry_send;
	    }
	  
	  else if (0 == check_request(head_u, _("TALK")))
	    {
	      flag_err = xfer_send_message(errmsg, sockfd, answer);
	    }

	  else
	    {
	      /* --- Unexpected reply from server. ---
	       */
	      sh_error_handle((-1), FIL__, __LINE__, 0,
			      MSG_TCP_UNEXP);
	      flag_err = (-1);
		
	    }
	}
    }


  else if (what == SH_PROTO_BIG)
    {
      if (flag_err == 0)
	{
	  
	  /* --- Re-negotiate key. ---
	   */
	  if (0 == check_request_nerr(head_u, _("INIT")))
	    {
	      flag_err    = 0;
	      initialized = BAD;
	      if (xfer_auth(S_TRUE, &initialized, sockfd, answer) == 0)
		goto retry_send;
	    }
	  
 
	  else if (0 == check_request(head_u, _("NSRV")))
	    {
	      size_t buffersize;
#ifdef SH_ENCRYPT
	      /* --- Set encryption flag. ---
	       */
	      theProto = (SH_PROTO_BIG|SH_PROTO_ENC);
#endif

	      (void) sl_strlcpy(nsrv, answer, KEY_LEN+1);
	      
	      /* --- Generate a nonce. ---
	       */
	      ticks = (UINT32) taus_get ();
              
	      (void) sl_strlcpy(nclt, 
				sh_tiger_hash((char *) &ticks, 
					      TIGER_DATA, 
					      (unsigned long)sizeof(UINT32), 
					      hashbuf, sizeof(hashbuf)),
				KEY_LEN+1);

	      /* --- Compute H(nsrv, nclt, skey). ---
	       */
	      buffer = sh_util_strconcat (nsrv, nclt, 
					  skey->session, NULL);
	      (void)sl_strlcpy(foo_M1, 
			       sh_tiger_hash(buffer, TIGER_DATA,
					     (unsigned long)sl_strlen(buffer), 
					     hashbuf, sizeof(hashbuf)),
			       KEY_LEN+1);
	      memset (buffer, 0, sl_strlen(buffer));
	      SH_FREE(buffer);

	      /* --- Send (nclt, msg) ---
	       */
	      if (S_TRUE == sl_ok_adds(strlen(errmsg), strlen(nclt)+2+KEY_LEN))
		{
		  buffersize = strlen(nclt)+strlen(errmsg)+2;
		  
#if !defined(SH_ENCRYPT)
		  buffersize += KEY_LEN;
#endif
		  buffer = SH_ALLOC(buffersize);

		  sl_strlcpy(buffer, nclt,   buffersize);
		  sl_strlcat(buffer, errmsg, buffersize);
		  
#if !defined(SH_ENCRYPT)
		  if (4 == sl_strlen(errmsg)) {  /* backward compatibility   */
		    buffersize = sl_strlen(buffer);
		    buffer[buffersize]   = theProto; /* nctl//DATA//theProto */
		    buffer[buffersize+1] = '\0';
		  }
		  sh_tools_hash_add(foo_M1, buffer, buffersize+1);
#endif
	      
		  flag_err = 
		    xfer_send_crypt (sockfd, (char) theProto, _("NCLT"),
				     buffer, 
				     (unsigned long) sl_strlen(buffer));
		  
		  TPT(( 0, FIL__, __LINE__, _("msg=<Sent %s, status %d.>\n"), 
			buffer, flag_err));
		  SH_FREE (buffer);
		}
	      else {
		flag_err = -1;
	      }
	    } 
	}

      if (flag_err == 0)
	{
	  /* --- Receive the file. ---
	   */
	  SL_TICKET sfd = xfer_get_file(sockfd, answer, nclt, foo_M1, theProto);
	  if (!SL_ISERROR(sfd))
	    {
	      (void) sl_close_fd (FIL__, __LINE__, sockfd);
	      memset(answer, 0, TRANS_BYTES + 256);
	      MUNLOCK(answer, TRANS_BYTES + 256);
	      SH_FREE(answer);
	      xfer_timeout_val = 1;

	      SL_RETURN( (sfd), _("xfer_try_report_int"));
	    }
	}

      (void) sl_close_fd (FIL__, __LINE__, sockfd);
      memset(answer, 0, TRANS_BYTES + 256);
      MUNLOCK(answer, TRANS_BYTES + 256);
      SH_FREE(answer);
      xfer_timeout_val *= 2;

      SL_RETURN( (-1), _("xfer_try_report_int"));
    }
 
  (void) sl_close_fd (FIL__, __LINE__, sockfd);
  memset(answer, 0, 512);
  MUNLOCK(answer, 512);
  SH_FREE(answer);

#ifndef EIO
#define EIO 5
#endif
  

#ifdef SH_ERROR_H  
  if (flag_err != 0)
    {
      char errbuf[SH_ERRBUF_SIZE];
      conn_state = S_FALSE;
      xfer_timeout_val *= 2;
      if (flag_err < 0 || NULL == sh_error_message(flag_err, errbuf, sizeof(errbuf)))
	flag_err = EIO;
      sh_error_handle((-1), FIL__, __LINE__, flag_err, MSG_TCP_ECONN,
		      sh_error_message(flag_err, errbuf, sizeof(errbuf)));
      SL_RETURN( (-1), _("xfer_try_report_int"));
    }
#endif
  xfer_timeout_val = 1;

  SL_RETURN( (0), _("xfer_try_report_int"));
}

/* #ifdef SH_WITH_CLIENT */
#endif




