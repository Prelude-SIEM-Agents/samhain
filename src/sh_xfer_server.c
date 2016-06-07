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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

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

/*
#ifdef TM_IN_SYS_TIME
#include <sys/time.h>
#else
#include <time.h>
#endif
*/

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
#include "sh_guid.h"

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
#define FIL__  _("sh_xfer_server.c")

int     clt_class = (-1);

extern int flag_err_debug;
extern int flag_err_info;


#if defined (SH_WITH_SERVER)

#if defined(WITH_TRACE) || defined(WITH_TPT) 
extern char * hu_trans(const char * ihu);
#endif
extern unsigned int ServerPort;
#if !defined(USE_SRP_PROTOCOL)
extern void sh_passwd (char * salt, char * password, char * nounce, char *hash);
#endif

static int StripDomain = S_TRUE;

int sh_xfer_set_strip (const char * str)
{
  static int fromcl = 0;

  if (fromcl == 1)
    return 0;
  else
    return (sh_util_flagval(str, &StripDomain));
}

static char * sh_strip_domain (char *name)
{
  char * out = NULL;

  SL_ENTER(_("sh_strip_domain"));

  if (StripDomain == S_FALSE || strchr(name, '.') == NULL) 
    {
      out = sh_util_strdup(name);
      SL_RETURN( out, _("sh_strip_domain"));
    }
  else
    {
      /* check whether it is in dotted number format
       * --> last part must be kept
       */
      if (0 != sh_ipvx_is_numeric(name))
	{
	  out = sh_util_strdup(name);
	  SL_RETURN( out, _("sh_strip_domain"));
	}
      else
	{
	  char * p;
	  out = sh_util_strdup(name);
	  p   = strchr(out, '.');
	  if (p) *p = '\0';
	  SL_RETURN( out, _("sh_strip_domain"));
	}
    }

  SL_RETURN( out, _("sh_strip_domain"));
}

#ifndef USE_SRP_PROTOCOL

int sh_xfer_make_client (const char * str)
{
  /* char *          safer; */
  char            key[KEY_LEN+1];
  unsigned char   in[PW_LEN+1];
  int    i = 0, j, k, l = 0;
  char hashbuf[KEYBUF_SIZE];
  
  if (sl_strlen(str) != (PW_LEN * 2)) 
    {
      fprintf(stderr, 
	      _("Input must be a %d digit hexadecimal number"\
		" (only 0-9, a-f, A-F allowed in input)\n"),
	      (PW_LEN * 2));
      _exit(EXIT_FAILURE);
    }
  
  while (i < (PW_LEN * 2))
    {
      k = sh_util_hexchar(str[i]); j = sh_util_hexchar(str[i+1]); 
      if (k != -1 && j != -1) 
        {
          in[l] = (k * 16 + j);
          ++l; i+= 2;
        }
      else
        {
          fprintf(stderr, _("Invalid char %c\n"), str[i]);
          _exit(EXIT_FAILURE);
        }
    }
  in[PW_LEN] = '\0';

  sl_strlcpy ((char *)key, 
	      sh_tiger_hash ((char*)in, TIGER_DATA, PW_LEN, 
			     hashbuf, sizeof(hashbuf)), 
	      KEY_LEN+1);
  key[KEY_LEN] = '\0';
  
  fprintf(stdout, _("Client entry: Client=HOSTNAME@00000000@%s\n"), 
	  key);
  fflush(stdout);

  _exit(EXIT_SUCCESS);
  return 0;
}

#else

int sh_xfer_make_client (const char * str)
{
  char * foo_v;

  char   salt[17];
  char   key[KEY_LEN+1];
  char   in[PW_LEN];
  int    i = 0, j, k, l = 0;
  char hashbuf[KEYBUF_SIZE];
  
  if (sl_strlen(str) != (PW_LEN*2)) 
    {
      fprintf(stderr, 
	      _("Input must be a %d digit hexadecimal number"\
		" (only 0-9, a-f, A-F allowed in input)\n"),
	      (PW_LEN*2));
      _exit(EXIT_FAILURE);
    }

    while (i < (PW_LEN*2))
      {
        k = sh_util_hexchar(str[i]); j = sh_util_hexchar(str[i+1]); 
        if (k != -1 && j != -1) 
          {
            in[l] = (k * 16 + j);
            ++l; i+= 2;
          }
        else
          {
            fprintf(stderr, _("Invalid char %c\n"), str[i]);
            _exit(EXIT_FAILURE);
          }
      }
    
  
    if (0 == sh_srp_init())
      {
	sh_util_keyinit(key, KEY_LEN);
	sl_strlcpy(salt, sh_tiger_hash(key, TIGER_DATA, KEY_LEN, 
				       hashbuf, sizeof(hashbuf)), 
		   17); 
	sh_srp_x (salt, in);
	foo_v  = sh_srp_verifier ();
	fprintf(stdout, _("Client=HOSTNAME@%s@%s\n"), 
		salt, foo_v);
	fflush(stdout);
	SH_FREE(foo_v);
	sh_srp_exit();
	_exit(EXIT_SUCCESS);
      }
    fprintf(stdout, "%s",_("ERROR initializing BigNum library.\n"));
    fflush (stdout);
    _exit(EXIT_FAILURE);
    return -1;
}
#endif


int sh_xfer_create_password (const char * dummy)
{
  UINT32   val[2]; 
  char     output[KEY_LEN+1];
  char hashbuf[KEYBUF_SIZE];

  val[0] = taus_get ();
  val[1] = taus_get ();

  sl_strlcpy (output, 
	      sh_tiger_hash((char *)(&val[0]), TIGER_DATA, 2*sizeof(UINT32),
			    hashbuf, sizeof(hashbuf)),
	      KEY_LEN);

  output[16] = '\0';

  fprintf(stdout, _("%s\n"), output);
  fflush (stdout);

  if (dummy)
    _exit(EXIT_SUCCESS);
  else
    _exit(EXIT_SUCCESS);  
  return (0);  /* avoid compiler warning */
}

/* #if defined (SH_WITH_SERVER) */
#endif

/**************************************************
 *
 *
 *  S E R V E R   
 *
 *
 ***************************************************/

#ifdef SH_WITH_SERVER

#include "sh_readconf.h"


#define CONN_FREE    0
#define CONN_READING 1
#define CONN_SENDING 2
#define CONN_PAUSE   3
#define CONN_BUSY    4

char * clt_stat[] = {
  N_("Inactive"),
  N_("Started"),
  N_("ILLEGAL"),
  N_("FAILED"),
  N_("Exited"),
  N_("PANIC"),
  N_("POLICY"),
  N_("File_transfer"),
  N_("Message"),
  N_("TIMEOUT_EXCEEDED"),
  N_("Suspended"),
  N_("Filecheck"),
};

#include <time.h>

/* in sh_html.h:
 *  typedef struct client_entry {
 *  } client_t;
 */

#include "zAVLTree.h"

static char * sh_tolower (char * s)
{
  char * ret = s;
  if (s)
    {
      for (; *s; ++s)
	{ 
	  *s = tolower((unsigned char) *s);
	}
    }
  return ret;
}

/* Function to return the key for indexing
 * the argument 
 */
zAVLKey sh_avl_key (void const * arg)
{
  const client_t * sa = (const client_t *) arg;
  return (zAVLKey) sa->hostname;
}

zAVLTree * all_clients = NULL;

void sh_xfer_html_write()
{
  SL_ENTER(_("sh_xfer_html_write"));
  sh_html_write(all_clients);
  SL_RET0(_("sh_xfer_html_write"));
}


int sh_xfer_use_clt_class (const char * c)
{
  int i;
  SL_ENTER(_("sh_xfer_use_clt_class"));
  i = sh_util_flagval(c, &(sh.flag.client_class));
  SL_RETURN(i, _("sh_xfer_use_clt_class"));
}

int sh_xfer_use_clt_sev (const char * c)
{
  int i;
  SL_ENTER(_("sh_xfer_use_clt_sev"));
  i = sh_util_flagval(c, &(sh.flag.client_severity));
  SL_RETURN(i, _("sh_xfer_use_clt_sev"));  
}


/* the destructor
 */
void free_client(void * inptr)
{
  client_t * here;

  SL_ENTER(_("free_client"));
  if (inptr == NULL)
    SL_RET0(_("free_client"));
  else
    here = (client_t *) inptr;

  if (here->hostname != NULL)
    SH_FREE(here->hostname);
  if (here->salt != NULL)
    SH_FREE(here->salt);
  if (here->verifier != NULL)
    SH_FREE(here->verifier);
  SH_FREE(here);
  SL_RET0(_("free_client"));
}


int sh_xfer_register_client (const char * str)
{
  client_t   * newclt;
  client_t   * testclt;

  const char * ptr;
  int          sepnum = 0;
  int          sep[2];
  register int i = 0;
  int          siz_str = 0;

  SL_ENTER(_("sh_xfer_register_client"));

  ptr = str; 
  while (*ptr) {
    if (*ptr == '@' && sepnum < 2 ) 
      { 
	sep[sepnum] = i;
	++sepnum;
      } 
    ++ptr; ++i; 
  }

  if (all_clients == NULL)
    {
      all_clients = zAVLAllocTree (sh_avl_key, zAVL_KEY_STRING);
      if (all_clients == NULL) 
	{
	  (void) safe_logger (0, 0, NULL);
	  aud__exit(FIL__, __LINE__, EXIT_FAILURE);
	}
    }
  
  if ((sepnum == 2) && (sep[0] > 0) && (sep[1] > sep[0]))
    {
      newclt = SH_ALLOC (sizeof(client_t));
      newclt->hostname = SH_ALLOC (sep[0]+1);
      newclt->salt     = SH_ALLOC (sep[1]-sep[0]);
      newclt->verifier = SH_ALLOC (sl_strlen(str)-sep[1]+1);
      newclt->exit_flag         = 0;
      newclt->dead_flag         = 0;
#ifdef SH_ENCRYPT
      newclt->encf_flag         = SH_PROTO_ENC;
      newclt->ency_flag         = SH_PROTO_ENC;
#else
      newclt->encf_flag         = 0;
      newclt->ency_flag         = 0;
#endif
      newclt->ivst_flag         = 0;
      newclt->session_key[0]    = '\0';
      newclt->last_connect      = (time_t) 0;
      newclt->session_key_timer = (time_t) 0;
      newclt->status_now        = CLT_INACTIVE;
      for (i = 0; i < CLT_MAX; ++i) 
	newclt->status_arr[i] = CLT_INACTIVE;
      (void) sh_unix_time(0, newclt->timestamp[CLT_INACTIVE], TIM_MAX);

      /* truncate */
      sl_strlcpy(newclt->hostname,  &str[0],        sep[0]+1);
      sh_tolower(newclt->hostname);

      /* truncate */
      sl_strlcpy(newclt->salt,      &str[sep[0]+1], sep[1]-sep[0]);
      sl_strlcpy(newclt->verifier,  &str[sep[1]+1], sl_strlen(str)-sep[1]+1);

      testclt = (client_t *) zAVLSearch (all_clients, newclt->hostname);

      if (testclt != NULL)
	{
	  SH_FREE(testclt->verifier);
	  siz_str = strlen (newclt->verifier) + 1;
	  testclt->verifier = SH_ALLOC (siz_str);
	  sl_strlcpy(testclt->verifier, newclt->verifier, siz_str);

	  SH_FREE(testclt->salt);
	  siz_str = strlen (newclt->salt) + 1;
	  testclt->salt = SH_ALLOC (siz_str);
	  sl_strlcpy(testclt->salt, newclt->salt, siz_str);

	  testclt->dead_flag = 0;
	      
	  free_client(newclt);
	  SL_RETURN( 0, _("sh_xfer_register_client"));
	}
      else
	{
	  if (0 == zAVLInsert (all_clients, newclt))
	    {
	      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_CREG,
			      newclt->hostname, 
			      newclt->salt, newclt->verifier);
	      SL_RETURN( 0, _("sh_xfer_register_client"));
	    }
	}
    }
  SL_RETURN (-1, _("sh_xfer_register_client"));
}

typedef struct {
  int             state;
  int             fd;
  char          * buf;
  unsigned char   head[SH_HEADER_SIZE];
  char            challenge[SH_CHALLENGE_SIZE];
  char            peer[SH_MINIBUF+1];
  client_t      * client_entry;
  char          * K;
  char          * M1;
  char          * A;
  int             headcount;
  unsigned long   bytecount;
  unsigned long   bytes_to_send;
  unsigned long   bytes_to_get;
  int             pass;
  unsigned long   timer;

  char          * FileName;
  unsigned long   FileLength;
  unsigned long   FileSent;
  char            FileType[5];

  struct sh_sockaddr addr_peer;
} sh_conn_t;


static char zap_challenge[SH_CHALLENGE_SIZE] = { 0 };
 
void sh_xfer_do_free (sh_conn_t * conn)
{
  SL_ENTER(_("sh_xfer_do_free"));

  if (conn->K != NULL) 
    {
      SH_FREE(conn->K);
      conn->K           = NULL;
    }
  if (conn->A != NULL) 
    {
      SH_FREE(conn->A);
      conn->A           = NULL;
    }
  if (conn->M1 != NULL) 
    {
      SH_FREE(conn->M1);
      conn->M1           = NULL;
    }
  if (conn->buf != NULL) 
    {
      SH_FREE(conn->buf);
      conn->buf          = NULL;
    }
  if (conn->fd != (-1))
    {
      sl_close_fd (FIL__, __LINE__, conn->fd);
      conn->fd            = -1;
    }
  memcpy(conn->challenge, zap_challenge, SH_CHALLENGE_SIZE);
  conn->state         = CONN_FREE;
  conn->headcount     = 0;
  conn->bytecount     = 0;
  conn->bytes_to_send = 0;
  conn->bytes_to_get  = 0;
  conn->pass          = 0;
  conn->timer         = 0;
  conn->client_entry  = NULL;

  if (conn->FileName != NULL) 
    {
      SH_FREE(conn->FileName);
      conn->FileName     = NULL;
    }
  conn->FileLength     = 0;
  conn->FileSent       = 0;
  conn->FileType[0] = '\0';
  conn->FileType[1] = '\0';
  conn->FileType[2] = '\0';
  conn->FileType[3] = '\0';
  conn->FileType[4] = '\0';

  --server_status.conn_open;
  
  SL_RET0(_("sh_xfer_do_free"));
}

/****************************************
 *
 *   -- Reconfiguration. --
 *
 *   (1) Mark all clients as 'dead'.
 *   (2) Reload configuration - clients
 *       in config are non-dead now.
 *   (3) Remove all clients still
 *       marked as 'dead'.
 */

/* -- Mark all clients as dead.
 */
void sh_xfer_mark_dead (void)
{
  zAVLCursor avlcursor;
  client_t * item;

  SL_ENTER(_("sh_xfer_mark_dead"));

  for (item = (client_t *) zAVLFirst(&avlcursor, all_clients); item;
       item = (client_t *) zAVLNext(&avlcursor))
    {
      item->dead_flag = 1;
    }
  SL_RET0(_("sh_xfer_mark_dead"));
}


/* -- Clean tree from dead clients.
 */
void sh_xfer_clean_tree (void)
{
  zAVLCursor avlcursor;
  client_t * item;

  SL_ENTER(_("sh_xfer_clean_tree"));

 repeat_search:

  for (item = (client_t *) zAVLFirst(&avlcursor, all_clients); item;
       item = (client_t *) zAVLNext(&avlcursor))
    {
      if (item->dead_flag == 1)
	{
	  zAVLDelete (all_clients, item->hostname);
	  free_client (item);
	  goto repeat_search;
	}
    }
  SL_RET0(_("sh_xfer_clean_tree"));
}

/*
 *
 **********************************************/



/* -- SERVER SEND FUNCTION. --
 */
void sh_xfer_prep_send_int (sh_conn_t * conn, 
			    char * msg, unsigned long length,
			    char * u, char protocol,
			    int docrypt)
{
  /* register unsigned long i; */
  unsigned long           length2;

#if !defined(SH_ENCRYPT)
  (void) docrypt;
#endif

  SL_ENTER(_("sh_xfer_prep_send_int"));

  TPT((0, FIL__, __LINE__, _("msg=<%s>, docrypt=<%d>\n"), msg, docrypt ));

  length2 = length;

  conn->headcount     = 0;
  conn->bytecount     = 0;
  conn->bytes_to_send = 0;
  conn->bytes_to_get  = 0;

  if (conn->buf != NULL) 
    {
      SH_FREE(conn->buf);
      conn->buf           = NULL;
    }

  put_header (conn->head, protocol, &length2, u);
  SH_SHOWPROT(conn->head,'>');

  TPT((0, FIL__, __LINE__, _("msg=<put_header done>\n") ));

  if (msg == NULL) 
    length2 = 0;
  
#ifdef SH_ENCRYPT
  if      ((S_TRUE == docrypt) && ((protocol & SH_PROTO_ENC) != 0))
    {
      TPT((0, FIL__, __LINE__, _("encrypting (version 2)\n")));
      
      conn->buf = sh_tools_makePack (conn->head, conn->client_entry->ivst_flag,
				     msg, length2,
				     &(conn->client_entry->keyInstE));
    }
  else if (msg == NULL)
    {
      sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
		      _("msg is NULL"), 
		      _("sh_xfer_prep_send_int: cipherInit"));
    }
  else
    {
      if ((length2 + 1) < length2) --length2;
      conn->buf       = SH_ALLOC(length2 + 1);

      memcpy(conn->buf, msg, length2);
      conn->buf[length2] = '\0';
      TPT((0, FIL__, __LINE__, _("msg=<no encryption done>\n") ));
    }
#else
  if ((length2 + 1) < length2) --length2;
  conn->buf       = SH_ALLOC(length2 + 1);

  memcpy(conn->buf, msg, length2);
  conn->buf[length2] = '\0';
  TPT((0, FIL__, __LINE__, _("msg=<no encryption done>\n") ));
#endif

  conn->state     = CONN_SENDING;
  SL_RET0(_("sh_xfer_prep_send_int"));
}

/* -- Send/Receive. --
 */
void sh_xfer_prep_send (sh_conn_t * conn, 
			   char * msg, unsigned long length,
			   char * u, char protocol)
{
  SL_ENTER(_("sh_xfer_prep_send"));
  sh_xfer_prep_send_int (conn,  msg, length, u, protocol, S_FALSE);
  SL_RET0(_("sh_xfer_prep_send"));
}  

void sh_xfer_send_crypt (sh_conn_t * conn, 
				 char * msg, unsigned long length,
				 char * u, char protocol)
{
  SL_ENTER(_("sh_xfer_send_crypt"));
  sh_xfer_prep_send_int (conn,  msg, length, u, protocol, S_TRUE);
  SL_RET0(_("sh_xfer_send_crypt"));
}  

/* #include <sys/times.h> */

#if defined(WITH_EXTERNAL)
#include "sh_extern.h"
#endif

/* -- Update the client status. --
 *
 * Update the status array for the client,
 * and eventually call external program.
 */
static void status_update (client_t * conn, int status)
{ 
#if defined(WITH_EXTERNAL)
  char msg[2 * SH_MINIBUF + TIM_MAX + 3];
#endif

  SL_ENTER(_("status_update"));

  if (conn == NULL || 
      status < 0   || status >= CLT_MAX)
    SL_RET0(_("status_update"));

  conn->status_now = status;
  conn->status_arr[status] = status;
  (void) sh_unix_time(0, conn->timestamp[status], TIM_MAX);

#if defined(WITH_EXTERNAL)
  sl_snprintf(msg, sizeof(msg), _("%s %s %s"),
	      conn->hostname, conn->timestamp[status], _(clt_stat[status]));
  sh_ext_execute('s', 'r', 'v', msg, 0);
#endif

  SL_RET0(_("status_update"));
}

static time_t time_client_limit = 86400;

int sh_xfer_set_time_limit (const char * c)
{
  long val;

  SL_ENTER(_("sh_xfer_set_time_limit"));

  val = strtol (c, (char **)NULL, 10);
  if (val <= 0)
    SL_RETURN( (-1), _("sh_xfer_set_time_limit"));

  time_client_limit = (time_t) val;
  SL_RETURN( (0), _("sh_xfer_set_time_limit"));
}


/* -- Check for time limit exceeded. --
 */
static int client_time_check(void)
{
  zAVLCursor avlcursor;
  client_t * item;

  SL_ENTER(_("client_time_check"));

  if (time_client_limit == (time_t) 0)
    SL_RETURN( 0, _("client_time_check"));

  for (item = (client_t *) zAVLFirst(&avlcursor, all_clients); item;
       item = (client_t *) zAVLNext(&avlcursor))
    {
      if (item->exit_flag == 0 && item->last_connect != (time_t) 0)
	{
	  if ( (time(NULL) - item->last_connect) > time_client_limit)
	    {
	      if (item->status_now != CLT_TOOLONG)
		{
		  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_TIMEXC,
				  item->hostname);
		  status_update (item, CLT_TOOLONG);
		}
	    }
	}
    }
  SL_RETURN( 0, _("client_time_check"));
}

static int lookup_err = SH_ERR_SEVERE;

int sh_xfer_lookup_level (const char * c)
{
  int ci =  sh_error_convert_level (c);

  SL_ENTER(_("sh_xfer_lookup_level"));

  if (ci >= 0)
    {
      lookup_err = ci;
      SL_RETURN( 0, _("sh_xfer_lookup_level"));
    }
  else
    SL_RETURN( (-1), _("sh_xfer_lookup_level"));
}

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN  127
#endif

int check_addr (const char * claim, struct sh_sockaddr * addr_peer)
{
  char               h_name[MAXHOSTNAMELEN + 1];
  char               h_peer[MAXHOSTNAMELEN + 1];
  char               h_peer_IP[SH_IP_BUF];
  char               tmp_peer_IP[SH_IP_BUF];
  char             * canonical;
  char               numeric[SH_IP_BUF];

  SL_ENTER(_("check_addr"));

  if (claim == NULL)
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      _("NULL input"), _("check_addr"));
      SL_RETURN ((-1), _("check_addr"));
    }

  /* Make sure we have the canonical name for the client
   */
  canonical = sh_ipvx_canonical(claim, numeric, sizeof(numeric));

  /* copy canonical name into h_name
   */
  if (canonical != NULL)
    {
      sl_strlcpy(h_name, canonical, MAXHOSTNAMELEN + 1);
      SH_FREE(canonical);
    }
  else
    {
      sh_error_handle(lookup_err, FIL__, __LINE__, 0, MSG_TCP_RESCLT,
		      claim);
      SL_RETURN ((0), _("check_addr"));
    }


  /* get canonical name of socket peer
   */
  canonical = sh_ipvx_addrtoname(addr_peer);

  if (canonical)
    {
      if (0 == sl_strcmp(canonical, _("localhost")))
	sl_strlcpy(h_peer, sh.host.name, MAXHOSTNAMELEN + 1);
      else
	sl_strlcpy(h_peer, canonical, MAXHOSTNAMELEN + 1);
      SH_FREE(canonical);
    }
  else
    {
      sh_ipvx_ntoa (tmp_peer_IP, sizeof(tmp_peer_IP), addr_peer);
      sh_error_handle(lookup_err, FIL__, __LINE__, 0, MSG_TCP_RESPEER,
		      claim, tmp_peer_IP);
      SL_RETURN ((0), _("check_addr"));
    }

  sh_ipvx_ntoa (h_peer_IP, sizeof(h_peer_IP), addr_peer);

  /* reverse lookup
   */
  if (0 == sh_ipvx_reverse_check_ok (h_peer, ServerPort, addr_peer))
    {
      sh_ipvx_ntoa (tmp_peer_IP, sizeof(tmp_peer_IP), addr_peer);

      sh_error_handle(lookup_err, FIL__, __LINE__, 0, MSG_TCP_LOOKERS,
		      claim, h_peer, tmp_peer_IP);
      SL_RETURN ((0), _("check_addr"));
    }

  /* Check whether claim and peer are identical
   */
  sh_tolower(h_peer); /* Canonical name of what the peer is     */
  sh_tolower(h_name); /* Canonical name of what the peer claims */

  if ((0 == sl_strcmp(h_peer, h_name)) || (0 == sl_strcmp(h_peer_IP, h_name)))
    {
      SL_RETURN ((0), _("check_addr"));
    }
#if !defined(USE_IPVX)
  else
    {
      struct hostent   * he = sh_gethostbyname(h_peer);
      int                i = 0;
      int                flag = 0;

      while (he->h_aliases[i] != NULL)
	{
	  if (0 == sl_strcmp(sh_tolower(he->h_aliases[i]), h_name))
	    {
	      flag = 1;
	      break;
	    }
	  ++i;
	}
      if (flag == 0) 
	sh_error_handle(lookup_err, FIL__, __LINE__, 0, MSG_TCP_LOOKUP,
			claim, h_peer);
    }
#endif

  SL_RETURN ((0), _("check_addr"));
}

static int UseSocketPeer = S_FALSE;

int set_socket_peer (const char * c)
{
  return sh_util_flagval(c, &UseSocketPeer);
}


/* -- Search register. --
 */
client_t * search_register(sh_conn_t * conn, int pos)
{
  client_t * this_client;
  char       peer_ip[SH_IP_BUF];
  char       numerical[SH_IP_BUF];
  char       peer_name[MAXHOSTNAMELEN+1];
  char     * search_string;

  struct sh_sockaddr peer_addr;
  char             * canonical;

  SL_ENTER(_("search_register"));

  if (UseSocketPeer == S_TRUE)
    {
      memcpy(&peer_addr, &(conn->addr_peer), sizeof(struct sh_sockaddr));
      sh_ipvx_ntoa (peer_ip, sizeof(peer_ip), &peer_addr);

      /* get canonical name of socket peer
       */
      canonical = sh_ipvx_canonical(peer_ip, numerical, sizeof(numerical));

      if (canonical != NULL)
	{
	  if (0 == sl_strcmp(canonical, _("localhost")))
	    sl_strlcpy(peer_name, sh.host.name, MAXHOSTNAMELEN + 1);
	  else
	    sl_strlcpy(peer_name, canonical,    MAXHOSTNAMELEN + 1);
	  SH_FREE(canonical);
	}

      if (0 == sh_ipvx_reverse_check_ok (peer_name, ServerPort, &peer_addr))
	{
	  sl_strlcpy(peer_name, peer_ip, MAXHOSTNAMELEN + 1);
	}

      search_string = peer_name;
    }
  else
    {
      search_string = &(conn->buf[pos]);

      if (0 != check_addr (search_string, &(conn->addr_peer)))
	{
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_BADCONN,
			  _("Reverse lookup failed"), search_string);
	  sh_xfer_do_free (conn);
	  SL_RETURN( NULL, _("search_register"));
	} 
    }

  sh_tolower(search_string);

  /* ----  search the register  -----
   */
  this_client = zAVLSearch(all_clients, search_string);

  if (this_client == NULL)
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_BADCONN,
		      _("Not in client list"), search_string);
      sh_xfer_do_free (conn);
      SL_RETURN( NULL, _("search_register"));
    } 
  if (this_client->exit_flag == 1)
    {
      TPT((0, FIL__, __LINE__, _("msg=<this_client->exit_flag == 1>\n")));
      this_client->session_key_timer = (time_t) 0;
      this_client->session_key[0]    = '\0';
      this_client->exit_flag         = 0;    
    }
  TPT((0, FIL__, __LINE__, _("msg=<search_register: client %s>\n"), 
       this_client->hostname));
  TPT((0, FIL__, __LINE__, _("msg=<search_register: key %s>\n"), 
       this_client->session_key));
  SL_RETURN( this_client, _("search_register"));
}  

client_t * do_check_client(sh_conn_t * conn, int * retval)
{
  client_t * this_client = NULL; 
  char sigbuf[KEYBUF_SIZE];
  
  *retval = 0;

  TPT(( 0, FIL__, __LINE__, _("msg=<Client connect - HELO (1).>\n")));
	  
  if (conn->buf == NULL || sl_strlen(conn->buf) <= KEY_LEN)
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_NOCLT);
      sh_xfer_do_free (conn);
      return NULL;
    } 
	  
  /* ----  search the register  -----
   */
  
  this_client = search_register (conn, KEY_LEN);
  if (this_client == NULL)
    return NULL;
  
  /* ---- force authentication -----
   */
  
  if (this_client->session_key[0] == '\0' ||
      (time(NULL) - this_client->session_key_timer) 
      > (time_t) TIMEOUT_KEY )
    {
      size_t len;

      /* fake an auth request and jump there
       */
      conn->head[0]  = (conn->head[0] | SH_PROTO_SRP);
      conn->head[3]  = 'S';
      conn->head[4]  = 'A';
      conn->head[5]  = 'L';
      conn->head[6]  = 'T';
      if (flag_err_info == S_TRUE)
	sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_FAUTH,
			&(conn->buf[KEY_LEN]));
      len = sl_strlen(&(conn->buf[KEY_LEN])) + 1;
      /* may overlap, thus only memmove is correct */
      memmove(conn->buf, &(conn->buf[KEY_LEN]), len); 
      this_client->session_key[0]    = '\0';
      this_client->session_key_timer = (time_t) 1;
      *retval = -1;
      return NULL;
    }

  /* --- check whether hostname is properly signed ---
   */ 
  if (conn->K != NULL) 
    {
      SH_FREE(conn->K);
      conn->K = NULL;
    }
  
  conn->K = SH_ALLOC(KEY_LEN+1);
  
  sl_strlcpy (conn->K, 
	      sh_util_siggen(this_client->session_key,
			     &(conn->buf[KEY_LEN]),
			     sl_strlen(&(conn->buf[KEY_LEN])),
			     sigbuf, sizeof(sigbuf)),
	      KEY_LEN+1);
  
  if (0 != sl_strncmp(conn->K, conn->buf, KEY_LEN))
    {
      TPT((0, FIL__, __LINE__, _("msg=<clt %s>\n"), conn->buf));
      TPT((0, FIL__, __LINE__, _("msg=<srv %s>\n"), conn->K));
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_BADCONN,
		      _("Signature mismatch"), 
		      &(conn->buf[KEY_LEN]));
      
      this_client->session_key_timer =
	time(NULL) - (2*TIMEOUT_KEY);
      
      sh_xfer_do_free (conn);
      return NULL;
    }
  SH_FREE(conn->K); 
  conn->K = NULL;

  return this_client;
}

/* ------------------------------------------------------
 *
 *  FILE TRANSFER
 *
 * ------------------------------------------------------ */

static void do_file_send_data(sh_conn_t * conn)
{
  char     * read_buf = 0;
  char     * send_buf;
  int        bytes;
  SL_TICKET  sfd = -1;
#ifdef SH_ENCRYPT
  int        blkfac;
  int        rem;
  int        send_bytes;
#endif

  if (conn == NULL    || conn->FileName == NULL)
    {
      sh_error_handle((-1), FIL__, __LINE__, sfd, MSG_TCP_NFILE,
                      conn->peer, 
                      (conn->FileName == NULL) ? 
                      _("(NULL)") : conn->FileName);
      status_update (conn->client_entry, CLT_FAILED);
      sh_xfer_do_free (conn);
      return;
    }

  if (conn->FileSent == conn->FileLength)
    {
      send_buf = hash_me(conn->K, conn->peer, sl_strlen(conn->peer));
#ifdef SH_ENCRYPT
      sh_xfer_send_crypt (conn, send_buf, sl_strlen(conn->peer)+KEY_LEN, 
				  _("EEOT"), SH_PROTO_BIG|conn->client_entry->encf_flag);
#else
      sh_xfer_send_crypt (conn, send_buf, sl_strlen(conn->peer)+KEY_LEN, 
				  _("EEOT"), SH_PROTO_BIG);
#endif
      SH_FREE(send_buf);
    }
  else
    {
      bytes = -1;

      sfd = sl_open_read(FIL__, __LINE__, conn->FileName, SL_YESPRIV);

      if (!SL_ISERROR(sfd))
	{
	  read_buf = SH_ALLOC(TRANS_BYTES);
	  if (conn->FileSent > 0)
	    sl_seek (sfd, (off_t) conn->FileSent);
	  bytes = sl_read (sfd, read_buf, TRANS_BYTES);
	  sl_close(sfd);
	}
      else
	{
	  sh_error_handle((-1), FIL__, __LINE__, sfd, 
			  MSG_E_ACCESS, (long) geteuid(), conn->FileName);
	}

      if (bytes >= 0)
	{
#ifdef SH_ENCRYPT
	  /* need to send N * B_SIZ bytes
	   */ 
	  blkfac = bytes / B_SIZ;
	  rem    = bytes - (blkfac * B_SIZ);
	  if (rem != 0)
	    {
	      memset(&read_buf[bytes], '\n', (B_SIZ-rem));
	      ++blkfac;
	      send_bytes = blkfac * B_SIZ;
	    }
	  else
	    send_bytes = bytes;
	  
	  send_buf = hash_me(conn->K, read_buf,  send_bytes);
	  
	  sh_xfer_send_crypt (conn, send_buf, send_bytes+KEY_LEN, _("FILE"),  
				      SH_PROTO_BIG|conn->client_entry->encf_flag);
#else
	  send_buf = hash_me(conn->K, read_buf, bytes);
	  sh_xfer_send_crypt (conn, send_buf, bytes+KEY_LEN, _("FILE"),  
				      SH_PROTO_BIG);
#endif
	  conn->FileSent += bytes;
	  if (send_buf) /* hash_me() *may* return NULL */
	    SH_FREE(send_buf);
	  SH_FREE(read_buf);
	}
      else
	{
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_NFILE, conn->peer,
			  (conn->FileName == NULL) ? _("(NULL)") : conn->FileName);
	  status_update (conn->client_entry, CLT_FAILED);
	  sh_xfer_do_free (conn);
	}
    }
  return;
}

static void do_file_initial(sh_conn_t * conn)
{
  char     * ptok;
  char       hashbuf[KEYBUF_SIZE];

  /* --- get client nonce and compute hash ---
   *
   *  K = H(NSRV, NCLT, session_key) 
   */ 
  if (conn->A != NULL)
    {
      SH_FREE(conn->A);
      conn->A = NULL;
    }
  conn->A = SH_ALLOC(3*KEY_LEN+1);
  sl_strlcpy (conn->A, conn->K, KEY_LEN+1); 
  sl_strlcat(conn->A, conn->buf, /* truncate */
	     2*KEY_LEN+1);
  sl_strlcat(conn->A, conn->client_entry->session_key, 
	     3*KEY_LEN+1);
  sl_strlcpy (conn->K, sh_tiger_hash(conn->A,TIGER_DATA,3*KEY_LEN,
				     hashbuf, sizeof(hashbuf)),
	      KEY_LEN+1);
  SH_FREE(conn->A); 
  conn->A = NULL;
  

  /* Warn about encryption mismatch
   */
#ifdef SH_ENCRYPT
  if ((conn->client_entry->encf_flag != 0) &&  /* server */
      ((conn->head[0] & SH_PROTO_ENC) == 0))   /* client */
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_MISENC,
		      _("file download"), _("version2"), _("none"));
    }

  else if ((conn->client_entry->encf_flag != 0) && /* server */
	   ((conn->head[0] & SH_MASK_ENC) !=       /* client */
	    conn->client_entry->encf_flag))
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_MISENC,
		      _("file download"), _("version2"),
		      ((conn->head[0] & SH_PROTO_ENC) == SH_PROTO_ENC) ? 
		      _("version2") : _("invalid"));
      conn->client_entry->encf_flag = (conn->head[0] & SH_MASK_ENC);
    }
#else
  if ((conn->head[0] & SH_PROTO_ENC) != 0) 
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_MISENC,
		      _("file download"), _("none"), 
		      ((conn->head[0] & SH_PROTO_ENC) == SH_PROTO_ENC) ? 
		      _("version2") : _("invalid"));
    }
#endif
  
  
  if (conn->FileName != NULL)
    {
      SH_FREE(conn->FileName);
      conn->FileName = NULL;
    }

  /* Determine what to send
   */
  if (0 == sl_strncmp (_("CONF"), &(conn->buf[KEY_LEN]), 4))
    {
      strcpy(conn->FileType, _("CONF"));     /* known to fit  */
      conn->FileName = get_client_conf_file(conn->peer, &(conn->FileLength));
      conn->FileSent = 0;
    }
  else  if (0 == sl_strncmp (_("DATA"), &(conn->buf[KEY_LEN]), 4))
    {
      strcpy(conn->FileType, _("DATA"));     /* known to fit  */
      conn->FileName = get_client_data_file(conn->peer, &(conn->FileLength));
      conn->FileSent = 0;
    }
  else  if (0 == sh_uuid_check(&(conn->buf[KEY_LEN])))
    {
      char * uuid = &(conn->buf[KEY_LEN]);
      strcpy(conn->FileType, _("UUID"));     /* known to fit  */
      conn->FileName = get_client_uuid_file(conn->peer, &(conn->FileLength), uuid);
      conn->FileSent = 0;
    }
  else
    {
      ptok = sh_util_safe_name(&(conn->buf[KEY_LEN]));
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_FFILE,
		      conn->peer, 
		      ptok);
      SH_FREE(ptok);
      status_update (conn->client_entry, CLT_FAILED);
      sh_xfer_do_free (conn);
    }

  return;
}


static int do_file_transfer(sh_conn_t * conn, int state)
{
  client_t * this_client; 
  UINT32     ticks;
  char       hashbuf[KEYBUF_SIZE];

  SL_ENTER(_("do_file_transfer"));

  if (state == SH_DO_READ)        /* finished reading */
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<File transfer - entry.>\n")));
      
      /* -- Client requests challenge. --
       */
      if (0 == check_request_nerr ((char *) &(conn->head[3]), _("HELO")))
	{
	  int client_state;

	  this_client = do_check_client(conn, &client_state);
	  if (!this_client)
	    SL_RETURN(client_state, _("do_file_transfer"));

	  /* --- create and send a nonce ---
	   */
	  
	  conn->client_entry = this_client;
	  sl_strlcpy (conn->peer, &(conn->buf[KEY_LEN]), SH_MINIBUF+1);
	  
	  ticks = (UINT32) taus_get ();
	  
	  if (conn->K != NULL) 
	    {
	      SH_FREE(conn->K);
	      conn->K = NULL;
	    }
	  conn->K = SH_ALLOC(KEY_LEN+1);
	  sl_strlcpy (conn->K, 
		      sh_tiger_hash ((char *) &ticks, 
				     TIGER_DATA, sizeof(UINT32), 
				     hashbuf, sizeof(hashbuf)), 
		      KEY_LEN+1);
	  
	  TPT((0, FIL__, __LINE__, _("msg=<send nonce>\n")));
	  sh_xfer_prep_send (conn, conn->K, KEY_LEN+1, _("NSRV"), 
				SH_PROTO_BIG);
	}

      /* --- Client has send a message. Check state and message. ---
       */
      else if (0 == check_request_nerr((char *)&(conn->head[3]), _("NCLT")) &&
	       conn->client_entry != NULL                           &&
	       sl_strlen(conn->buf) > KEY_LEN                       &&
	       conn->K != NULL)
	{
	  
	  TPT(( 0, FIL__, __LINE__, 
		_("msg=<File transfer - NCLT (3).>\n")));
	  
          do_file_initial(conn);
	  do_file_send_data(conn);
	}
      
      else if (0 == check_request_nerr((char *)&(conn->head[3]), 
				       _("RECV"))                    &&
	       conn->client_entry != NULL                           &&
	       conn->K != NULL                                      &&
	       conn->FileName != NULL)
	{
	  
	  TPT(( 0, FIL__, __LINE__, 
		_("msg=<File transfer - RCVT (5+).>\n")));
	  
	  do_file_send_data(conn);
	}
      
      
      else if (0 == check_request_nerr((char *)&(conn->head[3]), 
				       _("EOTE")) &&
	       conn->client_entry != NULL)
	{
	  
	  TPT(( 0, FIL__, __LINE__, 
		_("msg=<File transfer - EOTE (7).>\n")));
	  
	  if (flag_err_info == S_TRUE)
	    sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_OKFILE,
			    conn->peer);
	  
	  if ((conn->client_entry->status_now != CLT_SUSPEND) &&
	      (conn->client_entry->status_now != CLT_TOOLONG))
	    { status_update (conn->client_entry, CLT_FILE); }
	  else
	    { conn->client_entry->session_key[0]    = '\0'; }
	  conn->client_entry->last_connect = time (NULL);
	  sh_xfer_do_free (conn);
	}
      
      
      /* client does something unexpected
       */
      else  /* ---- ??? ----- */
	{
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_FINV,
			  1, conn->pass, conn->peer,  
			  '\\', conn->head[3], '\\',conn->head[4],
			  '\\', conn->head[5], '\\',conn->head[6]);
	  status_update (conn->client_entry, CLT_FAILED);
	  sh_xfer_do_free (conn);
	}
    }
  
  else if (state == SH_DO_WRITE)  /* finished writing */
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<File transfer - (wait).>\n")));
      
      /* challenge is sent, now wait for message from client
       */
      conn->headcount     = 0;
      conn->bytecount     = 0;
      conn->bytes_to_send = 0;
      conn->bytes_to_get  = 0;
      if (conn->buf != NULL) 
	{
	  SH_FREE(conn->buf);
	  conn->buf           = NULL;
	}
      conn->state     = CONN_READING;
    }
  SL_RETURN(0, _("do_file_transfer"));
}

/* ------------------------------------------------------
 *
 *  MESSAGE TRANSFER
 *
 * ------------------------------------------------------ */
static int do_message_transfer(sh_conn_t * conn, int state)
{
  client_t * this_client; 
  char     * cmd;
  char       hash[SH_MAXMSGLEN + KEY_LEN + KEY_LEN + 1];
  char     * buffer;
  int        clt_sev;
  char     * ptok;
  UINT32     ticks;
  size_t     len;
  int        i;
  char     * test;
  char       sigbuf[KEYBUF_SIZE];

  SL_ENTER(_("do_message_transfer"));

  if (state == SH_DO_READ)        /* finished reading */
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<File transfer - entry.>\n")));
      
      /* -- Client requests challenge. --
       */
      if (0 == check_request_nerr ((char *) &(conn->head[3]), _("HELO")))
	{
	  int client_state;
	  
	  this_client = do_check_client(conn, &client_state);
	  if (!this_client)
	    SL_RETURN(client_state, _("do_message_transfer"));
	  
	  
	  /* -- create a nonce and send it --
	   */
	  conn->client_entry = this_client;
	  sl_strlcpy (conn->peer, &(conn->buf[KEY_LEN]), SH_MINIBUF+1);
	  
	  ticks = (UINT32) taus_get ();
	  
	  test = (char *) &ticks;
	  sh_util_cpylong (conn->challenge, test, 4);
	  conn->challenge[4] = '\0';
	  for (i = 0; i < 4; ++i)
	    if (conn->challenge[i] == '\0')
	      conn->challenge[i] = 0x01;
      
	  sh_xfer_prep_send (conn, conn->challenge, 5, _("TALK"), 
				SH_PROTO_MSG);
	  TPT(( 0, FIL__, __LINE__, _("msg=<Sent %s.>\n"), 
		hu_trans(conn->challenge)));
	}
      
      /* Client has send a message. Check whether we are in proper
       * state, and verify message.
       */
      else if (0 == 
	       check_request_nerr((char *)&(conn->head[3]), _("MESG")) &&
	       conn->client_entry != NULL                           &&
	       conn->client_entry->session_key[0] != '\0'           &&
	       (len = sl_strlen(conn->buf) - KEY_LEN) > 0           &&
	       sl_strlen(conn->challenge) == 4)
	{
	  TPT(( 0, FIL__, __LINE__, 
		_("msg=<Message transfer - MESG (3).>\n")));
	  
#ifdef SH_ENCRYPT
	  if (conn->client_entry->encf_flag == 0) {
	    conn->client_entry->ency_flag = 0;
	  }
	  if ((conn->client_entry->ency_flag != 0) && 
	      ((conn->head[0] & SH_PROTO_ENC) == 0)) 
	    {
	      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_MISENC,
			      _("message transfer"), 
			      _("version2"),
			      _("none"));
	    }
	  else if ((conn->client_entry->ency_flag != 0) &&
		   ((conn->head[0] & SH_MASK_ENC) != 
		    conn->client_entry->ency_flag))
	    {
	      sh_error_handle(SH_ERR_NOTICE, FIL__, __LINE__, 0, 
			      MSG_TCP_MISENC,
			      _("message transfer"), 
			      _("version2"),
			      ((conn->head[0] & SH_PROTO_ENC) == SH_PROTO_ENC) ? _("version2") : _("invalid"));
	      conn->client_entry->ency_flag = 
		(conn->head[0] & SH_MASK_ENC); 
	    }
#else
	  if ((conn->head[0] & SH_PROTO_ENC) != 0) 
	    {
	      sh_error_handle((-1), FIL__, __LINE__, 0, 
			      MSG_TCP_MISENC,
			      _("message transfer"), 
			      _("none"), 
			      ((conn->head[0] & SH_PROTO_ENC) == SH_PROTO_ENC) ? _("version2") : _("invalid"));
	    }
#endif
	  
	  TPT(( 0, FIL__, __LINE__, _("msg=<Rcvt %s.>\n"), conn->buf));
	  /* get hash from message end, truncate message
	   */
	  sl_strlcpy(hash, &(conn->buf[len]), KEY_LEN+1);
	  conn->buf[len] = '\0';
	  
	  /* verify hash
	   */
	  buffer = sh_util_strconcat(conn->buf, conn->challenge, NULL);
	  i =  sl_strncmp(hash, 
			  sh_util_siggen(conn->client_entry->session_key,
					 buffer,
					 sl_strlen(buffer),
					 sigbuf, sizeof(sigbuf)),
			  KEY_LEN);
	  TPT((0, FIL__, __LINE__, _("msg=<sign %s.>\n"),
	       sh_util_siggen(conn->client_entry->session_key,
			      buffer,
			      sl_strlen(buffer),
			      sigbuf, sizeof(sigbuf))));
	  
	  
	  if (0 != i)
	    {
	      TPT((0, FIL__, __LINE__, _("msg=<update status>\n")));
	      status_update (conn->client_entry, CLT_FAILED);
	      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_BADCONN,
			      _("Msg signature mismatch"), conn->peer);
	      conn->client_entry->session_key_timer = 
		time(NULL) - (2*TIMEOUT_KEY);
	      sh_xfer_do_free (conn);
	      SL_RETURN(0, _("do_message_transfer"));
	    }
	  else
	    {
	      conn->client_entry->last_connect = time (NULL);
	      
	      if (NULL != sl_strstr(conn->buf,      _("EXIT")))
		{
		  TPT((0, FIL__, __LINE__, _("msg=<update status>\n")));
		  conn->client_entry->exit_flag = 1;
		  status_update (conn->client_entry, CLT_EXITED);
		}
	      else if (NULL != sl_strstr(conn->buf, _("PANIC")))
		{
		  TPT((0, FIL__, __LINE__, _("msg=<update status>\n")));
		  status_update (conn->client_entry, CLT_PANIC);
		}
	      else if (NULL != sl_strstr(conn->buf, _("SUSPEND")))
		{
		  TPT((0, FIL__, __LINE__, _("msg=<update status>\n")));
		  status_update (conn->client_entry, CLT_SUSPEND);
		}
	      else if (NULL != sl_strstr(conn->buf, _("POLICY")))
		{
		  TPT((0, FIL__, __LINE__, _("msg=<update status>\n")));
		  status_update (conn->client_entry, CLT_POLICY);
		}
	      else if (NULL != sl_strstr(conn->buf, 
					 _("File check completed")))
		{
		  TPT((0, FIL__, __LINE__, _("msg=<update status>\n")));
		  status_update (conn->client_entry, CLT_CHECK);
		}
	      else if (NULL != sl_strstr(conn->buf, _("START")))
		{
		  TPT((0, FIL__, __LINE__, _("msg=<update status>\n")));
		  sh_socket_add2reload (conn->client_entry->hostname);
		  if (conn->client_entry->status_now == CLT_SUSPEND) {
		    status_update (conn->client_entry, CLT_ILLEGAL);
		    sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_ILL,
				    conn->peer);
		  }
		  else
		    status_update (conn->client_entry, CLT_STARTED);
		}
	      else
		{
		  TPT((0, FIL__, __LINE__, _("msg=<update status>\n")));
		  if (NULL != sl_strstr(conn->buf, 
					_("Runtime configuration reloaded")))
		    {
		      sh_socket_add2reload (conn->client_entry->hostname);
		    }
		  status_update (conn->client_entry, CLT_MSG);
		}
	      
	      TPT((0, FIL__, __LINE__, _("msg=<status updated>\n")));
	      clt_sev   = atoi(conn->buf);
	      clt_class = (-1);
	      ptok    = strchr(conn->buf, '?');
	      if (ptok != NULL)
		{
		  ++ptok;
		  if (ptok != NULL && sh.flag.client_class == S_TRUE) 
		    clt_class = atoi(ptok);  /* is a global */
		  ptok = strchr(ptok, '?');
		  if (ptok != NULL) 
		    ++ptok;
		}
	      if (sh.flag.client_severity == S_FALSE)
		clt_sev = (-1);
	      
	      /* here we expect an xml formatted message, thus we don't
		 escape xml special chars (flag == 0) */
	      ptok = 
		sh_tools_safe_name ((ptok!=NULL) ? ptok : conn->buf, 0);
	      
	      /* push client name to error routine
	       */
#if defined(SH_WITH_SERVER) && defined(HAVE_LIBPRELUDE)
	      {
		char peer_ip[SH_IP_BUF];
		sh_ipvx_ntoa(peer_ip, sizeof(peer_ip), &(conn->addr_peer)); 
		sh_error_set_peer_ip( peer_ip );
	      }                        
#endif
	      {
		char * pstrip = sh_strip_domain (conn->peer);
		sh_error_set_peer(pstrip);
		sh_error_handle(clt_sev, FIL__, __LINE__, 0, MSG_TCP_MSG,
				pstrip, 
				ptok);
		SH_FREE(pstrip);
		sh_error_set_peer(NULL);
	      }
#if defined(SH_WITH_SERVER) && defined(HAVE_LIBPRELUDE)
	      sh_error_set_peer_ip(NULL);
#endif
	      
	      TPT((0, FIL__, __LINE__, _("msg=<%s>\n"), ptok));
	      SH_FREE(ptok);
	      clt_class = (-1);
	    }
	  memset(buffer, '\0', sl_strlen(buffer));
	  SH_FREE(buffer);
	  
	  /* SERVER CONF SEND
	   */
	  buffer = sh_util_strconcat(conn->buf,
				     conn->challenge,
				     NULL);
	  sl_strlcpy(hash, 
		     sh_util_siggen ( conn->client_entry->session_key,
				      buffer,
				      sl_strlen(buffer),
				      sigbuf, sizeof(sigbuf)),
		     KEY_LEN+1);
	  
	  /* --- SERVER CMD --- */
	  cmd = sh_socket_check (conn->peer);
	  
	  if (cmd != NULL)
	    {
	      /* max cmd size is SH_MAXMSGLEN bytes
	       */
	      sl_strlcpy(&hash[KEY_LEN], cmd, SH_MAXMSGLEN);
	      sl_strlcat(&hash[KEY_LEN],
			 sh_util_siggen ( conn->client_entry->session_key,
					  &hash[KEY_LEN],
					  sl_strlen(&hash[KEY_LEN]),
					  sigbuf, sizeof(sigbuf)),
			 SH_MAXMSGLEN+KEY_LEN+1);
	      
	      TPT((0, FIL__, __LINE__, _("CONF SEND <0> <%s>\n"), 
		   &hash[KEY_LEN]));
	      
	    } else {
	    
	    TPT((0, FIL__, __LINE__, _("CONF SEND <0> <[NULL]>\n")));
	    
	  }
	  /* --- SERVER CMD END --- */
	  
	  TPT((0, FIL__, __LINE__, _("msg=<sign %s.>\n"),
	       sh_util_siggen(conn->client_entry->session_key,
			      buffer,
			      sl_strlen(buffer),
			      sigbuf, sizeof(sigbuf))));
	  
#ifdef SH_ENCRYPT
	  sh_xfer_send_crypt (conn, hash, 
			      sl_strlen(hash) /* KEY_LEN */, 
			      _("CONF"), 
			      SH_PROTO_MSG|SH_PROTO_END|conn->client_entry->ency_flag);
#else
	  sh_xfer_send_crypt (conn, hash, 
			      sl_strlen(hash) /* KEY_LEN */, 
			      _("CONF"), 
			      SH_PROTO_MSG|SH_PROTO_END);
#endif
	  
	  memset(buffer, '\0', sl_strlen(buffer));
	  SH_FREE(buffer);
	  
	  /* sh_xfer_do_free (conn); */
	}
      
      /* client does something unexpected
       */
      else  /* ---- ??? ----- */
	{
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_FINV,
			  2, conn->pass, conn->peer,  
			  '\\', conn->head[3], '\\',conn->head[4],
			  '\\', conn->head[5], '\\',conn->head[6]);
	  status_update (conn->client_entry, CLT_FAILED);
	  conn->client_entry->session_key_timer = 
	    time(NULL) - (2*TIMEOUT_KEY);
	  sh_xfer_do_free (conn);
	}
    }

  else if (state == SH_DO_WRITE)  /* finished writing */
    {
      if (0 != (conn->head[0] & SH_PROTO_END))
	{
	  if (flag_err_debug == S_TRUE)
	    {
	      char * pstrip = sh_strip_domain (conn->peer);
	      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_OKMSG,
			      pstrip);
	      SH_FREE(pstrip);
	    }
	  sh_xfer_do_free (conn);
	  SL_RETURN(0, _("do_message_transfer"));
	}
      
      TPT(( 0, FIL__, __LINE__, _("msg=<Msg transfer - (wait).>\n")));
      
      /* challenge is sent, now wait for message from client
       */
      conn->headcount     = 0;
      conn->bytecount     = 0;
      conn->bytes_to_send = 0;
      conn->bytes_to_get  = 0;
      if (conn->buf != NULL) 
	{
	  SH_FREE(conn->buf);
	  conn->buf           = NULL;
	}
      conn->state     = CONN_READING;
    }
  TPT((0, FIL__, __LINE__, _("msg=<return>\n") ));
  SL_RETURN(0, _("do_message_transfer"));
}

/* ------------------------------------------------------
 *
 *  AUTHENTICATION
 *
 * ------------------------------------------------------ */

static void check_probe(sh_conn_t * conn)
{
  if (conn && conn->client_entry)
    {
      /* If client has sent probe, change ivst_flag and clear probe in head[0].
       */
      conn->head[0] = sh_tools_probe_store(conn->head[0], 
					   &(conn->client_entry->ivst_flag));
    }
}

client_t * do_auth_start(sh_conn_t * conn)
{
  client_t * this_client;

  TPT((0, FIL__, __LINE__, 
       _("msg=<Authentication - SALT (1).>\n")));
  
  if (conn->buf == NULL || sl_strlen(conn->buf) == 0)
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_NOCLT);
      sh_xfer_do_free (conn);
      return NULL;
    } 
                  
  /* search the register
   */
  
  this_client = search_register (conn, 0);
  if (NULL == this_client)
    return NULL;
    
  conn->client_entry = this_client;
  sl_strlcpy (conn->peer, conn->buf, SH_MINIBUF+1);
  
  if (0 != check_request_s((char *)&(conn->head[3]), 
			   _("SALT"),conn->peer))
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_BADCONN,
		      _("No salt requested"), conn->peer);
      status_update (conn->client_entry, CLT_FAILED);
      conn->client_entry->session_key_timer = 
	time(NULL) - (2*TIMEOUT_KEY);
      sh_xfer_do_free (conn);
      return NULL;
    }

  check_probe(conn);
  return this_client;
}

#if !defined(USE_SRP_PROTOCOL)

int do_auth(sh_conn_t * conn)
{
  client_t * this_client; 
  UINT32     ticks;
  char       u[5] = "OOOO";
#ifdef SH_ENCRYPT
  int        err_num;
  char expbuf[SH_ERRBUF_SIZE];
#endif
  char       hash[SH_MAXMSGLEN + KEY_LEN + KEY_LEN + 1];
  char hashbuf[KEYBUF_SIZE];

  /* first pass -- client request salt  
   */
  if (conn->pass    == 1) 
    {
      this_client = do_auth_start(conn);

      if (!this_client)
	return -1;

      /* -- create server nounce v --
       */
      ticks = (UINT32) taus_get ();
      
      if (conn->A != NULL)
	{
	  SH_FREE(conn->A);
	  conn->A = NULL;
	}
      conn->A = SH_ALLOC(KEY_LEN+1);
      
      sl_strlcpy(conn->A, 
		 sh_tiger_hash((char *) &ticks, 
			       TIGER_DATA, sizeof(UINT32), 
			       hashbuf, sizeof(hashbuf)),
		 KEY_LEN+1);
      u[0] = 'I'; u[1] = 'N'; u[2] = 'I'; u[3] = 'T'; u[4] = '\0';
      
      if (conn->M1 != NULL)
	{
	  SH_FREE(conn->M1);
	  conn->M1 = NULL;
	}
      conn->M1 = SH_ALLOC(2*KEY_LEN+1);
      
      /* compute hash key H(v(server), P)v(server)
       */
      sh_passwd (conn->A, conn->client_entry->verifier, 
		 NULL, conn->M1);
      
      sl_strlcat(conn->M1, conn->A, 2*KEY_LEN+1);
      
      
      /* --- send H(v(server), P)v(server) ----
       */
      sh_xfer_prep_send (conn, 
			    conn->M1, 
			    sl_strlen(conn->M1), 
			    u, 
			    (conn->head[0]|SH_PROTO_SRP));
      
      SH_FREE(conn->M1); 
      conn->M1 = NULL;
    }
  
  /* client -- third pass
   * Message is H(H(u,v),P)u
   *
   * A := v, verifier := H(password), 
   */
  else if (conn->pass    == 3                   && 
	   conn->client_entry != NULL)
    {
      
      TPT((0, FIL__, __LINE__, 
	   _("msg=<Authentication - PASS (3).>\n")));
      
      if (0 != check_request_s((char *) &(conn->head[3]), _("PASS"), 
			       conn->peer)                    ||
	  sl_strlen(conn->buf) <= KEY_LEN                        ||
	  conn->A == NULL)
	{
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_BADCONN,
			  _("Invalid client request"), conn->peer);
	  status_update (conn->client_entry, CLT_FAILED);
	  conn->client_entry->session_key_timer = 
	    time(NULL) - (2*TIMEOUT_KEY);
	  sh_xfer_do_free (conn);
	  return -1;
	} 

      check_probe(conn);

      /* store random nonce u from client
       */
      if (conn->K != NULL)
	{
	  SH_FREE(conn->K);
	  conn->K = NULL;
	}
      conn->K = SH_ALLOC(KEY_LEN+1);
      sl_strlcpy(conn->K, &(conn->buf[KEY_LEN]), KEY_LEN+1);
      
      /* verify random nonce u from client
       */
      if (conn->M1 != NULL)
	{
	  SH_FREE(conn->M1);
	  conn->M1 = NULL;
	}
      conn->M1 = sh_util_strconcat(conn->K, conn->A, NULL);
      
      TPT((0, FIL__, __LINE__, _("msg=<c/r: K = %s>\n"), conn->K));
      TPT((0, FIL__, __LINE__, _("msg=<c/r: A = %s>\n"), conn->A));
      TPT((0, FIL__, __LINE__, _("msg=<c/r: M = %s>\n"), conn->M1));
      
      sl_strlcpy(hash, sh_tiger_hash (conn->M1, 
				      TIGER_DATA, 
				      sl_strlen(conn->M1),
				      hashbuf, sizeof(hashbuf)), 
		 KEY_LEN+1); 
      sh_passwd (hash, conn->client_entry->verifier, NULL, conn->M1);
      
      TPT((0, FIL__, __LINE__, _("msg=<c/r: H = %s>\n"), hash));
      TPT((0, FIL__, __LINE__, _("msg=<c/r: P = %s>\n"), conn->M1));
      
      if ( 0 != sl_strncmp(conn->M1, conn->buf, KEY_LEN))
	{
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_BADCONN,
			  _("Session key mismatch"), conn->peer);
	  status_update (conn->client_entry, CLT_FAILED);
	  conn->client_entry->session_key_timer = 
	    time(NULL) - (2*TIMEOUT_KEY);
	  sh_xfer_do_free (conn);
	  return -1;
	} 
      
      /* ---- compute hash key H(v, P, u) ----
       */
      sh_passwd (conn->A, conn->client_entry->verifier, conn->K,
		 conn->M1);
      
      sl_strlcpy(conn->client_entry->session_key, 
		 conn->M1, KEY_LEN+1);
      TPT((0, FIL__, __LINE__, _("msg=<c/r: Key = %s>\n"), 
	   conn->client_entry->session_key));
      
#ifdef SH_ENCRYPT
      err_num = rijndael_makeKey(&(conn->client_entry->keyInstE), 
				 DIR_ENCRYPT, 192, 
				 conn->client_entry->session_key);
      if (err_num < 0)
	sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
			errorExplain(err_num, expbuf, sizeof(expbuf)), 
			_("check_protocol: makeKey"));
      err_num = rijndael_makeKey(&(conn->client_entry->keyInstD), 
				 DIR_DECRYPT, 192, 
				 conn->client_entry->session_key);
      if (err_num < 0)
	sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
			errorExplain(err_num, expbuf, sizeof(expbuf)), 
			_("check_protocol: makeKey"));
#endif
      
      if (conn->K  != NULL) SH_FREE (conn->K);
      conn->K  = NULL;
      if (conn->A  != NULL) SH_FREE (conn->A);
      conn->A  = NULL;
      if (conn->M1 != NULL) SH_FREE (conn->M1);
      conn->M1 = NULL;
      
      /* if (conn->client_entry->status_now == CLT_STARTED */
      if (((conn->client_entry->status_now != CLT_INACTIVE) &&
	   (conn->client_entry->status_now != CLT_EXITED)   &&
	   (conn->client_entry->status_now != CLT_SUSPEND))
	  && conn->client_entry->session_key_timer > (time_t) 1)
	{
	  status_update (conn->client_entry, CLT_ILLEGAL);
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_ILL,
			  conn->peer);
	}
      else if (conn->client_entry->session_key_timer == (time_t) 0)
	{
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_NEW,
			  conn->peer);
	  if (conn->client_entry->status_now != CLT_SUSPEND)
	    status_update (conn->client_entry, CLT_STARTED);
	}
      
      conn->client_entry->session_key_timer = time (NULL);
      conn->client_entry->last_connect = time (NULL);
      
      /* put in read state
       */
      sh_xfer_prep_send (conn, 
			    _("AUTH"),
			    5, 
			    _("AUTH"), 
			    (conn->head[0]|SH_PROTO_SRP));
      
    }
  else
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_FINV,
		      3, conn->pass, conn->peer, 
		      '\\', conn->head[3], '\\', conn->head[4],
		      '\\', conn->head[5], '\\', conn->head[6]);
      sh_xfer_do_free (conn);
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
  
/* use SRP */

int do_auth(sh_conn_t * conn)
{
  client_t * this_client; 
  UINT32     ticks;
  char       u[5] = "OOOO";
#ifdef SH_ENCRYPT
  int        err_num;
  char expbuf[SH_ERRBUF_SIZE];
#endif
  size_t     len;
  char     * test;
  char     * foo_B;
  char     * foo_Ss;
  char hashbuf[KEYBUF_SIZE];

  /* use SRP                    
   */
  if (conn->pass == 1)
    {
      this_client = do_auth_start(conn);
      if (!this_client)
	return -1;

      u[0] = 'I'; u[1] = 'N'; u[2] = 'I'; u[3] = 'T'; u[4] = '\0';
      sh_xfer_prep_send (conn, 
			    conn->client_entry->salt, 
			    sl_strlen(conn->client_entry->salt), 
			    u, 
			    (conn->head[0]|SH_PROTO_SRP));
    }

  /* client has sent A -- third pass
   */
  else if (conn->pass == 3                    && 
	   conn->client_entry != NULL)
    {
      
      TPT((0, FIL__, __LINE__, 
	   _("msg=<Authentication - PC01 (3).>\n")));
      
      if (0 != check_request_s((char *)&(conn->head[3]),_("PC01"),conn->peer)||
	  conn->buf == NULL
	  )
	{
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_BADCONN,
			  _("Invalid client request"), conn->peer);
	  status_update (conn->client_entry, CLT_FAILED);
	  conn->client_entry->session_key_timer = 
	    time(NULL) - (2*TIMEOUT_KEY);
	  sh_xfer_do_free (conn);
	  return -1;
	} 
      
      check_probe(conn); noise();

      if (0 != sh_srp_init())
	{
	  status_update (conn->client_entry, CLT_FAILED);
	  sh_error_handle(SH_ERR_SEVERE, FIL__, __LINE__, 0, 
			  MSG_TCP_EBGN);
	  sh_xfer_do_free (conn);
	  return -1;
	}
      
      
      /* check A, only send B if correct 
       */
      if ( sl_strlen(conn->buf) < SH_BUFSIZE && 
	   0 == sh_srp_check_zero (conn->buf) )
	{
	  len = sl_strlen(conn->buf)+1;
	  
	  if (conn->A != NULL)
	    {
	      SH_FREE(conn->A);
	      conn->A = NULL;
	    }
	  conn->A = SH_ALLOC(len);
	  sl_strlcpy (conn->A, conn->buf, len);
	  
	  /* 
	   * compute B 
	   */
	  if (0 != sh_srp_make_a ())     /* b        random number */
	    {
	      status_update (conn->client_entry, CLT_FAILED);
	      
	      sh_error_handle(SH_ERR_SEVERE, FIL__, __LINE__, 0, 
			      MSG_TCP_EBGN);
	      sh_srp_exit();
	      sh_xfer_do_free (conn);
	      return -1;
	    }
	  
	  foo_B = sh_srp_B               /* B = v + g^b            */
	    (conn->client_entry->verifier);
	  
	  if (foo_B == NULL)
	    {
	      status_update (conn->client_entry, CLT_FAILED);
	      
	      sh_error_handle(SH_ERR_SEVERE, FIL__, __LINE__, 0, 
			      MSG_TCP_EBGN);
	      sh_srp_exit();
	      sh_xfer_do_free (conn);
	      return -1;
	    }
	  
	  TPT((0, FIL__, __LINE__, _("msg=<srp: A = %s>\n"), conn->A));
	  TPT((0, FIL__, __LINE__, _("msg=<srp: B = %s>\n"), foo_B));
	  
	  /* 
	   * create nonce u 
	   */
	  ticks = (UINT32) taus_get ();
	  
	  test = (char *) &ticks;
	  sh_util_cpylong (u, test, 4);  /* u        nounce        */
	  u[4] = '\0';
	  sl_strlcpy(conn->challenge, 
		     sh_tiger_hash(u, TIGER_DATA, 4, hashbuf, sizeof(hashbuf)),
		     SH_CHALLENGE_SIZE);
	  
	  TPT((0, FIL__, __LINE__, _("msg=<srp: u = %03o-%03o-%03o-%03o>\n"), u[0], u[1], u[2], u[3]));
	  TPT((0, FIL__, __LINE__, _("msg=<srp: U = %s>\n"), 
	       conn->challenge));
	  
	  /* 
	   * compute the session key K and M1 = Hash(A,B,K)
	   */
	  foo_Ss = sh_srp_S_s (conn->challenge, 
			       conn->A, 
			       conn->client_entry->verifier);
	  
	  if (foo_Ss == NULL || 0 != sh_srp_check_zero (foo_Ss))
	    {
	      status_update (conn->client_entry, CLT_FAILED);
	      
	      sh_error_handle(SH_ERR_SEVERE, FIL__, __LINE__, 0, 
			      MSG_TCP_EBGN);
	      sh_srp_exit();
	      sh_xfer_do_free (conn);
	      return -1;
	    }
	  
	  if (conn->K != NULL)
	    {
	      SH_FREE(conn->K);
	      conn->K = NULL;
	    }
	  conn->K = SH_ALLOC(KEY_LEN+1);
	  sl_strlcpy(conn->K, 
		     sh_tiger_hash(foo_Ss, TIGER_DATA, 
				   sl_strlen(foo_Ss), 
				   hashbuf, sizeof(hashbuf)),
		     KEY_LEN+1);
	  
	  if (conn->M1 != NULL)
	    {
	      SH_FREE(conn->M1);
	      conn->M1 = NULL;
	    }
	  conn->M1 = SH_ALLOC(KEY_LEN+1);
	  sh_srp_M (conn->A, foo_B, conn->K, conn->M1, KEY_LEN+1);
	  
	  TPT((0, FIL__, __LINE__, _("msg=<srp:Ss = %s>\n"), foo_Ss));
	  TPT((0, FIL__, __LINE__, _("msg=<srp: K = %s>\n"), conn->K));
	  TPT((0, FIL__, __LINE__, _("msg=<srp:M1 = %s>\n"),conn->M1));
	  
	  /*
	   * send B
	   */
	  sh_xfer_prep_send (conn, 
				foo_B,
				sl_strlen(foo_B)+1,
				u,
				(conn->head[0]|SH_PROTO_SRP));
	  if (foo_Ss != NULL)
	    {
	      SH_FREE(foo_Ss);
	      foo_Ss = NULL;
	    }
	  if (foo_B  != NULL)
	    {
	      SH_FREE(foo_B);
	      foo_B = NULL;
	    }
	}
      else
	{
	  status_update (conn->client_entry, CLT_FAILED);
	  
	  sh_error_handle(SH_ERR_SEVERE, FIL__, __LINE__, 0, 
			  MSG_TCP_EZERO);
	  sh_xfer_do_free (conn);
	}
      
      sh_srp_exit();
    }
  
  /* client has sent M1 -- fifth pass
   */
  else if (conn->pass    == 5           && 
	   conn->client_entry != NULL) 
    {
      TPT((0, FIL__, __LINE__, 
	   _("msg=<Authentication - PC02 (5).>\n")));
      
      /* check that the state is valid
       */
      if (0 != check_request_s((char *)&(conn->head[3]), _("PC02"),
			       conn->peer)                   ||
	  conn->A == NULL || conn->K == NULL || conn->M1 == NULL)
	{
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_BADCONN,
			  _("Invalid client request"), conn->peer);
	  status_update (conn->client_entry, CLT_FAILED);
	  conn->client_entry->session_key_timer = 
	    time(NULL) - (2*TIMEOUT_KEY);
	  sh_xfer_do_free (conn);
	  return -1;
	} 

      check_probe(conn); noise();

      /* ------ verify M1 = H(A,  B, K) -------
       * -----    send M2 = H(A, M1, K) -------
       */
      if (conn->buf != NULL && 
	  sl_strncmp(conn->buf, conn->M1, KEY_LEN) == 0)
	{
	  /*
	   * send M2
	   */
	  char M_buf[KEY_LEN+1];
	  sh_xfer_prep_send (conn, 
				sh_srp_M (conn->A, conn->M1, conn->K,
					  M_buf, sizeof(M_buf)),
				KEY_LEN+1,
				_("PARP"),
				(conn->head[0]|SH_PROTO_SRP));
	  
	  if (conn->A  != NULL) SH_FREE(conn->A);  conn->A  = NULL;
	  if (conn->M1 != NULL) SH_FREE(conn->M1); conn->M1 = NULL;
	  sl_strlcpy(conn->client_entry->session_key, 
		     conn->K, KEY_LEN+1);
	  TPT((0, FIL__, __LINE__, _("msg=<key %s>\n"), 
	       conn->client_entry->session_key));
	  
#ifdef SH_ENCRYPT
	  err_num = rijndael_makeKey(&(conn->client_entry->keyInstE), 
				     DIR_ENCRYPT, 192, 
				     conn->client_entry->session_key);
	  if (err_num < 0)
	    sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
			    errorExplain(err_num, expbuf, sizeof(expbuf)), 
			    _("sh_xfer_prep_send_int: makeKey"));
	  err_num = rijndael_makeKey(&(conn->client_entry->keyInstD), 
				     DIR_DECRYPT, 192, 
				     conn->client_entry->session_key);
	  if (err_num < 0)
	    sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
			    errorExplain(err_num, expbuf, sizeof(expbuf)), 
			    _("sh_xfer_prep_send_int: makeKey"));
#endif
	  
	  if (conn->K  != NULL) SH_FREE(conn->K);  conn->K  = NULL;
	  
	  conn->client_entry->last_connect = time (NULL);
	  
	  if (((conn->client_entry->status_now != CLT_INACTIVE) &&
	       (conn->client_entry->status_now != CLT_EXITED)   &&
	       (conn->client_entry->status_now != CLT_SUSPEND))
	      && conn->client_entry->session_key_timer > (time_t) 1)
	    {
	      status_update (conn->client_entry, CLT_ILLEGAL);
	      
	      sh_error_handle((-1), FIL__, __LINE__, 0, 
			      MSG_TCP_ILL,
			      conn->peer);
	    }
	  else if (conn->client_entry->session_key_timer == (time_t) 0)
	    {
	      sh_error_handle((-1), FIL__, __LINE__, 0, 
			      MSG_TCP_NEW,
			      conn->peer);
	      if (conn->client_entry->status_now != CLT_SUSPEND)
		status_update (conn->client_entry, CLT_STARTED);
	    }
	  conn->client_entry->session_key_timer = time (NULL);
	  
	}
      else
	{
	  status_update (conn->client_entry, CLT_FAILED);
	  conn->client_entry->session_key_timer = 
	    time(NULL) - (2*TIMEOUT_KEY);
	  
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_BADCONN,
			  _("Session key mismatch"), conn->peer);
	  sh_xfer_do_free (conn);
	} 
    }
  
  else
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_FINV,
		      4, conn->pass, conn->peer, 
		      '\\', conn->head[3], '\\', conn->head[4],
		      '\\', conn->head[5], '\\', conn->head[6]);
      sh_xfer_do_free (conn);
    }
  return 0;
}
#endif

/************************************************************************
 *
 * Here we check the message received, and decide on the answer to send
 * (if any). The connection is in CONN_PAUSED state, thus we must:
 * (i)   define the proper reaction
 * (ii)  reset to CONN_READING or CONN_WRITING or CONN_FREE
 * (iii) eventually reset the connection entry
 *
 *************************************************************************/
static
void check_protocol(sh_conn_t * conn, int state)
{
  SL_ENTER(_("check_protocol"));

  /* seed / re-seed the PRNG if required
   */
  (void) taus_seed();

  /* protocols: 
   * -- (iii)    file transfer
   * -- (ii)     authenticated message transfer
   * -- (i)      SRP key exchange
   */

  /* --------- FILE TRANSFER  -----------
   */
  if ( (conn->head[0] & SH_PROTO_SRP) == 0  &&
       (conn->head[0] & SH_PROTO_BIG) != 0  /* is set */ )
    {
      /* nonzero means re-authentication is required
       */
      if (0 == do_file_transfer(conn, state))
	SL_RET0(_("check_protocol"));
    }
  /* --------- END FILE TRANSFER ----------- */


  /* ---------  message exchange  -----------
   */
  else if ((conn->head[0] & SH_PROTO_SRP) == 0  && 
	   (conn->head[0] & SH_PROTO_MSG) != 0  /* is set */ )
    {
      /* nonzero means re-authentication is required
       */
      if (0 == do_message_transfer(conn, state))
	SL_RET0(_("check_protocol"));
    }
  /* ---------  END MESSAGE TRANSFER ------ */

  /* ---------  authentication  -----------
   */
  if ( (conn->head[0] & SH_PROTO_SRP) != 0   /* is set */ )
    {
      if (state == SH_DO_READ)        /* finished reading */
	{
	  do_auth(conn);
	}

      else if (state == SH_DO_WRITE)  /* finished writing */
	{
	  TPT((0, FIL__, __LINE__, _("msg=<Authentication -- (wait).>\n")));

	  conn->headcount     = 0;
	  conn->bytecount     = 0;
	  conn->bytes_to_send = 0;
	  conn->bytes_to_get  = 0;
	  if (conn->buf != NULL) 
	    {
	      SH_FREE(conn->buf);
	      conn->buf           = NULL;
	    }
	  conn->state     = CONN_READING;
	}
    }
  SL_RET0(_("check_protocol"));
}


/***********************************************************
 *
 *    SERVER RECEIVE FUNCTION
 *
 ***********************************************************
 */
int sh_xfer_do_read (sh_conn_t * conn)
{
  unsigned long   byteread;     /* bytes read         */

  SL_ENTER(_("sh_xfer_do_read"));

  if (conn->state == CONN_SENDING)
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_SYNC,
		      conn->peer);
      SL_RETURN( (-1), _("sh_xfer_do_read"));
    }

  if (conn->headcount < SH_HEADER_SIZE) 
    {
      conn->bytes_to_get = SH_HEADER_SIZE - conn->headcount;
      byteread = read (conn->fd, &(conn->head[conn->headcount]),
		       conn->bytes_to_get);
      if (byteread > 0 || errno == EINTR) 
	{
	  if (byteread > 0) 
	    conn->headcount += byteread;
	  if (conn->headcount == SH_HEADER_SIZE)
	    {
	      conn->bytes_to_get = (256 * (unsigned int)conn->head[1] + 
				    (unsigned int)conn->head[2]);
	      SH_SHOWPROT(conn->head, '<');
	      conn->bytecount = 0;
	    }
	}
      else
	goto conn_reset;
      SL_RETURN( (0), _("sh_xfer_do_read"));
    }

  /* limit message size
   */
  conn->bytes_to_get = (conn->bytes_to_get > TRANS_BYTES) ? 
    TRANS_BYTES : conn->bytes_to_get;

  if (conn->headcount == SH_HEADER_SIZE && conn->bytes_to_get > 0)
    {
      if ( conn->bytecount == 0)
	{
	  if (conn->buf != NULL)
	    SH_FREE (conn->buf);
	  conn->buf = SH_ALLOC(conn->bytes_to_get + 1); /* <= TRANS_BYTES+1 */
	}

      byteread           = read (conn->fd, &(conn->buf[conn->bytecount]),
				 conn->bytes_to_get - conn->bytecount);
      if (byteread > 0 || errno == EINTR) 
	{
	  if (byteread > 0) 
	    conn->bytecount    += byteread;
	  if (conn->bytecount == conn->bytes_to_get) 
	    {
	      ++conn->pass;
	      /* always terminate with NULL - we might use sl_strcmp() */
	      conn->buf[conn->bytecount] = '\0';
	      conn->state                = CONN_PAUSE;

#ifdef SH_ENCRYPT
	      if ((conn->head[0] & SH_PROTO_ENC) != 0) 
		{
		  conn->buf = sh_tools_revertPack (conn->head, 
						   conn->client_entry->ivst_flag,
						   conn->buf,
						   &(conn->client_entry->keyInstD),
						   conn->bytecount);
		}
#endif
	      /* ------  HERE CALL check_protocol(conn) -------  */
	      check_protocol(conn, SH_DO_READ);
	    }
	}
      else
	  goto conn_reset;
    }

  else if (conn->headcount == SH_HEADER_SIZE && conn->bytes_to_get == 0)
    {
      if (conn->buf != NULL)
	SH_FREE (conn->buf);
      conn->buf       = NULL;
      conn->bytecount = 0;
      ++conn->pass;
      conn->state     = CONN_PAUSE;
      /* ------  HERE CALL check_protocol(conn) -------  */
      check_protocol(conn, SH_DO_READ);
    }
      
  SL_RETURN( (0), _("sh_xfer_do_read"));

 conn_reset:
  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_RESET,
		  conn->peer);
  sh_xfer_do_free ( conn );
  SL_RETURN( (-1), _("sh_xfer_do_read"));
}

#if !defined(O_NONBLOCK)
#if defined(O_NDELAY)
#define O_NONBLOCK  O_NDELAY
#else
#define O_NONBLOCK  0
#endif
#endif

/* send to the client
 */
int sh_xfer_do_write (sh_conn_t * conn)
{
  int    flags;
  long   arg = 0;
  long   bytesent;     /* bytes read         */

  SL_ENTER(_("sh_xfer_do_write"));

  /* ---- consistency check ------
   */
  if (conn->state == CONN_READING)
    {
      sh_error_handle( (-1), FIL__, __LINE__, 0, MSG_TCP_SYNC,
		      conn->peer);
      SL_RETURN( (-1), _("sh_xfer_do_write"));
    }
 
  flags = retry_fcntl (FIL__, __LINE__, conn->fd, F_GETFL, arg);
  retry_fcntl (FIL__, __LINE__, conn->fd, F_SETFL,  flags|O_NONBLOCK);

  /* ---- send the header ------
   */
  if (conn->headcount < SH_HEADER_SIZE) 
    {
      conn->bytes_to_send = SH_HEADER_SIZE - conn->headcount;
      bytesent = write (conn->fd, &(conn->head[conn->headcount]), 
			conn->bytes_to_send);
      if (bytesent >= 0 || errno == EINTR || errno == EAGAIN) 
	{
	  if (bytesent > 0) 
	    conn->headcount += bytesent;
	  if (conn->headcount == SH_HEADER_SIZE) 
	    conn->bytes_to_send = 
	      (256 * (int)conn->head[1] + (int)conn->head[2]);
	}
      else 
	goto conn_reset_w;

      if (conn->fd >= 0)
	retry_fcntl (FIL__, __LINE__, conn->fd, F_SETFL,  flags);
      SL_RETURN( (0), _("sh_xfer_do_write"));
    }

  /* ---- send the body ------
   */

  if (conn->headcount == SH_HEADER_SIZE && conn->bytes_to_send > 0 &&
      conn->buf != NULL)
    {
      bytesent = write (conn->fd, &(conn->buf[conn->bytecount]), 
			conn->bytes_to_send - conn->bytecount);
      if (bytesent >= 0 || errno == EINTR || errno == EAGAIN) 
	{
	  if (bytesent > 0) 
	    conn->bytecount    += bytesent;
	  if (conn->bytecount == conn->bytes_to_send) 
	    {
	      ++conn->pass;
	      conn->state = CONN_PAUSE;
	      /* ------  HERE CALL check_protocol(conn) -------  */
	      check_protocol(conn, SH_DO_WRITE);
	    }
	}
      else
	goto conn_reset_w;
    }
      
  else if (conn->headcount == SH_HEADER_SIZE && conn->bytes_to_send == 0)
    {
      ++conn->pass;
      conn->state = CONN_PAUSE;
      /* ------  HERE CALL check_protocol(conn) -------  */
      check_protocol(conn, SH_DO_WRITE);
    }

  if (conn->fd >= 0)
    retry_fcntl (FIL__, __LINE__, conn->fd, F_SETFL,  flags);
  SL_RETURN( (0), _("sh_xfer_do_write"));

 conn_reset_w:
  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_RESET,
		  conn->peer);
  sh_xfer_do_free ( conn );
  SL_RETURN( (-1), _("sh_xfer_do_write"));
}

/* accept a connection from a client
 */ 
#include <syslog.h>
#ifdef SH_USE_LIBWRAP
#include <tcpd.h>

#ifndef ALLOW_SEVERITY 
#define ALLOW_SEVERITY LOG_INFO
#define DENY_SEVERITY  LOG_WARNING
#endif

int allow_severity;
int deny_severity;
#endif

#ifdef SH_USE_LIBWRAP
static int check_libwrap(int rc, sh_conn_t * newconn)
{
  struct request_info request;
  char                errbuf[128];
  char                daemon[128];

  sl_strlcpy(daemon, SH_INSTALL_NAME, sizeof(daemon));
  request_init(&request, RQ_DAEMON, daemon, RQ_FILE, rc, 0);
  fromhost(&request);
  if (!hosts_access(&request)) 
    {
      sl_strlcpy(errbuf, _("Refused connection from "), sizeof(errbuf));
      sl_strlcat(errbuf,   eval_client(&request), sizeof(errbuf));
      
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      errbuf, _("libwrap"));
      newconn->fd    = -1;
      newconn->state = CONN_FREE;
      sl_close_fd(FIL__, __LINE__, rc);
      return -1;
    }
  return 0;
}
#endif

int sh_xfer_accept (int sock, sh_conn_t * newconn)
{
  int                errflag;
  int                rc;
  struct sh_sockaddr addr;
  
  /* handle AIX (size_t addrlen) in wrapper
   */
  int                addrlen = sizeof(addr);

  SL_ENTER(_("sh_xfer_accept"));

  rc = retry_accept(FIL__, __LINE__, sock, &addr, &addrlen);

  if (rc < 0)
    {
      char err_buf[SH_ERRBUF_SIZE];
      errflag = errno;
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      sh_error_message(errflag,err_buf, sizeof(err_buf)), _("accept"));
      newconn->fd    = -1;
      newconn->state = CONN_FREE;
      SL_RETURN( (-1), _("sh_xfer_accept"));
    }

  if (addrlen == 0)
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      _("Connecting entity unknown"), _("accept"));
      newconn->fd    = -1;
      newconn->state = CONN_FREE;
      sl_close_fd(FIL__, __LINE__, rc);
      SL_RETURN( (-1), _("sh_xfer_accept"));
    }

#ifdef SH_USE_LIBWRAP
  if (check_libwrap(rc, newconn) < 0)
    SL_RETURN( (-1), _("sh_xfer_accept"));
#endif

  memcpy (&(newconn->addr_peer), &addr, sizeof(struct sh_sockaddr));

  /* prepare for usage of connection
   */
  (void) retry_fcntl( FIL__, __LINE__, rc, F_SETFD, 1 );
  newconn->fd           = rc;
  newconn->state        = CONN_READING;
  newconn->timer        = (unsigned long) time (NULL);
  
  if (flag_err_info == S_TRUE)
    sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_CNEW, newconn->fd);

  SL_RETURN( (0), _("sh_xfer_accept"));
}

extern char sh_sig_msg[64];  /* defined in sh_unix.c */

/* ------------  port and interface -------
 */
static unsigned int server_port = SH_DEFAULT_PORT;

int sh_xfer_set_port (const char * str)
{
  int retval = 0;
  unsigned long   i;
  char * endptr;
  
  SL_ENTER(_("sh_xfer_set_port"));
  i = strtoul (str, &endptr, 0);
  if (endptr == str) {
    retval = -1;
  } else if (i > 65535) {
    retval = -1;
  } else {
    server_port = i;
  }
  SL_RETURN( (retval), _("sh_xfer_set_port"));
}

static struct sh_sockaddr server_interface;
static int            use_server_interface = 0;

int sh_xfer_set_interface (const char * str)
{
  if (0 == strcmp(str, _("INADDR_ANY")))
    {
      use_server_interface = 0;
      return 0;
    }

  if (0 == sh_ipvx_aton(str, &server_interface)) 
    {
      use_server_interface = 0;
      return -1;
    }

  use_server_interface = 1;
  return 0;
}

/* ------------  print error --------------
 */
struct sock_err_st {
  char msg[128];
  int  errnum;
  int  port;
  int  line;
  int  euid;
};

static struct sock_err_st sock_err[2];

void sh_xfer_printerr(char * str, int errnum, unsigned int port, int line)
{
  int slot = 0;

  if (port != server_port)
    slot = 1;
  if (str == NULL)
    sock_err[slot].msg[0] = '\0';
  else
    sl_strlcpy(sock_err[slot].msg, str, 128);
  sock_err[slot].errnum = errnum;
  sock_err[slot].port   = port;
  sock_err[slot].line   = line;
  sock_err[slot].euid   = (int) geteuid();
}

int sh_xfer_printerr_final(int slot)
{
  char errbuf[SH_ERRBUF_SIZE];

  SL_ENTER(_("sh_xfer_printerr_final"));
  if (sock_err[slot].msg[0] != '\0')
    {
      dlog(1, FIL__, __LINE__, 
	   _("Could not set up the listening socket for the server because of the\nfollowing error: %s\nPossible reasons include:\n - insufficient privilege for UID %d, or\n - the port %d is already used by another program.\n"),
	   sh_error_message(sock_err[slot].errnum, errbuf, sizeof(errbuf)), 
	   sock_err[slot].euid, 
	   sock_err[slot].port);
      sh_error_handle((-1), FIL__, sock_err[slot].line, 
		      sock_err[slot].errnum, MSG_EXIT_ABORTS,
		      sh_error_message(sock_err[slot].errnum, errbuf, sizeof(errbuf)),
		      sh.prg_name,
		      sock_err[slot].msg);
      SL_RETURN((-1), _("sh_xfer_printerr_final"));
    }
  SL_RETURN(0, _("sh_xfer_printerr_final"));
}

#define  TIME_OUT_DEF 900
static   unsigned long  time_out_val = TIME_OUT_DEF;

int sh_xfer_set_timeout (const char * c)
{
  long val;

  SL_ENTER(_("sh_xfer_set_time_out"));

  val = strtol (c, (char **)NULL, 10);

  if (val == 0)
    {
      val = TIME_OUT_DEF;
    }
  else if (val < 0)
    {
      time_out_val = TIME_OUT_DEF;
      SL_RETURN( (-1), _("sh_xfer_set_time_out"));
    }

  time_out_val = (unsigned long) val;
  SL_RETURN( (0), _("sh_xfer_set_time_out"));
}


static   sh_conn_t        * conns = NULL;
static   int  maxconn = 0;  /* maximum number of simultaneous connections */


#ifdef INET_SYSLOG
#define INET_SUSPEND_TIME 180		/* equal to 3 minutes */
#define SH_MINSOCK_DEFAULT 3
int sh_xfer_syslog_sock[SH_SOCKMAX] = { -1 };
extern int sh_xfer_recv_syslog_socket   (int fd);
int sh_xfer_syslog_sock_n = 0;
#else
#define SH_MINSOCK_DEFAULT 2
#endif

int SH_MINSOCK = SH_MINSOCK_DEFAULT;

extern int pf_unix_fd;

/* the tcp socket, and the function to establish it
 */
static int sh_tcp_sock[SH_SOCKMAX] = { -1 };
static int sh_tcp_sock_n = 0;

static int do_socket(int domain, int type, int protocol,
		     struct sockaddr * sa, int salen)
{
  int sock = -1;
  int errnum = 0;
  int flag   = 1; /* non-zero to enable an option */

  /* create the socket, bind() it and listen()
   */
  if ((sock = socket(domain, type, protocol)) < 0 )
    {
      errnum = errno; 
      sh_xfer_printerr (_("socket"), errnum, server_port, __LINE__);
      return -1;
    }
  (void) retry_fcntl( FIL__, __LINE__, sock, F_SETFD, 1 );
 
  if ( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		  (void *) &flag, sizeof(flag)) < 0 )
    {
      errnum = errno;
      sh_xfer_printerr (_("setsockopt"), errnum, server_port, __LINE__);
      sl_close_fd (FIL__, __LINE__, sock);
      return -1;
    }
  
  if ( bind(sock, (struct sockaddr *) sa, salen) < 0) 
    {
      if (errno != EADDRINUSE)
	{
	  errnum = errno;
	  sh_xfer_printerr (_("bind"), errnum, server_port, __LINE__);
	  sl_close_fd (FIL__, __LINE__, sock);
	  return -1;
	}
      else
	{
	  sl_close_fd (FIL__, __LINE__, sock);
	  return -2;
	}
    }
  
  if ( retry_fcntl( FIL__, __LINE__, sock, F_SETFL, O_NONBLOCK ) < 0 )
    {
      errnum = errno;
      sh_xfer_printerr (_("fcntl"), errnum, server_port, __LINE__);
      sl_close_fd (FIL__, __LINE__, sock);
      return -1;
    }
  
  if ( listen(sock, 64) < 0)
    {
      errnum = errno;
      sh_xfer_printerr (_("listen"), errnum, server_port, __LINE__);
      sl_close_fd (FIL__, __LINE__, sock);
      return -1;
    }

  return sock;
}

int sh_create_tcp_socket (void)
{
#if defined(USE_IPVX)
  struct addrinfo *ai;
  struct addrinfo *p;
  struct addrinfo hints;
  char            port[32];
#else
  struct sockaddr_in addr;
  int addrlen      = sizeof(addr);
#endif

  int sock   = -1;

  SL_ENTER(_("sh_create_tcp_socket"));

  sh_xfer_printerr (NULL, 0, server_port, __LINE__);

#if defined(USE_IPVX)
  if (use_server_interface == 0) /* INADDR_ANY, listen on all interfaces */
    {
      memset (&hints, '\0', sizeof (hints));
      hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_family   = AF_UNSPEC;
      sl_snprintf(port, sizeof(port), "%d", server_port);

      if (getaddrinfo (NULL, port, &hints, &ai) != 0)
	{
	  int errnum = errno;
	  sh_xfer_printerr (_("getaddrinfo"), errnum, server_port, __LINE__);
	  sl_close_fd (FIL__, __LINE__, sock);
	  SL_RETURN((-1), _("sl_create_tcp_socket"));
	}
      
      p = ai;
      
      while (p != NULL && sh_tcp_sock_n < SH_SOCKMAX)
	{
	  sock = do_socket(p->ai_family, p->ai_socktype, p->ai_protocol,
			   p->ai_addr, p->ai_addrlen);
	  
	  if (sock >= 0) {
	    if (sh_tcp_sock_n < SH_SOCKMAX) {
	      sh_tcp_sock[sh_tcp_sock_n] = sock;
	      ++sh_tcp_sock_n;
	    }
	    else {
	      sl_close_fd (FIL__, __LINE__, sock);
	    }    
	  } else if (sock == -1) {
	    freeaddrinfo (ai);
	    goto end;
	  }
	  p = p->ai_next;
	}
      
      freeaddrinfo (ai);
    }
  else
    {
      sh_ipvx_set_port(&server_interface, server_port);

      sock = do_socket(server_interface.ss_family, SOCK_STREAM, 0, 
		       sh_ipvx_sockaddr_cast(&server_interface), 
		       SH_SS_LEN(server_interface));
      
      if (sock >= 0) {
	sh_tcp_sock[0] = sock;
	sh_tcp_sock_n  = 1;
      }
    }	       
#else
  if (use_server_interface == 0)
    addr.sin_addr.s_addr = INADDR_ANY;
  else
    memcpy(&addr, sh_ipvx_sockaddr_cast(&server_interface), addrlen);
  addr.sin_family      = AF_INET;
  addr.sin_port        = htons(server_port);
  
  sock = do_socket(AF_INET, SOCK_STREAM, 0, (struct sockaddr *) &addr, addrlen);

  if (sock >= 0) {
      sh_tcp_sock[0] = sock;
      sh_tcp_sock_n  = 1;
  }

#endif

#if defined(USE_IPVX)
 end:
#endif
  if (sh_tcp_sock_n > 1)
    SH_MINSOCK += (sh_tcp_sock_n - 1);

  SL_RETURN((sh_tcp_sock_n), _("sl_create_tcp_socket"));
}

/*****************************************
 *
 * This is the server main loop.
 *
 * The server is set up for listening, and
 * and starts a select() loop.
 *
 *****************************************/

void sh_xfer_start_server()
{
#ifdef SH_USE_XML
  extern int  sh_log_file    (char * message, char * inet_peer);
#endif

  /* Use volatile to circumvent a gcc4 problem on RH/CentOS 4.8 (?) */
  volatile int       sock = -1;
  sh_conn_t        * cx;
  fd_set             readset;
  fd_set             writeset;
  struct timeval     tv;
  int                num_sel;
  int                errnum;
  int                nowconn;
  int                status;
  int                high_fd = -1;
  register int       i;
  long               dummy = 0;
  unsigned long      time_now;
  unsigned long      time_last = 0;
  unsigned long      time_out = time_out_val;  
  
  time_t told;
  time_t tcurrent;

  unsigned long tchkold;

  int setsize_fd;

  int sock_tcp[2];
  int sock_unix;
#ifdef INET_SYSLOG
  int sock_log[2];
#endif
  
  SL_ENTER(_("sh_xfer_start_server"));

  if ( sh_xfer_printerr_final(0) < 0)
    {
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }

  sock = sh_tcp_sock[0];

  /* ****************************************************************
   *
   * This is a non-forking server. We use select() on the listen()
   * socket to watch for new connections. For new connections, accept()
   * will return a new socket that is put in the read/write filesets.
   * Data about active connections are kept in the 'conns' table. 
   *
   ******************************************************************/
  
  /* The table to hold info on sockets.
   * We reserve 6 file descriptors for misc. use.
   * The POSIX lower limit on open files seems to be eight. 
   */
  maxconn    = get_open_max() - 6;

  /* ugly fix for FreeBSD compiler warning; casting FD_SETSIZE in the
   * conditional expression does not suppress the warning... */
  setsize_fd = (int)FD_SETSIZE;
  maxconn = (setsize_fd < maxconn) ? setsize_fd : maxconn;

  if (maxconn < 0 || !sl_ok_muls(maxconn, sizeof(sh_conn_t)))
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_START_SRV,
		      0, sock);
      aud_exit (FIL__, __LINE__, EXIT_FAILURE);
    }
  conns   = SH_ALLOC (sizeof(sh_conn_t) * maxconn);

  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_START_SRV,
		  (maxconn-1), sock);

  /* timer
   */
  tcurrent                   = (unsigned long) time (NULL);
  told                       = tcurrent;

  tchkold                    = tcurrent;
  
  for (i = SH_MINSOCK; i < maxconn; ++i)
    {
      conns[i].buf         = NULL;
      conns[i].K           = NULL;
      conns[i].A           = NULL;
      conns[i].M1          = NULL;
      conns[i].FileName    = NULL;
      conns[i].fd          = -1;
      sh_xfer_do_free ( &conns[i]);
    }
  
  /* status init
   */
  server_status.conn_open  = 0;
  server_status.conn_total = 0;
  server_status.conn_max   = maxconn-1;
  server_status.start      = time (NULL);
  server_status.last       = (time_t) 0;

  nowconn    = 1;
  tv.tv_sec  = 5;
  tv.tv_usec = 0;
  
  /* conns[0] is the listen() socket. Always in read mode.
   */
  sock = 0;

  sock_tcp[0] = 0;
  while (sock < sh_tcp_sock_n)
    {
      conns[sock].fd    = sh_tcp_sock[sock];
      conns[sock].state = CONN_READING;
      /* high_fd = (sh_tcp_sock[sock] > high_fd) ? sh_tcp_sock[sock] : high_fd; */
      ++sock;
    }
  sock_tcp[1] = sock;
  
  conns[sock].fd    = pf_unix_fd;
  conns[sock].state = CONN_READING;
  /* high_fd = (pf_unix_fd > high_fd) ? pf_unix_fd : high_fd; */

  sock_unix = sock;

  ++sock;

#ifdef INET_SYSLOG
  conns[sock].fd = -1;

  if ( sh_xfer_printerr_final(1) < 0)
    {
      SH_FREE(conns);
      conns = NULL;
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }

  sock_log[0] = sock;
  sock_log[1] = sock;

  if (sh_xfer_syslog_sock_n > 0)
    {
      int s2;
      for (s2 = 0; s2 < sh_xfer_syslog_sock_n; ++s2)
	{
	  conns[sock].fd    = sh_xfer_syslog_sock[s2];
	  conns[sock].state = CONN_READING;
	  /* high_fd = (high_fd > conns[sock].fd) ? high_fd : conns[sock].fd; */
	  ++sock;
	}
      sock_log[1] = sock;

    }
#endif
  
  sh_html_write(all_clients);
  
  /* This is the select() loop.
   */
  while (1 == 1)
    {

    if (sig_raised > 0)
      {
	TPT((0, FIL__, __LINE__, _("msg=<Process a signal.>\n")))

	if (sig_termfast == 1)  /* SIGTERM */
	  {
	    TPT((0, FIL__, __LINE__, _("msg=<Terminate.>\n")));
	    strncpy (sh_sig_msg, _("SIGTERM"), 20);
	    --sig_raised; --sig_urgent;
	    aud_exit (FIL__, __LINE__, EXIT_SUCCESS);
	  }
	  
	if (sig_config_read_again == 1)
	  {
	    TPT((0, FIL__, __LINE__, _("msg=<Re-read configuration.>\n")));
	    sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_RECONF);


	    /* -- Delete the name server cache. --
	     */

	    delete_cache();
#if defined(WITH_EXTERNAL)
	    /* -- Delete list of external tasks. --
	     */
	    (void) sh_ext_cleanup();
#endif
#if defined(SH_WITH_MAIL)
	      sh_nmail_free();
#endif
	    /* - mark all clients dead
	     * - read configuration file
	     * - remove clients still dead
	     */
	    sh_xfer_mark_dead ();

	    reset_count_dev_console();
	    reset_count_dev_time();
	    sl_trust_purge_user();

	    (void) sh_readconf_read ();

	    for (i = SH_MINSOCK; i < maxconn; ++i)
	      if (conns[i].state != CONN_FREE   && 
		  conns[i].client_entry != NULL &&
		  conns[i].client_entry->dead_flag == 1)
		sh_xfer_do_free ( &conns[i]);
	    sh_xfer_clean_tree ();

	    sig_config_read_again = 0;
	    --sig_raised;
	  }

	if (sig_fresh_trail == 1) /* SIGIOT */
	  {
	    /* Logfile access 
	     */
#ifdef SH_USE_XML
	    sh_log_file (NULL, NULL);
#endif
	    TPT((0, FIL__, __LINE__, _("msg=<Logfile stop/restart.>\n")));
	    sh_error_only_stderr (S_TRUE);
	    sh_unix_rm_lock_file(sh.srvlog.name);
	    retry_msleep(3, 0);
	    sh.flag.log_start = S_TRUE;
	    sh_error_only_stderr (S_FALSE);
	    sig_fresh_trail       = 0;
	    --sig_raised;
	  }
	
	  
	if (sig_terminate == 1 && nowconn < 2)  /* SIGQUIT */
	  {
	    TPT((0, FIL__, __LINE__, _("msg=<Terminate.>\n")));
	    strncpy (sh_sig_msg, _("SIGQUIT"), 20);
	    --sig_raised; --sig_urgent;
	    aud_exit (FIL__, __LINE__, EXIT_SUCCESS);
	  }
	
	  
	if (sig_debug_switch == 1)  /* SIGUSR1 */
	  {
	    TPT((0, FIL__, __LINE__, _("msg=<Debug switch.>\n")));
	    sh_error_dbg_switch();
	    sig_debug_switch = 0;
	    --sig_raised;
	  }
	
	if (sig_suspend_switch > 0)  /* SIGUSR2 */
	  {
	    TPT((0, FIL__, __LINE__, _("msg=<Suspend switch.>\n")));
	    if (sh_global_suspend_flag == 1) {
	      sh_global_suspend_flag = 0;
	    } else {
	      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_SUSPEND, 
			      sh.prg_name);
	      sh_global_suspend_flag = 1;
	    }
	    --sig_suspend_switch;
	    --sig_raised; --sig_urgent;
	  }

	sig_raised = (sig_raised < 0) ? 0 : sig_raised;
	sig_urgent = (sig_urgent < 0) ? 0 : sig_urgent;
	TPT((0, FIL__, __LINE__, _("msg=<End signal processing.>\n")));
      }
      
      if (sh_global_suspend_flag == 1)
	{
	  (void) retry_msleep (1, 0);
	  continue;
	}

      /* Recompute the descriptor set. select() modifies it,
       * thus we update it using the info from the connection table.
       * Also recompute the number of open connections.
       */
      FD_ZERO( &readset );
      FD_ZERO( &writeset );
      high_fd = conns[0].fd;

      for (sock = sock_tcp[0]; sock < sock_tcp[1]; ++sock)
	{
	  FD_SET(conns[sock].fd, &readset );
	  high_fd   = (high_fd > conns[sock].fd) ? high_fd : conns[sock].fd;
	}

      if (conns[sock_unix].fd > -1)
	{
	  FD_SET(conns[sock_unix].fd, &readset );
	  high_fd   = (high_fd > conns[sock_unix].fd) ? high_fd : conns[sock_unix].fd;
	}

#ifdef INET_SYSLOG
      for (sock = sock_log[0]; sock < sock_log[1]; ++sock)
	{
	  if (conns[sock].fd > -1)
	    {
	      FD_SET(conns[sock].fd, &readset );
	      high_fd   = (high_fd > conns[sock].fd) ? high_fd : conns[sock].fd;
	    }
	}
#endif

      time_now  = (unsigned long) time (NULL);
      nowconn   = 1;
      
      for (i = SH_MINSOCK; i < maxconn; ++i)
	{
	  /* eliminate timed out connections
	   */
	  if (conns[i].state != CONN_FREE) 
	    {
	      if (time_now-conns[i].timer > time_out)
		{
		  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_TIMOUT,
				  conns[i].peer);
		  sh_xfer_do_free ( &conns[i]);
		}
	      else
		++nowconn;
	    }
	  
	  
	  if       (conns[i].state   == CONN_READING)
	    { 
	      FD_SET(conns[i].fd, &readset);
	      high_fd = (high_fd < conns[i].fd ? conns[i].fd : high_fd);
	    }
	  else if  (conns[i].state   == CONN_SENDING)
	    {
	      FD_SET(conns[i].fd, &writeset);
	      high_fd = (high_fd < conns[i].fd ? conns[i].fd : high_fd);
	    }
	}

      /* -- Exponentially reduce timeout limit if more than 1/2 full. --
       */
      /* Eliminate this, will cause problems when too much clients are
       * starting up. */
#if 0
      if (nowconn > (maxconn/2))
	time_out = ( (time_out/2) > 1) ? (time_out/2) : 1;
      else
	time_out = time_out_val;
#endif
      
      
      /* -- Do the select(). --
       */
      num_sel = select(high_fd+1, &readset, &writeset, NULL, &tv);
      errnum  = errno;
      
      /* reset timeout - modified by select() on some systems
       */
      tv.tv_sec  = 5;
      tv.tv_usec = 0;
      

      if ( (time_now - time_last) > 2L)
	{
	  time_last = time_now;
	  if (sh_html_write(all_clients) < 0)
	    sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_HTML);
	}
      
      
      /* Error handling.
       */
      if ( num_sel < 0 )        /* some error             */
	{
	  char errbuf[SH_ERRBUF_SIZE];

	  if (sig_raised == 1)
	    {
	      sig_raised = 2;
	      continue;
	    }

	  if ( errnum == EINTR)
	    continue;	  /* try again              */

	  if ( errnum == EBADF)
	    {
	      /* seek and destroy the bad fd
	       */
	      for (i = SH_MINSOCK; i < high_fd; ++i)
		{
		  if ((conns[i].state == CONN_READING) ||
		      (conns[i].state == CONN_SENDING))
		    {
		      if (-1 == retry_fcntl(FIL__, __LINE__, 
					    conns[i].fd, F_GETFL, dummy))
			sh_xfer_do_free ( &conns[i]);
		    }
		}
	      continue;
	    }

	  sh_error_handle((-1), FIL__, __LINE__, errnum, MSG_EXIT_ABORTS,
			  sh_error_message(errnum, errbuf, sizeof(errbuf)), 
			  sh.prg_name,
			  _("select"));
	  aud_exit(FIL__, __LINE__,  EXIT_FAILURE );
	}
      

      /* log the timestamp
       */
      if ((tcurrent - told) > sh.looptime )
	{
	  told = tcurrent;
#ifdef MEM_DEBUG
	  sh_mem_check();
	  sh_unix_count_mlock();
#else
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_STAMP);
#endif
	}

#if defined(SH_WITH_MAIL)
      /* 
       * flush the mail queue
       */
      if (tcurrent - sh.mailTime.alarm_last > sh.mailTime.alarm_interval) 
	{
	  TPT((0, FIL__, __LINE__, _("msg=<Flush mail queue.>\n")))
	  (void) sh_nmail_flush ();
	  sh.mailTime.alarm_last = tcurrent;
	}
#endif
#ifdef MEM_DEBUG
      sh_mem_dump();
#endif

      tcurrent = (unsigned long) time (NULL);

      /* check for time limit exceeded
       */
      if ((tcurrent - tchkold) > (unsigned int) 3 )
	{
	  tchkold = tcurrent;
	  client_time_check(/* all_clients */);
	  /* reset cache */
	  sh_userid_destroy();
	}
      
      /* seed / re-seed the PRNG if required
       */
      (void) taus_seed();

      /* select() timeout handling.
       */
      if ( num_sel == 0 )       /* timeout - no connection */ 
	{
	  if (sh_html_write(all_clients) < 0)
	    sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_HTML);
	  continue;
	}

      /* New connection.
       */
      for (sock = sock_tcp[0]; sock < sock_tcp[1]; ++sock)
	{
	  if ( FD_ISSET(conns[sock].fd , &readset )) /* a new connection   */
	    {
	      --num_sel;
	      status = 0;
	      if (nowconn < maxconn && sig_terminate == 0 && sig_termfast == 0)
		{
		  /* Find a free slot to accept the connection
		   */
		  i = SH_MINSOCK;
		  while (i < maxconn)
		    {
		      if (conns[i].state == CONN_FREE)
			{
			  /* Here we run the accept() and copy the peer to
			   * the free slot. 
			   */
			  status = sh_xfer_accept(conns[sock].fd, &conns[i]);
			  
			  if (status == 0)
			    {
			      high_fd = 
				(high_fd > conns[i].fd ? high_fd : conns[i].fd);
			      ++server_status.conn_open;
			      ++server_status.conn_total;
			      server_status.last = time (NULL);
			    }
			  break;
			}
		      ++i;
		    }
		}
	      /* This re-runs select to accept data on the new
	       * connection, rather than first dealing with old
	       * connections.
	       */
	      if (status == 0) 
		continue;
	    }
	}
      
      /* check for commands on the socket
       */
      if (conns[sock_unix].fd > (-1) && FD_ISSET(conns[sock_unix].fd , &readset ))
	{
	  sh_socket_poll();
	}

#ifdef INET_SYSLOG
      for (sock = sock_log[0]; sock < sock_log[1]; ++sock)
	{
	  if (conns[sock].fd > (-1) && FD_ISSET(conns[sock].fd , &readset ))
	    {
	      sh_xfer_recv_syslog_socket (conns[sock].fd);
	    }
	}
#endif

      /* Check for pending read/write on the rest of the sockets.
       */
      for ( i = SH_MINSOCK; num_sel > 0 && i < maxconn; ++i )
	{
	  if (sig_termfast == 1)
	    break;

	  cx = &conns[i];
	  if ( cx->state == CONN_READING &&
	       FD_ISSET( cx->fd, &readset ) )
	    {
	      --num_sel;
	      sh_xfer_do_read ( cx );
	    }
	  else if ( cx->state == CONN_SENDING &&
		    FD_ISSET( cx->fd, &writeset ) )
	    {
	      --num_sel;
	      sh_xfer_do_write ( cx );
	    }
	}
      /* continue */
    }
  /* notreached */
}

void  free_client_tree (void)
{
  SL_ENTER(_("free_client_tree"));
  zAVLFreeTree (all_clients, free_client);
  SL_RET0(_("free_client_tree"));
}

void sh_xfer_free_all ()
{
  register int i;
  
  SL_ENTER(_("sh_xfer_free_all"));

  if (conns != NULL)
    for (i = SH_MINSOCK; i < maxconn; ++i)
      {
	sh_xfer_do_free ( &conns[i]);
      }


  free_client_tree ();

  if (conns != NULL)
    SH_FREE (conns);

  SL_RET0(_("sh_xfer_free_all"));
}



/* #ifdef SH_WITH_SERVER */
#endif


  



