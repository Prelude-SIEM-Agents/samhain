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
#include <ctype.h>

/* Must be early on FreeBSD
 */
#include <sys/types.h>

#ifdef HAVE_MEMORY_H
#include <memory.h>
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

#include <sys/socket.h>

#ifdef  HOST_IS_HPUX
#define _XOPEN_SOURCE_EXTENDED
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

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

#define SH_REAL_SET

#include "samhain.h"
#include "sh_mem.h"
#include "sh_error.h"
#include "sh_tools.h"
#include "sh_utils.h"
#include "sh_tiger.h"
#define SH_NEED_GETHOSTBYXXX
#include "sh_static.h"
#include "sh_pthread.h"
#include "sh_ipvx.h"

#undef  FIL__
#define FIL__  _("sh_tools.c")

static int tools_debug = 0;

#ifdef SH_ENCRYPT
#include "rijndael-api-fst.h"
char * errorExplain (int err_num, char * buffer, size_t len)
{
  char * p;

  if      (err_num == BAD_KEY_DIR)
    p = (_("Key direction is invalid"));
  else if (err_num == BAD_KEY_MAT) 
    p = (_("Key material not of correct length"));
  else if (err_num == BAD_KEY_INSTANCE) 
    p = (_("Key passed is not valid"));
  else if (err_num == BAD_CIPHER_MODE) 
    p = (_("Params struct passed to rijndael_cipherInit invalid"));
  else if (err_num == BAD_CIPHER_STATE) 
    p = (_("Cipher in wrong state"));
  else if (err_num == BAD_BLOCK_LENGTH) 
    p = (_("Bad block length"));
  else if (err_num == BAD_CIPHER_INSTANCE) 
    p = (_("Bad cipher instance"));
  else if (err_num == BAD_DATA) 
    p = (_("Data contents are invalid"));
  else  
    p = (_("Unknown error"));
  sl_strlcpy (buffer, p, len);
  return buffer;
}

#endif

/* --- check for an interface ---
 */
int sh_tools_iface_is_present(char *str)
{
#if defined(USE_IPVX)
  struct addrinfo *ai;
  struct addrinfo hints;
  int             res;

  memset (&hints, '\0', sizeof (hints));
  hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
  hints.ai_socktype = SOCK_STREAM;
  res = getaddrinfo (str, _("2543"), &hints, &ai);
  
  if (res == 0)
    {
      struct addrinfo *p = ai;
      while (p != NULL)
	{
	  int fd = socket (p->ai_family, p->ai_socktype,
			   p->ai_protocol);

	  if (fd < 0)
	    {
	      freeaddrinfo (ai);
	      return 0;
	    }

	  if (bind (fd, p->ai_addr, p->ai_addrlen) != 0)
	    {
	      /* bind() fails for access reasons, iface exists
	       */
	      if (errno == EACCES || errno == EADDRINUSE)
		{
		  sl_close_fd (FIL__, __LINE__, fd);
		  freeaddrinfo (ai);
		  return 1;
		}

	      sl_close_fd (FIL__, __LINE__, fd);
	      freeaddrinfo (ai);
	      return 0;
	    }

	  sl_close_fd (FIL__, __LINE__, fd);
	  freeaddrinfo (ai);
	  return 1;
	  /* p = p->ai_next; */ 
	}
    }
#else
  struct sockaddr_in sin;
  int sd;

  memset(&sin, '\0', sizeof(sin));
  sin.sin_family = AF_INET;
  if (inet_aton(str, &(sin.sin_addr)))
    {
      sin.sin_port = htons(2543);

      if (-1 == (sd = socket(AF_INET, SOCK_STREAM, 0)))
	{
	  return 0;
	}

      if (-1 == bind(sd, (struct sockaddr *)&sin, sizeof(sin)))
	{
	  int retval = 0;

	  /* bind() fails for access reasons, iface exists
	   */
	  if (errno == EACCES || errno == EADDRINUSE)
	    retval = 1;
	  sl_close_fd (FIL__, __LINE__, sd);
	  return retval;
	}

      /* bind() succeeds, iface exists
       */
      sl_close_fd(FIL__, __LINE__, sd);
      return 1;
    }
#endif
  return 0;
}

/* --- recode all \blah escapes to qp (quoted printable) '=XX' format, and 
 *     also code all remaining unprintable chars                           ---
 */
#define SH_PUT_4(p, a, b, c) (p)[0] = (a); (p)[1] = (b); (p)[2] = (c);
  
char * sh_tools_safe_name (const char * instr, int flag)
{
  unsigned char c, d;
  const  char * p;
  char   tmp[4];
  char * outstr;
  size_t len = 1;
  int    i = 0;
  unsigned char   val_octal = '\0';
  static char ctable[16] = { '0', '1', '2', '3', '4', '5', '6', '7', 
			     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' }; 

  SL_ENTER(_("sh_tools_safe_name"));

  if (instr)
    {
      len = strlen(instr);
      if (sl_ok_muls (3, len) && sl_ok_adds ((3*len), 4))
	{
	  len = (3 * len) + 4;
	  p = instr;
	}
      else
	{
	  len = 1;
	  p   = NULL;
	}
    }
  else
    {
      p = NULL;
    }

  outstr = SH_ALLOC(len);

  outstr[0] = '\0';
  tmp[3]    = '\0';

#if !defined(SH_USE_XML)
  (void) flag; /* fix compiler warning */
#endif

  if (!p)
    goto end;

  while (*p)
    {
      c = *p;

      if (*p == '\n')
	{
	  outstr[i] = ' '; ++i; ++p;
	  continue;
	}

#ifdef SH_USE_XML
      if (flag == 1)
	{
	  if ((*p) == '"')
	    { 
	      SH_PUT_4(&outstr[i], '=', '2', '2');
	      i+=3; ++p;
	      continue;
	    } 
	  else if ((*p) == '&')
	    { 
	      SH_PUT_4(&outstr[i], '=', '2', '6');
	      i+=3; ++p;
	      continue;
	    } 
	  else if ((*p) == '<') 
	    {     /* left angle       */
	      SH_PUT_4(&outstr[i], '=', '3', 'c');
	      i+=3; ++p;
	      continue;
	    } 
	  else if ((*p) == '>') 
	    {     /* right angle      */
	      SH_PUT_4(&outstr[i], '=', '3', 'e');
	      i+=3; ++p;
	      continue;
	    }
	}
#endif

      if ( (*p) != '\\' && (*p) != '&' && (*p) != '='  && (*p) != '\'') 
        {
	  outstr[i] = *p; ++i;
	  ++p;
	      
	  if (c < 32 || c > 126)
	    {
	      --i;
	      d = c % 16; c = c / 16;
	      outstr[i] = '=';       ++i;
	      outstr[i] = ctable[c]; ++i;
	      outstr[i] = ctable[d]; ++i;
	    }

	  continue;
	}
      else if ((*p) == '\'')
	{
	  SH_PUT_4(&outstr[i], '=', '2', '7');
	  i+=3; ++p;
	}
      else if (*p == '=')
	{
	  if (p[1] != '"' && p[1] != '<')
	    { 
	      SH_PUT_4(&outstr[i], '=', '3', 'd');
	      i+=3; ++p;
	    }
	  else
	    { outstr[i] = *p; ++i; ++p; }
	}
      else if (*p == '\\')
	{
	  ++p;
	  if (!p)
	    break;
	  if (!(*p))
	    break;



	  switch (*p) {
	  case '\\':
	    SH_PUT_4(&outstr[i], '=', '5', 'c');
	    i+=3; ++p;
	    break;
	  case 'n':
	    SH_PUT_4(&outstr[i], '=', '0', 'a');
	    i+=3; ++p;
	    break;
	  case 'b':
	    SH_PUT_4(&outstr[i], '=', '0', '8');
	    i+=3; ++p;
	    break;		       
	  case 'r':		       
	    SH_PUT_4(&outstr[i], '=', '0', 'd');
	    i+=3; ++p;
	    break;		       
	  case 't':		       
	    SH_PUT_4(&outstr[i], '=', '0', '9');
	    i+=3; ++p;
	    break;		       
	  case 'v':		       
	    SH_PUT_4(&outstr[i], '=', '0', 'b');
	    i+=3; ++p;
	    break;		       
	  case 'f':		       
	    SH_PUT_4(&outstr[i], '=', '0', 'c');
	    i+=3; ++p;
	    break;		       
	  case '\'':		       
	    SH_PUT_4(&outstr[i], '=', '2', '7');
	    i+=3; ++p;
	    break;		       
	  case '"':	/* also encode quoted '"' */ 	       
	    SH_PUT_4(&outstr[i], '=', '2', '2');
	    i+=3; ++p;
	    break;		       
	  case ' ':		       
	    SH_PUT_4(&outstr[i], '=', '2', '0');
	    i+=3; ++p;
	    break;
	  default:
	    if (strlen(p) < 3) /* certainly not an octal number, skip */
	      {
		p += strlen(p);
	      }
	    else
	      {
		tmp[0] = p[0]; tmp[1] = p[1]; tmp[2] = p[2]; 
		val_octal = (unsigned char) strtoul(tmp, (char **)NULL, 8);
		if (val_octal != '\0') { 
		  c = val_octal;
		  d = c % 16; c = c / 16;
		  outstr[i] = '=';       ++i;
		  outstr[i] = ctable[c]; ++i;
		  outstr[i] = ctable[d]; ++i;
		} 
		p += 3;
	      }
	  }
	}
      else if (*p == '&')
	{
	  ++p;
	  if (!p || !(*p))
	    {
	      outstr[i] = '&'; ++i;
	      break;
	    }

	  if (p[0] == 'a' && p[1] == 'm' && p[2] == 'p' && p[3] == ';')
	    {
	      SH_PUT_4(&outstr[i], '=', '2', '6');
	      i+=3; p += 4;
	    }
	  else if (p[0] == 'q' && p[1] == 'u' && p[2] == 'o' && p[3] == 't' &&
		   p[4] == ';')
	    {
	      SH_PUT_4(&outstr[i], '=', '2', '2');
	      i+=3; p += 5;
	    }
	  else if (p[0] == 'l' && p[1] == 't' && p[2] == ';')
	    {
	      SH_PUT_4(&outstr[i], '=', '3', 'c');
	      i+=3; p += 3;
	    }
	  else if (p[0] == 'g' && p[1] == 't' && p[2] == ';')
	    {
	      SH_PUT_4(&outstr[i], '=', '3', 'e');
	      i+=3; p += 3;
	    }
	  else /* conserve the '&' */
	    {
	      outstr[i] = '&'; ++i;
	    }
	}
      else
	{
	  outstr[i] = *p; ++i;
	  ++p;
	}
    } /* while (p && *p) */

 end:
  
  outstr[i] = '\0';
  SL_RETURN( outstr, _("sh_tools_safe_name"));
}


/* extern int h_errno; */ 

char * sh_tools_errmessage (int tellme, char * errbuf, size_t len)
{
  char * p = NULL;
#ifdef HOST_NOT_FOUND
    if (tellme == HOST_NOT_FOUND)  
      p = _("The specified host is unknown: ");
#endif
#ifdef NO_ADDRESS
    if (tellme == NO_ADDRESS)  
      p = _("The requested name is valid but does not have an IP address: ");
#endif
#ifdef NO_RECOVERY
    if (tellme == NO_RECOVERY)  
      p = _("A non-recoverable name server error occurred: ");
#endif
#ifdef TRY_AGAIN
    if (tellme == TRY_AGAIN)  
      p = _("A temporary error occurred on an authoritative name server. The specified host is unknown: ");
#endif
    if (!p) p =  _("Unknown error");
    sl_strlcpy(errbuf, p, len);
    return errbuf;
}

#if defined (SH_WITH_SERVER)

int get_open_max ()
{
  int value;

#ifdef _SC_OPEN_MAX
  value = sysconf (_SC_OPEN_MAX);
#else
#ifdef OPEN_MAX
  value = OPEN_MAX;
#else
  value = _POSIX_OPEN_MAX;
#endif
#endif

  if (value < 0)
    value = 8;  /* POSIX lower limit */

  if (value > 4096)
    value = 4096;

  return value;
}

#endif

typedef struct _sin_cache {
  char * address;
  struct sh_sockaddr  saddr;
  struct _sin_cache * next;
} sin_cache;

static sin_cache * conn_cache = NULL;
static int cached_addr = 0;

void delete_cache()
{
  sin_cache * check_cache = conn_cache;
  sin_cache * old_entry;

  SL_ENTER(_("delete_cache"));

  while (check_cache != NULL)
    {
      old_entry   = check_cache;
      check_cache = check_cache->next;
      SH_FREE(old_entry->address);
      SH_FREE(old_entry);
    }

  cached_addr = 0;

  conn_cache = NULL;
  SL_RET0(_("delete_cache"));
}
      
int DoReverseLookup = S_TRUE;

int set_reverse_lookup (const char * c)
{
  return sh_util_flagval(c, &DoReverseLookup);
}

#if !defined(USE_IPVX)
int connect_port (char * address, int port, 
		  char * ecall, int * errnum, char * errmsg, int errsiz)
{
  struct in_addr       haddr;   /* host address from numeric                */
                                /* host details returned by the DNS         */
  struct hostent *host_entry = NULL;   
  struct sockaddr_in sinr;      /* socket to the remote host                */

  char   * host_name;

  volatile int    fd = (-1);
  int    status;
  volatile int    fail   = 0;
  int    cached = 0;

  int    retval;
  char   errbuf[SH_ERRBUF_SIZE];

  sin_cache * check_cache = conn_cache;

  SL_ENTER(_("connect_port"));

  if (tools_debug)
    fprintf(stderr, _("-00- <%s> <%d> no IPv6 support\n"), address, port);

  if (errsiz > 0) errmsg[0] = '\0';

  /* paranoia -- should not happen
   */
  if (cached_addr > 128)
    delete_cache();

  if (check_cache != NULL)
    {
      while (check_cache && check_cache->address)
	{
          if (tools_debug)
            fprintf(stderr, _("-01- <%s> <%s>\n"), 
                    address, check_cache->address);

	  if ( 0 == sl_strncmp(check_cache->address, 
			       address, sl_strlen(address)) )
	    {
	      memcpy (&sinr, &((check_cache->saddr).sin), sizeof(struct sockaddr_in));
	      sinr.sin_family = AF_INET;
	      sinr.sin_port   = htons (port);
	      cached = 1;
	      break;
	    }
	  if (tools_debug)
	    {
	      char eaddr[SH_IP_BUF];
	      sl_strlcpy(eaddr, 
			 inet_ntoa(*(struct in_addr *) &(sinr.sin_addr)), 
			 sizeof(eaddr));
	      fprintf(stderr, _("-02- <AF_INET> <%s> <%d> <%d>\n"), 
		      eaddr,
		      port, cached);
	    }
	  if (check_cache->next)
	    check_cache = check_cache->next;
	  else
	    check_cache = NULL;
	}
    }

  /* only use gethostbyname() if neccessary
   */
  if (cached == 0)
    {
      if (tools_debug)
        fputs(_("-03- not cached\n"), stderr); 
#ifdef HAVE_INET_ATON
      if (0 == inet_aton(address, &haddr))
#else
      if ((unsigned long)-1  == (haddr.s_addr = inet_addr(address)))
#endif
	{
	  SH_MUTEX_LOCK(mutex_resolv);

	  host_name = NULL;

	  host_entry = sh_gethostbyname(address);

	  if (host_entry == NULL || host_entry->h_addr == NULL) 
	    {
	      sl_strlcpy(ecall, _("gethostbyname"), SH_MINIBUF);
#ifndef NO_H_ERRNO
	      *errnum = h_errno;
#else
	      *errnum = 666;
#endif
	      (void) sh_tools_errmessage (*errnum, errmsg, errsiz);
	      sl_strlcat(errmsg, address, errsiz); 
	      fail = (-1);
	    }
	  else
	    {
	      sinr.sin_family = AF_INET;
	      sinr.sin_port   = htons (port);
	      sinr.sin_addr   = *(struct in_addr *) host_entry->h_addr;

	      if (tools_debug)
                fprintf(stderr, 
			_("-04- <%s> <%s> hostent->h_name %s <%s> hostent->h_addr\n"), 
                        address, 
			(host_entry->h_name == NULL) ? _("NULL") : host_entry->h_name,
			(host_entry->h_addrtype == AF_INET) ? _("AF_INET") : _("AF_INET6"),
			inet_ntoa(*(struct in_addr *) &(sinr.sin_addr)));

	      /* reverse DNS lookup
	       */
	      if (DoReverseLookup == S_TRUE)
		{
		  if (host_entry->h_name == NULL)
		    {
		      host_name = SH_ALLOC(1);
		      host_name[0] = '\0';
		    }
		  else
		    {
		      host_name = sh_util_strdup(host_entry->h_name);
		    }

		  host_entry = sh_gethostbyaddr ((char *) &sinr.sin_addr, 
					      sizeof(struct in_addr),
					      AF_INET);
		  if (host_entry == NULL || host_entry->h_name == NULL)
		    {
		      sl_strlcpy(ecall, _("gethostbyaddr"), SH_MINIBUF);
#ifndef NO_H_ERRNO
		      *errnum = h_errno;
#else
		      *errnum = 666;
#endif
		      (void) sh_tools_errmessage (*errnum, errmsg, errsiz);
		      sl_strlcat(errmsg, 
				 inet_ntoa (*(struct in_addr *) &(sinr.sin_addr)),
				 errsiz); 
		      fail = (-1);
		    }
		  else
		    {
		      *errnum = 0;
		      if (sl_strlen(host_entry->h_name) == 0 || 
			  (*errnum = sl_strcasecmp(host_name,host_entry->h_name)) != 0)
			{ 
			  if (*errnum)
			    sl_strlcpy(ecall, _("strcmp"), SH_MINIBUF);
			  else
			    sl_strlcpy(ecall, _("strlen"), SH_MINIBUF);
			  sl_strlcpy(errmsg, _("Reverse lookup failed: "), 
				     errsiz);
			  sl_strlcat(errmsg, address, errsiz);
			  sl_strlcat(errmsg, _(" vs "), errsiz);
			  sl_strlcat(errmsg, 
				     inet_ntoa (*(struct in_addr *) &(sinr.sin_addr)),
				     errsiz);
			  fail = -1;
			}
		    }
		}
	    }
	  SH_MUTEX_UNLOCK(mutex_resolv);
	  if (host_name) SH_FREE(host_name);
	}
  
      else  /* address was numeric */
	{
	  sinr.sin_family = AF_INET;
	  sinr.sin_port   = htons (port);
	  sinr.sin_addr   = haddr;

	  if (tools_debug)
	    fprintf(stderr, 
		    _("-04- <%s> is_numeric AF_INET <%s> \n"), 
		    address, 
		    inet_ntoa(*(struct in_addr *) &(sinr.sin_addr)));
	}


      if (fail != -1)
	{
	  /* put it into the cache
	   */
	  check_cache          = SH_ALLOC(sizeof(sin_cache));
	  check_cache->address = SH_ALLOC(sl_strlen(address) + 1);
	  sl_strlcpy (check_cache->address, address, sl_strlen(address) + 1);

	  sh_ipvx_save(&(check_cache->saddr), AF_INET, (struct sockaddr *) &sinr);

	  ++cached_addr;
	  
	  if (conn_cache)
	    {
	      if (conn_cache->next)
		check_cache->next    = conn_cache->next;
	      else
		check_cache->next    = NULL;
	      conn_cache->next     = check_cache;
	    }
	  else
	    {
	      check_cache->next    = NULL;
	      conn_cache           = check_cache;
	    }
	}
    }

  
  if (fail != (-1)) 
    { 
      fd = socket(AF_INET, SOCK_STREAM, 0);
      if (fd < 0) {
	fail   = (-1);
	status = errno;
	sl_strlcpy(ecall, _("socket"), SH_MINIBUF);
	*errnum = status;
	sl_strlcpy(errmsg, sh_error_message (status, errbuf, sizeof(errbuf)), errsiz);
	sl_strlcat(errmsg, _(", address "), errsiz);
	sl_strlcat(errmsg, address, errsiz);
      }
    }
  
  if (fail != (-1)) {
    
    if ( retry_connect(FIL__, __LINE__, fd, 
		       (struct sockaddr *) &sinr, sizeof(sinr)) < 0) 
      {
	status = errno;
	sl_strlcpy(ecall, _("connect"), SH_MINIBUF);
	*errnum = status;
	sl_strlcpy(errmsg, sh_error_message (status, errbuf, sizeof(errbuf)), errsiz);
	sl_strlcat(errmsg, 
		   (sinr.sin_family == AF_INET) ? _(", AF_INET ") : _(", AF_INET6 "),
		   errsiz);
	sl_strlcat(errmsg, _(", address "), errsiz);
	sl_strlcat(errmsg, address, errsiz);
	sl_close_fd(FIL__, __LINE__, fd);
	fail = (-1); 
      }
  }

  retval = (fail < 0) ? (-1) : fd;
  SL_RETURN(retval, _("connect_port"));
}
#else
int connect_port (char * address, int port, 
		  char * ecall, int * errnum, char * errmsg, int errsiz)
{
  struct sockaddr_in *sin;
  struct sockaddr_in6 *sin6;
  struct sh_sockaddr ss;
  sin_cache * check_cache = conn_cache;
  int    cached = 0;
  int    fail   = 0;
  int    fd     = -1;
  int    status = 0;

  int    retval;
  char   errbuf[SH_ERRBUF_SIZE];

  SL_ENTER(_("connect_port"));

  /* paranoia -- should not happen
   */
  if (cached_addr > 128)
    delete_cache();

  if (tools_debug)
    fprintf(stderr, _("-00- <%s> <%d>\n"), address, port);

  if (check_cache != NULL)
    {
      while (check_cache && check_cache->address)
	{
	  if (tools_debug)
	    fprintf(stderr, _("-01- <%s> <%s>\n"), 
		    address, check_cache->address);

	  if ( 0 == sl_strcmp(check_cache->address, address) )
	    {
	      memcpy (&ss, &(check_cache->saddr), sizeof(struct sh_sockaddr));
	      switch (ss.ss_family) 
		{
		case AF_INET:
		  sin = &(ss.sin);
		  sin->sin_port   = htons (port);
		  cached = 1;
		  break;
		case AF_INET6:
		  sin6 = &(ss.sin6);
		  sin6->sin6_port  = htons (port);
		  cached = 1;
		  break;
		default:
		  break;
		}
	      if (tools_debug)
		{
		  char eaddr[SH_IP_BUF];
		  sh_ipvx_ntoa(eaddr, sizeof(eaddr), &ss);
		  fprintf(stderr, _("-02- <%s> <%s> <%d> <%d>\n"), 
			  (ss.ss_family == AF_INET) ? _("AF_INET") : _("AF_INET6"),
			  eaddr,
			  port, cached);
		}
	      break;
	    }
	  if (check_cache->next)
	    check_cache = check_cache->next;
	  else
	    check_cache = NULL;
	}
    }

  if (cached != 0)
    {
      if (tools_debug)
	fputs(_("-03- cached\n"), stderr); 
      fd = socket(ss.ss_family, SOCK_STREAM, 0);
      if (fd < 0) 
	{
	  status = errno;
	  fail   = (-1);
	  sl_strlcpy(ecall, _("socket"), SH_MINIBUF);
	  *errnum = status;
	  sl_strlcpy(errmsg, sh_error_message (status, errbuf, sizeof(errbuf)), errsiz);
	  sl_strlcat(errmsg, _(", address "), errsiz);
	  sl_strlcat(errmsg, address, errsiz);
	}


      if (fail != (-1)) 
	{
	  int addrlen = SH_SS_LEN(ss);
	
	  if ( retry_connect(FIL__, __LINE__, fd, 
			     sh_ipvx_sockaddr_cast(&ss), addrlen) < 0) 
	    {
	      status = errno;
	      sl_strlcpy(ecall, _("connect"), SH_MINIBUF);
	      *errnum = status;
	      sl_strlcpy(errmsg, sh_error_message (status, errbuf, sizeof(errbuf)), errsiz);
	      sl_strlcat(errmsg, _(", address "), errsiz);
	      sl_strlcat(errmsg, address, errsiz);
	      sl_close_fd(FIL__, __LINE__, fd);
	      fail = (-1); 
	    }
	}

      if (fail != 0)
	{
	  delete_cache();
	  cached = 0;
	}
    }

  if (cached == 0)
    {
      int    res;
      char   sport[32];
      struct addrinfo *ai;
      struct addrinfo hints;

      if (tools_debug)
	fputs(_("-03- not cached\n"), stderr);

      memset (&hints, '\0', sizeof (hints));
      hints.ai_flags = AI_ADDRCONFIG;
#if defined(AI_CANONNAME)
      hints.ai_flags |= AI_CANONNAME;
#endif 
      hints.ai_family   = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      sl_snprintf(sport, sizeof(sport), "%d", port);

      res = getaddrinfo (address, sport, &hints, &ai);
      if (res != 0)
	{
	  fail = (-1);
	  status = errno;
	  sl_strlcpy(ecall, _("getaddrinfo"), SH_MINIBUF);
	  *errnum = status;
	  sl_strlcpy(errmsg, gai_strerror (res), errsiz);
	  sl_strlcat(errmsg, _(", address "), errsiz);
	  sl_strlcat(errmsg, address, errsiz);
	}

      if (fail != (-1) && (DoReverseLookup == S_TRUE) && !sh_ipvx_is_numeric(address))
	{
	  struct addrinfo *p = ai;
	  int    success = 0;
	  char hostname[SH_BUFSIZE];
	  const char * canonical;


#if defined(AI_CANONNAME)
	  if (ai->ai_canonname && strlen(ai->ai_canonname) > 0)
	    {
	      canonical = ai->ai_canonname;
	      if (tools_debug)
		fprintf(stderr, _("-04- <%s> <%s> ai->ai_canonname\n"), 
			address, canonical);
	    }
	  else
	    {
	      canonical = address;
	      if (tools_debug)
		fprintf(stderr, _("-04- <%s> <%s> defined ai_canonname\n"), 
			address, canonical);
	    }
#else
	  canonical = address;
	  if (tools_debug)
	    fprintf(stderr, _("-04- <%s> <%s> not defined ai_canonname\n"), 
		    address, canonical);
#endif

	  while (p != NULL)
	    {
	      int e = getnameinfo (p->ai_addr, p->ai_addrlen, 
				   hostname, sizeof(hostname),
				   NULL, 0, NI_NAMEREQD);
	      
	      if (e == 0)
		{
		  if (tools_debug)
		    {
		      fprintf(stderr, _("-05- <%s> <%s> <%s>\n"), 
			      (p->ai_family == AF_INET) ? _("AF_INET") : _("AF_INET6"),
			      sh_ipvx_print_sockaddr (p->ai_addr, p->ai_family),
			      hostname);
		    }

		  if (sl_strcasecmp(hostname, canonical) == 0)
		    {
		      if (tools_debug)
			fprintf(stderr, _("-06- <%s> <%s> match\n"), 
				hostname, canonical);
		      success = 1;
		      break;
		    }

		}
	    
	      p = p->ai_next;
	    }

	  if (success == 0)
	    {
	      sl_strlcpy(ecall, _("strcmp"), SH_MINIBUF);
	      sl_strlcpy(errmsg, _("Reverse lookup failed: "), 
			 errsiz);
	      sl_strlcat(errmsg, address, errsiz);
	      fail = -1;
	      freeaddrinfo (ai);
	    }
	}

      if (fail != (-1))
	{
	  struct addrinfo *p = ai;

	  while (p != NULL)
	    {
	      if ( (SOCK_STREAM == p->ai_socktype) &&
		   ((p->ai_family == AF_INET) || (p->ai_family == AF_INET6)) )
		{
		
		  fd = socket(p->ai_family, SOCK_STREAM, 0);
		  
		  if (fd != (-1))
		    {
		      if (retry_connect(FIL__, __LINE__, fd, 
					p->ai_addr, p->ai_addrlen) >= 0)
			{
			  /* put it into the cache
			   */
			  check_cache          = SH_ALLOC(sizeof(sin_cache));
			  check_cache->address = SH_ALLOC(sl_strlen(address) + 1);
			  sl_strlcpy (check_cache->address, address, sl_strlen(address) + 1);
			  
			  sh_ipvx_save(&(check_cache->saddr), p->ai_family, p->ai_addr);
			  
			  ++cached_addr;
			  
			  if (conn_cache)
			    {
			      if (conn_cache->next)
				check_cache->next    = conn_cache->next;
			      else
				check_cache->next    = NULL;
			      conn_cache->next     = check_cache;
			    }
			  else
			    {
			      check_cache->next    = NULL;
			      conn_cache           = check_cache;
			    }
			  
			  freeaddrinfo (ai);
			  goto end;
			}
		      status = errno;
		      sl_close_fd(FIL__, __LINE__, fd);
		    }
		  else
		    {
		      status = errno;
		    }
		}
	      p = p->ai_next;
	    }
	  fail = (-1);
	  freeaddrinfo (ai);

	  sl_strlcpy(ecall, _("connect"), SH_MINIBUF);
	  *errnum = status;
	  sl_strlcpy(errmsg, sh_error_message (status, errbuf, sizeof(errbuf)), errsiz);
	  sl_strlcat(errmsg, _(", address "), errsiz);
	  sl_strlcat(errmsg, address, errsiz);
	}
    }

 end:
  retval = (fail < 0) ? (-1) : fd;
  SL_RETURN(retval, _("connect_port"));

}
#endif

int connect_port_2 (char * address1, char * address2, int port, 
		    char * ecall, int * errnum, char * errmsg, int errsiz)
{
  int retval = (-1);

  SL_ENTER(_("connect_port_2"));

  errmsg[0] = '\0';
  *errnum = 0;

  if (address1 != NULL && address1[0] != '\0')
    retval = connect_port (address1, port, 
			   ecall, errnum, 
			   errmsg, errsiz);

  if (retval < 0 && address2 != NULL && address2[0] != '\0')
    {
      /* can't use sh_error_handle here, as this would cause an infinite
       * loop if called from sh_unix_time
       */
      TPT(( 0, FIL__, __LINE__, _("msg=<Using alternative server %s.>\n"),
	    address2));
      retval = connect_port (address2, port, 
			     ecall, errnum, 
			     errmsg, errsiz);
    }

  if ((retval < 0) &&
      (address1 == NULL || address1[0] == '\0') &&
      (address1 == NULL || address1[0] == '\0'))
    {
      sl_strlcpy(ecall, _("connect_port_2"), SH_MINIBUF);
      sl_strlcpy(errmsg, _("No server address known"), errsiz);
    }
  SL_RETURN(retval, _("connect_port_2"));
  /* return retval; */
}

#if defined(HAVE_NTIME) || defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER)
static
int sh_write_select(int type, int sockfd, 
		    char *buf, int nbytes, 
		    int * w_error, int timeout)
{
  int    countbytes, count;
  fd_set fds;
  struct timeval tv;
  int    select_now;
  int    num_sel;
  
  char    errbuf[SH_ERRBUF_SIZE];

  SL_ENTER(_("sh_write_select"));

  FD_ZERO(&fds);
  FD_SET(sockfd, &fds);

  countbytes   = 0;
  tv.tv_sec    = 1;
  tv.tv_usec   = 0;
  select_now   = 0;

  *w_error = 0;

  while ( countbytes < nbytes ) {

    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);

    if (type == SH_DO_WRITE) 
      {
	if ( (num_sel = select (sockfd+1, NULL, &fds, NULL, &tv)) == -1) 
	  {
	    if (sig_raised == 1)
	      {
		sig_raised = 2;
		continue;
	      }
	    if ( errno == EINTR || errno == EINPROGRESS ) /* try again */
	      continue;
	    *w_error = errno;

	    sh_error_message(*w_error, errbuf, sizeof(errbuf));
	    sh_error_handle (SH_ERR_INFO, FIL__, __LINE__, errno, MSG_E_SUBGEN,
			     errbuf,
			     _("sh_write_select (ws)") ); 
	    TPT(( 0, FIL__, __LINE__, _("msg=<select: %s>\n"), errbuf ));
	    SL_RETURN( countbytes, _("sh_write_select"));
	  }
      }
    else
      {
	if ( (num_sel = select (sockfd+1, &fds, NULL, NULL, &tv)) == -1) 
	  {
	    if (sig_raised == 1)
	      {
		sig_raised = 2;
		continue;
	      }
	    if ( errno == EINTR || errno == EINPROGRESS ) /* try again */
	      continue;
	    *w_error = errno;

	    sh_error_message(*w_error, errbuf, sizeof(errbuf));
	    sh_error_handle (SH_ERR_INFO, FIL__, __LINE__, errno, MSG_E_SUBGEN,
			     errbuf,
			     _("sh_write_select (rs)") ); 
	    TPT(( 0, FIL__, __LINE__, _("msg=<select: %s>\n"), errbuf ));
	    SL_RETURN( countbytes, _("sh_write_select"));
	  }
      }
      
    /* on Linux, timeout  is  modified to reflect the amount of
     * time not slept
     */
    tv.tv_sec    = 1;
    tv.tv_usec   = 0;


    /* let's not hang on forever
     */
    if (num_sel == 0) 
      {
	++select_now;       /* timeout */
	if ( select_now > timeout )  /* 5 minutes */
	  {
#ifdef ETIMEDOUT
	    *w_error = ETIMEDOUT;
#else
	    *w_error = 0;
#endif

	    TPT(( 0, FIL__, __LINE__, _("msg=<Timeout>\n")));
	    SL_RETURN( countbytes, _("sh_write_select"));
	  }
      }
    
    if ( FD_ISSET (sockfd, &fds) ) 
      {
	if (type == SH_DO_WRITE)
	  count = write (sockfd, buf, nbytes-countbytes);
	else
	  count = read  (sockfd, buf, nbytes-countbytes);

	if (count > 0) 
	{
	  countbytes += count;
	  buf        += count;    /* move buffer pointer forward */
	  if (countbytes < nbytes) FD_SET( sockfd, &fds );
	}
	else if (count < 0 && errno == EINTR)
	  {
	    FD_SET( sockfd, &fds );
	  }
	else if (count < 0)
	  {
	    *w_error = errno;

	    sh_error_message(*w_error, errbuf, sizeof(errbuf));
	    sh_error_handle (SH_ERR_INFO, FIL__, __LINE__, errno, MSG_E_SUBGEN,
			     errbuf,
			     (type == SH_DO_WRITE) ? 
			     _("sh_write_select (w)") : _("sh_write_select (r)")); 
	    TPT(( 0, FIL__, __LINE__, _("msg=<count < 0>\n")));
	    SL_RETURN( countbytes, _("sh_write_select"));
	  }
	else /* count == 0 */
	  {
	    *w_error = errno;

	    TPT(( 0, FIL__, __LINE__, _("msg=<count == 0>\n")));
	    SL_RETURN( countbytes, _("sh_write_select"));
	  }
      }
  }

  *w_error = 0;

  TPT(( 0, FIL__, __LINE__, _("msg=<count = %d>\n"), countbytes));
  SL_RETURN( countbytes, _("sh_write_select"));
}
#endif

#if defined (SH_WITH_CLIENT) || defined(SH_WITH_SERVER)
unsigned long write_port (int sockfd, char *buf, unsigned long nbytes, 
			  int * w_error, int timeout)
{
  unsigned long bytes;

  SL_ENTER(_("write_port"));

  bytes = sh_write_select(SH_DO_WRITE, sockfd, buf, nbytes, w_error, timeout);
  if (*w_error != 0)
    {
      char errbuf[SH_ERRBUF_SIZE];
      sh_error_handle((-1), FIL__, __LINE__, *w_error, MSG_TCP_NETRP, 
		      sh_error_message (*w_error, errbuf, sizeof(errbuf)),
		      (long) sockfd, _("write_port"));
    }
  SL_RETURN( bytes, _("write_port"));
}
#endif

#if defined(HAVE_NTIME) || defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER)

unsigned long read_port (int sockfd, char *buf, unsigned long nbytes, 
	       int * w_error, int timeout)
{
  unsigned long bytes;

  SL_ENTER(_("read_port"));

  bytes = sh_write_select(SH_DO_READ, sockfd, buf, nbytes, w_error, timeout);
  if (*w_error != 0)
    {
      char errbuf[SH_ERRBUF_SIZE];
      sh_error_handle((-1), FIL__, __LINE__, *w_error, MSG_TCP_NETRP, 
		      sh_error_message (*w_error, errbuf, sizeof(errbuf)),
		      (long) sockfd, _("read_port"));
    }
  SL_RETURN( bytes, _("read_port"));
}
#endif

#if defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER) 

int check_request_nerr (char * have, char * need)
{
  SL_ENTER(_("check_request_nerr"));
  ASSERT_RET((have != NULL && need != NULL), 
	     _("have != NULL && need != NULL"), (-1))

  if ( (have[0] == need[0]) && (have[1] == need[1]) &&
       (have[2] == need[2]) && (have[3] == need[3]))
    SL_RETURN(0, _("check_request_nerr"));
  SL_RETURN((-1), _("check_request_nerr"));
}
#endif

#if defined (SH_WITH_CLIENT) || defined(SH_WITH_SERVER)

int check_request (char * have, char * need)
{
  char first[21], second[5];
  int  i;

  SL_ENTER(_("check_request"));
  i = check_request_nerr (have, need);

  if (i == 0)
    SL_RETURN(0, _("check_request"));

  for (i = 0; i < 4; ++i)
    {
      second[i] = need[i];
      sprintf(&first[i*4], _("%c%03o"),               /* known to fit  */
	      '\\', (unsigned char) have[i]);
    }

  first[20] = '\0'; second[4] = '\0';

  sh_error_handle((-1), FIL__, __LINE__, EINVAL, MSG_E_NETST, 
		  second, first);
  SL_RETURN((-1), _("check_request"));
}
#endif

#if defined (SH_WITH_SERVER)

int check_request_s (char * have, char * need, char * clt)
{
  char first[21], second[5];
  int  i;

  SL_ENTER(_("check_request_s"));
  i = check_request_nerr (have, need);

  if (i == 0)
    SL_RETURN( (0), _("check_request_s"));

  for (i = 0; i < 4; ++i)
    {
      second[i] = need[i];
      sprintf(&first[i*4], _("%c%03o"),               /* known to fit  */
	      '\\', (unsigned char) have[i]);
    }
  first[20] = '\0'; second[4] = '\0';
  sh_error_handle((-1), FIL__, __LINE__, EINVAL, MSG_E_NETST1, 
		  second, first, clt);
  SL_RETURN( (-1), _("check_request_s"));
}
#endif

#if defined (SH_WITH_CLIENT) || defined (SH_WITH_SERVER)

#if defined (SH_WITH_CLIENT)

static int           probe_done = S_FALSE;
static unsigned char probe_flag = '\0';

void sh_tools_probe_reset()
{
  probe_done = S_FALSE;
  probe_flag = '\0';
  return;
}

static int probe_ok(int flag)
{
  (void) flag;
  if ((probe_flag & SH_PROTO_IVA) != 0)
    return S_TRUE;
  return S_FALSE;
}

static unsigned char probe_header_set(unsigned char protocol)
{
  if (probe_done || (protocol & SH_PROTO_SRP) == 0)
    return 0;

  return (char) SH_PROTO_IVA;
}

static void probe_header_get(unsigned char protocol)
{
  if (probe_done || (protocol & SH_PROTO_SRP) == 0)
    return;

  /* If the server doesn't know about it,
   * it will simply mirror it back. */
  
  if ((protocol & SH_PROTO_IVA) != 0)
    {
      /* probe was mirrored */;
    }
  else
    {
      /* probe was UNset */
      probe_flag |= SH_PROTO_IVA;
    }
  probe_done = S_TRUE;
  return;
}

#else
static unsigned char probe_header_set(unsigned char protocol) { 
  (void) protocol; return 0; }
static void probe_header_get(unsigned char protocol) { 
  (void) protocol; return; }
void sh_tools_probe_reset() { return; }

unsigned char sh_tools_probe_store(unsigned char protocol, int * probe_flag)
{
  if ((protocol & SH_PROTO_SRP) == 0)
    return protocol;

  if ((protocol & SH_PROTO_IVA) != 0)
    {
      /* probe received */
      *probe_flag |=  SH_PROTO_IVA;
      protocol    &= ~SH_PROTO_IVA;
    }
  return protocol; 
}

static int probe_ok(int flag)
{
  if ((flag & SH_PROTO_IVA) != 0)
    return S_TRUE;
  return S_FALSE;
}
#endif


void get_header (unsigned char * head, unsigned long * bytes, char * u)
{
  SL_ENTER(_("get_header"));

  probe_header_get(head[0]);

  *bytes = 
    (256 * (unsigned int)head[1] + (unsigned int)head[2]);

  if (u != NULL)
    {
      u[0]     = head[3];
      u[1]     = head[4];
      u[2]     = head[5];
      u[3]     = head[6];
      u[4]     = '\0';
    }

  SL_RET0(_("get_header"));
}
#endif

#if defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER)

#ifdef  SH_ENCRYPT
#define TRANS_BYTES 65120
#else
#define TRANS_BYTES 65280
#endif

void put_header (unsigned char * head, const int protocol, 
		 unsigned long * length, char * u)
{
  unsigned char probe = probe_header_set(protocol);

  /* static long transfer_limit = (8 * SH_BUFSIZE); V0.8 */
  static unsigned long transfer_limit = TRANS_BYTES + 6 + KEY_LEN;

  SL_ENTER(_("put_header"));

  head[0]   = protocol|probe;

  ASSERT((*length < transfer_limit), _("*length < transfer_limit"))

  if (*length > transfer_limit)
    *length = transfer_limit;

  head[1]   = (unsigned int)(*length/256);
  head[2]   = (unsigned int)(*length-256 * head[1]);
  if (u == NULL)
    {
      head[3] = 0x01;
      head[4] = 0x01;
      head[5] = 0x01;
      head[6] = 0x01;
    }
  else
    {
      head[3]   = u[0];
      head[4]   = u[1];
      head[5]   = u[2];
      head[6]   = u[3];
    }

  SL_RET0(_("put_header"));
}

/* ------------------------------------------
 *
 *  version 2 client/server protocol
 *
 * ------------------------------------------ 
 *
 * header :  flag size[2]
 *
 * payload:  random_pad[8] protocol[4] size[4] payload[payload_size] padding
 *
 * full_size <= 8192; payload_size <= 8176 (511*16); msg_size <= 8128 (508*16)
 * (msg_size = payload_size - key_len = payload_size - 48)
 */ 

/* 
 * only SH_V2_FULLSIZE is used, and only once
 */

#define SH_V2_FULLSIZE 1024

#ifdef SH_ENCRYPT
#include "rijndael-api-fst.h"
#endif

void sh_tools_show_header (unsigned char * head, char sign)
{
#define SH_IS_ASCII(c) (((c) & ~0x7f) == 0)


  int    msg_size = (256 * (unsigned int)head[1] + (unsigned int)head[2]);
  char   code[32]; 
  char * p = &code[0];

  memset (code, ' ', 32); /* space */
 
  if ((head[0] & SH_PROTO_SRP) != 0) { p[0]='S';p[1]='R';p[2]='P';}
  p += 4;
  if ((head[0] & SH_PROTO_MSG) != 0) { p[0]='M';p[1]='S';p[2]='G';}
  p += 4;
  if ((head[0] & SH_PROTO_BIG) != 0) { p[0]='B';p[1]='I';p[2]='G';}
  p += 4;
  if ((head[0] & SH_PROTO_END) != 0) { p[0]='E';p[1]='N';p[2]='D';}
  p += 4;
  if ((head[0] & SH_PROTO_ENC) != 0) { p[0]='E';p[1]='N';p[2]='C';}
  p += 4;
  if ((head[0] & SH_PROTO_EN2) != 0) { p[0]='E';p[1]='N';p[2]='2';}
  code[23] = '\0';

  if (SH_IS_ASCII(head[3]) && isalpha(head[3]) &&
      SH_IS_ASCII(head[4]) && isalpha(head[4]) &&			   
      SH_IS_ASCII(head[5]) && isalpha(head[5]) &&			   
      SH_IS_ASCII(head[6]) && isalpha(head[6])) {
    fprintf(stderr, _("%c %3o %s %5d  %c  %c  %c  %c\n"), sign,
	    head[0], code, msg_size, head[3], head[4], head[5], head[6]); 
  } else {
    fprintf(stderr, _("%c %3o %s %5d %2X %2X %2X %2X\n"), sign,
	    head[0], code, msg_size, head[3], head[4], head[5], head[6]); 
  }
  return;
}

#ifdef SH_ENCRYPT

/*
 * #define DEBUG_EN2
 *
 * ingest version 1 7-byte header and payload, return version2 header/payload
 * last 4 bytes of outgoing header are set to dummy value
 */
char * sh_tools_makePack (unsigned char * header, int flag,
			  char * payload, unsigned long payload_size,
			  keyInstance * keyInstE)
{
  BYTE            inBlock[B_SIZ]; 
  BYTE            outBlock[B_SIZ];
  char            ivBlock[B_SIZ];

  UINT32          rpad[3];
  unsigned char   head[16];
  double          epad;
  unsigned long   i_epad = 0;
  unsigned long   i_blk = payload_size / 16;
  unsigned long   i_blkmax = SH_V2_FULLSIZE / 16;
  unsigned long   pads = 0;
  size_t          full_size;
  char          * full_ret;

  unsigned char * p;
  int             j;
  cipherInstance  cipherInst;
  int             err_num;
  int             blkfac;
  int             oflow = 0;
  char expbuf[SH_ERRBUF_SIZE];

  /* 
     SL_REQUIRE (i_blk*16 == payload_size, _("payload_size % 16 != 0"));
  */
  if ((i_blk * 16) != payload_size) ++i_blk;

  /* random_pad
   */
  rpad[1] = taus_get ();
  memcpy (head,      &rpad[1],    4);
  rpad[0] = taus_get ();
  memcpy (&head[4],  &rpad[0],    4);
  rpad[2] = taus_get ();
  memcpy (&head[8],  &rpad[2],    4);

  /* size (payload)
   */ 
  head[12] = header[1];
  head[13] = header[2];
  head[14] = '\0';
  head[15] = '\0';

  if (i_blk < i_blkmax) 
  {
    pads   = i_blkmax - i_blk;
    epad   = taus_get_double (&rpad);
    i_epad = (unsigned long) (pads * epad);
  }

  full_size =  16;                        /* head     */
  if (sl_ok_muls(i_blk, 16) && sl_ok_adds(full_size, (i_blk*16)))
    full_size =  full_size + (i_blk*16);  /* payload  */
  else
    oflow = 1;
  if (sl_ok_adds(full_size, (i_epad*16)))
    full_size =  full_size + (i_epad*16); /* pad      */
  else
    i_epad = 0;

  if (oflow)
    {
      sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
		      _("integer overflow"), 
		      _("sh_tools_makePack"));
    }

  full_ret = SH_ALLOC(full_size);

  memcpy(full_ret,                   head,    16);
  if (payload != NULL && !oflow)
    memcpy(&full_ret[16],              payload, payload_size);

  if ((i_blk*16) > payload_size && !oflow) 
    {
      memset(&full_ret[16+payload_size], '\0', (i_blk*16) - payload_size);
      payload_size = i_blk * 16;
    }
  memset(&full_ret[16+payload_size], '\0', i_epad*16);

  /* rewrite header
   */
  header[1]   = (unsigned int)(full_size/256);
  header[2]   = (unsigned int)(full_size - (256 * header[1]));

  p      = (unsigned char *) full_ret; 
  blkfac = full_size / B_SIZ;

  err_num = rijndael_cipherInit (&cipherInst, MODE_CBC, NULL);
  
  if (err_num < 0) {
    sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
		    errorExplain(err_num, expbuf, sizeof(expbuf)), 
		    _("sh_tools_makePack: rijndael_cipherInit")); }

  if (probe_ok(flag)) {
    memcpy(inBlock, p, B_SIZ);
    err_num = rijndael_blockEncrypt(&cipherInst, keyInstE, 
				    inBlock, 128, outBlock);
    if (err_num >= 0) {
      memcpy(p, outBlock, B_SIZ); p += B_SIZ;
      memcpy(ivBlock, outBlock, sizeof(ivBlock));
      err_num = rijndael_cipherInit (&cipherInst, MODE_CBC, ivBlock);
      if (err_num >= 0) {
	err_num = rijndael_blockEncrypt(&cipherInst, keyInstE, 
					p, 128*(blkfac-1), p);
      }
    }
  }

  else {
    for (j = 0; j < blkfac; ++j) {
      memcpy(inBlock, p, B_SIZ);
      err_num = rijndael_blockEncrypt(&cipherInst, keyInstE, 
				      inBlock, 128, outBlock);
      
      if (err_num < 0) {
	sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
			errorExplain(err_num, expbuf, sizeof(expbuf)), 
			_("sh_tools_makePack: rijndael_blockEncrypt"));
	break; }
      
      memcpy(p, outBlock, B_SIZ);
      p += B_SIZ;
    }
  }

  return full_ret;
}

/* write a 7-byte header and return payload as expected by version 1
 * last 4 bytes of incoming header are dummy
 */
char * sh_tools_revertPack (unsigned char * header, int flag, char * message, 
			    keyInstance * keyInstD,
			    unsigned long message_size)
{
  BYTE                    inBlock[B_SIZ]; 
  BYTE                    outBlock[B_SIZ];
  char                    ivBlock[B_SIZ];
  unsigned long   msg_size;
  char          * msg_ret;

  unsigned char         * p;
  int                     j;
  cipherInstance          cipherInst;
  int                     err_num;
  int                     blkfac;
  char expbuf[SH_ERRBUF_SIZE];

  msg_size = (256 * (unsigned int)header[1] + (unsigned int)header[2]);
  if (msg_size > message_size) 
    msg_size = message_size;

  p = (unsigned char *) message; blkfac = msg_size / 16;

  err_num = rijndael_cipherInit (&cipherInst, MODE_CBC, NULL);
  
  if (err_num < 0) 
    {
      sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
		      errorExplain(err_num, expbuf, sizeof(expbuf)), 
		      _("sh_tools_revertPack: rijndael_cipherInit"));
    }

  if (probe_ok(flag)) {
    memcpy(inBlock, p, B_SIZ);
    err_num = rijndael_blockDecrypt(&cipherInst, keyInstD, 
				    inBlock, 128, outBlock);
    if (err_num >= 0) {
      memcpy(p, outBlock, B_SIZ); p += B_SIZ;
      memcpy(ivBlock, inBlock, sizeof(ivBlock));
      err_num = rijndael_cipherInit (&cipherInst, MODE_CBC, ivBlock);
      if (err_num >= 0) {
	err_num = rijndael_blockDecrypt(&cipherInst, keyInstD, 
					p, 128*(blkfac-1), p);
      }
    }
  }

  else {
    for (j = 0; j < blkfac; ++j) {
      memcpy(inBlock, p, B_SIZ);
      err_num = rijndael_blockDecrypt(&cipherInst, keyInstD, 
				      inBlock, 128, outBlock);
  
      if (err_num < 0) {
	sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
			errorExplain(err_num, expbuf, sizeof(expbuf)), 
			_("sh_tools_revertPack: rijndael_blockDecrypt"));
	break; }
      
      memcpy(p, outBlock, B_SIZ);
      p += B_SIZ;
    }
  }

  /* rewrite size in header
   */
  header[1]   = message[12];
  header[2]   = message[13];
  msg_size = (256 * (unsigned int)header[1] + (unsigned int)header[2]);

  if (msg_size > (message_size-16)) 
    {
      msg_size    = message_size-16;
      header[1]   = (unsigned int)(msg_size/256);
      header[2]   = (unsigned int)(msg_size - (256 * header[1]));
    }

  /* payload 
   */
  msg_ret = SH_ALLOC(msg_size+1);
  if (msg_size > 0)
    memcpy(msg_ret, &message[16], msg_size);
  msg_ret[msg_size] = '\0';

  SH_FREE(message);
  return msg_ret;
}
#endif /* #ifdef SH_ENCRYPT */

int sh_tools_hash_add(char * key, char * buf, int buflen)
{
  char         * theSig;
  char sigbuf[KEYBUF_SIZE];

  SL_ENTER(_("sh_tools_hash_add"));

  theSig = sh_util_siggen (key, buf, buflen, sigbuf, sizeof(sigbuf));
  sl_strlcat(buf, theSig, buflen + KEY_LEN + 1);
      
  SL_RETURN((0), _("sh_tools_hash_add"));
}


/* return 0 (== FALSE) if no match, else 1 (== TRUE)
 */
int sh_tools_hash_vfy(char * key, char * buf, int buflen)
{
  char           hash[KEY_LEN+1];
  register int   i;
  char         * theSig;
  char sigbuf[KEYBUF_SIZE];

  SL_ENTER(_("sh_tools_hash_vfy"));

  theSig = sh_util_siggen (key, buf, buflen, sigbuf, sizeof(sigbuf));
  sl_strlcpy(hash, theSig, KEY_LEN+1);

  for (i = 0; i < KEY_LEN; ++i)
    {
      if (buf[buflen + i] != hash[i])
	SL_RETURN((0), _("sh_tools_hash_vfy"));
    }
      
  SL_RETURN((1), _("sh_tools_hash_vfy"));
}

#endif /* defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER) */


/* ------------------------------------------ */

#if defined (SH_WITH_SERVER)

/* add a checksum to a buffer; put checksum in front
 */
char * hash_me (char * key, char * buf,   int buflen)
{
  char           hash[KEY_LEN+1];
  char         * temp = NULL;
  register int   i;
  int            total = 0;
  char         * theSig;
  char sigbuf[KEYBUF_SIZE];


  SL_ENTER(_("hash_me"));

#ifdef DEBUG_EN2
  fprintf(stderr, "hash_me    <%s> <%d>\n", 
	  (key == NULL) ? "NULL" : key, buflen);
#endif
  /* key = H(NSRV,NCLT,SK)
   */
  ASSERT_RET((key != NULL), _("key != NULL"), (NULL));
  ASSERT_RET((buflen >= 0), _("buflen >= 0"), (NULL));

  theSig = sh_util_siggen (key, buf, buflen, sigbuf, sizeof(sigbuf));
  sl_strlcpy(hash, theSig, KEY_LEN+1);

  if (sl_ok_adds(buflen, KEY_LEN))
    {
      total = KEY_LEN + buflen;
      temp  = SH_ALLOC (total);

      for (i = 0; i < KEY_LEN; ++i)
	temp[i] = hash[i];

      for (i = 0; i < buflen; ++i)
	temp[i+KEY_LEN] = buf[i];
    }
  else
    {
      sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
		      _("integer overflow"), 
		      _("hash_me"));
      temp = sh_util_strdup(buf);
    }
  SL_RETURN(temp, _("hash_me"));
}
#endif

#if defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER)

/* verify the checksum of a buffer; checksum comes first
 */
int hash_check(char * key, 
	       char * buf,   int buflen)
{
  char           hash[KEY_LEN+1];
  register int   i;
  char         * theSig;
  char sigbuf[KEYBUF_SIZE];

  SL_ENTER(_("hash_check"));

#ifdef DEBUG_EN2
  fprintf(stderr, "hash_check <%s> <%d>\n", 
	  (key == NULL) ? "NULL" : key, buflen);
#endif
  theSig = sh_util_siggen (key, &buf[KEY_LEN], buflen-KEY_LEN,
			   sigbuf, sizeof(sigbuf));
  sl_strlcpy(hash, theSig, KEY_LEN+1);
      
  for (i = 0; i < KEY_LEN; ++i)
    {
      if (buf[i] != hash[i])
	SL_RETURN((-1), _("hash_check"));
    }
  SL_RETURN((0), _("hash_check"));
}

#endif

#if defined (SH_WITH_SERVER)

char * get_client_conf_file (const char * peer, unsigned long * length)
{
  char * ret;
  int    status;
  struct stat buf;
  char * base;

  SL_ENTER(_("get_client_conf_file"));

  base = sh_util_strdup(DEFAULT_DATAROOT);
  ret = sh_util_strconcat(base, _("/rc."), peer, NULL);
  if (!ret) 
    { SH_FREE(base); *length = 0; SL_RETURN(NULL, _("get_client_conf_file")); }

  status = retry_stat (FIL__, __LINE__, ret, &buf);
  if (status == 0)
    goto lab_end;
  else
    sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, status, MSG_E_ACCESS,
		    (long) sh.effective.uid, ret);

  SH_FREE(ret); ret = sh_util_strconcat(base, _("/rc"), NULL);
  if (!ret) 
    { SH_FREE(base); *length = 0; SL_RETURN(NULL, _("get_client_conf_file")); }
  
  status = retry_stat (FIL__, __LINE__, ret, &buf);
  if (status == 0)
    goto lab_end;
  else
    sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, status, MSG_E_ACCESS,
		    (long) sh.effective.uid, ret);

  SH_FREE(base); SH_FREE(ret); *length=0;
  SL_RETURN(NULL, _("get_client_conf_file"));

 lab_end:
  if (buf.st_size > 0x7fffffff)
    {
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, status, MSG_E_SUBGEN,
		    _("File too large"), _("get_client_conf_file"));
      SH_FREE(base); SH_FREE(ret); *length = 0;
      SL_RETURN(NULL, _("get_client_conf_file"));
    }

  SH_FREE(base); *length = (unsigned long) buf.st_size;
  SL_RETURN(ret, _("get_client_conf_file"));
}

char * get_client_data_file (const char * peer, unsigned long * length)
{
  char * ret;
  int    status;
  struct stat buf;
  char * base;

  SL_ENTER(_("get_client_data_file"));

  base = sh_util_strdup(DEFAULT_DATAROOT);
  ret = sh_util_strconcat(base, _("/file."), peer, NULL);
  if (!ret) 
    { SH_FREE(base); *length = 0; SL_RETURN(NULL, _("get_client_data_file")); }

  status = retry_stat (FIL__, __LINE__, ret, &buf);
  if (status == 0)
    goto lab1_end;
  else
    sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, status, MSG_E_ACCESS,
		    (long) sh.effective.uid, ret);

  SH_FREE(ret); 
  ret = sh_util_strconcat(base, _("/file"), NULL);
  if (!ret) 
    { SH_FREE(base); *length = 0; SL_RETURN(NULL, _("get_client_data_file")); }

  status = retry_stat (FIL__, __LINE__, ret, &buf);
  if (status == 0)
    goto lab1_end;
  else
    sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, status, MSG_E_ACCESS,
		    (long) sh.effective.uid, ret);

  *length = 0; SH_FREE(base); SH_FREE(ret);
  SL_RETURN(NULL, _("get_client_data_file"));

 lab1_end:
  if (buf.st_size > 0x7fffffff)
    {
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, status, MSG_E_SUBGEN,
		    _("File too large"), _("get_client_data_file"));
      SH_FREE(base); SH_FREE(ret); *length = 0;
      SL_RETURN(NULL, _("get_client_data_file"));
    }

  *length = (unsigned long) buf.st_size; SH_FREE(base);
  SL_RETURN(ret, _("get_client_data_file"));
}

char * get_client_uuid_file (const char * peer, unsigned long * length, const char * uuid)
{
  char * ret;
  int    status;
  struct stat buf;
  char * base;

  SL_ENTER(_("get_client_uuid_file"));

  base = sh_util_strdup(DEFAULT_DATAROOT);
  ret = sh_util_strconcat(base, _("/file."), peer, ".", uuid, NULL);
  SH_FREE(base);
  if (!ret) 
    { *length = 0; SL_RETURN(NULL, _("get_client_uuid_file")); }

  status = retry_stat (FIL__, __LINE__, ret, &buf);
  if (status != 0)
    {
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, status, MSG_E_ACCESS,
		      (long) sh.effective.uid, ret);
      SH_FREE(ret); *length = 0;
      SL_RETURN(NULL, _("get_client_uuid_file"));
    }
  else if (buf.st_size > 0x7fffffff)
    {
      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, status, MSG_E_SUBGEN,
		    _("File too large"), _("get_client_uuid_file"));
      SH_FREE(ret); *length = 0;
      SL_RETURN(NULL, _("get_client_data_file"));
    }

  *length = (unsigned long) buf.st_size;
  SL_RETURN(ret, _("get_client_uuid_file"));
}

#endif

#if defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER) || defined(SH_STEALTH) || defined(WITH_GPG) || defined(WITH_PGP)

/* --------- secure temporary file ------------ */

SL_TICKET open_tmp ()
{
  SL_TICKET     fd;
  UINT32        ticks;
  char        * file;
  struct stat   buf;
  int           error;
  int           status = BAD;
  char        * my_tmp_dir;
  char hashbuf[KEYBUF_SIZE];

  SL_ENTER(_("open_tmp"));

#if defined(SH_TMPDIR)
  my_tmp_dir = sh_util_strdup(SH_TMPDIR); 
#else
#if defined(SH_WITH_SERVER)
  my_tmp_dir = sh_util_strdup(DEFAULT_LOGDIR); 
#else
  my_tmp_dir = sh_util_strdup(sh.effective.home);
#endif 
#endif

  if (0 !=  tf_trust_check (my_tmp_dir, SL_YESPRIV))
      {
	dlog(1, FIL__, __LINE__, 
	     _("The directory for temporary files: %s is untrusted, i.e. an\nuntrusted user owns or can write to some directory in the path.\n"), 
	     my_tmp_dir);
	sh_error_handle ((-1), FIL__, __LINE__, EACCES, MSG_TRUST,
			 (long) sh.effective.uid,
			 my_tmp_dir);
	SH_FREE(my_tmp_dir);
	aud_exit (FIL__, __LINE__, EXIT_FAILURE);
      }

  do {

    /* create random filename in effective users home directory
     */
    ticks = taus_get ();
    if (my_tmp_dir[0] == '/' && my_tmp_dir[1] == '\0')
      file = sh_util_strconcat (my_tmp_dir, 
				sh_tiger_hash( (char *) &ticks, TIGER_DATA, 4,
					       hashbuf, sizeof(hashbuf)),
				NULL);
    else
      file = sh_util_strconcat (my_tmp_dir, 
				"/", 
				sh_tiger_hash( (char *) &ticks, TIGER_DATA, 4,
					       hashbuf, sizeof(hashbuf)),
				NULL);

    /* check whether it already exists (paranoia)
     */
    errno  = 0;
    status = retry_lstat(FIL__, __LINE__, file, &buf);
    error  = errno;

    if ( (status < 0) && (error == ENOENT) ) /* file does not exist        */
      status = GOOD;
    else if (status < 0)                     /* unexpected error condition */
      {
	SH_FREE (file);
	SH_FREE(my_tmp_dir);
	sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, status, MSG_E_SUBGEN, 
			_("Error (lstat) while opening temporary file"), _("open_tmp"));
	TPT(( 0, FIL__, __LINE__, _("msg=<Unexpected error %d>\n"), error));
	SL_RETURN((-1), _("open_tmp"));
      }
    else                                     /* file exists                */
      {
	status = BAD;
	TPT(( 0, FIL__, __LINE__, _("msg=<Temporary file exists already>\n")));
      }
    
    if (status == GOOD)
      {  
	if (0 ==  tf_trust_check (file, SL_YESPRIV))
	  status = GOOD;
	else
	  {
	    status = BAD;
	    TPT(( 0, FIL__, __LINE__, _("msg=<Temporary file untrusted>\n")));
	  }
      }

    if (status == BAD)
      SH_FREE (file);

  } while (status == BAD);

  fd = sl_open_safe_rdwr (FIL__, __LINE__, file, SL_YESPRIV);
  if (SL_ISERROR(fd))
    {
      sh_error_handle((-1), FIL__, __LINE__, fd, MSG_E_SUBGEN, 
		      _("Error opening temporary file"), _("open_tmp"));
      TPT(( 0, FIL__, __LINE__, _("msg=<Error %d temporary file %s>\n"), 
	    fd, file));
    }

  SH_FREE (file);
  SH_FREE(my_tmp_dir);

  if (!SL_ISERROR(fd)) {
    sl_unlink(fd);
  } 

  if (!SL_ISERROR(fd))
    SL_RETURN((fd), _("open_tmp"));
  else
    SL_RETURN((-1), _("open_tmp"));
}


int close_tmp (SL_TICKET fd)
{
  SL_ENTER(_("close_tmp"));

  if (SL_ISERROR(sl_close (fd)))
    SL_RETURN((-1), _("close_tmp"));
  SL_RETURN((0), _("close_tmp"));  
}

int rewind_tmp (SL_TICKET fd)
{
  SL_ENTER(_("rewind_tmp"));

  if (SL_ISERROR(sl_rewind (fd)))
    SL_RETURN((-1), _("rewind_tmp"));
  SL_RETURN((0), _("rewind_tmp"));
}
#endif

/********************************************************
 * Search rotated logfile
 */
#include <unistd.h>
#include <libgen.h>
#include <dirent.h>

char * sh_rotated_log_search(const char * path, struct stat * buf)
{

  size_t size;
  int    i;
  char * searchpath;
  struct stat sbuf;
  DIR  * dp;
  char * dname;
  char * bname;

  dname  = sh_util_dirname(path);
  bname  = sh_util_basename(path);

  size = strlen(dname) + strlen(bname) + 4;
  searchpath = SH_ALLOC(size);

  for (i = 0; i < 2; ++i)
    {
      snprintf(searchpath, size, "%s/%s.%1d", dname, bname, i);
      if (0 == stat(searchpath, &sbuf) && sbuf.st_ino == buf->st_ino)
	{
	  SH_FREE(dname);
	  SH_FREE(bname);
	  return searchpath;
	}
    }

  SH_FREE(searchpath);

  if (NULL != (dp = opendir(dname)))
    {
      struct dirent * de;

      while (NULL != (de = readdir(dp)))
	{
	  if (0 == strcmp(de->d_name, ".") || 0 == strcmp(de->d_name, ".."))
	    continue;

	  size = strlen(dname) + strlen(de->d_name) + 2;
	  searchpath = SH_ALLOC(size);
	  snprintf(searchpath, size, "%s/%s", dname, de->d_name);

	  if (0 == stat(searchpath, &sbuf) && sbuf.st_ino == buf->st_ino)
	    {
	      SH_FREE(dname);
	      SH_FREE(bname);
	      closedir(dp);
	      return searchpath;
	    }
	  
	  SH_FREE(searchpath);
	}
      closedir(dp);
    }

  SH_FREE(dname);
  SH_FREE(bname);

  return NULL;
}

