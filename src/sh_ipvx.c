/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2010 Rainer Wichmann                                      */
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>

#undef  FIL__
#define FIL__  _("sh_ipvx.c")

#include "samhain.h"
#define SH_NEED_GETHOSTBYXXX
#include "sh_static.h"
#include "sh_pthread.h"
#include "sh_utils.h"
#include "sh_ipvx.h"

static int sh_ipvx_is_ipv4 (const char * addr)
{
  int j;
  int count = 0;
  int len = sl_strlen(addr);
  unsigned int a, b, c, d;
  
  if (len > 15) /* 3*4 + 3 dots */
    return (1 == 0);

  for (j = 0; j < len; ++j) {
    if ( (addr[j] < '0' || addr[j] > '9') && addr[j] != '.')
      return (1 == 0);
    if (addr[j] == '.') ++count;
  }

  if (count != 3)
    return (1 == 0);

  if (sscanf(addr, "%3u.%3u.%3u.%3u", &a, &b, &c, &d) != 4)
    return( 1 == 0 );

  if ((a|b|c|d) > 255) 
    return( 1 == 0 );

  return (1 == 1);
}

#if defined(USE_IPVX)
static int sh_ipvx_is_ipv6 (const char * addr)
{
  int j, k = 0;
  char c;
  int len = sl_strlen(addr);
  
  for (j = 0; j < len; ++j) {
    c = addr[j];
    if (( c < '0' || c > '9' ) &&
	( c < 'a' || c > 'f' ) &&
	( c < 'A' || c > 'F' ) &&
	( c != ':') && ( c != '.'))
      return (1 == 0);
    else if (c == ':')
      ++k;
    else if (c == '.' && k < 2)
      return (1 == 0); /* ::ffff:ipv4 */
  }
  if (k < 2 || k > 7)
    return (1 == 0);

  return (1 == 1);
}
#endif


int sh_ipvx_is_numeric (const char * addr)
{
#if defined(USE_IPVX)
  if (!sh_ipvx_is_ipv4(addr))
    return sh_ipvx_is_ipv6(addr);
  else
    return (1 == 1);
#else
  return sh_ipvx_is_ipv4(addr);
#endif
}

int sh_ipvx_isany (struct sh_sockaddr * a)
{
#if defined(HOST_IS_CYGWIN)
  /* 
   * Cygwin implementation gives 'missing braces around initializer'
   * warning, thus replace it with correct version.
   */
#undef IN6ADDR_ANY_INIT
#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#endif

#if defined(USE_IPVX)
  struct in6_addr anyaddr = IN6ADDR_ANY_INIT; 
#endif

  switch (a->ss_family)
    {
    case AF_INET:
      if ((a->sin).sin_addr.s_addr == INADDR_ANY)
	return 1;
      break;
#if defined(USE_IPVX)
    case AF_INET6:
      if (0 == memcmp(&((a->sin6).sin6_addr.s6_addr), &anyaddr, 16))
	return 1;
      break;
#endif
    }
  return 0;
}

int sh_ipvx_cmp (struct sh_sockaddr * a, struct sh_sockaddr * b)
{
  if (a->ss_family != b->ss_family)
    return 1;
  
  switch (a->ss_family)
    {
    case AF_INET:
      return memcmp(&((a->sin).sin_addr.s_addr), &((b->sin).sin_addr.s_addr), 4);
      break;
#if defined(USE_IPVX)
    case AF_INET6:
      return memcmp(&((a->sin6).sin6_addr.s6_addr), &((b->sin6).sin6_addr.s6_addr), 16);
      break;
#endif
    }
  return 1;
}

int sh_ipvx_ntoa (char * name, size_t name_size, struct sh_sockaddr * ss)
{
#if defined(USE_IPVX)
  int len = (ss->ss_family == AF_INET) ? 
    sizeof(struct sockaddr_in) :
    sizeof(struct sockaddr_in6);

  int ret = getnameinfo(sh_ipvx_sockaddr_cast(ss), len,
			name, name_size, NULL, 0, NI_NUMERICHOST);

  if (ret != 0 && name_size > 0)
    {
      name[name_size-1] = '\0';

      if (!sh_ipvx_is_numeric(name))
	{
	  if (name_size > 7) {
	    name[0] = '0'; name[1] = '.'; name[2] = '0'; name[3] = '.'; 
	    name[4] = '0'; name[5] = '.'; name[6] = '0'; name[7] = '\0';
	  } else {
	    name[0] = '\0';
	  }
	}
    } 
  return ret;
#else
  char * p = inet_ntoa((ss->sin).sin_addr);
  sl_strlcpy(name, p, name_size);
  return 0;
#endif
}

struct sockaddr * sh_ipvx_sockaddr_cast (struct sh_sockaddr * ss)
{
#if defined(USE_IPVX)
  if (ss->ss_family == AF_INET6)
    return (struct sockaddr *) &(ss->sin6);
#endif
  return (struct sockaddr *) &(ss->sin);
}

char * sh_ipvx_print_sockaddr (struct sockaddr * sa, int sa_family)
{
  struct sh_sockaddr ss;
  static char ipbuf[SH_IP_BUF];

  sh_ipvx_save(&ss, sa_family, sa);
  sh_ipvx_ntoa (ipbuf, sizeof(ipbuf), &ss);
  return ipbuf;
}

void sh_ipvx_save(struct sh_sockaddr * ss, int sa_family, struct sockaddr * sa)
{
  /* memset(ss, '\0', sizeof(struct sh_sockaddr)); */

  switch (sa_family)
    {
    case AF_INET:
      ss->ss_family = AF_INET;
      memcpy(&(ss->sin), (struct sockaddr_in*) sa, sizeof(struct sockaddr_in));
      break;
#if defined(USE_IPVX)
    case AF_INET6:
      ss->ss_family = AF_INET6;
      memcpy(&(ss->sin6), (struct sockaddr_in6*) sa, sizeof(struct sockaddr_in6));
      break;
#endif
    default:
      break;
    }
  return;
}

int sh_ipvx_set_port(struct sh_sockaddr * ss, int port)
{
#if defined(USE_IPVX)

  switch (ss->ss_family)
    {
    case AF_INET:
      (ss->sin).sin_family = AF_INET;
      (ss->sin).sin_port = htons (port);
      break;
    case AF_INET6:
      (ss->sin6).sin6_family = AF_INET6;
      (ss->sin6).sin6_port = htons (port);
      break;
    }
  return 0;
#else
  (ss->sin).sin_family = AF_INET;
  (ss->sin).sin_port = htons (port);
  return 0;
#endif
}

int sh_ipvx_get_port(struct sockaddr * sa, int sa_family)
{
  int port = 0;
#if defined(USE_IPVX)

  switch (sa_family)
    {
    case AF_INET:
      port = ntohs(((struct sockaddr_in *)sa)->sin_port);
      break;
    case AF_INET6:
      port = ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
      break;
    }
#else
  (void) sa_family;
  port = ntohs(((struct sockaddr_in *)sa)->sin_port);
#endif
  return port;
}

int sh_ipvx_aton (const char * name, struct sh_sockaddr * ss)
{
#if defined(USE_IPVX)
  int             ret;
  struct addrinfo hints;
  struct addrinfo *res;

  memset(&hints, '\0', sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_flags  = AI_NUMERICHOST;
  ret = getaddrinfo(name, NULL, &hints, &res);

  if (ret)
    return 0;

  memset(ss, '\0', sizeof(struct sh_sockaddr));
  switch(res->ai_family)
    {
    case AF_INET:
      memcpy(&(ss->sin), res->ai_addr, sizeof(struct sockaddr_in));
      ss->ss_family = AF_INET;
      break;
    case AF_INET6:
      memcpy(&(ss->sin6), res->ai_addr, sizeof(struct sockaddr_in6));
      ss->ss_family = AF_INET6;
      break;
    default:
      return 0;
      break;
    }
  return 1;
#else
  int ret = inet_aton(name, &((ss->sin).sin_addr));
  ss->ss_family = AF_INET;
  return ret;
#endif
}

#if !defined(USE_IPVX)
static const char * sh_ipvx_h_name (struct hostent * host_entry)
{
  char ** p;
  if (strchr(host_entry->h_name, '.')) {
    return host_entry->h_name;
  } else {
    for (p = host_entry->h_aliases; *p; ++p) {
      if (strchr(*p, '.'))
	return *p;
    }
  }
  return host_entry->h_name;
}
#endif

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

void * sh_dummy_341_out;

char * sh_ipvx_canonical(const char * hostname, char * numeric, size_t nlen)
{
  volatile int    flag = 0;
  char            *out = NULL;
#if defined(USE_IPVX)
  struct addrinfo hints;
  struct addrinfo *res;
  struct sockaddr *sa;
  int             salen;
  int             err;
  struct sh_sockaddr  ss;
  const char * host;
  char hostbuf[SH_BUFSIZE];

  numeric[0] = '\0';

  sh_dummy_341_out = (void *) &out;
 
  if (sh_ipvx_is_numeric(hostname))
    {
      sh_ipvx_aton (hostname, &ss);
      if (0 == getnameinfo(sh_ipvx_sockaddr_cast(&ss), SH_SS_LEN(ss),
			   hostbuf, sizeof(hostbuf), NULL, 0, NI_NAMEREQD))
	host = hostbuf;
      else
	host = hostname;
    }
  else
    {
      host = hostname;
    }
 
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
#if defined(AI_CANONNAME)
  hints.ai_flags = AI_CANONNAME;
#endif 

  err = getaddrinfo(host, NULL, &hints, &res);
  if (err == 0)
    {
#if defined(AI_CANONNAME)
      if (res->ai_canonname && strlen(res->ai_canonname) > 0)
	{
	  out = sh_util_strdup(res->ai_canonname);
	  sh_tolower (out);
	  if (strchr(out, '.'))
	    flag = 1;
	}
#endif

      sa = res->ai_addr;
      salen = res->ai_addrlen;
      getnameinfo(sa, salen,
		  numeric, nlen, NULL, 0, NI_NUMERICHOST);

      if (!flag)
	out = SH_ALLOC(SH_PATHBUF);

      while (res && !flag) 
	{
	  sa = res->ai_addr;
	  salen = res->ai_addrlen;

	  getnameinfo(sa, salen,
		      out, SH_PATHBUF, NULL, 0, 0);
	  sh_tolower (out);
	  if (strchr(out, '.'))
	    flag = 1;
	  
	  res = res->ai_next;
	}
    }
#else
  struct hostent     *he;
  struct sh_sockaddr  ss;
  volatile int        isNum = 0;
  struct sockaddr_in *sin;

  numeric[0] = '\0';

  sh_dummy_341_out = (void *) &out;

  if (sh_ipvx_is_numeric(hostname))
    {
      sh_ipvx_aton (hostname, &ss);
      isNum = 1;
    }
 

  SH_MUTEX_LOCK(mutex_resolv);

  if (isNum == 0)
    {
      he = sh_gethostbyname(hostname);
    }
  else
    {
      sin = (struct sockaddr_in *) sh_ipvx_sockaddr_cast(&ss);
      he = sh_gethostbyaddr(&(sin->sin_addr), sizeof(sin->sin_addr), AF_INET);
    }

  if (he != NULL)
    {
      out = sh_util_strdup(sh_ipvx_h_name(he));
      sh_tolower (out);
      sl_strlcpy (numeric, 
		  inet_ntoa (*(struct in_addr *) he->h_addr), 
		  nlen);
      flag = 1;
    }
  SH_MUTEX_UNLOCK(mutex_resolv);
#endif

  if (flag)
    return out;
  
  if (out)
    SH_FREE(out);
  if (numeric[0] == '\0')
    sl_strlcpy (numeric, _("0.0.0.0"), nlen);
  return NULL;
}

char * sh_ipvx_addrtoname(struct sh_sockaddr * ss)
{
#if defined(USE_IPVX)
  char namebuf[SH_BUFSIZE];

  if (getnameinfo(sh_ipvx_sockaddr_cast(ss), SH_SSP_LEN(ss),
		  namebuf, sizeof(namebuf), NULL, 0, NI_NAMEREQD) != 0)
    {
      return NULL;
    }
  return sh_util_strdup(namebuf);
#else
  struct sockaddr_in *sin;
  struct hostent *he;

  sin = (struct sockaddr_in *) sh_ipvx_sockaddr_cast(ss);

  he = sh_gethostbyaddr(&(sin->sin_addr), sizeof(sin->sin_addr), AF_INET);

  if (he && he->h_name)
    {
      return sh_util_strdup(he->h_name);
    }

  return NULL;
#endif
}

int sh_ipvx_reverse_check_ok (char * peer, int port, struct sh_sockaddr * ss)
{
#if defined(USE_IPVX)
  struct addrinfo *res;
  struct addrinfo hints;
  char            sport[32];
  struct addrinfo *p;

  sl_snprintf(sport, sizeof(sport), "%d", port);

  memset(&hints, '\0', sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_ADDRCONFIG;

  if (getaddrinfo(peer, sport, &hints, &res) != 0)
    {
      return 0;
    }
  
  p = res;
  while (p != NULL)
    {
      if (ss->ss_family == p->ai_family)
	{
	  struct sh_sockaddr pp;

	  char dst1[SH_IP_BUF];
	  char dst2[SH_IP_BUF];

	  sh_ipvx_save(&pp, p->ai_family, p->ai_addr);

	  sh_ipvx_ntoa (dst1, sizeof(dst1), &pp);
	  sh_ipvx_ntoa (dst2, sizeof(dst2),  ss);

	  if (0 == sl_strcmp(dst1, dst2))
	    {
	      return 1;
	    }
	}
      p = p->ai_next;
    }
  freeaddrinfo(res);
#else
  struct hostent * he;
  char          ** p;
  struct sockaddr_in * sin = (struct sockaddr_in *) sh_ipvx_sockaddr_cast(ss);

  (void) port;

  he = sh_gethostbyname(peer);
  if (he != NULL)
    {
      for (p = he->h_addr_list; *p; ++p)
	{
	  if (0 == memcmp (*p, &(sin->sin_addr), sizeof(in_addr_t)) )
	    return 1;
	}
    }
#endif
  return 0;
}

#ifdef SH_CUTEST
#include <stdlib.h>
#include "CuTest.h"

void Test_ipvx (CuTest *tc) {

  int result;

  result = sh_ipvx_is_ipv4("123456789");
  CuAssertTrue(tc, result == FALSE);

  result = sh_ipvx_is_ipv4("123456789123...");
  CuAssertTrue(tc, result == FALSE);

  result = sh_ipvx_is_ipv4("123.456.789.123");
  CuAssertTrue(tc, result == FALSE);

  result = sh_ipvx_is_ipv4("123.156.189.254");
  CuAssertTrue(tc, result == TRUE);

  result = sh_ipvx_is_ipv4("255.255.255.255");
  CuAssertTrue(tc, result == TRUE);

  result = sh_ipvx_is_ipv4("0.0.0.0");
  CuAssertTrue(tc, result == TRUE);

  result = sh_ipvx_is_ipv4("0022.156.189.254");
  CuAssertTrue(tc, result == FALSE);

  result = sh_ipvx_is_ipv4("999999999.1.1.2");
  CuAssertTrue(tc, result == FALSE);

}
#endif

