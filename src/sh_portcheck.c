/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2006 Rainer Wichmann                                      */
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

/***************************************************************************
 *
 * This file provides a module for samhain to check for open ports
 * on the local machine.
 *
 */


/* #define TEST_ONLY */
#ifndef TEST_ONLY
#include "config_xor.h"
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#define PORTCHK_VERSION "1.0"

#if defined(TEST_ONLY) || (defined(SH_USE_PORTCHECK) && (defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)))


#define PORTMAP
#ifdef  HAVE_RPC_RPC_H
#include <rpc/rpc.h>
#ifdef  HAVE_RPC_RPCENT_H
#include <rpc/rpcent.h>
#endif
#include <rpc/pmap_clnt.h>
#include <rpc/pmap_prot.h>
#endif
#include <netdb.h>

/*
 * struct pmaplist {
 *      struct pmap     pml_map;
 *      struct pmaplist *pml_next;
 * };
 */

/* struct pmap {
 *      long unsigned pm_prog;
 *      long unsigned pm_vers;
 *      long unsigned pm_prot;
 *      long unsigned pm_port;
 * };
 */

/* TIME_WAIT ? 60-240 seconds */

#if !defined(TEST_ONLY)

#define FIL__ _("sh_portcheck.c")
#include "samhain.h"
#include "sh_error.h"
#include "sh_mem.h"
#include "sh_calls.h"
#include "sh_utils.h"
#include "sh_modules.h"
#define SH_NEED_GETHOSTBYXXX
#include "sh_static.h"
#include "sh_pthread.h"
#include "sh_ipvx.h"

/* the size of an interface string 
 */
#define SH_INTERFACE_SIZE SH_IP_BUF

#define SH_PORT_NOT 0
#define SH_PORT_REQ 1
#define SH_PORT_OPT 2
#define SH_PORT_IGN 3
#define SH_PORT_BLACKLIST 4

static char * sh_port_type2str (int type)
{
  if (type == 0) return _("not");
  if (type == 1) return _("req");
  if (type == 2) return _("opt");
  if (type == 3) return _("ign");
  if (type == 4) return _("blc");
  return _("???");
}

#define SH_PORT_MISS 0
#define SH_PORT_ISOK 1
#define SH_PORT_UNKN 2

#define SH_PORT_NOREPT 0
#define SH_PORT_REPORT 1

#define SH_PROTO_TCP 0
#define SH_PROTO_UDP 1
#define SH_PROTO_STR(a) (((a) == IPPROTO_TCP) ? _("tcp") : _("udp"))

struct sh_portentry {
  int  port;
  char interface[SH_INTERFACE_SIZE];
  char * service;
  char * error;
  int  flag;    /* required or not */
  int  status;  /* missing or not  */
  struct sh_portentry * next;
};

static struct sh_portentry * portlist_tcp = NULL;
static struct sh_portentry * portlist_udp = NULL;


#define SH_PORTCHK_INTERVAL 300

static int sh_portchk_check_udp = 1;
static int sh_portchk_active    = 1;
static int sh_portchk_interval  = SH_PORTCHK_INTERVAL;

static int sh_portchk_minport = -1;
static int sh_portchk_maxport = -1;

struct sh_port {
  int                  port;
  struct sh_sockaddr * paddr;
  struct sh_port     * next;
};

static struct sh_port * blacklist_tcp = NULL;
static struct sh_port * blacklist_udp = NULL;

SH_MUTEX_STATIC(mutex_port_check, PTHREAD_MUTEX_INITIALIZER);

static int sh_portchk_severity  = SH_ERR_SEVERE;

extern char * sh_port2proc_query(int proto, struct sh_sockaddr * saddr, int sport,
				 unsigned long * pid, char * user, size_t userlen);
extern int sh_port2proc_prepare();
extern void sh_port2proc_finish();

#endif

/* Exported interface to add ignoreable ports as 'iface:portlist'
 */
static int sh_portchk_add_ignore (const char * str);

/* Exported interface to add required ports as 'iface:portlist'
 */
static int sh_portchk_add_required (const char * str);

/* Exported interface to add optional ports as 'iface:portlist'
 */
static int sh_portchk_add_optional (const char * str);

/* Exported interface to add blacklisted ports as 'iface:portlist'
 */
static int sh_portchk_add_blacklist (const char * str);

/* Exported interface to add an ethernet interface
 */
static int sh_portchk_add_interface (const char * str);

/* verify whether port/interface is blacklisted (do not check)
 */
static int sh_portchk_is_blacklisted(int port, struct sh_sockaddr * haddr, int proto);

#ifndef TEST_ONLY

static int sh_portchk_set_interval (const char * c)
{
  int retval = 0;
  long val;

  SL_ENTER(_("sh_portchk_set_interval"));
  val = strtol (c, (char **)NULL, 10);
  if (val <= 0)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS,
		       _("port check interval"), c);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      retval = -1;
    }
  else
    {
      sh_portchk_interval = (time_t) val;
    }
  SL_RETURN(retval, _("sh_portchk_set_interval"));
}

static int sh_portchk_set_port_minmax (const char * c, int * setthis)
{
  int retval = 0;
  long val;

  SL_ENTER(_("sh_portchk_set_port_minmax"));
  val = strtol (c, (char **)NULL, 10);
  if (val < 0 || val > 65535)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS,
		       _("port check port minmax"), c);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      retval = -1;
    }
  else
    {
      *setthis = (int) val;
    }
  SL_RETURN(retval, _("sh_portchk_set_port_minmax"));
}


static int sh_portchk_set_minport   (const char * str)
{
  return sh_portchk_set_port_minmax (str, &sh_portchk_minport);
}

static int sh_portchk_set_maxport   (const char * str)
{
  return sh_portchk_set_port_minmax (str, &sh_portchk_maxport);
}

static int sh_portchk_set_active   (const char * str)
{
  return sh_util_flagval(str, &sh_portchk_active);
}

static int sh_portchk_set_udp      (const char * str)
{
  return sh_util_flagval(str, &sh_portchk_check_udp);
}

static int sh_portchk_set_severity (const char * str)
{
  char tmp[32];
  tmp[0] = '='; tmp[1] = '\0';
  sl_strlcat (tmp, str, 32);
  return sh_error_set_level (tmp, &sh_portchk_severity);
}

sh_rconf sh_portchk_table[] = {
    {
        N_("severityportcheck"),
        sh_portchk_set_severity,
    },
    {
        N_("portcheckrequired"),
        sh_portchk_add_required,
    },
    {
        N_("portcheckoptional"),
        sh_portchk_add_optional,
    },
    {
        N_("portcheckignore"),
        sh_portchk_add_ignore,
    },
    {
        N_("portcheckskip"),
        sh_portchk_add_blacklist,
    },
    {
        N_("portcheckactive"),
        sh_portchk_set_active,
    },
    {
        N_("portcheckinterface"),
        sh_portchk_add_interface,
    },
    {
        N_("portcheckinterval"),
        sh_portchk_set_interval,
    },
    {
        N_("portcheckminport"),
        sh_portchk_set_minport,
    },
    {
        N_("portcheckmaxport"),
        sh_portchk_set_maxport,
    },
    {
        N_("portcheckudp"),
        sh_portchk_set_udp,
    },
    {
        NULL,
        NULL
    }
};

#endif

/* Interface to initialize port check
 */
int sh_portchk_init (struct mod_type * arg);

/* Interface to reset port check
 */
int sh_portchk_reset (void);

/* Interface to run port check
 */
int sh_portchk_check (void);


static char * check_services (int port, int proto);

#ifdef TEST_ONLY

static int portchk_debug = 0; 
#define SH_ALLOC       malloc
#define SH_FREE        free
#define sh_util_strdup strdup
#define sl_strlcpy     strncpy
#define _(a)           a

#else

static int portchk_debug = 0;

#endif

#ifdef  HAVE_RPC_RPC_H
static char * sh_getrpcbynumber (int number, char * buf, size_t len)
{
  FILE * fp;

  if (NULL != (fp = fopen(_("/etc/rpc"), "r")))
    {
      sh_string * s = sh_string_new(0);
      while (0 < sh_string_read(s, fp, 1024))
	{
	  char * p = sh_string_str(s);
	  while (*p && (*p == ' ' || *p == '\t')) ++p; /* skip whitespace */
	  if (*p == '\0' || *p == '#') 
	    continue; /* skip comment */
	  else
	    {
	      size_t lengths[3];
 	      unsigned int  fields = 3;
 	      char * q             = sh_string_str(s);
	      char ** splits       = split_array_ws(q, &fields, lengths);

	      if (fields >= 2)
		{
		  int n = atoi(splits[1]);
		  if (n == number)
		    {
		      sl_strlcpy(buf, splits[0], len);
		      SH_FREE(splits);
		      sh_string_destroy(&s);
		      sl_fclose(FIL__, __LINE__, fp);
		      return buf;
		    }
		}
	      SH_FREE(splits);
	    }
	}
      sh_string_destroy(&s);
      sl_fclose(FIL__, __LINE__, fp);
    }
  return NULL;
}
#endif

static char * sh_getservbyport (int port, const char * proto_in, char * buf, size_t len)
{
  FILE * fp;
  char   proto[8];

  sl_strlcpy(proto, proto_in, sizeof(proto));

  if (NULL != (fp = fopen(_("/etc/services"), "r")))
    {
      sh_string * s = sh_string_new(0);
      while (0 < sh_string_read(s, fp, 1024))
	{
	  char * p = sh_string_str(s);
	  while (*p && (*p == ' ' || *p == '\t')) ++p; /* skip whitespace */
	  if (*p == '\0' || *p == '#')
	    continue; /* skip comment */
	  else
	    {
	      size_t lengths[3];
 	      unsigned int  fields = 3;
 	      char * q             = sh_string_str(s);
	      char ** splits       = split_array_ws(q, &fields, lengths);

	      if (fields >= 2)
		{
		  char * end;
		  long n = strtol(splits[1], &end, 10);
		  if (n == port && end && (*end == '/' || *end == ','))
		    {
		      ++end;
		      if (0 == strcmp(end, proto))
			{
			  sl_strlcpy(buf, splits[0], len);
			  SH_FREE(splits);
			  sh_string_destroy(&s);
			  sl_fclose(FIL__, __LINE__, fp);
			  return buf;
			}
		    }
		}
	      SH_FREE(splits);
	    }
	}
      sh_string_destroy(&s);
      sl_fclose(FIL__, __LINE__, fp);
    }
  return NULL;
}

static void sh_portchk_add_to_list (int proto, 
				    int port, struct sh_sockaddr * paddr, 
				    char * service,
				    int flag, int status)
{
  struct sh_portentry * new = SH_ALLOC (sizeof(struct sh_portentry));

  new->port = port;
  sh_ipvx_ntoa(new->interface, SH_INTERFACE_SIZE, paddr);
  new->status = status;
  new->flag   = flag;

  new->error  = NULL;

  if (portchk_debug)
    fprintf(stderr, _("add to list: port %d/%s %d %d (%s) %s\n"),
	    port, SH_PROTO_STR(proto), flag, status, service ? service : _("undef"),
	    new->interface);

  if (service)
    new->service = sh_util_strdup (service);
  else
    new->service = NULL;
  if (proto == IPPROTO_TCP)
    {
      new->next = portlist_tcp;
      portlist_tcp = new;
    }
  else
    {
      new->next = portlist_udp;
      portlist_udp = new;
    }
  return;
}

/* Reset the list by setting all entries to UNKN.
 * In the next cycle we will check, and set found ports to ISOK.
 * Thereafter, we check for entries that are still UNKN.
 */
static void sh_portchk_reset_lists (void)
{
  struct sh_portentry * portlist;

  portlist = portlist_tcp;
  while (portlist)
    {
      if (portlist->status != SH_PORT_MISS)
	portlist->status = SH_PORT_UNKN;
      portlist = portlist->next;
    }
  portlist = portlist_udp;
  while (portlist)
    {
      if (portlist->status != SH_PORT_MISS)
	portlist->status = SH_PORT_UNKN;
      portlist = portlist->next;
    }
  return;
}

static struct sh_portentry * sh_portchk_kill_list (struct sh_portentry * head)
{
  if (head)
    {
      if (head->next)
	sh_portchk_kill_list (head->next);

      if (head->service)
	SH_FREE(head->service);
      SH_FREE(head);
    }
  return NULL;
}
  
static struct sh_port * sh_portchk_kill_blacklist (struct sh_port * head)
{
  if (head)
    {
      if (head->next)
	sh_portchk_kill_blacklist (head->next);

      SH_FREE(head->paddr);
      SH_FREE(head);
    }
  return NULL;
}
  
/* These variables are not used anywhere. They only exist
 * to assign &pre, &ptr to them, which keeps gcc from
 * putting it into a register, and avoids the 'clobbered
 * by longjmp' warning. And no, 'volatile' proved insufficient.
 */
void * sh_dummy_531_pre = NULL;
void * sh_dummy_532_ptr = NULL;

/* check the list of open ports for any that are marked as UNKN
 */
static void sh_portchk_check_list (struct sh_portentry ** head, 
				   int proto, int report)
{
  struct sh_portentry * ptr = *head;
  struct sh_portentry * pre = *head;
  char errbuf[256];

  /* Take the address to keep gcc from putting them into registers. 
   * Avoids the 'clobbered by longjmp' warning. 
   */
  sh_dummy_531_pre = (void*) &pre;
  sh_dummy_532_ptr = (void*) &ptr;
 
  while (ptr)
    {
      if (portchk_debug && report)
	fprintf(stderr, _("check list: port %d/%s %d %d\n"),
		ptr->port, SH_PROTO_STR(proto), ptr->flag, ptr->status);

      if (ptr->status == SH_PORT_UNKN)
	{
	  /* Don't report missing ports that are marked as optional
	   */
	  if (ptr->flag != SH_PORT_OPT && ptr->flag != SH_PORT_IGN)
	    {
	      snprintf (errbuf, sizeof(errbuf), _("port: %s:%d/%s (%s)"), 
			ptr->interface, ptr->port, SH_PROTO_STR(proto), 
			ptr->service ? ptr->service : check_services(ptr->port, proto));
#ifdef TEST_ONLY
	      if (report == SH_PORT_REPORT)
		fprintf(stderr, _("%s\n"), errbuf);
#else
	      if (report == SH_PORT_REPORT)
		{
		  SH_MUTEX_LOCK(mutex_thread_nolog);
		  sh_error_handle(sh_portchk_severity, FIL__, __LINE__, 0, 
				  MSG_PORT_MISS, errbuf);
		  SH_MUTEX_UNLOCK(mutex_thread_nolog);
		}
#endif
	    }

	  ptr->status = SH_PORT_MISS;

	  if ((ptr->flag != SH_PORT_REQ) && (ptr->flag != SH_PORT_OPT) && (ptr->flag != SH_PORT_IGN))
	    {
	      if (portchk_debug && report)
		fprintf(stderr, _("removing: port %d/%s %d %d\n"),
			ptr->port, SH_PROTO_STR(proto), ptr->flag, ptr->status);
	      
	      if (ptr == *head)
		{
		  *head = ptr->next;
		  if (ptr->service)
		    SH_FREE(ptr->service);
		  SH_FREE(ptr);
		  ptr = *head;
		  pre = *head;
		  continue;
		}
	      else if (ptr->next == NULL)
		{
		  pre->next = NULL;
		  if (ptr->service)
		    SH_FREE(ptr->service);
		  SH_FREE(ptr);
		  return;
		}
	      else
		{
		  pre->next = ptr->next;
		  if (ptr->service)
		    SH_FREE(ptr->service);
		  SH_FREE(ptr);
		  ptr = pre->next;
		  continue;
		}
	    }
	}
      pre = ptr;
      ptr = ptr->next;
    }

  sh_dummy_532_ptr = NULL;
  sh_dummy_531_pre = NULL;

  return;
}


static struct sh_portentry * sh_portchk_get_from_list (int proto, int port, 
						       struct sh_sockaddr * paddr, char * service)
{
  struct sh_portentry * portlist;
  char str_addr[SH_IP_BUF];

  if (proto == IPPROTO_TCP)
    portlist = portlist_tcp;
  else
    portlist = portlist_udp;

  sh_ipvx_ntoa(str_addr, sizeof(str_addr), paddr);

  if (service)
    {
      while (portlist) 
	{
	  if (portlist->service && 
	      0 == strcmp(service, portlist->service) &&
	      ( 0 == strcmp(portlist->interface, str_addr) ||
	        sh_ipvx_isany(paddr) ))
	    return portlist;
	  portlist = portlist->next;
	}
    }
  else
    {
      while (portlist) 
	{
	  if (port == portlist->port &&
	      (0 == strcmp(portlist->interface, str_addr)  ||
	       sh_ipvx_isany(paddr) ))
	    return portlist;
	  portlist = portlist->next;
	}
    }
  return NULL;
}
      

static void sh_portchk_cmp_to_list (int proto, int port, 
				    struct sh_sockaddr * paddr, char * service)
{
  struct sh_portentry * portent;
  char errbuf[256];

  
  portent = sh_portchk_get_from_list (proto, port, paddr, service);

  if (service)
    {
      if (!portent)
	{
	  char * path;
	  unsigned long qpid;
	  char   user[USER_MAX];
	  char   saddr[SH_IP_BUF];

	  sh_ipvx_ntoa(saddr, sizeof(saddr), paddr);

	  snprintf (errbuf, sizeof(errbuf), _("port: %s:%d/%s (%s)"), 
		    saddr, port, SH_PROTO_STR(proto), service);

	  if (portchk_debug)
	    fprintf(stderr, _("cmp_to_list: open port: %s:%d/%s (%s)\n"), 
		    saddr, port, SH_PROTO_STR(proto), service);

#ifndef TEST_ONLY
	  path = sh_port2proc_query(proto, paddr, port, &qpid, user, sizeof(user));
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle(sh_portchk_severity, FIL__, __LINE__, 0, 
			  MSG_PORT_NEW, errbuf, path, qpid, user);
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  SH_FREE(path);
#endif
	  /* 
	   * was not there, thus it is not in 'required' or 'optional' list
	   */
	  sh_portchk_add_to_list (proto, port, paddr, service, SH_PORT_NOT, SH_PORT_ISOK);
	}
      else if (portent->status == SH_PORT_MISS && portent->flag != SH_PORT_IGN)
	{
	  char * path;
	  unsigned long qpid;
	  char   user[USER_MAX];
	  char   saddr[SH_IP_BUF];

	  sh_ipvx_ntoa(saddr, sizeof(saddr), paddr);

	  snprintf (errbuf, sizeof(errbuf), _("port: %s:%d/%s (%s), was %d/%s"), 
		    saddr, port, SH_PROTO_STR(proto), service, portent->port, SH_PROTO_STR(proto));
#ifdef TEST_ONLY
	  fprintf(stderr, _("service: %s\n"), errbuf);
#else
	  path = sh_port2proc_query(proto, paddr, port, &qpid, user, sizeof(user));
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle(sh_portchk_severity, FIL__, __LINE__, 0, 
			  MSG_PORT_RESTART, errbuf, path, qpid, user);
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  SH_FREE(path);
#endif

	  portent->status = SH_PORT_ISOK;
	}
      else if (port != portent->port && (-1) != portent->port)
	{
	  char * path;
	  unsigned long qpid;
	  char   user[USER_MAX];
	  char   saddr[SH_IP_BUF];

	  sh_ipvx_ntoa(saddr, sizeof(saddr), paddr);

	  snprintf (errbuf, sizeof(errbuf), _("port: %s:%d/%s (%s), was %d/%s"), 
		    saddr, port, SH_PROTO_STR(proto), service, portent->port, SH_PROTO_STR(proto));
#ifdef TEST_ONLY
	  fprintf(stderr, _("service: %s\n"), errbuf);
#else
	  path = sh_port2proc_query(proto, paddr, port, &qpid, user, sizeof(user));
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle(sh_portchk_severity, FIL__, __LINE__, 0, 
			  MSG_PORT_NEWPORT, errbuf, path, qpid, user);
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  SH_FREE(path);
#endif
	  portent->port   = port;
	  portent->status = SH_PORT_ISOK;
	}
      else
	{
	  portent->status = SH_PORT_ISOK;
	}
    }
  else
    {
      if (!portent)
	{
	  char * path;
	  unsigned long qpid;
	  char   user[USER_MAX];
	  char   saddr[SH_IP_BUF];

	  if (portchk_debug)
	    fprintf(stderr, _("call to  sh_ipvx_ntoa (port %d)\n"), port);
 
	  sh_ipvx_ntoa(saddr, sizeof(saddr), paddr);

	  snprintf (errbuf, sizeof(errbuf), _("port: %s:%d/%s (%s)"), 
		    saddr, port, SH_PROTO_STR(proto), check_services(port, proto));

	  if (portchk_debug)
	    fprintf(stderr, _("cmp_to_list: open port: %s:%d/%s (%s) check_services\n"), 
		    saddr, port, SH_PROTO_STR(proto), check_services(port, proto));

#ifndef TEST_ONLY
	  path = sh_port2proc_query(proto, paddr, port, &qpid, user, sizeof(user));
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle(sh_portchk_severity, FIL__, __LINE__, 0, 
			  MSG_PORT_NEW, errbuf, path, qpid, user);
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  SH_FREE(path);
#endif

	  /* was not there, thus it is not in 'required' or 'optional' list
	   */
	  sh_portchk_add_to_list (proto, port, paddr, service, SH_PORT_NOT, SH_PORT_ISOK);
	}
      else if (portent->status == SH_PORT_MISS && portent->flag != SH_PORT_IGN)
	{
	  char * path;
	  unsigned long qpid;
	  char   user[USER_MAX];
	  char   saddr[SH_IP_BUF];

	  sh_ipvx_ntoa(saddr, sizeof(saddr), paddr);

	  snprintf (errbuf, sizeof(errbuf), _("port: %s:%d/%s (%s)"), 
		    saddr, port, SH_PROTO_STR(proto), check_services(port, proto));
#ifdef TEST_ONLY
	  fprintf(stderr, _("port   : %s\n"), errbuf);
#else
	  path = sh_port2proc_query(proto, paddr, port, &qpid, user, sizeof(user));
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle(sh_portchk_severity, FIL__, __LINE__, 0, 
			  MSG_PORT_RESTART, errbuf, path, qpid, user);
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  SH_FREE(path);
#endif

	  portent->status = SH_PORT_ISOK;
	}
      else
	{
	  portent->status = SH_PORT_ISOK;
	}
    }

  return;
}

			       
/* Returns a static buffer containing the name of the service
 * running on port <port> (from /etc/services)
 * Returns NULL on failure
 */
static char * check_services (int port, int proto)
{
  static char buf[256];
  char * service = sh_getservbyport(port, SH_PROTO_STR(proto), buf, sizeof(buf));

  if (!service)
    {
      snprintf (buf, sizeof(buf), "%s",_("unknown"));
    }
  return buf;
}

/* Returns a static buffer containing the name of the service
 * running on port <port> at <address> (from portmap daemon)
 * Returns NULL on failure
 */
static char * check_rpc_list (int port, struct sockaddr_in * address, 
			      unsigned long prot)
{
#if defined(HAVE_RPC_RPC_H) && defined(HAVE_PMAP_GETMAPS)
  struct pmaplist * head;
  char *r;
  static char buf[256];

  head = pmap_getmaps(address);

  if (head) 
    {
      do /* while (head != NULL) */
	{
	  if ((head->pml_map.pm_prot == prot) && 
	      (port == (int)head->pml_map.pm_port)) 
	    {
	      r = sh_getrpcbynumber((int)head->pml_map.pm_prog, 
				    buf, sizeof(buf));
	      if (r)
		{
		  return buf;
		}
	      else
		{
		  snprintf (buf, sizeof(buf), "RPC_%lu",
			    (unsigned long)head->pml_map.pm_prog);
		  return buf;
		}
	    }
	  head = head->pml_next;
	}
      while (head != NULL);
    }
#else
  (void) port;
  (void) address;
  (void) prot;
#endif
  return NULL;
}

static int check_port_udp_internal (int fd, int port, struct sh_sockaddr * paddr)
{
  int                retval;
  char             * p = NULL;
  char               buf[8];
#ifndef TEST_ONLY
  char               errmsg[256];
  int                nerr;
#endif
  char errbuf[SH_ERRBUF_SIZE];
  char ipbuf[SH_IP_BUF];

  sh_ipvx_set_port(paddr, port);

  do {
    retval = connect(fd, sh_ipvx_sockaddr_cast(paddr), SH_SSP_LEN(paddr));
  } while (retval < 0 && (errno == EINTR || errno == EINPROGRESS));

  if (retval == -1)
    {
#ifdef TEST_ONLY
      if (portchk_debug)
	perror(_("connect"));
#else
      sh_ipvx_ntoa(ipbuf, sizeof(ipbuf), paddr);

      nerr = errno;
      sl_snprintf(errmsg, sizeof(errmsg), _("check port: %5d/udp on %15s: %s"),
		  port, ipbuf, sh_error_message(errno, errbuf, sizeof(errbuf)));
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle((-1), FIL__, __LINE__, nerr, MSG_E_SUBGEN, 
		      errmsg, _("connect"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
#endif
    }
  else
    {
      do {
	retval = send (fd, buf, 0, 0);
      } while (retval < 0 && errno == EINTR);

      if (retval == -1 && errno == ECONNREFUSED)
	{
	  sh_ipvx_ntoa(ipbuf, sizeof(ipbuf), paddr);
	  if (portchk_debug)
	    fprintf(stderr, _("check port_udp: %5d/udp on %15s established/time_wait\n"),
		    port, ipbuf);
	}
      else 
	{
	  /* Only the second send() may catch the error 
	   */
	  do {
	    retval = send (fd, buf, 0, 0);
	  } while (retval < 0 && errno == EINTR);

	  if (retval == -1 && errno == ECONNREFUSED)
	    {
	      sh_ipvx_ntoa(ipbuf, sizeof(ipbuf), paddr);
	      if (portchk_debug)
		fprintf(stderr, _("check port: %5d/udp on %15s established/time_wait\n"),
			port, ipbuf);
	    }
	  else if (retval != -1)
	    {
	      /* Try to get service name from portmap
	       */
	      if (paddr->ss_family == AF_INET)
		{
		  p = check_rpc_list (port, 
				      (struct sockaddr_in *) sh_ipvx_sockaddr_cast(paddr), 
				      IPPROTO_UDP);
		}

	      sh_portchk_cmp_to_list (IPPROTO_UDP, port, paddr, p ? p : NULL);
	      
	      /* If not an RPC service, try to get name from /etc/services
	       */
	      if (!p)
		p = check_services(port, IPPROTO_UDP);
	      
	      if (portchk_debug)
		{
		  sh_ipvx_ntoa(ipbuf, sizeof(ipbuf), paddr);
		  fprintf(stderr, _("check port_udp: %5d/udp on %15s open %s\n"), 
			  port, ipbuf, p);
		}
	      
	    }
	  else
	    {
	      if (portchk_debug)
		{
		  sh_ipvx_ntoa(ipbuf, sizeof(ipbuf), paddr);
		  fprintf(stderr, _("check port_udp: %5d/udp on %15s ERRNO %d\n"), 
			  port, ipbuf, errno);
		}
	    }
	}
    }
  sl_close_fd (FIL__, __LINE__, fd);
  return 0;
}

static int check_port_tcp_internal (int fd, int port, struct sh_sockaddr * paddr)
{
  int                retval;
  int                flags;
  char             * p = NULL;
#ifndef TEST_ONLY
  char               errmsg[256];
  int                nerr;
#endif
  char errbuf[SH_ERRBUF_SIZE];
  char ipbuf[SH_IP_BUF];

  sh_ipvx_set_port(paddr, port);

  do {
    retval = connect(fd, sh_ipvx_sockaddr_cast(paddr), SH_SSP_LEN(paddr));
  } while (retval < 0 && (errno == EINTR || errno == EINPROGRESS));

  if (retval == -1 && errno == ECONNREFUSED)
    {
      if (portchk_debug)
	{
	  sh_ipvx_ntoa(ipbuf, sizeof(ipbuf), paddr);
	  fprintf(stderr, _("check port_tcp: %5d on %15s closed\n"),
		  port, ipbuf);
	}
    }
  else if (retval == -1)
    {
#ifdef TEST_ONLY
      if (portchk_debug)
	perror(_("connect"));
#else
      sh_ipvx_ntoa(ipbuf, sizeof(ipbuf), paddr);
      nerr = errno;
      sl_snprintf(errmsg, sizeof(errmsg), _("check port: %5d/tcp on %15s: %s"),
		  port, ipbuf, sh_error_message(errno, errbuf, sizeof(errbuf)));
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle((-1), FIL__, __LINE__, nerr, MSG_E_SUBGEN, 
		      errmsg, _("connect"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
#endif
    }
  else
    {
      /* Try to get service name from portmap
       */
      if (paddr->ss_family == AF_INET)
	{
	  p = check_rpc_list (port, 
			      (struct sockaddr_in *) sh_ipvx_sockaddr_cast(paddr), 
			      IPPROTO_TCP);
	}

      sh_portchk_cmp_to_list (IPPROTO_TCP, port, paddr, p ? p : NULL);

      /* If not an RPC service, try to get name from /etc/services
       */
      if (!p)
	p = check_services(port, IPPROTO_TCP);

      if (portchk_debug)
	{
	  sh_ipvx_ntoa(ipbuf, sizeof(ipbuf), paddr);
	  fprintf(stderr, _("check port_tcp: %5d on %15s open %s\n"), 
		  port, ipbuf, p);
	}

#if !defined(O_NONBLOCK)
#if defined(O_NDELAY)
#define O_NONBLOCK  O_NDELAY
#else
#define O_NONBLOCK  0
#endif
#endif

      /* prepare to close connection gracefully
       */
      if      (port == 22)  /* ssh */
	{
	  flags = retry_fcntl(FIL__, __LINE__, fd, F_GETFL, 0);
	  retry_fcntl(FIL__, __LINE__, fd, F_SETFL, flags | O_NONBLOCK);
	  retval = write (fd, _("SSH-2.0-Foobar"), 14);
	  if (retval > 0) retval = write (fd, "\r\n", 2);
	}
      else if (port == 25)  /* smtp */
	{
	  flags = retry_fcntl(FIL__, __LINE__, fd, F_GETFL, 0);
	  retry_fcntl(FIL__, __LINE__, fd, F_SETFL, flags | O_NONBLOCK);
	  retval = write (fd, _("QUIT"), 4);
	  if (retval > 0) retval = write (fd, "\r\n", 2);
	}
      else if (port == 79)  /* finger */
	{
	  flags = retry_fcntl(FIL__, __LINE__, fd, F_GETFL, 0);
	  retry_fcntl(FIL__, __LINE__, fd, F_SETFL, flags | O_NONBLOCK);
	  retval = write (fd, "\r\n", 2);
	}
      else if (port == 110) /* pop3 */
	{
	  flags = retry_fcntl(FIL__, __LINE__, fd, F_GETFL, 0);
	  retry_fcntl(FIL__, __LINE__, fd, F_SETFL, flags | O_NONBLOCK);
	  retval = write (fd, _("QUIT"), 4);
	  if (retval > 0) retval = write (fd, "\r\n", 2);
	}
      else if (port == 143) /* imap */
	{
	  flags = retry_fcntl(FIL__, __LINE__, fd, F_GETFL, 0);
	  retry_fcntl(FIL__, __LINE__, fd, F_SETFL, flags | O_NONBLOCK);
	  retval = write (fd, _("A01 LOGOUT"), 10);
	  if (retval > 0) retval = write (fd, "\r\n", 2);
	}

      if (portchk_debug && retval < 0)
	fprintf(stderr, _("check port: error writing to port %5d\n"), 
		port);
     }
  sl_close_fd (FIL__, __LINE__, fd);
  return 0;
}

/* typedef uint32_t in_addr_t;
 * struct in_addr
 * {
 * in_addr_t s_addr;
 * };
 */

#define SH_IFACE_MAX 16

struct portchk_interfaces {
  struct sh_sockaddr iface[SH_IFACE_MAX];
  int            used;
};

static struct portchk_interfaces iface_list;
static int iface_initialized = 0;

#ifdef TEST_ONLY
static char * portchk_hostname = NULL;
#else
static char * portchk_hostname = sh.host.name;
#endif

static int sh_portchk_init_internal (void)
{
  volatile int     i, j; /* might be clobbered by ‘longjmp’ or ‘vfork’*/
  char errbuf[256];
#if defined(USE_IPVX)
  struct addrinfo hints;
  struct addrinfo *res;
#else
  struct hostent * hent;
#endif
  char ipbuf[SH_IP_BUF];

  if (portchk_debug)
    fprintf(stderr, _("checking ports on: %s\n"), portchk_hostname ? portchk_hostname : _("NULL"));

  if (!portchk_hostname)
    return -1;

  if (sh_portchk_active == S_FALSE)
    return -1;

  SH_MUTEX_LOCK(mutex_port_check);
  if (iface_initialized == 0)
    {
      iface_list.used   = 0;
      iface_initialized = 1;
    }

#if !defined(USE_IPVX)
  SH_MUTEX_LOCK(mutex_resolv);
  hent = sh_gethostbyname(portchk_hostname);
  i = 0;
  while (hent && hent->h_addr_list[i] && (iface_list.used < SH_IFACE_MAX))
    {
      struct sockaddr_in sin;
      struct sh_sockaddr iface_tmp;

      memcpy(&(sin.sin_addr.s_addr), hent->h_addr_list[i], sizeof(in_addr_t));
      sh_ipvx_save(&iface_tmp, AF_INET, (struct sockaddr *)&sin);

      for (j = 0; j < iface_list.used; ++j)
	{
	  if (0 == sh_ipvx_cmp(&iface_tmp, &(iface_list.iface[j])))
	    {
	      goto next_iface;
	    }
	}

      sh_ipvx_save(&(iface_list.iface[iface_list.used]), 
		   AF_INET, (struct sockaddr *)&sin);
      
      if (portchk_debug)
	{
	  char buf[256];
	  sh_ipvx_ntoa(buf, sizeof(buf), &(iface_list.iface[iface_list.used]));
	  fprintf(stderr, _("added interface[%d]: %s\n"), i, buf); 
	}
      ++iface_list.used;

    next_iface:
      ++i;
    }
  SH_MUTEX_UNLOCK(mutex_resolv);
#else
  memset(&hints, '\0', sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_flags  = AI_ADDRCONFIG;

  if (0 == getaddrinfo(portchk_hostname, NULL, &hints, &res))
    {
      struct addrinfo *p = res;
      struct sh_sockaddr iface_tmp;

      while ((p != NULL) && (iface_list.used < SH_IFACE_MAX))
	{
	  sh_ipvx_save(&iface_tmp, p->ai_family, p->ai_addr);

          for (j = 0; j < iface_list.used; ++j)
	    {
	      if (portchk_debug)
		{
		  char buf1[256], buf2[256];
		  sh_ipvx_ntoa(buf1, sizeof(buf1), &(iface_list.iface[j]));
		  sh_ipvx_ntoa(buf2, sizeof(buf2), &iface_tmp);
		  fprintf(stderr, _("check interface[%d]: %s vs %s\n"), j, buf1, buf2); 
		}
	      if (0 == sh_ipvx_cmp(&iface_tmp, &(iface_list.iface[j])))
		{
		  if (portchk_debug) 
		    fprintf(stderr, _("skipping interface[%d]\n"), j);
		  goto next_iface;
		}
	    }
	  sh_ipvx_save(&(iface_list.iface[iface_list.used]), 
		       p->ai_family, p->ai_addr);

	  if (portchk_debug)
	    {
	      char buf[256];
	      sh_ipvx_ntoa(buf, sizeof(buf), &(iface_list.iface[iface_list.used]));
	      fprintf(stderr, _("added interface[%d]: %s\n"), iface_list.used, buf); 
	    }

	  ++iface_list.used;

	next_iface:
	  p = p->ai_next;
	}
      freeaddrinfo(res);
    } 
#endif

  for (i = 0; i < iface_list.used; ++i)
    {
      sh_ipvx_ntoa(ipbuf, sizeof(ipbuf), &(iface_list.iface[i]));
      sl_snprintf(errbuf, sizeof(errbuf), _("added interface: %s"), ipbuf);

      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_INFO, FIL__, __LINE__, 0, MSG_E_SUBGEN, 
		      errbuf, _("sh_portchk_init"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
    }
  SH_MUTEX_UNLOCK(mutex_port_check);

  return 0;
}

int sh_portchk_init (struct mod_type * arg)
{
#ifndef HAVE_PTHREAD
  (void) arg;
#endif

  if (sh_portchk_active == S_FALSE)
    return SH_MOD_FAILED;
  if (!portchk_hostname)
    return SH_MOD_FAILED;

#ifdef HAVE_PTHREAD
  if (arg != NULL && arg->initval < 0 &&
      (sh.flag.isdaemon == S_TRUE || sh.flag.loop == S_TRUE))
    {
      if (0 == sh_pthread_create(sh_threaded_module_run, (void *)arg))
	return SH_MOD_THREAD;
      else
	return SH_MOD_FAILED;
    }
  else if (arg != NULL && arg->initval == SH_MOD_THREAD &&
	   (sh.flag.isdaemon == S_TRUE || sh.flag.loop == S_TRUE))
    {
      return SH_MOD_THREAD;
    }
#endif
  return sh_portchk_init_internal();
}



#if !defined(TEST_ONLY)
int sh_portchk_reconf (void)
{
  SH_MUTEX_LOCK(mutex_port_check);
  iface_initialized    = 0;
  sh_portchk_active    = 1;
  sh_portchk_check_udp = 1;
  sh_portchk_interval  = SH_PORTCHK_INTERVAL;

  sh_portchk_minport = -1;
  sh_portchk_maxport = -1;

  portlist_udp = sh_portchk_kill_list (portlist_udp);
  portlist_tcp = sh_portchk_kill_list (portlist_tcp);

  blacklist_udp = sh_portchk_kill_blacklist (blacklist_udp);
  blacklist_tcp = sh_portchk_kill_blacklist (blacklist_tcp);
  sh_port2proc_finish();

  SH_MUTEX_UNLOCK(mutex_port_check);
  return 0;
}

int sh_portchk_cleanup (void)
{
  return sh_portchk_reconf ();
}

int sh_portchk_timer (time_t tcurrent) 
{
  static time_t lastcheck = 0;

  SL_ENTER(_("sh_portchk_timer"));
  if ((time_t) (tcurrent - lastcheck) >= sh_portchk_interval)
    {
      lastcheck  = tcurrent;
      SL_RETURN((-1), _("sh_portchk_timer"));
    }
  SL_RETURN(0, _("sh_portchk_timer"));
}
#endif

static int check_port_generic (int port, int domain, int type, int protocol)
{
  volatile int     i    =  0;
  int              sock = -1;
  int              flag =  1; /* non-zero to enable an option */
  struct sh_sockaddr   paddr;
  char errbuf[SH_ERRBUF_SIZE];

  /* Check all interfaces for this host
   */
  while (i < iface_list.used)
    {
      memcpy(&paddr, &(iface_list.iface[i]), sizeof(paddr));

      if (paddr.ss_family != domain)
	{
	  ++i;
	  continue;
	}

      if (0 != sh_portchk_is_blacklisted(port, &paddr, protocol))
	{
	  ++i; 
	  continue;
	}

      if ((sock = socket(paddr.ss_family, type, protocol)) < 0 )
	{
	  ++i;
#ifdef TEST_ONLY
	  if (portchk_debug)
	    perror(_("socket"));
#else

#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT 0
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT    0
#endif
	  if (errno != EPROTONOSUPPORT && errno != EAFNOSUPPORT)
	    {
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN, 
			      sh_error_message(errno, errbuf, sizeof(errbuf)), _("socket"));
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	    }
#endif
	  continue;
	}
      if ( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		      (void *) &flag, sizeof(flag)) < 0 )
	{
	  ++i;
#ifdef TEST_ONLY
	  if (portchk_debug)
	    perror(_("setsockopt"));
#else
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN, 
			  sh_error_message(errno, errbuf, sizeof(errbuf)),_("setsockopt"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
#endif
	  continue;
	}


      if (protocol == IPPROTO_TCP)
	check_port_tcp_internal(sock, port, &paddr);
      else
	check_port_udp_internal(sock, port, &paddr);

      ++i;
    }

  return 0;
}



static int check_port_udp (int port, int domain)
{
  return check_port_generic(port, domain, SOCK_DGRAM, IPPROTO_UDP);
}

static int check_port_tcp (int port, int domain)
{
  return check_port_generic(port, domain, SOCK_STREAM, IPPROTO_TCP);
}


static int sh_portchk_scan_ports_generic (int min_port, int max_port_arg, 
					  int domain, int type, int protocol)
{
  /*
  int min_port = 1024;
  int max_port = 65535;
  */

  volatile int port; /*  might be clobbered by ‘longjmp’ or ‘vfork’*/
  volatile int max_port = max_port_arg;
  int retval;
  int sock   = -1;
#if 0
  int flag   = 1; /* non-zero to enable an option */
#endif
  struct sockaddr_in  addr4;
  struct sockaddr_in6 addr6;

  int addrlen4      = sizeof(addr4);
  int addrlen6      = sizeof(addr6);

  struct in6_addr anyaddr = IN6ADDR_ANY_INIT; 

  char errbuf[SH_ERRBUF_SIZE];

  if (min_port == -1)
     min_port = 0;
  if (max_port == -1)
    max_port = 65535;

  if (portchk_debug)
    fprintf(stderr, _("scan_ports_generic %d-%d %s %s\n"), 
	    min_port, max_port, (domain == AF_INET6) ? _("AF_INET6") : _("AF_INET"),
	    (protocol == IPPROTO_TCP) ? _("tcp") : _("udp"));
	    
  for (port = min_port; port <= max_port; ++port) 
    {
      if ((sock = socket(domain, type, protocol)) < 0 )
	{
#ifdef TEST_ONLY
	  if (portchk_debug)
	    perror(_("socket"));
#else
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT 0
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT    0
#endif
	  if (errno != EPROTONOSUPPORT && errno != EAFNOSUPPORT)
	    {
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN, 
			      sh_error_message(errno, errbuf, sizeof(errbuf)), _("socket"));
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	    }
#endif
	  continue;
	}

#if 0
      if ( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		      (void *) &flag, sizeof(flag)) < 0 )
	{
#ifdef TEST_ONLY
	  if (portchk_debug)
	    perror(_("setsockopt"));
#else
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN, 
			  sh_error_message(errno, errbuf, sizeof(errbuf)),_("setsockopt"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
#endif
	  continue;
	}
#endif

      if (domain == AF_INET)
	{
	  addr4.sin_family      = AF_INET;
	  addr4.sin_port        = htons(port);
	  addr4.sin_addr.s_addr = INADDR_ANY;
	  retval = bind (sock, (struct sockaddr *) &addr4, addrlen4);
	}
      else
	{
	  addr6.sin6_family       = AF_INET6;
	  addr6.sin6_port         = htons(port);
	  memcpy(&(addr6.sin6_addr.s6_addr), &anyaddr, sizeof(anyaddr));
	  retval = bind (sock, (struct sockaddr *) &addr6, addrlen6);
	}

      if (retval == 0)
	{
	  /* we can bind the port, thus it is unused
	   */
	  sl_close_fd (FIL__, __LINE__, sock);
	}
      else
	{
	  if (errno == EINVAL || errno == EADDRINUSE)
	    {
	      /* try to connect to the port
	       */
	      if (protocol == IPPROTO_TCP)
		check_port_tcp(port, domain);
	      else
		check_port_udp(port, domain);
	    }
	  else
	    {
#ifdef TEST_ONLY
	      if (portchk_debug)
		perror(_("bind"));
#else
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle((-1), FIL__, __LINE__, errno, MSG_E_SUBGEN, 
			      sh_error_message(errno, errbuf, sizeof(errbuf)), _("bind"));
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
#endif
	    }
	  sl_close_fd (FIL__, __LINE__, sock);
	}
    }
  return 0;
}

static int sh_portchk_scan_ports_tcp (int min_port, int max_port)
{
#if defined(USE_IPVX)
  sh_portchk_scan_ports_generic (min_port, max_port, AF_INET6, 
				 SOCK_STREAM, IPPROTO_TCP);
#endif
  return sh_portchk_scan_ports_generic (min_port, max_port, AF_INET, 
					SOCK_STREAM, IPPROTO_TCP);
}
 
static int sh_portchk_scan_ports_udp (int min_port, int max_port)
{
#if defined(USE_IPVX)
  sh_portchk_scan_ports_generic (min_port, max_port, AF_INET6, 
				 SOCK_DGRAM, IPPROTO_UDP);
#endif
  return sh_portchk_scan_ports_generic (min_port, max_port, AF_INET,
					SOCK_DGRAM, IPPROTO_UDP);
}

/* Subroutine to add an interface
 */
void * sh_dummy_1564_str    = NULL; /* fix clobbered by.. warning */

static int sh_portchk_add_interface (const char * str)
{
  struct sh_sockaddr saddr;
  char errbuf[256];
  char buf[64];

  sh_dummy_1564_str    = (void*) &str;

  if (iface_initialized == 0)
    {
      iface_list.used   = 0;
      iface_initialized = 1;
    }

  do {

    while (*str == ',' || *str == ' ' || *str == '\t') ++str;

    if (*str)
      {
	char ipbuf[SH_IP_BUF];
	unsigned int i = 0;
	while (*str && i < (sizeof(buf)-1) && 
	       *str != ',' && *str != ' ' && *str != '\t')
	  {
	    buf[i] = *str; ++str; ++i;
	  }
	buf[i] = '\0';

	if (0 == sh_ipvx_aton(buf, &saddr))
	  return -1;

	if (iface_list.used == SH_IFACE_MAX)
	  return -1;

	sh_ipvx_ntoa(ipbuf, sizeof(ipbuf), &saddr);
	sl_snprintf(errbuf, sizeof(errbuf), _("interface: %s"), ipbuf);
	SH_MUTEX_LOCK(mutex_thread_nolog);
	sh_error_handle(SH_ERR_INFO, FIL__, __LINE__, 0, MSG_E_SUBGEN, 
			errbuf, _("sh_portchk_add_interface"));
	SH_MUTEX_UNLOCK(mutex_thread_nolog);
	
	memcpy (&(iface_list.iface[iface_list.used]), &(saddr), sizeof(saddr));
	++iface_list.used;
      }
  } while (*str);

  sh_dummy_1564_str = NULL;
  return 0;
}

/* verify whether port/interface is blacklisted (do not check)
 */
static int sh_portchk_is_blacklisted(int port, struct sh_sockaddr * saddr, 
				     int proto)
{
  struct sh_port * head;

  if (proto == IPPROTO_TCP)
    head = blacklist_tcp;
  else
    head = blacklist_udp;

  while (head)
    {
      if (head->port == port)
	{
	  if (sh_ipvx_isany(head->paddr) || 
	      0 == sh_ipvx_cmp(head->paddr, saddr))
	    return 1;
	  else
	    return 0;
	}
      head = head->next;
    }
  return 0;
}


static int sh_portchk_blacklist(int port, struct sh_sockaddr * saddr, int proto)
{
  struct sh_port * black;
  struct sh_port * head;

  if (proto == IPPROTO_TCP)
    head = blacklist_tcp;
  else
    head = blacklist_udp;

  black = head;

  while (black)
    {
      if (black->port == port && 
	  0 == sh_ipvx_cmp(head->paddr, saddr))
	return -1;
      black = black->next;
    }

  black = SH_ALLOC (sizeof(struct sh_port));
  black->paddr = SH_ALLOC (sizeof(struct sh_sockaddr));
  black->port  = port;
  memcpy(black->paddr, saddr, sizeof(struct sh_sockaddr));
  black->next  = head;

  if (proto == IPPROTO_TCP)
    blacklist_tcp = black;
  else
    blacklist_udp = black;

  if (portchk_debug)
    {
      int checkit = sh_portchk_is_blacklisted(port, saddr, proto);
      fprintf(stderr, _("port blacklisted: %d %s\n"), port, 
	      (checkit == 1) ? _("ok") : _("fail"));
    }
  return 0;
}
  
 
/* Subroutine to add a required or optional port/service
 */
static int sh_portchk_add_required_port_generic (char * service, 
						 char * interface, int type)
{
  char buf[256] = { '\0' };
  int proto;
  char * p;
  char * endptr;
  unsigned long int  port;
  struct sh_sockaddr   saddr;
  struct sh_portentry * portent;

  if (0 == sh_ipvx_aton(interface, &saddr))
    return -1;

  sl_strlcpy (buf, service, sizeof(buf));

  p = strchr(buf, '/');
  if (!p)
    return -1;
  if (0 == strcmp(p, _("/tcp")))
    proto = IPPROTO_TCP;
  else if  (0 == strcmp(p, _("/udp")))
    proto = IPPROTO_UDP;
  else
    return -1;

  *p = '\0';
  port = strtoul(buf, &endptr, 0);

  if (portchk_debug)
    {
      char buf[SH_IP_BUF];
      sh_ipvx_ntoa(buf, sizeof(buf), &saddr);
      fprintf(stderr, _("add_port_generic: %s (%s) %d %s (%s)\n"),
	      interface, buf, (int) port, (proto == IPPROTO_TCP) ? _("tcp") : _("udp"),
	      sh_port_type2str(type));
    }

  /* Blacklisted ports
   */
  if (*endptr == '\0' && port <= 65535 && type == SH_PORT_BLACKLIST)
    return (sh_portchk_blacklist(port, &saddr, proto));

  if (*endptr != '\0')
    {  
      portent = sh_portchk_get_from_list (proto, -1, &saddr, buf);
      if (!portent)
	{
	  if (portchk_debug)
	    fprintf(stderr, _("add_required_port %d\n"), (int) port);
	  sh_portchk_add_to_list (proto,   -1, &saddr,  buf, type, SH_PORT_UNKN);
	}
      else
	{
#ifdef TEST_ONLY
	  fprintf(stderr, "** WARNING: duplicate port definition %s/%s\n", buf, SH_PROTO_STR(proto));
#else
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN, 
			  _("duplicate port definition"), _("sh_portchk_add_required_port_generic"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
#endif
	  return -1;
	}
    }
  else if (port <= 65535)
    {
      portent = sh_portchk_get_from_list (proto, port, &saddr, NULL);
      if (!portent)
	{
	  if (portchk_debug)
	    fprintf(stderr, _("add_required_port: open port: %d/%s\n"), 
		    (int) port, SH_PROTO_STR(proto));
	  sh_portchk_add_to_list (proto, port, &saddr, NULL, type, SH_PORT_UNKN);
	}
      else
	{
#ifdef TEST_ONLY
	  fprintf(stderr, "** WARNING: duplicate port definition %lu/%s\n", port, SH_PROTO_STR(proto));
#else
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN, 
			  _("duplicate port definition"), _("sh_portchk_add_required_port_generic"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
#endif
	  return -1;
	}
    }
  else
    return -1;

  return 0;
}

/* Internal interface to add required or optional ports as 'iface:portlist'
 */
static int sh_portchk_add_required_generic (const char * str, int type)
{
  size_t ll = 0;
  int    status;

  char * interface = NULL;
  char * list;
  char * p;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
  char * saveptr;
#endif

  if (!str)
    return -1;

  if (strchr(str, ':'))
    {
      char *last = strrchr(str, ':');
      if (last != NULL)
	{
	  size_t tolast = (last - str);
	  interface = SH_ALLOC(tolast+1);
	  sl_strlcpy(interface, str, tolast+1);
	  interface[tolast] = '\0';

	  ll = tolast;

	  while (str[ll] == ':' || str[ll] == ' ' || str[ll] == '\t')
	    ++ll;
	}
    }
  else
    {
      interface = SH_ALLOC(8);
      sl_strlcpy(interface, _("0.0.0.0"), 8);
      interface[7] = '\0';
      while (str[ll] == ' ' || str[ll] == '\t')
	++ll;      
    }

  if (!interface)
    return -1;

  if (str[ll] == '\0')
    {
      SH_FREE(interface);
      return -1;
    }

  if (portchk_debug)
    fprintf(stderr, "add ports for interface: %s (%s)\n", interface, sh_port_type2str(type));

  list = sh_util_strdup(&str[ll]);
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
  p    = strtok_r (list, " ,\t", &saveptr);
#else
  p    = strtok (list, " ,\t");
#endif
  if (!p)
    {
      SH_FREE(interface);
      SH_FREE(list);
      return -1;
    }
  while (p)
    {
      status = sh_portchk_add_required_port_generic (p, interface, type);

      if (-1 == status)
	{
	  SH_FREE(interface);
	  SH_FREE(list);
	  return -1;
	}
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
      p    = strtok_r (NULL, " ,\t", &saveptr);
#else
      p    = strtok (NULL, " ,\t");
#endif
    }
  SH_FREE(interface);
  SH_FREE(list);
  return 0;
}

/* User interface to add required ports as 'iface:portlist'
 */
static int sh_portchk_add_required (const char * str)
{
  return sh_portchk_add_required_generic (str, SH_PORT_REQ); 
}

/* User interface to add optional ports as 'iface:portlist'
 */
static int sh_portchk_add_optional (const char * str)
{
  return sh_portchk_add_required_generic (str, SH_PORT_OPT); 
}

/* User interface to add ignoreable ports as 'iface:portlist'
 */
static int sh_portchk_add_ignore (const char * str)
{
  return sh_portchk_add_required_generic (str, SH_PORT_IGN); 
}

/* User interface to add ports that should not be checked as 'iface:portlist'
 */
static int sh_portchk_add_blacklist (const char * str)
{
  return sh_portchk_add_required_generic (str, SH_PORT_BLACKLIST); 
}

/* Interface to run port check
 */
int sh_portchk_check ()
{
  volatile int min_port;
  static int noprivports = 0;

  SH_MUTEX_LOCK(mutex_port_check);

  min_port = (sh_portchk_minport == -1) ? 0 : sh_portchk_minport;

  if (sh_portchk_active != S_FALSE)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_INFO, FIL__, __LINE__, 0, MSG_E_SUBGEN, 
		      _("Checking for open ports"),
		      _("sh_portchk_check"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);

      sh_portchk_reset_lists();
      if ((0 != geteuid()) && (min_port < 1024))
	{
	  min_port = 1024;
	  if (noprivports == 0)
	    {
#ifdef TEST_ONLY
	      fprintf(stderr, "** WARNING not scanning ports < 1024\n");
#else
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN, 
			      _("not scanning ports below 1024"), 
			      _("sh_portchk_check"));
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
#endif
	      noprivports = 1;
	    }
	}

      sh_port2proc_prepare();

      if (sh_portchk_check_udp == 1)
	sh_portchk_scan_ports_udp(min_port, sh_portchk_maxport);
      sh_portchk_scan_ports_tcp(min_port, sh_portchk_maxport);


      sh_portchk_check_list (&portlist_tcp, IPPROTO_TCP, SH_PORT_REPORT);
      if (sh_portchk_check_udp == 1)
	sh_portchk_check_list (&portlist_udp, IPPROTO_UDP, SH_PORT_REPORT);

    }
  SH_MUTEX_UNLOCK(mutex_port_check);
  return 0;
}
#endif

#ifdef SH_CUTEST
#include "CuTest.h"

void Test_portcheck_lists (CuTest *tc)
{
#if defined(SH_USE_PORTCHECK) && (defined(SH_WITH_CLIENT) || defined(SH_STANDALONE))
  struct sh_sockaddr    haddr_local;
  struct sh_portentry * portent;
  char   buf[256];
  char * p;

#ifdef HAVE_RPC_RPC_H
  p = sh_getrpcbynumber(0, buf, sizeof(buf));
  CuAssertTrue(tc, p == NULL);

  p = sh_getrpcbynumber(100000, buf, sizeof(buf));
  CuAssertPtrNotNull(tc, p);
  CuAssertTrue(tc, (0 == strcmp(p, "portmapper") || 0 == strcmp(p, "rpcbind")));
  CuAssertTrue(tc, (0 == strcmp(buf, "portmapper") || 0 == strcmp(p, "rpcbind")));

  p = sh_getrpcbynumber(100007, buf, sizeof(buf));
  CuAssertPtrNotNull(tc, p);
  CuAssertTrue(tc, 0 == strcmp(p, "ypbind"));
  CuAssertTrue(tc, 0 == strcmp(buf, "ypbind"));
#endif

  p = sh_getservbyport(0, SH_PROTO_STR(IPPROTO_UDP), buf, sizeof(buf));
  CuAssertTrue(tc, p == NULL);

#if !defined(HOST_IS_CYGWIN)
  p = sh_getservbyport(22, SH_PROTO_STR(IPPROTO_TCP), buf, sizeof(buf));
  CuAssertPtrNotNull(tc, p);
  CuAssertTrue(tc, 0 == strcmp(p, "ssh"));
  CuAssertTrue(tc, 0 == strcmp(buf, "ssh"));
#endif

  p = sh_getservbyport(13, SH_PROTO_STR(IPPROTO_UDP), buf, sizeof(buf));
  CuAssertPtrNotNull(tc, p);
  CuAssertTrue(tc, 0 == strcmp(p, "daytime"));
  CuAssertTrue(tc, 0 == strcmp(buf, "daytime"));

  CuAssertTrue(tc, 0 != sh_ipvx_aton("127.0.0.1", &haddr_local));

  sh_portchk_add_to_list (IPPROTO_TCP,  8000, &haddr_local, NULL, SH_PORT_NOT, SH_PORT_UNKN);

  portent = sh_portchk_get_from_list(IPPROTO_TCP,  8000, &haddr_local, NULL);
  CuAssertPtrNotNull(tc, portent);

  CuAssertTrue(tc, portent->port == 8000);
  CuAssertTrue(tc, 0 == strcmp("127.0.0.1", portent->interface));
  CuAssertTrue(tc, portent->status == SH_PORT_UNKN);
  CuAssertTrue(tc, portent->flag == SH_PORT_NOT);

  sh_portchk_check_list (&portlist_tcp, IPPROTO_TCP, SH_PORT_NOREPT);

  CuAssertTrue(tc, NULL == portlist_tcp);

  sh_portchk_add_to_list (IPPROTO_TCP,  8000, &haddr_local, NULL, SH_PORT_REQ, SH_PORT_UNKN);
  sh_portchk_add_to_list (IPPROTO_TCP,  8001, &haddr_local, NULL, SH_PORT_NOT, SH_PORT_UNKN);
  sh_portchk_add_to_list (IPPROTO_TCP,  8002, &haddr_local, NULL, SH_PORT_REQ, SH_PORT_UNKN);
  sh_portchk_add_to_list (IPPROTO_TCP,  8003, &haddr_local, NULL, SH_PORT_NOT, SH_PORT_UNKN);
  sh_portchk_add_to_list (IPPROTO_TCP,  8004, &haddr_local, NULL, SH_PORT_IGN, SH_PORT_UNKN);
  sh_portchk_add_to_list (IPPROTO_TCP,    -1, &haddr_local, "foo1", SH_PORT_NOT, SH_PORT_UNKN);
  sh_portchk_add_to_list (IPPROTO_TCP,    -1, &haddr_local, "foo2", SH_PORT_REQ, SH_PORT_UNKN);
  sh_portchk_add_to_list (IPPROTO_TCP,    -1, &haddr_local, "foo3", SH_PORT_NOT, SH_PORT_UNKN);
  sh_portchk_add_to_list (IPPROTO_TCP,    -1, &haddr_local, "foo4", SH_PORT_REQ, SH_PORT_UNKN);
  sh_portchk_add_to_list (IPPROTO_TCP,    -1, &haddr_local, "foo5", SH_PORT_IGN, SH_PORT_UNKN);

  sh_portchk_check_list (&portlist_tcp, IPPROTO_TCP, SH_PORT_NOREPT);

  CuAssertPtrNotNull(tc, portlist_tcp);

  portent = sh_portchk_get_from_list(IPPROTO_TCP,  8000, &haddr_local, NULL);
  CuAssertPtrNotNull(tc, portent);

  portent = sh_portchk_get_from_list(IPPROTO_TCP,  8001, &haddr_local, NULL);
  CuAssertTrue(tc, NULL == portent);

  portent = sh_portchk_get_from_list(IPPROTO_TCP,  8002, &haddr_local, NULL);
  CuAssertPtrNotNull(tc, portent);

  portent = sh_portchk_get_from_list(IPPROTO_TCP,  8003, &haddr_local, NULL);
  CuAssertTrue(tc, NULL == portent);

  portent = sh_portchk_get_from_list(IPPROTO_TCP,  8004, &haddr_local, NULL);
  CuAssertPtrNotNull(tc, portent);

  portent = sh_portchk_get_from_list(IPPROTO_TCP,  8000, &haddr_local, "foo1");
  CuAssertTrue(tc, NULL == portent);

  portent = sh_portchk_get_from_list(IPPROTO_TCP,  8000, &haddr_local, "foo2");
  CuAssertPtrNotNull(tc, portent);
  CuAssertTrue(tc, 0 == strcmp(portent->service, "foo2"));

  portent = sh_portchk_get_from_list(IPPROTO_TCP,  8000, &haddr_local, "foo3");
  CuAssertTrue(tc, NULL == portent);

  portent = sh_portchk_get_from_list(IPPROTO_TCP,  8000, &haddr_local, "foo4");
  CuAssertPtrNotNull(tc, portent);
  CuAssertTrue(tc, 0 == strcmp(portent->service, "foo4"));

  portent = sh_portchk_get_from_list(IPPROTO_TCP,  8000, &haddr_local, "foo5");
  CuAssertPtrNotNull(tc, portent);
  CuAssertTrue(tc, 0 == strcmp(portent->service, "foo5"));

  CuAssertTrue(tc, 0 == sh_portchk_blacklist(666, &haddr_local, IPPROTO_TCP));
  CuAssertTrue(tc, 0 != sh_portchk_blacklist(666, &haddr_local, IPPROTO_TCP));
  CuAssertTrue(tc, 0 == sh_portchk_blacklist(667, &haddr_local, IPPROTO_TCP));
  CuAssertTrue(tc, 0 == sh_portchk_blacklist(668, &haddr_local, IPPROTO_TCP));
  CuAssertTrue(tc, 0 == sh_portchk_blacklist(666, &haddr_local, IPPROTO_UDP));
  CuAssertTrue(tc, 0 != sh_portchk_blacklist(666, &haddr_local, IPPROTO_UDP));
  CuAssertTrue(tc, 0 == sh_portchk_blacklist(667, &haddr_local, IPPROTO_UDP));
  CuAssertTrue(tc, 0 == sh_portchk_blacklist(668, &haddr_local, IPPROTO_UDP));

  CuAssertTrue(tc, 0 != sh_portchk_is_blacklisted(668, &haddr_local, IPPROTO_UDP));
  CuAssertTrue(tc, 0 != sh_portchk_is_blacklisted(667, &haddr_local, IPPROTO_UDP));
  CuAssertTrue(tc, 0 != sh_portchk_is_blacklisted(666, &haddr_local, IPPROTO_UDP));
  CuAssertTrue(tc, 0 == sh_portchk_is_blacklisted(665, &haddr_local, IPPROTO_UDP));

  CuAssertTrue(tc, 0 != sh_portchk_is_blacklisted(668, &haddr_local, IPPROTO_TCP));
  CuAssertTrue(tc, 0 != sh_portchk_is_blacklisted(667, &haddr_local, IPPROTO_TCP));
  CuAssertTrue(tc, 0 != sh_portchk_is_blacklisted(666, &haddr_local, IPPROTO_TCP));
  CuAssertTrue(tc, 0 == sh_portchk_is_blacklisted(665, &haddr_local, IPPROTO_TCP));
#else
  (void) tc; /* fix compiler warning */
#endif
  return;
}
#endif

#ifdef TEST_ONLY

void usage (char * pname)
{
  printf ("%s [-r|--required interface:portlist][-o|--optional interface:portlist][--no-udp][-d|--debug] hostname\n\n", pname);
  printf ("   Check local host for open ports; Version %s\n\n", PORTCHK_VERSION);
  printf ("   Interface: Numeric address for an interface, e.g. 127.0.0.1\n");
  printf ("   Portlist:  List of ports or services, e.g. 22/tcp,nfs/udp,nlockmgr/udp\n");
  printf ("     required -> must be open\n");
  printf ("     optional ->  may be open or closed\n");
  printf ("   RPC services must be specified with service **name**, others with **port number**\n\n");
  printf ("   Example:\n");
  printf ("      %s --required 192.168.1.2:22/tcp,nfs/udp,nlockmgr/udp\n\n", pname);
  return;
}

int main(int argc, char *argv[])
{
  char * pname = argv[0];


  /* 
  test_lists();

  portlist_tcp = sh_portchk_kill_list (portlist_tcp);
  portlist_udp = sh_portchk_kill_list (portlist_udp);
  */

  /* sh_portchk_add_required ("127.0.0.1 : nlockmgr/tcp, 5308/tcp, nfs/tcp"); */

  while (argc > 1 && argv[1][0] == '-')
    {
      if (0 == strcmp(argv[1], "--help") || 0 == strcmp(argv[1], "-h"))
	{
	  usage(pname);
	  exit (0);
	}
      else if (0 == strcmp(argv[1], "--required") || 0 == strcmp(argv[1], "-r"))
	{
	  if (argc < 3)
	    {
	      usage(pname);
	      exit (1);
	    }
	  sh_portchk_add_required (argv[2]);
	  --argc; ++argv;
	}
      else if (0 == strcmp(argv[1], "--optional") || 0 == strcmp(argv[1], "-o"))
	{
	  if (argc < 3)
	    {
	      usage(pname);
	      exit (1);
	    }
	  sh_portchk_add_optional (argv[2]);
	  --argc; ++argv;
	}
      else if (0 == strcmp(argv[1], "--no-udp"))
	{
	  sh_portchk_check_udp = 0;
	}
      else if (0 == strcmp(argv[1], "--debug") || 0 == strcmp(argv[1], "-d"))
	{
	  portchk_debug = 1;
	}
      else
	{
	  usage(pname);
	  exit (1);
	}
      --argc; ++argv;
    }

  if (argc < 2)
    {
      usage(pname);
      exit (1);
    }

  portchk_hostname = argv[1];
      
  if (0 != sh_portchk_init ())
    {
      usage(pname);
      exit (1);
    }

  sh_portchk_check();

  return 0;
}
#endif
