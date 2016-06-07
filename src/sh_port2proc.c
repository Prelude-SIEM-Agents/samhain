/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2008 Rainer Wichmann                                      */
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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#define NAMLEN(dirent) sl_strlen((dirent)->d_name)
#else
#define dirent direct
#define NAMLEN(dirent) (dirent)->d_namlen
#ifdef HAVE_SYS_NDIR_H
#include <sys/ndir.h>
#endif
#ifdef HAVE_SYS_DIR_H
#include <sys/dir.h>
#endif
#ifdef HAVE_NDIR_H
#include <ndir.h>
#endif
#endif
#define NEED_ADD_DIRENT

#if defined(SH_USE_PORTCHECK) && (defined (SH_WITH_CLIENT) || defined (SH_STANDALONE))

/* #define DEBUG_P2P 1 */

#include "samhain.h"
#include "sh_utils.h"

/****************************************************************************
 *
 *  >>> COMMON CODE <<<
 *
 ****************************************************************************/
#if defined(__linux__) || defined(__FreeBSD__)
 
#include "sh_error_min.h"
#include "sh_pthread.h"
#include "sh_ipvx.h"

#define FIL__  _("sh_port2proc.c")

struct sock_store {
  unsigned long sock;
  size_t        pid;
  char *        path;
  char *        user;
  struct sock_store * next;
};

/* /proc: 
 *        linux:     /proc/pid/exe
 *        freebsd:   /proc/pid/file
 *        solaris10: /proc/pid/path/a.out
 */
static void get_user_and_path (struct sock_store * add)
{
  extern char *  sh_unix_getUIDname (int level, uid_t uid, char * out, size_t len);

  char        path[128];
  char *      buf;
  struct stat sbuf;
  int         len;
  char *      tmp;

  sl_snprintf (path, sizeof(path), "/proc/%ld/exe", (unsigned long) add->pid);

  if (0 == retry_lstat(FIL__, __LINE__, path, &sbuf) && S_ISLNK(sbuf.st_mode))
    {
      goto linkread;
    }

  sl_snprintf (path, sizeof(path), "/proc/%ld/file", (unsigned long) add->pid);

  if (0 == retry_lstat(FIL__, __LINE__, path, &sbuf) && S_ISLNK(sbuf.st_mode))
    {
      goto linkread;
    }

  sl_snprintf (path, sizeof(path), "/proc/%ld/path/a.out", (unsigned long) add->pid);

  if (0 == retry_lstat(FIL__, __LINE__, path, &sbuf) && S_ISLNK(sbuf.st_mode))
    {
      goto linkread;
    }

  return;

 linkread:

  buf = SH_ALLOC(PATH_MAX);
  len = readlink(path, buf, PATH_MAX);   /* flawfinder: ignore */
  len = (len >= PATH_MAX) ? (PATH_MAX-1) : len;

  if (len > 0)
    { 
      buf[len] = '\0';
      add->path = buf;
    }
  else
    {
      SH_FREE(buf);
    }

  add->user = SH_ALLOC(USER_MAX);
  tmp  = sh_unix_getUIDname (SH_ERR_ALL, sbuf.st_uid, add->user, USER_MAX);

  if (!tmp)
    sl_snprintf (add->user, USER_MAX, "%ld", (unsigned long) sbuf.st_uid);

  return;
}

#endif

/****************************************************************************
 *
 *  >>> LINUX CODE <<<
 *
 ****************************************************************************/

#if defined(__linux__)

static  size_t  sh_minpid = 0x0001;
static  size_t  sh_maxpid = 0x8000;

#ifndef HAVE_LSTAT
#define lstat(x,y) stat(x,y)
#endif /* HAVE_LSTAT */

#if defined(S_IFLNK) && !defined(S_ISLNK)
# define S_ISLNK(mode) (((mode) & S_IFMT) == S_IFLNK)
#else
# if !defined(S_ISLNK)
#  define S_ISLNK(mode) (0)
# endif
#endif

#if defined(__linux__)
#define PROC_PID_MAX _("/proc/sys/kernel/pid_max")

static int proc_max_pid (size_t * procpid)
{
  char * ret;
  unsigned long  pid;
  FILE * fd;
  char   str[128];
  char * ptr;

  SL_ENTER(_("proc_max_pid"));
    
  if (0 == access(PROC_PID_MAX, R_OK)) /* flawfinder: ignore */
    {
      if (NULL != (fd = fopen(PROC_PID_MAX, "r")))
        {
          str[0] = '\0';
          ret = fgets(str, 128, fd);
          if (ret && *str != '\0')
            {
              pid = strtoul(str, &ptr, 0);
              if (*ptr == '\0' || *ptr == '\n')
                {
                  sl_fclose(FIL__, __LINE__, fd);
                  *procpid = (size_t) pid;
                  SL_RETURN(0, _("proc_max_pid"));
                }
            }
          sl_fclose(FIL__, __LINE__, fd);
        }
    }
  SL_RETURN((-1), _("proc_max_pid"));
}
#else
static int proc_max_pid(size_t * procpid)
{
  *procpid = sh_maxpid;
  return 0;
}
#endif

static struct sock_store * socklist = NULL;

static void del_sock_all()
{
  struct sock_store * del = socklist;

  while (del)
    {
      socklist = del->next;
      if (del->path)
	SH_FREE(del->path);
      if (del->user)
	SH_FREE(del->user);
      SH_FREE(del);
      del = socklist;
    }
  socklist = NULL;
  return;
}

static void add_sock(unsigned long sock, size_t pid)
{
  struct sock_store * add = SH_ALLOC(sizeof(struct sock_store));

  add->sock = sock;
  add->pid  = pid;
  add->path = NULL;
  add->user = NULL;
  SH_MUTEX_LOCK(mutex_thread_nolog);
  get_user_and_path(add);
  SH_MUTEX_UNLOCK(mutex_thread_nolog);
  add->next = socklist;
  socklist  = add;
  return;
}

static void check_and_add_sock(char * fbuf, size_t pid)
{
  if (0 == strncmp(_("socket:["), fbuf, 8))
    {
      char * end;
      unsigned long sock;
      size_t len = strlen(fbuf);
      if (fbuf[len-1] == ']')
	fbuf[len-1] = '\0';
      sock = strtoul(&fbuf[8], &end, 0);
      if (*end == '\0' && fbuf[8] != '\0')
	{
	  add_sock(sock, pid);
	}
    }
}

static void fetch_socks(size_t pid)
{
  char path[128];
  DIR * dir;
  sl_snprintf(path, sizeof(path), _("/proc/%lu/fd"), (unsigned long) pid);

  dir = opendir(path);
  if (dir)
    {
      struct dirent *entry;
      while (NULL != (entry = readdir(dir)))
	{
	  char fpath[384];
	  char fbuf[64];
	  int  ret;
	  /* /proc/PID/fd/N-> socket:[15713] */
	  sl_snprintf(fpath, sizeof(fpath), _("%s/%s"), path, entry->d_name);
	  ret = readlink(fpath, fbuf, sizeof(fbuf)-1);   /* flawfinder: ignore */
	  if (ret > 0)
	    {
	      fbuf[ret] = '\0';
	      check_and_add_sock(fbuf, pid);
	    }
	}
      closedir(dir);
    }
}

int sh_port2proc_prepare()
{
  size_t i;
  
  if (0 != proc_max_pid(&sh_maxpid))
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN, 
                      _("Failed to detect max_pid"), 
                      _("sh_port2proc"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      SL_RETURN ((-1), _("sh_port2proc"));
    }

  /* Delete old socket list and re-create it
   */
  del_sock_all();

  for (i = sh_minpid; i < sh_maxpid; ++i)
    {
      fetch_socks(i);
    }

  return 0;
}

void sh_port2proc_finish()
{
  /* Delete old socket list
   */
  del_sock_all();
  return;
}


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* returns the command and fills the 'user' array 
 */
static char * port2proc_query(char * file, int proto, int domain,
			      struct sh_sockaddr * saddr, int sport, 
			      unsigned long * pid, char * user, size_t userlen)
{
  FILE * fd;

  fd = fopen(file, "r");

  *pid = 0;

#ifdef DEBUG_P2P
  {
    char errmsg[256];
    char siface[SH_IP_BUF];
    sh_ipvx_ntoa(siface, sizeof(siface), saddr);
    sl_snprintf(errmsg, sizeof(errmsg), 
		"query, file=%s, proto=%d, port=%d, iface=%s\n",
		file, proto, sport, siface);
    fprintf(stderr, "%s", errmsg);
  }
#endif

  if (fd)
    {
      unsigned int n, i, port, niface, inode, istatus;
      char line[512];
      char ip_port[128];
      char iface[SH_IP_BUF];

      while (NULL != fgets(line, sizeof(line), fd))
	{
	
#ifdef DEBUG_P2P
	  {
	    fprintf(stderr, "%s", line);
	  }
#endif

	  if (4 == sscanf(line, 
			  "%u: %127s %*X:%*X %X %*X:%*X %*X:%*X %*X %*d %*d %u %*s",
			  &n, ip_port, &istatus, &inode))
	    {
	      struct sockaddr_in  addr4;
	      struct sockaddr_in6 addr6;
	      struct sh_sockaddr  ss;
	      
	      char * p;

	      ip_port[127] = '\0';

	      p = strchr(ip_port, ':');

	      if (p)
		{
		  *p = '\0'; ++p;
		  port = (unsigned int) strtoul(p, NULL, 16);
		  sl_strlcpy(iface, ip_port, sizeof(iface));
		}
	      else
		{
		  continue;
		}

	      niface = 0;

	      switch (domain) 
		{
		case AF_INET:
		  addr4.sin_addr.s_addr = (int) strtol(iface, NULL, 16);
		  niface = (unsigned int) addr4.sin_addr.s_addr;
		  sh_ipvx_save(&ss, AF_INET, (struct sockaddr *)&addr4);
		  break;

		case AF_INET6:
		  sscanf(iface, 
			 "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx", 
			 &addr6.sin6_addr.s6_addr[3], &addr6.sin6_addr.s6_addr[2], &addr6.sin6_addr.s6_addr[1], &addr6.sin6_addr.s6_addr[0], 
			 &addr6.sin6_addr.s6_addr[7], &addr6.sin6_addr.s6_addr[6], &addr6.sin6_addr.s6_addr[5], &addr6.sin6_addr.s6_addr[4], 
			 &addr6.sin6_addr.s6_addr[11], &addr6.sin6_addr.s6_addr[10], &addr6.sin6_addr.s6_addr[9], &addr6.sin6_addr.s6_addr[8], 
			 &addr6.sin6_addr.s6_addr[15], &addr6.sin6_addr.s6_addr[14], &addr6.sin6_addr.s6_addr[13], &addr6.sin6_addr.s6_addr[12]);
		  
		  for (i = 0; i < 16; ++i)
		    {
		      if (0 != (unsigned int) addr6.sin6_addr.s6_addr[i]) 
			++niface;
		    }
		  sh_ipvx_save(&ss, AF_INET6, (struct sockaddr *)&addr6);
		  break;
		}

#ifdef DEBUG_P2P
	      {
		char a[SH_IP_BUF];
		char b[SH_IP_BUF];

		sh_ipvx_ntoa(a, sizeof(a), &ss);
		sh_ipvx_ntoa(b, sizeof(b), saddr);

		fprintf(stderr, " -> inode %u, iface/port %s,%u, status %u, searching %s,%u, %u\n", 
			inode, a, port, istatus, b, sport, 
			proto == IPPROTO_TCP ? 0x0a : 0x07);
	      }
#endif

	      if (proto == IPPROTO_TCP && istatus != 0x0a)
		continue;
	      if (proto == IPPROTO_UDP && istatus == 0x01)
		continue;

#ifdef DEBUG_P2P
	      {
		fprintf(stderr, "check iface %u..\n", iface);
	      }
#endif

	      if ((proto == IPPROTO_UDP || niface == 0 || 0 == sh_ipvx_cmp(&ss, saddr)) && 
		  port == (unsigned int)sport)
		{
		  struct sock_store * new = socklist;

#ifdef DEBUG_P2P
		  {
		    fprintf(stderr, "found it\n");
		  }
#endif

		  while (new)
		    {
#ifdef DEBUG_P2P
		      {
			fprintf(stderr, "searching inode %u: %lu\n", 
				inode, new->sock);
		      }
#endif
		      if (inode == new->sock)
			{
#ifdef DEBUG_P2P
			  {
			    fprintf(stderr, "found it: path=(%s), user=(%s)\n",
				    new->path == NULL ? "NULL" : new->path,
				    new->user == NULL ? "NULL" : new->user);
			  }
#endif
			  sl_fclose(FIL__, __LINE__, fd);
			  *pid = (unsigned long) new->pid;
			  if (new->path)
			    {
			      if (new->user)
				sl_strlcpy(user, new->user, userlen);
			      else
				sl_strlcpy(user, "-", userlen);
			      return sh_util_strdup(new->path);
			    }
			  goto err_out;
			}
		      new = new->next;
		    }
		}
	    }
	}
      sl_fclose(FIL__, __LINE__, fd);
    }
 err_out:
  sl_strlcpy(user, "-", userlen);
  return sh_util_strdup("-");
}

/* returns the command and fills the 'user' array 
 */
char * sh_port2proc_query(int proto, struct sh_sockaddr * saddr, int sport, 
			  unsigned long * pid, char * user, size_t userlen)
{
  char file[32];
  char * ret;
 
  if (proto == IPPROTO_TCP)
    {
      sl_strlcpy(file, _("/proc/net/tcp"), sizeof(file));
      ret = port2proc_query(file, proto, AF_INET, saddr, sport, pid, user, userlen);

      if (ret[0] == '-' && ret[1] == '\0')
	{
	  SH_FREE(ret);
	  sl_strlcpy(file, _("/proc/net/tcp6"), sizeof(file));
	  ret = port2proc_query(file, proto, AF_INET6, saddr, sport, pid, user, userlen);
	}
      return ret;
    }
  else
    {
      char * ret;
      sl_strlcpy(file, _("/proc/net/udp"), sizeof(file));
      ret = port2proc_query(file, proto, AF_INET, saddr, sport, pid, user, userlen);

      if (ret[0] == '-' && ret[1] == '\0')
	{
	  SH_FREE(ret);
	  sl_strlcpy(file, _("/proc/net/udp6"), sizeof(file));
	  ret = port2proc_query(file, proto, AF_INET6, saddr, sport, pid, user, userlen);
	}
      return ret;
    }
}


/****************************************************************************
 *
 *  >>> FREEBSD CODE <<<
 *
 ****************************************************************************/

#elif defined(__FreeBSD__)

/* Uses code from sockstat.c. Error and memory handling modified.
 * Only required functions from sockstat.c are included.
 */

/*-
 * Copyright (c) 2002 Dag-Erling Co<EF>dan Sm<F8>rgrav
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/usr.bin/sockstat/sockstat.c,v 1.13.2.1.4.1 2008/10/02 02:57:24 kensmith Exp $");

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/file.h>
#include <sys/user.h>

#include <sys/un.h>
#include <sys/unpcb.h>

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

static int       opt_4 = 1;         /* Show IPv4 sockets */
static int       opt_6 = 1;         /* Show IPv6 sockets */
static int       opt_c = 0;         /* Show connected sockets */
static int       opt_l = 1;         /* Show listening sockets */
static int       opt_v = 0;         /* Verbose mode */

struct sock {
        void *socket;
        void *pcb;
        int vflag;
        int family;
        int proto;

        struct sockaddr_storage laddr;
        struct sockaddr_storage faddr;
        struct sock *next;
};

#define HASHSIZE 1009
static struct sock *sockhash[HASHSIZE];

static struct xfile *xfiles;
static int nxfiles;


static void * xrealloc(void * buf, size_t len0, size_t len)
{
  if (len > 0)
    {
      void * xbuf = SH_ALLOC(len);
      if (buf)
	{
	  if (len0 <= len)
	    memcpy(xbuf, buf, len0);
	  else
	    memset(xbuf, '\0', len);
	  SH_FREE(buf);
	}
      return xbuf;
    }
  SH_FREE(buf);
  return NULL;
}

/* Sets address and port in struct sockaddr_storage *sa
 */
static void
sockaddr(struct sockaddr_storage *sa, int af, void *addr, int port)
{
        struct sockaddr_in *sin4;
        struct sockaddr_in6 *sin6;

        bzero(sa, sizeof *sa);
        switch (af) {
        case AF_INET:
                sin4 = (struct sockaddr_in *)sa;
                sin4->sin_len = sizeof *sin4;
                sin4->sin_family = af;
                sin4->sin_port = port;
                sin4->sin_addr = *(struct in_addr *)addr;
                break;
        case AF_INET6:
                sin6 = (struct sockaddr_in6 *)sa;
                sin6->sin6_len = sizeof *sin6;
                sin6->sin6_family = af;
                sin6->sin6_port = port;
                sin6->sin6_addr = *(struct in6_addr *)addr;
                break;
        default:
                return;
        }
}

/* Get socket information from the kernel.
 */
static void
gather_inet(int proto)
{
        struct xinpgen *xig, *exig;
        struct xinpcb *xip;
        struct xtcpcb *xtp;
        struct inpcb *inp;
        struct xsocket *so;
        struct sock *sock;
        char varname[32];
        size_t len, bufsize, bufsize0;
        void *buf;
        int hash, retry, vflag;

        vflag = 0;
        if (opt_4)
                vflag |= INP_IPV4;
        if (opt_6)
                vflag |= INP_IPV6;

        switch (proto) {
        case IPPROTO_TCP:
	  sl_strlcpy(varname, _("net.inet.tcp.pcblist"), sizeof(varname));
                break;
        case IPPROTO_UDP:
                sl_strlcpy(varname, _("net.inet.udp.pcblist"), sizeof(varname));
                break;
        case IPPROTO_DIVERT:
                sl_strlcpy(varname, _("net.inet.divert.pcblist"), sizeof(varname));
                break;
        default:
                return;
        }

        buf = NULL;
        bufsize  = 8192;
	bufsize0 = bufsize;
        retry = 5;
        do {
                for (;;) {
		        buf = xrealloc(buf, bufsize0, bufsize);
			bufsize0 = bufsize;
                        len = bufsize;
                        if (sysctlbyname(varname, buf, &len, NULL, 0) == 0)
                                break;
		        if (errno == ENOENT)
                                goto out;
                        if (errno != ENOMEM)
			  {
			    SH_MUTEX_LOCK(mutex_thread_nolog);
			    sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 
					    0, MSG_E_SUBGEN, 
					    _("sysctlbyname()"), 
					    _("gather_inet"));
			    SH_MUTEX_UNLOCK(mutex_thread_nolog);
			    SH_FREE(buf);
			    return;
			  }
                        bufsize *= 2;
                }
                xig = (struct xinpgen *)buf;
                exig = (struct xinpgen *)(void *)
                    ((char *)buf + len - sizeof *exig);
                if (xig->xig_len != sizeof *xig ||
                    exig->xig_len != sizeof *exig)
		  {
		    SH_MUTEX_LOCK(mutex_thread_nolog);
		    sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN, 
				    _("struct xinpgen size mismatch"), 
				    _("gather_inet"));
		    SH_MUTEX_UNLOCK(mutex_thread_nolog);
		    goto out;
		  }

        } while (xig->xig_gen != exig->xig_gen && retry--);

        if (xig->xig_gen != exig->xig_gen && opt_v)
		  {
		    SH_MUTEX_LOCK(mutex_thread_nolog);
		    sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, 0, MSG_E_SUBGEN, 
				    _("data may be inconsistent"), 
				    _("gather_inet"));
		    SH_MUTEX_UNLOCK(mutex_thread_nolog);
		  }

        for (;;) {
                xig = (struct xinpgen *)(void *)((char *)xig + xig->xig_len);
                if (xig >= exig)
                        break;
                switch (proto) {
                case IPPROTO_TCP:
                        xtp = (struct xtcpcb *)xig;
                        if (xtp->xt_len != sizeof *xtp) {
				SH_MUTEX_LOCK(mutex_thread_nolog);
				sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, 0, MSG_E_SUBGEN, 
						_("struct xtcpcb size mismatch"), 
						_("gather_inet"));
				SH_MUTEX_UNLOCK(mutex_thread_nolog);
                                goto out;
                        }
                        inp = &xtp->xt_inp;
                        so = &xtp->xt_socket;
                        break;
                case IPPROTO_UDP:
                case IPPROTO_DIVERT:
                        xip = (struct xinpcb *)xig;
                        if (xip->xi_len != sizeof *xip) {
				SH_MUTEX_LOCK(mutex_thread_nolog);
				sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, 0, MSG_E_SUBGEN, 
						_("struct xinpcb size mismatch"), 
						_("gather_inet"));
				SH_MUTEX_UNLOCK(mutex_thread_nolog);
                                goto out;
                        }
                        inp = &xip->xi_inp;
                        so = &xip->xi_socket;
                        break;
                default:
                        return;
                }
                if ((inp->inp_vflag & vflag) == 0)
                        continue;
                if (inp->inp_vflag & INP_IPV4) {
                        if ((inp->inp_fport == 0 && !opt_l) ||
                            (inp->inp_fport != 0 && !opt_c))
                                continue;
                } else if (inp->inp_vflag & INP_IPV6) {
#ifndef in6p_fport
#define in6p_fport inp_fport
#endif
                        if ((inp->in6p_fport == 0 && !opt_l) ||
                            (inp->in6p_fport != 0 && !opt_c))
                                continue;
                } else {
		        if (opt_v) {
			        char errmsg[64];
                                sl_snprintf(errmsg, sizeof(errmsg), 
					    _("invalid vflag 0x%x"), inp->inp_vflag);
				SH_MUTEX_LOCK(mutex_thread_nolog);
				sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, 0, MSG_E_SUBGEN, 
						errmsg, 
						_("gather_inet"));
				SH_MUTEX_UNLOCK(mutex_thread_nolog);
				continue;
			}
                }

                sock = SH_ALLOC(sizeof *sock);
		memset(sock, '\0', sizeof (*sock));

#ifndef in6p_lport
#define in6p_lport inp_lport
#endif
                sock->socket = so->xso_so;
                sock->proto = proto;
                if (inp->inp_vflag & INP_IPV4) {
                        sock->family = AF_INET;
                        sockaddr(&sock->laddr, sock->family,
                            &inp->inp_laddr, inp->inp_lport);
                        sockaddr(&sock->faddr, sock->family,
                            &inp->inp_faddr, inp->inp_fport);
                } else if (inp->inp_vflag & INP_IPV6) {
                        sock->family = AF_INET6;
                        sockaddr(&sock->laddr, sock->family,
                            &inp->in6p_laddr, inp->in6p_lport);
                        sockaddr(&sock->faddr, sock->family,
                            &inp->in6p_faddr, inp->in6p_fport);
                }
                sock->vflag = inp->inp_vflag;

                hash = (int)((uintptr_t)sock->socket % HASHSIZE);
                sock->next = sockhash[hash];
                sockhash[hash] = sock;
        }
out:
	if (buf)
	  SH_FREE(buf);
}

static void
getfiles(void)
{
        size_t len;
        size_t len0;

        xfiles = SH_ALLOC(len = sizeof *xfiles);
	len0   = len;

        while (sysctlbyname(_("kern.file"), xfiles, &len, 0, 0) == -1) {
                if (errno != ENOMEM)
		  {
		    volatile int status = errno;
		    SH_MUTEX_LOCK(mutex_thread_nolog);
		    sh_error_handle((-1), FIL__, __LINE__, status, MSG_E_SUBGEN,
				    _("sysctlbyname()"),
				    _("getfiles"));
		    SH_MUTEX_UNLOCK(mutex_thread_nolog);
		  }
                len *= 2;
                xfiles = xrealloc(xfiles, len0, len);
		len0   = len;
        }
        if (len > 0 && xfiles->xf_size != sizeof *xfiles)
                if (errno != ENOMEM)
		  {
		    volatile int status = errno;
		    SH_MUTEX_LOCK(mutex_thread_nolog);
		    sh_error_handle((-1), FIL__, __LINE__, status, MSG_E_SUBGEN,
				    _("struct xfile size mismatch"),
				    _("getfiles"));
		    SH_MUTEX_UNLOCK(mutex_thread_nolog);
		  }
        nxfiles = len / sizeof *xfiles;
}

static const char *
getprocname(pid_t pid)
{
        static struct kinfo_proc proc;
        size_t len;
        int mib[4];

        mib[0] = CTL_KERN;
        mib[1] = KERN_PROC;
        mib[2] = KERN_PROC_PID;
        mib[3] = (int)pid;
        len = sizeof proc;
        if (sysctl(mib, 4, &proc, &len, NULL, 0) == -1) {
                /* Do not warn if the process exits before we get its name. */
                if (errno != ESRCH)
		  {
		    volatile int status = errno;
		    SH_MUTEX_LOCK(mutex_thread_nolog);
		    sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, status, MSG_E_SUBGEN,
				    _("sysctl()"),
				    _("getfiles"));
		    SH_MUTEX_UNLOCK(mutex_thread_nolog);
		  }
                return ("-");
        }
        return (proc.ki_ocomm);
}

char * sh_port2proc_query(int proto, struct sh_sockaddr * saddr, int sport,
			  unsigned long * pid, char * user, size_t userlen)
{
  int n, hash;
  struct xfile *xf;
  struct in_addr  * haddr  = NULL;
  struct in6_addr * haddr6 = NULL;
  struct sock * s;
  struct in6_addr   anyaddr = IN6ADDR_ANY_INIT; 

  *pid = 0;
  
  for (xf = xfiles, n = 0; n < nxfiles; ++n, ++xf) {
    
    if (xf->xf_data == NULL)
      continue;
    
    /* Find the socket in sockhash[] that corresponds to it
     */
    hash = (int)((uintptr_t)xf->xf_data % HASHSIZE);
    for (s = sockhash[hash]; s != NULL; s = s->next)
      if ((void *)s->socket == xf->xf_data)
	break;
    
    if (!s)
      continue;

    if (s->proto != proto)
      continue;

    if (s->family != AF_INET && s->family != AF_INET6)
      continue;

    if (s->family == AF_INET &&
	(sport != ntohs(((struct sockaddr_in *)(&s->laddr))->sin_port)))
      continue;

    if (s->family == AF_INET6 &&
	(sport != ntohs(((struct sockaddr_in6 *)(&s->laddr))->sin6_port)))
      continue;

    if (s->family == AF_INET)
      haddr  = &((struct sockaddr_in  *)(&s->laddr))->sin_addr;
    if (s->family == AF_INET6)
      haddr6 = &((struct sockaddr_in6 *)(&s->laddr))->sin6_addr;
    

    if ( (s->family == AF_INET && 
	  (haddr->s_addr == (saddr->sin).sin_addr.s_addr || 
	   sh_ipvx_isany(saddr) || 
	   inet_lnaof(*haddr) == INADDR_ANY))
	 ||
	 (s->family == AF_INET6 &&
	  (0 == memcmp(haddr6->s6_addr, &((saddr->sin6).sin6_addr.s6_addr), 16) ||
	   0 == memcmp(haddr6->s6_addr, &(anyaddr.s6_addr), 16) ||
	   sh_ipvx_isany(saddr) ))
	 )
      {
	struct sock_store try;
	
	*pid = xf->xf_pid;

	try.pid  = xf->xf_pid;
	try.path = NULL;
	try.user = NULL;
	get_user_and_path (&try); /* Try to get info from /proc */

	if (try.path == NULL)
	  {
	    extern char * sh_unix_getUIDname (int level, uid_t uid, char * out, size_t len);
	    char * tmp  = sh_unix_getUIDname (SH_ERR_ALL, xf->xf_uid, user, userlen);
	    if (!tmp)
	      sl_snprintf (user, userlen, "%ld", (unsigned long) xf->xf_uid);
	    return sh_util_strdup(getprocname(xf->xf_pid));
	  }
	else
	  {
	    sl_strlcpy(user, try.user, userlen);
	    SH_FREE(try.user);
	    return try.path;
	  }
      }
  }
  sl_strlcpy(user, "-", userlen);
  return sh_util_strdup("-");
}

static void sockdel(struct sock * sock)
{
  if (sock)
    {
      if (sock->next)
	sockdel(sock->next);
      SH_FREE(sock);
    }
  return;
}

int sh_port2proc_prepare()
{
  int i;

  if (xfiles)
    {
      SH_FREE(xfiles);
      xfiles = NULL;
    }

  for (i = 0; i < HASHSIZE; ++i)
    {
      sockdel(sockhash[i]);
      sockhash[i] = NULL;
    }

  /* Inet connections
   */
  gather_inet(IPPROTO_TCP);
  gather_inet(IPPROTO_UDP);
  gather_inet(IPPROTO_DIVERT);

  getfiles();

  return 0;
}

void sh_port2proc_finish()
{
  return;
}

#else /* !defined(__linux__) && !defined(__FreeBSD__) */

#include "samhain.h"
#include "sh_utils.h"
#include "sh_ipvx.h"

char * sh_port2proc_query(int proto, struct sh_sockaddr * saddr, int sport,
			  unsigned long * pid, char * user, size_t userlen)
{
  (void) proto;
  (void) saddr;
  (void) sport;

  *pid = 0;

  sl_strlcpy(user, "-", userlen);
  return sh_util_strdup("-");
}

int sh_port2proc_prepare()
{
  return 0;
}

void sh_port2proc_finish()
{
  return;
}
#endif

#endif /* defined(SH_USE_PORTCHECK) */
