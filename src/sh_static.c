/*  Copyright (C) 2003     Manuel Novoa III
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 *  You should have received a copy of the GNU Library General Public
 *  License along with this library; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*  Nov 6, 2003  Initial version.
 *
 *  NOTE: This implementation is quite strict about requiring all
 *    field seperators.  It also does not allow leading whitespace
 *    except when processing the numeric fields.  glibc is more
 *    lenient.  See the various glibc difference comments below.
 *
 *  TODO:
 *    Move to dynamic allocation of (currently staticly allocated)
 *      buffers; especially for the group-related functions since
 *      large group member lists will cause error returns.
 *
 */

/* Jul 20, 2004 Adapted for samhain. Rainer Wichmann.
 *
 *   Stripped all unneeded code.
 */

#include "config_xor.h"

#if defined(SH_COMPILE_STATIC) && defined(__linux__)

#define _GNU_SOURCE
#include <features.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>

#include "sh_pthread.h"

extern  int sl_close_fd (const char * file, int line, int fd);
extern  int sl_fclose (const char * file, int line, FILE * fp);


#ifndef _PATH_PASSWD
#define _PATH_PASSWD "/etc/passwd"
#endif
#ifndef _PATH_GROUP
#define _PATH_GROUP "/etc/group"
#endif

#undef  FIL__
#define FIL__  _("sh_static.c")

extern  int sl_strlcpy(char * dst, /*@null@*/const char * src, size_t siz);
extern  int sl_strlcat(char * dst, /*@null@*/const char * src, size_t siz);


/**********************************************************************/
/* Sizes for staticly allocated buffers. */

#define PWD_BUFFER_SIZE 256
#define GRP_BUFFER_SIZE 3584
#define GRP_BUFFER_SIZE_MALLOC 32768

/**********************************************************************/
/* Prototypes for internal functions. */

static int __parsepwent(void *pw, char *line);
static int __parsegrent(void *gr, char *line);

static int __pgsreader(int (*__parserfunc)(void *d, char *line), void *data,
		       char *__restrict line_buff, 
		       size_t buflen, FILE *f);

#undef  GETXXKEY_R_FUNC	
#undef  GETXXKEY_R_PARSER
#undef  GETXXKEY_R_ENTTYPE
#undef  GETXXKEY_R_TEST
#undef  DO_GETXXKEY_R_KEYTYPE
#undef  DO_GETXXKEY_R_PATHNAME
#define GETXXKEY_R_FUNC			sh_getpwnam_r
#define GETXXKEY_R_PARSER   	__parsepwent
#define GETXXKEY_R_ENTTYPE		struct passwd
#define GETXXKEY_R_TEST(ENT)	(!strcmp((ENT)->pw_name, key))
#define DO_GETXXKEY_R_KEYTYPE	const char *__restrict
#define DO_GETXXKEY_R_PATHNAME  _PATH_PASSWD

int GETXXKEY_R_FUNC(DO_GETXXKEY_R_KEYTYPE key,
		    GETXXKEY_R_ENTTYPE *__restrict resultbuf,
		    char *__restrict buffer, size_t buflen,
		    GETXXKEY_R_ENTTYPE **__restrict result)
{
  FILE *stream;
  int rv;
  
  *result = NULL;
  
  if (!(stream = fopen(DO_GETXXKEY_R_PATHNAME, "r"))) {
    rv = errno;
  } else {
    /* __STDIO_SET_USER_LOCKING(stream); */
    do {
      if (!(rv = __pgsreader(GETXXKEY_R_PARSER, resultbuf,
			     buffer, buflen, stream))
	  ) {
	if (GETXXKEY_R_TEST(resultbuf)) { /* Found key? */
	  *result = resultbuf;
	  break;
	}
      } else {
	if (rv == ENOENT) {	/* end-of-file encountered. */
	  rv = 0;
	}
	break;
      }
    } while (1);
    sl_fclose(FIL__, __LINE__, stream);
  }
  
  return rv;
}

#undef  GETXXKEY_R_FUNC	
#undef  GETXXKEY_R_PARSER
#undef  GETXXKEY_R_ENTTYPE
#undef  GETXXKEY_R_TEST
#undef  DO_GETXXKEY_R_KEYTYPE
#undef  DO_GETXXKEY_R_PATHNAME
#define GETXXKEY_R_FUNC			sh_getgrnam_r
#define GETXXKEY_R_PARSER   	__parsegrent
#define GETXXKEY_R_ENTTYPE		struct group
#define GETXXKEY_R_TEST(ENT)	(!strcmp((ENT)->gr_name, key))
#define DO_GETXXKEY_R_KEYTYPE	const char *__restrict
#define DO_GETXXKEY_R_PATHNAME  _PATH_GROUP

int GETXXKEY_R_FUNC(DO_GETXXKEY_R_KEYTYPE key,
		    GETXXKEY_R_ENTTYPE *__restrict resultbuf,
		    char *__restrict buffer, size_t buflen,
		    GETXXKEY_R_ENTTYPE **__restrict result)
{
  FILE *stream;
  int rv;
  
  *result = NULL;
  
  if (!(stream = fopen(DO_GETXXKEY_R_PATHNAME, "r"))) {
    rv = errno;
  } else {
    /* __STDIO_SET_USER_LOCKING(stream); */
    do {
      if (!(rv = __pgsreader(GETXXKEY_R_PARSER, resultbuf,
			     buffer, buflen, stream))
	  ) {
	if (GETXXKEY_R_TEST(resultbuf)) { /* Found key? */
	  *result = resultbuf;
	  break;
	}
      } else {
	if (rv == ENOENT) {	/* end-of-file encountered. */
	  rv = 0;
	}
	break;
      }
    } while (1);
    sl_fclose(FIL__, __LINE__, stream);
  }
  
  return rv;
}

#undef  GETXXKEY_R_FUNC	
#undef  GETXXKEY_R_PARSER
#undef  GETXXKEY_R_ENTTYPE
#undef  GETXXKEY_R_TEST
#undef  DO_GETXXKEY_R_KEYTYPE
#undef  DO_GETXXKEY_R_PATHNAME
#define GETXXKEY_R_FUNC			sh_getpwuid_r
#define GETXXKEY_R_PARSER   	__parsepwent
#define GETXXKEY_R_ENTTYPE		struct passwd
#define GETXXKEY_R_TEST(ENT)	((ENT)->pw_uid == key)
#define DO_GETXXKEY_R_KEYTYPE	uid_t
#define DO_GETXXKEY_R_PATHNAME  _PATH_PASSWD

int GETXXKEY_R_FUNC(DO_GETXXKEY_R_KEYTYPE key,
		    GETXXKEY_R_ENTTYPE *__restrict resultbuf,
		    char *__restrict buffer, size_t buflen,
		    GETXXKEY_R_ENTTYPE **__restrict result)
{
  FILE *stream;
  int rv;
  
  *result = NULL;
  
  if (!(stream = fopen(DO_GETXXKEY_R_PATHNAME, "r"))) {
    rv = errno;
  } else {
    /* __STDIO_SET_USER_LOCKING(stream); */
    do {
      if (!(rv = __pgsreader(GETXXKEY_R_PARSER, resultbuf,
			     buffer, buflen, stream))
	  ) {
	if (GETXXKEY_R_TEST(resultbuf)) { /* Found key? */
	  *result = resultbuf;
	  break;
	}
      } else {
	if (rv == ENOENT) {	/* end-of-file encountered. */
	  rv = 0;
	}
	break;
      }
    } while (1);
    sl_fclose(FIL__, __LINE__, stream);
  }
  
  return rv;
}

#undef  GETXXKEY_R_FUNC	
#undef  GETXXKEY_R_PARSER
#undef  GETXXKEY_R_ENTTYPE
#undef  GETXXKEY_R_TEST
#undef  DO_GETXXKEY_R_KEYTYPE
#undef  DO_GETXXKEY_R_PATHNAME
#define GETXXKEY_R_FUNC			sh_getgrgid_r
#define GETXXKEY_R_PARSER   	__parsegrent
#define GETXXKEY_R_ENTTYPE		struct group
#define GETXXKEY_R_TEST(ENT)	((ENT)->gr_gid == key)
#define DO_GETXXKEY_R_KEYTYPE	gid_t
#define DO_GETXXKEY_R_PATHNAME  _PATH_GROUP

int GETXXKEY_R_FUNC(DO_GETXXKEY_R_KEYTYPE key,
		    GETXXKEY_R_ENTTYPE *__restrict resultbuf,
		    char *__restrict buffer, size_t buflen,
		    GETXXKEY_R_ENTTYPE **__restrict result)
{
  FILE *stream;
  int rv;
  
  *result = NULL;
  
  if (!(stream = fopen(DO_GETXXKEY_R_PATHNAME, "r"))) {
    rv = errno;
  } else {
    /* __STDIO_SET_USER_LOCKING(stream); */
    do {
      if (!(rv = __pgsreader(GETXXKEY_R_PARSER, resultbuf,
			     buffer, buflen, stream))
	  ) {
	if (GETXXKEY_R_TEST(resultbuf)) { /* Found key? */
	  *result = resultbuf;
	  break;
	}
      } else {
	if (rv == ENOENT) {	/* end-of-file encountered. */
	  rv = 0;
	}
	break;
      }
    } while (1);
    sl_fclose(FIL__, __LINE__, stream);
  }
  
  return rv;
}

struct passwd * sh_getpwuid(uid_t uid)
{
	static char buffer[PWD_BUFFER_SIZE];
	static struct passwd resultbuf;
	struct passwd *result;

	sh_getpwuid_r(uid, &resultbuf, buffer, sizeof(buffer), &result);
	return result;
}

struct passwd * getpwuid(uid_t uid)
{
        return sh_getpwuid(uid);
}

struct group * sh_getgrgid(gid_t gid)
{
	static char buffer[GRP_BUFFER_SIZE];
	static struct group resultbuf;
	struct group *result;

	sh_getgrgid_r(gid, &resultbuf, buffer, sizeof(buffer), &result);
	return result;
}

struct group * getgrgid(gid_t gid)
{
        return sh_getgrgid(gid);
}

struct passwd * sh_getpwnam(const char *name)
{
	static char buffer[PWD_BUFFER_SIZE];
	static struct passwd resultbuf;
	struct passwd *result;

	sh_getpwnam_r(name, &resultbuf, buffer, sizeof(buffer), &result);
	return result;
}

struct group * sh_getgrnam(const char *name)
{
	static char buffer[GRP_BUFFER_SIZE];
	static struct group resultbuf;
	struct group *result;

	sh_getgrnam_r(name, &resultbuf, buffer, sizeof(buffer), &result);
	return result;
}

SH_MUTEX_STATIC(pwf_lock, PTHREAD_MUTEX_INITIALIZER);


static FILE *pwf = NULL;

void  sh_setpwent(void)
{
        SH_MUTEX_LOCK(pwf_lock);
	if (pwf) {
		rewind(pwf);
	}
	SH_MUTEX_UNLOCK(pwf_lock);
}

void  sh_endpwent(void)
{
        SH_MUTEX_LOCK(pwf_lock);
	if (pwf) {
		sl_fclose(FIL__, __LINE__, pwf);
		pwf = NULL;
	}
	SH_MUTEX_UNLOCK(pwf_lock);
}


static int  sh_getpwent_r(struct passwd *__restrict resultbuf, 
			  char *__restrict buffer, size_t buflen,
			  struct passwd **__restrict result)
{
	int rv;

        SH_MUTEX_LOCK(pwf_lock);

	*result = NULL;				/* In case of error... */

	if (!pwf) {
		if (!(pwf = fopen(_PATH_PASSWD, "r"))) {
			rv = errno;
			goto ERR;
		}
		/* __STDIO_SET_USER_LOCKING(pwf); */
	}

	if (!(rv = __pgsreader(__parsepwent, resultbuf,
						   buffer, buflen, pwf))) {
		*result = resultbuf;
	}

 ERR:
	; /* 'label at end of compound statement' */
	SH_MUTEX_UNLOCK(pwf_lock);

	return rv;
}

SH_MUTEX_STATIC(grf_lock, PTHREAD_MUTEX_INITIALIZER);

static FILE *grf = NULL;

void  sh_setgrent(void)
{
	SH_MUTEX_LOCK(grf_lock);
	if (grf) {
		rewind(grf);
	}
	SH_MUTEX_UNLOCK(grf_lock);
}

void  sh_endgrent(void)
{
	SH_MUTEX_LOCK(grf_lock);
	if (grf) {
		sl_fclose(FIL__, __LINE__, grf);
		grf = NULL;
	}
	SH_MUTEX_UNLOCK(grf_lock);
}

static int sh_getgrent_r(struct group *__restrict resultbuf,
			 char *__restrict buffer, size_t buflen,
			 struct group **__restrict result)
{
	int rv;

	SH_MUTEX_LOCK(grf_lock);

	*result = NULL;				/* In case of error... */

	if (!grf) {
		if (!(grf = fopen(_PATH_GROUP, "r"))) {
			rv = errno;
			goto ERR;
		}
		/* __STDIO_SET_USER_LOCKING(grf); */
	}

	if (!(rv = __pgsreader(__parsegrent, resultbuf,
						   buffer, buflen, grf))) {
		*result = resultbuf;
	}

 ERR:
	; /* 'label at end of compound statement' */
	SH_MUTEX_UNLOCK(grf_lock);

	return rv;
}


struct passwd * sh_getpwent(void)
{
	static char line_buff[PWD_BUFFER_SIZE];
	static struct passwd pwd;
	struct passwd *result;

	sh_getpwent_r(&pwd, line_buff, sizeof(line_buff), &result);
	return result;
}


struct group * sh_getgrent(void)
{
	static char line_buff[GRP_BUFFER_SIZE];
	static struct group gr;
	struct group *result;

	sh_getgrent_r(&gr, line_buff, sizeof(line_buff), &result);
	return result;
}

int  sh_initgroups(const char *user, gid_t gid)
{
	FILE *grf;
	gid_t *group_list;
	int num_groups, rv;
	char **m;
	struct group group;

	char * buff = calloc(1,GRP_BUFFER_SIZE_MALLOC);

	rv = -1;

	/* We alloc space for 8 gids at a time. */
	if (((group_list = calloc(8,sizeof(gid_t *))) != NULL)
		&& ((grf = fopen(_PATH_GROUP, "r")) != NULL)
		) {

	  /* __STDIO_SET_USER_LOCKING(grf); */

		*group_list = gid;
		num_groups = 1;

		while (!__pgsreader(__parsegrent, &group, buff, GRP_BUFFER_SIZE_MALLOC, grf)) {
			assert(group.gr_mem); /* Must have at least a NULL terminator. */
			if (group.gr_gid != gid) {
				for (m=group.gr_mem ; *m ; m++) {
					if (!strcmp(*m, user)) {
						if (!(num_groups & 7)) {
							gid_t *tmp = (gid_t *)
								realloc(group_list,
										(num_groups+8) * sizeof(gid_t *));
							if (!tmp) {
								rv = -1;
								goto DO_CLOSE;
							}
							group_list = tmp;
						}
						group_list[num_groups++] = group.gr_gid;
						break;
					}
				}
			}
		}

		rv = setgroups(num_groups, group_list);
	DO_CLOSE:
		sl_fclose(FIL__, __LINE__, grf);
	}

	/* group_list will be NULL if initial malloc failed, which may trigger
	 * warnings from various malloc debuggers. */
	free(group_list);
	free(buff);
	return rv;
}


/**********************************************************************/
/* Internal uClibc functions.                                         */
/**********************************************************************/

static const unsigned char pw_off[] = {
	offsetof(struct passwd, pw_name), 	/* 0 */
	offsetof(struct passwd, pw_passwd),	/* 1 */
	offsetof(struct passwd, pw_uid),	/* 2 - not a char ptr */
	offsetof(struct passwd, pw_gid), 	/* 3 - not a char ptr */
	offsetof(struct passwd, pw_gecos),	/* 4 */
	offsetof(struct passwd, pw_dir), 	/* 5 */
	offsetof(struct passwd, pw_shell) 	/* 6 */
};

static int __parsepwent(void *data, char *line)
{
	char *endptr;
	char *p;
	int i;

	i = 0;
	do {
		p = ((char *) ((struct passwd *) data)) + pw_off[i];

		if ((i & 6) ^ 2) { 	/* i!=2 and i!=3 */
			*((char **) p) = line;
			if (i==6) {
				return 0;
			}
			/* NOTE: glibc difference - glibc allows omission of
			 * ':' seperators after the gid field if all remaining
			 * entries are empty.  We require all separators. */
			if (!(line = strchr(line, ':'))) {
				break;
			}
		} else {
			unsigned long t = strtoul(line, &endptr, 10);
			/* Make sure we had at least one digit, and that the
			 * failing char is the next field seperator ':'.  See
			 * glibc difference note above. */
			/* TODO: Also check for leading whitespace? */
			if ((endptr == line) || (*endptr != ':')) {
				break;
			}
			line = endptr;
			if (i & 1) {		/* i == 3 -- gid */
				*((gid_t *) p) = t;
			} else {			/* i == 2 -- uid */
				*((uid_t *) p) = t;
			}
		}

		*line++ = 0;
		++i;
	} while (1);

	return -1;
}

static const unsigned char gr_off[] = {
	offsetof(struct group, gr_name), 	/* 0 */
	offsetof(struct group, gr_passwd),	/* 1 */
	offsetof(struct group, gr_gid)		/* 2 - not a char ptr */
};

static int __parsegrent(void *data, char *line)
{
	char *endptr;
	char *p;
	int i;
	char **members;
	char *end_of_buf;

	end_of_buf = ((struct group *) data)->gr_name; /* Evil hack! */
	i = 0;
	do {
		p = ((char *) ((struct group *) data)) + gr_off[i];

		if (i < 2) {
			*((char **) p) = line;
			if (!(line = strchr(line, ':'))) {
				break;
			}
			*line++ = 0;
			++i;
		} else {
			*((gid_t *) p) = strtoul(line, &endptr, 10);

			/* NOTE: glibc difference - glibc allows omission of the
			 * trailing colon when there is no member list.  We treat
			 * this as an error. */

			/* Make sure we had at least one digit, and that the
			 * failing char is the next field seperator ':'.  See
			 * glibc difference note above. */
			if ((endptr == line) || (*endptr != ':')) {
				break;
			}

			i = 1;				/* Count terminating NULL ptr. */
			p = endptr;

			if (p[1]) { /* We have a member list to process. */
				/* Overwrite the last ':' with a ',' before counting.
				 * This allows us to test for initial ',' and adds
				 * one ',' so that the ',' count equals the member
				 * count. */
				*p = ',';
				do {
					/* NOTE: glibc difference - glibc allows and trims leading
					 * (but not trailing) space.  We treat this as an error. */
					/* NOTE: glibc difference - glibc allows consecutive and
					 * trailing commas, and ignores "empty string" users.  We
					 * treat this as an error. */
					if (*p == ',') {
						++i;
						*p = 0;	/* nul-terminate each member string. */
						if (!*++p || (*p == ',') || isspace(*p)) {
							goto ERR;
						}
					}
				} while (*++p);
			}

			/* Now align (p+1), rounding up. */
			/* Assumes sizeof(char **) is a power of 2. */
			members = (char **)( (((intptr_t) p) + sizeof(char **))
								 & ~((intptr_t)(sizeof(char **) - 1)) );

			if (((char *)(members + i)) > end_of_buf) {	/* No space. */
				break;
			}

			((struct group *) data)->gr_mem = members;

			if (--i) {
				p = endptr;	/* Pointing to char prior to first member. */
				do {
					*members++ = ++p;
					if (!--i) break;
					while (*++p) {}
				} while (1);
			}				
			*members = NULL;

			return 0;
		}
	} while (1);

 ERR:
	return -1;
}

/* Reads until if EOF, or until if finds a line which fits in the buffer
 * and for which the parser function succeeds.
 *
 * Returns 0 on success and ENOENT for end-of-file (glibc concession).
 */

static int __pgsreader(int (*__parserfunc)(void *d, char *line), void *data,
		       char *__restrict line_buff, size_t buflen, FILE *f)
{
        size_t line_len; /* int -> size_t R.W. */
	int skip;
	int rv = ERANGE;

	if (buflen < PWD_BUFFER_SIZE) {
	        errno = rv;
	} else {
	  /* __STDIO_THREADLOCK(f); */

		skip = 0;
		do {
			if (!fgets(line_buff, buflen, f)) {
				if (feof(f)) {
					rv = ENOENT;
				}
				break;
			}

			line_len = strlen(line_buff) - 1; /* strlen() must be > 0. */
			if (line_buff[line_len] == '\n') {
				line_buff[line_len] = 0;
			} else if (line_len + 2 == buflen) { /* line too long */
			        rv = ERANGE;
				break;
				/*
				++skip;
				continue;
				*/
			}

			if (skip) {
				--skip;
				continue;
			}

			/* NOTE: glibc difference - glibc strips leading whitespace from
			 * records.  We do not allow leading whitespace. */

			/* Skip empty lines, comment lines, and lines with leading
			 * whitespace. */
			if (*line_buff && (*line_buff != '#') && !isspace(*line_buff)) {
				if (__parserfunc == __parsegrent) {	/* Do evil group hack. */
					/* The group entry parsing function needs to know where
					 * the end of the buffer is so that it can construct the
					 * group member ptr table. */
					((struct group *) data)->gr_name = line_buff + buflen;
				}

				if (!__parserfunc(data, line_buff)) {
					rv = 0;
					break;
				}
			}
		} while (1);

		/* __STDIO_THREADUNLOCK(f); */
	}

	return rv;
}

/* resolv.c: DNS Resolver
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *                     The Silver Hammer Group, Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
*/

/*
 * Portions Copyright (c) 1985, 1993
 *    The Regents of the University of California.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Portions Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 *
 *  5-Oct-2000 W. Greathouse  wgreathouse@smva.com
 *                              Fix memory leak and memory corruption.
 *                              -- Every name resolution resulted in
 *                                 a new parse of resolv.conf and new
 *                                 copy of nameservers allocated by
 *                                 strdup.
 *                              -- Every name resolution resulted in
 *                                 a new read of resolv.conf without
 *                                 resetting index from prior read...
 *                                 resulting in exceeding array bounds.
 *
 *                              Limit nameservers read from resolv.conf
 *
 *                              Add "search" domains from resolv.conf
 *
 *                              Some systems will return a security
 *                              signature along with query answer for
 *                              dynamic DNS entries.
 *                              -- skip/ignore this answer
 *
 *                              Include arpa/nameser.h for defines.
 *
 *                              General cleanup
 *
 * 20-Jun-2001 Michal Moskal <malekith@pld.org.pl>
 *   partial IPv6 support (i.e. gethostbyname2() and resolve_address2()
 *   functions added), IPv6 nameservers are also supported.
 *
 * 6-Oct-2001 Jari Korva <jari.korva@iki.fi>
 *   more IPv6 support (IPv6 support for gethostbyaddr();
 *   address family parameter and improved IPv6 support for get_hosts_byname
 *   and read_etc_hosts; getnameinfo() port from glibc; defined
 *   defined ip6addr_any and in6addr_loopback)
 *
 * 2-Feb-2002 Erik Andersen <andersee@debian.org>
 * Added gethostent(), sethostent(), and endhostent()
 *
 * 17-Aug-2002 Manuel Novoa III <mjn3@codepoet.org>
 *   Fixed __read_etc_hosts_r to return alias list, and modified buffer
 *   allocation accordingly.  See MAX_ALIASES and ALIAS_DIM below.
 *   This fixes the segfault in the Python 2.2.1 socket test.
 *
 * 04-Jan-2003 Jay Kulpinski <jskulpin@berkshire.rr.com>
 *   Fixed __decode_dotted to count the terminating null character
 *   in a host name.
 *
 * 02-Oct-2003 Tony J. White <tjw@tjw.org>
 *   Lifted dn_expand() and dependent ns_name_uncompress(), ns_name_unpack(),
 *   and ns_name_ntop() from glibc 2.3.2 for compatibility with ipsec-tools 
 *   and openldap.
 *
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* sl_close_fd(FIL__, __LINE__, )
 */
#include <unistd.h>

/* 'struct hostent'
 */
#include <netdb.h>

/* constanst like HFIXEDSZ
 */
#include <arpa/nameser.h>

SH_MUTEX_STATIC(resolv_lock, PTHREAD_MUTEX_INITIALIZER);

#define __UCLIBC_HAS_IPV6__
#define MAX_RECURSE 5
#define REPLY_TIMEOUT 10
#define MAX_RETRIES 3
#define MAX_SERVERS 3
#define MAX_SEARCH 4
#define MAX_ALIASES	5

/* 1:ip + 1:full + MAX_ALIASES:aliases + 1:NULL */
#define 	ALIAS_DIM		(2 + MAX_ALIASES + 1)

static int __nameservers;
static char * __nameserver[MAX_SERVERS];
static int __searchdomains;
static char * __searchdomain[MAX_SEARCH];

#undef DEBUG
/*#define DEBUG*/

#ifdef DEBUG
/* flawfinder: ignore *//* definition of debug macro */
#define DPRINTF(X,args...) fprintf(stderr, X, ##args)
#else
#define DPRINTF(X,args...)
#endif /* DEBUG */

struct resolv_header {
	int id;
	int qr,opcode,aa,tc,rd,ra,rcode;
	int qdcount;
	int ancount;
	int nscount;
	int arcount;
};

struct resolv_question {
	char * dotted;
	int qtype;
	int qclass;
};

struct resolv_answer {
	char * dotted;
	int atype;
	int aclass;
	int ttl;
	int rdlength;
	unsigned char * rdata;
	int rdoffset;
};

enum etc_hosts_action {
    GET_HOSTS_BYNAME = 0,
    GETHOSTENT,
    GET_HOSTS_BYADDR,
};

static int __encode_header(struct resolv_header *h, unsigned char *dest, int maxlen)
{
	if (maxlen < HFIXEDSZ)
		return -1;

	dest[0] = (h->id & 0xff00) >> 8;
	dest[1] = (h->id & 0x00ff) >> 0;
	dest[2] = (h->qr ? 0x80 : 0) |
		((h->opcode & 0x0f) << 3) |
		(h->aa ? 0x04 : 0) | 
		(h->tc ? 0x02 : 0) | 
		(h->rd ? 0x01 : 0);
	dest[3] = (h->ra ? 0x80 : 0) | (h->rcode & 0x0f);
	dest[4] = (h->qdcount & 0xff00) >> 8;
	dest[5] = (h->qdcount & 0x00ff) >> 0;
	dest[6] = (h->ancount & 0xff00) >> 8;
	dest[7] = (h->ancount & 0x00ff) >> 0;
	dest[8] = (h->nscount & 0xff00) >> 8;
	dest[9] = (h->nscount & 0x00ff) >> 0;
	dest[10] = (h->arcount & 0xff00) >> 8;
	dest[11] = (h->arcount & 0x00ff) >> 0;

	return HFIXEDSZ;
}

static int __decode_header(unsigned char *data, struct resolv_header *h)
{
	h->id = (data[0] << 8) | data[1];
	h->qr = (data[2] & 0x80) ? 1 : 0;
	h->opcode = (data[2] >> 3) & 0x0f;
	h->aa = (data[2] & 0x04) ? 1 : 0;
	h->tc = (data[2] & 0x02) ? 1 : 0;
	h->rd = (data[2] & 0x01) ? 1 : 0;
	h->ra = (data[3] & 0x80) ? 1 : 0;
	h->rcode = data[3] & 0x0f;
	h->qdcount = (data[4] << 8) | data[5];
	h->ancount = (data[6] << 8) | data[7];
	h->nscount = (data[8] << 8) | data[9];
	h->arcount = (data[10] << 8) | data[11];

	return HFIXEDSZ;
}

static int __length_dotted(const unsigned char *data, int offset)
{
	int orig_offset = offset;
	int l;

	if (!data)
		return -1;

	do {

	        if (offset < INT_MAX)
	                offset++;
		else
		        return -1;

		l = data[offset];

		if ((l & 0xc0) == (0xc0)) {
		        if (offset < INT_MAX)
			  offset++;
			else
			  return -1;
			break;
		}

		if (offset <= (INT_MAX - l))
		  offset += l;
		else
		  return -1;

	} while (l);

	return offset - orig_offset;
}

static int __length_question(unsigned char *message, int offset)
{
	int i;

	i = __length_dotted(message, offset);
	if (i < 0)
		return i;
	if (i < (INT_MAX - 4))
	  return i + 4;
	else
	  return -1;
}

/* Decode a dotted string from nameserver transport-level encoding.
   This routine understands compressed data. */

static int __decode_dotted(const unsigned char *data, int offset,
				  char *dest, int maxlen)
{
	int l;
	int measure = 1;
	int total = 0;
	int used = 0;

	if (!data)
		return -1;
	if ((offset < 0) || (offset > (PACKETSZ-1)))
	        return -1;
	while ((l=data[offset])) {
	        if (offset < (PACKETSZ-1)) offset++;
		else return -1;
		if (measure)
		    { if (total < INT_MAX) total++; else return -1; }
		if ((l & 0xc0) == (0xc0)) {
		        if (measure)
			  { if (total < INT_MAX) total++; else return -1; }
		        /* compressed item, redirect */ 
			offset = ((l & 0x3f) << 8) | data[offset];
			if ((offset < 0) || (offset > (PACKETSZ-1)))
			  return -1; 
			measure = 0;
			continue;
		}
	        
		if (used >= (INT_MAX - l))
		  return -1;

		if ((used + l + 1) >= maxlen)
		  return -1; 

		memcpy(dest + used, data + offset, l);
		
		if (offset <= ((PACKETSZ-1) - l))
		  offset += l;
		else
		  return -1;

		if (used <= (INT_MAX - l))
		  used += l;
		else
		  return -1;
		if (measure)
		  { if (total <= (INT_MAX -l)) total += l; else return -1; }

		if (used >= maxlen)
		  return -1;
		if (data[offset] != 0)
			dest[used++] = '.';
		else
			dest[used++] = '\0';
	}

	/* The null byte must be counted too */
	if (measure) {
	    if (total < INT_MAX) total++; else return -1; 
	}

	DPRINTF("Total decode len = %d\n", total);

	return total;
}

static int __decode_answer(unsigned char *message, int offset,
				  struct resolv_answer *a)
{
	char temp[256];
	int i = 0;

	i = __decode_dotted(message, offset, temp, sizeof(temp));
	if (i < 0 || i > PACKETSZ)
		return -1;

	if (offset <= ((PACKETSZ - 10) - i))
	  message += offset + i;
	else
	  return -1;

	a->dotted = strdup(temp);
	a->atype = (message[0] << 8) | message[1];
	message += 2;
	a->aclass = (message[0] << 8) | message[1];
	message += 2;
	a->ttl = (message[0] << 24) |
		(message[1] << 16) | (message[2] << 8) | (message[3] << 0);
	message += 4;
	a->rdlength = (message[0] << 8) | message[1];
	message += 2;
	a->rdata = message;
	a->rdoffset = offset + i + RRFIXEDSZ;

	DPRINTF("i=%d,rdlength=%d\n", i, a->rdlength);

	if (RRFIXEDSZ <= (INT_MAX - i))
	  i += RRFIXEDSZ;
	else
	  return -1;
	if (a->rdlength <= (INT_MAX - i))
	  return i + a->rdlength;
	else
	  return -1;
}


/* Encode a dotted string into nameserver transport-level encoding.
   This routine is fairly dumb, and doesn't attempt to compress
   the data */

static int __encode_dotted(const char *dotted, unsigned char *dest, int maxlen)
{
	unsigned int used = 0;

	while (dotted && *dotted) {
		char *c = strchr(dotted, '.');
		unsigned int l = c ? (unsigned int)(c - dotted) : strlen(dotted);

		if (l >= ((unsigned int)maxlen - used - 1))
			return -1;

		dest[used++] = l;
		memcpy(dest + used, dotted, l);
		used += l;

		if (c)
			dotted = c + 1;
		else
			break;
	}

	if (maxlen < 1)
		return -1;

	dest[used++] = 0;

	return used;
}

static int __encode_question(struct resolv_question *q,
					unsigned char *dest, int maxlen)
{
	int i;

	i = __encode_dotted(q->dotted, dest, maxlen);
	if (i < 0)
		return i;

	dest += i;
	if (maxlen < i)
	  return -1;
	maxlen -= i;

	if (maxlen < 4)
		return -1;

	dest[0] = (q->qtype & 0xff00) >> 8;
	dest[1] = (q->qtype & 0x00ff) >> 0;
	dest[2] = (q->qclass & 0xff00) >> 8;
	dest[3] = (q->qclass & 0x00ff) >> 0;

	if (i <= (INT_MAX - 4))
	  return i + 4;
	else
	  return -1;
}


/* Just for the record, having to lock __dns_lookup() just for these two globals
 * is pretty lame.  I think these two variables can probably be de-global-ized, 
 * which should eliminate the need for doing locking here...  Needs a closer 
 * look anyways. */
static int ns=0, id=1;

static int __dns_lookup(const char *name, int type, int nscount, char **nsip,
			   unsigned char **outpacket, struct resolv_answer *a)
{
	int i, j, len, fd, pos, rc;
	struct timeval tv;
	fd_set fds;
	struct resolv_header h;
	struct resolv_question q;
	int retries = 0;
	unsigned char * packet = calloc(1,PACKETSZ);
	char *dns, *lookup = calloc(1,MAXDNAME);
	int variant = 0;
	struct sockaddr_in sa;
#ifdef __UCLIBC_HAS_IPV6__
	int v6;
	struct sockaddr_in6 sa6;
#endif

	fd = -1;

	if (!packet || !lookup || !nscount)
	    goto fail;

	DPRINTF("Looking up type %d answer for '%s'\n", type, name);

	SH_MUTEX_LOCK_UNSAFE(resolv_lock);
	ns %= nscount;
	SH_MUTEX_UNLOCK_UNSAFE(resolv_lock);

	while (retries++ < MAX_RETRIES) {
		if (fd != -1)
			sl_close_fd(FIL__, __LINE__, fd);

		memset(packet, 0, PACKETSZ);

		memset(&h, 0, sizeof(h));

		/* Mess with globals while under lock */
		SH_MUTEX_LOCK_UNSAFE(resolv_lock);
		++id;
		id &= 0xffff;
		h.id = id;
		dns = nsip[ns];
		SH_MUTEX_UNLOCK_UNSAFE(resolv_lock);

		h.qdcount = 1;
		h.rd = 1;

		DPRINTF("encoding header\n", h.rd);

		i = __encode_header(&h, packet, PACKETSZ);
		if (i < 0)
			goto fail;

		sl_strlcpy(lookup,name,MAXDNAME);
		SH_MUTEX_LOCK_UNSAFE(resolv_lock);
		if (variant < __searchdomains && strchr(lookup, '.') == NULL)
		{
		    sl_strlcat(lookup,".", MAXDNAME);
		    sl_strlcat(lookup,__searchdomain[variant], MAXDNAME);
		}
		SH_MUTEX_UNLOCK_UNSAFE(resolv_lock);
		DPRINTF("lookup name: %s\n", lookup);
		q.dotted = (char *)lookup;
		q.qtype = type;
		q.qclass = C_IN; /* CLASS_IN */

		j = __encode_question(&q, packet+i, PACKETSZ-i);
		if (j < 0)
			goto fail;

		len = i + j;

		DPRINTF("On try %d, sending query to port %d of machine %s\n",
				retries, NAMESERVER_PORT, dns);

#ifdef __UCLIBC_HAS_IPV6__
		v6 = inet_pton(AF_INET6, dns, &sa6.sin6_addr) > 0;
		fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#else
		fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#endif
		if (fd < 0) {
		    continue;
		}

		/* Connect to the UDP socket so that asyncronous errors are returned */		 
#ifdef __UCLIBC_HAS_IPV6__
		if (v6) {
		    sa6.sin6_family = AF_INET6;
		    sa6.sin6_port = htons(NAMESERVER_PORT);
		    /* sa6.sin6_addr is already here */
		    rc = connect(fd, (struct sockaddr *) &sa6, sizeof(sa6));
		} else {
#endif
		    sa.sin_family = AF_INET;
		    sa.sin_port = htons(NAMESERVER_PORT);
		    sa.sin_addr.s_addr = inet_addr(dns);
		    rc = connect(fd, (struct sockaddr *) &sa, sizeof(sa));
#ifdef __UCLIBC_HAS_IPV6__
		}
#endif
		if (rc < 0) {
		    if (errno == ENETUNREACH) {
			/* routing error, presume not transient */
			goto tryall;
		    } else
			/* retry */
			continue;
		}

		DPRINTF("Transmitting packet of length %d, id=%d, qr=%d\n",
				len, h.id, h.qr);

		send(fd, packet, len, 0);

		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		tv.tv_sec = REPLY_TIMEOUT;
		tv.tv_usec = 0;
		if (select(fd + 1, &fds, NULL, NULL, &tv) <= 0) {
		    DPRINTF("Timeout\n");

			/* timed out, so retry send and receive, 
			 * to next nameserver on queue */
			goto again;
		}

		i = recv(fd, packet, 512, 0);
		if (i < HFIXEDSZ) {
			/* too short ! */
			goto again;
		}

		/* ok because we have checked that recv at least HFIXEDSZ */
		__decode_header(packet, &h);

		DPRINTF("id = %d, qr = %d\n", h.id, h.qr);

		SH_MUTEX_LOCK_UNSAFE(resolv_lock);
		if ((h.id != id) || (!h.qr)) {
			SH_MUTEX_UNLOCK_UNSAFE(resolv_lock);
			/* unsolicited */
			goto again;
		}
		SH_MUTEX_UNLOCK_UNSAFE(resolv_lock);


		DPRINTF("Got response %s\n", "(i think)!");
		DPRINTF("qrcount=%d,ancount=%d,nscount=%d,arcount=%d\n",
				h.qdcount, h.ancount, h.nscount, h.arcount);
		DPRINTF("opcode=%d,aa=%d,tc=%d,rd=%d,ra=%d,rcode=%d\n",
				h.opcode, h.aa, h.tc, h.rd, h.ra, h.rcode);

		if ((h.rcode) || (h.ancount < 1)) {
			/* negative result, not present */
			goto again;
		}

		pos = HFIXEDSZ;

		for (j = 0; j < h.qdcount; j++) {
			DPRINTF("Skipping question %d at %d\n", j, pos);
			i = __length_question(packet, pos);
			DPRINTF("Length of question %d is %d\n", j, i);
			if (i < 0)
				goto again;
			pos += i;
			if (pos >= PACKETSZ)
			        goto again;
		}
		DPRINTF("Decoding answer at pos %d\n", pos);

		for (j=0;j<h.ancount;j++)
		{
		    i = __decode_answer(packet, pos, a);

		    if (i<0) {
			DPRINTF("failed decode %d\n", i);
			goto again;
		    }
		    /* For all but T_SIG, accept first answer */
		    if (a->atype != T_SIG)
			break;

		    DPRINTF("skipping T_SIG %d\n", i);
		    free(a->dotted);
		    pos += i;
		    if (pos >= PACKETSZ)
		            goto again;
		}

		DPRINTF("Answer name = |%s|\n", a->dotted);
		DPRINTF("Answer type = |%d|\n", a->atype);

		sl_close_fd(FIL__, __LINE__, fd);

		if (outpacket)
			*outpacket = packet;
		else
			free(packet);
		free(lookup);
		return (0);				/* success! */

	  tryall:
		/* if there are other nameservers, give them a go,
		   otherwise return with error */
		{
		    int sdomains;

		    SH_MUTEX_LOCK_UNSAFE(resolv_lock);
		    sdomains=__searchdomains;
		    SH_MUTEX_UNLOCK_UNSAFE(resolv_lock);
		    variant = 0;
		    if (retries >= nscount*(sdomains+1))
			goto fail;
		}

	  again:
		/* if there are searchdomains, try them or fallback as passed */
		{
		    int sdomains;
		    SH_MUTEX_LOCK_UNSAFE(resolv_lock);
		    sdomains=__searchdomains;
		    SH_MUTEX_UNLOCK_UNSAFE(resolv_lock);

		    if (variant < sdomains) {
			/* next search */
			variant++;
		    } else {
			/* next server, first search */
			SH_MUTEX_LOCK_UNSAFE(resolv_lock);
			ns = (ns + 1) % nscount;
			SH_MUTEX_UNLOCK_UNSAFE(resolv_lock);
			variant = 0;
		    }
		}
	}

fail:
	if (fd != -1)
	    sl_close_fd(FIL__, __LINE__, fd);
	if (lookup)
	    free(lookup);
	if (packet)
	    free(packet);
	return -1;
}

static void __open_etc_hosts(FILE **fp)
{
	if ((*fp = fopen("/etc/hosts", "r")) == NULL) {
		*fp = fopen("/etc/config/hosts", "r");
	}
	return;
}

static int __read_etc_hosts_r(FILE * fp, const char * name, int type,
		     enum etc_hosts_action action,
		     struct hostent * result_buf,
		     char * buf, size_t buflen,
		     struct hostent ** result,
		     int * h_errnop)
{
	struct in_addr	*in=NULL;
	struct in_addr	**addr_list=NULL;
#ifdef __UCLIBC_HAS_IPV6__
	struct in6_addr	*in6=NULL;
	struct in6_addr	**addr_list6=NULL;
#endif /* __UCLIBC_HAS_IPV6__ */
	char					*cp;
	char					**alias;
	int						aliases, i;
	int		ret=HOST_NOT_FOUND;

	if (buflen < sizeof(char *)*(ALIAS_DIM))
		return ERANGE;
	alias=(char **)buf;
	buf+=sizeof(char **)*(ALIAS_DIM);
	buflen-=sizeof(char **)*(ALIAS_DIM);

	if (action!=GETHOSTENT) {
#ifdef __UCLIBC_HAS_IPV6__
		char *p=buf;
		size_t len=buflen;
#endif /* __UCLIBC_HAS_IPV6__ */
		*h_errnop=NETDB_INTERNAL;
		if (buflen < sizeof(*in))
			return ERANGE;
		in=(struct in_addr*)buf;
		buf+=sizeof(*in);
		buflen-=sizeof(*in);

		if (buflen < sizeof(*addr_list)*2)
			return ERANGE;
		addr_list=(struct in_addr **)buf;
		buf+=sizeof(*addr_list)*2;
		buflen-=sizeof(*addr_list)*2;

#ifdef __UCLIBC_HAS_IPV6__
		if (len < sizeof(*in6))
			return ERANGE;
		in6=(struct in6_addr*)p;
		p+=sizeof(*in6);
		len-=sizeof(*in6);

		if (len < sizeof(*addr_list6)*2)
			return ERANGE;
		addr_list6=(struct in6_addr**)p;
		p+=sizeof(*addr_list6)*2;
		len-=sizeof(*addr_list6)*2;

		if (len < buflen) {
			buflen=len;
			buf=p;
		}
#endif /* __UCLIBC_HAS_IPV6__ */

		if (buflen < 80)
			return ERANGE;

		__open_etc_hosts(&fp);
		if (fp == NULL) {
			result=NULL;
			return errno;
		}
	}

	*h_errnop=HOST_NOT_FOUND;
	while (fgets(buf, buflen, fp)) {
		if ((cp = strchr(buf, '#')))
			*cp = '\0';
		DPRINTF("Looking at: %s\n", buf);
		aliases = 0;

		cp = buf;
		while (*cp) {
			while (*cp && isspace(*cp))
				*cp++ = '\0';
			if (!*cp)
				continue;
			if (aliases < (2+MAX_ALIASES))
				alias[aliases++] = cp;
			while (*cp && !isspace(*cp))
				cp++;
		}
		alias[aliases] = 0;

		if (aliases < 2)
			continue; /* syntax error really */
		
		if (action==GETHOSTENT) {
			/* Return whatever the next entry happens to be. */
			break;
		} else if (action==GET_HOSTS_BYADDR) {
			if (strcmp(name, alias[0]) != 0)
				continue;
		} else {
			/* GET_HOSTS_BYNAME */
			for (i = 1; i < aliases; i++)
				if (strcasecmp(name, alias[i]) == 0)
					break;
			if (i >= aliases)
				continue;
		}

		if (type == AF_INET && inet_pton(AF_INET, alias[0], in) > 0) {
			DPRINTF("Found INET\n");
			addr_list[0] = in;
			addr_list[1] = 0;
			result_buf->h_name = alias[1];
			result_buf->h_addrtype = AF_INET;
			result_buf->h_length = sizeof(*in);
			result_buf->h_addr_list = (char**) addr_list;
			result_buf->h_aliases = alias + 2;
			*result=result_buf;
			ret=NETDB_SUCCESS;
#ifdef __UCLIBC_HAS_IPV6__
        } else if (type == AF_INET6 && inet_pton(AF_INET6, alias[0], in6) > 0) {
			DPRINTF("Found INET6\n");
			addr_list6[0] = in6;
			addr_list6[1] = 0;
			result_buf->h_name = alias[1];
			result_buf->h_addrtype = AF_INET6;
			result_buf->h_length = sizeof(*in6);
			result_buf->h_addr_list = (char**) addr_list6;
			result_buf->h_aliases = alias + 2;
			*result=result_buf;
			ret=NETDB_SUCCESS;
#endif /* __UCLIBC_HAS_IPV6__ */
		} else {
			DPRINTF("Error\n");
			ret=TRY_AGAIN;
			break; /* bad ip address */
        }
        
		if (action!=GETHOSTENT) {
			sl_fclose(FIL__, __LINE__, fp);
		}
		return ret;
	}
	if (action!=GETHOSTENT) {
		sl_fclose(FIL__, __LINE__, fp);
	}
	return ret;
}

/*
 *	we currently read formats not quite the same as that on normal
 *	unix systems, we can have a list of nameservers after the keyword.
 */
int __get_hosts_byname_r(const char * name, int type,
			    struct hostent * result_buf,
			    char * buf, size_t buflen,
			    struct hostent ** result,
			    int * h_errnop)
{
	return(__read_etc_hosts_r(NULL, name, type, GET_HOSTS_BYNAME, result_buf, buf, buflen, result, h_errnop));
}

static int __open_nameservers(void)
{
	FILE *fp;
	int i;
#define RESOLV_ARGS 5
	char szBuffer[128], *p, *argv[RESOLV_ARGS];
	int argc;

	SH_MUTEX_LOCK(resolv_lock);
	if (__nameservers > 0) {
	  goto the_end;
	}

	if ((fp = fopen("/etc/resolv.conf", "r")) ||
			(fp = fopen("/etc/config/resolv.conf", "r"))) {

		while (fgets(szBuffer, sizeof(szBuffer), fp) != NULL) {

			for (p = szBuffer; *p && isspace(*p); p++)
				/* skip white space */;
			if (*p == '\0' || *p == '\n' || *p == '#') /* skip comments etc */
				continue;
			argc = 0;
			while (*p && argc < RESOLV_ARGS) {
				argv[argc++] = p;
				while (*p && !isspace(*p) && *p != '\n')
					p++;
				while (*p && (isspace(*p) || *p == '\n')) /* remove spaces */
					*p++ = '\0';
			}

			if (strcmp(argv[0], "nameserver") == 0) {
				for (i = 1; i < argc && __nameservers < MAX_SERVERS; i++) {
					__nameserver[__nameservers++] = strdup(argv[i]);
					DPRINTF("adding nameserver %s\n", argv[i]);
				}
			}

			/* domain and search are mutually exclusive, the last one wins */
			if (strcmp(argv[0],"domain")==0 || strcmp(argv[0],"search")==0) {
				while (__searchdomains > 0) {
					free(__searchdomain[--__searchdomains]);
					__searchdomain[__searchdomains] = NULL;
				}
				for (i=1; i < argc && __searchdomains < MAX_SEARCH; i++) {
					__searchdomain[__searchdomains++] = strdup(argv[i]);
					DPRINTF("adding search %s\n", argv[i]);
				}
			}
		}
		sl_fclose(FIL__, __LINE__, fp);
	} else {
	    DPRINTF("failed to open %s\n", "resolv.conf");
	}
	DPRINTF("nameservers = %d\n", __nameservers);
 the_end:
	; /* 'label at end of compound statement' */
	SH_MUTEX_UNLOCK(resolv_lock);
	/* cppcheck-suppress resourceLeak */
	return 0;
}

static int sh_gethostbyname_r(const char * name,
			    struct hostent * result_buf,
			    char * buf, size_t buflen,
			    struct hostent ** result,
			    int * h_errnop)
{
	struct in_addr *in;
	struct in_addr **addr_list;
	unsigned char *packet;
	struct resolv_answer a;
	int i;
	int nest = 0;
	int __nameserversXX;
	char ** __nameserverXX;

	__open_nameservers();

	*result=NULL;
	if (!name)
		return EINVAL;

	/* do /etc/hosts first */
	if ((i=__get_hosts_byname_r(name, AF_INET, result_buf,
				  buf, buflen, result, h_errnop))==0)
		return i;
	switch (*h_errnop) {
		case HOST_NOT_FOUND:
		case NO_ADDRESS:
			break;
		case NETDB_INTERNAL:
			if (errno == ENOENT) {
			    break;
			}
			/* else fall through */
		default:
			return i;
	}

	DPRINTF("Nothing found in /etc/hosts\n");

	*h_errnop = NETDB_INTERNAL;
	if (buflen < sizeof(*in))
		return ERANGE;
	in=(struct in_addr*)buf;
	buf+=sizeof(*in);
	buflen-=sizeof(*in);

	if (buflen < sizeof(*addr_list)*2)
		return ERANGE;
	addr_list=(struct in_addr**)buf;
	buf+=sizeof(*addr_list)*2;
	buflen-=sizeof(*addr_list)*2;

	addr_list[0] = in;
	addr_list[1] = 0;
	
	if (buflen<256)
		return ERANGE;
	strncpy(buf, name, buflen);

	/* First check if this is already an address */
	if (inet_aton(name, in)) {
	    result_buf->h_name = buf;
	    result_buf->h_addrtype = AF_INET;
	    result_buf->h_length = sizeof(*in);
	    result_buf->h_addr_list = (char **) addr_list;
	    *result=result_buf;
	    *h_errnop = NETDB_SUCCESS;
	    return NETDB_SUCCESS;
	}

	for (;;) {

	SH_MUTEX_LOCK_UNSAFE(resolv_lock);
	__nameserversXX=__nameservers;
	__nameserverXX=__nameserver;
	SH_MUTEX_UNLOCK_UNSAFE(resolv_lock);
		i = __dns_lookup(buf, T_A, __nameserversXX, __nameserverXX, &packet, &a);

		if (i < 0) {
			*h_errnop = HOST_NOT_FOUND;
			DPRINTF("__dns_lookup\n");
			return TRY_AGAIN;
		}

		strncpy(buf, a.dotted, buflen);
		free(a.dotted);

		if (a.atype == T_CNAME) {		/* CNAME */
			DPRINTF("Got a CNAME in gethostbyname()\n");
			i = __decode_dotted(packet, a.rdoffset, buf, buflen);
			free(packet);

			if (i < 0) {
				*h_errnop = NO_RECOVERY;
				DPRINTF("__decode_dotted\n");
				return -1;
			}
			if (++nest > MAX_RECURSE) {
				*h_errnop = NO_RECOVERY;
				DPRINTF("recursion\n");
				return -1;
			}
			continue;
		} else if (a.atype == T_A) {	/* ADDRESS */
			memcpy(in, a.rdata, sizeof(*in));
			result_buf->h_name = buf;
			result_buf->h_addrtype = AF_INET;
			result_buf->h_length = sizeof(*in);
			result_buf->h_addr_list = (char **) addr_list;
			free(packet);
			break;
		} else {
			free(packet);
			*h_errnop=HOST_NOT_FOUND;
			return TRY_AGAIN;
		}
	}

	*result=result_buf;
	*h_errnop = NETDB_SUCCESS;
	return NETDB_SUCCESS;
}

struct hostent * sh_gethostbyname(const char *name)
{
	static struct hostent h;
	static char buf[sizeof(struct in_addr) +
			sizeof(struct in_addr *)*2 +
			sizeof(char *)*(ALIAS_DIM) + 256/*namebuffer*/ + 32/* margin */];
	struct hostent *hp;

	sh_gethostbyname_r(name, &h, buf, sizeof(buf), &hp, &h_errno);

	return hp;
}

static int __get_hosts_byaddr_r(const char * addr, int len, int type,
			    struct hostent * result_buf,
			    char * buf, size_t buflen,
			    struct hostent ** result,
			    int * h_errnop)
{
#ifndef __UCLIBC_HAS_IPV6__
	char	ipaddr[INET_ADDRSTRLEN];
#else
	char	ipaddr[INET6_ADDRSTRLEN];
#endif /* __UCLIBC_HAS_IPV6__ */

    switch (type) {
	case AF_INET:
		if (len != sizeof(struct in_addr))
			return 0;
		break;
#ifdef __UCLIBC_HAS_IPV6__
	case AF_INET6:
		if (len != sizeof(struct in6_addr))
			return 0;
		break;
#endif /* __UCLIBC_HAS_IPV6__ */
	default:
		return 0;
	}

	inet_ntop(type, addr, ipaddr, sizeof(ipaddr));

	return(__read_etc_hosts_r(NULL, ipaddr, type, GET_HOSTS_BYADDR, 
		    result_buf, buf, buflen, result, h_errnop));
}

static int sh_gethostbyaddr_r (const void *addr, socklen_t len, int type,
			    struct hostent * result_buf,
			    char * buf, size_t buflen,
			    struct hostent ** result,
			    int * h_errnop)

{
	struct in_addr *in;
	struct in_addr **addr_list;
#ifdef __UCLIBC_HAS_IPV6__
	char *qp;
	size_t plen;
	struct in6_addr	*in6;
	struct in6_addr	**addr_list6;
#endif /* __UCLIBC_HAS_IPV6__ */
	unsigned char *packet;
	struct resolv_answer a;
	int i;
	int nest = 0;
	int __nameserversXX;
	char ** __nameserverXX;

	*result=NULL;
	if (!addr)
		return EINVAL;
        
	switch (type) {
		case AF_INET:
			if (len != sizeof(struct in_addr))
				return EINVAL;
			break;
#ifdef __UCLIBC_HAS_IPV6__
		case AF_INET6:
			if (len != sizeof(struct in6_addr))
				return EINVAL;
			break;
#endif /* __UCLIBC_HAS_IPV6__ */
		default:
			return EINVAL;
	}

	/* do /etc/hosts first */
	if ((i=__get_hosts_byaddr_r(addr, len, type, result_buf,
				  buf, buflen, result, h_errnop))==0)
		return i;
	switch (*h_errnop) {
		case HOST_NOT_FOUND:
		case NO_ADDRESS:
			break;
		default:
			return i;
	}

	__open_nameservers();

#ifdef __UCLIBC_HAS_IPV6__
	qp=buf;
	plen=buflen;
#endif /* __UCLIBC_HAS_IPV6__ */

	*h_errnop = NETDB_INTERNAL;
	if (buflen < sizeof(*in))
		return ERANGE;
	in=(struct in_addr*)buf;
	buf+=sizeof(*in);
	buflen-=sizeof(*in);

	if (buflen < sizeof(*addr_list)*2)
		return ERANGE;
	addr_list=(struct in_addr**)buf;
	buf+=sizeof(*addr_list)*2;
	buflen-=sizeof(*addr_list)*2;

#ifdef __UCLIBC_HAS_IPV6__
	if (plen < sizeof(*in6))
		return ERANGE;
	in6=(struct in6_addr*)qp;
	qp+=sizeof(*in6);
	plen-=sizeof(*in6);

	if (plen < sizeof(*addr_list6)*2)
		return ERANGE;
	addr_list6=(struct in6_addr**)qp;
	qp+=sizeof(*addr_list6)*2;
	plen-=sizeof(*addr_list6)*2;

	if (plen < buflen) {
		buflen=plen;
		buf=qp;
	}
#endif /* __UCLIBC_HAS_IPV6__ */

	if (buflen<256)
		return ERANGE;

	if(type == AF_INET) {
		const unsigned char *tmp_addr = (const unsigned char *)addr;

		memcpy(&in->s_addr, addr, len);

		addr_list[0] = in;

		sprintf(buf, "%u.%u.%u.%u.in-addr.arpa",
			tmp_addr[3], tmp_addr[2], tmp_addr[1], tmp_addr[0]);
#ifdef __UCLIBC_HAS_IPV6__
	} else {
		memcpy(in6->s6_addr, addr, len);

		addr_list6[0] = in6;
		qp = buf;

		for (i = len - 1; i >= 0; i--) {
			qp += sprintf(qp, "%x.%x.", in6->s6_addr[i] & 0xf,
				(in6->s6_addr[i] >> 4) & 0xf);
    	}
    	strcpy(qp, "ip6.int");
#endif /* __UCLIBC_HAS_IPV6__ */
	}

	addr_list[1] = 0;

	for (;;) {

	SH_MUTEX_LOCK_UNSAFE(resolv_lock);
	__nameserversXX=__nameservers;
	__nameserverXX=__nameserver;
	SH_MUTEX_UNLOCK_UNSAFE(resolv_lock);
		i = __dns_lookup(buf, T_PTR, __nameserversXX, __nameserverXX, &packet, &a);

		if (i < 0) {
			*h_errnop = HOST_NOT_FOUND;
			return TRY_AGAIN;
		}

		strncpy(buf, a.dotted, buflen);
		free(a.dotted);

		if (a.atype == T_CNAME) {		/* CNAME */
			DPRINTF("Got a CNAME in gethostbyaddr()\n");
			i = __decode_dotted(packet, a.rdoffset, buf, buflen);
			free(packet);

			if (i < 0) {
				*h_errnop = NO_RECOVERY;
				return -1;
			}
			if (++nest > MAX_RECURSE) {
				*h_errnop = NO_RECOVERY;
				return -1;
			}
			continue;
		} else if (a.atype == T_PTR) {	/* ADDRESS */
			i = __decode_dotted(packet, a.rdoffset, buf, buflen);
			free(packet);

			result_buf->h_name = buf;
			result_buf->h_addrtype = type;

			if(type == AF_INET) {
				result_buf->h_length = sizeof(*in);
#ifdef __UCLIBC_HAS_IPV6__
			} else {
				result_buf->h_length = sizeof(*in6);
#endif /* __UCLIBC_HAS_IPV6__ */
    		}

			result_buf->h_addr_list = (char **) addr_list;
			break;
		} else {
			free(packet);
			*h_errnop = NO_ADDRESS;
			return TRY_AGAIN;
		}
	}

	*result=result_buf;
	*h_errnop = NETDB_SUCCESS;
	return NETDB_SUCCESS;
}

struct hostent * sh_gethostbyaddr (const void *addr, socklen_t len, int type)
{
	static struct hostent h;
	static char buf[
#ifndef __UCLIBC_HAS_IPV6__
		sizeof(struct in_addr) + sizeof(struct in_addr *)*2 +
#else
		sizeof(struct in6_addr) + sizeof(struct in6_addr *)*2 +
#endif /* __UCLIBC_HAS_IPV6__ */
		sizeof(char *)*(ALIAS_DIM) + 256/*namebuffer*/ + 32/* margin */];
	struct hostent *hp;

	sh_gethostbyaddr_r(addr, len, type, &h, buf, sizeof(buf), &hp, &h_errno);
        
	return hp;
}

/* NEED_STATIC_LIBS */
#else

/* include something to avoid empty compilation unit */
#include <stdio.h>

#endif

