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


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

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


#include "samhain.h"
#include "sh_error.h"
#include "sh_utils.h"
#include "sh_unix.h"
#include "sh_tiger.h"
#include "sh_entropy.h"
#include "sh_pthread.h"

#undef  FIL__
#define FIL__  _("sh_utils.c")

UINT32 ErrFlag[2];

int sh_util_flagval(const char * c, int * fval)
{
  SL_ENTER(_("sh_util_flagval"));
  if (c == NULL)
    SL_RETURN( (-1), _("sh_util_flagval"));
  if ( c[0] == '1'  || c[0] == 'y'  || c[0] == 'Y' ||
       c[0] == 't'  || c[0] == 'T')
    {
      *fval = S_TRUE;
      SL_RETURN( (0), _("sh_util_flagval"));
    }
  if ( c[0] == '0'  || c[0] == 'n'  || c[0] == 'N' ||
       c[0] == 'f'  || c[0] == 'F')
    {
      *fval = S_FALSE;
      SL_RETURN( (0), _("sh_util_flagval"));
    }
  SL_RETURN( (-1), _("sh_util_flagval"));
}

int sh_util_timeout_check (SH_TIMEOUT * sh_timer)
{
  UINT64 now = (UINT64) time(NULL);
  UINT64 dif;
  
  if (sh_timer->flag_ok == S_FALSE)
    {
      /* first time
       */
      if (sh_timer->time_last == 0)
	{
	  sh_timer->time_last = now;
	  return S_TRUE;
	}
      /* later on
       */
      dif = now - sh_timer->time_last;
      if (dif < sh_timer->time_dist)
	{
	  return S_FALSE;
	}
      sh_timer->time_last = now;
      return S_TRUE;
    }
  sh_timer->time_last = now;
  return S_FALSE;
}

static int sh_ask_update = S_FALSE;

int sh_util_set_interactive(const char * str)
{
  (void) str;

  sh_ask_update = S_TRUE;
  sh_unix_setnodeamon(NULL);

  return 0;
}

static char * sh_update_file = NULL;

int sh_util_update_file (const char * str)
{
  if (str)
    {
      if (0 == access(str, R_OK)) /* flawfinder: ignore */
	{
	  if (NULL != sh_update_file)
	    SH_FREE(sh_update_file);
	  sh_update_file = sh_util_strdup(str);
	  sh_ask_update = S_TRUE;
	  sh_unix_setnodeamon(NULL);
	  return 0;
	}
      else
	{
	  char ebuf[SH_ERRBUF_SIZE];
	  int  errnum = errno;

	  sh_error_message(errnum, ebuf, sizeof(ebuf));
	  sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, errnum, MSG_E_SUBGEN,
			   ebuf, _("sh_util_update_file") );
	  
	  return -1;
	}
    }

  return -1;
}


#if !defined(STDIN_FILENO)
#define STDIN_FILENO 0
#endif
#if !defined(STDERR_FILENO)
#define STDERR_FILENO 0
#endif

/* Returns S_FALSE if no update desired 
 */
int sh_util_update_checkfile(const char * path)
{
  FILE * fd = fopen(sh_update_file, "r");
  char * line;

  if (!fd)
    {
      uid_t  euid;
      int errnum = errno;
      sl_get_euid(&euid);
      sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, errnum, MSG_NOACCESS,
		       (long) euid, sh_update_file);
      aud_exit (FIL__, __LINE__, EXIT_FAILURE);
      return S_FALSE;
    }

  line = SH_ALLOC(8192);

  while (NULL != fgets(line, 8192, fd))
    {
      char * nl = strrchr(line, '\n');

      if (nl)
	{
	  *nl = '\0';

	  /* Check for MS Windows line terminator 
	   */
	  if (nl > line) --nl;
	  if (*nl == '\r')
	    *nl = '\0';
	}

      if (0 == sl_strcmp(line, path))
	{
	  SH_FREE(line);
	  fclose(fd);
	  return S_TRUE;
	}
    }
  SH_FREE(line);
  fclose(fd);
  return S_FALSE;
}

/* Returns S_FALSE if no update desired 
 */
int sh_util_ask_update(const char * path)
{
  int    inchar, c;
  int    i = S_TRUE;
  char * tmp = NULL;

  SL_ENTER(_("sh_util_ask_update"));

  if (sh_ask_update != S_TRUE)
    {
      SL_RETURN(i, _("sh_util_ask_update"));
    }

  if (sh_update_file)
    {
      i = sh_util_update_checkfile(path);
      SL_RETURN(i, _("sh_util_ask_update"));
    }

#ifdef HAVE_TTYNAME
  if (!ttyname(STDIN_FILENO))
    {
      if (NULL != ttyname(STDERR_FILENO))
        {
	  /* cppcheck-suppress leakReturnValNotUsed */
          if (NULL == freopen(ttyname(STDERR_FILENO), "r", stdin))
            {
              sh_error_handle ((-1), FIL__, __LINE__, 0, 
			       MSG_E_SUBGEN,
			       _("Cannot continue: stdin is not a terminal"),
			       _("sh_util_ask_update"));
              exit(EXIT_FAILURE);
	    }
        }
      else
        {
	  sh_error_handle ((-1), FIL__, __LINE__, 0, 
			   MSG_E_SUBGEN,
			   _("Cannot continue: stdin is not a terminal"),
			   _("sh_util_ask_update"));
          exit(EXIT_FAILURE);
        }
    }
#endif

  if (sh_ask_update == S_TRUE)
    {
      tmp = sh_util_safe_name (path);
      fprintf (stderr, _("Update %s [Y/n] ? "), tmp);
      SH_FREE(tmp);
      while (1 == 1)
	{
	  c = fgetc(stdin); inchar = c;
	  /*@+charintliteral@*/
	  while (c != '\n' && c != EOF)
	    c = fgetc(stdin);
	  /* fprintf(stderr, "CHAR (1): %c\n", inchar); */
	  if (inchar == 'Y' || inchar == 'y' || inchar == '\n')
	    {
	      break;
	    }
	  else if (inchar == 'n' || inchar == 'N')
	    {
	      i = S_FALSE;
	      break;
	    }
	  else
	    {
	      fprintf(stderr, "%s", _("Please answer y(es) or n(o)\n"));
	    }
	  /*@-charintliteral@*/
	}
    }

  SL_RETURN(i, _("sh_util_ask_update"));
}

int sh_util_hidesetup(const char * c)
{
  int i;
  SL_ENTER(_("sh_util_hidesetup"));
  i = sh_util_flagval(c, &(sh.flag.hidefile));

  SL_RETURN(i, _("sh_util_hidesetup"));
}

char * sh_util_acl_compact(char * buf, ssize_t len)
{
  unsigned char  * p = (unsigned char *) buf;
  int       state = 0;
  ssize_t   rem = 0;
  char    * out;
  
  SH_VALIDATE_NE(buf, NULL);
  SH_VALIDATE_GE(len, 0);

  out = SH_ALLOC(len + 1);

  while (*p != '\0')  {

    /* -- not at start or after newline
     */
    if (state == 1) {
      if (*p == '\n' || *p == ' ' || *p == '\t' || *p == '#') {
	while (*p != '\n') {
	  ++p;
	  if (*p == '\0') {
	    goto exit_it;
	  }
	}
	out[rem] = ','; ++rem;    /* <-- ensures (rem > 0) is true    */ 
	while (p[1] == '\n') ++p; /* scan over consecutive newlines   */
	state = 0;
	if (p[1] == '\0') {
	  out[rem-1] = '\0';      /* rem > 0 because of 4 lines above */
	  break;
	}
      }
      else {
	if (*p <= 0x7F && isgraph((int) *p)) {
	  out[rem] = (char) *p; ++rem;
	}
      }
    }

    /* -- at start or after newline
     */
    else /* if (state == 0) */ {
      if        (0 == strncmp((char *) p, "user", 4)) {
	out[rem] = 'u'; ++rem;
	p += 3;
      } else if (0 == strncmp((char *) p, "group", 5)) {
	out[rem] = 'g'; ++rem;
	p += 4; 
      } else if (0 == strncmp((char *) p, "mask", 4)) {
	out[rem] = 'm'; ++rem;
	p += 3;
      } else if (0 == strncmp((char *) p, "other", 5)) {
	out[rem] = 'o';
	p += 4; ++rem;
      } else if (*p == '\0') {
	if (rem > 0) { out[rem-1] = '\0'; }
	break;
      } else {
	if (*p <= 0x7F && isprint((int) *p)) {
	  out[rem] = (char) *p; ++rem;
	}
      }
      state = 1;
    }
    ++p;
  }
 exit_it:
  out[rem] = '\0';
  return out;
}


char * sh_util_strdup_l (const char * str, size_t len)
{
  char * p = NULL;

  SL_ENTER(_("sh_util_strdup_l"));

  SH_VALIDATE_NE(str, NULL);
  SH_VALIDATE_NE(len, 0);

  if (str && sl_ok_adds (len, 1))
    {
      p   = SH_ALLOC (len + 1);
      (void) memcpy (p, str, len+1);
    }
  else
    {
      safe_fatal(_("integer overflow in sh_util_strdup_l"), FIL__, __LINE__);
    }
  SL_RETURN( p, _("sh_util_strdup_l"));
}

char * sh_util_strdup (const char * str) 
{
  char * p = NULL;
  size_t len;

  SL_ENTER(_("sh_util_strdup"));

  SH_VALIDATE_NE(str, NULL);

  if (str)
    {
      len = sl_strlen(str);
      p   = SH_ALLOC (len + 1);
      (void) memcpy (p, str, len+1);
    }
  SL_RETURN( p, _("sh_util_strdup"));
}

char * sh_util_strdup_track (const char * str, char * file, int line) 
{
  char * p = NULL;
  size_t len;

  SL_ENTER(_("sh_util_strdup_track"));

  SH_VALIDATE_NE(str, NULL);

  if (str)
    {
      len = sl_strlen(str);
      p   = SH_OALLOC (len + 1, file, line);
      (void) memcpy (p, str, len+1);
    }
  SL_RETURN( p, _("sh_util_strdup_track"));
}

/* by the eircom.net computer incident
 * response team
 */
char * sh_util_strsep (char **str, const char *delim) 
{
  char *ret, *c;
  const char *d;

  SL_ENTER(_("sh_util_strsep"));
  ret = *str;

  SH_VALIDATE_NE(ret, NULL);

  if (*str)
    {
      for (c = *str; *c != '\0'; c++) {
	for (d = delim; *d != '\0'; d++) {
	  if (*c == *d) {
	    *c = '\0';
	    *str = c + 1;
	    SL_RETURN(ret, _("sh_util_strsep"));
	  }
	}
      }
    }

  /* If we get to here, there's no delimiters in the string */
  *str = NULL;
  SL_RETURN(ret, _("sh_util_strsep"));
}


/* returned string must be free'd by caller.
 */
char * sh_util_formatted (const char * formatt, st_format * ftab)
{
  struct tm   * time_ptr;
  size_t size;
  size_t isiz;
  char * fmt = NULL;
  char * p;
  char * q;
  char * outstr;
  int    i;
  int    j;
  time_t inpp;

  char * clist[16] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
  int    nn = 0;

  SL_ENTER(_("sh_util_formatted"));

  if (formatt == NULL || ftab == NULL || *formatt == '\0')
    SL_RETURN(NULL, _("sh_util_formatted"));

  /* -- save the format (we overwrite it !!) --
   */
  size = sl_strlen(formatt);

  if (!sl_ok_adds(size, 1))
    SL_RETURN(NULL, _("sh_util_formatted"));

  ++size;
  fmt = SH_ALLOC(size);
  (void) sl_strlcpy(fmt, formatt, size);

  p = fmt;

  j = 0;
  while (ftab[j].fchar != '\0') {
    if (ftab[j].type != S_FMT_STRING)
      ftab[j].data_str = NULL;
    ++j;
  }
 
  while (p != NULL && *p != '\0' && NULL != (q = strchr(p, '%')))
    {
      ++q;

      /* fprintf(stderr, "p ==  %s   q == %s\n", p, q); */

      /* -- end of string is a '%' --
       */
      if (*q == '\0')
	{
	  --q;
	  *q = '\0';
	  break;
	}

      i = 0;
      j = 0;

      /* -- search the format char in input table --
       * put (nn < 16) here -> all remaining %foo will be
       * converted to %%
       */
      while (ftab[j].fchar != '\0' && nn < 16)
	{
	  if (ftab[j].fchar == *q)
	    {
	      /* -- Convert it to a string format (%s). --
	       */
	      *q = 's'
;
	      i  = 1;
	      
	      switch(ftab[j].type) {

	      case S_FMT_STRING:
		{
		  isiz = sl_strlen(ftab[j].data_str);
		  if (isiz > 0 && sl_ok_adds(size, isiz))
		    {
		      size += isiz;
		      clist[nn] = ftab[j].data_str;
		      ++nn;
		    }
		  else
		    *q = '%';
		  goto endsrch;
		}
		break;

	      case S_FMT_ULONG:
		{
		  ftab[j].data_str = (char *) SH_ALLOC(64);
		  /*@-bufferoverflowhigh@*/
		  sprintf (ftab[j].data_str, "%lu",      /* known to fit  */
			   ftab[j].data_ulong);
		  /*@+bufferoverflowhigh@*/
		  isiz = sl_strlen(ftab[j].data_str);
		  if (isiz > 0 && sl_ok_adds(size, isiz))
		    {
		      size += isiz;
		      clist[nn] = ftab[j].data_str;
		      ++nn;
		    }
		  else
		    *q = '%';
		  goto endsrch;
		}
		break;

	      case S_FMT_LONG:
		{
		  ftab[j].data_str = (char *) SH_ALLOC(64);
		  /*@-bufferoverflowhigh@*/
		  sprintf (ftab[j].data_str, "%ld",      /* known to fit  */
			   ftab[j].data_long);
		  /*@+bufferoverflowhigh@*/
		  isiz = sl_strlen(ftab[j].data_str);
		  if (isiz > 0 && sl_ok_adds(size, isiz))
		    {
		      size += isiz;
		      clist[nn] = ftab[j].data_str;
		      ++nn;
		    }
		  else
		    *q = '%';
		  goto endsrch;
		}
		break;

	      case S_FMT_TIME:
		{
		  ftab[j].data_str = (char *) SH_ALLOC(64);
                  inpp = (time_t)ftab[j].data_ulong;
		  if (inpp != 0)
		    {
		      time_ptr = localtime (&(inpp));
		      if (time_ptr != NULL) 
			(void) strftime(ftab[j].data_str, 64, 
					_("%d-%m-%Y %H:%M:%S"), time_ptr);
		      else
			(void) sl_strlcpy(ftab[j].data_str, 
					  _("00-00-0000 00:00:00"), 64);
		    }
		  else
		    {
		      (void) sl_strlcpy(ftab[j].data_str, 
					_("(None)"), 64);
		    }
		  isiz = sl_strlen(ftab[j].data_str);
		  if (isiz > 0 && sl_ok_adds(size, isiz))
		    {
		      size += isiz;
		      clist[nn] = ftab[j].data_str;
		      ++nn;
		    }
		  else
		    *q = '%';
		  goto endsrch;
		}
		break;

	      default:
		/* do nothing */;
	      }

	    }
	  ++j;
	}

    endsrch:

      p = q;

      /* -- not found -- */
      if (i == 0)
	{
	  *q = '%';
	  ++p;
	}

    }

  /* -- Format string evaluated.
     clist[]   List of strings
     size      Total size of format string + clist[] strings
     -- */
  
  /* -- closing '\0' --
   */
  if (sl_ok_adds(size, 1))
    size++;
  outstr = (char *) SH_ALLOC(size);

  /* -- print it --
   */
  (void) sl_snprintf( outstr, size, fmt,
		      clist[0],  clist[1], clist[2],  clist[3], 
		      clist[4],  clist[5], clist[6],  clist[7], 
		      clist[8],  clist[9], clist[10], clist[11], 
		      clist[12], clist[13], clist[14], clist[15]); 
  outstr[size-1] = '\0';

  /* -- cleanup --
   */
  j = 0;
  while (ftab[j].fchar != '\0') {
    if (ftab[j].type != S_FMT_STRING && ftab[j].data_str != NULL)
      SH_FREE(ftab[j].data_str);
    ++j;
  }
  SH_FREE(fmt);

  SL_RETURN(outstr, _("sh_util_formatted"));
}

/* read a hexchar, return int value (0-15)
 * can't inline (AIX)
 */
int sh_util_hexchar( const char c )
{
  /*@+charint@*/
  if      ( c >= '0' && c <= '9' )
    return c - '0';
  else if ( c >= 'a' && c <= 'f' )
    return c - 'a' + 10;
  else if ( c >= 'A' && c <= 'F' )
    return c - 'A' + 10;
  else return -1;
  /*@-charint@*/
}

char * sh_util_charhex( unsigned char i , char * i2h)
{
  int j, k;

  j = i / 16;
  k = i - (j*16);

  if (j < 10) i2h[0] = '0'+j;
  else        i2h[0] = 'A'+(j-10);
  
  if (k < 10) i2h[1] = '0'+k;
  else        i2h[1] = 'A'+(k-10);

  return i2h;
}

/* read a hexadecimal key, convert to binary
 */
int sh_util_hextobinary (char * binary, const char * hex, int bytes)
{
  int i = 0, j, k, l = 0;
  char c;

#define SH_HEXCHAR(x, y) \
    c = (x); \
    if ( c >= '0' && c <= '9' ) \
      y = c - '0'; \
    else if ( c >= 'a' && c <= 'f' ) \
      y = c - 'a' + 10; \
    else if ( c >= 'A' && c <= 'F' ) \
      y = c - 'A' + 10; \
    else \
      SL_RETURN((-1), _("sh_util_hextobinary"))


  SL_ENTER(_("sh_util_hextobinary"));

  if (bytes < 2)
    SL_RETURN((-1), _("sh_util_hextobinary"));

  while (i < (bytes-1))
    {
      SH_HEXCHAR(hex[i],   k);
      SH_HEXCHAR(hex[i+1], j);
      
      binary[l] = (char)(k * 16 + j);
      ++l; i+= 2;
    }
  
  SL_RETURN((0), _("sh_util_hextobinary"));
}

static void copy_four (unsigned char * dest, UINT32 in)
{
  UINT32 i, j;
  int    count;

  SL_ENTER(_("copy_four"));
  for (count = 0; count < 4; ++count)
    {
      i  = in / 256;
      j  = in - (i*256);
      dest[count] = (unsigned char) j;
      in = i;
    }
  SL_RET0(_("copy_four"));
}

/* compute HMAC-TIGER
 */
static char * sh_util_hmac_tiger (char * hexkey,  
				  char * text, size_t textlen,
				  char * res, size_t len)
{
  static char opad[KEY_BLOCK] = { 
    (char)0x5C, (char)0x5C, (char)0x5C, (char)0x5C, (char)0x5C, (char)0x5C, 
    (char)0x5C, (char)0x5C, (char)0x5C, (char)0x5C, (char)0x5C, (char)0x5C, 
    (char)0x5C, (char)0x5C, (char)0x5C, (char)0x5C, (char)0x5C, (char)0x5C, 
    (char)0x5C, (char)0x5C, (char)0x5C, (char)0x5C, (char)0x5C, (char)0x5C
  };
  static char ipad[KEY_BLOCK] = { 
    (char)0x36, (char)0x36, (char)0x36, (char)0x36, (char)0x36, (char)0x36,  
    (char)0x36, (char)0x36, (char)0x36, (char)0x36, (char)0x36, (char)0x36,  
    (char)0x36, (char)0x36, (char)0x36, (char)0x36, (char)0x36, (char)0x36,  
    (char)0x36, (char)0x36, (char)0x36, (char)0x36, (char)0x36, (char)0x36
  };
  static char  zap[KEY_BLOCK] = { 
    (char)0x00, (char)0x00, (char)0x00, (char)0x00, (char)0x00, (char)0x00,  
    (char)0x00, (char)0x00, (char)0x00, (char)0x00, (char)0x00, (char)0x00,  
    (char)0x00, (char)0x00, (char)0x00, (char)0x00, (char)0x00, (char)0x00,  
    (char)0x00, (char)0x00, (char)0x00, (char)0x00, (char)0x00, (char)0x00
  };
  char        K[KEY_BLOCK];
  char        outer[KEY_BLOCK];
  char      * inner;
  UINT32    * h1;
  UINT32    * h2;
  UINT32      cc[KEY_LEN/4];
  UINT32      kbuf[KEY_BYT/sizeof(UINT32)];
  char hashbuf[KEYBUF_SIZE];

  int         result;
  size_t      i;

  SL_ENTER(_("sh_util_hmac_tiger"));

  ASSERT((KEY_BLOCK <= (KEY_LEN/2)), _("KEY_BLOCK <= (KEY_LEN/2)"));

  memcpy (K, zap, KEY_BLOCK);

  result = sh_util_hextobinary (K, hexkey, KEY_LEN);

  ASSERT((result >= 0), _("result >= 0"));

  if ((result >= 0) && sl_ok_adds(textlen, KEY_BLOCK))
    {
      inner = (char *) SH_ALLOC (textlen + KEY_BLOCK); 

      for (i = 0; i < KEY_BLOCK; ++i)
	{
	  outer[i]  = K[i] ^ opad[i];
	  inner[i]  = K[i] ^ ipad[i];
	}
      for (i = KEY_BLOCK; i < (KEY_BLOCK+textlen); ++i)
	{
	  inner[i] = text[i - KEY_BLOCK];
	}
    }
  else
    {
      sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
		      _("integer overflow"), 
		      _("sh_util_hmac_tiger"));
      (void) sh_tiger_hash (NULL, TIGER_DATA, 0, hashbuf, sizeof(hashbuf));
      sl_strlcpy(res, hashbuf, len);
      SL_RETURN(res, _("sh_util_hmac_tiger"));
    }

  /* now compute the hash 
   */
  h1 = sh_tiger_hash_uint32 ( outer, TIGER_DATA, KEY_BLOCK,
			      kbuf, KEY_BYT/sizeof(UINT32));
  for (i = 0; i < (KEY_LEN/8); ++i)
    copy_four ( (unsigned char *) &(cc[i]), h1[i]);

  h2 = sh_tiger_hash_uint32 ( inner, TIGER_DATA,
			      (unsigned long) KEY_BLOCK+textlen,
			      kbuf, KEY_BYT/sizeof(UINT32));
  for (i = KEY_LEN/8; i < (KEY_LEN/4); ++i)
    copy_four ( (unsigned char *) &(cc[i]), h2[i - (KEY_LEN/8)]);

  SH_FREE(inner);
  
  (void) sh_tiger_hash ((char *) &cc[0],
			TIGER_DATA,
			(unsigned long) (KEY_LEN/4 * sizeof(UINT32)),
			hashbuf, sizeof(hashbuf));

  sl_strlcpy(res, hashbuf, len);
  SL_RETURN(res, _("sh_util_hmac_tiger"));
}

static char * sh_util_hash_tiger ( char * hexkey,  
				   char * text, size_t textlen,
				   char * res, size_t len)
{
  char           h2[2*KEY_LEN+1];
  char hashbuf[KEYBUF_SIZE];

  SL_ENTER(_("sh_util_hash_tiger"));

  (void) sl_strlcpy(h2, hexkey, KEY_LEN+1); 
  (void) sl_strlcat(h2, 
		    sh_tiger_hash(text, TIGER_DATA, 
				  (unsigned long) textlen,
				  hashbuf, sizeof(hashbuf)), 
		    2*KEY_LEN+1
		    );

  (void) sh_tiger_hash(h2, TIGER_DATA, 2*KEY_LEN, hashbuf, sizeof(hashbuf));

  sl_strlcpy(res, hashbuf, len);
  SL_RETURN(res, _("sh_util_hash_tiger"));
}

/* --- compute signature on data ---
 */
#define TYPE_HMAC 0
#define TYPE_HASH 1

static int sigtype = TYPE_HMAC;

int sh_util_sigtype (const char * c)
{
  SL_ENTER(_("sh_util_sigtype"));
  if (c == NULL)
    SL_RETURN( -1, _("sh_util_sigtype"));

  if (0 == strcmp(_("HMAC-TIGER"), c))
    sigtype = TYPE_HMAC;
  else if  (0 == strcmp(_("HASH-TIGER"), c))
    sigtype = TYPE_HASH;
  else
    SL_RETURN( -1, _("sh_util_sigtype"));

  SL_RETURN( 0, _("sh_util_sigtype"));
}

char * sh_util_siggen (char * hexkey,  
		       char * text, size_t textlen,
		       char * res, size_t len)  
{
  char * p;
  
  SL_ENTER(_("sh_util_siggen"));
  if (sigtype == TYPE_HMAC)
    p = sh_util_hmac_tiger (hexkey,  
			    text, textlen, res, len);
  else
    p = sh_util_hash_tiger (hexkey,  
			    text, textlen, res, len);
  SL_RETURN(p, _("sh_util_siggen"));
}    

 
/* a simple compressor
 */
size_t sh_util_compress (char * dest, char * src, size_t dest_size)
{
  char * add;
  char * get;
  size_t   count = 0;
  size_t   dest_end;

  SL_ENTER(_("sh_util_compress"));

  if (dest_size == 0)
    SL_RETURN((0), _("sh_util_compress"));
  
  if ((dest == NULL) || (src == NULL))
    SL_RETURN((0), _("sh_util_compress"));
  
  dest_end = sl_strlen(dest);

  if (dest_end > dest_size)
    SL_RETURN((0), _("sh_util_compress"));

  add      = &dest[dest_end];
  get      = src;

  while (count < (dest_size-dest_end))
    {
      if (isalnum((int) *get)) 
	{
	  *add = *get;
	  ++add;
	  ++count;
	}
      ++get; 
      if (*get == '\0' && (count < (dest_size-dest_end))) 
	/* end of src reached */
	{
	  *add = *get;  /* copy the '\0'      */
	  break;        /* and stop copying   */
	}
    }

  dest[dest_size-1] = '\0'; /* paranoia       */
  SL_RETURN((count), _("sh_util_compress")); /* no of chars copied */    
}


/* copy the four least significant bytes 
 */
void sh_util_cpylong (char * dest, const char * src, int len )
{
  int i, j;
  union
  {
    long l;
    char c[sizeof(long)];
  } u;
#ifdef WORDS_BIGENDIAN
  unsigned char swap;
  unsigned char * ii = (unsigned char *) dest;
#endif

  SL_ENTER(_("sh_util_cpylong"));    

  u.l = 1;

  /* MSB is first
   */
  if (sizeof(long)>4 &&/*@+charint@*/(u.c[sizeof(long)-1] == 1)/*@-charint@*/)
    {
      j = (int) (sizeof(long)-4);
      for (i = 0; i < j; ++i) ++src;
    }

  i = 0;

  while (i < 4)
    {
      *dest = (*src);
      ++dest; ++src;
      if (i == (len-1)) break;
      ++i;
    }
#ifdef WORDS_BIGENDIAN
  swap = ii[0]; ii[0] = ii[3]; ii[3] = swap;
  swap = ii[1]; ii[1] = ii[2]; ii[2] = swap;
#endif
  SL_RET0(_("sh_util_cpylong"));
}

/*  This is a maximally equidistributed combined Tausworthe
 *  generator. The sequence is,
 *
 *   x_n = (s1_n ^ s2_n ^ s3_n) 
 *
 *   s1_{n+1} = (((s1_n & 4294967294) <<12) ^ (((s1_n <<13) ^ s1_n) >>19))
 *   s2_{n+1} = (((s2_n & 4294967288) << 4) ^ (((s2_n << 2) ^ s2_n) >>25))
 *   s3_{n+1} = (((s3_n & 4294967280) <<17) ^ (((s3_n << 3) ^ s3_n) >>11))
 *
 *   computed modulo 2^32. In the three formulas above '^' means
 *   exclusive-or (C-notation), not exponentiation. Note that the
 *   algorithm relies on the properties of 32-bit unsigned integers (it
 *   is formally defined on bit-vectors of length 32). 
 *
 *   Stolen from GSL (GNU scientific library) and modified somewhat.
 *   I am using UINT32, which is guaranteed to be 32 bits. Also made
 *   sure that the initialization vector is valid.
 */


/* interval [0, 4294967295]
 */
static UINT32 taus_get_long (void *vstate)
{
  UINT32 * state = (UINT32 *) vstate;

  /*
  if (skey->rngI == BAD)
    (void)taus_seed();
  */

#define TAUSWORTHE(s,a,b,c,d) ((s &c) <<d) ^ (((s <<a) ^s) >>b)
  /*@+ignorequals@*/
  state[0] = TAUSWORTHE (state[0], 13, 19, 4294967294UL, 12);
  state[1] = TAUSWORTHE (state[1],  2, 25, 4294967288UL,  4);
  state[2] = TAUSWORTHE (state[2],  3, 11, 4294967280UL, 17);
  /*@-ignorequals@*/
  return (state[0] ^ state[1] ^ state[2]);
}

/* Hide the internal state of the PRNG by using its output as
 * input for a one-way hash function.
 */

UINT32 taus_get ()
{
#define TAUS_SAMPLE 12

  UINT32   taus_svec[TAUS_SAMPLE];
  UINT32   retval;
  UINT32 * res;
  UINT32 * res_vec = &(skey->res_vec[0]);
  static   int      res_num = 0;
  register int i;
  UINT32       kbuf[KEY_BYT/sizeof(UINT32)];

  SH_MUTEX_LOCK_UNSAFE(mutex_skey);
  if (res_num > 0)
    {
      retval  = res_vec[res_num];
      res_num = (res_num == 5) ? 0 : (res_num + 1);
      SH_MUTEX_UNLOCK_UNSAFE(mutex_skey); /* alternative path */
      return  retval;
    }
  SH_MUTEX_UNLOCK_UNSAFE(mutex_skey);

  (void)taus_seed();

  SH_MUTEX_LOCK_UNSAFE(mutex_skey);
  for (i = 0; i < (TAUS_SAMPLE/3); ++i)
    {
      taus_svec[i*3]   = taus_get_long (&(skey->rng0[0]));
      taus_svec[i*3+1] = taus_get_long (&(skey->rng1[0]));
      taus_svec[i*3+2] = taus_get_long (&(skey->rng2[0]));
    }
  SH_MUTEX_UNLOCK_UNSAFE(mutex_skey);

  res     = sh_tiger_hash_uint32 ( (char *) &taus_svec[0], 
				   TIGER_DATA, 
				   (unsigned long)(TAUS_SAMPLE * sizeof(UINT32)),
				   kbuf, KEY_BYT/sizeof(UINT32));

  SH_MUTEX_LOCK_UNSAFE(mutex_skey);
  for (i = 1; i < 6; ++i)
    { 
      res_vec[i] = res[i];
    }
  retval  = res[0];
  res_num = 1;
  SH_MUTEX_UNLOCK_UNSAFE(mutex_skey);

  memset(taus_svec, '\0', TAUS_SAMPLE * sizeof(UINT32));

  return retval;
}

/* interval [0,1)
 */
double taus_get_double (void *vstate)
{
  return taus_get_long (vstate) / (4294967296.0 + 1.0) ;
}

#define LCG(n) ((69069 * n) & 0xffffffffUL)

/* TAKE CARE: state[0], state[1], state[2] must be > 2,8,16, respectively 
 */
static void taus_set_from_ulong (void *vstate, unsigned long int s)
{
  UINT32  *state = (UINT32  *) vstate;

  if (s == 0)
    s = 1;	/* default seed is 1 */

  state[0] = (UINT32)(LCG (s)        | (UINT32) 0x03);
  state[1] = (UINT32)(LCG (state[0]) | (UINT32) 0x09);
  state[2] = (UINT32)(LCG (state[1]) | (UINT32) 0x17);

  /* 'warm up'
   */
  (void) taus_get_long (state);
  (void) taus_get_long (state);
  (void) taus_get_long (state);
  (void) taus_get_long (state);
  (void) taus_get_long (state);
  (void) taus_get_long (state);

  return;
}

static void taus_set_from_state (void *vstate, void *init_state)
{
  UINT32  *state  = (UINT32  *) vstate;
  UINT32  *state0 = (UINT32  *) init_state;

  state[0] = state0[0]  | (UINT32) 0x03;
  state[1] = state0[1]  | (UINT32) 0x09;
  state[2] = state0[2]  | (UINT32) 0x17;
  
  return;
}

 
int taus_seed ()
{
  char                 bufx[9 * sizeof(UINT32) + 1];
  int                  status;
  static unsigned long seed_time    = 0;
  static unsigned long seed_counter = 3000;
  unsigned long        gtime;

  SL_ENTER(_("taus_seed"));

  if (skey->rngI == GOOD)
    {
      ++seed_counter;

      if ( ((sh_unix_longtime () - seed_time) < 1800) &&
	   ( seed_counter                     < 3000))
	SL_RETURN( (0), _("taus_seed"));
    }
  
  seed_time    = sh_unix_longtime ();
  seed_counter = 0;

  status = sh_entropy (24, bufx);

  if (!SL_ISERROR(status))
    {
      SH_MUTEX_LOCK_UNSAFE(mutex_skey);
      memcpy (&skey->rng0[0], &bufx[0],                  2*sizeof(UINT32));
      memcpy (&skey->rng1[0], &bufx[2*sizeof(UINT32)],   2*sizeof(UINT32));
      memcpy (&skey->rng2[0], &bufx[4*sizeof(UINT32)],   2*sizeof(UINT32));
      memset (bufx, 0, 9 * sizeof(UINT32) + 1);

      skey->rng0[2] = 0;
      skey->rng1[2] = 0;
      skey->rng2[2] = 0;

      taus_set_from_state( &(skey->rng0[0]), &(skey->rng0[0]));
      taus_set_from_state( &(skey->rng1[0]), &(skey->rng1[0]));
      taus_set_from_state( &(skey->rng2[0]), &(skey->rng2[0]));

      skey->rngI = GOOD;
      SH_MUTEX_UNLOCK_UNSAFE(mutex_skey);
      SL_RETURN( (0), _("taus_seed"));
    }

  sh_error_handle ((-1), FIL__, __LINE__, status, MSG_ES_ENT,
		   _("sh_entropy"));

  /* emergency backup - unsafe !
   */
#ifdef HAVE_GETTIMEOFDAY
  gtime = sh_unix_notime();
#else
  gtime = seed_time;
#endif

  SH_MUTEX_LOCK_UNSAFE(mutex_skey);
  taus_set_from_ulong ( &(skey->rng0[0]), LCG (gtime)          );
  taus_set_from_ulong ( &(skey->rng1[0]), LCG (skey->rng0[0])  );
  taus_set_from_ulong ( &(skey->rng2[0]), LCG (skey->rng1[0])  );
  skey->rngI = BAD;
  SH_MUTEX_UNLOCK_UNSAFE(mutex_skey);

  SL_RETURN( (-1), _("taus_seed"));
}

/*@+charint@*/
static unsigned char new_key[] = { 0xA7,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xA7 };
/*@-charint@*/
static void copy_four (unsigned char * dest, UINT32 in);

int sh_util_set_newkey (const char * new_in)
{
  size_t i, j = 0;
  size_t len;
  SL_TICKET fp;
  SL_TICKET fout;
  char * key;
  char * path = NULL;
  char * outpath = NULL;
  unsigned char * image = NULL;
  long s = 0;
  long ilen = 0;
  long ii, k = 0;
  UINT32    * h1;
  char * new = NULL;

  if (0 != sl_is_suid())
    {
      fprintf(stderr, "%s", _("ERROR: insufficient privilege\n"));
      _exit (EXIT_FAILURE);
      /*@notreached@*/
      return -1;  /* braindead MAC OSX compiler needs this */
    }
        
  if (new_in == NULL || new_in[0] == '\0')
    {
      fprintf(stderr, "%s", 
	      _("ERROR: no key given\n Argument must be 'key@path'\n"));
      _exit (EXIT_FAILURE);
      /*@notreached@*/
      return -1;
    }

  if (NULL == (new = calloc(1,strlen(new_in) + 1)))
    goto bail_mem;
  sl_strncpy(new, new_in, strlen(new_in) + 1);

  key = new;
  len = strlen(new);
  for (i = 1; i < (len-2); ++i)
    {
      if (new[i] == '@' && new[i+1] == '/')
	{
	  j = i+1; new[i] = '\0'; break;
	}
    }
  if (j == 0)
    {
      fprintf(stderr, "%s",
	      _("ERROR: no path to executable given\n Argument must be 'key@path'\n"));
      free(new);
      _exit (EXIT_FAILURE);
      /*@notreached@*/
      return -1;
    }
  else
    path = &new[j];

  len = strlen(path) + 1 + 4;
  /*@-usedef@*/
  if (NULL == (outpath = calloc(1,len)))
    goto bail_mem;
  /*@-usedef@*/
  sl_snprintf (outpath, len, _("%s.out"), path);

  fp = sl_open_read(FIL__, __LINE__, path, SL_NOPRIV);
  if (SL_ISERROR(fp))
    {
      fprintf(stderr, 
	      _("ERROR: cannot open %s for read (errnum = %ld)\n"), path, fp);
      free(new); free (outpath);
      _exit (EXIT_FAILURE);
      /*@notreached@*/
      return -1;
    }
  
  fout = sl_open_write(FIL__, __LINE__, outpath, SL_NOPRIV);
  if (SL_ISERROR(fout))
    {
      fprintf(stderr, 
	      _("ERROR: cannot open %s (errnum = %ld)\n"), outpath, fout);
      free(new); free (outpath);
      _exit (EXIT_FAILURE);
      /*@notreached@*/
      return -1;
    }


  image = calloc(1,4096);
  if (!image)
    goto bail_mem;
  while (0 < (ii = sl_read (fp, &image[s], 4096)))
    {
      unsigned char * ptr;
      ilen += ii;
      s    += 4096;
      ptr = realloc (image, (size_t) (4096 + s));
      if (ptr)
	image = ptr;
      else
	{ free(image); image = NULL; }
      if (!image)
	goto bail_mem;
    }

  printf(_("%ld bytes read\n"), ilen);

  
  for (k = 0; k < (ilen - 8); ++k) 
    {
      if (image[k]   == new_key[0] &&
	  image[k+1] == new_key[1] &&
	  image[k+2] == new_key[2] &&
	  image[k+3] == new_key[3] &&
	  image[k+4] == new_key[4] &&
	  image[k+5] == new_key[5] &&
	  image[k+6] == new_key[6] &&
	  image[k+7] == new_key[7])
	{
	  UINT32 kbuf[KEY_BYT/sizeof(UINT32)];

	  printf("%s", _("old key found\n")); 
	  h1 = sh_tiger_hash_uint32 (key, TIGER_DATA, 
				     (unsigned long)strlen(key),
				     kbuf, KEY_BYT/sizeof(UINT32));
	  copy_four( (unsigned char *) &(image[k]),   h1[0]);
	  copy_four( (unsigned char *) &(image[k+4]), h1[1]);
	  (void) sl_write (fout, image, ilen);
	  (void) sl_close (fout);
	  printf(_("new file %s written\n"), outpath);
	  free(new); free (outpath); free(image);
	  _exit (EXIT_SUCCESS);
	  /*@notreached@*/
	  return 0;
	}
    }

  fprintf(stderr, "%s",
	  _("ERROR: old key not found\n"));
  free(new); free (outpath); free(image);
  _exit (EXIT_FAILURE);
  /*@notreached@*/
  return -1;


 bail_mem:
  fprintf(stderr, "%s",
	  _("ERROR: out of memory\n"));
  if (new) free(new); 
  if (outpath) free (outpath);
  if (image) free (image);
  _exit (EXIT_FAILURE);
  /*@notreached@*/
  return -1;
}

  

	
/* A simple en-/decoder, based on Vernam cipher. We use the
 * message as salt to hide the key by obtaining a different one-time 
 * pad each time.
 * Should be safe against a listener on the network, but not against someone
 * with read access to the binary.
 */
void sh_util_encode (char * data, char * salt, int mode, char fill)
{
  static char     cc1[17] = N_("0123456789ABCDEF");
  char            cc[17] = "\0";
  register int    i, j, j1 = 0, j2 = 0, j3;
  char          * dez; 
  char hashbuf[KEYBUF_SIZE];

  SL_ENTER(_("sh_util_encode"));

  /* init
   */
  (void) sl_strlcpy( cc, _(cc1), sizeof(cc));

  /* max 128 bits keyspace
   */
  memset (skey->vernam, (int)fill, KEY_LEN+1);

  dez    = (char *) &(skey->ErrFlag[0]);
  sh_util_cpylong (skey->vernam,     dez, 4);
  dez    = (char *) &(skey->ErrFlag[1]);
  sh_util_cpylong (&skey->vernam[4], dez, 4);

  skey->vernam[KEY_LEN] = '\0';

  (void) sl_strlcpy(skey->vernam, 
		    sh_tiger_hash(skey->vernam, TIGER_DATA, KEY_LEN,
				  hashbuf, sizeof(hashbuf)), 
		    KEY_LEN+1);

  (void) sl_strlcpy(skey->vernam, 
		    sh_util_hmac_tiger (skey->vernam, salt, strlen(salt),
					hashbuf, sizeof(hashbuf)),
		    KEY_LEN+1);

  (void) sl_strlcpy(skey->vernam, 
		    sh_util_hmac_tiger (skey->vernam, (char*) new_key, 8,
					hashbuf, sizeof(hashbuf)),
		    KEY_LEN+1);

  /* The following routine adds/subtracts  data[j] and vernam[j] mod 16.
   */
  j = 0;
  while (j < KEY_LEN)
    {
      for (i = 0; i < 16; ++i)
	{
	  if (cc[i] == data[j])   j1 = i;
	  if (cc[i] == skey->vernam[j])    j2 = i;
	}
      if (mode == 0)
	{
	  j3 = j1 + j2;
	  if (j3 > 15) j3 -= 16;
	  data[j] = cc[j3];
	}
      else
	{
	  j3 = j1 - j2;
	  if (j3 <  0) j3 += 16;
	  data[j] = cc[j3];
	}
      ++j;
    }
  SL_RET0(_("sh_util_encode"));
}

/* server mode 
 */
int sh_util_setserver (const char * dummy)
{
  SL_ENTER(_("sh_util_setserver"));

  (void) dummy;
  sh.flag.isserver = GOOD;
  SL_RETURN((0),_("sh_util_setserver"));
}


int sh_util_setlooptime (const char * str)
{
  int i = atoi (str);
  
  SL_ENTER(_("sh_util_setlooptime"));

  if (i >= 0 && i < INT_MAX) {
    sh.looptime = i;
    SL_RETURN((0),_("sh_util_setlooptime"));
  } else {
    sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS,
		     _("loop time"), str);
    SL_RETURN((-1),_("sh_util_setlooptime"));
  }
}

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)
int  sh_util_setchecksum (const char * str)
{
  static int reject = 0;

  SL_ENTER(_("sh_util_setchecksum"));

  if (reject == 1)
    SL_RETURN((0), _("sh_util_setchecksum"));
  reject = 1;

  if (sl_strncmp (str, _("init"), sizeof("init")-1) == 0)
    {
      sh.flag.checkSum = SH_CHECK_INIT;
    }
  else if (sl_strncmp (str, _("update"), sizeof("update")-1) == 0)
    {
      if (S_TRUE == file_is_remote()) 
	{
	  sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS,
			   _("checksum testing"), str);
	  SL_RETURN((-1), _("sh_util_setchecksum"));
	}
      else
	{
	  sh.flag.checkSum = SH_CHECK_CHECK;
	  sh.flag.update   = S_TRUE;
	}
    }
  else if (sl_strncmp (str, _("check"), sizeof("check")-1) == 0)
    {
      sh.flag.checkSum = SH_CHECK_CHECK;
    }
  /*
  else if (sl_strncmp (str, _("update"), sizeof("update")-1) == 0)
    {
      sh.flag.checkSum = SH_CHECK_INIT;
      sh.flag.update   = S_TRUE;
    }
  */
  else if (sl_strncmp (str, _("none"), sizeof("none")-1) == 0)
    {
      sh.flag.checkSum = SH_CHECK_NONE;
    }
  else 
    {
      sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS,
		       _("checksum testing"), str);
      SL_RETURN((-1), _("sh_util_setchecksum"));
    }
  SL_RETURN((0), _("sh_util_setchecksum"));
}
#endif
 
/*@+charint@*/
unsigned char TcpFlag[8][PW_LEN+1] = { 
#if (POS_TF == 1)
  { 0xF7,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xF7,0x00 },
#endif
  { 0xFF,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xFF,0x00 },
#if (POS_TF == 2)
  { 0xF7,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xF7,0x00 },
#endif
  { 0xFF,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xFF,0x00 },
#if (POS_TF == 3)
  { 0xF7,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xF7,0x00 },
#endif
  { 0xFF,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xFF,0x00 },
#if (POS_TF == 4)
  { 0xF7,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xF7,0x00 },
#endif
  { 0xFF,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xFF,0x00 },
#if (POS_TF == 5)
  { 0xF7,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xF7,0x00 },
#endif
  { 0xFF,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xFF,0x00 },
#if (POS_TF == 6)
  { 0xF7,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xF7,0x00 },
#endif
  { 0xFF,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xFF,0x00 },
#if (POS_TF == 7)
  { 0xF7,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xF7,0x00 },
#endif
  { 0xFF,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xFF,0x00 },
#if (POS_TF == 8)
  { 0xF7,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xF7,0x00 },
#endif
};
/*@-charint@*/

/* initialize a key to a random value
 * rev 0.8
 */
int sh_util_keyinit (char * buf, long size)
{
  UINT32       bufy[6];
  int          i;
  int          status = 0;
  char       * p;
  char hashbuf[KEYBUF_SIZE];

  SL_ENTER(_("sh_util_keyinit"));

  ASSERT((size <= KEY_LEN+1), _("size <= KEY_LEN+1"))

  if (size > KEY_LEN+1)
    size = KEY_LEN+1;

  /* seed / re-seed the PRNG if required
   */
  status = taus_seed ();

  if (status == -1)
    sh_error_handle ((-1), FIL__, __LINE__, -1, MSG_ES_KEY1,
		     _("taus_seed"));

  for (i = 0; i < 6; ++i)
    bufy[i] = taus_get();

  p = sh_tiger_hash ((char *) bufy, TIGER_DATA, 
		     (unsigned long)(6*sizeof(UINT32)),
		     hashbuf, sizeof(hashbuf));

  i = sl_strlcpy(buf, p, (size_t)size);

  memset (bufy, 0, 6*sizeof(UINT32));

  if ((status == 0) && (!SL_ISERROR(i)) )
    SL_RETURN((0),_("sh_util_keyinit"));

  if (SL_ISERROR(i))
    sh_error_handle ((-1), FIL__, __LINE__, i, MSG_ES_KEY2, 
		     _("sl_strlcpy"));

  SL_RETURN((-1),_("sh_util_keyinit"));
}

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)

static unsigned char sh_obscure_index[256];
static int sh_obscure_no_check = S_FALSE;

int sh_util_valid_utf8 (const unsigned char * str) 
{
  const int     sh_val_utf8_1 = 1;
  const int     sh_val_utf8_2 = 2;
  const int     sh_val_utf8_3 = 3;
  const int     sh_val_utf8_4 = 4;

  size_t        len = strlen((const char *)str);
  size_t        l   = 0;
  int           typ = 0;
  unsigned char c     = '\0';
  unsigned char c2[2] = { 0x00, 0x00 };
  unsigned char c3[3] = { 0x00, 0x00, 0x00 };


#define SH_VAL_UTF8_1 ((c != '\0') && ((c & 0x80) == 0x00))
#define SH_VAL_UTF8_2 ((c != '\0') && ((c & 0xE0) == 0xC0)) /* 110x xxxx */
#define SH_VAL_UTF8_3 ((c != '\0') && ((c & 0xF0) == 0xE0)) /* 1110 xxxx */
#define SH_VAL_UTF8_4 ((c != '\0') && ((c & 0xF8) == 0xF0)) /* 1111 0xxx */
#define SH_VAL_UTF8_N ((c != '\0') && ((c & 0xC0) == 0x80)) /* 10xx xxxx */
#define SH_VAL_BAD    ((c == '"')  || (c == '\t') || (c == '\b') || \
                       (c == '\f') || (c == '\n') || \
                       (c == '\r') || (c == '\v') || iscntrl((int) c) || \
                       (c != ' ' && !isgraph ((int) c)))
   
  while(l < len) 
    {
      c = str[l];

      if      (SH_VAL_UTF8_1) 
	{
	  if (!(SH_VAL_BAD && (sh_obscure_index[c] != 1)))
	    {
	      typ = sh_val_utf8_1;
	      ++l; continue;
	    }
	  else
	    {
	      return S_FALSE;
	    }
	} 
      else if (SH_VAL_UTF8_2) 
	{ 
	  typ = sh_val_utf8_2;
	  c2[0] = c;
	  if ((c & 0x3e) != 0x00) /* !(overlong 2-byte seq.) */
	    {
	      ++l; 
	      if (l != len) {
		c = str[l];
		if(SH_VAL_UTF8_N) {
		  c2[1] = c;
		  ++l; continue;
		} 
		else {
		  return S_FALSE;
		} 
	      } 
	      else {
		return S_FALSE; 
	      }
	    }
	  else
	    {
	      return S_FALSE; /* overlong 2-byte seq. */
	    }
	} 
      else if (SH_VAL_UTF8_3) 
	{
	  typ = sh_val_utf8_3;
	  c3[0] = c;
	  ++l; if (l == len) return S_FALSE; c = str[l];
	  if(!SH_VAL_UTF8_N) return S_FALSE;
	  if (((str[l-1] & 0x1F) == 0x00) && ((c & 0x60) == 0x00))
	    return S_FALSE; /* overlong 3-byte seq. */
	  c3[1] = c;
	  ++l; if (l == len) return S_FALSE; c = str[l];
	  if(!SH_VAL_UTF8_N) return S_FALSE;
	  c3[2] = c;
	  ++l; continue;
	} 
      else if (SH_VAL_UTF8_4) 
	{
	  typ = sh_val_utf8_4;
	  ++l; if (l == len) return S_FALSE; c = str[l];
	  if(!SH_VAL_UTF8_N) return S_FALSE;
	  if (((str[l-1] & 0x0F) == 0x00) && ((c & 0x70) == 0x00))
	    return S_FALSE; /* overlong 4-byte seq. */
	  ++l; if (l == len) return S_FALSE; c = str[l];
	  if(!SH_VAL_UTF8_N) return S_FALSE;
	  ++l; if (l == len) return S_FALSE; c = str[l];
	  if(!SH_VAL_UTF8_N) return S_FALSE;
	  ++l; continue;
	}
      return S_FALSE;
    }

  /* last character is invisible (space or else)
   */
  if (typ == sh_val_utf8_1)
    { 
      if (c != ' ')
	return S_TRUE;
      else
	return S_FALSE;
    }
  else if (typ == sh_val_utf8_2)
    {
      if (c2[0] == 0xC2 && c2[1] == 0xA0) /* nbsp */
	return S_FALSE;
      else
	return S_TRUE;
    }
  else if (typ == sh_val_utf8_3)
    {
      if (c3[0] == 0xE2) 
	{
	  if (c3[1] == 0x80 && c3[2] >= 0x80 && c3[2] <= 0x8F)
	    return S_FALSE; /* various spaces, left-to-right, right-to-left */
	  else if (c3[1] == 0x80 && (c3[2] == 0xA8 || c3[2] == 0xA9 || 
				     c3[2] == 0xAD || c3[2] == 0xAF))
	    return S_FALSE; /* line sep, para sep, zw word joiner, nnbsp */
	  else if (c3[1] == 0x81 && (c3[2] == 0xA0 || c3[2] == 0xA1 || 
				     c3[2] == 0x9F))
	    return S_FALSE; /* word joiner, function app, math space */
	  else
	    return S_TRUE;
	}
      else if (c3[0] == 0xE3 && c3[1] == 0x80 && c3[2] == 0x80)
	{
	  return S_FALSE; /* ideographic space */
	}
      else if (c3[0] == 0xEF && c3[1] == 0xBB && c3[2] == 0xBF)
	{
	  return S_FALSE; /* zwnbsp */
	}
      else
	{
	  return S_TRUE;
	}
    }
  else
    {
      return S_TRUE;
    }
}


int sh_util_obscure_ok (const char * str)
{
  unsigned long   i;
  char * endptr = NULL;

  SL_ENTER(_("sh_util_obscure_ok"));

  if (0 == sl_strncmp("all", str, 3))
    {
      for (i = 0; i < 255; ++i)
	{
	  sh_obscure_index[i] = (unsigned char)1;
	}
      sh_obscure_no_check = S_TRUE;
      SL_RETURN(0, _("sh_util_obscure_ok"));
    }

  sh_obscure_no_check = S_FALSE;

  for (i = 0; i < 255; ++i)
    {
      sh_obscure_index[i] = (unsigned char)0;
    }

  i = strtoul (str, &endptr, 0);
  if (i > 255)
    {
      SL_RETURN(-1, _("sh_util_obscure_ok"));
    }
  sh_obscure_index[i] = (unsigned char)1;
  if (*endptr == ',')
    ++endptr;

  while (*endptr != '\0')
    {
      i = strtoul (endptr, &endptr, 0);
      if (i > 255)
	{
	  SL_RETURN(-1, _("sh_util_obscure_ok"));
	}
      sh_obscure_index[i] = (unsigned char)1;
      if (*endptr == ',')
	++endptr;
    }
  SL_RETURN(0, _("sh_util_obscure_ok"));
}

static int sh_obscure_check_utf8 = S_FALSE;

int sh_util_obscure_utf8 (const char * c)
{
  int i;
  SL_ENTER(_("sh_util_obscure_utf8"));
  i = sh_util_flagval(c, &(sh_obscure_check_utf8));
  if (sh_obscure_check_utf8 == S_TRUE)
    sh_obscure_no_check = S_FALSE;
  SL_RETURN(i, _("sh_util_obscure_utf8"));
}


int sh_util_obscurename (ShErrLevel level, const char * name_orig, int flag)
{
  const unsigned char * name = (const unsigned char *) name_orig;
  char * safe;
  unsigned int i;
  size_t len = 0;

  SL_ENTER(_("sh_util_obscurename"));

  ASSERT_RET((name != NULL), _("name != NULL"), (0))

  if (sh_obscure_no_check == S_FALSE)
    {
      if (sh_obscure_check_utf8 != S_TRUE)
	{
	  /* -- Check name. --
	   */
	  while (*name != '\0') 
	    {
	      if ( (*name) >  0x7F || (*name) == '"'  || (*name) == '\t' ||
		   (*name) == '\b' || (*name) == '\f' || 
		   (*name) == '\n' || (*name) == '\r' ||
		   (*name) == '\v' || iscntrl((int) *name) || 
		   ((*name) != ' ' && !isgraph ((int) *name)) ) 
		{
		  i = (unsigned char) *name;
		  if (sh_obscure_index[i] != (unsigned char)1)
		    {
		      goto err;
		    }
		}
	      name++; ++len;
	    }

	  /* Check for blank at end of name
	   */
	  if ((len > 0) && (name_orig[len-1] == ' '))
	    {
	      goto err;
	    }
	}
      else
	{
	  if (S_FALSE == sh_util_valid_utf8(name))
	    {
	      goto err;
	    }
	  SL_RETURN((0),_("sh_util_obscurename"));
	}
    }
      
  SL_RETURN((0),_("sh_util_obscurename"));

 err:
  
  if (flag == S_TRUE)
    {
      safe = sh_util_safe_name (name_orig);  
      sh_error_handle (level, FIL__, __LINE__, 0, MSG_FI_OBSC, 
		       safe);
      SH_FREE(safe);
    }
  SL_RETURN((-1),_("sh_util_obscurename"));
}

#endif

/* returns freshly allocated memory, return value should be free'd
 */
char * sh_util_dirname(const char * fullpath)
{
  char * retval;
  size_t len;
  char * tmp;

  SL_ENTER(_("sh_util_dirname"));

  ASSERT_RET ((fullpath != NULL), _("fullpath != NULL"), (NULL))
  ASSERT_RET ((*fullpath == '/'), _("*fullpath == '/'"), (NULL))

  retval = sh_util_strdup(fullpath);

  tmp    = retval;
  while (*tmp == '/') ++tmp;

  /* (1) only leading slashes -- return exact copy 
   */
  if (*tmp == '\0')
    {
      SL_RETURN(retval, _("sh_util_dirname"));
    }

  /* (2) there are non-slash characters, so delete trailing slashes
   */
  len    = sl_strlen (retval);     /* retval[len] is terminating '\0' */

  while (len > 1 && retval[len-1] == '/')    /* delete trailing slash */
    {
      retval[len-1] = '\0';
      --len;
    }

  /* (3) now delete all non-slash characters up to the preceding slash
   */
  while (len > 1 && retval[len-1] != '/') {
    retval[len-1] = '\0';
    --len;
  }

  /* (4a) only leading slashes left, so return this
   */
  if (&(retval[len]) == tmp)
    {
      SL_RETURN(retval, _("sh_util_dirname"));
    }

  /* (4b) strip trailing slash(es) of parent directory
   */
  while (len > 1 && retval[len-1] == '/') {
    retval[len-1] = '\0';
    --len;
  }
  SL_RETURN(retval, _("sh_util_dirname"));

}

/* returns freshly allocated memory, return value should be free'd
 */
char * sh_util_basename(const char * fullpath)
{
  char       * retval = NULL;
  const char * tmp;
  char       * tmp2;
  char       * c;
  size_t       len;

  SL_ENTER(_("sh_util_basename"));

  ASSERT_RET ((fullpath != NULL), _("fullpath != NULL"), (NULL))

  tmp = fullpath; while (*tmp == '/') ++tmp;
  if (*tmp == '\0')
    {
      retval = sh_util_strdup(fullpath);
    }
  else
    {
      tmp2 = sh_util_strdup(tmp);
      len  = sl_strlen (tmp2);

      while (len > 1 && tmp2[len-1] == '/')
	{
	  tmp2[len-1] = '\0';
	  --len;
	}

      if (tmp2) /* for llvm/clang analyzer */
	{
	  c = strrchr(tmp2, '/');
	  if (c)
	    {
	      retval = sh_util_strdup(++c);
	      SH_FREE(tmp2);
	    }
	  else
	    {
	      retval = tmp2;
	    }
	}
    }

  SL_RETURN(retval, _("sh_util_basename"));
}

#define SH_ESCAPE_SPACE      1
#define SH_DONT_ESCAPE_SPACE 0    
char * sh_util_safe_name_int (const char * name, int escape_space);

char * sh_util_safe_name (const char * name)
{
  return sh_util_safe_name_int (name, SH_ESCAPE_SPACE); 
}

char * sh_util_safe_name_keepspace (const char * name)
{
  return sh_util_safe_name_int (name, SH_DONT_ESCAPE_SPACE); 
}

/* returns freshly allocated memory, return value should be free'd
 */
char * sh_util_safe_name_int (const char * name, int escape_space)
{
  register int  i = 0;
  const char  * p;
  char        * retval;
  char          oct[32];
  char          format[16];
  size_t        len;

  SL_ENTER(_("sh_util_safe_name"));

  if (name == NULL)
    {
      /* return an allocated array
       */
      retval = SH_ALLOC(7);
      (void) sl_strlcpy(retval, _("(null)"), 7);
      SL_RETURN(retval, _("sh_util_safe_name"));
    }

  /*
  ASSERT_RET ((name != NULL), _("name != NULL"), _("NULL"))
  */

  len = sl_strlen(name);
  p   = name;

#ifdef SH_USE_XML
  if (sl_ok_muls (6, len) && sl_ok_adds ((6*len), 2))
    { retval = SH_ALLOC(6 * len + 2); }
  else
    {
      /* return an allocated array
       */
      retval = SH_ALLOC(11);
      (void) sl_strlcpy(retval, _("(overflow)"), 11);
      SL_RETURN(retval, _("sh_util_safe_name"));
    }
#else
  if (sl_ok_muls (4, len) && sl_ok_adds ((4*len), 2))
    { retval = SH_ALLOC(4 * len + 2); }
  else
    {
      /* return an allocated array
       */
      retval = SH_ALLOC(11);
      (void) sl_strlcpy(retval, _("(overflow)"), 11);
      SL_RETURN(retval, _("sh_util_safe_name"));
    }
#endif 

  (void) sl_strncpy(format, _("%c%03o"), 16);

  while (*p != '\0') {
    /* Most frequent cases first
     */
    if ( ((*p) >= 'a' && (*p) <= 'z')  || ((*p) == '/') || ((*p) == '.') ||
	 ((*p) >= '0' && (*p) <= '9')  || 
	 ((*p) >= 'A' && (*p) <= 'Z')) {
      retval[i] = *p; 
    } else if ( (*p) == '\\') {           /* backslash        */
      retval[i] = '\\'; ++i; 
      retval[i] = '\\';
    } else if ( (*p) == '\n') {    /* newline          */
      retval[i] = '\\'; ++i; 
      retval[i] = 'n';
    } else if ( (*p) == '\b') {    /* backspace        */
      retval[i] = '\\'; ++i; 
      retval[i] = 'b';
    } else if ( (*p) == '\r') {    /* carriage  return */
      retval[i] = '\\'; ++i; 
      retval[i] = 'r';
    } else if ( (*p) == '\t') {    /* horizontal tab   */
      retval[i] = '\\'; ++i; 
      retval[i] = 't';
    } else if ( (*p) == '\v') {    /* vertical tab     */
      retval[i] = '\\'; ++i; 
      retval[i] = 'v';
    } else if ( (*p) == '\f') {    /* form-feed        */
      retval[i] = '\\'; ++i; 
      retval[i] = 'f';
#ifdef WITH_DATABASE
    } else if ( (*p) == '\'') {    /* single quote     */
      retval[i] = '\\'; ++i; 
      retval[i] = '\'';
#endif
    } else if ( (*p) == ' ') {     /* space            */
      if (escape_space) {
	retval[i] = '\\'; ++i; 
	retval[i] = ' ';
      }
      else {
	retval[i] = *p;
      }
#ifdef SH_USE_XML
    } else if ( (*p) == '"') {     /* double quote     */
      retval[i] = '&'; ++i; 
      retval[i] = 'q'; ++i;
      retval[i] = 'u'; ++i;
      retval[i] = 'o'; ++i;
      retval[i] = 't'; ++i;
      retval[i] = ';';
    } else if ( (*p) == '&') {     /* ampersand        */
      retval[i] = '&'; ++i; 
      retval[i] = 'a'; ++i;
      retval[i] = 'm'; ++i;
      retval[i] = 'p'; ++i;
      retval[i] = ';';
    } else if ( (*p) == '<') {     /* left angle       */
      retval[i] = '&'; ++i; 
      retval[i] = 'l'; ++i;
      retval[i] = 't'; ++i;
      retval[i] = ';';
    } else if ( (*p) == '>') {     /* right angle      */
      retval[i] = '&'; ++i; 
      retval[i] = 'g'; ++i;
      retval[i] = 't'; ++i;
      retval[i] = ';';
#else
    } else if ( (*p) == '"') {     /* double quote     */
      retval[i] = '\\'; ++i; 
      retval[i] = '\"';
#endif
    } else if (!isgraph ((int) *p)) {    /* not printable    */
      /*@-bufferoverflowhigh -formatconst@*/
      /* flawfinder: ignore */
      sprintf(oct, format, '\\',                 /* known to fit  */
	      (unsigned char) *p);
      /*@+bufferoverflowhigh +formatconst@*/
      retval[i] = oct[0]; ++i;
      retval[i] = oct[1]; ++i;
      retval[i] = oct[2]; ++i;
      retval[i] = oct[3]; 
    } else {
      retval[i] = *p;
    }
    ++p;
    ++i;
  }
  retval[i] = '\0';
  SL_RETURN(retval, _("sh_util_safe_name"));
}

int sh_util_isnum (const char *str)
{
  const char *p = str;

  SL_ENTER(_("sh_util_isnum"));

  ASSERT_RET ((str != NULL), _("str != NULL"), (-1))

  while (p) {
    if (!isdigit((int) *p) ) 
      SL_RETURN((-1), _("sh_util_isnum"));
    ++p;
  }
  SL_RETURN((0), _("sh_util_isnum"));
}

char * sh_util_strconcat (const char * arg1, ...)
{
  size_t    length, l2;
  char    * s;
  char    * strnew;
  va_list vl;

  SL_ENTER(_("sh_util_strconcat"));

  ASSERT_RET ((arg1 != NULL), _("arg1 != NULL"), (NULL))

  length = sl_strlen (arg1) + 1;

  va_start (vl, arg1);
  s = va_arg (vl, char * );
  while (s != NULL)
    {
      l2 = sl_strlen (s);
      if (sl_ok_adds(length, l2))
	length += l2;
      else
	SL_RETURN(NULL, _("sh_util_strconcat"));
      s = va_arg (vl, char * );
    }
  va_end (vl);

  if (sl_ok_adds(length, 2))
    strnew = SH_ALLOC( length + 2 );
  else
    SL_RETURN(NULL, _("sh_util_strconcat"));

  strnew[0] = '\0';

  (void) sl_strlcpy (strnew, arg1, length + 2); 

  va_start (vl, arg1);
  s = va_arg (vl, char * );
  while (s)
    {
      (void) sl_strlcat (strnew, s, length + 2);
      s = va_arg (vl, char * );
    }
  va_end (vl);

  SL_RETURN(strnew, _("sh_util_strconcat"));
}

static const char bto64_0[] = N_("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()");
static char bto64[65] = { '\0' };

  
size_t sh_util_base64_enc (unsigned char * out, 
			   const unsigned char * instr, 
			   size_t lin)
{
  int             ll;
  unsigned char   a, b, c;
  size_t          len  = 0;
  size_t          j    = 0;

 start:
  if (bto64[0] != '\0')
    {
      if (instr /* && *instr *//* need to handle binary data */)
	{
	  if (lin == 0)
	    lin = strlen((const char *)instr);

	  if (lin > 0)
	    {
	      do {
		ll = 0;
		
		if (len < lin) 
		  { a = *instr; ++instr; ++len; ++ll; }
		else 
		  { a = 0; }
		if (len < lin) 
		  { b = *instr; ++instr; ++len; ++ll; }
		else 
		  { b = 0; }
		if (len < lin) 
		  { c = *instr; ++instr; ++len; ++ll; }
		else 
		  { c = 0; }
		
		*out = bto64[ a >> 2 ];
		++j; ++out;
		*out = bto64[ ((a & 0x03) << 4) | ((b & 0xf0) >> 4) ];
		++j; ++out;
		*out = (unsigned char) (ll > 1 ? bto64[ ((b & 0x0f) << 2) | ((c & 0xc0) >> 6) ] : '?');
		++j; ++out;
		*out = (unsigned char) (ll > 2 ? bto64[ c & 0x3f ] : '?');
		++j; ++out;
	      } while (len < lin);
	    }
	}
      *out = '\0';
      return j;
    }

  memcpy(bto64, _(bto64_0), 65);
  goto start;
}

size_t sh_util_base64_enc_alloc (char **out, const char *in, size_t inlen)
{
  size_t outlen = SH_B64_SIZ(inlen);

  if (inlen > outlen) /* overflow */
    {
      *out = NULL;
      return 0;
    }

  *out = SH_ALLOC(outlen);
  return sh_util_base64_enc((unsigned char *)*out, (const unsigned char *)in, inlen);
}

size_t sh_util_base64_dec (unsigned char *out, 
			   const unsigned char *in, 
			   size_t lin)
{
  size_t i;
  unsigned char c;
  unsigned char b;
  size_t lout = 0;
  unsigned int  w = 0;

  if (out && in)
    {
      if (lin == 0)
	lin = strlen((const char *)in);

      for (i = 0; i < lin; i++)
	{
	  c = *in; ++in;
	  b = 0;
	  
	  if ((c >= 'A') && (c <= 'Z'))
	    {
	      b = (c - 'A');
	    }
	  else if ((c >= 'a') && (c <= 'z'))
	    {
	      b = (c - 'a' + 26);
	    }
	  else if ((c >= '0') && (c <= '9'))
	    {
	      b = (c - '0' + 52);
	    }
	  else if (c == '(' || c == '+')
	    {
	      b = 62;
	    }
	  else if (c == ')' || c == '/')
	    {
	      b = 63;
	    }
	  else if (c == '?' || c == '=')
	    {
	      /* last byte was written to, but will now get
	       * truncated
	       */
	      if (lout > 0) --lout;
	      break;
	    }
	  
	  if (w == 0)
	    {
	      *out = (b << 2) & 0xfc;
	      ++lout;
	    }
	  else if (w == 1)
	    {
	      *out |= (b >> 4) & 0x03;
	      ++out;
	      *out = (b << 4) & 0xf0;
	      ++lout;
	    }
	  else if (w == 2)
	    {
	      *out |= (b >> 2) & 0x0f;
	      ++out;
	      *out = (b << 6) & 0xc0;
	      ++lout;
	    }
	  else if (w == 3)
	    {
	      *out |= b & 0x3f;
	      ++out;
	    }
	  
	  ++w;
	  
	  if (w == 4)
	    {
	      w = 0;
	    }
	}
      *out = '\0';
    }
  return lout;
}

size_t sh_util_base64_dec_alloc (unsigned char **out, const unsigned char *in, 
				 size_t lin)
{
  size_t lout = 3 * (lin / 4) + 2;

  *out = SH_ALLOC(lout);

  return sh_util_base64_dec (*out, in, lin);
}


#ifdef HAVE_REGEX_H

#include <regex.h>

int sh_util_regcmp (char * regex_str, char * in_str)
{
#if defined(REG_ESPACE)
  int        status = REG_ESPACE;
#else
  int        status = -1;
#endif
  regex_t    preg;
  char     * errbuf;

  SL_ENTER(_("sh_util_regcmp"));

  status = regcomp(&preg, regex_str, REG_NOSUB|REG_EXTENDED);

  if (status == 0)
    {
      if ((status = regexec(&preg, in_str, 0, NULL, 0)) == 0) 
	{
	  regfree (&preg);
	  SL_RETURN((0), _("sh_util_regcmp"));
	}
    }

  if (status != 0 && status != REG_NOMATCH) 
    {
      errbuf = SH_ALLOC(BUFSIZ);
      (void) regerror(status, &preg, errbuf, BUFSIZ); 
      errbuf[BUFSIZ-1] = '\0';
      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_E_REGEX,
		       errbuf, regex_str);
      SH_FREE(errbuf);
    }
	
  regfree (&preg);
  SL_RETURN((-1), _("sh_util_regcmp"));
}

#endif








