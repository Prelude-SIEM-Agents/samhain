/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999 Rainer Wichmann                                      */
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


#ifndef SH_UTILS_H
#define SH_UTILS_H

#include <stdarg.h>

#include "slib.h"

#include "sh_error.h"
#include "sh_unix.h"

#define S_FMT_STRING   1
#define S_FMT_ULONG    2
#define S_FMT_TIME     3
#define S_FMT_LONG     4


typedef struct ft_struc {
  char            fchar;
  int             type;
  unsigned long   data_ulong;
  long            data_long;
  char           *data_str;
} st_format;

/* returns allocated string
 */
char * sh_util_formatted (const char * fmt, st_format * ftab);

typedef struct sh_timeout_struct {
  UINT64   time_last;
  UINT64   time_dist;
  int      flag_ok;
} SH_TIMEOUT;

int sh_util_timeout_check (SH_TIMEOUT * sh_timer);

/*  This is a maximally equidistributed combined Tausworthe
 *  generator. 
 */
UINT32 taus_get            (void);  
double taus_get_double     (void *vstate);  /* fast */
int    taus_seed           (void);

/* returns allocated memory
 */
char * sh_util_strdup (const char * str) SH_GNUC_MALLOC;
char * sh_util_strdup_track (const char * str, 
			     char * file, int line) SH_GNUC_MALLOC;

/* returns allocated memory
 */
char * sh_util_strdup_l (const char * str, size_t len) SH_GNUC_MALLOC;

/* returns pointer within str
 */
char * sh_util_strsep (char **str, const char *delim);

/* compactify verbose acl text, returns allocated memory
 */
char * sh_util_acl_compact (char * buf, ssize_t len);

/* set signature type HASH-TIGER/HMAC-TIGER
 */
int sh_util_sigtype (const char * c);

/* compute a signature
 */
char * sh_util_siggen (char * hexkey,  
		       char * text, size_t textlen, 
		       char * sigbuf, size_t sigbuflen);

/* eval boolean input
 */
int sh_util_flagval(const char * c, int * fval);

/* ask if a file should be updated (returns S_TRUE/S_FALSE)
 */
int sh_util_ask_update(const char * path);
int sh_util_set_interactive(const char * str);
int sh_util_update_file (const char * str);

/* don't log output files
 */
int sh_util_hidesetup(const char * c);

/* valif utf-8 string
 */
int sh_util_valid_utf8 (const unsigned char * str);

/* filenames are utf8
 */
int sh_util_obscure_utf8 (const char * c);

/* exceptions to obscure name check
 */
int sh_util_obscure_ok (const char * str);

/* output a hexchar[2]; i2h must be char[2]
 */
char * sh_util_charhex( unsigned char c, char * i2h );

/* read a hexchar, return int value (0-15)
 */
int sh_util_hexchar( char c ) SH_GNUC_CONST;

/* change verifier 
 */
int sh_util_set_newkey (const char * str);

/* server mode 
 */
int sh_util_setserver (const char * dummy);

/* a simple compressor
 */
size_t sh_util_compress (char * dest, char * src, size_t dest_size);

/* an even simpler en-/decoder 
 */
void sh_util_encode (char * data, char * salt, int mode, char fill);

/* copy len ( < 4) bytes from (char *) (long src) to (char *) dest,
 * determine the four LSB's and use them (independent of sizeof(long))
 */
void sh_util_cpylong (char * dest, const char * src, int len );

/* set timer for main loop
 */
int sh_util_setlooptime (const char * str);

/* whether init or check the database
 */
int  sh_util_setchecksum (const char * str);

/* compare an in_string against a regular expression regex_str
   return GOOD on successful match
*/
int sh_util_regcmp (char * regex_str, char * in_str);


/* returns freshly allocated memory, return value should be free'd.
 * Argument list must be NULL terminated.
 */
char * sh_util_strconcat (const char * arg1, ...) SH_GNUC_MALLOC SH_GNUC_SENTINEL;

/* check if string is numeric only
 */
int sh_util_isnum (const char *str) SH_GNUC_PURE;

/* init a key w/random string
 */
int sh_util_keyinit (char * buf, long size);


/* returns freshly allocated memory, return value should be free'd
 */
char * sh_util_dirname(const char * fullpath);

/* returns freshly allocated memory, return value should be free'd
 */
char * sh_util_safe_name (const char * name) SH_GNUC_MALLOC SH_GNUC_PURE;

char * sh_util_safe_name_keepspace (const char * name) SH_GNUC_MALLOC SH_GNUC_PURE;

/* check max size of printf result string
 */
int sh_util_printf_maxlength (const char * fmt, va_list  vl);

/* check for obscure filenames
 */
int sh_util_obscurename (ShErrLevel level, const char * name, int flag);

/* returns freshly allocated memory, return value should be free'd
 */
char * sh_util_basename(const char * fullpath);

/* required size (including terminating NULL) for string of strlen l
 */
#define SH_B64_SIZ(l)  (1 + ((((l) + 2) / 3) * 4))

/* return len of encoded string
 */
size_t sh_util_base64_enc (unsigned char * out, const unsigned char * instr, 
			   size_t lin);

/* return allocated encoded string in out, return its len
 */
size_t sh_util_base64_enc_alloc (char **out, const char *in, size_t inlen);

/* return len of decoded string
 */  
size_t sh_util_base64_dec (unsigned char *out, const unsigned char *in, size_t lin);

/* return allocated decoded string in out, return its len
 */  
size_t sh_util_base64_dec_alloc (unsigned char **out, const unsigned char *in, size_t lin);

#endif
