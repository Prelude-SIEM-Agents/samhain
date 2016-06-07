#include "config_xor.h"

#define USE_MD5
#define USE_SHA1

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
#include <sys/mman.h>
#endif

#include "sh_tiger.h"

#include "sh_unix.h"
#include "sh_error.h"
#include "sh_utils.h"
#include "sh_pthread.h"
#include "sh_string.h"

#define PRIV_MAX  32768

#if defined(TIGER_64_BIT)
#if defined(HAVE_LONG_64)
typedef unsigned long int word64;
#elif defined(HAVE_LONG_LONG_64)
typedef unsigned long long int word64;
#else
#error No 64 bit type found !
#endif
#endif

#if defined(HAVE_INT_32)
typedef unsigned int sh_word32;
#define MYFORMAT   (_("%08X%08X%08X%08X%08X%08X"))
#define GPGFORMAT (_("%08X %08X %08X  %08X %08X %08X"))
#elif defined(HAVE_LONG_32)
typedef unsigned long sh_word32;
#define MYFORMAT   (_("%08lX%08lX%08lX%08lX%08lX%08lX"))
#define GPGFORMAT (_("%08lX %08lX %08lX  %08lX %08lX %08lX"))
#elif defined(HAVE_SHORT_32)
typedef unsigned short sh_word32;
#define MYFORMAT   (_("%08X%08X%08X%08X%08X%08X"))
#define GPGFORMAT (_("%08X %08X %08X  %08X %08X %08X"))
#else
#error No 32 bit type found !
#endif

#if defined(__GNUC__) && (__GNUC__ >= 3)
#undef  SH_GNUC_ALIGN8
#define SH_GNUC_ALIGN8   __attribute__((aligned(8)))
#else
#undef  SH_GNUC_ALIGN8
#define SH_GNUC_ALIGN8
#endif


typedef unsigned char sh_byte;

#define SH_KEY_NULL _("000000000000000000000000000000000000000000000000")

#undef  FIL__
#define FIL__  _("sh_tiger0.c")

#if defined(TIGER_64_BIT)

void tiger_t(const word64 *str, word64 length, word64 * res);
void tiger(const word64 *str, word64 length, word64 * res);

#ifdef TIGER_DBG
static void tiger_dbg(word64 res[3], int step, 
		      unsigned long nblocks, unsigned long ncount)
{
  return;
}
#endif
#else
void tiger(const sh_word32 *str, sh_word32 length, sh_word32 * res);
void tiger_t(const sh_word32 *str, sh_word32 length, sh_word32 * res);

#ifdef TIGER_DBG
static 
void tiger_dbg(sh_word32 res[6], int step, 
	       unsigned long nblocks, unsigned long ncount)
{
    fprintf(stderr,                                     
            _("ST %d BLK %2ld CT %2ld %08lX %08lX %08lX %08lX %08lX %08lX\n"),
	    step,
	    nblocks,
	    ncount,
            (sh_word32)(res[1]), 
            (sh_word32)(res[0]), 
            (sh_word32)(res[3]), 
            (sh_word32)(res[2]), 
            (sh_word32)(res[5]), 
            (sh_word32)(res[4]) );
}
#endif
#endif

/* this is the wrapper function -- not part of the tiger reference
 * implementation
 */

/* static sh_byte buffer[PRIV_MAX + 72]; */

#if defined(TIGER_64_BIT)
static
word64 * sh_tiger_hash_val (const char * filename, TigerType what, 
			    UINT64 * Length, int timeout, word64 * res)
#else
static
sh_word32 * sh_tiger_hash_val (const char * filename, TigerType what, 
			       UINT64 * Length, int timeout, sh_word32 * res)
#endif
{
  SL_TICKET  fd;
  sh_string * content = NULL;
  int  i, j, tt;
  int  count = 0;
  int  blk;
  char    * tmp;
  sh_byte * bptr;
  sh_byte   SH_GNUC_ALIGN8 bbuf[64];
  UINT64    bcount = 0;

  sh_byte * buffer = SH_ALLOC(PRIV_MAX + 72);

  unsigned long pages_read;
  uid_t   euid;

  unsigned long ncount = 0, nblocks = 0;
  unsigned long  t, msb, lsb;

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)
  /*@-nestedextern@*/
  extern long IO_Limit;
  /*@+nestedextern@*/
#endif

#if defined(TIGER_64_BIT)
#define TIGER_CAST (const word64*)
  /* word64 res[3]; */
  res[0]= (word64) 0x0123456789ABCDEFLL;
  res[1]= (word64) 0xFEDCBA9876543210LL;
  res[2]= (word64) 0xF096A5B4C3B2E187LL;
#else
#define TIGER_CAST (const sh_word32*)
  /* sh_word32 res[6]; */
  res[0]= (sh_word32) 0x89ABCDEF;
  res[1]= (sh_word32) 0x01234567;
  res[2]= (sh_word32) 0x76543210;
  res[3]= (sh_word32) 0xFEDCBA98;
  res[4]= (sh_word32) 0xC3B2E187;
  res[5]= (sh_word32) 0xF096A5B4;
#endif

  SL_ENTER(_("sh_tiger_hash_val"));

  if (what >= TIGER_FILE) 
    {
      if (what > TIGER_FILE)
	{
	  fd      = what;
	  content = sl_get_content(fd);
	  TPT((0,FIL__, __LINE__, _("msg=<TIGER_FD>, fd=<%ld>\n"), fd));
	}
      else
	{
	  TPT((0,FIL__, __LINE__, _("msg=<TIGER_FILE>, path=<%s>\n"),
	       (filename == NULL ? _("(null)") : filename) ));
	  fd = sl_open_read (FIL__, __LINE__, filename, SL_YESPRIV);
	}

      if (SL_ISERROR (fd)) 
	{
	  TPT((0, FIL__, __LINE__, _("msg=<SL_ISERROR (%ld)>\n"), fd));
	  tmp = sh_util_safe_name (filename);
	  (void) sl_get_euid(&euid);
	  sh_error_handle (ShDFLevel[SH_ERR_T_FILE], FIL__, __LINE__, (int)fd,
			   MSG_E_ACCESS, (long) euid, tmp);
	  SH_FREE(tmp);
	  SH_FREE(buffer);
	  *Length = 0;
	  SL_RETURN( NULL, _("sh_tiger_hash_val"));
	}

#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
    if (skey->mlock_failed == S_FALSE) 
      {
        if ( (-1) == sh_unix_mlock(FIL__, __LINE__, 
				   (char *)buffer, 
				   (PRIV_MAX)*sizeof(sh_byte))) 
	  {
	    SH_MUTEX_LOCK_UNSAFE(mutex_skey);  
	    skey->mlock_failed = S_TRUE;
	    SH_MUTEX_UNLOCK_UNSAFE(mutex_skey);
	  }
      }
#else
    if (skey->mlock_failed == S_FALSE)
      {
	SH_MUTEX_LOCK_UNSAFE(mutex_skey);  
	skey->mlock_failed = S_TRUE;
	SH_MUTEX_UNLOCK_UNSAFE(mutex_skey);
      }
#endif

#ifdef TIGER_DBG
    tiger_dbg (res, 0, nblocks, ncount);
#endif

    pages_read = 0;

    while (1) 
      {
	if (timeout > 0)
	  count = sl_read_timeout (fd, buffer, PRIV_MAX, timeout, S_TRUE);
	else
	  count = sl_read         (fd, buffer, PRIV_MAX);

	++pages_read;

	if (SL_ISERROR (count)) 
	  {
	    int error = errno;

	    if (sig_termfast == 1) {
	      sh_unix_munlock((char *)buffer, (PRIV_MAX)*sizeof(sh_byte));
	      SH_FREE(buffer);
	      *Length = 0;
	      SL_RETURN( NULL, _("sh_tiger_hash_val"));
	    }
	    TPT((0, FIL__ , __LINE__ , _("msg=<SL_ISERROR (%ld)>\n"), count)); 
	    tmp = sh_util_safe_name (filename);
	    if (count == SL_TIMEOUT)
	      {
		if (timeout != 7) {
		  sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, count, 
				   MSG_E_TIMEOUT, timeout, tmp);
		}
	      }
	    else
	      {
		char errbuf[SH_ERRBUF_SIZE];
		char errbuf2[SH_ERRBUF_SIZE];
		sl_strlcpy(errbuf, sl_error_string(count), sizeof(errbuf));
		sh_error_message(error, errbuf2, sizeof(errbuf2));
		sh_error_handle (ShDFLevel[SH_ERR_T_FILE], FIL__, __LINE__, 
				 count, MSG_E_READ, errbuf, errbuf2, tmp);
	      }
	    SH_FREE(tmp);
	    memset (bbuf,   0, 64);
	    memset (buffer, 0, PRIV_MAX);

	    sh_unix_munlock((char *)buffer, (PRIV_MAX)*sizeof(sh_byte));
	    SH_FREE(buffer);
	    *Length = 0;
	    SL_RETURN( NULL, _("sh_tiger_hash_val"));
	  }

	if (content)
	  sh_string_cat_lchar(content, (char*)buffer, count);

	bcount += count;

	if (*Length != TIGER_NOLIM)
	  {
	    if (bcount > *Length)
	      {
		count   = count - (bcount - (*Length));
		bcount  = *Length;
		count = (count < 0) ? 0 : count;
	      }
	  }

	blk      = (count / 64); /* number of 64-byte words */

	/* nblocks += blk; number of 64-byte words 
	 * count cannot be negative here, see 'if (SL_ISERROR (count))'
	 */
	tt = blk*64;

	ncount = (unsigned long) (count - tt);

	nblocks += blk;
	/* MAY_LOCK */
	sh.statistics.bytes_hashed += tt;
	
	tt = 0;
	for (i = 0; i < blk; ++i)
	  {
	    bptr = &buffer[tt]; tt += 64;
	    
	    tiger_t(TIGER_CAST bptr, 64, res);
	    
#ifdef TIGER_DBG
	    tiger_dbg (res, 3, nblocks, ncount);
#endif
	  }
	
	if (blk < (PRIV_MAX / 64)) /* this must be (PRIV_MAX / 64) */
	  break;

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
	if (sig_termfast == 1) 
	  {
	    memset (bbuf,   0, 64);
	    memset (buffer, 0, PRIV_MAX);
	    sh_unix_munlock((char *)buffer, (PRIV_MAX)*sizeof(sh_byte));
	    SH_FREE(buffer);
	    *Length = 0;
	    SL_RETURN( NULL, _("sh_tiger_hash_val"));
	  }
	if ((IO_Limit) > 0 && (pages_read == 32)) /* check for I/O limit */
	  {
	    sh_unix_io_pause ();
	    pages_read = 0;
	  }
#endif 
      }

    TPT((0, FIL__, __LINE__ , _("msg=<Last block.>\n")));

    /* copy incomplete block
     */
    j = 0; 
    for (i = 0; i < 64; i += 4) 
      {
	bbuf[i]   = (sh_byte) '\0';
	bbuf[i+1] = (sh_byte) '\0';
	bbuf[i+2] = (sh_byte) '\0';
	bbuf[i+3] = (sh_byte) '\0';
      }
    for (i = (count/64) * 64; i < count; ++i)
      /*@-usedef@*/bbuf[j++] = buffer[i];/*@+usedef@*/

#ifdef TIGER_DBG
    tiger_dbg (res, 5, nblocks, ncount);
#endif

    msb = 0;
    t = nblocks;
    if( (lsb = t << 6) < t )    
      msb++;
    msb += t >> 26;
    t = lsb;
    if( (lsb = t + ncount) < t ) 
      msb++;
    t = lsb;
    if( (lsb = t << 3) < t )    
      msb++;
    msb += t >> 29;

    if( j < 56 ) 
      { 
        bbuf[j++] = (sh_byte) 0x01; ++ncount;
        while( j < 56 )
	  { bbuf[j++] = (sh_byte) 0; ++ncount; } 
      }
    else 
      { 
        bbuf[j++] = (sh_byte) 0x01;
        while( j < 64 )
	  bbuf[j++] = (sh_byte) 0;
	tiger_t(TIGER_CAST bbuf, 64, res);
	/* MAY_LOCK */
	sh.statistics.bytes_hashed += 64;
	++nblocks; 
#ifdef TIGER_DBG
	ncount = 0;
#endif
        sl_memset(bbuf, 0, 56 ); 
      }

#ifdef TIGER_DBG
    tiger_dbg (res, 6, nblocks, ncount);
#endif

    bbuf[56] = (sh_byte) (lsb      );
    bbuf[57] = (sh_byte) (lsb >>  8);
    bbuf[58] = (sh_byte) (lsb >> 16);
    bbuf[59] = (sh_byte) (lsb >> 24);
    bbuf[60] = (sh_byte) (msb      );
    bbuf[61] = (sh_byte) (msb >>  8);
    bbuf[62] = (sh_byte) (msb >> 16);
    bbuf[63] = (sh_byte) (msb >> 24);

    tiger_t(TIGER_CAST bbuf, 64, res);
    sh.statistics.bytes_hashed += 64;
    
#ifdef TIGER_DBG
    tiger_dbg (res, 7, nblocks, ncount);
#endif

    sl_memset (bbuf,   '\0', sizeof(bbuf));
    sl_memset (buffer, '\0', sizeof(buffer));

    if (what == TIGER_FILE)
      (void) sl_close (fd);
    sh_unix_munlock((char *)buffer, (PRIV_MAX)*sizeof(sh_byte));
    SH_FREE(buffer);
    *Length = bcount;
    SL_RETURN( res, _("sh_tiger_hash_val"));
  }

  if (what == TIGER_DATA && filename != NULL) 
    {
      tiger(TIGER_CAST filename, (sh_word32) *Length, res);
      sh_unix_munlock((char *)buffer, (PRIV_MAX)*sizeof(sh_byte));
      SH_FREE(buffer);
      SL_RETURN(res, _("sh_tiger_hash_val"));
    }
  sh_unix_munlock((char *)buffer, (PRIV_MAX)*sizeof(sh_byte));
  SH_FREE(buffer);
  *Length = 0;
  SL_RETURN( NULL, _("sh_tiger_hash_val"));
}

/* Thu Oct 18 18:53:33 CEST 2001
 */

#ifdef USE_MD5
/*@-type@*/
/* md5.c - Functions to compute MD5 message digest of files or memory blocks
 *         according to the definition of MD5 in RFC 1321 from April 1992.
 * Copyright (C) 1995, 1996 Free Software Foundation, Inc.
 *
 * NOTE: The canonical source of this file is maintained with the GNU C
 * Library.  Bugs can be reported to bug-glibc@prep.ai.mit.edu.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* Written by Ulrich Drepper <drepper@gnu.ai.mit.edu>, 1995.  */

/* Hacked to work with samhain by R. Wichmann             */

typedef UINT32 md5_uint32;


/* Structure to save state of computation between the single steps.  */
typedef struct md5_ctx
{
  md5_uint32 A;
  md5_uint32 B;
  md5_uint32 C;
  md5_uint32 D;

  md5_uint32 total[2];
  md5_uint32 buflen;
  char buffer[128];
} md5Param;

/*
 * The following three functions are build up the low level used in
 * the functions `md5_stream' and `md5_buffer'.
 */

/* Initialize structure containing state of computation.
   (RFC 1321, 3.3: Step 3)  */
static void md5_init_ctx (struct md5_ctx *ctx);

/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is necessary that LEN is a multiple of 64!!! */
static void md5_process_block (const void *buffer, size_t len,
				    struct md5_ctx *ctx);

/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is NOT required that LEN is a multiple of 64.  */
static void md5_process_bytes (const void *buffer, size_t len,
				    struct md5_ctx *ctx);

/* Process the remaining bytes in the buffer and put result from CTX
   in first 16 bytes following RESBUF.  The result is always in little
   endian byte order, so that a byte-wise output yields to the wanted
   ASCII representation of the message digest.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
static void *md5_finish_ctx (struct md5_ctx *ctx, void *resbuf);


/* Put result from CTX in first 16 bytes following RESBUF.  The result is
   always in little endian byte order, so that a byte-wise output yields
   to the wanted ASCII representation of the message digest.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
static void *md5_read_ctx (const struct md5_ctx *ctx, void *resbuf);

#if WORDS_BIGENDIAN
static md5_uint32 swapu32(md5_uint32 n)
{
  return (    ((n & 0xffU) << 24) |
	      ((n & 0xff00U) << 8) |
	      ((n & 0xff0000U) >> 8) |
	      ((n & 0xff000000U) >> 24) );
}
#define SWAP(n) swapu32(n)
#else
#define SWAP(n) (n)
#endif

/* This array contains the bytes used to pad the buffer to the next
   64-byte boundary.  (RFC 1321, 3.1: Step 1)  */
static const unsigned char fillbuf[64] = { 0x80, 0 /* , 0, 0, ...  */  };

/* Initialize structure containing state of computation.
   (RFC 1321, 3.3: Step 3)  */
static void md5_init_ctx(struct md5_ctx *ctx)
{
  ctx->A = 0x67452301;
  ctx->B = 0xefcdab89;
  ctx->C = 0x98badcfe;
  ctx->D = 0x10325476;

  ctx->total[0] = ctx->total[1] = 0;
  ctx->buflen = 0;
}

/* Put result from CTX in first 16 bytes following RESBUF.  The result
   must be in little endian byte order.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
static void *md5_read_ctx(const struct md5_ctx *ctx, void *resbuf)
{
  ((md5_uint32 *) resbuf)[0] = SWAP(ctx->A);
  ((md5_uint32 *) resbuf)[1] = SWAP(ctx->B);
  ((md5_uint32 *) resbuf)[2] = SWAP(ctx->C);
  ((md5_uint32 *) resbuf)[3] = SWAP(ctx->D);

  return resbuf;
}

/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
static void *md5_finish_ctx(struct md5_ctx *ctx, void *resbuf)
{
  /* Take yet unprocessed bytes into account.  */
  md5_uint32 bytes = ctx->buflen;
  size_t pad;
  md5_uint32 temp;

  /* Now count remaining bytes.  */
  ctx->total[0] += bytes;
  if (ctx->total[0] < bytes)
    ++ctx->total[1];

  pad = bytes >= 56 ? 64 + 56 - bytes : 56 - bytes;
  memcpy(&ctx->buffer[bytes], fillbuf, pad);

  /* Put the 64-bit file length in *bits* at the end of the buffer.  */
  temp = SWAP(ctx->total[0] << 3);
  memcpy(&(ctx->buffer[bytes + pad]), &temp, sizeof(temp));
  temp = SWAP((ctx->total[1] << 3) | (ctx->total[0] >> 29));
  memcpy(&(ctx->buffer[bytes + pad + 4]), &temp, sizeof(temp));

  /* Process last bytes.  */
  md5_process_block(ctx->buffer, bytes + pad + 8, ctx);

  return md5_read_ctx(ctx, resbuf);
}

/* Compute MD5 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
void *md5_buffer(const char *buffer, size_t len, void *resblock)
{
  struct md5_ctx ctx;

  /* Initialize the computation context.  */
  md5_init_ctx(&ctx);

  /* Process whole buffer but last len % 64 bytes.  */
  md5_process_bytes(buffer, len, &ctx);

  /* Put result in desired memory area.  */
  return md5_finish_ctx(&ctx, resblock);
}

static void md5_process_bytes(const void *buffer, size_t len, struct md5_ctx *ctx)
{
  /* When we already have some bits in our internal buffer concatenate
     both inputs first.  */
  if (ctx->buflen != 0) {
    size_t left_over = ctx->buflen;
    size_t add = 128 - left_over > len ? len : 128 - left_over;

    memcpy(&ctx->buffer[left_over], buffer, add);
    ctx->buflen += add;

    if (left_over + add > 64) {
      md5_process_block(ctx->buffer, (left_over + add) & ~63, ctx);
      /* The regions in the following copy operation cannot overlap.  */
      memcpy(ctx->buffer, &ctx->buffer[(left_over + add) & ~63],
	     (left_over + add) & 63);
      ctx->buflen = (left_over + add) & 63;
    }

    buffer = (const char *) buffer + add;
    len -= add;
  }

  /* Process available complete blocks.  */
  if (len > 64) {
    md5_process_block(buffer, len & ~63, ctx);
    buffer = (const char *) buffer + (len & ~63);
    len &= 63;
  }

  /* Move remaining bytes in internal buffer.  */
  if (len > 0) {
    memcpy(ctx->buffer, buffer, len);
    ctx->buflen = len;
  }
}

/* These are the four functions used in the four steps of the MD5 algorithm
   and defined in the RFC 1321.  The first function is a little bit optimized
   (as found in Colin Plumbs public domain implementation).  */
/* #define FF(b, c, d) ((b & c) | (~b & d)) */
#define FF(b, c, d) (d ^ (b & (c ^ d)))
#define FG(b, c, d) FF (d, b, c)
#define FH(b, c, d) (b ^ c ^ d)
#define FI(b, c, d) (c ^ (b | ~d))

/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 64 == 0.  */
static void md5_process_block(const void *buffer, size_t len, struct md5_ctx *ctx)
{
  md5_uint32 correct_words[16];
  const md5_uint32 *words = buffer;
  size_t nwords = len / sizeof(md5_uint32);
  const md5_uint32 *endp = words + nwords;
  md5_uint32 A = ctx->A;
  md5_uint32 B = ctx->B;
  md5_uint32 C = ctx->C;
  md5_uint32 D = ctx->D;

  /* First increment the byte count.  RFC 1321 specifies the possible
     length of the file up to 2^64 bits.  Here we only compute the
     number of bytes.  Do a double word increment.  */
  ctx->total[0] += len;
  if (ctx->total[0] < len)
    ++ctx->total[1];

  /* Process all bytes in the buffer with 64 bytes in each round of
     the loop.  */
  while (words < endp) {
    md5_uint32 *cwp = correct_words;
    md5_uint32 A_save = A;
    md5_uint32 B_save = B;
    md5_uint32 C_save = C;
    md5_uint32 D_save = D;

    /* First round: using the given function, the context and a constant
       the next context is computed.  Because the algorithms processing
       unit is a 32-bit word and it is determined to work on words in
       little endian byte order we perhaps have to change the byte order
       before the computation.  To reduce the work for the next steps
       we store the swapped words in the array CORRECT_WORDS.  */

#define OP(a, b, c, d, s, T)						\
      do								\
        {								\
	  a += FF (b, c, d) + (*cwp++ = SWAP (*words)) + T;		\
	  ++words;							\
	  CYCLIC (a, s);						\
	  a += b;							\
        }								\
      while (0)

    /* It is unfortunate that C does not provide an operator for
       cyclic rotation.  Hope the C compiler is smart enough.  */
#define CYCLIC(w, s) (w = (w << s) | (w >> (32 - s)))

    /* Before we start, one word to the strange constants.
       They are defined in RFC 1321 as

       T[i] = (int) (4294967296.0 * fabs (sin (i))), i=1..64
    */

    /* Round 1.  */
    OP(A, B, C, D, 7, 0xd76aa478);
    OP(D, A, B, C, 12, 0xe8c7b756);
    OP(C, D, A, B, 17, 0x242070db);
    OP(B, C, D, A, 22, 0xc1bdceee);
    OP(A, B, C, D, 7, 0xf57c0faf);
    OP(D, A, B, C, 12, 0x4787c62a);
    OP(C, D, A, B, 17, 0xa8304613);
    OP(B, C, D, A, 22, 0xfd469501);
    OP(A, B, C, D, 7, 0x698098d8);
    OP(D, A, B, C, 12, 0x8b44f7af);
    OP(C, D, A, B, 17, 0xffff5bb1);
    OP(B, C, D, A, 22, 0x895cd7be);
    OP(A, B, C, D, 7, 0x6b901122);
    OP(D, A, B, C, 12, 0xfd987193);
    OP(C, D, A, B, 17, 0xa679438e);
    OP(B, C, D, A, 22, 0x49b40821);
    /* For the second to fourth round we have the possibly swapped words
       in CORRECT_WORDS.  Redefine the macro to take an additional first
       argument specifying the function to use.  */
#undef OP
#define OP(f, a, b, c, d, k, s, T)					\
      do 								\
	{								\
	  a += f (b, c, d) + correct_words[k] + T;			\
	  CYCLIC (a, s);						\
	  a += b;							\
	}								\
      while (0)

    /* Round 2.  */
    OP(FG, A, B, C, D, 1, 5, 0xf61e2562);
    OP(FG, D, A, B, C, 6, 9, 0xc040b340);
    OP(FG, C, D, A, B, 11, 14, 0x265e5a51);
    OP(FG, B, C, D, A, 0, 20, 0xe9b6c7aa);
    OP(FG, A, B, C, D, 5, 5, 0xd62f105d);
    OP(FG, D, A, B, C, 10, 9, 0x02441453);
    OP(FG, C, D, A, B, 15, 14, 0xd8a1e681);
    OP(FG, B, C, D, A, 4, 20, 0xe7d3fbc8);
    OP(FG, A, B, C, D, 9, 5, 0x21e1cde6);
    OP(FG, D, A, B, C, 14, 9, 0xc33707d6);
    OP(FG, C, D, A, B, 3, 14, 0xf4d50d87);
    OP(FG, B, C, D, A, 8, 20, 0x455a14ed);
    OP(FG, A, B, C, D, 13, 5, 0xa9e3e905);
    OP(FG, D, A, B, C, 2, 9, 0xfcefa3f8);
    OP(FG, C, D, A, B, 7, 14, 0x676f02d9);
    OP(FG, B, C, D, A, 12, 20, 0x8d2a4c8a);

    /* Round 3.  */
    OP(FH, A, B, C, D, 5, 4, 0xfffa3942);
    OP(FH, D, A, B, C, 8, 11, 0x8771f681);
    OP(FH, C, D, A, B, 11, 16, 0x6d9d6122);
    OP(FH, B, C, D, A, 14, 23, 0xfde5380c);
    OP(FH, A, B, C, D, 1, 4, 0xa4beea44);
    OP(FH, D, A, B, C, 4, 11, 0x4bdecfa9);
    OP(FH, C, D, A, B, 7, 16, 0xf6bb4b60);
    OP(FH, B, C, D, A, 10, 23, 0xbebfbc70);
    OP(FH, A, B, C, D, 13, 4, 0x289b7ec6);
    OP(FH, D, A, B, C, 0, 11, 0xeaa127fa);
    OP(FH, C, D, A, B, 3, 16, 0xd4ef3085);
    OP(FH, B, C, D, A, 6, 23, 0x04881d05);
    OP(FH, A, B, C, D, 9, 4, 0xd9d4d039);
    OP(FH, D, A, B, C, 12, 11, 0xe6db99e5);
    OP(FH, C, D, A, B, 15, 16, 0x1fa27cf8);
    OP(FH, B, C, D, A, 2, 23, 0xc4ac5665);

    /* Round 4.  */
    OP(FI, A, B, C, D, 0, 6, 0xf4292244);
    OP(FI, D, A, B, C, 7, 10, 0x432aff97);
    OP(FI, C, D, A, B, 14, 15, 0xab9423a7);
    OP(FI, B, C, D, A, 5, 21, 0xfc93a039);
    OP(FI, A, B, C, D, 12, 6, 0x655b59c3);
    OP(FI, D, A, B, C, 3, 10, 0x8f0ccc92);
    OP(FI, C, D, A, B, 10, 15, 0xffeff47d);
    OP(FI, B, C, D, A, 1, 21, 0x85845dd1);
    OP(FI, A, B, C, D, 8, 6, 0x6fa87e4f);
    OP(FI, D, A, B, C, 15, 10, 0xfe2ce6e0);
    OP(FI, C, D, A, B, 6, 15, 0xa3014314);
    OP(FI, B, C, D, A, 13, 21, 0x4e0811a1);
    OP(FI, A, B, C, D, 4, 6, 0xf7537e82);
    OP(FI, D, A, B, C, 11, 10, 0xbd3af235);
    OP(FI, C, D, A, B, 2, 15, 0x2ad7d2bb);
    OP(FI, B, C, D, A, 9, 21, 0xeb86d391);

    /* Add the starting values of the context.  */
    A += A_save;
    B += B_save;
    C += C_save;
    D += D_save;
  }

  /* Put checksum in context given as argument.  */
  ctx->A = A;
  ctx->B = B;
  ctx->C = C;
  ctx->D = D;
}


/*----------------------------------------------------------------------------
 *--------end of md5.c
 *----------------------------------------------------------------------------*/

 
int md5Reset(register md5Param* p)
{
        unsigned int i;

        md5_init_ctx(p);
	
        for (i = 0; i < 16; i += 8)
	  {
	    p->buffer[i]   = 0x00;
	    p->buffer[i+1] = 0x00;
	    p->buffer[i+2] = 0x00;
	    p->buffer[i+3] = 0x00;
	    p->buffer[i+4] = 0x00;
	    p->buffer[i+5] = 0x00;
	    p->buffer[i+6] = 0x00;
	    p->buffer[i+7] = 0x00;
	  }
	
        return 0;
}

int md5Update(md5Param* p, const sh_byte* data, int size)
{
  md5_process_bytes(data, size, p);
  return 0;
}

static void md5Finish(md5Param* p, void *resblock)
{
  (void) md5_finish_ctx(p, resblock);
}

int md5Digest(md5Param* p, md5_uint32* data)
{
        md5Finish(p, data);
        (void) md5Reset(p);
        return 0;
}
/*@+type@*/


/* Compute MD5 message digest for bytes read from STREAM.  The
   resulting message digest number will be written into the 16 bytes
   beginning at RESBLOCK.  */
static int md5_stream(char * filename, void *resblock, 
		      UINT64 * Length, int timeout, SL_TICKET fd)
{
  /* Important: BLOCKSIZE must be a multiple of 64.  */
  static const int BLOCKSIZE = 8192;
  struct md5_ctx ctx;
  char * buffer = SH_ALLOC(8264); /* BLOCKSIZE + 72  AIX compiler chokes */
  size_t sum;

  char * tmp;
  uid_t   euid;
  UINT64  bcount = 0;
  sh_string * content;

  unsigned long pages_read;
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
  /*@-nestedextern@*/
  extern long IO_Limit;
  /*@+nestedextern@*/
#endif

  /* Initialize the computation context.  */
  (void) md5Reset (&ctx);

  if (SL_ISERROR (fd))
    {
      TPT((0, FIL__, __LINE__, _("msg=<SL_ISERROR (%ld)>\n"), fd));
      tmp = sh_util_safe_name (filename);
      (void) sl_get_euid(&euid);
      sh_error_handle (ShDFLevel[SH_ERR_T_FILE], FIL__, __LINE__, fd,
		       MSG_E_ACCESS, (long) euid, tmp);
      SH_FREE(tmp);
      *Length = 0;
      SH_FREE(buffer);
      return -1;
    }

  pages_read = 0;

  content = sl_get_content(fd);

  /* Iterate over full file contents.  */
  while (1) {
    /* We read the file in blocks of BLOCKSIZE bytes.  One call of the
       computation function processes the whole buffer so that with the
       next round of the loop another block can be read.  */
    off_t  n;
    sum = 0;

    /* Read block.  Take care for partial reads.  */
    do {

      n = (off_t) sl_read_timeout (fd, buffer + sum, 
				   (size_t) BLOCKSIZE - sum, timeout, S_FALSE);

      if (SL_ISERROR (n))
	{
	  int error = errno;

	  if (sig_termfast == 1)
	    {
	      SH_FREE(buffer);
	      return -1;
	    }
	  TPT((0, FIL__ , __LINE__ , _("msg=<SL_ISERROR (%ld)>\n"), n));
	  tmp = sh_util_safe_name (filename);
	  if (n == SL_TIMEOUT) 
	    {
	      if (timeout != 7) {
		sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, n, MSG_E_TIMEOUT,
				 timeout, tmp);
	      }
	    }
	  else
	    {
	      char errbuf[SH_ERRBUF_SIZE];
	      char errbuf2[SH_ERRBUF_SIZE];
	      sl_strlcpy(errbuf, sl_error_string(n), sizeof(errbuf));
	      sh_error_message(error, errbuf2, sizeof(errbuf2));
	      sh_error_handle (ShDFLevel[SH_ERR_T_FILE], FIL__, __LINE__, n,
			       MSG_E_READ, errbuf, errbuf2, tmp);
	    }
	  SH_FREE(tmp);
	  *Length = 0;
	  SH_FREE(buffer);
	  return -1;
	}

      if (content)
	sh_string_cat_lchar(content, buffer, n);

      bcount += n;

      if (*Length != TIGER_NOLIM)
	{
	  if (bcount > *Length) 
	    {
	      n = n - (bcount - (*Length));
	      bcount = *Length;
	      n = (n < 0) ? 0 : n;
	    }
	}

      sum += n;
    }
    while (sum < (size_t) BLOCKSIZE 
	   && n != 0);

    ++pages_read;

    /* If end of file is reached, end the loop.  */
    if (n == 0)
      break;

    /* Process buffer with BLOCKSIZE bytes.  Note that
       BLOCKSIZE % 64 == 0
    */
    md5_process_block(buffer, BLOCKSIZE, &ctx);
    sh.statistics.bytes_hashed += BLOCKSIZE;

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
    if ((IO_Limit) > 0 && (pages_read == 32)) /* check for I/O limit */
      {
	sh_unix_io_pause ();
	pages_read = 0;
      }
    if (sig_termfast == 1) 
      {
	*Length = 0;
	SH_FREE(buffer);
	return -1;
      }
#endif 
  }

  /* Add the last bytes if necessary.  */
  if (sum > 0)
    {
      md5_process_bytes(buffer, sum, &ctx);
      sh.statistics.bytes_hashed += BLOCKSIZE;
    }

  /* Construct result in desired memory.  */
  (void) md5Digest(&ctx, resblock);

  *Length = bcount;
  SH_FREE(buffer);
  return 0;
}

static
char * sh_tiger_md5_hash  (char * filename, TigerType what, 
			   UINT64 * Length, int timeout, char * out, size_t len)
{
  int cnt;
  char outbuf[KEY_LEN+1];
  unsigned char md5buffer[16];

  (void) md5_stream (filename, md5buffer, Length, timeout, what);

  /*@-bufferoverflowhigh -usedef@*/
  for (cnt = 0; cnt < 16; ++cnt)
    sprintf (&outbuf[cnt*2], _("%02X"),                 /* known to fit  */
	     (unsigned int) md5buffer[cnt]);
  /*@+bufferoverflowhigh +usedef@*/
  for (cnt = 32; cnt < KEY_LEN; ++cnt)
    outbuf[cnt] = '0';
  outbuf[KEY_LEN] = '\0';

  sl_strlcpy(out, outbuf, len);
  return out;
}

/* USE_MD5 */
#endif

/***************************************************************
 *
 * SHA1
 *
 ***************************************************************/

#ifdef USE_SHA1
/*@-type@*/

typedef unsigned char sha_word8;
typedef sh_word32     sha_word32;

/* The SHA block size and message digest sizes, in bytes */

#define SHA_DATASIZE    64
#define SHA_DATALEN     16
#define SHA_DIGESTSIZE  20
#define SHA_DIGESTLEN    5
/* The structure for storing SHA info */

typedef struct sha_ctx {
  sha_word32 digest[SHA_DIGESTLEN];  /* Message digest */
  sha_word32 count_l, count_h;       /* 64-bit block count */
  sha_word8 block[SHA_DATASIZE];     /* SHA data buffer */
  int index;                             /* index into buffer */
} SHA_CTX;

static void sha_init(struct sha_ctx *ctx);
static void sha_update(struct sha_ctx *ctx, sha_word8 *buffer,sha_word32 len);
static void sha_final(struct sha_ctx *ctx);
static void sha_digest(struct sha_ctx *ctx, sha_word8 *s);


/* The SHA f()-functions.  The f1 and f3 functions can be optimized to
   save one boolean operation each - thanks to Rich Schroeppel,
   rcs@cs.arizona.edu for discovering this */

/*#define f1(x,y,z) ( ( x & y ) | ( ~x & z ) )          // Rounds  0-19 */
#define f1(x,y,z)   ( z ^ ( x & ( y ^ z ) ) )           /* Rounds  0-19 */
#define f2(x,y,z)   ( x ^ y ^ z )                       /* Rounds 20-39 */
/*#define f3(x,y,z) ( ( x & y ) | ( x & z ) | ( y & z ) )   // Rounds 40-59 */
#define f3(x,y,z)   ( ( x & y ) | ( z & ( x | y ) ) )   /* Rounds 40-59 */
#define f4(x,y,z)   ( x ^ y ^ z )                       /* Rounds 60-79 */

/* The SHA Mysterious Constants */

#define K1  0x5A827999L                                 /* Rounds  0-19 */
#define K2  0x6ED9EBA1L                                 /* Rounds 20-39 */
#define K3  0x8F1BBCDCL                                 /* Rounds 40-59 */
#define K4  0xCA62C1D6L                                 /* Rounds 60-79 */

/* SHA initial values */

#define h0init  0x67452301L
#define h1init  0xEFCDAB89L
#define h2init  0x98BADCFEL
#define h3init  0x10325476L
#define h4init  0xC3D2E1F0L

/* 32-bit rotate left - kludged with shifts */

#define ROTL(n,X)  ( ( (X) << (n) ) | ( (X) >> ( 32 - (n) ) ) )

/* The initial expanding function.  The hash function is defined over an
   80-word expanded input array W, where the first 16 are copies of the input
   data, and the remaining 64 are defined by

        W[ i ] = W[ i - 16 ] ^ W[ i - 14 ] ^ W[ i - 8 ] ^ W[ i - 3 ]

   This implementation generates these values on the fly in a circular
   buffer - thanks to Colin Plumb, colin@nyx10.cs.du.edu for this
   optimization.

   The updated SHA changes the expanding function by adding a rotate of 1
   bit.  Thanks to Jim Gillogly, jim@rand.org, and an anonymous contributor
   for this information */

#define expand(W,i) ( W[ i & 15 ] = \
                      ROTL( 1, ( W[ i & 15 ] ^ W[ (i - 14) & 15 ] ^ \
                                 W[ (i - 8) & 15 ] ^ W[ (i - 3) & 15 ] ) ) )


/* The prototype SHA sub-round.  The fundamental sub-round is:

        a' = e + ROTL( 5, a ) + f( b, c, d ) + k + data;
        b' = a;
        c' = ROTL( 30, b );
        d' = c;
        e' = d;

   but this is implemented by unrolling the loop 5 times and renaming the
   variables ( e, a, b, c, d ) = ( a', b', c', d', e' ) each iteration.
   This code is then replicated 20 times for each of the 4 functions, using
   the next 20 values from the W[] array each time */

#define subRound(a, b, c, d, e, f, k, data) \
    ( e += ROTL( 5, a ) + f( b, c, d ) + k + data, b = ROTL( 30, b ) )

/* Initialize the SHA values */

static void sha_init(struct sha_ctx *ctx)
{
  /* Set the h-vars to their initial values */
  ctx->digest[ 0 ] = h0init;
  ctx->digest[ 1 ] = h1init;
  ctx->digest[ 2 ] = h2init;
  ctx->digest[ 3 ] = h3init;
  ctx->digest[ 4 ] = h4init;

  /* Initialize bit count */
  ctx->count_l = ctx->count_h = 0;

  /* Initialize buffer */
  ctx->index = 0;
}

/* Perform the SHA transformation.  Note that this code, like MD5, seems to
   break some optimizing compilers due to the complexity of the expressions
   and the size of the basic block.  It may be necessary to split it into
   sections, e.g. based on the four subrounds

   Note that this function destroys the data area */

static void sha_transform(struct sha_ctx *ctx, sha_word32 *data )
{
  register sha_word32 A, B, C, D, E;     /* Local vars */

  /* Set up first buffer and local data buffer */
  A = ctx->digest[0];
  B = ctx->digest[1];
  C = ctx->digest[2];
  D = ctx->digest[3];
  E = ctx->digest[4];

  /* Heavy mangling, in 4 sub-rounds of 20 interations each. */
  subRound( A, B, C, D, E, f1, K1, data[ 0] );
  subRound( E, A, B, C, D, f1, K1, data[ 1] );
  subRound( D, E, A, B, C, f1, K1, data[ 2] );
  subRound( C, D, E, A, B, f1, K1, data[ 3] );
  subRound( B, C, D, E, A, f1, K1, data[ 4] );
  subRound( A, B, C, D, E, f1, K1, data[ 5] );
  subRound( E, A, B, C, D, f1, K1, data[ 6] );
  subRound( D, E, A, B, C, f1, K1, data[ 7] );
  subRound( C, D, E, A, B, f1, K1, data[ 8] );
  subRound( B, C, D, E, A, f1, K1, data[ 9] );
  subRound( A, B, C, D, E, f1, K1, data[10] );
  subRound( E, A, B, C, D, f1, K1, data[11] );
  subRound( D, E, A, B, C, f1, K1, data[12] );
  subRound( C, D, E, A, B, f1, K1, data[13] );
  subRound( B, C, D, E, A, f1, K1, data[14] );
  subRound( A, B, C, D, E, f1, K1, data[15] );
  subRound( E, A, B, C, D, f1, K1, expand( data, 16 ) );
  subRound( D, E, A, B, C, f1, K1, expand( data, 17 ) );
  subRound( C, D, E, A, B, f1, K1, expand( data, 18 ) );
  subRound( B, C, D, E, A, f1, K1, expand( data, 19 ) );

  subRound( A, B, C, D, E, f2, K2, expand( data, 20 ) );
  subRound( E, A, B, C, D, f2, K2, expand( data, 21 ) );
  subRound( D, E, A, B, C, f2, K2, expand( data, 22 ) );
  subRound( C, D, E, A, B, f2, K2, expand( data, 23 ) );
  subRound( B, C, D, E, A, f2, K2, expand( data, 24 ) );
  subRound( A, B, C, D, E, f2, K2, expand( data, 25 ) );
  subRound( E, A, B, C, D, f2, K2, expand( data, 26 ) );
  subRound( D, E, A, B, C, f2, K2, expand( data, 27 ) );
  subRound( C, D, E, A, B, f2, K2, expand( data, 28 ) );
  subRound( B, C, D, E, A, f2, K2, expand( data, 29 ) );
  subRound( A, B, C, D, E, f2, K2, expand( data, 30 ) );
  subRound( E, A, B, C, D, f2, K2, expand( data, 31 ) );
  subRound( D, E, A, B, C, f2, K2, expand( data, 32 ) );
  subRound( C, D, E, A, B, f2, K2, expand( data, 33 ) );
  subRound( B, C, D, E, A, f2, K2, expand( data, 34 ) );
  subRound( A, B, C, D, E, f2, K2, expand( data, 35 ) );
  subRound( E, A, B, C, D, f2, K2, expand( data, 36 ) );
  subRound( D, E, A, B, C, f2, K2, expand( data, 37 ) );
  subRound( C, D, E, A, B, f2, K2, expand( data, 38 ) );
  subRound( B, C, D, E, A, f2, K2, expand( data, 39 ) );

  subRound( A, B, C, D, E, f3, K3, expand( data, 40 ) );
  subRound( E, A, B, C, D, f3, K3, expand( data, 41 ) );
  subRound( D, E, A, B, C, f3, K3, expand( data, 42 ) );
  subRound( C, D, E, A, B, f3, K3, expand( data, 43 ) );
  subRound( B, C, D, E, A, f3, K3, expand( data, 44 ) );
  subRound( A, B, C, D, E, f3, K3, expand( data, 45 ) );
  subRound( E, A, B, C, D, f3, K3, expand( data, 46 ) );
  subRound( D, E, A, B, C, f3, K3, expand( data, 47 ) );
  subRound( C, D, E, A, B, f3, K3, expand( data, 48 ) );
  subRound( B, C, D, E, A, f3, K3, expand( data, 49 ) );
  subRound( A, B, C, D, E, f3, K3, expand( data, 50 ) );
  subRound( E, A, B, C, D, f3, K3, expand( data, 51 ) );
  subRound( D, E, A, B, C, f3, K3, expand( data, 52 ) );
  subRound( C, D, E, A, B, f3, K3, expand( data, 53 ) );
  subRound( B, C, D, E, A, f3, K3, expand( data, 54 ) );
  subRound( A, B, C, D, E, f3, K3, expand( data, 55 ) );
  subRound( E, A, B, C, D, f3, K3, expand( data, 56 ) );
  subRound( D, E, A, B, C, f3, K3, expand( data, 57 ) );
  subRound( C, D, E, A, B, f3, K3, expand( data, 58 ) );
  subRound( B, C, D, E, A, f3, K3, expand( data, 59 ) );

  subRound( A, B, C, D, E, f4, K4, expand( data, 60 ) );
  subRound( E, A, B, C, D, f4, K4, expand( data, 61 ) );
  subRound( D, E, A, B, C, f4, K4, expand( data, 62 ) );
  subRound( C, D, E, A, B, f4, K4, expand( data, 63 ) );
  subRound( B, C, D, E, A, f4, K4, expand( data, 64 ) );
  subRound( A, B, C, D, E, f4, K4, expand( data, 65 ) );
  subRound( E, A, B, C, D, f4, K4, expand( data, 66 ) );
  subRound( D, E, A, B, C, f4, K4, expand( data, 67 ) );
  subRound( C, D, E, A, B, f4, K4, expand( data, 68 ) );
  subRound( B, C, D, E, A, f4, K4, expand( data, 69 ) );
  subRound( A, B, C, D, E, f4, K4, expand( data, 70 ) );
  subRound( E, A, B, C, D, f4, K4, expand( data, 71 ) );
  subRound( D, E, A, B, C, f4, K4, expand( data, 72 ) );
  subRound( C, D, E, A, B, f4, K4, expand( data, 73 ) );
  subRound( B, C, D, E, A, f4, K4, expand( data, 74 ) );
  subRound( A, B, C, D, E, f4, K4, expand( data, 75 ) );
  subRound( E, A, B, C, D, f4, K4, expand( data, 76 ) );
  subRound( D, E, A, B, C, f4, K4, expand( data, 77 ) );
  subRound( C, D, E, A, B, f4, K4, expand( data, 78 ) );
  subRound( B, C, D, E, A, f4, K4, expand( data, 79 ) );

  /* Build message digest */
  ctx->digest[0] += A;
  ctx->digest[1] += B;
  ctx->digest[2] += C;
  ctx->digest[3] += D;
  ctx->digest[4] += E;
}

#if 1

#ifndef EXTRACT_UCHAR
#define EXTRACT_UCHAR(p)  (*(unsigned char *)(p))
#endif

#define STRING2INT(s) ((((((EXTRACT_UCHAR(s) << 8)    \
                         | EXTRACT_UCHAR(s+1)) << 8)  \
                         | EXTRACT_UCHAR(s+2)) << 8)  \
                         | EXTRACT_UCHAR(s+3))
#else
sha_word32 STRING2INT(word8 *s)
{
  sha_word32 r;
  int i;

  for (i = 0, r = 0; i < 4; i++, s++)
    r = (r << 8) | *s;
  return r;
}
#endif

static void sha_block(struct sha_ctx *ctx, sha_word8 *block)
{
  sha_word32 data[SHA_DATALEN];
  int i;

  /* Update block count */
  /*@-boolops@*/
  if (!++ctx->count_l)
    ++ctx->count_h;
  /*@+boolops@*/

  /* Endian independent conversion */
  for (i = 0; i<SHA_DATALEN; i++, block += 4)
    data[i] = STRING2INT(block);

  sha_transform(ctx, data);
}

static void sha_update(struct sha_ctx *ctx, sha_word8 *buffer, sha_word32 len)
{
  if (ctx->index != 0)
    { /* Try to fill partial block */
      unsigned left = SHA_DATASIZE - ctx->index;
      if (len < left)
        {
          memmove(ctx->block + ctx->index, buffer, len);
          ctx->index += len;
          return; /* Finished */
        }
      else
        {
          memmove(ctx->block + ctx->index, buffer, left);
          sha_block(ctx, ctx->block);
          buffer += left;
          len -= left;
        }
    }
  while (len >= SHA_DATASIZE)
    {
      sha_block(ctx, buffer);
      buffer += SHA_DATASIZE;
      len -= SHA_DATASIZE;
    }
  /*@-predboolint@*/
  if ((ctx->index = len))     /* This assignment is intended */
  /*@+predboolint@*/
    /* Buffer leftovers */
    memmove(ctx->block, buffer, len);
}

/* Final wrapup - pad to SHA_DATASIZE-byte boundary with the bit pattern
   1 0* (64-bit count of bits processed, MSB-first) */

static void sha_final(struct sha_ctx *ctx)
{
  sha_word32 data[SHA_DATALEN];
  int i;
  int words;

  i = ctx->index;
  /* Set the first char of padding to 0x80.  This is safe since there is
     always at least one byte free */
  ctx->block[i++] = 0x80;

  /* Fill rest of word */
  /*@-predboolint@*/
  for( ; i & 3; i++)
    ctx->block[i] = 0;
  /*@+predboolint@*/

  /* i is now a multiple of the word size 4 */
  /*@-shiftimplementation@*/
  words = i >> 2;
  /*@+shiftimplementation@*/
  for (i = 0; i < words; i++)
    data[i] = STRING2INT(ctx->block + 4*i);

  if (words > (SHA_DATALEN-2))
    { /* No room for length in this block. Process it and
       * pad with another one */
      for (i = words ; i < SHA_DATALEN; i++)
        data[i] = 0;
      sha_transform(ctx, data);
      for (i = 0; i < (SHA_DATALEN-2); i++)
        data[i] = 0;
    }
  else
    for (i = words ; i < SHA_DATALEN - 2; i++)
      data[i] = 0;
  /* Theres 512 = 2^9 bits in one block */
  /*@-shiftimplementation@*/
  data[SHA_DATALEN-2] = (ctx->count_h << 9) | (ctx->count_l >> 23);
  data[SHA_DATALEN-1] = (ctx->count_l << 9) | (ctx->index << 3);
  /*@+shiftimplementation@*/
  sha_transform(ctx, data);
}

static void sha_digest(struct sha_ctx *ctx, sha_word8 *s)
{
  int i;

  for (i = 0; i < SHA_DIGESTLEN; i++)
    {
      *s++ =         ctx->digest[i] >> 24;
      *s++ = 0xff & (ctx->digest[i] >> 16);
      *s++ = 0xff & (ctx->digest[i] >> 8);
      *s++ = 0xff &  ctx->digest[i];
    }
}
/*@+type@*/

#include "sh_checksum.h"

#define SH_VAR_SHA1   0
#define SH_VAR_SHA256 1

/* Compute SHA1 message digest for bytes read from STREAM.  The
   resulting message digest number will be written into the 16 bytes
   beginning at RESBLOCK.  */
static int SHA_stream(char * filename, void *resblock, 
		      UINT64 * Length, int timeout, SL_TICKET fd, int variant)
{
  /* Important: BLOCKSIZE must be a multiple of 64.  */
  static const int BLOCKSIZE = 4096;
  struct sha_ctx ctx;
  SHA256_CTX ctx_sha2;
  char * buffer = SH_ALLOC(4168); /* BLOCKSIZE + 72 AIX compiler chokes */
  off_t sum = 0;
  char * tmp;
  uid_t  euid;
  UINT64 bcount = 0;
  sh_string * content;

  unsigned long pages_read;
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
  /*@-nestedextern@*/
  extern long IO_Limit;
  /*@+nestedextern@*/
#endif

  /* Initialize the computation context.  */
  if (variant == SH_VAR_SHA256)
    (void) SHA256_Init(&ctx_sha2);
  else
    (void) sha_init(&ctx);

  if (SL_ISERROR (fd))
    {
      TPT((0, FIL__, __LINE__, _("msg=<SL_ISERROR (%ld)>\n"), fd));
      tmp = sh_util_safe_name (filename);
      (void) sl_get_euid(&euid);
      sh_error_handle (ShDFLevel[SH_ERR_T_FILE], FIL__, __LINE__, fd,
		       MSG_E_ACCESS, (long) euid, tmp);
      SH_FREE(tmp);
      *Length = 0;
      SH_FREE(buffer);
      return -1;
    }

  /* Iterate over full file contents.  */

  pages_read = 0;

  content = sl_get_content(fd);

  while (1 == 1) {
    /* We read the file in blocks of BLOCKSIZE bytes.  One call of the
       computation function processes the whole buffer so that with the
       next round of the loop another block can be read.  */
    off_t  n;
    sum = 0;

    /* Read block.  Take care for partial reads.  */
    do {
      n = (off_t) sl_read_timeout(fd, buffer + sum, 
				  (size_t) BLOCKSIZE - sum, timeout, S_FALSE);

      if (SL_ISERROR (n))
	{
	  int error = errno;

	  if (sig_termfast == 1)
	    {
	      SH_FREE(buffer);
	      return -1;
	    }

	  TPT((0, FIL__ , __LINE__ , _("msg=<SL_ISERROR (%ld)>\n"), n));
	  tmp = sh_util_safe_name (filename);
	  if (n == SL_TIMEOUT)
	    {
	      if (timeout != 7) {
		sh_error_handle (SH_ERR_ERR, FIL__, __LINE__, n, MSG_E_TIMEOUT,
				 timeout, tmp);
	      }
	    }
	  else 
	    {
	      char errbuf[SH_ERRBUF_SIZE];
	      char errbuf2[SH_ERRBUF_SIZE];
	      sl_strlcpy(errbuf, sl_error_string(n), sizeof(errbuf));
	      sh_error_message(error, errbuf2, sizeof(errbuf2));
	      sh_error_handle (ShDFLevel[SH_ERR_T_FILE], FIL__, __LINE__, n,
			       MSG_E_READ, errbuf, errbuf2, tmp);
	    }
	  SH_FREE(tmp);
	  *Length = 0;
	  SH_FREE(buffer);
	  return -1;
	}

      if (content)
	sh_string_cat_lchar(content, buffer, n);

      bcount += n;

      if (*Length != TIGER_NOLIM)
	{
	  if (bcount > *Length)
	    {
	      n = n - (bcount - (*Length));
	      bcount = *Length;
	      n = (n < 0) ? 0 : n;
	    }
	}

      sum += n;
    }
    while (sum < (off_t)BLOCKSIZE 
	   && n != 0);

    ++pages_read;

    /* If end of file is reached, end the loop.  */
    if (n == 0)
      break;

    /* Process buffer with BLOCKSIZE bytes.  Note that
       BLOCKSIZE % 64 == 0
    */
    if (variant == SH_VAR_SHA256)
      SHA256_Update(&ctx_sha2, (sha2_byte*) buffer, (size_t) BLOCKSIZE);
    else
      sha_update(&ctx, (sha_word8*) buffer, (sha_word32) BLOCKSIZE);
    sh.statistics.bytes_hashed += BLOCKSIZE;

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
    if ((IO_Limit) > 0 && (pages_read == 32)) /* check for I/O limit */
      {
	sh_unix_io_pause ();
	pages_read = 0;
      }
    if (sig_termfast == 1) 
      {
	*Length = 0;
	SH_FREE(buffer);
	return -1;
      }
#endif 

  }

  /* Add the last bytes if necessary.  */
  if (sum > 0)
    {
      if (variant == SH_VAR_SHA256)
	SHA256_Update(&ctx_sha2, (sha2_byte*) buffer, (size_t) sum);
      else
	sha_update(&ctx, (sha_word8*) buffer, (sha_word32) sum);
      sh.statistics.bytes_hashed += sum;
    }

  /* Construct result in desired memory.  */
  if (variant == SH_VAR_SHA256)
    {
      SHA256_End(&ctx_sha2, resblock);
    }
  else
    {
      sha_final (&ctx);
      sha_digest (&ctx, resblock);
    }

  *Length = bcount;
  SH_FREE(buffer);
  return 0;
}


static char * sh_tiger_sha1_hash  (char * filename, TigerType what, 
				   UINT64 * Length, int timeout, 
				   char * out, size_t len)
{
  int cnt;
  char outbuf[KEY_LEN+1];
  unsigned char sha1buffer[20];

  (void) SHA_stream (filename, sha1buffer, Length, timeout, what, SH_VAR_SHA1);

  /*@-bufferoverflowhigh -usedef@*/
  for (cnt = 0; cnt < 20; ++cnt)
    sprintf (&outbuf[cnt*2], _("%02X"),              /* known to fit  */
	     (unsigned int) sha1buffer[cnt]);
  /*@+bufferoverflowhigh +usedef@*/
  for (cnt = 40; cnt < KEY_LEN; ++cnt)
    outbuf[cnt] = '0';
  outbuf[KEY_LEN] = '\0';

  sl_strlcpy(out, outbuf, len);
  return out;
}

static char * sh_tiger_sha256_hash  (char * filename, TigerType what, 
				     UINT64 * Length, int timeout, 
				     char * out, size_t len)
{
  char outbuf[KEYBUF_SIZE];

  (void) SHA_stream (filename, outbuf, Length, timeout, what, SH_VAR_SHA256);

  sl_strlcpy(out, outbuf, len);
  return out;
}

/* ifdef USE_SHA1 */
#endif

static int hash_type = SH_TIGER192;

int sh_tiger_get_hashtype ()
{
  return hash_type;
}

void sh_tiger_get_mask_hashtype(unsigned long * mask)
{
  if (hash_type == SH_TIGER192) 
    *mask |= MODI_TIGER192;
  else if (hash_type == SH_SHA1)
    *mask |= MODI_SHA1;
  else if (hash_type == SH_MD5)
    *mask |= MODI_MD5;
  else if (hash_type == SH_SHA256)
    *mask |= MODI_SHA256;
  return;
}

void sh_tiger_set_hashtype_mask(unsigned long mask)
{
  unsigned long type = mask & MODI_HASHTYPE;

  if (type == MODI_TIGER192)
    hash_type = SH_TIGER192;
  else if (type == MODI_SHA1)
    hash_type = SH_SHA1;
  else if (type == MODI_MD5)
    hash_type = SH_MD5;
  else if (type == MODI_SHA256)
    hash_type = SH_SHA256;
  return;
}


int sh_tiger_hashtype (const char * c)
{
  SL_ENTER( _("sh_tiger_hashtype"));

  if (!c)
    {
      SL_RETURN( -1, _("sh_tiger_hashtype"));
    }

  if (0 == strcmp(c, _("TIGER192")))
    hash_type = SH_TIGER192;
#ifdef USE_SHA1
  else if (0 == strcmp(c, _("SHA1")))    
    hash_type = SH_SHA1;
#endif
#ifdef USE_MD5
  else if (0 == strcmp(c, _("MD5")))    
    hash_type = SH_MD5;
#endif
#ifdef USE_SHA1
  else if (0 == strcmp(c, _("SHA256")))    
    hash_type = SH_SHA256;
#endif
  else
    {
      SL_RETURN( -1, _("sh_tiger_hashtype"));
    }
  SL_RETURN( 0, _("sh_tiger_hashtype"));
}

static char * sh_tiger_hash_internal (const char * filename, TigerType what, 
				      UINT64 * Length, int timeout,
				      char * out, size_t len);

char * sh_tiger_hash (const char * filename, TigerType what, 
		      UINT64 Length, char * out, size_t len)
{
  UINT64 local_length = Length;
  char * retval = sh_tiger_hash_internal (filename, what, &local_length, 0, out,len);
  return retval;
}

char * sh_tiger_generic_hash (char * filename, TigerType what, 
			      UINT64 * Length, int timeout,
			      char * out, size_t len)
{
#ifdef USE_SHA1
  if (hash_type == SH_SHA1)
    return sh_tiger_sha1_hash    (filename, what, Length, timeout, out, len);
#endif
#ifdef USE_MD5
  if (hash_type == SH_MD5)
    return sh_tiger_md5_hash     (filename, what, Length, timeout, out, len);
#endif
#ifdef USE_SHA1
  if (hash_type == SH_SHA256)
    return sh_tiger_sha256_hash  (filename, what, Length, timeout, out, len);
#endif
  return sh_tiger_hash_internal  (filename, what, Length, timeout, out, len);
}

/*
 * -------   end new ---------  */
  
static char * sh_tiger_hash_internal (const char * filename, TigerType what, 
				      UINT64 * Length, int timeout, 
				      char * out, size_t len)
{
#if defined(TIGER_64_BIT)
  word64 res[3];
#else
  sh_word32 res[6];
#endif

  SL_ENTER( _("sh_tiger_hash_internal"));

  SH_VALIDATE_GE(len, (KEY_LEN+1));

  if (NULL != sh_tiger_hash_val (filename, what, Length, timeout, res))
    {
#if defined(TIGER_64_BIT)
      sl_snprintf(out, len,
		  MYFORMAT,
		  (sh_word32)(res[0]>>32), 
		  (sh_word32)(res[0]), 
		  (sh_word32)(res[1]>>32), 
		  (sh_word32)(res[1]), 
		  (sh_word32)(res[2]>>32), 
		  (sh_word32)(res[2]) );
#else
      sl_snprintf(out, len,
		  MYFORMAT,
		  (sh_word32)(res[1]), 
		  (sh_word32)(res[0]), 
		  (sh_word32)(res[3]), 
		  (sh_word32)(res[2]), 
		  (sh_word32)(res[5]), 
		  (sh_word32)(res[4]) );
#endif
      out[len-1] = '\0';
      SL_RETURN( out, _("sh_tiger_hash_internal"));

    }

   SL_RETURN( SH_KEY_NULL, _("sh_tiger_hash_internal"));
}

char * sh_tiger_hash_gpg (const char * filename, TigerType what, 
			  UINT64 Length)
{
  size_t  len;
  char * out;
  char   outhash[48+6+1];
#if defined(TIGER_64_BIT)
  word64 res[3];
#else
  sh_word32 res[6];
#endif
  UINT64 local_length = Length;

  SL_ENTER(_("sh_tiger_hash_gpg"));

  if (NULL != sh_tiger_hash_val (filename, what, &local_length, 0, res))
    {
#if defined(TIGER_64_BIT)
      sl_snprintf(outhash,
		  sizeof(outhash),
		  GPGFORMAT,
		  (sh_word32)(res[0]>>32), 
		  (sh_word32)(res[0]), 
		  (sh_word32)(res[1]>>32), 
		  (sh_word32)(res[1]), 
		  (sh_word32)(res[2]>>32), 
		  (sh_word32)(res[2]) );
#else
      sl_snprintf(outhash,
		  sizeof(outhash),
		  GPGFORMAT,
		  (sh_word32)(res[1]), 
		  (sh_word32)(res[0]), 
		  (sh_word32)(res[3]), 
		  (sh_word32)(res[2]), 
		  (sh_word32)(res[5]), 
		  (sh_word32)(res[4]) );
#endif
      outhash[sizeof(outhash)-1] = '\0';
    }
  else
    {
      sl_strlcpy(outhash,
		 _("00000000 00000000 00000000  00000000 00000000 00000000"),
		 sizeof(outhash));
    }

  if (what == TIGER_FILE && sl_ok_adds(sl_strlen (filename), (2 + 48 + 6)))
    len = sl_strlen (filename) + 2 + 48 + 6;
  else
    len = 48 + 6;

  out = SH_ALLOC(len + 1);

  if (what == TIGER_FILE)
    {
      (void) sl_strlcpy (out, filename, len+1);
      (void) sl_strlcat (out,  _(": "), len+1);
      (void) sl_strlcat (out,  outhash, len+1);
    }
  else
    {
      (void) sl_strlcpy (out,  outhash, len+1);
    }
  SL_RETURN( out, _("sh_tiger_hash_gpg"));
}


UINT32 * sh_tiger_hash_uint32 (char * filename, 
			       TigerType what, 
			       UINT64 Length, UINT32 * out, size_t len)
{
#if defined(TIGER_64_BIT)
  word64 res[3];
#else
  sh_word32 res[6];
#endif
  UINT64 local_length = Length;

  SL_ENTER(_("sh_tiger_hash_uint32"));

  SH_VALIDATE_GE(len, 6);

  out[0] = 0; out[1] = 0; out[2] = 0;
  out[3] = 0; out[4] = 0; out[5] = 0;

  if (NULL != sh_tiger_hash_val (filename,  what,  &local_length, 0, res))
    {
#if defined(TIGER_64_BIT)
	out[0] =  (UINT32)(res[0]>>32); 
	out[1] =  (UINT32)(res[0]);
	out[2] =  (UINT32)(res[1]>>32); 
	out[3] =  (UINT32)(res[1]); 
	out[4] =  (UINT32)(res[2]>>32); 
	out[5] =  (UINT32)(res[2]);
#else
	out[0] =  (UINT32)(res[1]); 
	out[1] =  (UINT32)(res[0]);
	out[2] =  (UINT32)(res[3]); 
	out[3] =  (UINT32)(res[2]); 
	out[4] =  (UINT32)(res[5]); 
	out[5] =  (UINT32)(res[4]);
#endif
    }

  SL_RETURN(out, _("sh_tiger_hash_uint32"));
}
  



