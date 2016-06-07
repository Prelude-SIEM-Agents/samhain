/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2013 Rainer Wichmann                                      */
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
#include "samhain.h"
#include "sh_checksum.h"
#include <string.h>

#undef  FIL__
#define FIL__  _("sh_checksum.c")

/*
 * sha2.c
 *
 * Version 1.0.0beta1
 *
 * Written by Aaron D. Gifford <me@aarongifford.com>
 *
 * Copyright 2000 Aaron D. Gifford.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR(S) OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/* Modified for use in samhain by R. Wichmann */

#if WORDS_BIGENDIAN
#define SHA2_BIG_ENDIAN    4321
#define SHA2_BYTE_ORDER SHA2_BIG_ENDIAN
#else
#define SHA2_LITTLE_ENDIAN 1234
#define SHA2_BYTE_ORDER SHA2_LITTLE_ENDIAN
#endif

#if SHA2_BYTE_ORDER == SHA2_LITTLE_ENDIAN
#define REVERSE32(w,x)  { \
        sha2_word32 tmp = (w); \
        tmp = (tmp >> 16) | (tmp << 16); \
        (x) = ((tmp & 0xff00ff00UL) >> 8) | ((tmp & 0x00ff00ffUL) << 8); \
}
#define REVERSE64(w,x)  { \
        sha2_word64 tmp = (w); \
        tmp = (tmp >> 32) | (tmp << 32); \
        tmp = ((tmp & 0xff00ff00ff00ff00ULL) >> 8) | \
              ((tmp & 0x00ff00ff00ff00ffULL) << 8); \
        (x) = ((tmp & 0xffff0000ffff0000ULL) >> 16) | \
              ((tmp & 0x0000ffff0000ffffULL) << 16); \
}
#endif

/*
 * Macro for incrementally adding the unsigned 64-bit integer n to the
 * unsigned 128-bit integer (represented using a two-element array of
 * 64-bit words):
 */
#define ADDINC128(w,n)  { \
        (w)[0] += (sha2_word64)(n); \
        if ((w)[0] < (n)) { \
                (w)[1]++; \
        } \
}

/*** THE SIX LOGICAL FUNCTIONS ****************************************/
/*
 * Bit shifting and rotation (used by the six SHA-XYZ logical functions:
 *
 *   NOTE:  The naming of R and S appears backwards here (R is a SHIFT and
 *   S is a ROTATION) because the SHA-256/384/512 description document
 *   (see http://csrc.nist.gov/cryptval/shs/sha256-384-512.pdf) uses this
 *   same "backwards" definition.
 */
/* Shift-right (used in SHA-256, SHA-384, and SHA-512): */
#define R(b,x)          ((x) >> (b))
/* 32-bit Rotate-right (used in SHA-256): */
#define S32(b,x)        (((x) >> (b)) | ((x) << (32 - (b))))
/* 64-bit Rotate-right (used in SHA-384 and SHA-512): */
#define S64(b,x)        (((x) >> (b)) | ((x) << (64 - (b))))

/* Two of six logical functions used in SHA-256, SHA-384, and SHA-512: */
#define Ch(x,y,z)       (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)      (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* Four of six logical functions used in SHA-256: */
#define Sigma0_256(x)   (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))
#define Sigma1_256(x)   (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
#define sigma0_256(x)   (S32(7,  (x)) ^ S32(18, (x)) ^ R(3 ,   (x)))
#define sigma1_256(x)   (S32(17, (x)) ^ S32(19, (x)) ^ R(10,   (x)))

/*** INTERNAL FUNCTION PROTOTYPES *************************************/
/* NOTE: These should not be accessed directly from outside this
 * library -- they are intended for private internal visibility/use
 * only.
 */
void SHA256_Transform(SHA256_CTX*, const sha2_word32*);

/*** SHA-XYZ INITIAL HASH VALUES AND CONSTANTS ************************/
/* Hash constant words K for SHA-256: */
static const sha2_word32 K256[64] = {
        0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
        0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
        0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
        0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
        0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
        0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
        0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
        0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
        0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
        0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
        0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
        0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
        0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
        0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
        0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
        0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

/* Initial hash value H for SHA-256: */
static const sha2_word32 sha256_initial_hash_value[8] = {
        0x6a09e667UL,
        0xbb67ae85UL,
        0x3c6ef372UL,
        0xa54ff53aUL,
        0x510e527fUL,
        0x9b05688cUL,
        0x1f83d9abUL,
        0x5be0cd19UL
};

/*
 * Constant used by SHA256/384/512_End() functions for converting the
 * digest to a readable hexadecimal character string:
 */
static const char *sha2_hex_digits = "0123456789abcdef";

/*** SHA-256: *********************************************************/
void SHA256_Init(SHA256_CTX* context) {
  if (context == (SHA256_CTX*)0) {
    return;
  }
  memcpy(context->state, sha256_initial_hash_value, SHA256_DIGEST_LENGTH);
  /* bcopy(sha256_initial_hash_value, context->state, SHA256_DIGEST_LENGTH); */
  memset(context->buffer, 0, SHA256_BLOCK_LENGTH);
  /* bzero(context->buffer, SHA256_BLOCK_LENGTH); */
  
  context->bitcount = 0;
}

#ifdef SHA2_UNROLL_TRANSFORM

/* Unrolled SHA-256 round macros: */

#if SHA2_BYTE_ORDER == SHA2_LITTLE_ENDIAN

#define ROUND256_0_TO_15(a,b,c,d,e,f,g,h)       \
        REVERSE32(*data++, W256[j]); \
        T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + \
             K256[j] + W256[j]; \
        (d) += T1; \
        (h) = T1 + Sigma0_256(a) + Maj((a), (b), (c)); \
        j++

#else /* SHA2_BYTE_ORDER == SHA2_LITTLE_ENDIAN */

#define ROUND256_0_TO_15(a,b,c,d,e,f,g,h)       \
        T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + \
             K256[j] + (W256[j] = *data++); \
        (d) += T1; \
        (h) = T1 + Sigma0_256(a) + Maj((a), (b), (c)); \
        j++

#endif /* SHA2_BYTE_ORDER == SHA2_LITTLE_ENDIAN */

#define ROUND256(a,b,c,d,e,f,g,h)       \
        s0 = W256[(j+1)&0x0f]; \
        s0 = sigma0_256(s0); \
        s1 = W256[(j+14)&0x0f]; \
        s1 = sigma1_256(s1); \
        T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + K256[j] + \
             (W256[j&0x0f] += s1 + W256[(j+9)&0x0f] + s0); \
        (d) += T1; \
        (h) = T1 + Sigma0_256(a) + Maj((a), (b), (c)); \
        j++

void SHA256_Transform(SHA256_CTX* context, const sha2_word32* data) {
  sha2_word32     a, b, c, d, e, f, g, h, s0, s1;
  sha2_word32     T1, *W256;
  int             j;
  
  W256 = (sha2_word32*)context->buffer;
  
  /* Initialize registers with the prev. intermediate value */
  a = context->state[0];
  b = context->state[1];
  c = context->state[2];
  d = context->state[3];
  e = context->state[4];
  f = context->state[5];
  g = context->state[6];
  h = context->state[7];
  
  j = 0;
  do {
    /* Rounds 0 to 15 (unrolled): */
    ROUND256_0_TO_15(a,b,c,d,e,f,g,h);
    ROUND256_0_TO_15(h,a,b,c,d,e,f,g);
    ROUND256_0_TO_15(g,h,a,b,c,d,e,f);
    ROUND256_0_TO_15(f,g,h,a,b,c,d,e);
    ROUND256_0_TO_15(e,f,g,h,a,b,c,d);
    ROUND256_0_TO_15(d,e,f,g,h,a,b,c);
    ROUND256_0_TO_15(c,d,e,f,g,h,a,b);
    ROUND256_0_TO_15(b,c,d,e,f,g,h,a);
  } while (j < 16);
  
  /* Now for the remaining rounds to 64: */
  do {
    ROUND256(a,b,c,d,e,f,g,h);
    ROUND256(h,a,b,c,d,e,f,g);
    ROUND256(g,h,a,b,c,d,e,f);
    ROUND256(f,g,h,a,b,c,d,e);
    ROUND256(e,f,g,h,a,b,c,d);
    ROUND256(d,e,f,g,h,a,b,c);
    ROUND256(c,d,e,f,g,h,a,b);
    ROUND256(b,c,d,e,f,g,h,a);
  } while (j < 64);
  
  /* Compute the current intermediate hash value */
  context->state[0] += a;
  context->state[1] += b;
  context->state[2] += c;
  context->state[3] += d;
  context->state[4] += e;
  context->state[5] += f;
  context->state[6] += g;
  context->state[7] += h;
  
  /* Clean up */
  a = b = c = d = e = f = g = h = T1 = 0;
}

#else /* SHA2_UNROLL_TRANSFORM */

void SHA256_Transform(SHA256_CTX* context, const sha2_word32* data) {
  sha2_word32     a, b, c, d, e, f, g, h, s0, s1;
  sha2_word32     T1, T2, *W256;
  int             j;
  
  W256 = (sha2_word32*)context->buffer;
  
  /* Initialize registers with the prev. intermediate value */
  a = context->state[0];
  b = context->state[1];
  c = context->state[2];
  d = context->state[3];
  e = context->state[4];
  f = context->state[5];
  g = context->state[6];
  h = context->state[7];
  
  j = 0;
  do {
#if SHA2_BYTE_ORDER == SHA2_LITTLE_ENDIAN
    /* Copy data while converting to host byte order */
    REVERSE32(*data++,W256[j]);
    /* Apply the SHA-256 compression function to update a..h */
    T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] + W256[j];
#else /* SHA2_BYTE_ORDER == SHA2_LITTLE_ENDIAN */
    /* Apply the SHA-256 compression function to update a..h with copy */
    T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] + (W256[j] = *data++);
#endif /* SHA2_BYTE_ORDER == SHA2_LITTLE_ENDIAN */
    T2 = Sigma0_256(a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
    
    j++;
  } while (j < 16);
  
  do {
    /* Part of the message block expansion: */
    s0 = W256[(j+1)&0x0f];
    s0 = sigma0_256(s0);
    s1 = W256[(j+14)&0x0f]; 
    s1 = sigma1_256(s1);
    
    /* Apply the SHA-256 compression function to update a..h */
    T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] + 
      (W256[j&0x0f] += s1 + W256[(j+9)&0x0f] + s0);
    T2 = Sigma0_256(a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
    
    j++;
  } while (j < 64);
  
  /* Compute the current intermediate hash value */
  context->state[0] += a;
  context->state[1] += b;
  context->state[2] += c;
  context->state[3] += d;
  context->state[4] += e;
  context->state[5] += f;
  context->state[6] += g;
  context->state[7] += h;
  
  /* Clean up */
  a = b = c = d = e = f = g = h = T1 = T2 = 0;
}

#endif /* SHA2_UNROLL_TRANSFORM */

void SHA256_Update(SHA256_CTX* context, const sha2_byte *data, size_t len) {
  unsigned int    freespace, usedspace;
  
  if (len == 0) {
    /* Calling with no data is valid - we do nothing */
    return;
  }
  
  usedspace = (context->bitcount >> 3) % SHA256_BLOCK_LENGTH;
  
  if (usedspace > 0) {
    /* Calculate how much free space is available in the buffer */
    freespace = SHA256_BLOCK_LENGTH - usedspace;
    
    if (len >= freespace) {
      /* Fill the buffer completely and process it */
      memcpy(&context->buffer[usedspace], data, freespace);
      /* bcopy(data, &context->buffer[usedspace], freespace); */
      context->bitcount += freespace << 3;
      len -= freespace;
      data += freespace;
      SHA256_Transform(context, (sha2_word32*)context->buffer);
    } else {
      /* The buffer is not yet full */
      memcpy(&context->buffer[usedspace], data, len);
      /* bcopy(data, &context->buffer[usedspace], len); */
      context->bitcount += len << 3;
      
      /* Clean up: */
      usedspace = freespace = 0;
      return;
    }
  }
  while (len >= SHA256_BLOCK_LENGTH) {
    /* Process as many complete blocks as we can */
    SHA256_Transform(context, (const sha2_word32*)data);
    context->bitcount += SHA256_BLOCK_LENGTH << 3;
    len -= SHA256_BLOCK_LENGTH;
    data += SHA256_BLOCK_LENGTH;
  }
  if (len > 0) {
    /* There's left-overs, so save 'em */
    memcpy(context->buffer, data, len);
    /* bcopy(data, context->buffer, len); */
    context->bitcount += len << 3;
  }
  /* Clean up: */
  usedspace = freespace = 0;
}

void SHA256_Final(sha2_byte digest[], SHA256_CTX* context) 
{
  sha2_word32     *d = (sha2_word32*)digest;
  unsigned int    usedspace;
  union {
    sha2_word64     bitcount;
    sha2_byte       buffer[sizeof(sha2_word64)];
  } sha2_union;
  
  /* If no digest buffer is passed, we don't bother doing this: */
  if (digest != (sha2_byte*)0) {
    
    usedspace = (context->bitcount >> 3) % SHA256_BLOCK_LENGTH;
    
#if SHA2_BYTE_ORDER == SHA2_LITTLE_ENDIAN
    /* Convert FROM host byte order */
    REVERSE64(context->bitcount,context->bitcount);
#endif
    if (usedspace > 0) {
      /* Begin padding with a 1 bit: */
      context->buffer[usedspace++] = 0x80;
      
      if (usedspace <= SHA256_SHORT_BLOCK_LENGTH) {
	/* Set-up for the last transform: */
	memset(&context->buffer[usedspace], 0, SHA256_SHORT_BLOCK_LENGTH - usedspace);
      } else {
	if (usedspace < SHA256_BLOCK_LENGTH) {
	  memset(&context->buffer[usedspace], 0, SHA256_BLOCK_LENGTH - usedspace);
	}
	/* Do second-to-last transform: */
	SHA256_Transform(context, (sha2_word32*)context->buffer);
	
	/* And set-up for the last transform: */
	memset(context->buffer, 0, SHA256_SHORT_BLOCK_LENGTH);
      }
    } else {
      /* Set-up for the last transform: */
      memset(context->buffer, 0, SHA256_SHORT_BLOCK_LENGTH);
      
      /* Begin padding with a 1 bit: */
      *context->buffer = 0x80;
    }

    /* Set the bit count (with fix for gcc type-punning warning): */
    sha2_union.bitcount = context->bitcount;
    memcpy (&context->buffer[SHA256_SHORT_BLOCK_LENGTH], sha2_union.buffer, sizeof(sha2_word64));
    /* *(sha2_word64*) &context->buffer[SHA256_SHORT_BLOCK_LENGTH] = context->bitcount; */
    
    /* Final transform: */
    SHA256_Transform(context, (sha2_word32*)context->buffer);
    
#if SHA2_BYTE_ORDER == SHA2_LITTLE_ENDIAN
    {
      /* Convert TO host byte order */
      int     j;
      for (j = 0; j < 8; j++) {
	REVERSE32(context->state[j],context->state[j]);
	*d++ = context->state[j];
      }
    }
#else
    memset(d, context->state, SHA256_DIGEST_LENGTH);
    /* bcopy(context->state, d, SHA256_DIGEST_LENGTH); */
#endif
  }
  
  /* Clean up state data: */
  memset(context, 0, sizeof(SHA256_CTX));
  usedspace = 0;
}

#include "sh_utils.h"

/* If buffer is of length KEYBUF_SIZE, the digest will fit */
char *SHA256_End(SHA256_CTX* context, char buffer[]) 
{
  sha2_byte       digest[SHA256_DIGEST_LENGTH];
  
  if (buffer != (char*)0) {
    SHA256_Final(digest, context);
    sh_util_base64_enc ((unsigned char *)buffer, digest,  SHA256_DIGEST_LENGTH);
  } else {
    memset(context, 0, sizeof(SHA256_CTX));
  }
  memset(digest, 0, SHA256_DIGEST_LENGTH);
  return buffer;
}

char* SHA256_Data(const sha2_byte* data, size_t len, char digest[KEYBUF_SIZE]) 
{
  SHA256_CTX      context;
  
  SHA256_Init(&context);
  SHA256_Update(&context, data, len);
  return SHA256_End(&context, digest);
}

char* SHA256_Base2Hex(char * b64digest, char * hexdigest) 
{
  int        i;
  sha2_byte data[512];
  sha2_byte *d;
  size_t     len;
  char * buffer;

  len = strlen(b64digest);
  sh_util_base64_dec ((unsigned char*) data, (unsigned char *)b64digest, len);
  d = data;

  buffer = hexdigest;
  for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    *buffer++ = sha2_hex_digits[(*d & 0xf0) >> 4];
    *buffer++ = sha2_hex_digits[*d & 0x0f];
    d++;
  }
  *buffer = (char)0;

  return hexdigest;
}

char * SHA256_ReplaceBaseByHex(const char * str, char * before, char after)
{
  char   keybuf[KEYBUF_SIZE];
  char * s   = strstr(str, before);

  if (s)
    {
      char * p;

      s += strlen(before);
      memcpy(keybuf, s, sizeof(keybuf));
      keybuf[sizeof(keybuf)-1] = '\0';
      p = strchr(keybuf, after);

      if (p)
	{
	  char   hexbuf[SHA256_DIGEST_STRING_LENGTH];
	  char * ret = SH_ALLOC(strlen(str) + 1 + sizeof(keybuf)); 
	  char * r   = ret;

	  *p = '\0';
	  SHA256_Base2Hex(keybuf, hexbuf);

	  memcpy(ret, str, (s - str));
	  r += (int)(s - str); *r = '\0';
	  strcpy(r, hexbuf); /* flawfinder: ignore */
	  r += strlen(hexbuf);
	  p = strchr(s, after);
	  strcpy(r, p);      /* flawfinder: ignore */

	  return ret;
	}
    }
  return NULL;
}


#ifdef SH_CUTEST
#include <stdlib.h>
#include "CuTest.h"

void Test_sha256 (CuTest *tc) {

  char hexdigest[SHA256_DIGEST_STRING_LENGTH];
  char b64digest[KEYBUF_SIZE];
  char * b64;
  char * buffer;
  size_t len;
  sha2_byte data[512];
  sha2_byte *d;
  int        i;

  data[0] = '\0'; len = 0;
  b64 = SHA256_Data(data, len, b64digest);
  CuAssertPtrNotNull(tc, b64);

  len = strlen((char*)b64);
  sh_util_base64_dec (data, (unsigned char*)b64, len);
  d = data;
  buffer = hexdigest;
  for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    *buffer++ = sha2_hex_digits[(*d & 0xf0) >> 4];
    *buffer++ = sha2_hex_digits[*d & 0x0f];
    d++;
  }
  *buffer = (char)0;
  CuAssertStrEquals(tc, hexdigest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

  memset(hexdigest, 0, sizeof(hexdigest));
  buffer = SHA256_Base2Hex(b64digest, hexdigest);
  CuAssertPtrNotNull(tc, buffer);
  CuAssertStrEquals(tc, hexdigest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  CuAssertStrEquals(tc,    buffer, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

  strcpy((char*)data, "The quick brown fox jumps over the lazy dog"); len = strlen((char*)data);
  b64 = SHA256_Data(data, len, b64digest);
  CuAssertPtrNotNull(tc, b64);

  len = strlen((char*)b64);
  sh_util_base64_dec (data, (unsigned char*)b64, len);
  d = data;
  buffer = hexdigest;
  for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    *buffer++ = sha2_hex_digits[(*d & 0xf0) >> 4];
    *buffer++ = sha2_hex_digits[*d & 0x0f];
    d++;
  }
  *buffer = (char)0;
  CuAssertStrEquals(tc, hexdigest, "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");

  strcpy((char*)data, "The quick brown fox jumps over the lazy dog."); len = strlen((char*)data);
  b64 = SHA256_Data(data, len, b64digest);
  CuAssertPtrNotNull(tc, b64);

  len = strlen((char*)b64);
  sh_util_base64_dec (data, (unsigned char*)b64, len);
  d = data;
  buffer = hexdigest;
  for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    *buffer++ = sha2_hex_digits[(*d & 0xf0) >> 4];
    *buffer++ = sha2_hex_digits[*d & 0x0f];
    d++;
  }
  *buffer = (char)0;
  CuAssertStrEquals(tc, hexdigest, "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c");

}

#endif
