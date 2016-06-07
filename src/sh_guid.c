/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2015 Rainer Wichmann                                      */
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
#include "sh_utils.h"

#include <stdio.h>
#include <string.h>

/*
 * gen_uuid.c --- generate a DCE-compatible uuid
 *
 * Copyright (C) 1996, 1997, 1998, 1999 Theodore Ts'o.
 *
 * %Begin-Header%
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 * %End-Header%
 */

#define UUID_SIZE 36

struct uuid {
        UINT32        time_low;
        UINT16        time_mid;
        UINT16        time_hi_and_version;
        UINT16        clock_seq;
        UBYTE node[6];
};

typedef unsigned char uuid_t[16];


static void uuid_pack(const struct uuid *uu, uuid_t ptr)
{
  UINT32          tmp;
  unsigned char   *out = ptr;
  
  tmp = uu->time_low;
  out[3] = (unsigned char) tmp;
  tmp >>= 8;
  out[2] = (unsigned char) tmp;
  tmp >>= 8;
  out[1] = (unsigned char) tmp;
  tmp >>= 8;
  out[0] = (unsigned char) tmp;
  
  tmp = uu->time_mid;
  out[5] = (unsigned char) tmp;
  tmp >>= 8;
  out[4] = (unsigned char) tmp;
  
  tmp = uu->time_hi_and_version;
  out[7] = (unsigned char) tmp;
  tmp >>= 8;
  out[6] = (unsigned char) tmp;
  
  tmp = uu->clock_seq;
  out[9] = (unsigned char) tmp;
  tmp >>= 8;
  out[8] = (unsigned char) tmp;
  
  memcpy(out+10, uu->node, 6);
  return;
}

static void uuid_unpack(const uuid_t in, struct uuid *uu)
{
  const uint8_t	*ptr = in;
  uint32_t		tmp;
  
  tmp = *ptr++;
  tmp = (tmp << 8) | *ptr++;
  tmp = (tmp << 8) | *ptr++;
  tmp = (tmp << 8) | *ptr++;
  uu->time_low = tmp;
  
  tmp = *ptr++;
  tmp = (tmp << 8) | *ptr++;
  uu->time_mid = tmp;
  
  tmp = *ptr++;
  tmp = (tmp << 8) | *ptr++;
  uu->time_hi_and_version = tmp;
  
  tmp = *ptr++;
  tmp = (tmp << 8) | *ptr++;
  uu->clock_seq = tmp;
  
  memcpy(uu->node, ptr, 6);
  return;
}

static void get_random_bytes(unsigned char * buf, size_t len)
{
  unsigned int j;

  union {
    UINT32 i;
    char c[sizeof(UINT32)];
  } u;

  do {
    u.i = taus_get();

    for (j= 0; j < sizeof(UINT32); j++)
      {
	if (len) {
	  --len;
	  *buf = u.c[j];
	  ++buf;
	}
      }
  } while (len);

  return;
}

static void uuid_generate_random(uuid_t out)
{
  uuid_t  buf;
  struct uuid uu;

  get_random_bytes(buf, sizeof(buf));
  uuid_unpack(buf, &uu);

  /* Version and variant 
   */
  uu.clock_seq = (uu.clock_seq & 0x3FFF) | 0x8000;
  uu.time_hi_and_version = (uu.time_hi_and_version & 0x0FFF)
    | 0x4000;
  uuid_pack(&uu, out);
  return;
}

static const char *fmt_lower =	N_("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x");

static void uuid_unparse(const uuid_t uu, char *out, size_t len)
{
  struct uuid uuid;
  char fmt[80];
  

  sl_strlcpy(fmt, _(fmt_lower), sizeof(fmt));

  uuid_unpack(uu, &uuid);

  sl_snprintf (out, len, fmt,
	       uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
	       uuid.clock_seq >> 8, uuid.clock_seq & 0xFF,
	       uuid.node[0], uuid.node[1], uuid.node[2],
	       uuid.node[3], uuid.node[4], uuid.node[5]);

  return;
}

#if defined(__linux__)
static char * uuid_generate_random_linux(char * out, size_t len)
{
  FILE * fd = fopen(_("/proc/sys/kernel/random/uuid"), "r");

  if (fd)
    {
      if (NULL != fgets(out, len, fd))
	{
	  size_t ll = strlen(out);
	  if (ll > 0 && out[ll-1] == '\n') {
	    --ll;
	    out[ll] = '\0';
	  }
	}
      fclose(fd);
    }
  return out;
}
#endif

static char * uuid_generate_random_gen(char * out, size_t len)
{
  uuid_t u;

  uuid_generate_random(u);
  uuid_unparse(u, out, len);

  return out;
}

char * sh_uuid_generate_random(char * out, size_t len)
{
  *out = '\0';

#if defined(__linux__)
  uuid_generate_random_linux(out, len);
  if (UUID_SIZE == strlen(out))
    return out;
#endif

  uuid_generate_random_gen(out, len);
  return out;
}

#include <ctype.h>
int sh_uuid_check(const char * in)
{
  int 		i;
  const char	*cp;

  if (strlen(in) != UUID_SIZE)
    return -1;
  for (i=0, cp = in; i <= UUID_SIZE; i++,cp++) {
    if ((i == 8) || (i == 13) || (i == 18) ||
	(i == 23)) {
      if (*cp == '-')
	continue;
      else
	return -1;
    }
    if (i== UUID_SIZE)
      if (*cp == 0)
	continue;
    if (!isxdigit(*cp))
      return -1;
  }
  return 0;
}


#ifdef SH_CUTEST
#include "CuTest.h"

#include <stdlib.h>

static int uuid_type(const uuid_t uu)
{
  struct uuid		uuid;
  
  uuid_unpack(uu, &uuid);
  return ((uuid.time_hi_and_version >> 12) & 0xF);
}

#define UUID_VARIANT_NCS	0
#define UUID_VARIANT_DCE	1
#define UUID_VARIANT_MICROSOFT	2
#define UUID_VARIANT_OTHER	3

#define UUID_TYPE_DCE_TIME   1
#define UUID_TYPE_DCE_RANDOM 4

static int uuid_variant(const uuid_t uu)
{
  struct uuid		uuid;
  int			var;
  
  uuid_unpack(uu, &uuid);
  var = uuid.clock_seq;
  
  if ((var & 0x8000) == 0)
    return UUID_VARIANT_NCS;
  if ((var & 0x4000) == 0)
    return UUID_VARIANT_DCE;
  if ((var & 0x2000) == 0)
    return UUID_VARIANT_MICROSOFT;
  return UUID_VARIANT_OTHER;
}

static int uuid_parse(const char *in, uuid_t uu)
{
  struct uuid	uuid;
  int 		i;
  const char	*cp;
  char		buf[3];
  
  if (sh_uuid_check(in) < 0)
    return -1;
    
  uuid.time_low = strtoul(in, NULL, 16);
  uuid.time_mid = strtoul(in+9, NULL, 16);
  uuid.time_hi_and_version = strtoul(in+14, NULL, 16);
  uuid.clock_seq = strtoul(in+19, NULL, 16);
  cp = in+24;
  buf[2] = 0;
  for (i=0; i < 6; i++) {
    buf[0] = *cp++;
    buf[1] = *cp++;
    uuid.node[i] = strtoul(buf, NULL, 16);
  }
  
  uuid_pack(&uuid, uu);
  return 0;
}

void Test_uuid (CuTest *tc) {

  char * p; int res;
  char out[80];
  size_t len = sizeof(out);
  uuid_t uu;
  int type, variant;

  p = uuid_generate_random_gen(out, len);
  CuAssertPtrNotNull(tc, p);
  res = strlen(p);
  CuAssertIntEquals(tc,UUID_SIZE,res);
  res = uuid_parse(p, uu);
  CuAssertIntEquals(tc,0,res);
  type = uuid_type(uu); 
  CuAssertIntEquals(tc,UUID_TYPE_DCE_RANDOM,type);
  variant = uuid_variant(uu);
  CuAssertIntEquals(tc,UUID_VARIANT_DCE,variant);

#if defined(__linux__)
  p = uuid_generate_random_linux(out, len);
  CuAssertPtrNotNull(tc, p);
  res = strlen(p);
  CuAssertIntEquals(tc,UUID_SIZE,res);
  res = uuid_parse(p, uu);
  CuAssertIntEquals(tc,0,res);
  type = uuid_type(uu); 
  CuAssertIntEquals(tc,UUID_TYPE_DCE_RANDOM,type);
  variant = uuid_variant(uu);
  CuAssertIntEquals(tc,UUID_VARIANT_DCE,variant);
#endif

  p = sh_uuid_generate_random(out, len);
  CuAssertPtrNotNull(tc, p);
  res = strlen(p);
  CuAssertIntEquals(tc,UUID_SIZE,res);
  res = uuid_parse(p, uu);
  CuAssertIntEquals(tc,0,res);
  type = uuid_type(uu); 
  CuAssertIntEquals(tc,UUID_TYPE_DCE_RANDOM,type);
  variant = uuid_variant(uu);
  CuAssertIntEquals(tc,UUID_VARIANT_DCE,variant);

}
#endif
