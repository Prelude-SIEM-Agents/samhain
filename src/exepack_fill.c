/* +++Date last modified: 05-Jul-1997 */

/*
**  Case-sensitive Boyer-Moore-Horspool pattern match
**
**  public domain by Raymond Gardner 7/92
**
**  limitation: pattern length + string length must be less than 32767
**
**  10/21/93 rdg  Fixed bug found by Jeff Dunlop
**
**  limitation lifted Rainer Wichmann 07/2000
*/
#include "config.h"

#ifdef HAVE_BROKEN_INCLUDES
#define _ANSI_C_SOURCE
#define _POSIX_SOURCE
#endif

#include <limits.h>                                         /* rdg 10/93 */
#include <stddef.h>
#include <string.h>

typedef unsigned char uchar;

#define LARGE 2147483647     /* rw 7/2000 */

static long patlen;            /* rw 7/2000 */
static long skip[UCHAR_MAX+1]; /* rw 7/2000 */     /* rdg 10/93 */
static long skip2;             /* rw 7/2000 */
static uchar *pat;             /* rw 7/2000 */

void bmh_init(const char *pattern)
{
  long i, lastpatchar;
  
  pat = (uchar *)pattern;
  patlen = strlen(pattern);
  for (i = 0; i <= UCHAR_MAX; ++i)                  /* rdg 10/93 */
    skip[i] = patlen;
  for (i = 0; i < patlen; ++i)
    skip[pat[i]] = patlen - i - 1;
  lastpatchar = pat[patlen - 1];
  skip[lastpatchar] = LARGE;
  skip2 = patlen;                 /* Horspool's fixed second shift */
  for (i = 0; i < patlen - 1; ++i)
    {
      if (pat[i] == lastpatchar)
	skip2 = patlen - i - 1;
    }
}

char * bmh_search(const char * string, const long stringlen)
{
  long i, j; /* rw 7/2000 */
  char *s;
  
  i = patlen - 1 - stringlen;
  if (i >= 0)
    return NULL;
  string += stringlen;
  for ( ;; )
    {
      while ( (i += skip[((uchar *)string)[i]]) < 0 )
	;                           /* mighty fast inner loop */
      if (i < (LARGE - stringlen))
	return NULL;
      i -= LARGE;
      j = patlen - 1;
      s = (char *)string + (i - j);
      while (--j >= 0 && s[j] == pat[j])
	;
      if ( j < 0 )                                    /* rdg 10/93 */
	return s;                                 /* rdg 10/93 */
      if ( (i += skip2) >= 0 )                        /* rdg 10/93 */
	return NULL;                              /* rdg 10/93 */
    }
}

/* Everything below: Copyright 2000, Rainer Wichmann  */

char * my_locate (const char * pattern, const char * data, const long datalen)
{
  bmh_init (pattern);
  return   (bmh_search (data, datalen) );
}

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>


#include "config.h"

#include "minilzo.h"

/* integer data type that is _exactly_ 32 bit
 */
#if defined(HAVE_INT_32)
#define UINT32 unsigned int
#elif defined(HAVE_LONG_32)
#define UINT32 unsigned long
#elif defined(HAVE_SHORT_32)
#define UINT32 unsigned short
#endif

static UINT32 cstate[3], astate[3];

static UINT32 taus_get_long (UINT32 * state)
{
#define TAUSWORTHE(s,a,b,c,d) ((s &c) <<d) ^ (((s <<a) ^s) >>b)

  state[0] = TAUSWORTHE (state[0], 13, 19, 4294967294UL, 12);
  state[1] = TAUSWORTHE (state[1],  2, 25, 4294967288UL,  4);
  state[2] = TAUSWORTHE (state[2],  3, 11, 4294967280UL, 17);

  return (state[0] ^ state[1] ^ state[2]);
}

void taus_set_from_state (UINT32 * state, UINT32 * state0)
{
  state[0] = state0[0]  | (UINT32) 0x03;
  state[1] = state0[1]  | (UINT32) 0x09;
  state[2] = state0[2]  | (UINT32) 0x17;
  
  /* 'warm up'
   */
  taus_get_long (state);
  taus_get_long (state);
  taus_get_long (state);
  taus_get_long (state);
  taus_get_long (state);
  taus_get_long (state);

  return;
}

int replaceData (char * data, long len, char * in, char * out, long size)
{
  char * pos;
  int    i;

  pos = my_locate (in, data, len);
  if (pos == NULL)
    return (-1);
  
  for (i = 0; i < size; ++i)
    {
      pos[i] = out[i];
    }

  return 0;
}

/* Work-memory needed for compression. Allocate memory in units
 * of `long' (instead of `char') to make sure it is properly aligned.
 */
#define HEAP_ALLOC(var,size) long __LZO_MMODEL var [ ((size) + (sizeof(long) - 1)) / sizeof(long) ]

static HEAP_ALLOC(wrkmem, LZO1X_1_MEM_COMPRESS);

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char * argv[])
{
  FILE * fd;
  unsigned long   clen;
  char * data;
  struct stat sbuf;

  char * ptest;

  unsigned long   i;

  int    status;

  unsigned long   len  = 0;
  unsigned long   have = 0;

  /* For compression.
   */
  lzo_byte * inbuf;
  lzo_byte * outbuf;
  int        r;
  lzo_uint   in_len;
  lzo_uint   out_len;

  UINT32 len_raw;
  UINT32 len_cmp;


  astate[0] = EXEPACK_STATE_0;
  astate[1] = EXEPACK_STATE_1;
  astate[2] = EXEPACK_STATE_2;


  if (argc < 4)
    {
      fprintf(stderr, 
	      "Usage: exepack_fill <container_file> <infile> <outfile>\n");
      exit (EXIT_FAILURE);
    }

  if (0 != stat (argv[1], &sbuf))
    {
      fprintf(stderr, "exepack_fill: could not access file %s\n", argv[1]); 
      return (-1);
    }
  clen = sbuf.st_size;


  data = (char *) malloc (clen * sizeof(char));
  if (data == NULL)
    return (-1);

  fd = fopen (argv[1], "r");
  if (fd == NULL)
    return (-1);

  if (clen != fread  (data, 1, clen, fd))
    return (-1);
  fclose (fd);


  /*******************
   *
   * THE DATA
   *
   *******************/



  if (stat (argv[2], &sbuf) < 0)
    {
      perror ("exepack_fill");
      exit (EXIT_FAILURE);
    }
      
  len = (unsigned long) sbuf.st_size;

  /* Because the input block may be incompressible,
   * we must provide a little more output space in case that compression
   * is not possible.
   */
  inbuf  = (lzo_byte *) malloc (sizeof(lzo_byte) * len);
  outbuf = (lzo_byte *) malloc (sizeof(lzo_byte) * (len + len / 64 + 16 + 3));
  in_len = len;

  if (NULL == inbuf || NULL == outbuf)
    {
      fprintf(stderr, "exepack_fill: Out of memory.");
      exit (EXIT_FAILURE);
    }

  if (NULL == (fd = fopen(argv[2], "r")))
    {
      perror ("exepack_fill");
      exit (EXIT_FAILURE);
    }

  have = fread  (inbuf, 1, len, fd);
  fclose (fd);

  if (have != len)
    {
      fprintf (stderr, "exepack_mkdata: Error reading %s", argv[2]);
      exit (EXIT_FAILURE);
    }

  /*
   * Step 1: initialize the LZO library
   */
  if (lzo_init() != LZO_E_OK)
    {
      fprintf(stderr, "exepack_fill: lzo_init() failed\n");
      return 3;
    }

  /*
   * Step 3: compress from `in' to `out' with LZO1X-1
   */
  r = lzo1x_1_compress(inbuf, in_len, outbuf, &out_len, wrkmem);

  if (r == LZO_E_OK)
    printf("exepack_fill: compressed %lu bytes into %lu bytes\n",
	   (long) in_len, (long) out_len);
  else
    {
      /* this should NEVER happen */
      printf("exepack_fill: internal error - compression failed: %d\n", r);
      return 2;
    }

  /* check for an incompressible block 
   */
  if (out_len >= in_len)
    {
      printf("exepack_fill: Incompressible data.\n");
    }
  
  taus_set_from_state (cstate, astate);
  for (i = 0; i < out_len; ++i)
    {
      outbuf[i] ^= (taus_get_long (cstate) & 0xff);
    }

  len_raw = in_len;
  len_cmp = out_len;

  if ( (unsigned long) len_cmp > (unsigned long) clen)
    {
      printf("exepack_fill: Compressed length (%ld) exceeds container length (%ld).\n", (long) len_cmp, (long) clen);
      return (8);
    }
      

  /***********
   *
   * Fill program
   *
   **********/

  status = replaceData (data, clen, "LLLL", (char *) &len_raw, sizeof(UINT32));
  if (status < 0)
    {
      printf("exepack_fill: Could not write raw lenght %d.\n", len_raw);
      return (8);
    }
  status = replaceData (data, clen, "CCCC", (char *) &len_cmp, sizeof(UINT32));
  if (status < 0)
    {
      printf("exepack_fill: Could not write compressed lenght %d.\n", 
	     len_cmp);
      return (8);
    }
  status = replaceData (data, clen, "CONTAINER", (char *) outbuf, out_len);
  if (status < 0)
    {
      printf("exepack_fill: Could not write program data.\n");
      return (8);
    }

  /***********
   *
   * Write program
   *
   **********/

  if ( NULL == (fd = fopen(argv[3], "w" )))
    {
      perror ("exepack_fill");
      exit (EXIT_FAILURE);
    }

  fwrite  (data, 1, clen, fd);

  fclose (fd);

  ptest = my_locate("LLLL", data, clen);
  if (ptest != NULL)
    {
      printf("exepack_fill: ERROR:  program length not updated.\n");
      return (8);
    }
  ptest = my_locate("CCCC", data, clen);
  if (ptest != NULL)
    {
      printf("exepack_fill: ERROR:  compressed program length not updated.\n");
      return (8);
    }
  ptest = my_locate("CONTAINER", data, clen);
  if (ptest != NULL)
    {
      printf("exepack_fill: ERROR:  program data not updated.\n");
      return (8);
    }

  return 0;
}

