#include "config.h"


#include <stdlib.h>
#include <stdio.h>
#include <time.h>


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

#if 0
static UINT32 cstate[3], astate[3];
 
/* interval [0, 4294967296]
 */       
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
#endif


/* Work-memory needed for compression. Allocate memory in units
 * of `long' (instead of `char') to make sure it is properly aligned.
 */
#define HEAP_ALLOC(var,size) \
        long __LZO_MMODEL var [ ((size) + (sizeof(long) - 1)) / sizeof(long) ]

static HEAP_ALLOC(wrkmem,LZO1X_1_MEM_COMPRESS);

#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) 
{

  FILE * fd;
  FILE * fd_out;

  struct stat     sbuf;

  int             num = -1;

  unsigned long   i;
  unsigned long   len  = 0;
  unsigned long   have = 0;

  /* For compression.
   */
  lzo_byte * inbuf;
  lzo_byte * outbuf;
  int        r;
  lzo_uint   in_len;
  lzo_uint   out_len;


#if 0
  astate[0] = EXEPACK_STATE_0;
  astate[1] = EXEPACK_STATE_1;
  astate[2] = EXEPACK_STATE_2;
#endif

  if (argc < 4  || (num = atoi(argv[3])) < 0)
    {
      fprintf(stderr, 
	      "Usage: exepack_mkdata <infile> <outfile> <num> [ARGS]\n");
      exit (EXIT_FAILURE);
    }

  /* the include file 
   */
  if (NULL == (fd_out = fopen(argv[2], "w")) )
    {
      fprintf(stderr, "exepack_mkdata: Error opening %s for write.\n", 
	      argv[2]);
      exit (EXIT_FAILURE);
    }


  /* write data
   */
  fprintf (fd_out, "UINT32 programkey_%d[3] = { 0x%x, 0x%x, 0x%x };\n", 
	   num, EXEPACK_STATE_0, EXEPACK_STATE_1, EXEPACK_STATE_2);

  if (num == 0)
    {
      fprintf (fd_out, "UINT32 programlen_%d = %ld;\n\n", 
	       num, 0x4C4C4C4CL);
      fprintf (fd_out, "UINT32 programlen_compressed_%d = %ld;\n\n", 
	       num, 0x43434343L);
    }
  else
    {
      fprintf (fd_out, "UINT32 programlen_%d = %ld;\n\n", 
	       num, 0x4D4D4D4DL);
      fprintf (fd_out, "UINT32 programlen_compressed_%d = %ld;\n\n", 
	       num, 0x44444444L);
    }


  if (stat (argv[1], &sbuf) < 0)
    {
      perror ("exepack_mkdata");
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
      fprintf(stderr, "exepack_mkdata: Out of memory.");
      exit (EXIT_FAILURE);
    }

  if (NULL == (fd = fopen(argv[1], "r")))
    {
      perror ("exepack_mkdata");
      exit (EXIT_FAILURE);
    }

  have = fread  (inbuf, 1, len, fd);
  fclose (fd);

  if (have != len)
    {
      fprintf (stderr, "exepack_mkdata: Error reading %s", argv[1]);
      exit (EXIT_FAILURE);
    }

  /*
   * Step 1: initialize the LZO library
   */
  if (lzo_init() != LZO_E_OK)
    {
      fprintf(stderr, "exepack_mkdata: lzo_init() failed\n");
      return 3;
    }

  /*
   * Step 3: compress from `in' to `out' with LZO1X-1
   */
  r = lzo1x_1_compress(inbuf, in_len, outbuf, &out_len, wrkmem);

  if (r == LZO_E_OK)
    printf("exepack_mkdata: compressed %lu bytes into %lu bytes\n",
	   (long) in_len, (long) out_len);
  else
    {
      /* this should NEVER happen */
      printf("exepack_mkdata: internal error - compression failed: %d\n", r);
      return 2;
    }

  /* check for an incompressible block 
   */
  if (out_len >= in_len)
    {
      printf("exepack_mkdata: Incompressible data.\n");
    }
  
  fprintf (fd_out, "lzo_byte program_%d[] = {\n", num);

  fprintf (fd_out, "0x43, 0x4F, 0x4E, 0x54, 0x41, 0x49, 0x4E, 0x45, 0x52,\n");

  /*
  taus_set_from_state (cstate, astate);
  for (i = 0; i < out_len; ++i)
    {
      outbuf[i] =^ (taus_get_long (cstate) & 0xff);
    }
  */


  for (i = 1; i <= out_len; ++i)
    {
      fprintf(fd_out, "0x00,");
      if (0 == (i % 20)) 
	fprintf(fd_out, "\n");
    }
      
  fprintf(fd_out, "\n");

  for (i = 1; i <= 256; ++i)
    {
      fprintf(fd_out, "0x00,");
      if (0 == (i % 20)) 
	fprintf(fd_out, "\n");
    }

  fprintf (fd_out, "0x00 };\n\n");


  fclose (fd_out);

  if (argc > 4)
    {
      fprintf (fd_out, "char * const programargv_%d[]={\n", num);

      for(len = 4; len < (unsigned int) argc; len++) 
	fprintf(fd_out, "\"%s\",", argv[len-4]);

      fprintf(fd_out, "NULL };\n\n");
    }

  return 0;
}
