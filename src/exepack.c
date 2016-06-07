#include "config.h"


#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

extern char **environ;


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


#include "exepack.data"


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

void set2 (char * pos, char c1, char c2)
{
  pos[0] = c1;
  pos[1] = c2;
  return;
}
  
void set4 (char * pos, char c1, char c2, char c3, char c4)
{
  pos[0] = c1;
  pos[1] = c2;
  pos[2] = c3;
  pos[3] = c4;
  return;
}

int main(int argc, char *argv[]) 
{
  int file;
  long result;

  unsigned long i    = argc; /* dummy use of argc to fix compiler warning */
  unsigned long len  = 0;

  struct stat sbuf;
  struct stat fbuf;

  /* For compression.
   */
  lzo_byte *    inbuf;
  lzo_byte *    outbuf;
  int           r;
  lzo_uint      in_len;
  lzo_uint      out_len;


  char *        p;

  char          fname[128];
#if defined (__linux__)
  char          pname[128];
#endif

  UINT32        pid;

  /* no SUID
   */
  if (getuid() != geteuid())
    {
      setuid(getuid());
    }

  /* reset umask 
   */
  umask(0);


  astate[0] = programkey_0[0];
  astate[1] = programkey_0[1];
  astate[2] = programkey_0[2];

  taus_set_from_state (cstate, astate);

  out_len = (unsigned long) programlen_compressed_0;
  len     = (unsigned long) programlen_0;
  in_len  = len;

  outbuf  = program_0;

  /* Decode.
   */
  for (i = 0; i < out_len; ++i)
    {
      outbuf[i] ^= (taus_get_long (cstate) & 0xff);
    }


  inbuf  = (lzo_byte *) malloc (sizeof(lzo_byte) * len);


  /*
   * Step 1: initialize the LZO library
   */
  if (lzo_init() != LZO_E_OK)
    {
      return 1;
    }

  /*
   * Step 2: decompress again, now going from `out' to `in'
   */
  r = lzo1x_decompress_safe (outbuf, out_len, inbuf, &in_len, NULL);

  if (r == LZO_E_OK && in_len == len)
    {
      /*
      printf("decompressed %lu bytes back into %lu bytes\n",
	     (long) out_len, (long) in_len);
      */
      ;
    }
  else
    {
      /*
      printf("internal error - decompression failed: %d\n", 
	     r);
      */
      return 2;
    }

  /*
   * Step 3: choose a filename
   */

 nameIt:

  p  = fname;

  /* --- use /tmp if the sticky bit is set ---
   */
#if defined(S_ISVTX)

  set4 (p, '/', 't', 'm', 'p');
  p += 4;
  *p = '\0';

  if ( 0 != stat(fname, &sbuf))
    {
      if ( (sbuf.st_mode & S_ISVTX) != S_ISVTX)
	{
	  p  = fname;
	  set4 (p, '/', 'u', 's', 'r');
	  p += 4;
	  set4 (p, '/', 'b', 'i', 'n');
	  p += 4;
	}
    }

#else

  set4 (p, '/', 'u', 's', 'r');
  p += 4;
  set4 (p, '/', 'b', 'i', 'n');
  p += 4;

#endif

  set4 (p, '/', 't', 'm', 'p');

  p += 4;

  cstate[0] ^= (UINT32) getpid ();
  cstate[1] ^= (UINT32) time (NULL);
  cstate[0] |= (UINT32) 0x03;
  cstate[1] |= (UINT32) 0x09;

  pid = (UINT32) (taus_get_long (cstate) ^ taus_get_long (cstate));

  for (i = 0; i < 4; ++i)
    {
      *p = 'a' + (pid % 26);
      pid /= 26;
      ++p;
    }

  pid = (UINT32) (taus_get_long (cstate) ^ taus_get_long (cstate));

  for (i = 0; i < 4; ++i)
    {
      *p = 'a' + (pid % 26);
      pid /= 26;
      ++p;
    }

  pid = (UINT32) (taus_get_long (cstate) ^ taus_get_long (cstate));

  for (i = 0; i < 3; ++i)
    {
      *p = 'a' + (pid % 26);
      pid /= 26;
      ++p;
    }
  *p = '\0';

  if ( (-1) != stat(fname, &sbuf) || errno != ENOENT)
    {
      /* because cstate[2] is not initialized, the next name will
       * be different
       */
      goto nameIt;
    } 
      
  if ((file = open (fname, O_CREAT|O_EXCL|O_WRONLY, 0700)) < 0)
    {
      return (4);
    } 

  result = (long) write(file, inbuf, in_len);
  if (result < 0 || in_len != (lzo_uint) result)
    {
      return (5);
    }

#if defined(__linux__)

  if ( 0 != fstat(file, &sbuf))
    {
      return (6);
    } 
  
  /* Must reopen for read only.
   */
  close(file);
  file = open (fname, O_RDONLY, 0);

  if ( 0 != fstat(file, &fbuf))
    {
      return (7);
    } 

  /* check mode, inode, owner, and device, to make sure it is the same file
   */
  if (sbuf.st_mode != fbuf.st_mode || 
      sbuf.st_ino  != fbuf.st_ino  || 
      sbuf.st_uid  != fbuf.st_uid  ||
      sbuf.st_gid  != fbuf.st_gid  ||
      sbuf.st_dev  != fbuf.st_dev )
    {
      close  ( file );
      return ( 8 );
    }
  
  p = pname;
  set4(p, '/', 'p', 'r', 'o');
  p += 4;

  set2(p, 'c', '/');
  p += 2;

  set4(p, 's', 'e', 'l', 'f');
  p += 4;

  set4(p, '/', 'f', 'd', '/');
  p += 4;

  sprintf(p, "%d", file);


  if (0 == access(pname, R_OK|X_OK))
    {
      unlink (fname);
      fcntl  (file, F_SETFD, FD_CLOEXEC);
      execve (pname, argv, environ); 
      return (9);
    }
#endif

  /* /proc not working, or not linux
   */
  close (file);

  if ( (i = fork()) != 0) 
    {
      wait   (NULL);
      execve (fname, argv, environ);
      unlink (fname);
      return (10);
    } 
  else if (i == 0)
    {
      if (0 == fork())
	{
	  sleep  (3);
	  unlink (fname);
	}
      return (0);
    }

  /* only reached in case of error 
   */
  unlink (fname);
  return (-1);
}

