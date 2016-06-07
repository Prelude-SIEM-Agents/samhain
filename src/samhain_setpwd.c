#include "config_xor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>

#if defined(HAVE_SCHED_H) && defined(HAVE_SCHED_YIELD)
#include <sched.h>
#endif

#if defined(HAVE_INT_32)
typedef unsigned int UINT32;
#elif defined(HAVE_LONG_32)
typedef unsigned long UINT32;
#elif defined(HAVE_SHORT_32)
typedef unsigned short UINT32;
#endif

#define TAUS_MAX 4294967295UL

static UINT32 taus_state[3];

static UINT32 taus_get ()
{

#define TAUSWORTHE(s,a,b,c,d) ((s &c) <<d) ^ (((s <<a) ^s) >>b)
  taus_state[0] = TAUSWORTHE (taus_state[0], 13, 19, 4294967294UL, 12);
  taus_state[1] = TAUSWORTHE (taus_state[1],  2, 25, 4294967288UL,  4);
  taus_state[2] = TAUSWORTHE (taus_state[2],  3, 11, 4294967280UL, 17);
  return (taus_state[0] ^ taus_state[1] ^ taus_state[2]);
}

static void taus_seed ()
{
  unsigned char buf[12];
  unsigned char buf2[12];
  unsigned char buf3[12];
  ssize_t count;
  size_t nbytes = sizeof(buf);
  size_t where  = 0;

  struct timeval t1, t2;
  UINT32 delta, k[3];
  int i, j;

  int fd = open ("/dev/urandom", O_RDONLY);

  if (fd == -1)
    {
      gettimeofday(&t1, NULL);
      delta = t1.tv_usec;
      memcpy(&buf[0], &delta, 4);
      gettimeofday(&t1, NULL);
      delta = t1.tv_usec;
      memcpy(&buf[4], &delta, 4);
      gettimeofday(&t1, NULL);
      delta = t1.tv_usec;
      memcpy(&buf[8], &delta, 4);
      goto second;
    }

  do {
    count = read(fd, &buf[where], nbytes);
    if (count == -1 && errno == EINTR)
      continue;
    where  += count;
    nbytes -= count;
  } while (nbytes);

  close(fd);

 second:
  for (i = 0; i < 12; ++i)
    {
      gettimeofday(&t1, NULL);
      if (0 == fork())
	_exit(EXIT_SUCCESS);
      wait(NULL);
      gettimeofday(&t2, NULL);
      delta = t2.tv_usec - t1.tv_usec;
      buf2[i] = (unsigned char) delta;
    }

  for (i = 0; i < 12; ++i)
    {
      gettimeofday(&t1, NULL);
      for (j = 0; j < 32768; ++j)
	{
	  if (0 == kill (j,0))
	    k[i % 3] ^= j;
	}
      gettimeofday(&t2, NULL);
      delta = t2.tv_usec - t1.tv_usec;
      buf3[i] ^= (unsigned char) delta;
    }

  memcpy(&taus_state[0], &buf3[0], 4);
  memcpy(&taus_state[1], &buf3[4], 4);
  memcpy(&taus_state[2], &buf3[8], 4);

  taus_state[0] ^= k[0];
  taus_state[1] ^= k[1];
  taus_state[2] ^= k[2];
  
  memcpy(&k[0], &buf2[0], 4);
  memcpy(&k[1], &buf2[4], 4);
  memcpy(&k[2], &buf2[8], 4);

  taus_state[0] ^= k[0];
  taus_state[1] ^= k[1];
  taus_state[2] ^= k[2];
  
  memcpy(&k[0], &buf[0], 4);
  memcpy(&k[1], &buf[4], 4);
  memcpy(&k[2], &buf[8], 4);

  taus_state[0] ^= k[0];
  taus_state[1] ^= k[1];
  taus_state[2] ^= k[2];

  taus_state[0] |= (UINT32) 0x03;
  taus_state[1] |= (UINT32) 0x09;
  taus_state[2] |= (UINT32) 0x17;
}

#ifdef SH_STEALTH
char * globber(const char * string);
#define _(string) globber(string) 
#define N_(string) string
#else
#define _(string)  string 
#define N_(string) string
#endif

#ifdef SH_STEALTH
#ifndef SH_MAX_GLOBS
#define SH_MAX_GLOBS 32
#endif
char * globber(const char * str)
{
  register int i, j;
  static int  count = -1;
  static char glob[SH_MAX_GLOBS][128];

  ++count; if (count > (SH_MAX_GLOBS-1) ) count = 0;
  j = strlen(str);
  if (j > 127) j = 127;

  for (i = 0; i < j; ++i)
    {
      if (str[i] != '\n' && str[i] != '\t') 
	glob[count][i] = str[i] ^ XOR_CODE;
      else
	glob[count][i] = str[i];
    }
  glob[count][j] = '\0';
  return glob[count];
}
#endif

/* This is a very inefficient algorithm, but there is really no
 * need for anything more elaborated here. Can handle NULL's in haystack
 * (not in needle), which strstr() apparently cannot.
 */
char * my_strstr (char * haystack, char * needle, int haystack_size)
{
  register int      i = 0, j = 0;
  register int      siz;
  register char * ptr = haystack;
  register int      len;

  siz = strlen(needle);
  len = haystack_size - siz;

  while (j < len)
    {
      i = 0;
      while (i < siz)
	{
	  if (needle[i] != ptr[i]) break;
	  if (i == (siz-1)) 
	      return ptr;
	  ++i;
	}
      ++ptr; ++j;
    }
  return NULL;
}

/* fread()  does not return the number of chars read, thus we need to
 * read only a small number of bytes, in order not to expand the binary
 * too much with the last fwrite(). Too lazy to fix this now. 
 */
#define GRAB_SIZE 1024

int readhexchar ( char c )
{
  if      ( c >= '0' && c <= '9' )
    return c - '0';
  else if ( c >= 'a' && c <= 'f' )
    return c - 'a' + 10;
  else if ( c >= 'A' && c <= 'F' )
    return c - 'A' + 10;
  else return -1;
}

int main (int argc, char * argv[])
{
  /* the default password
   */
  unsigned char TcpFlag[9] = { 0xF7,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xF7 }; 
  unsigned char BadFlag[9] = { 0xFF,0xC3,0x12,0xAA,0xAA,0x12,0xC3,0xFF }; 
  
  char * found_it;
  int    i;
  int    suc    = 0;
  int    badcnt = 0;

  char * newn;
  size_t nlen;
  int    oldf;
  int    newf;
  int    ret;

  unsigned long bytecount;

  char   in[9];
  int    j, k;
  char   ccd;
  char * str;

  char * buf = (char *) malloc(GRAB_SIZE);
  size_t dat;
  char * newpwd = (char *) malloc(5 * 8 + 2); 
  char * oldpwd = (char *) malloc(5 * 8 + 2); 

  memset (newpwd, '\0', 5 * 8 + 2); 
  memset (oldpwd, '\0', 5 * 8 + 2); 


  if (argc < 4) 
    {
      fprintf (stderr, "%s", _("\nUsage: samhain_setpwd <filename> <suffix> "\
	       "<new_password>\n\n"));
      fprintf (stderr, "%s", _("   This program is a utility that will:\n"));
      fprintf (stderr, "%s", _("    - search in the binary executable "\
	       "<filename> for samhain's\n"));
      fprintf (stderr, "%s", _("      compiled-in default password,\n"));
      fprintf (stderr, "%s", _("    - change it to <new_password>,\n"));
      fprintf (stderr, "%s", _("    - and output the modified binary to "\
	       "<filename>.<suffix>\n\n"));
      fprintf (stderr, "%s", _("   To allow for non-printable chars, "\
			 "<new_password> must be\n")); 
      fprintf (stderr, "%s", _("   a 16-digit hexadecimal "\
	       "number (only 0-9,A-F allowed in input),\n"));
      fprintf (stderr, "%s", _("   thus corresponding"\
			 "   to an 8-byte password.\n\n"));
      fprintf (stderr, "%s", _("   Example: 'samhain_setpwd samhain new "\
	       "4142434445464748'\n"));
      fprintf (stderr, "%s", _("   takes the file 'samhain', sets the "\
	       "password to 'ABCDEFGH'\n")); 
      fprintf (stderr, "%s", _("   ('A' = 41 hex, 'B' = 42 hex, ...) "\
	       "and outputs the result\n"));
      fprintf (stderr, "%s", _("   to 'samhain.new'.\n"));
      return  EXIT_FAILURE;
    }

  if (strlen(argv[3]) != 16)
    {
      fprintf (stdout, 
	       _("ERROR <new_password> |%s| has not exactly 16 chars\n"),
	       argv[3]);
      fflush(stdout);
      return  EXIT_FAILURE;
    }


  str = &argv[3][0];
  i = 0;
  while (i < 16)
    {
      k = i/2; j = 0; 
      if (2*k == i) in[k] = 0;
      while (j < 16)
	{
	  if (-1 != readhexchar(str[i])) 
	    {
	      in[k] += readhexchar(str[i]) * (i == 2*k ? 16 : 1);
	      break;
	    }
	  ++j;
	  if (j == 16) 
	    {
	      fprintf(stdout, _("ERROR Invalid char %c\n"), str[i]);
	      fflush(stdout);
	      return EXIT_FAILURE;
	    }
	}
      ++i;
    }
  in[8] = '\0';

  /* ---- initialize -----
   */
  (void) umask (0);

  taus_seed();

  bytecount = 0;


  /* ---- open files -----
   */
  
  oldf = open(argv[1], O_RDONLY);

  nlen = strlen(argv[1])+strlen(argv[2])+2;
  newn = (char *) malloc (nlen);
  strncpy(newn, argv[1], nlen); newn[nlen-1] = '\0';
  strncat(newn, ".", nlen);     newn[nlen-1] = '\0';
  strncat(newn, argv[2], nlen); newn[nlen-1] = '\0';
  newf = open(newn, O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU);

  if (oldf < 0)
    {
      fprintf(stdout, _("ERROR Cannot open input file %s.\n"), argv[1]);
      fflush(stdout);
      return EXIT_FAILURE;
    }
  if (newf < 0)
    {
      fprintf(stdout, _("ERROR Cannot open output file %s.\n"), newn);
      fflush(stdout);
      return EXIT_FAILURE;
    }
      
  /* ---- scan file -----
   */
  

  while (1)
    {
      dat = read (oldf, buf, GRAB_SIZE); 
      if (dat == 0) 
	break;

      bytecount += dat;

      while ( (found_it = my_strstr(buf, (char *) TcpFlag, GRAB_SIZE)) != NULL)
	{
	  suc = 1;
	  fprintf (stdout, "%s", _("INFO   old password found\n"));
	  fflush(stdout);
	  for (i = 0; i < 8; ++i)
	    {
	      sprintf(&oldpwd[i*2], _("%02x"), 
		      (unsigned char) *found_it);
	      sprintf(&newpwd[i*2], _("%02x"), 
		      (unsigned char) in[i]);
	      *found_it = in[i];
	      ++found_it;
	    }
	  fprintf (stdout, _("INFO   replaced:  %s  by:  %s\n"), 
		   oldpwd, newpwd);
	  fflush(stdout);
	}

      while ( (found_it = my_strstr(buf, (char *) BadFlag, GRAB_SIZE)) != NULL)
	{
	  badcnt++;
	  /* fprintf (stderr, _("INFO   old filler found\n")); */
	  for (i = 0; i < 8; ++i)
	    {
	      sprintf(&oldpwd[i*2], _("%02x"), 
		      (unsigned char) *found_it);

	      ccd = (unsigned char) (256.0 * (taus_get()/(TAUS_MAX+1.0)));
	      sprintf(&newpwd[i*2], _("%02x"), 
		      (unsigned char) ccd);
	      *found_it = ccd;

	      ++found_it;
	    }
	  /* fprintf (stderr, _("INFO   replaced:  %s  by:  %s\n"), 
	     oldpwd, newpwd);
	  */
	}


      ret = write (newf, buf, dat);
      if (dat > 0 && ret < 0)
	{
	  fprintf(stdout, _("ERROR Cannot write to output file %s.\n"), newn);
	  fflush(stdout);
	  return EXIT_FAILURE;
	}
    }

  if (suc == 1 && badcnt == 7)
    {
      fprintf (stdout, "%s", _("INFO   finished\n"));
      close (newf);
      close (oldf);
      fflush(stdout);
      return (0);
    }

  lseek (oldf, 0, SEEK_SET);
  lseek (newf, 0, SEEK_SET);

  fprintf (stdout, "%s", _("INFO   Not found in first pass.\n"));
  fprintf (stdout, "%s", _("INFO   Second pass ..\n"));

  /* offset the start point
   */

  dat = read (oldf, buf, (GRAB_SIZE / 2));
  ret = write (newf, buf, dat);
  if (dat > 0 && ret < 0)
    {
      fprintf(stdout, _("ERROR Cannot write to output file %s.\n"), newn);
      fflush(stdout);
      return EXIT_FAILURE;
    }

  bytecount = 0;
  suc       = 0;
  badcnt    = 0;

  while (1)
    {
      dat = read (oldf, buf, GRAB_SIZE); 
      if (dat == 0) 
	break;

      bytecount += dat;

      while ( (found_it = my_strstr(buf, (char *) TcpFlag, GRAB_SIZE)) != NULL)
	{
	  suc = 1;
	  fprintf (stdout, "%s", _("INFO   old password found\n"));
	  for (i = 0; i < 8; ++i)
	    {
	      sprintf(&oldpwd[i*2], _("%02x"), 
		      (unsigned char) *found_it);
	      sprintf(&newpwd[i*2], _("%02x"), 
		      (unsigned char) in[i]);
	      *found_it = in[i];
	      ++found_it;
	    }
	  fprintf (stdout, _("INFO   Replaced:  %s  by:  %s\n"), 
		   oldpwd, newpwd);
	}

      while ( (found_it = my_strstr(buf, (char *) BadFlag, GRAB_SIZE)) != NULL)
	{
	  badcnt++;
	  /* fprintf (stderr, _("INFO   old filler found\n")); */
	  for (i = 0; i < 8; ++i)
	    {
	      sprintf(&oldpwd[i*2], _("%02x"), 
		      (unsigned char) *found_it);

	      ccd = (unsigned char) (256.0 * taus_get()/(TAUS_MAX+1.0));
	      sprintf(&newpwd[i*2], _("%02x"), 
		      (unsigned char) ccd);
	      *found_it = ccd;

	      ++found_it;
	    }
	  /* fprintf (stderr, _("INFO   Replaced:  %s  by:  %s\n"), 
	     oldpwd, newpwd);*/
	}

      ret = write (newf, buf, dat);
      if (dat > 0 && ret < 0)
	{
	  fprintf(stdout, _("ERROR Cannot write to output file %s.\n"), newn);
	  fflush(stdout);
	  return EXIT_FAILURE;
	}
    }

  close (newf);
  close (oldf);

  if (suc == 1 && badcnt == 7)
    {
      fprintf (stdout, "%s", _("INFO   finished\n"));
      fflush(stdout);
      return 0;
    }

  if (suc == 0 || badcnt < 7)
    {
      fprintf (stdout, "%s", _("ERROR incomplete replacement\n"));
    }
  else 
    {
      fprintf (stdout, "%s", _("ERROR bad replacement\n"));
    }
  fflush(stdout);
  return EXIT_FAILURE;
}
