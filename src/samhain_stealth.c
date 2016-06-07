#include "config_xor.h"

#ifdef HAVE_BROKEN_INCLUDES
#define _ANSI_C_SOURCE
#define _POSIX_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#ifndef SH_BUFSIZE
#define SH_BUFSIZE 1024
#endif

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

#ifndef GLOB_LEN
#define GLOB_LEN 511
#endif

char * globber(const char * str)
{
  register int i, j;
  static int  count = -1;
  static char glob[SH_MAX_GLOBS][GLOB_LEN+1];

  ++count; if (count > (SH_MAX_GLOBS-1) ) count = 0;
  j = strlen(str);
  if (j > GLOB_LEN) j = GLOB_LEN;

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

static unsigned long off_data;

char sh_util_charhex( int c )
{
  if      ( c >= 0 && c <= 9 )
    return '0' + c;
  else if ( c >= 10 && c <= 15 )
    return 'a' + (c - 10);
  else 
    {
      fprintf(stderr, _("Out of range: %d\n"), c);
      return 'X';
    }
}
 
int sh_util_hexchar( char c )
{
  if      ( c >= '0' && c <= '9' )
    return c - '0';
  else if ( c >= 'a' && c <= 'f' )
    return c - 'a' + 10;
  else if ( c >= 'A' && c <= 'F' )
    return c - 'A' + 10;
  else return -1;
}
 
/* ---------  third step -----------
 *
 * get data from a block of hex data
 */
int hideout_hex_block(int fd, unsigned char * str, int len)
{
  register int  i, j, k;
  unsigned char c, e;
  register int  num;
  unsigned char mask[9] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
  unsigned long here   = 0;
  unsigned long retval = 0;

  i = 0;
  while (i < len)
    {
      for (j = 0; j < 8; ++j)
	{

	  /* get a low byte, modify, read back */
	  for (k = 0; k < 2; ++k)
	    {
	      c = ' ';
	      do {
		do {
		  num = read (fd, &c, 1);
		} while (num == 0 && errno == EINTR);
		if (num == 0) return -1;
		++here; 
	      } while (c == '\n' || c == '\t' || c == '\r' || 
		       c == ' ');
	    }
	  

	  /* e is the value of the low byte
	   */
	  e = (unsigned char) sh_util_hexchar( c );
	  if ((e & mask[7]) != 0)  /* bit is set     */
	    str[i] |= mask[j];
	  else                     /* bit is not set */
	    str[i] &= ~mask[j];

	}
      if (str[i] == '\n') break;
      ++i;
    }
  str[i+1] = '\0';
  retval += here;
  return retval;
}

/* ---------  second step -----------
 *
 * hide data in a block of hex data
 */
int hidein_hex_block(int fd, char * str, int len)
{
  register int  i, j, k;
  unsigned char c, d, e;
  register int  num;
  unsigned char mask[9] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
  unsigned long here   = 0;
  unsigned long retval = 0;

  for (i = 0; i < len; ++i)
    {
      d = str[i];
      for (j = 0; j < 8; ++j)
	{

	  /* get a low byte, modify, read back */
	  for (k = 0; k < 2; ++k)
	    {
	      c = ' ';
	      do {
		do {
		  num = read (fd, &c, 1);
		} while (num == 0 && errno == EINTR);
		if (num == 0) return -1;
		++here; 
	      } while (c == '\n' || c == '\t' || c == '\r' || 
		       c == ' ');
	    }

	  /* e is the value of the low byte
	   */
	  e = (unsigned char) sh_util_hexchar( c );
	  if ((d & mask[j]) != 0)  /* bit is set     */
	    e |= mask[7];
	  else                     /* bit is not set */
	    e &= ~mask[7];

	  e = sh_util_charhex ( e );
	  lseek(fd, -1, SEEK_CUR);
	  do {
		num = write(fd, &e, 1);
	  } while (num == 0 && errno == EINTR);
	}
    }
  retval += here;
  return retval;
}

/* ---------  first step -----------
 *
 * find first block of hex data
 */
unsigned long first_hex_block(int fd, unsigned long * max)
{
  int           i;
  register int  num = 1;
  char          c;
  int           nothex = 0;
  unsigned long retval = 0;
  int           this_line = 0;
  char          theline[SH_BUFSIZE];

  *max = 0;

  while (1)
    {
      theline[0] = '\0';
      this_line  = 0;
      c          = '\0';
      while (c != '\n' && num > 0)
	{
	  do {
	    num = read (fd, &c, 1);
	  } while (num == 0 && errno == EINTR);
	  if (num > 0) theline[this_line] = c;
	  else         return 0;
	  this_line += num;
	}
      theline[this_line] = '\0';
      
      /* not only 'newline' */ 
      if (this_line > 60)
	{
	  nothex  = 0;
	  i       = 0;
	  while (nothex == 0 && i < (this_line-1))
	    {
	      if (! isxdigit((int)theline[i])) nothex = 1;
	      ++i;
	    }
	  if (nothex == 1) retval += this_line;
	}
      else
	{
	  nothex = 1;
	  retval += this_line;
	}

      if (nothex == 0)
	{
	  *max = 0; 
	  do {
	    do {
	      num = read (fd, theline, SH_BUFSIZE);
	    } while (num == 0 && errno == EINTR);
	    for (i = 0; i < num; ++i)
	      { 
		c = theline[i];
		if (c == '\n' || c == '\t' || c == '\r' || c == ' ') 
		  ;
		else if (!isxdigit((int)c))
		  break;
		else
		  *max += 1;
	      }
	  } while (num > 0);

	  *max /= 16;
	  return retval;
	}

    }
  /* return 0; *//* unreachable */
}

static void usage ()
{
      fprintf(stdout, "%s", _("\nUsage:  samhain_stealth -i|s|g|o <where> "\
			      "[what]\n\n"));

      fprintf(stdout, "%s", _("   -i info on PS image 'where'\n"));
      fprintf(stdout, "%s", _("      (how much bytes can be hidden in it).\n"));
      fprintf(stdout, "%s", _("   -s hide file 'what' in PS image 'where'\n"));
      fprintf(stdout, "%s", _("   -g get hidden data from PS image 'where'\n"));
      fprintf(stdout, "%s", _("      (output to stdout)\n"));
      fprintf(stdout, "%s", _("   -o size of file 'where' = offset to "\
			      "end-of-file\n"));
      fprintf(stdout, "%s", _("      (same as wc -c).\n\n"));
      fprintf(stdout, "%s", _(" Example: let bar.ps be the ps file, and"\
			      "foo the config file\n"));
      fprintf(stdout, "%s", _("   1) extract with: samhain_stealth "\
			      "-g bar.ps >foo\n"));
      fprintf(stdout, "%s", _("   2) hide with:    samhain_stealth "\
			      "-s bar.ps foo\n\n"));

      fprintf(stdout, "%s", _(" This program hides a file in an UNCOMPRESSED "\
			      "postscript\n"));
      fprintf(stdout, "%s", _(" image. To generate such an image, you may " \
			      "use e.g.:\n"));
      fprintf(stdout, "%s", _("   'convert +compress foo.jpg bar.ps'.\n"));
      fprintf(stdout, "%s", _("   'gimp' apparently saves postscript "\
			      "uncompressed by default\n"));
      fprintf(stdout, "%s", _("         (V 1.06 of the postscript plugin).\n"));
      fprintf(stdout, "%s", _("   'xv' seems to save with run-length "\
			      "compression, which is unsuitable.\n"));
      fprintf(stdout, "%s", _(" The program does not check the "\
			      "compression type of the PS file.\n"));
      fprintf(stdout, "%s", _(" Just have a look at the result to check.\n"));
      return;
}

int main (int argc, char * argv[])
{
  int fd;
  int add_off;
  unsigned long max;
  char buf[1024];
  FILE * infil;
  int  pgp_flag = 0;

  if (argc == 2 && argv[1][0] == '-' && argv[1][1] == 'h')
    {
      usage();
      return (0);
    }
  if (argc == 2 && 0 == strcmp(argv[1], _("--help")))
    {
      usage();
      return (0);
    }

  if (argc < 3 || argv[1][0] != '-' ||
      (argv[1][1] != 'o' && argv[1][1] != 'i' && 
       argv[1][1] != 's' && argv[1][1] != 'g'))
    {
      usage ();
      return (1);
    }


  
  /* offset to end 
   */
  if (argv[1][1] == 'o') 
    {
      fd = open(argv[2], O_RDONLY);
      if (fd == -1) 
	{
	  fprintf(stderr, _("Error: could not open() %s for reading\n"), 
		  argv[2]);
	  return (1);
	}

      off_data = lseek (fd, 0, SEEK_END);
      fprintf(stdout, _("%ld %s\n"), 
	      off_data, argv[2]);
      close (fd);
      return (0);
    }

  fd = open(argv[2], O_RDWR);
  if (fd == -1) 
    {
      fprintf(stderr, _("Error: could not open() %s for read/write\n"), 
	      argv[2]);
      return (1);
    }

  /* find the first block of hex data 
   */
  if (argv[1][1] == 'i') 
    {
      off_data = first_hex_block(fd, &max);
      fprintf(stdout, _("IMA START AT: %ld  MAX. CAPACITY: %ld Bytes\n"), 
	      off_data, max);
      if (max > 0)
	return (0);
      else
	{
	  fprintf(stderr, _("Error: %s is probably not an uncompressed postscript image\n"), argv[2]);
	  return (1);
	}
    }

  /* seek to the first block of fresh hex data and hide data 
   */
  if (argv[1][1] == 's') 
    {
      infil = fopen(argv[3], "r");
      if (infil == NULL) 
	{
	  fprintf(stderr, _("Error: could not open() %s\n"), argv[3]);
	  return (8);
	}
      off_data = first_hex_block(fd, &max);
      fprintf(stdout, _("IMA START AT: %ld  MAX. CAPACITY: %ld Bytes\n"), 
	      off_data, max);
      if (max == 0)
	{
	  fprintf(stderr, _("Error: %s is probably not an uncompressed postscript image\n"), argv[2]);
	  return (1);
	}

      fprintf(stdout, _(" .. hide %s in %s .. \n"), argv[3], argv[2]);
      while (fgets(buf, sizeof(buf), infil))
	{
	  lseek(fd, off_data, SEEK_SET);
	  add_off = hidein_hex_block(fd, buf, strlen(buf));
	  if (add_off == -1)
	    {
	      fprintf(stderr, _("Error: %s has insufficient capacity\n"),
		       argv[2]);
	      return (1);
	    }
	  off_data += add_off;
	}
      fclose(infil);
      /* 
       * make sure there is a terminator 
       */
      lseek(fd, off_data, SEEK_SET);
      add_off = hidein_hex_block(fd, _("\n[EOF]\n"), 7);
      if (add_off == -1)
	{
	  fprintf(stderr, _("Error: %s has insufficient capacity\n"),
		  argv[2]);
	  return (1);
	}
      fprintf(stdout, "%s", _(" .. finished\n"));
      return (0);
    }

  if (argv[1][1] == 'g') 
    {
      off_data = first_hex_block(fd, &max);
      if (max == 0)
	{
	  fprintf(stderr, _("Error: %s is probably not an uncompressed postscript image\n"), argv[2]);
	  return (1);
	}
      lseek(fd, off_data, SEEK_SET);
      
      while (1 == 1)
	{
	  add_off = hideout_hex_block(fd, (unsigned char *) buf, 1023);
	  if (add_off == -1)
	    {
	      fprintf(stderr, _("Error: premature end of data in %s\n"), 
		      argv[2]);
	      return (1);
	    }
	  if (0 == strcmp(buf, _("-----BEGIN PGP SIGNED MESSAGE-----\n")))
	    pgp_flag = 1;
	  fprintf(stdout, "%s", buf);
	  if (0 == strncmp(buf, _("[EOF]"), 5) && pgp_flag == 0)
	    break;
	  if (0 == strcmp(buf, _("-----END PGP SIGNATURE-----\n")) && 
	      pgp_flag == 1)
	    break;

	  off_data += add_off;
	  lseek(fd, off_data, SEEK_SET);
	}
     return (0); 
    }

  fprintf(stderr, _("Invalid mode of operation: %s"), argv[1]);
  return (1);
}

