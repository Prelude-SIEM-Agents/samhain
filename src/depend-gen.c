#include <stdio.h>
#include <string.h>

/*  copyright (c) 2002 Rainer Wichmann
 *  License: GNU Public License (GPL) version 2 or later
 */

/* gcc -O2 -Wall -o depend depend.c 
 */

/*

# redo if sources change
#
depend.dep: depend.c $(SOURCES)
   $(CC) -o depend depend.c
   for ff in $(SOURCES); do; \
     depend -o depend.dep $ff; \
   done
   nsum=`sum depend.dep`; \
   osum=`cat depend.sum`; \
   if test "x$$osum" != "x$$nsum"; then \
      echo $$nsum > depend.sum
   fi

# only updated if depencies change
#
depend.sum: depend.dep

Makefile.in: depend.sum
   for ff in $(SOURCES); do; \
     depend -o Makefile.in $ff; \
   done

Makefile: Makefile.in

*/

unsigned int lzo_adler32(unsigned int adler, 
			 const char *buf, unsigned int len);


int main (int argc, char * argv[])
{
  FILE * fout = NULL;
  FILE * ftmp = NULL;
  FILE * fin  = NULL;

  int    filep = 1;

  char   name[1024];
  char   base[1024];
  char   tmpname[1024];
  char   line[1024];
  char   buffer[2048];
  char   incdir[1024];
  int    inclen = 0;
  int    count = 2047;
  int    len = 0;

  unsigned int adler;

  char * p;
  char * q;

  incdir[0] = '\0';

  if (argc < 2)
    {
      fprintf(stderr, "depend-gen: Missing argument\n");
      return 1;
    }

  if (argv[1][0] == '-' && argv[1][1] == 'h')
    {
      printf("Usage: depend-gen [-i includedir] -(o|t) outfile infile\n");
      printf("        -o replaces, -t truncates\n");
      return 0;
    }

  if (argv[1][0] == '-' && argv[1][1] == 'i')
    {
      if (argc < 3)
	{
	  fprintf(stderr, "depend-gen: -i: Missing argument (includedir)\n");
	  return 1;
	}
      strncpy(incdir, argv[2], 1023);
      incdir[1023] = '\0';
      inclen = strlen(incdir);
      argc -= 2; ++argv; ++argv;
    }

  if (argv[1][0] == '-' && 
      (argv[1][1] == 'o' || argv[1][1] == 't' || argv[1][1] == 'c'))
    {
      if (argc < 3) 
	{
	  fprintf(stderr, "depend-gen: -%c: Missing argument\n", argv[1][1]);
	  return 1;
	}
      if (argv[1][1] == 'o' || argv[1][1] == 'c')
	fout = fopen(argv[2], "r+");
      else
	fout = fopen(argv[2], "w+");

      if (!fout)
	{
	  perror("depend-gen: fopen");
	  fprintf(stderr, "depend-gen [%d]: -%c %s: Could not open file\n", 
		  __LINE__, argv[1][1], argv[2]);
	  return 1;
	}
      filep += 2;

      if (argv[1][1] == 'c')
	{
	  adler = lzo_adler32(0, NULL, 0);
	  while (NULL != fgets(line, 1023, fout))
	    {
	      adler = lzo_adler32(adler, line, strlen(line));
	    }
	  printf("%u\n", adler);
	  return 0;
	}

      if (argv[1][1] == 't')
	ftmp = fout;
      else
	{
	  tmpname[0] = '\0';
	  if (strlen(argv[filep]) > 1029)
	    {
	      fprintf(stderr, "depend-gen: -%c %s: filename too long\n", 
		      argv[1][1], argv[2]);
	      return 1;
	    }
	  
	  
	  strncat(tmpname, argv[filep], 1029);
	  strncat(tmpname, ".tmp", 1023);
	  ftmp = fopen(tmpname, "w");
	  if (!ftmp)
	    {
	      perror("depend-gen: fopen");
	      fprintf(stderr, "depend-gen [%d]: -%c %s: Could not open file\n", 
		__LINE__, argv[1][1], tmpname);
	      return 1;
	    }
	}
	  
    }
  else
    {
      fprintf(stderr, "depend-gen: no output file given (-(o|t) outfile)\n");
      return 1;
    }


  if (argc < (filep+1))
    {
      fprintf(stderr, "depend-gen: missing argument (infile)\n");
      return 1;
    }
  fin = fopen(argv[filep], "r");
  if (!fin)
    {
      perror("depend-gen: fopen");
      fprintf(stderr, "depend-gen [%d]: -%c %s: Could not open file\n", 
	__LINE__, argv[1][1], argv[filep]);
      return 1;
    }

  /* fast forward to dependencies start
   */
  do
    {
      if (NULL == fgets(line, 1023, fout))
	break;
      if (0 == strncmp(line, "# DO NOT DELETE THIS LINE", 25))
	break;
      fprintf(ftmp, "%s", line);
    }
  while (1 == 1);

  if (argv[1][1] == 'o')
    {
      fprintf(ftmp, "# DO NOT DELETE THIS LINE\n");
    }

  strncpy(name, argv[filep], 1023);
  p = name;
  while (*p != '\0') ++p;
  if (name[0] != '\0') --p;
  if (*p == 'c') *p = 'o';

  p = strrchr(name, '/');
  if (p)
    {
      ++p;
      len = strlen(p);
    }

  /* skip other dependencies
   */
  do
    {
      if (NULL == fgets(line, 1023, fout))
	break;
      if (p && 0 == strncmp(line, p, len))
	break;
      fprintf(ftmp, "%s", line);
    }
  while (1 == 1);

  buffer[0] = '\0';

  while (NULL != fgets(line, 1023, fin))
    {
      p = line;
      while (*p != '\0' && (*p == ' ' || *p == '\t'))
	++p;
      if (0 == strncmp(p, "#include", 8)) 
	p += 8;
      else
	continue;
      while (*p != '\0' && (*p == ' ' || *p == '\t'))
	++p;
      if (*p != '"')
	continue;
      else
	{
	  ++p;
	  q = p; 
	  ++q;
	  while (*q != '\0' && *q != '"')
	    ++q;
	  if (*q != '"')
	    continue;
	  *q = '\0';

	  /**************************************************
	   *
	   * EXCEPTIONS
	   *
	   **************************************************/
	  if (0 == strcmp(p, "sh_gpg_chksum.h") ||
	      0 == strcmp(p, "sh_gpg_fp.h"))
	    {
	      /* fprintf(stderr, "Excluding %s\n", p); */
	      continue;
	    }

	  len = strlen(p);
	  if (len > count)
	    {
	      /* graceful failure */
	      fprintf(fout, "# OVERFLOW: incomplete dependencies\n");
	      break;
	    }
	  if (incdir[0] != '\0')
	    {
	      if (0 == strcmp(p, "config.h") ||
		  0 == strcmp(p, "config_xor.h") ||
		  0 == strcmp(p, "internal.h") ||
		  0 == strcmp(p, "sh_ks.h") ||
		  0 == strcmp(p, "sh_ks_xor.h") ||
		  0 == strcmp(p, "sh_MK.h"));      /* do nothing */
	      else
		{
		  strncat(buffer, incdir, count);
		  count -= inclen;
		}
	    }
	  strncat(buffer, p, count);
	  count -= len;
	  strncat(buffer, " ", count);
	  --count;
	}
    }

  /* write the dependencies found
   */
  p = strrchr(argv[filep], '/');
  if (p)
    {
      ++p;
      strncpy(name, p, 1023);
    }
  else
    strncpy(name, argv[filep], 1023);
  name[1023] = '\0';

  strcpy(base, "$(srcsrc)/");
  strcat(base, name);

  p = name;
  while (*p != '\0') ++p;
  if (name[0] != '\0') --p;
  if (*p == 'c')
    {
      *p = 'o';
      fprintf(ftmp, "%s: %s Makefile %s\n", name, base /* argv[filep] */, 
	      buffer);
    }
  else
    {
      fprintf(ftmp, "%s: Makefile %s\n", argv[filep], buffer);
    }

  /* more dependencies
   */
  do
    {
      if (NULL == fgets(line, 1023, fout))
	break;
      fprintf(ftmp, "%s", line);
    }
  while (1 == 1);

  if (ftmp != NULL)
    {
      fclose(ftmp);
    }
  if (fout != NULL)
    {
      fclose(fout);
    }
  if (fin != NULL)
    {
      fclose(fin);
    }

  if (argv[1][1] == 'o')
    {
      if (0 != rename (tmpname, argv[2]))
	{
	  perror("depend-gen: rename");
	  fprintf(stderr, "depend-gen: could not rename %s --> %s\n", 
		  tmpname, argv[2]);
	  return 1;
	}
    }

  return 0;
}

/* from the LZO real-time data compression library

   Copyright (C) 1999 Markus Franz Xaver Johannes Oberhumer
   Copyright (C) 1998 Markus Franz Xaver Johannes Oberhumer
   Copyright (C) 1997 Markus Franz Xaver Johannes Oberhumer
   Copyright (C) 1996 Markus Franz Xaver Johannes Oberhumer

   The LZO library is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   The LZO library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with the LZO library; see the file COPYING.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   Markus F.X.J. Oberhumer
   <markus.oberhumer@jk.uni-linz.ac.at>
   http://wildsau.idv.uni-linz.ac.at/mfx/lzo.html
*/
/*
 * NOTE:
 *   the full LZO package can be found at
 *   http://wildsau.idv.uni-linz.ac.at/mfx/lzo.html
 */

#define LZO_BASE 65521u
#define LZO_NMAX 5552

#define LZO_DO1(buf,i)  {s1 += buf[i]; s2 += s1;}
#define LZO_DO2(buf,i)  LZO_DO1(buf,i); LZO_DO1(buf,i+1);
#define LZO_DO4(buf,i)  LZO_DO2(buf,i); LZO_DO2(buf,i+2);
#define LZO_DO8(buf,i)  LZO_DO4(buf,i); LZO_DO4(buf,i+4);
#define LZO_DO16(buf,i) LZO_DO8(buf,i); LZO_DO8(buf,i+8);

unsigned int lzo_adler32(unsigned int adler, const char *buf, unsigned int len)
{
    unsigned int s1 = adler & 0xffff;
    unsigned int s2 = (adler >> 16) & 0xffff;
    int k;

    if (buf == NULL)
	return 1;

    while (len > 0)
    {
	k = len < LZO_NMAX ? (int) len : LZO_NMAX;
	len -= k;
	if (k >= 16) do
	{
	    LZO_DO16(buf,0);
	    buf += 16;
	    k -= 16;
	} while (k >= 16);
	if (k != 0) do
	{
	    s1 += *buf++;
	    s2 += s1;
	} while (--k > 0);
	s1 %= LZO_BASE;
	s2 %= LZO_BASE;
    }
    return (s2 << 16) | s1;
}
