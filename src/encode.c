
/* #include "config.h" */


#include <stdio.h>
#include <stdlib.h>

int main(int argv, char * argc[])
{
  int xor_base = -1;

  FILE * inf;
  FILE * ouf;
  char a, b;
  int  i, j;
  char outfile[1024];
  int inbracket = 0, quoted = 0;
  unsigned long count;


  /*  char command[1024]; */

  if ( argv < 3) 
    {
      fprintf(stderr,"\nUsage: encode <XOR_VAL> "\
	      "<file>\n\n");
      fprintf(stderr,"    This program will:\n");
      fprintf(stderr,"    - take as input a source code file <file>,\n");
      fprintf(stderr,"    - search for literal strings inclosed by _(), "\
	      "like '_(string)',\n");
      fprintf(stderr,"    - replace _(string) by "\
	      "_(string XOR <XOR_VAL>),\n");
      fprintf(stderr,
	      "    - and output the result to './x_<file>'.\n\n");
      fprintf(stderr,"    _() is supposed to be defined as a macro in "\
	      "the code, that\n");
      fprintf(stderr,"    will allow the program to decode the xor'ed string "\
	      "at runtime.\n");
      fprintf(stderr,"    The effect is that the compiled executable does "\
	      "not contain literal\n");
      fprintf(stderr,"    strings that may trivially be found with the Unix "\
	      "'strings' command,\n");
      fprintf(stderr,"    and thus reveal the nature of "\
	      "the program.\n");

      return -1;
    }

  --argv; ++argc;

  xor_base = atoi(argc[0]);

  if (xor_base < 0 || (xor_base > 0 && xor_base < 128) || xor_base > 255)
    {
      fprintf(stderr, "\nERROR: encode: XOR_VAL=%d is out of "\
	      "range (0, 128..255)\n",
	      xor_base);
      fprintf(stderr, "** please follow these steps to fix the problem:\n\n");
      fprintf(stderr, "   make clean\n");
      fprintf(stderr, "   ./configure [more options] "\
	      "--with-stealth=XOR_VAL (range 0, 128..255)\n");
      fprintf(stderr, "   make\n\n");
      return -1;
    }
  
  /*  fprintf(stderr, "<XOR_CODE> %d\n", xor_base); */   

  --argv; ++argc;

  /*  fprintf(stderr, "File: %d\n", argv); */   

  while (argv > 0)
    {
      inf = fopen(argc[0], "r");
      if (inf == NULL)
	{
	  fprintf(stderr, "Error opening %s\n", argc[0]);
	  return -1;
	}
      /* outfile name
       */
      i = 0; j = 0;
      while (argc[0][i] != '\0')
	{
	  if (argc[0][i] == '/') j = i+1;
	  ++i;
	}
      i = 0;
      outfile[0] = 'x';
      outfile[1] = '_';
      outfile[2] = '\0';
      while (argc[0][j+i] != '\0')
	{
	  outfile[i+2] = argc[0][j+i];
	  ++i;
	}
      outfile[i+2] = '\0';
      ouf = fopen(outfile, "w");
      if (ouf == NULL)
	{
	  fprintf(stderr, "Error opening %s\n", outfile);
	  return -1;
	}

      /*  fprintf(stderr, "File: %s\n", argc[0]); */
      count = 0;

      while (fread(&a, 1, 1, inf) != 0)
	{
	  count++;

	  if (a == '"' && quoted == 0)
	    {
	      quoted = 1;
	      fwrite(&a, 1, 1, ouf);
	      continue;
	    }

	  if (a == '"' && quoted == 1)
	    {
	      quoted = 0;
	      fwrite(&a, 1, 1, ouf);
	      continue;
	    }

	  if (a == '\n' && quoted == 1)
	    {
	      quoted = 0;
	      fwrite(&a, 1, 1, ouf);
	      continue;
	    }

	  /* macro start ?
	   */
	  if (a == '_' && inbracket == 0 && quoted == 0)
	    {
	      fwrite(&a, 1, 1, ouf);
	      b = '\0';
	      fread(&b, 1, 1, inf);
	      count++;
	      fwrite(&b, 1, 1, ouf);
	      if (b == '(') inbracket = 1;
	      continue;
	    }
	  
	  /* macro end
	   */
	  if (a == ')' && quoted == 0    && inbracket == 1)
	    {
	      inbracket = 0;
	      /*  fprintf(stdout, "\n"); */
	      fwrite(&a, 1, 1, ouf);
	      continue;
	    }

	  /* in a bracket
	   */
	  if (inbracket == 1 && quoted == 1)
	    {
	      /*  fprintf(stdout, "%c", a); */
	      if (a == '\\')
                {
                  fread(&b, 1, 1, inf);

		  /* escape sequences
		   */
                  if (b == 't' || b == 'n' || b == 'r' || b == '"')
		    {
		      fwrite(&a, 1, 1, ouf);
		      fwrite(&b, 1, 1, ouf);
		    }

                  else
                    {
                      a ^= (char) xor_base;
                      b ^= (char) xor_base;
                    }
                }
              else
                {
	          a ^= (char) xor_base;
	          fwrite(&a, 1, 1, ouf);
                }
	      continue;
	    }

	  fwrite(&a, 1, 1, ouf);
	}
	  
      /*  fprintf(stderr, "Bytes read: %ld\n", count); */
      /*  sprintf(command, "mv tempfile %s", argc[0]); */
      /* system(command); */

      fclose(ouf);
      fclose(inf);
      --argv; ++argc;
    }
  return 0;
}
  
