
#include "config_xor.h"

#include <string.h>
#include <stdio.h>
#include <sys/types.h>

#include "sh_string.h"
#include "sh_mem.h"

#undef  FIL__
#define FIL__  _("sh_string.c")

extern int sl_ok_adds (size_t a, size_t b);
#define S_TRUE  1
#define S_FALSE 0

#include <ctype.h>
#include <errno.h>

/* Split array at delim in at most nfields fields. 
 * Empty fields are returned as empty (zero-length) strings. 
 * Leading and trailing WS are removed from token. 
 * The number of fields is returned in 'nfields', their
 * lengths in 'lengths'.
 * A single delimiter will return two empty fields.
 */
char ** split_array(char *line, unsigned int * nfields, 
                    char delim, size_t * lengths)
{
  char *a, *e, *s;
  unsigned int i = 0;
  int flag = 0;
  char **arr;
  unsigned int maxfields = (*nfields);

  arr = SH_ALLOC((maxfields+1) * sizeof (char*));

  e = line;

  do
    {
      /* skip leading WS 
       */
      for (s=e; *s && isspace((int)*s); ++s) /* nothing */;

      if (*s) 
        {
          /* move a to next delim
           */
          for (a=s; *a && *a != delim; ++a) /* nothing */;
          
          /* set e to next after delim
           */
          if (*a == delim)
            {
              e    = a+1;
              flag = 1;
            }
          else /* (!*a) */
            {
              e    = a;
              flag = 0;
            }

          if (a != line)
            {
	      if (i < (maxfields -1))
                {

		  /* chop off trailing WS 
		   */
		  for (a--; isspace((int)*a) && a > s; a--) /* do nothing */;
		  
		  /* terminate string
		   */
		  ++a; *a = '\0';
		}
              else
                {
                  /* If nfields < actual fields, last string 
                   * will be remainder, therefore skip to end.
                   */
                  if ( *a )
                    {
                      do {
                        a++;
                      } while ( *a );
                    }
                }
	    }
          else
            {
              *a = '\0';
            }
        }
      else /* (!*s) */
        {
          a = s;
	  /* (i == 0) handles the special case of splitting the empty string */
          if (flag || i == 0) 
            {
              flag = 0;
              goto setnext;
            }
          break;
        }

    setnext:
      lengths[i] = (size_t) (a-s); /* a >= s always */
      arr[i] = s;
      ++i;

    } while (i < maxfields);

  *nfields = i;
  arr[i]   = NULL;

  return arr;
}

/* Split array at whitespace in at most nfields fields.
 * Multiple whitespaces are collapsed. 
 * Empty fields are returned as empty (zero-length) strings.
 * The number of fields is returned in nfields.
 * An empty string will return zero fields.
 * If nfields < actual fields, last string will be remainder.
 */

#define SH_SPLIT_LIST 0
#define SH_SPLIT_WS   1

char ** split_array_ws_int (char *line, 
			    unsigned int * nfields, size_t * lengths,
			    const char *delim, int isList)
{
  char *a, *e, *s;
  unsigned int i = 0;
  char **arr;
  unsigned int maxfields = (*nfields);

  arr = SH_ALLOC((maxfields+1) * sizeof (char*));

  e = line;

  do
    {
      s = e;

      /* skip leading WS 
       */
      if (isList == SH_SPLIT_WS)
	{
	  if ( *s && isspace((int)*s) )
	    {
	      do {
		++s;
	      } while ( *s && isspace((int)*s) );
	    }
	}
      else
	{
          if ( *s && strchr(delim, (int)*s))
            {
              do {
                ++s;
              } while ( *s && strchr(delim, (int)*s));
            }

	}

      if (*s)
        {

          /* s is at non-ws, move a to next ws
           */
          a = s;
	  if (isList == SH_SPLIT_WS)
	    {
	      do {
		a++;
	      } while ( *a && (!isspace((int)*a)) );
	    }
	  else
	    {
              do {
                a++;
              } while ( *a && NULL == strchr(delim, (int)*a));
	    }

          /* next token, *a is either ws or '\0' 
           */
          e = ( (*a) ? a+1 : a);
          
          /* terminate and set arr[i]
           */
          if (i < (maxfields-1))
	    {
              *a = '\0';
	    }
	  else
	    {
	      /* If nfields < actual fields, last 
	       * string will be remainder. Therefore
	       * skip to end.
	       */
	      if ( *a )
		{
		  do {
		    a++;
		  } while ( *a );
		}
	    }
          lengths[i] = (size_t)(a-s); /* a >= s always */
          arr[i]     = s; 
          ++i;
        }
      else /* if (!*s) */
        {
          break;
        }

    } while (i < maxfields);

  *nfields = i;
  arr[i]   = NULL;

  return arr;
}

char ** split_array_ws (char *line, 
			unsigned int * nfields, size_t * lengths)
{
  return split_array_ws_int (line, nfields, lengths, NULL, SH_SPLIT_WS);
}

char ** split_array_list (char *line, 
			  unsigned int * nfields, size_t * lengths)
{
  return split_array_ws_int (line, nfields, lengths, ", \t", SH_SPLIT_LIST);
}

char ** split_array_token (char *line, 
			   unsigned int * nfields, size_t * lengths,
			   const char * token)
{
  return split_array_ws_int (line, nfields, lengths, token, SH_SPLIT_LIST);
}

/* return a split() of a list contained in 'PREFIX\s*( list ).*'
 */
char ** split_array_braced (char *line, const char * prefix,
			    unsigned int * nfields, size_t * lengths)
{
  char * s = line;
  char * p;
  unsigned int sind = (prefix) ? strlen(prefix) : 0;

  while ( *s && isspace((int)*s) ) ++s;
  if (prefix && 0 != strncmp(s, prefix, strlen(prefix)))
    return NULL;
  s = &s[sind];
  while ( *s && isspace((int)*s) ) ++s;
  if (!s || (*s != '('))
    return NULL;
  ++s;
  p = strchr(s, ')');
  if (!p || (*p == *s))
    return NULL;
  *p = '\0';
  return split_array_list (s, nfields, lengths);
}

#define SH_STRING_PARCEL 120

static
size_t sh_string_read_int(sh_string * s, FILE * fp, size_t maxlen, char *start);

size_t sh_string_read(sh_string * s, FILE * fp, size_t maxlen)
{
  return sh_string_read_int(s, fp, maxlen, NULL);
}

size_t sh_string_read_cont(sh_string * s, FILE * fp, size_t maxlen, char *cont)
{
  return sh_string_read_int(s, fp, maxlen, cont);
}

static char * sh_str_fgets (char *s, int size, FILE *fp)
{
  char * ret;
  do {
    clearerr(fp);
    ret = fgets(s, size, fp);
  } while (ret == NULL && ferror(fp) && errno == EAGAIN);

  return ret;
}

size_t sh_string_read_int(sh_string * s, FILE * fp, size_t maxlen, char *start)
{

  /* case 0) start != NULL and first char not in 'start'
   */
  if (start)
    {
      int first;

      do {
	clearerr(fp);
	first = fgetc(fp);
      } while (first == EOF && ferror(fp) && errno == EAGAIN);

      if (first == EOF)
	{
	  sh_string_truncate(s, 0);
	  if (ferror(fp))
	    return -1;
	  return 0;
	}

      if (NULL == strchr(start, first))
	{
	  ungetc(first, fp);
	  return 0;
	}
      ungetc(first, fp);
    }

  /* case 1) EOF or error 
   */
  if (sh_str_fgets(s->str, s->siz, fp) == NULL)
    {
      sh_string_truncate(s, 0);
      if (ferror(fp))
        return -1;
      return 0;
    }

  /* case 2) end of line reached. strlen should always be > 0
   *         because of the '\n', but we check.
   */
  s->len = strlen(s->str);
  if (s->len > 0 && (s->str)[s->len-1] == '\n') 
    {
      (s->str)[s->len-1] = '\0';
      --(s->len);
      return (s->len + 1);
    }
      
  /* case 3) incomplete string
   */
  for (;;) {
    
    if (maxlen > 0 && (s->siz+SH_STRING_PARCEL) > maxlen)
      {
        if (s->siz < maxlen)
          sh_string_grow(s, (maxlen-s->siz));
        else
          return -2;
      }
    else
      {
        sh_string_grow(s, 0);
      }
    
    if (sh_str_fgets(&(s->str[s->len]), (s->siz - s->len), fp) == NULL) 
      {
        if (ferror(fp))
          {
            sh_string_truncate(s, 0);
            return -1;
          }
        return s->len;
      }
    
    s->len += strlen( &(s->str[s->len]) );
    if (s->len > 0 && s->str[s->len-1] == '\n')
      {
        (s->str)[s->len-1] = '\0';
        --(s->len);
        return (s->len + 1);
      }
  }

  /* notreached */
}

sh_string * sh_string_cat_lchar(sh_string * s, const char * str, size_t len)
{
  if (sl_ok_adds(len, s->siz) == S_TRUE)
    {
      if ((len + 1 + s->len) > s->siz)
	{
	  sh_string_grow(s, ((len+1+s->len) - s->siz) );
	}
      memcpy(&(s->str[s->len]), str, len);
      s->len += len;
      s->str[s->len] = '\0';
      return s;
    }

  return NULL;
}

sh_string * sh_string_set_from_char(sh_string * s, const char * str)
{
  size_t len = strlen(str);

  if ((len+1) > s->siz)
    {
      sh_string_grow(s, ((len+1) - s->siz) );
    }
  memcpy(s->str, str, (len+1));
  s->len = len;
  return s;
}

sh_string * sh_string_add_from_char(sh_string * s, const char * str)
{
  size_t len   = strlen(str);
  size_t avail = (s->siz - s->len);

  if ((len+1) > avail)
    {
      (void) sh_string_grow(s, ((len+1) - avail) );
    }
  memcpy(&(s->str[s->len]), str, (len+1));
  s->len += len;
  return s;
}

sh_string * sh_string_new_from_lchar(const char * str, size_t len)
{
  sh_string * s;
  s      = SH_ALLOC(sizeof(sh_string));
  s->str = SH_ALLOC(len+1);
  if (str)
    memcpy(s->str, str, len);
  else
    s->str[0] = '\0';
  s->str[len] = '\0';
  s->siz = len+1;
  s->len = len;
  return s;
}

sh_string * sh_string_new_from_lchar3(const char * str1, size_t len1,
                                      const char * str2, size_t len2,
                                      const char * str3, size_t len3)
{
  sh_string * s;
  size_t len = 0;

  if (sl_ok_adds(len1, len2) == S_TRUE)
    len    = len1 + len2;
  else
    return NULL;
  if (sl_ok_adds( len, len3) == S_TRUE)
    len    = len  + len3;
  else
    return NULL;

  s      = SH_ALLOC(sizeof(sh_string));
  s->str = SH_ALLOC(len+1);

  memcpy(s->str, str1, len1);
  memcpy(&s->str[len1], str2, len2);
  memcpy(&s->str[len1+len2], str3, len3);

  s->str[len] = '\0';
  s->siz = len+1;
  s->len = len;
  return s;
}

sh_string * sh_string_grow(sh_string * s, size_t increase)
{
  char * new;

  if (increase == 0)
    increase = SH_STRING_PARCEL;
  
  if (s && sl_ok_adds(s->siz, increase) == S_TRUE)
    {
      new = SH_ALLOC(s->siz + increase);

      if (s->str)
        {
          memcpy(new, s->str, s->len+1);
          SH_FREE(s->str);
        }
      else
        {
          new[0] = '\0';
        }
      s->str  = new;
      s->siz += increase;
      return s;
    }
  return NULL;
}

sh_string * sh_string_truncate(sh_string * s, size_t len)
{
  if (s)
    {
      if (s->str && (s->len > len) )
        {
          s->len            = len;
          (s->str)[len]     = '\0';
        }
      return s;
    }
  return NULL;
}

void sh_string_destroy(sh_string ** s)
{
  if (s)
    {
      if ((*s) && (*s)->str)
        SH_FREE ((*s)->str);
      SH_FREE(*s);
      *s = NULL;
    }
  return;
}

sh_string * sh_string_new(size_t size)
{
  sh_string * s;
  s      = SH_ALLOC (sizeof(sh_string));
  if (size == 0)
    size = SH_STRING_PARCEL;
  s->str = SH_ALLOC (size);
  s->str[0] = '\0';
  s->siz = size;
  s->len = 0;
  return s;
}

/* Replaces fields in s with 'replacement'. Fields are given
 * in the ordered array ovector, comprising ovecnum pairs 
 * ovector[i], ovector[i+1] which list offset of first char
 * of field, offset of first char after field (this is how
 * the pcre library does it).
 */  
sh_string * sh_string_replace(const sh_string * s, 
                              const int * ovector, int ovecnum, 
                              const char * replacement, size_t rlen)
{
  sh_string * r = NULL;
  char * p;
  long   tlen;
  size_t len;
  int    end    = 0;
  int    start  = 0;
  size_t oldlen = 0;
  size_t newlen = 0;
  long   diff;
  int    i, curr, last;

  for (i = 0; i < ovecnum; ++i)
    {
      start = ovector[2*i];       /* offset of first char of substring       */
      if (start >= end)
        {
          end   = ovector[2*i+1]; /* offset of first char after substring end*/

          if (end > start && (unsigned int)end <= (s->len + 1))
            {
              oldlen += (end - start);
              newlen += rlen;
            }
          else                    /* inconsistency detected                  */
            {
              return NULL;
            }
        }
      else                        /* overlap detected                        */
        {
          return NULL;
        }
    }

  diff = newlen - oldlen;

  if ((diff > 0) && ((s->len + 1 + diff) > s->siz))
    {
      r = sh_string_new_from_lchar(sh_string_str(s), 
                                   sh_string_len(s));
      r = sh_string_grow(r, diff);
    }
  else
    {
      r = sh_string_new_from_lchar(sh_string_str(s), 
                                   sh_string_len(s));
    }


  curr = -1;

  for (i = 0; i < ovecnum; ++i)
    {
      if (ovector[2*i] >= 0)
        {
          curr = 2*i;
          break;
        }
    }
  
  if (r && ovecnum > 0 && ovector[curr] >= 0)
    {
      r->len = 0; r->str[0] = '\0'; p = r->str;

      /* First part, until start of first replacement 
       */
      if (r->siz > (unsigned int)ovector[curr]) {
	memcpy(p, s->str, (size_t)ovector[curr]); 
	p += ovector[curr]; 
	r->len += ovector[curr];
      }
      if (r->siz > (r->len + rlen)) {
	memcpy(p, replacement,    rlen); 
	p += rlen;
	r->len += rlen;
      }
      *p = '\0';

      last = curr + 1;

      for (i = 1; i < ovecnum; ++i)
        {
          if (ovector[2*i] < 0)
            continue;

          curr = 2*i;

          /* From end of last replacement to start of this */
          tlen = (long)(ovector[curr] - ovector[last]);
          if (tlen >= 0)
            {
              len = (size_t) tlen;

              if (tlen > 0 && r->siz > (r->len + len))
                {
                  memcpy(p, &(s->str[ovector[last]]), (size_t)len);
                  p += len;
		  r->len += len; 
                }
              
              /* The replacement */
	      if (r->siz > (r->len + rlen)) {
		memcpy(p, replacement, rlen);       
		p += rlen;
		r->len += rlen;
	      }
              
              /* null terminate */
              *p = '\0';

              last = curr + 1;
            }
	}

      /* Last part, after last replacement; includes terminating null 
       */
      if (last > 0)
        {
          /* If not, nothing has been replaced, and r is still a copy of s
           */
          tlen = (long)((s->len + 1) - ovector[last]);
          if (tlen > 0)
            {
              len = (size_t)tlen;
	      if (r->siz >= (r->len + len)) {
		memcpy(p, &(s->str[ovector[2*i -1]]), (size_t)len);
		p += (len - 1); 
		r->len += (len - 1);
		*p = '\0'; 
	      }
            }
        }

    }

  return r;
}


#ifdef SH_CUTEST
#include <stdlib.h>
#include "CuTest.h"

void Test_string (CuTest *tc) {
  int status, i, max = 120;
  FILE * fp;
  sh_string * s = NULL;
  sh_string * t;
  static char template[] = "/tmp/xtest.XXXXXX";
  char ** array;
  char test[128];
  size_t lengths[16];
  unsigned int iarr;
  int ovector[16];
  int ovecnum;

  s = sh_string_new(0);
  CuAssertPtrNotNull(tc, s);
  sh_string_destroy(&s);
  CuAssertTrue(tc, s == NULL);

  s = sh_string_new(0);
  CuAssertPtrNotNull(tc, s);

  status = mkstemp(template);
  CuAssertTrue(tc, status >= 0);

  fp = fdopen(status, "r+");
  CuAssertPtrNotNull(tc, fp);

  for (i = 0; i <  80; ++i) { fputc ('a', fp); } fputc ('\n', fp); /* 0 */
  for (i = 0; i < 118; ++i) { fputc ('a', fp); } fputc ('\n', fp); /* 1 */
  for (i = 0; i < 119; ++i) { fputc ('a', fp); } fputc ('\n', fp); /* 2 */
  for (i = 0; i < 120; ++i) { fputc ('a', fp); } fputc ('\n', fp); /* 3 */
  for (i = 0; i < 121; ++i) { fputc ('a', fp); } fputc ('\n', fp); /* 4 */
  for (i = 0; i < 238; ++i) { fputc ('a', fp); } fputc ('\n', fp);
  for (i = 0; i < 239; ++i) { fputc ('a', fp); } fputc ('\n', fp);
  for (i = 0; i < 240; ++i) { fputc ('a', fp); } fputc ('\n', fp);
  for (i = 0; i < 241; ++i) { fputc ('a', fp); } fputc ('\n', fp);

  rewind(fp);

  for (i = 0; i < 9; ++i)
    {
      status = sh_string_read(s, fp, max);

      switch (i) {
      case 0:
	CuAssertTrue(tc, s->len ==  80);
	CuAssertTrue(tc, s->siz == 120);
	CuAssertTrue(tc, status ==  81);
	break;
      case 1:
	CuAssertTrue(tc, s->len == 118);
	CuAssertTrue(tc, s->siz == 120);
	CuAssertTrue(tc, status == 119);
	break;
      case 2:
	CuAssertTrue(tc, s->len == 119);
	CuAssertTrue(tc, s->siz == 120);
	CuAssertTrue(tc, status ==  -2); /* no terminating '\n', truncated */
	break;
      case 3:
	CuAssertTrue(tc, s->len == 120);
	CuAssertTrue(tc, s->siz == 240);
	CuAssertTrue(tc, status == 121);
	break;
      case 4:
	CuAssertTrue(tc, s->len == 121);
	CuAssertTrue(tc, s->siz == 240);
	CuAssertTrue(tc, status == 122);
	break;
      case 5:
	CuAssertTrue(tc, s->len == 238);
	CuAssertTrue(tc, s->siz == 240);
	CuAssertTrue(tc, status == 239);
	break;
      case 6:
	CuAssertTrue(tc, s->len == 239);
	CuAssertTrue(tc, s->siz == 240);
	CuAssertTrue(tc, status ==  -2); /* no terminating '\n', truncated */
	break;
      default:
	CuAssertTrue(tc, s->len == 239);
	CuAssertTrue(tc, s->siz == 240);
	CuAssertTrue(tc, status ==  -2);
      }
      if (status == -2) /* read in rest of string */
        { max = 240; sh_string_read(s, fp, max); }
    }

  rewind(fp);

  sh_string_truncate(s, 0);
  CuAssertTrue(tc, s->len == 0);

  for (i = 0; i < 9; ++i)
    {
      status = sh_string_read(s, fp, 240);
      if (status == -2)
        sh_string_read(s, fp, 240);
      else
        {
          for (status = 0; status < (int)s->len; ++status)
            {
              if (s->str[status] != 'a')
                {
                  CuFail(tc, "unexpected character");
                }
            }
        }
    }

  status = fclose(fp); 
  CuAssertTrue(tc, status == 0);
  status = remove(template);
  CuAssertTrue(tc, status == 0);

  iarr = 10; strcpy(test, "|a1|| a2| |a3 |a4|a5|");
  array  = split_array(test, &iarr, '|', lengths);
  CuAssertIntEquals(tc,9,(int)iarr);
  CuAssertStrEquals(tc,"",   array[0]);
  CuAssertStrEquals(tc,"a1", array[1]);
  CuAssertStrEquals(tc,"",   array[2]);
  CuAssertStrEquals(tc,"a2", array[3]);
  CuAssertStrEquals(tc,"",   array[4]);
  CuAssertStrEquals(tc,"a3", array[5]);
  CuAssertStrEquals(tc,"a4", array[6]);
  CuAssertStrEquals(tc,"a5", array[7]);
  CuAssertStrEquals(tc,"",   array[8]);

  CuAssertIntEquals(tc, 0, (int)lengths[0]);
  CuAssertIntEquals(tc, 2, (int)lengths[1]);
  CuAssertIntEquals(tc, 0, (int)lengths[2]);
  CuAssertIntEquals(tc, 2, (int)lengths[3]);
  CuAssertIntEquals(tc, 0, (int)lengths[4]);
  CuAssertIntEquals(tc, 2, (int)lengths[5]);
  CuAssertIntEquals(tc, 2, (int)lengths[6]);
  CuAssertIntEquals(tc, 2, (int)lengths[7]);
  CuAssertIntEquals(tc, 0, (int)lengths[8]);

  iarr = 10; strcpy(test, "a1|| a2| |a3 |a4|a5|");
  array  = split_array(test, &iarr, '|', lengths);
  CuAssertIntEquals(tc,8,(int)iarr);
  CuAssertStrEquals(tc,"a1", array[0]);
  CuAssertStrEquals(tc,"",   array[1]);
  CuAssertStrEquals(tc,"a2", array[2]);
  CuAssertStrEquals(tc,"",   array[3]);
  CuAssertStrEquals(tc,"a3", array[4]);
  CuAssertStrEquals(tc,"a4", array[5]);
  CuAssertStrEquals(tc,"a5", array[6]);
  CuAssertStrEquals(tc,"",   array[7]);

  CuAssertIntEquals(tc, 2, (int)lengths[0]);
  CuAssertIntEquals(tc, 0, (int)lengths[1]);
  CuAssertIntEquals(tc, 2, (int)lengths[2]);
  CuAssertIntEquals(tc, 0, (int)lengths[3]);
  CuAssertIntEquals(tc, 2, (int)lengths[4]);
  CuAssertIntEquals(tc, 2, (int)lengths[5]);
  CuAssertIntEquals(tc, 2, (int)lengths[6]);
  CuAssertIntEquals(tc, 0, (int)lengths[7]);

  iarr = 10; strcpy(test, "  a1|| a2  | |a3 |a4|a5");
  array  = split_array(test, &iarr, '|', lengths);
  CuAssertIntEquals(tc,7,(int)iarr);
  CuAssertStrEquals(tc,"a1", array[0]);
  CuAssertStrEquals(tc,"",   array[1]);
  CuAssertStrEquals(tc,"a2", array[2]);
  CuAssertStrEquals(tc,"",   array[3]);
  CuAssertStrEquals(tc,"a3", array[4]);
  CuAssertStrEquals(tc,"a4", array[5]);
  CuAssertStrEquals(tc,"a5", array[6]);

  CuAssertIntEquals(tc, 2, (int)lengths[0]);
  CuAssertIntEquals(tc, 0, (int)lengths[1]);
  CuAssertIntEquals(tc, 2, (int)lengths[2]);
  CuAssertIntEquals(tc, 0, (int)lengths[3]);
  CuAssertIntEquals(tc, 2, (int)lengths[4]);
  CuAssertIntEquals(tc, 2, (int)lengths[5]);
  CuAssertIntEquals(tc, 2, (int)lengths[6]);

  iarr = 10; strcpy(test, "a1|| a2  | |a3 |a4|a5  ");
  array  = split_array(test, &iarr, '|', lengths);
  CuAssertIntEquals(tc,7,(int)iarr);
  CuAssertStrEquals(tc,"a1", array[0]);
  CuAssertStrEquals(tc,"",   array[1]);
  CuAssertStrEquals(tc,"a2", array[2]);
  CuAssertStrEquals(tc,"",   array[3]);
  CuAssertStrEquals(tc,"a3", array[4]);
  CuAssertStrEquals(tc,"a4", array[5]);
  CuAssertStrEquals(tc,"a5", array[6]);

  CuAssertIntEquals(tc, 2, (int)lengths[0]);
  CuAssertIntEquals(tc, 0, (int)lengths[1]);
  CuAssertIntEquals(tc, 2, (int)lengths[2]);
  CuAssertIntEquals(tc, 0, (int)lengths[3]);
  CuAssertIntEquals(tc, 2, (int)lengths[4]);
  CuAssertIntEquals(tc, 2, (int)lengths[5]);
  CuAssertIntEquals(tc, 2, (int)lengths[6]);

  iarr = 10; strcpy(test, "|");
  array  = split_array(test, &iarr, '|', lengths);
  CuAssertIntEquals(tc,2,(int)iarr);
  CuAssertStrEquals(tc,"",   array[0]);
  CuAssertStrEquals(tc,"",   array[1]);

  CuAssertIntEquals(tc, 0, (int)lengths[0]);
  CuAssertIntEquals(tc, 0, (int)lengths[1]);

  iarr = 10; strcpy(test, "|||");
  array  = split_array(test, &iarr, '|', lengths);
  CuAssertIntEquals(tc,4,(int)iarr);
  CuAssertStrEquals(tc,"",   array[0]);
  CuAssertStrEquals(tc,"",   array[1]);
  CuAssertStrEquals(tc,"",   array[2]);
  CuAssertStrEquals(tc,"",   array[3]);

  CuAssertIntEquals(tc, 0, (int)lengths[0]);
  CuAssertIntEquals(tc, 0, (int)lengths[1]);
  CuAssertIntEquals(tc, 0, (int)lengths[2]);
  CuAssertIntEquals(tc, 0, (int)lengths[3]);

  iarr = 10; strcpy(test, " a1 ");
  array  = split_array(test, &iarr, '|', lengths);
  CuAssertIntEquals(tc,1,(int)iarr);
  CuAssertStrEquals(tc,"a1",   array[0]);

  CuAssertIntEquals(tc, 2, (int)lengths[0]);

  iarr = 10; strcpy(test, "");
  array  = split_array(test, &iarr, '|', lengths);
  CuAssertIntEquals(tc,1,(int)iarr);
  CuAssertStrEquals(tc,"",   array[0]);

  CuAssertIntEquals(tc, 0, (int)lengths[0]);

  /* WS separated */

  iarr = 10; strcpy(test, "a1");
  array  = split_array_ws (test, &iarr, lengths);
  CuAssertIntEquals(tc,1,(int)iarr);
  CuAssertStrEquals(tc,"a1",   array[0]);

  CuAssertIntEquals(tc, 2, (int)lengths[0]);

  iarr = 10; strcpy(test, " a1");
  array  = split_array_ws (test, &iarr, lengths);
  CuAssertIntEquals(tc,1,(int)iarr);
  CuAssertStrEquals(tc,"a1",   array[0]);

  CuAssertIntEquals(tc, 2, (int)lengths[0]);

  iarr = 10; strcpy(test, " a1 ");
  array  = split_array_ws (test, &iarr, lengths);
  CuAssertIntEquals(tc,1,(int)iarr);
  CuAssertStrEquals(tc,"a1",   array[0]);

  CuAssertIntEquals(tc, 2, (int)lengths[0]);

  iarr = 10; strcpy(test, "   ");
  array  = split_array_ws (test, &iarr, lengths);
  CuAssertIntEquals(tc,0,(int)iarr);
  CuAssertTrue(tc, array[0] == NULL);

  iarr = 10; strcpy(test, " a1 a2");
  array  = split_array_ws (test, &iarr, lengths);
  CuAssertIntEquals(tc,2,(int)iarr);
  CuAssertStrEquals(tc,"a1",   array[0]);
  CuAssertStrEquals(tc,"a2",   array[1]);

  CuAssertIntEquals(tc, 2, (int)lengths[0]);
  CuAssertIntEquals(tc, 2, (int)lengths[1]);

  iarr = 10; strcpy(test, " a1  a2  ");
  array  = split_array_ws (test, &iarr, lengths);
  CuAssertIntEquals(tc,2,(int)iarr);
  CuAssertStrEquals(tc,"a1",   array[0]);
  CuAssertStrEquals(tc,"a2",   array[1]);

  CuAssertIntEquals(tc, 2, (int)lengths[0]);
  CuAssertIntEquals(tc, 2, (int)lengths[1]);

  iarr = 10; strcpy(test, "");
  array  = split_array_ws (test, &iarr, lengths);
  CuAssertIntEquals(tc,0,(int)iarr);
  CuAssertTrue(tc, array[0] == NULL);

  iarr = 3; strcpy(test, " this is a test for remainder");
  array  = split_array_ws (test, &iarr, lengths);
  CuAssertIntEquals(tc,3,(int)iarr);
  CuAssertStrEquals(tc,"this",   array[0]);
  CuAssertStrEquals(tc,"is",     array[1]);
  CuAssertStrEquals(tc,"a test for remainder",     array[2]);
  for (i = 0; i < 3; ++i)
    {
      CuAssertIntEquals(tc, (int)strlen(array[i]), lengths[i] );
    }

  /* split_array_list */
  iarr = 6; strcpy(test, " this(a) is_a(test);for(b),remainder(test)foo(bar)");
  array  = split_array_list (test, &iarr, lengths);
  CuAssertIntEquals(tc,3,(int)iarr);
  CuAssertStrEquals(tc,"this(a)",   array[0]);
  CuAssertStrEquals(tc,"is_a(test);for(b)",     array[1]);
  CuAssertStrEquals(tc,"remainder(test)foo(bar)",     array[2]);
  for (i = 0; i < 3; ++i)
    {
      CuAssertIntEquals(tc, (int)strlen(array[i]), lengths[i] );
    }

  
  /* string replace */
  s = sh_string_new_from_lchar3 ("abc ", 4, "def ", 4, "ghi ", 4);
  ovecnum = 2;
  ovector[0] = 0;  ovector[1] = 2;
  ovector[2] = 4;  ovector[3] = 11;

  t = sh_string_replace(s, ovector, ovecnum, 
                        "___", 3);
  CuAssertPtrNotNull(tc, t);
  CuAssertStrEquals(tc, "___c ___ ",   t->str);
  CuAssertIntEquals(tc, 9, (int)t->len);

  ovector[0] = 0;  ovector[1] = 2;
  ovector[2] = 4;  ovector[3] = 12; 
  t = sh_string_replace(s, ovector, ovecnum, 
                        "___", 3);
  CuAssertPtrNotNull(tc, t);
  CuAssertStrEquals(tc, "___c ___",   t->str);
  CuAssertIntEquals(tc, 8, (int)t->len);

  ovector[0] = 0;  ovector[1] = 0;
  ovector[2] = 0;  ovector[3] = 0; 
  t = sh_string_replace(s, ovector, ovecnum, 
                        "___", 3);
  CuAssertTrue(tc, t == NULL);

  ovector[0] = 0;  ovector[1] = 3;
  ovector[2] = 3;  ovector[3] = 6; 
  t = sh_string_replace(s, ovector, ovecnum, 
                        "___", 3);
  
  CuAssertPtrNotNull(tc, t);
  CuAssertStrEquals(tc, "______f ghi ",   t->str);
  CuAssertIntEquals(tc, 12, (int)t->len);

  ovector[0] = 4;  ovector[1] = 5;
  ovector[2] = 11;  ovector[3] = 12; 
  t = sh_string_replace(s, ovector, ovecnum, 
                        "___", 3);
  CuAssertPtrNotNull(tc, t);
  CuAssertStrEquals(tc, "abc ___ef ghi___",   t->str);
  CuAssertIntEquals(tc, 16, (int)t->len);

  t = sh_string_replace(s, ovector, 0, 
                        "___", 3);
  CuAssertPtrNotNull(tc, t);
  CuAssertStrEquals(tc, s->str,   t->str);
  CuAssertIntEquals(tc, (int)s->len, (int)t->len);

}

#endif
