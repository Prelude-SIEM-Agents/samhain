
#include "config_xor.h"

#include <string.h>
#include "CuTest.h"
#include "samhain.h"
#include "sh_unix.h"

int malloc_count = 0;

void Test_dnmalloc (CuTest *tc) {

  const int nalloc = 64 /* original dnmalloc 1.0-beta5 fails for >= 45 */;
  int j, i;
  int sum;
#ifndef USE_SYSTEM_MALLOC
  int i_malloc =  malloc_count;
#endif

  char * buf;
  char * area[256];

  /* test reuse of last freed chunk */
  buf = malloc(1024);
  CuAssertPtrNotNull(tc, buf);
  free(buf);
  area[0] = malloc(1024);
  CuAssertTrue(tc, buf == area[0]);
  free(area[0]);

  /* test realloc */
  buf = malloc(16);
  CuAssertPtrNotNull(tc, buf);
  strcpy(buf, "testing realloc");
  buf = realloc(buf, 32);
  strcat(buf, "testing realloc");
  CuAssertStrEquals(tc, "testing realloctesting realloc", buf);

#ifndef USE_SYSTEM_MALLOC
  i_malloc = malloc_count;
#endif

  for (j = 0; j < 64; ++j)
    {
      buf = malloc((j+1) * 1024);
      CuAssertPtrNotNull(tc, buf);
#ifndef USE_SYSTEM_MALLOC
#ifndef __clang__
      CuAssertIntEquals (tc, malloc_count, (i_malloc + 1));
#endif
#endif
      free(buf);
#ifndef USE_SYSTEM_MALLOC
      CuAssertIntEquals (tc, malloc_count, i_malloc);
#endif
    }

  /* test realloc */
  buf = malloc(16);
  CuAssertPtrNotNull(tc, buf);
  strcpy(buf, "testing realloc");
  buf = realloc(buf, 32);
  strcat(buf, "testing realloc");
  CuAssertStrEquals(tc, "testing realloctesting realloc", buf);

#ifndef USE_SYSTEM_MALLOC
  i_malloc = malloc_count;
#endif

  for (j = 0; j < 64; ++j)
    {
      buf = calloc(1, (j+1) * 1024);
      CuAssertPtrNotNull(tc, buf);
#ifndef USE_SYSTEM_MALLOC
      CuAssertIntEquals (tc, malloc_count, (i_malloc + 1));
#endif
      sum = 0;
      for (i = 0; i < ((j+1) * 1024); ++i)
	sum += buf[i];
      CuAssertIntEquals (tc, 0, sum);
      free(buf);
#ifndef USE_SYSTEM_MALLOC
      CuAssertIntEquals (tc, malloc_count, i_malloc);
#endif
    }

  /* test realloc */
  buf = malloc(16);
  CuAssertPtrNotNull(tc, buf);
  strcpy(buf, "testing realloc");
  buf = realloc(buf, 32);
  strcat(buf, "testing realloc");
  CuAssertStrEquals(tc, "testing realloctesting realloc", buf);

  for (j = 0; j < nalloc; ++j)
    {
      area[j] = malloc((j+1) * 1024);
      CuAssertPtrNotNull(tc, area[j]);
#ifndef USE_SYSTEM_MALLOC
      /* CuAssertIntEquals (tc, malloc_count, (i_malloc + (j+1))); */
#endif
      memset(area[j], (unsigned char) ('a'+1), (j+1) * 1024);
    }

#ifndef USE_SYSTEM_MALLOC
  i_malloc =  malloc_count;
#endif

  for (j = 0; j < nalloc; ++j)
    {
      sum = 0;
      for (i = 0; i < ((j+1) * 1024); ++i)
	sum +=  area[j][i];
      CuAssertIntEquals (tc, sum, ((j+1) * 1024 * ((unsigned char) ('a'+1))));
      free(area[j]);
#ifndef USE_SYSTEM_MALLOC
      CuAssertIntEquals (tc, malloc_count, i_malloc - (j+1));
#endif
    }

  /* test realloc */
  buf = malloc(16);
  CuAssertPtrNotNull(tc, buf);
  strcpy(buf, "testing realloc");
  buf = realloc(buf, 32);
  strcat(buf, "testing realloc");
  CuAssertStrEquals(tc, "testing realloctesting realloc", buf);


  for (j = 0; j < 32; ++j)
    {
#ifndef USE_SYSTEM_MALLOC
      i_malloc =  malloc_count;
#endif
      buf = malloc((j+1) * 1024 * 1024);
      CuAssertPtrNotNull(tc, buf);
      for (i = 0; i < 32; ++i)
	{
	  area[i] = malloc((i+1) * 1024);
	  CuAssertPtrNotNull(tc, area[i]);
	}
      free(buf);
      for (i = 0; i < 32; ++i)
	{
	  free(area[i]);
	}
#ifndef USE_SYSTEM_MALLOC
      CuAssertIntEquals (tc, malloc_count, i_malloc);
#endif
    }

  /* test realloc */
  buf = malloc(16);
  CuAssertPtrNotNull(tc, buf);
  strcpy(buf, "testing realloc");
  buf = realloc(buf, 32);
  strcat(buf, "testing realloc");
  CuAssertStrEquals(tc, "testing realloctesting realloc", buf);
}

  
void Test_sh_unix_lookup_page (CuTest *tc) {

  long pagesize = sh_unix_pagesize();
  
  unsigned long base;
  int          num_pages;

  CuAssert (tc, "pagesize > 0", (pagesize > 0));

  /* base = sh_unix_lookup_page(in_addr, len, *num_pages); */

  base = sh_unix_lookup_page(0, pagesize, &num_pages);
  CuAssert (tc, "base == 0", (base == 0));
  CuAssertIntEquals (tc, num_pages, 1);

  base = sh_unix_lookup_page(0, pagesize+1, &num_pages);
  CuAssert (tc, "base == 0", (base == 0));
  CuAssertIntEquals (tc, num_pages, 2);

  base = sh_unix_lookup_page((void*)pagesize, pagesize, &num_pages);
  CuAssert (tc, "base == 0", (base == (unsigned int)pagesize));
  CuAssertIntEquals (tc, num_pages, 1);

  base = sh_unix_lookup_page((void*)pagesize, pagesize+1, &num_pages);
  CuAssert (tc, "base == 0", (base == (unsigned int)pagesize));
  CuAssertIntEquals (tc, num_pages, 2);

  base = sh_unix_lookup_page((void*)(pagesize-1), pagesize+1, &num_pages);
  CuAssert (tc, "base == 0", (base == 0));
  CuAssertIntEquals (tc, num_pages, 2);

  base = sh_unix_lookup_page((void*)(pagesize-1), pagesize+2, &num_pages);
  CuAssert (tc, "base == 0", (base == 0));
  CuAssertIntEquals (tc, num_pages, 3);

}

  
