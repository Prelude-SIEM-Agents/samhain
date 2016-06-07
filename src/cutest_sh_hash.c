
#include "config_xor.h"

#include <string.h>
#include "CuTest.h"

extern char * quote_string   (const char * str, size_t len);
extern char * unquote_string (const char * str, size_t len);

void Test_quote_string_ok (CuTest *tc) {

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
  char * ret = 0;

  char   inp1[] = "foo\nba=r\ntest";
  char   out1[] = "foo=0Aba=3Dr=0Atest";

  char   inp2[] = "\n=foo\nba=r\ntest=\n";
  char   out2[] = "=0A=3Dfoo=0Aba=3Dr=0Atest=3D=0A";

  ret = quote_string(inp1, strlen(inp1));
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, out1, ret);

  ret = quote_string(inp2,strlen(inp2));
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, out2, ret);
#else
  (void) tc; /* fix compiler warning */
#endif
  return;
}

void Test_unquote_string_ok (CuTest *tc) {
#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
  char * ret = 0;

  char   out1[] = "foo\nba=r\ntes[t";
  char   inp1[] = "foo=0Aba=3Dr=0Ates=5Bt";

  char   out2[] = "\n=foo\nba=r\ntest=\n";
  char   inp2[] = "=0A=3Dfoo=0Aba=3Dr=0Atest=3D=0A";

  char   out3[] = ""; /* encoded '\0' at start */
  char   inp3[] = "=00=3Dfoo=0Aba=3Dr=0Atest=3D=0A";

  ret = unquote_string(inp1, strlen(inp1));
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, out1, ret);

  ret = unquote_string(inp2, strlen(inp2));
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, out2, ret);

  ret = unquote_string(inp3, strlen(inp3));
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, out3, ret);
#else
  (void) tc; /* fix compiler warning */
#endif
  return;
}


void Test_csv_escape_ok (CuTest *tc) {
#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)

  extern char * csv_escape(const char * str);

  char   test0[80];
  char   expec[80];
  char  *ret;

  strcpy(test0, "foobar");
  strcpy(expec, "\"foobar\"");
  ret = csv_escape(test0);
  CuAssertStrEquals(tc, expec, ret);

  strcpy(test0, "\"foobar\"");
  strcpy(expec, "\"\"\"foobar\"\"\"");
  ret = csv_escape(test0);
  CuAssertStrEquals(tc, expec, ret);

  strcpy(test0, "foo,bar");
  strcpy(expec, "\"foo,bar\"");
  ret = csv_escape(test0);
  CuAssertStrEquals(tc, expec, ret);

  strcpy(test0, "foob,\"a\"r");
  strcpy(expec, "\"foob,\"\"a\"\"r\"");
  ret = csv_escape(test0);
  CuAssertStrEquals(tc, expec, ret);

  strcpy(test0, "\",\"foobar\",\"");
  strcpy(expec, "\"\"\",\"\"foobar\"\",\"\"\"");
  ret = csv_escape(test0);
  CuAssertStrEquals(tc, expec, ret);

  strcpy(test0, "");
  strcpy(expec, "");
  ret = csv_escape(test0);
  CuAssertStrEquals(tc, expec, ret);

  strcpy(test0, "a");
  strcpy(expec, "\"a\"");
  ret = csv_escape(test0);
  CuAssertStrEquals(tc, expec, ret);

  strcpy(test0, "foo\"bar");
  strcpy(expec, "\"foo\"\"bar\"");
  ret = csv_escape(test0);
  CuAssertStrEquals(tc, expec, ret);

#else
  (void) tc; /* fix compiler warning */
#endif
  return;
}



