
#include "config_xor.h"

#include <string.h>
#include "CuTest.h"
#include "samhain.h"
#include "sh_tools.h"
#include "sh_ipvx.h"

void Test_sh_tools_safe_name_01(CuTest *tc) {
  /* xml specific */
  char* input = strdup("hello<wo>rld\"foo&");
  char* actual = sh_tools_safe_name(input, 1);
#ifdef SH_USE_XML
  char* expected = "hello=3cwo=3erld=22foo=26";
#else
  char* expected = "hello<wo>rld\"foo&";
#endif
  CuAssertStrEquals(tc, expected, actual);
}

void Test_sh_tools_safe_name_02(CuTest *tc) {
  /* html entities */
  char* input = strdup("hello&amp;&quot;&gt;&lt;");
  char* actual = sh_tools_safe_name(input, 0);
  char* expected = "hello=26=22=3e=3c";
  CuAssertStrEquals(tc, expected, actual);
}

void Test_sh_tools_safe_name_03(CuTest *tc) {
  char* input = strdup("\\\'hello\\");
  char* actual = sh_tools_safe_name(input, 0);
  char* expected = "=27hello";
  CuAssertStrEquals(tc, expected, actual);

  input = strdup("hello \"world\\\"");
  actual = sh_tools_safe_name(input, 0);
  expected = "hello \"world=22";
  CuAssertStrEquals(tc, expected, actual);

  input = strdup("hello\\\\");
  actual = sh_tools_safe_name(input, 0);
  expected = "hello=5c";
  CuAssertStrEquals(tc, expected, actual);

  input = strdup("hello\\n");
  actual = sh_tools_safe_name(input, 0);
  expected = "hello=0a";
  CuAssertStrEquals(tc, expected, actual);
}

void Test_sh_tools_safe_name_04(CuTest *tc) {
  /* invalid and valid octal code */
  char* input = strdup("hello\\\n");
  char* actual = sh_tools_safe_name(input, 0);
  char* expected = "hello";
  CuAssertStrEquals(tc, expected, actual);

  input = strdup("hello\\100");
  actual = sh_tools_safe_name(input, 0);
  expected = "hello=40";
  CuAssertStrEquals(tc, expected, actual);

  input = strdup("h\\\"ello\\100a");
  actual = sh_tools_safe_name(input, 0);
  expected = "h=22ello=40a";
  CuAssertStrEquals(tc, expected, actual);
}

void Test_sh_tools_safe_name_05(CuTest *tc) {
  /* encoding of '=' */
  char* input = strdup("he=llo=\"foo\"");
  char* actual = sh_tools_safe_name(input, 0);
  char* expected = "he=3dllo=\"foo\"";
  CuAssertStrEquals(tc, expected, actual);

  input = strdup("he=llo=<foo>");
  actual = sh_tools_safe_name(input, 0);
  expected = "he=3dllo=<foo>";
  CuAssertStrEquals(tc, expected, actual);
}

void Test_sh_tools_safe_name_06(CuTest *tc) {
  /* line break removal */
  char* input = strdup("hello\nworld");
  char* actual = sh_tools_safe_name(input, 0);
  char* expected = "hello world";
  CuAssertStrEquals(tc, expected, actual);
}

void Test_sh_tools_safe_name_07(CuTest *tc) {
  /* non-printable chars */
  char* input = strdup("hello world");
  char* actual;
  char* expected;

  input[0]  = 0x01;
  input[5]  = 0xFF;
  input[10] = 0xF0;

  actual   = sh_tools_safe_name(input, 0);
  expected = "=01ello=ffworl=f0";
  CuAssertStrEquals(tc, expected, actual);
}

void Test_is_numeric_01(CuTest *tc) {
  char* input  = strdup("hello world");

  CuAssertTrue(tc, !sh_ipvx_is_numeric(input));

  input  = strdup("127.0.0.1");
  CuAssertTrue(tc, sh_ipvx_is_numeric(input));
  input  = strdup("127.0.0.de");
  CuAssertTrue(tc, !sh_ipvx_is_numeric(input));
  input  = strdup("127");
  CuAssertTrue(tc, !sh_ipvx_is_numeric(input));
#if defined(USE_IPVX)
  input  = strdup("::1");
  CuAssertTrue(tc, sh_ipvx_is_numeric(input));
  input  = strdup("2002:c0a8:101::42");
  CuAssertTrue(tc, sh_ipvx_is_numeric(input));
  input  = strdup("2003:dead:beef:4dad:23:46:bb:101");
  CuAssertTrue(tc, sh_ipvx_is_numeric(input));
  input  = strdup("::192:168:0:1::");
  CuAssertTrue(tc, sh_ipvx_is_numeric(input));
  input  = strdup("1:1:192:168:0:1:1:1");
  CuAssertTrue(tc, sh_ipvx_is_numeric(input));
  input  = strdup("1:1:192:168:0:1:1:1:0");
  CuAssertTrue(tc, !sh_ipvx_is_numeric(input));
  input  = strdup("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
  CuAssertTrue(tc, sh_ipvx_is_numeric(input));
  input  = strdup("2001:db8:85a3:0:0:8a2e:370:7334");
  CuAssertTrue(tc, sh_ipvx_is_numeric(input));
  input  = strdup("2001:db8:85a3::8a2e:370:7334");
  CuAssertTrue(tc, sh_ipvx_is_numeric(input));
#endif
}

