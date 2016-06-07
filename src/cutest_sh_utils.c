
#include "config_xor.h"

#include <string.h>
#include "CuTest.h"
#include "samhain.h"
#include "sh_utils.h"

void Test_sl_strlcpy (CuTest *tc) {
  int ret;
  char out[] = "aaaaaa";
  char in[]  = "bbb";

  ret = sl_strlcpy (NULL, NULL, 0);
  CuAssertIntEquals(tc, ret, SL_ENONE);

  ret = sl_strlcpy (NULL, in, 0);
  CuAssertIntEquals(tc, ret, SL_ENULL);

  ret = sl_strlcpy (out, NULL, 0);
  CuAssertIntEquals(tc, ret, SL_ENONE);

  ret = sl_strlcpy (out, in, 0);
  CuAssertIntEquals(tc, ret, SL_ENONE);

  ret = sl_strlcpy (out, NULL, 7);
  CuAssertIntEquals(tc, ret, SL_ENONE);
  CuAssertStrEquals(tc, "", out);

  out[0] = 'a';
  ret = sl_strlcpy (out, in, 4);
  CuAssertIntEquals(tc, ret, SL_ENONE);
  CuAssertStrEquals(tc, "bbb", out);
  CuAssertStrEquals(tc, "aa", &out[4]);
  
  return;
}

void Test_sl_strlcat (CuTest *tc) {
  int ret;
  char out[16] = "aaaaaa";
  char in[16]  = "bbb";

  ret = sl_strlcat (NULL, NULL, 0);
  CuAssertIntEquals(tc, ret, SL_ENONE);

  ret = sl_strlcat (NULL, in, 0);
  CuAssertIntEquals(tc, ret, SL_ENONE);

  ret = sl_strlcat (out, NULL, 0);
  CuAssertIntEquals(tc, ret, SL_ENONE);

  ret = sl_strlcat (out, in, 0);
  CuAssertIntEquals(tc, ret, SL_ENONE);

  ret = sl_strlcat (out, NULL, sizeof(out));
  CuAssertIntEquals(tc, ret, SL_ENONE);
  CuAssertStrEquals(tc, "aaaaaa", out);

  ret = sl_strlcat (out, in, 7);
  CuAssertIntEquals(tc, ret, SL_ETRUNC);
  CuAssertStrEquals(tc, "aaaaaa", out);

  ret = sl_strlcat (out, in, 8);
  CuAssertIntEquals(tc, ret, SL_ETRUNC);
  CuAssertStrEquals(tc, "aaaaaab", out);

  ret = sl_strlcat (out, in, sizeof(out));
  CuAssertIntEquals(tc, ret, SL_ENONE);
  CuAssertStrEquals(tc, "aaaaaabbbb", out);

  CuAssertStrEquals(tc, "bbb", in);

  return;
}

void Test_sh_util_acl_compact (CuTest *tc) {
  char * ret = 0;
  char   inp1[] = "user::r--\nuser:lisa:rwx\t\t#effective: r--\ngroup::r--\ngroup:toolies:rw-  #effective: r--\nmask::r--\nother::r--\n";
  char   inp2[] = "use\n\nuser:lisa:rwx\t\t#effective: r--\ngroup::r--\ngroup:toolies:rw-  #effective: r--\nmask::r--\nother::r--\n";
  char   inp3[] = "user:\177\145\177\122:r--\nuser:lisa:rwx\t\t#effective: r--\ngroup::r--\ngroup:toolies:rw-  #effective: r--\nmask::r--\nother::r--\n";
  
  ret = sh_util_acl_compact (inp1, strlen(inp1));
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, "u::r--,u:lisa:rwx,g::r--,g:toolies:rw-,m::r--,o::r--",
		    ret); 

  ret = sh_util_acl_compact (inp2, strlen(inp2));
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, "use,u:lisa:rwx,g::r--,g:toolies:rw-,m::r--,o::r--",
		    ret); 

  ret = sh_util_acl_compact (inp3, strlen(inp3));
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, "u:eR:r--,u:lisa:rwx,g::r--,g:toolies:rw-,m::r--,o::r--",
		    ret); 

  return;
}

void Test_sh_util_strdup_ok (CuTest *tc) {
  char * ret = 0;
  char   inp[] = "foobar";

  ret = sh_util_strdup(inp);
  CuAssertPtrNotNull(tc, ret);
  CuAssert(tc, "expected inp != ret, but inp == ret", (inp != ret)); 
  CuAssertStrEquals(tc, "foobar", ret);
  return;
}

void Test_sh_util_strconcat_ok (CuTest *tc) {
  char * ret = 0;

  ret = sh_util_strconcat("foo", NULL);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, "foo", ret);

  ret = sh_util_strconcat("foo", "bar", NULL);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, "foobar", ret);

  ret = sh_util_strconcat("/", "foo", "/", "bar", NULL);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, "/foo/bar", ret);

  return;
}

void Test_sh_util_base64_enc_ok (CuTest *tc) {
  unsigned char   out[64];
  unsigned char   ou2[64];
  int    ret;
  unsigned char   inp0[64] = "";
  unsigned char   inp1[64] = "A";
  unsigned char   inp2[64] = "AB";
  unsigned char   inp3[64] = "ABC";
  unsigned char   inp4[64] = "ABCD";

  ret = sh_util_base64_enc (out, inp0, strlen((char*)inp0));
  CuAssertIntEquals(tc, 0, ret);
  CuAssertStrEquals(tc, "", (char*)out);
  ret = sh_util_base64_dec (ou2, out, strlen((char*)out));
  CuAssertIntEquals(tc, ret, 0);
  CuAssertStrEquals(tc, (char*)inp0, (char*)ou2);

  ret = sh_util_base64_enc (out, inp1, strlen((char*)inp1));
  CuAssertIntEquals(tc, ret, 4);
  CuAssertStrEquals(tc, "QQ??", (char*)out);
  ret = sh_util_base64_dec (ou2, out, strlen((char*)out));
  CuAssertStrEquals(tc, (char*)inp1, (char*)ou2);
  CuAssertIntEquals(tc, 1, ret);

  ret = sh_util_base64_enc (out, inp2, strlen((char*)inp2));
  CuAssertIntEquals(tc, ret, 4);
  CuAssertStrEquals(tc, "QUI?", (char*)out);
  ret = sh_util_base64_dec (ou2, out, strlen((char*)out));
  CuAssertStrEquals(tc, (char*)inp2, (char*)ou2);
  CuAssertIntEquals(tc, 2, ret);

  ret = sh_util_base64_enc (out, inp3, strlen((char*)inp3));
  CuAssertIntEquals(tc, ret, 4);
  CuAssertStrEquals(tc, "QUJD", (char*)out);
  ret = sh_util_base64_dec (ou2, out, strlen((char*)out));
  CuAssertStrEquals(tc, (char*)inp3, (char*)ou2);
  CuAssertIntEquals(tc, 3, ret);

  ret = sh_util_base64_enc (out, inp4, strlen((char*)inp4));
  CuAssertIntEquals(tc, ret, 8);
  CuAssertStrEquals(tc, "QUJDRA??", (char*)out);
  ret = sh_util_base64_dec (ou2, out, strlen((char*)out));
  CuAssertStrEquals(tc, (char*)inp4, (char*)ou2);
  CuAssertIntEquals(tc, 4, ret);


  return;
}

void Test_sh_util_dirname_ok (CuTest *tc) {
  char * ret = 0;

  char input0[] = "/foo/bar";
  char res0[] = "/foo";

  char input1[] = "/foo/bar/";
  char res1[] = "/foo";

  char input2[] = "/foo";
  char res2[] = "/";

  char input3[] = "/";
  char res3[] = "/";

  char input4[] = "///foo//bar";
  char res4[] = "///foo";

  char input5[] = "//foo///bar///";
  char res5[] = "//foo";

  char input6[] = "///";
  char res6[] = "///";

  char input7[] = "//f///b///";
  char res7[] = "//f";

  char input8[] = "/f/b/";
  char res8[] = "/f";

  char input9[] = "/e/b";
  char res9[] = "/e";

  ret = sh_util_dirname(input0);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res0, ret);

  ret = sh_util_dirname(input1);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res1, ret);

  ret = sh_util_dirname(input2);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res2, ret);

  ret = sh_util_dirname(input3);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res3, ret);

  ret = sh_util_dirname(input4);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res4, ret);

  ret = sh_util_dirname(input5);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res5, ret);

  ret = sh_util_dirname(input6);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res6, ret);

  ret = sh_util_dirname(input7);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res7, ret);

  ret = sh_util_dirname(input8);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res8, ret);

  ret = sh_util_dirname(input9);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res9, ret);
  return;
}

void Test_sh_util_basename_ok (CuTest *tc) {
  char * ret = 0;

  char input0[] = "/foo/bar";
  char res0[] = "bar";

  char input1[] = "/foo/";
  char res1[] = "foo";

  char input2[] = "/foo";
  char res2[] = "foo";

  char input3[] = "/";
  char res3[] = "/";

  char input4[] = "/foo/bar/";
  char res4[] = "bar";

  char input5[] = "/foo///bar///";
  char res5[] = "bar";

  char input6[] = "//foo";
  char res6[] = "foo";

  ret = sh_util_basename(input0);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res0, ret);

  ret = sh_util_basename(input1);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res1, ret);

  ret = sh_util_basename(input2);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res2, ret);

  ret = sh_util_basename(input3);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res3, ret);

  ret = sh_util_basename(input4);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res4, ret);

  ret = sh_util_basename(input5);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res5, ret);

  ret = sh_util_basename(input6);
  CuAssertPtrNotNull(tc, ret);
  CuAssertStrEquals(tc, res6, ret);

  return;
}

void Test_sh_util_utf8_ok (CuTest *tc) {
  int ret = 0;
#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
  unsigned char seq[16];
  unsigned char input[16] = "foobar";

  seq[0] = 0x00;
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_TRUE);

  seq[0] = 0xd7; seq[1] = 0x90; seq[2] = 0x00;
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_TRUE);

  seq[0] = 0xed; seq[1] = 0x9f; seq[2] = 0xbf; seq[3] = 0x00;
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_TRUE);

  seq[0] = 0xee; seq[1] = 0x80; seq[2] = 0x80; seq[3] = 0x00;
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_TRUE);

  seq[0] = 0xef; seq[1] = 0xbf; seq[2] = 0xbd; seq[3] = 0x00;
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_TRUE);

  seq[0] = 0xf4; seq[1] = 0x8f; seq[2] = 0xbf; seq[3] = 0xbf; seq[4] = 0x00;
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_TRUE);

  seq[0] = 0xf4; seq[1] = 0x90; seq[2] = 0x80; seq[3] = 0x80; seq[4] = 0x00;
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_TRUE);

  seq[0] = 0xd7; seq[1] = 0x90; seq[2] = 0xd7; seq[3] = 0x90; seq[4] = 0x00;
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_TRUE);

  /* cont. char */

  seq[0] = 0x80; seq[1] = 0x00; 
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_FALSE);

  seq[0] = 0xbf; seq[1] = 0x00; 
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_FALSE);

  /* overlong */

  seq[0] = 0xc0; seq[1] = 0xaf; seq[2] = 0x00;  
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_FALSE);

  seq[0] = 0xe0; seq[1] = 0x8f; seq[2] = 0xaf;  seq[3] = 0x00;  
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_FALSE);

  seq[0] = 0xf0; seq[1] = 0x80; seq[2] = 0x80;  seq[3] = 0xaf; seq[4] = 0x00;  
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_FALSE);

  /* overlong */

  seq[0] = 0xc1; seq[1] = 0xbf; seq[2] = 0x00;  
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_FALSE);

  seq[0] = 0xe0; seq[1] = 0x9f; seq[2] = 0xbf;  seq[3] = 0x00;  
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_FALSE);

  seq[0] = 0xf0; seq[1] = 0x8f; seq[2] = 0xbf;  seq[3] = 0xbf; seq[4] = 0x00;  
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_FALSE);

  /* overlong */

  seq[0] = 0xc0; seq[1] = 0x80; seq[2] = 0x00;  
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_FALSE);

  seq[0] = 0xe0; seq[1] = 0x80; seq[2] = 0x80;  seq[3] = 0x00;  
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_FALSE);

  seq[0] = 0xf0; seq[1] = 0x80; seq[2] = 0x80;  seq[3] = 0x80; seq[4] = 0x00;  
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_FALSE);

  /* cont missing */

  seq[0] = 0xd7; seq[1] = 0x20; seq[3] = 0x00;
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_FALSE);

  seq[0] = 0xee; seq[1] = 0x80; seq[2] = 0x20; seq[3] = 0x00;
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_FALSE);

  seq[0] = 0xf4; seq[1] = 0x8f; seq[2] = 0xbf; seq[3] = 0x20; seq[4] = 0x00;
  ret = sh_util_valid_utf8(seq);
  CuAssertIntEquals(tc, ret, S_FALSE);

  /* switch on utf8 checking for sh_util_obscurename() */

  ret = sh_util_obscure_utf8("Y");
  CuAssertIntEquals(tc, ret, 0);

  ret = sh_util_obscure_ok ("0x01,0x02,0x03");
  CuAssertIntEquals(tc, ret, 0);

  ret = sh_util_valid_utf8 (input);
  CuAssertIntEquals(tc, ret, S_TRUE);
  ret = sh_util_obscurename (0, (char *)input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, 0);

  input[0] = '\t';
  ret = sh_util_valid_utf8 (input);
  CuAssertIntEquals(tc, ret, S_FALSE);
  ret = sh_util_obscurename (0, (char *)input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, -1);

  input[0] = 0x01;
  ret = sh_util_valid_utf8 (input);
  CuAssertIntEquals(tc, ret, S_TRUE);
  ret = sh_util_obscurename (0, (char *)input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, 0);

  input[0] = 0x02;
  ret = sh_util_valid_utf8 (input);
  CuAssertIntEquals(tc, ret, S_TRUE);
  ret = sh_util_obscurename (0, (char *)input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, 0);

  input[0] = 0x03;
  ret = sh_util_valid_utf8 (input);
  CuAssertIntEquals(tc, ret, S_TRUE);
  ret = sh_util_obscurename (0, (char *)input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, 0);

  input[0] = 0x04;
  ret = sh_util_valid_utf8 (input);
  CuAssertIntEquals(tc, ret, S_FALSE);
  ret = sh_util_obscurename (0, (char *)input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, -1);

  input[0] = 'f';
  ret = sh_util_valid_utf8 (input);
  CuAssertIntEquals(tc, ret, S_TRUE);
  ret = sh_util_obscurename (0, (char *)input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, 0);

  input[5] = ' ';
  ret = sh_util_valid_utf8 (input);
  CuAssertIntEquals(tc, ret, S_FALSE);
  ret = sh_util_obscurename (0, (char *)input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, -1);

  input[5] = 'r'; input[3] = ' ';
  ret = sh_util_valid_utf8 (input);
  CuAssertIntEquals(tc, ret, S_TRUE);
  ret = sh_util_obscurename (0, (char *)input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, 0);


#else
  CuAssertIntEquals(tc, ret, 0);
#endif
}

void Test_sh_util_obscure_ok (CuTest *tc) {

  int ret = 0;
#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
  char input[16] = "foobar";

  /* switch off utf8 checking for sh_util_obscurename() */

  ret = sh_util_obscure_utf8("N");
  CuAssertIntEquals(tc, ret, 0);

  ret = sh_util_obscure_ok ("0xA1,0xA2,0xA3");
  CuAssertIntEquals(tc, ret, 0);

  ret = sh_util_obscurename (0, input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, 0);

  input[0] = '\t';
  ret = sh_util_obscurename (0, input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, -1);

  input[0] = 0xA1;
  ret = sh_util_obscurename (0, input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, 0);

  input[0] = 0xA2;
  ret = sh_util_obscurename (0, input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, 0);

  input[0] = 0xA3;
  ret = sh_util_obscurename (0, input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, 0);

  input[0] = 0xA4;
  ret = sh_util_obscurename (0, input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, -1);

  input[0] = 'f';
  ret = sh_util_obscurename (0, input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, 0);

  input[5] = ' ';
  ret = sh_util_obscurename (0, input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, -1);

  input[5] = 'r'; input[3] = ' ';
  ret = sh_util_obscurename (0, input, S_FALSE /* no log message */);
  CuAssertIntEquals(tc, ret, 0);
#else
  CuAssertIntEquals(tc, ret, 0);
#endif
}

