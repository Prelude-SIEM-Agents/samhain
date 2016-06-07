
#include "config_xor.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "CuTest.h"

#include "sh_tiger.h"
#include "sh_checksum.h"

#if defined(HAVE_PTHREAD) && defined(SH_STEALTH)
extern void sh_g_init(void);
#endif


static void init(void) {

  extern unsigned char TcpFlag[8][PW_LEN+1];
  extern UINT32  ErrFlag[2];
  unsigned char * dez = NULL;
  int i;

#if defined(HAVE_PTHREAD) && defined(SH_STEALTH)
  sh_g_init();
#endif
  skey = (sh_key_t *) malloc (sizeof(sh_key_t));
  if (skey != NULL) 
    {
      skey->mlock_failed = S_FALSE;
      skey->rngI         = BAD;
      /* properly initialized later 
       */
      skey->rng0[0] = 0x03; skey->rng0[1] = 0x09; skey->rng0[2] = 0x17;
      skey->rng1[0] = 0x03; skey->rng1[1] = 0x09; skey->rng1[2] = 0x17;
      skey->rng2[0] = 0x03; skey->rng2[1] = 0x09; skey->rng2[2] = 0x17;
      
      for (i = 0; i < KEY_BYT; ++i)
	skey->poolv[i] = '\0';
      
      skey->poolc        = 0;
      
      skey->ErrFlag[0]   = ErrFlag[0];
      ErrFlag[0]         = 0;
      skey->ErrFlag[1]   = ErrFlag[1];
      ErrFlag[1]         = 0;
      
      dez = &(TcpFlag[POS_TF-1][0]);
      for (i = 0; i < PW_LEN; ++i)
	{ 
	  skey->pw[i] = (char) (*dez); 
	  (*dez)      = '\0';
	  ++dez; 
	}
      
      skey->sh_sockpass[0]  = '\0';
      skey->sigkey_old[0]   = '\0';
      skey->sigkey_new[0]   = '\0';
      skey->mailkey_old[0]  = '\0';
      skey->mailkey_new[0]  = '\0';
      skey->crypt[0]        = '\0';
      skey->session[0]      = '\0';
      skey->vernam[0]       = '\0';
    }
  else
    {
      perror(_("sh_init"));
      _exit (EXIT_FAILURE);
    }

}
  
void Test_tiger(CuTest *tc) {

  char * input;
  char * actual;
  char * expected;
  char hashbuf[KEYBUF_SIZE];

#if defined(HAVE_PTHREAD) && defined(SH_STEALTH)
  sh_g_init();
#endif

  input  = "";
  actual = sh_tiger_hash(input, TIGER_DATA, strlen(input), hashbuf, sizeof(hashbuf));
  expected = "24F0130C63AC933216166E76B1BB925FF373DE2D49584E7A";
  CuAssertStrEquals(tc, expected, actual);

  input  = "abc";
  actual = sh_tiger_hash(input, TIGER_DATA, strlen(input), hashbuf, sizeof(hashbuf));
  expected = "F258C1E88414AB2A527AB541FFC5B8BF935F7B951C132951";
  CuAssertStrEquals(tc, expected, actual);
  
  input  = "Tiger";
  actual = sh_tiger_hash(input, TIGER_DATA, strlen(input), hashbuf, sizeof(hashbuf));
  expected = "9F00F599072300DD276ABB38C8EB6DEC37790C116F9D2BDF";
  CuAssertStrEquals(tc, expected, actual);
  
  input  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";
  actual = sh_tiger_hash(input, TIGER_DATA, strlen(input), hashbuf, sizeof(hashbuf));
  expected = "87FB2A9083851CF7470D2CF810E6DF9EB586445034A5A386";
  CuAssertStrEquals(tc, expected, actual);
  
  input  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789";
  actual = sh_tiger_hash(input, TIGER_DATA, strlen(input), hashbuf, sizeof(hashbuf));
  expected = "467DB80863EBCE488DF1CD1261655DE957896565975F9197";
  CuAssertStrEquals(tc, expected, actual);
  
  input  = "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham";
  actual = sh_tiger_hash(input, TIGER_DATA, strlen(input), hashbuf, sizeof(hashbuf));
  expected = "0C410A042968868A1671DA5A3FD29A725EC1E457D3CDB303";
  CuAssertStrEquals(tc, expected, actual);
  
  input  = "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge.";
  actual = sh_tiger_hash(input, TIGER_DATA, strlen(input), hashbuf, sizeof(hashbuf));
  expected = "EBF591D5AFA655CE7F22894FF87F54AC89C811B6B0DA3193";
  CuAssertStrEquals(tc, expected, actual);
  
  input  = "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge, 1996.";
  actual = sh_tiger_hash(input, TIGER_DATA, strlen(input), hashbuf, sizeof(hashbuf));
  expected = "3D9AEB03D1BD1A6357B2774DFD6D5B24DD68151D503974FC";
  CuAssertStrEquals(tc, expected, actual);
  
  input  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";
  actual = sh_tiger_hash(input, TIGER_DATA, strlen(input), hashbuf, sizeof(hashbuf));
  expected = "00B83EB4E53440C576AC6AAEE0A7485825FD15E70A59FFE4";
  CuAssertStrEquals(tc, expected, actual);
}

void Test_tiger_file(CuTest *tc) {

  SL_TICKET     rval_open;
  FILE * fp;
  int result;
  char * actual;
  char * expected;
  char hashbuf[KEYBUF_SIZE];
  char hexdigest[SHA256_DIGEST_STRING_LENGTH];
  UINT64  length;

  init();

  fp = fopen("cutest_foo", "w");
  CuAssertPtrNotNull(tc, fp);

  result = fprintf(fp, "%s\n", 
		   "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789");
  CuAssertTrue(tc, result >= 0);

  result = fclose(fp);
  CuAssertTrue(tc, result == 0);
  
  result = sh_tiger_hashtype("TIGER192");
  CuAssertTrue(tc, result == 0);

  /* same result as GnuPG 1.0.6 (gpg --load-extension tiger --print-md TIGER192) 
   */
  length = TIGER_NOLIM;
  actual = sh_tiger_generic_hash("cutest_foo", TIGER_FILE, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "0E9321614C966A33608C2A15F156E0435CACFD1213B9F095";
  CuAssertStrEquals(tc, expected, actual);

  rval_open = sl_open_fastread (__FILE__, __LINE__, "cutest_foo", SL_YESPRIV);
  CuAssertTrue(tc, rval_open >= 0);

  length = TIGER_NOLIM;
  actual = sh_tiger_generic_hash("cutest_foo", rval_open, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "0E9321614C966A33608C2A15F156E0435CACFD1213B9F095";
  CuAssertStrEquals(tc, expected, actual);

  result = sl_close(rval_open);
  CuAssertTrue(tc, result == 0);

  result = sh_tiger_hashtype("MD5");
  CuAssertTrue(tc, result == 0);

  rval_open = sl_open_fastread (__FILE__, __LINE__, "cutest_foo", SL_YESPRIV);
  CuAssertTrue(tc, rval_open >= 0);

  /* same result as GNU md5sum 
   */
  length = TIGER_NOLIM;
  actual = sh_tiger_generic_hash("cutest_foo", rval_open, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "AEEC4DDA496BCFBA691F4E8863BA84C00000000000000000";
  CuAssertStrEquals(tc, expected, actual);

  result = sl_close(rval_open);
  CuAssertTrue(tc, result == 0);

  result = sh_tiger_hashtype("SHA1");
  CuAssertTrue(tc, result == 0);

  rval_open = sl_open_fastread (__FILE__, __LINE__, "cutest_foo", SL_YESPRIV);
  CuAssertTrue(tc, rval_open >= 0);

  /* same result as gpg --print-md SHA1 
   */
  length = TIGER_NOLIM;
  actual = sh_tiger_generic_hash("cutest_foo", rval_open, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "2FE65D1D995B8F8BC8B13F798C07E7E935A787ED00000000";
  CuAssertStrEquals(tc, expected, actual);

  result = sl_close(rval_open);
  CuAssertTrue(tc, result == 0);

  result = sh_tiger_hashtype("SHA256");
  CuAssertTrue(tc, result == 0);

  rval_open = sl_open_fastread (__FILE__, __LINE__, "cutest_foo", SL_YESPRIV);
  CuAssertTrue(tc, rval_open >= 0);

  /* same result as gpg --print-md SHA256
   */
  length = TIGER_NOLIM;
  {
    char * tmp = sh_tiger_generic_hash("cutest_foo", rval_open, &length, 0, hashbuf, sizeof(hashbuf));
    actual = SHA256_Base2Hex(tmp, hexdigest);
  }
  expected = "235790848f95e96b2c627f1bf58a2b8c05c535ada8c0a3326aac34ce1391ad40";
  CuAssertStrEquals(tc, expected, actual);

  result = sl_close(rval_open);
  CuAssertTrue(tc, result == 0);

  result = remove("cutest_foo");
  CuAssertTrue(tc, result == 0);

  /* --------------------------------------------------- */

  fp = fopen("cutest_foo", "w");
  CuAssertPtrNotNull(tc, fp);

  result = fprintf(fp, "\n");
  CuAssertTrue(tc, result >= 0);

  result = fclose(fp);
  CuAssertTrue(tc, result == 0);
  
  result = sh_tiger_hashtype("TIGER192");
  CuAssertTrue(tc, result == 0);

  /* same result as GnuPG 1.0.6 (gpg --load-extension tiger --print-md TIGER192) 
   */
  length = TIGER_NOLIM;
  actual = sh_tiger_generic_hash("cutest_foo", TIGER_FILE, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "F987845A0EA784367BF9E4DB09014995810F27C99C891734";
  CuAssertStrEquals(tc, expected, actual);

  result = remove("cutest_foo");
  CuAssertTrue(tc, result == 0);

  /* --------------------------------------------------- */

  fp = fopen("cutest_foo", "w");
  CuAssertPtrNotNull(tc, fp);

  result = fprintf(fp, "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge, 1996.\n");
  CuAssertTrue(tc, result >= 0);

  result = fclose(fp);
  CuAssertTrue(tc, result == 0);
  
  result = sh_tiger_hashtype("TIGER192");
  CuAssertTrue(tc, result == 0);

  /* same result as GnuPG 1.0.6 (gpg --load-extension tiger --print-md TIGER192) 
   */
  length = TIGER_NOLIM;
  actual = sh_tiger_generic_hash("cutest_foo", TIGER_FILE, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "75B98A7AE257A230189828A40792E30B4038D286479CC7B8";
  CuAssertStrEquals(tc, expected, actual);

  result = remove("cutest_foo");
  CuAssertTrue(tc, result == 0);

}  

/* test checksum of file upto some given length
 */
void Test_tiger_file_with_length(CuTest *tc) {

  SL_TICKET     rval_open;
  FILE * fp;
  int result;
  char * actual;
  char * expected;
  char hashbuf[KEYBUF_SIZE];
  UINT64  length;

  char * teststring = "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge, 1996.\n";
  size_t    testlen = strlen(teststring);

  init();

  fp = fopen("cutest_foo", "w");
  CuAssertPtrNotNull(tc, fp);

  result = fprintf(fp, "%s", teststring);
  CuAssertTrue(tc, result >= 0);
  result = fprintf(fp, "%s", teststring);
  CuAssertTrue(tc, result >= 0);

  result = fclose(fp);
  CuAssertTrue(tc, result == 0);
  
  result = sh_tiger_hashtype("TIGER192");
  CuAssertTrue(tc, result == 0);

  /* same as GnuPG 1.0.6 (gpg --load-extension tiger --print-md TIGER192) 
   */
  length = 0;
  actual = sh_tiger_generic_hash("cutest_foo", TIGER_FILE, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "24F0130C63AC933216166E76B1BB925FF373DE2D49584E7A";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, 0 == length);

  length = testlen;
  actual = sh_tiger_generic_hash("cutest_foo", TIGER_FILE, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "75B98A7AE257A230189828A40792E30B4038D286479CC7B8";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, testlen == length);

  length = 2*testlen;
  actual = sh_tiger_generic_hash("cutest_foo", TIGER_FILE, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "B5B4FB97B01ADB58794D87A6A01B2368852FA764BD93AB90";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, 2*testlen == length);

  length = TIGER_NOLIM;
  actual = sh_tiger_generic_hash("cutest_foo", TIGER_FILE, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "B5B4FB97B01ADB58794D87A6A01B2368852FA764BD93AB90";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, 2*testlen == length);

  fp = fopen("cutest_foo", "a");
  CuAssertPtrNotNull(tc, fp);
  result = fprintf(fp, "%s", teststring);
  CuAssertTrue(tc, result >= 0);
  result = fclose(fp);
  CuAssertTrue(tc, result == 0);

  length = testlen;
  actual = sh_tiger_generic_hash("cutest_foo", TIGER_FILE, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "75B98A7AE257A230189828A40792E30B4038D286479CC7B8";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, testlen == length);

  length = 2*testlen;
  actual = sh_tiger_generic_hash("cutest_foo", TIGER_FILE, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "B5B4FB97B01ADB58794D87A6A01B2368852FA764BD93AB90";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, 2*testlen == length);

  length = 3*testlen;
  actual = sh_tiger_generic_hash("cutest_foo", TIGER_FILE, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "D0EE1A9956CAB22D84B51A5E0C093B724828C6A1F9CBDB7F";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, 3*testlen == length);

  length = TIGER_NOLIM;
  actual = sh_tiger_generic_hash("cutest_foo", TIGER_FILE, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "D0EE1A9956CAB22D84B51A5E0C093B724828C6A1F9CBDB7F";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, 3*testlen == length);

  length = 5;
  actual = sh_tiger_generic_hash("cutest_foo", TIGER_FILE, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "9F00F599072300DD276ABB38C8EB6DEC37790C116F9D2BDF";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, 5 == length);

  /* same results as GNU md5sum */

  result = sh_tiger_hashtype("MD5");
  CuAssertTrue(tc, result == 0);

  rval_open = sl_open_fastread (__FILE__, __LINE__, "cutest_foo", SL_YESPRIV);
  CuAssertTrue(tc, rval_open >= 0);

  length = testlen;
  actual = sh_tiger_generic_hash("cutest_foo", rval_open, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "11E7E7EA486136273606BEE57C71F34B0000000000000000";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, testlen == length);

  result = sl_rewind(rval_open);
  CuAssertTrue(tc, rval_open >= 0);

  length = 2*testlen;
  actual = sh_tiger_generic_hash("cutest_foo", rval_open, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "D49DAD474095D467E2E5EFCB2DC23A770000000000000000";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, 2*testlen == length);

  result = sl_rewind(rval_open);
  CuAssertTrue(tc, rval_open >= 0);

  length = 3*testlen;
  actual = sh_tiger_generic_hash("cutest_foo", rval_open, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "00A1F1C5EDDCCFC430D3862FDA94593E0000000000000000";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, 3*testlen == length);

  result = sl_rewind(rval_open);
  CuAssertTrue(tc, rval_open >= 0);

  length = TIGER_NOLIM;
  actual = sh_tiger_generic_hash("cutest_foo", rval_open, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "00A1F1C5EDDCCFC430D3862FDA94593E0000000000000000";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, 3*testlen == length);

  /* same result as gpg --print-md SHA1 
   */

  result = sh_tiger_hashtype("SHA1");
  CuAssertTrue(tc, result == 0);

  result = sl_rewind(rval_open);
  CuAssertTrue(tc, rval_open >= 0);

  length = testlen;
  actual = sh_tiger_generic_hash("cutest_foo", rval_open, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "F37DB4344CCD140EE315179E9A27512FB4704F0F00000000";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, testlen == length);

  result = sl_rewind(rval_open);
  CuAssertTrue(tc, rval_open >= 0);

  length = 2*testlen;
  actual = sh_tiger_generic_hash("cutest_foo", rval_open, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "D2AD5FC366452D81400BAC31F96269DEEF314BC200000000";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, 2*testlen == length);

  result = sl_rewind(rval_open);
  CuAssertTrue(tc, rval_open >= 0);

  length = 3*testlen;
  actual = sh_tiger_generic_hash("cutest_foo", rval_open, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "FAA937EF3389C7E786EB0F1006D049D7AEA7B7B600000000";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, 3*testlen == length);

  result = sl_rewind(rval_open);
  CuAssertTrue(tc, rval_open >= 0);

  length = TIGER_NOLIM;
  actual = sh_tiger_generic_hash("cutest_foo", rval_open, &length, 0, hashbuf, sizeof(hashbuf));
  expected = "FAA937EF3389C7E786EB0F1006D049D7AEA7B7B600000000";
  CuAssertStrEquals(tc, expected, actual);
  CuAssertTrue(tc, 3*testlen == length);

  result = sl_close(rval_open);
  CuAssertTrue(tc, result == 0);

  result = remove("cutest_foo");
  CuAssertTrue(tc, result == 0);
}
