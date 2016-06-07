
#include "config_xor.h"

#include <string.h>
#include "CuTest.h"
#include "samhain.h"

void Test_sl_stale (CuTest *tc) {

  extern int get_the_fd (SL_TICKET ticket);

  int       fd1, fd2, ret, line, val;
  SL_TICKET tfd1, tfd2;
  char *    err1;
  char      err2[128];

  line = __LINE__; tfd1 = sl_open_read(__FILE__, __LINE__, "/etc/group", SL_NOPRIV);
  CuAssertTrue(tc, tfd1 > 0);

  fd1 = get_the_fd(tfd1);
  CuAssertTrue(tc, fd1 >= 0);

  ret = close(fd1);
  CuAssertTrue(tc, ret == 0);

  tfd2 = sl_open_read(__FILE__, __LINE__, "/etc/group", SL_NOPRIV);
  CuAssertTrue(tc, tfd2 > 0);
  CuAssertTrue(tc, tfd2 != tfd1);

  fd2 = get_the_fd(tfd2);
  CuAssertIntEquals(tc, fd1, fd2);

  err1 = sl_check_stale();
  CuAssertTrue(tc, err1 != NULL);

  sl_snprintf(err2, sizeof(err2), 
	      "stale handle, %s, %d", __FILE__, line);
  val = strcmp(err1, err2);
  CuAssertIntEquals(tc, 0, val);
}

void Test_sl_snprintf (CuTest *tc) {

  int ret = 0;
  char input[16];

  memset (&input, 'X', 16);
  ret = sl_snprintf(input, 10, "%s\n", "01234567890123456789");
  CuAssertIntEquals(tc, ret, 0);
  CuAssertTrue(tc, input[9]  == '\0');
  CuAssertTrue(tc, input[10] == 'X');

  memset (&input, 'X', 16);
  ret = sl_snprintf(input, 4, "%d\n", "012345");
  CuAssertIntEquals(tc, ret, 0);
  CuAssertTrue(tc, input[3] == '\0');
  CuAssertTrue(tc, input[4] == 'X');
}

void Test_sl_strcasecmp (CuTest *tc) {
  char one[64], two[64];
  int  res;

  strcpy(one, "foo");
  strcpy(two, "foo");
  res = sl_strcasecmp(one, two);
  CuAssertIntEquals(tc, 0, res);

  strcpy(one, "fo");
  strcpy(two, "foo");
  res = sl_strcasecmp(one, two);
  CuAssertIntEquals(tc, -1, res);

  strcpy(one, "foo");
  strcpy(two, "fo");
  res = sl_strcasecmp(one, two);
  CuAssertIntEquals(tc, 1, res);

  strcpy(one, "1234");
  strcpy(two, "2345");
  res = sl_strcasecmp(one, two);
  CuAssertIntEquals(tc, -1, res);

  strcpy(one, "234");
  strcpy(two, "123");
  res = sl_strcasecmp(one, two);
  CuAssertIntEquals(tc, 1, res);

  strcpy(one, "");
  strcpy(two, "123");
  res = sl_strcasecmp(one, two);
  CuAssertIntEquals(tc, -1, res);

  strcpy(one, "234");
  strcpy(two, "");
  res = sl_strcasecmp(one, two);
  CuAssertIntEquals(tc, 1, res);

  strcpy(one, "");
  strcpy(two, "");
  res = sl_strcasecmp(one, two);
  CuAssertTrue(tc, res == 0);

#ifndef SL_FAIL_ON_ERROR
  res = sl_strcasecmp(NULL, two);
  CuAssertIntEquals(tc, -1, res);

  res = sl_strcasecmp(one, NULL);
  CuAssertIntEquals(tc, 1, res);

  res = sl_strcasecmp(NULL, NULL);
  CuAssertTrue(tc, res != 0);
#endif
}
