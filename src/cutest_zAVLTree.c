
#include "config_xor.h"

#include <string.h>
#include "CuTest.h"
#include "zAVLTree.h"

struct ztest {
  char name[32];
  int  iname;
};

static zAVLTree * ztest_tree   = NULL;

static zAVLKey ztest_key (void const * arg)
{
  const struct ztest * sa = (const struct ztest *) arg;
  return (zAVLKey) sa->name;
}

static zAVLKey ztest_intkey(void const *item)
{
  return (&((const struct ztest *)item)->iname);
}


static void free_node (void * inptr)
{
  struct ztest * ptr = (struct ztest *) inptr;
  ptr->name[0] = '\0';
  ptr->iname   = 0;
}

void Test_zAVLTree(CuTest *tc) {
  zAVLCursor    cursor;

  int result;
  int counter = 0;

  char * str;

  struct ztest z1 = { "abc"  , 1 };
  struct ztest z2 = { "aac"  , 2 };
  struct ztest z3 = { "aaa1" , 3 };
  struct ztest z4 = { "aaa3" , 4 };
  struct ztest z5 = { "aaa2" , 5 };
  struct ztest z6 = { "aaa6" , 6 };
  struct ztest z7 = { "aaa5" , 7 };
  struct ztest z8 = { "aaa4" , 8 };

  struct ztest iz1 = { "aaa1" , 8 };
  struct ztest iz2 = { "aaa2" , 7 };
  struct ztest iz3 = { "aaa3" , 1 };
  struct ztest iz4 = { "aaa4" , 3 };
  struct ztest iz5 = { "aaa5" , 2 };
  struct ztest iz6 = { "aaa5" , 6 };
  struct ztest iz7 = { "aaa7" , 5 };
  struct ztest iz8 = { "aaa8" , 4 };

  struct ztest * ptr;

  ptr = zAVLFirst(&cursor, ztest_tree);
  CuAssertTrue(tc, NULL == ptr);

  ztest_tree = zAVLAllocTree (ztest_key, zAVL_KEY_STRING);
  CuAssertPtrNotNull(tc, ztest_tree);

  do {

  ++counter;

  result = zAVLInsert(ztest_tree, &z1);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z2);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z3);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z4);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z5);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z6);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z7);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z8);
  CuAssertTrue(tc, 0 == result);

  ptr = zAVLFirst(&cursor, ztest_tree);
  CuAssertStrEquals(tc, ptr->name, z3.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z5.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z4.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z8.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z7.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z6.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z2.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z1.name);
  ptr = zAVLNext(&cursor);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLInsert(ztest_tree, &z8);
  CuAssertTrue(tc, 0 != result);
  result = zAVLInsert(ztest_tree, &z7);
  CuAssertTrue(tc, 0 != result);
  result = zAVLInsert(ztest_tree, &z6);
  CuAssertTrue(tc, 0 != result);
  result = zAVLInsert(ztest_tree, &z5);
  CuAssertTrue(tc, 0 != result);

  ptr = zAVLSearch(ztest_tree, z1.name);
  CuAssertStrEquals(tc, ptr->name, z1.name);
  ptr = zAVLSearch(ztest_tree, z2.name);
  CuAssertStrEquals(tc, ptr->name, z2.name);
  ptr = zAVLSearch(ztest_tree, z3.name);
  CuAssertStrEquals(tc, ptr->name, z3.name);
  ptr = zAVLSearch(ztest_tree, z4.name);
  CuAssertStrEquals(tc, ptr->name, z4.name);

  ptr = zAVLFirst(&cursor, ztest_tree);
  CuAssertStrEquals(tc, ptr->name, z3.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z5.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z4.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z8.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z7.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z6.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z2.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z1.name);
  ptr = zAVLNext(&cursor);
  CuAssertTrue(tc, NULL == ptr);


  ptr = zAVLSearch(ztest_tree, z5.name);
  CuAssertStrEquals(tc, ptr->name, z5.name);
  ptr = zAVLSearch(ztest_tree, z6.name);
  CuAssertStrEquals(tc, ptr->name, z6.name);
  ptr = zAVLSearch(ztest_tree, z7.name);
  CuAssertStrEquals(tc, ptr->name, z7.name);
  ptr = zAVLSearch(ztest_tree, z8.name);
  CuAssertStrEquals(tc, ptr->name, z8.name);
  ptr = zAVLSearch(ztest_tree, "foobar");
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z8.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z8.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z3.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z3.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z1.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z1.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLInsert(ztest_tree, &z1);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z8);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z3);
  CuAssertTrue(tc, 0 == result);

  ptr = zAVLFirst(&cursor, ztest_tree);
  CuAssertStrEquals(tc, ptr->name, z3.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z5.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z4.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z8.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z7.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z6.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z2.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z1.name);
  ptr = zAVLNext(&cursor);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z1.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z1.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z2.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z2.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z3.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z3.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z4.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z4.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z5.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z5.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z6.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z6.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z7.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z7.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z8.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z8.name);
  CuAssertTrue(tc, NULL == ptr);

} while (counter < 100);

  result = zAVLInsert(ztest_tree, &z1);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z2);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z3);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z4);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z5);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z6);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z7);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z8);
  CuAssertTrue(tc, 0 == result);

  zAVLFreeTree (ztest_tree, free_node);
  CuAssertTrue (tc, z1.name[0] == '\0');
  CuAssertTrue (tc, z2.name[0] == '\0');
  CuAssertTrue (tc, z3.name[0] == '\0');
  CuAssertTrue (tc, z4.name[0] == '\0');
  CuAssertTrue (tc, z5.name[0] == '\0');
  CuAssertTrue (tc, z6.name[0] == '\0');
  CuAssertTrue (tc, z7.name[0] == '\0');
  CuAssertTrue (tc, z8.name[0] == '\0');


  /* Numeric key here */

  counter    = 0;
  ztest_tree = NULL;

  ptr = zAVLFirst(&cursor, ztest_tree);
  CuAssertTrue(tc, NULL == ptr);

  ztest_tree = zAVLAllocTree (ztest_intkey, zAVL_KEY_INT);
  CuAssertPtrNotNull(tc, ztest_tree);

  do {

  ++counter;

  result = zAVLInsert(ztest_tree, &iz1);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &iz2);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &iz3);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &iz4);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &iz5);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &iz6);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &iz7);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &iz8);
  CuAssertTrue(tc, 0 == result);

  ptr = zAVLFirst(&cursor, ztest_tree);
  CuAssertStrEquals(tc, ptr->name, iz3.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz5.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz4.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz8.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz7.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz6.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz2.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz1.name);
  ptr = zAVLNext(&cursor);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLInsert(ztest_tree, &iz8);
  CuAssertTrue(tc, 0 != result);
  result = zAVLInsert(ztest_tree, &iz7);
  CuAssertTrue(tc, 0 != result);
  result = zAVLInsert(ztest_tree, &iz6);
  CuAssertTrue(tc, 0 != result);
  result = zAVLInsert(ztest_tree, &iz5);
  CuAssertTrue(tc, 0 != result);

  ptr = zAVLSearch(ztest_tree, &(iz1.iname));
  CuAssertIntEquals(tc, ptr->iname, iz1.iname);
  ptr = zAVLSearch(ztest_tree, &(iz2.iname));
  CuAssertIntEquals(tc, ptr->iname, iz2.iname);
  ptr = zAVLSearch(ztest_tree, &(iz3.iname));
  CuAssertIntEquals(tc, ptr->iname, iz3.iname);
  ptr = zAVLSearch(ztest_tree, &(iz6.iname));
  CuAssertIntEquals(tc, ptr->iname, iz6.iname);
  ptr = zAVLSearch(ztest_tree, &(iz4.iname));
  CuAssertIntEquals(tc, ptr->iname, iz4.iname);

  ptr = zAVLSearch(ztest_tree, &(iz2.iname));
  CuAssertIntEquals(tc, ptr->iname, iz2.iname);
  ptr = zAVLSearch(ztest_tree, &(iz3.iname));
  CuAssertIntEquals(tc, ptr->iname, iz3.iname);
  ptr = zAVLSearch(ztest_tree, &(iz7.iname));
  CuAssertIntEquals(tc, ptr->iname, iz7.iname);

  ptr = zAVLFirst(&cursor, ztest_tree);
  CuAssertStrEquals(tc, ptr->name, iz3.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz5.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz4.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz8.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz7.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz6.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz2.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz1.name);
  ptr = zAVLNext(&cursor);
  CuAssertTrue(tc, NULL == ptr);


  ptr = zAVLSearch(ztest_tree, &(iz5.iname));
  CuAssertStrEquals(tc, ptr->name, iz5.name);
  ptr = zAVLSearch(ztest_tree, &(iz6.iname));
  CuAssertStrEquals(tc, ptr->name, iz6.name);
  ptr = zAVLSearch(ztest_tree, &(iz7.iname));
  CuAssertStrEquals(tc, ptr->name, iz7.name);
  ptr = zAVLSearch(ztest_tree, &(iz8.iname));
  CuAssertStrEquals(tc, ptr->name, iz8.name);
  ptr = zAVLSearch(ztest_tree, &(z1.iname)); /* been set to 0 */
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, &(iz8.iname));
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, &(iz8.iname));
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, &(iz3.iname));
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, &(iz3.iname));
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, &(iz1.iname));
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, &(iz1.iname));
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLInsert(ztest_tree, &iz1);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &iz8);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &iz3);
  CuAssertTrue(tc, 0 == result);

  ptr = zAVLFirst(&cursor, ztest_tree);
  CuAssertIntEquals(tc, ptr->iname, iz3.iname);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz5.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz4.name);
  ptr = zAVLNext(&cursor);
  CuAssertIntEquals(tc, ptr->iname, iz8.iname);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz7.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz6.name);
  ptr = zAVLNext(&cursor);
  CuAssertIntEquals(tc, ptr->iname, iz2.iname);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, iz1.name);
  ptr = zAVLNext(&cursor);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, &(iz1.iname));
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, &(iz1.iname));
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, &(iz2.iname));
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, &(iz2.iname));
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, &(iz3.iname));
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, &(iz3.iname));
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, &(iz4.iname));
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, &(iz4.iname));
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, &(iz5.iname));
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, &(iz5.iname));
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, &(iz6.iname));
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, &(iz6.iname));
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, &(iz7.iname));
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, &(iz7.iname));
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, &(iz8.iname));
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, &(iz8.iname));
  CuAssertTrue(tc, NULL == ptr);

} while (counter < 100);

  result = zAVLInsert(ztest_tree, &iz1);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &iz2);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &iz3);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &iz4);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &iz5);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &iz6);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &iz7);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &iz8);
  CuAssertTrue(tc, 0 == result);

  zAVLFreeTree (ztest_tree, free_node);
  CuAssertTrue (tc, iz1.iname == 0);
  CuAssertTrue (tc, iz2.iname == 0);
  CuAssertTrue (tc, iz3.iname == 0);
  CuAssertTrue (tc, iz4.iname == 0);
  CuAssertTrue (tc, iz5.iname == 0);
  CuAssertTrue (tc, iz6.iname == 0);
  CuAssertTrue (tc, iz7.iname == 0);
  CuAssertTrue (tc, iz8.iname == 0);

  ztest_tree = NULL;
  str = strdup("foo");
  result = zAVL_string_set(&ztest_tree, str);
  CuAssertTrue(tc, 0 == result);
  CuAssertPtrNotNull(tc, ztest_tree);
  CuAssertStrEquals(tc, "foo", zAVL_string_get(ztest_tree, "foo")); 

  str = strdup("bar");
  result = zAVL_string_set(&ztest_tree, str);
  CuAssertTrue(tc, 0 == result);
  CuAssertStrEquals(tc, "foo", zAVL_string_get(ztest_tree, "foo")); 
  CuAssertStrEquals(tc, "bar", zAVL_string_get(ztest_tree, "bar")); 

  str = strdup("balloon");
  result = zAVL_string_set(&ztest_tree, str);
  CuAssertTrue(tc, 0 == result);
  CuAssertStrEquals(tc, "foo", zAVL_string_get(ztest_tree, "foo")); 
  CuAssertStrEquals(tc, "bar", zAVL_string_get(ztest_tree, "bar")); 
  CuAssertStrEquals(tc, "balloon", zAVL_string_get(ztest_tree, "balloon")); 

  str = zAVL_string_get(ztest_tree, "foobar");
  CuAssertTrue(tc, str == NULL);
  str = zAVL_string_get(ztest_tree, "");
  CuAssertTrue(tc, str == NULL);
  str = zAVL_string_get(ztest_tree, NULL);
  CuAssertTrue(tc, str == NULL);

  zAVL_string_reset(ztest_tree);
  str = zAVL_string_get(ztest_tree, "foo");
  CuAssertTrue(tc, str == NULL);
  str = zAVL_string_get(ztest_tree, "bar");
  CuAssertTrue(tc, str == NULL);
  str = zAVL_string_get(ztest_tree, "balloon");
  CuAssertTrue(tc, str == NULL);

}
