#!/bin/sh

# Auto generate single AllTests file for CuTest.
# Searches through all *.c files in the current directory.
# Prints to stdout.
# Author: Asim Jalis
# Date: 01/08/2003

# Modified to return non-zero if any test has failed
# Rainer Wichmann, 29. Jan 2006
# ...and to print to stderr if any test has failed
# Rainer Wichmann, 31. Jan 2006

if test $# -eq 0 ; then FILES=*.c ; else FILES=$* ; fi

echo '

/* This is auto-generated code. Edit at your own peril. */

#include "config.h"
#include <stdio.h>
#include "CuTest.h"
'

cat $FILES | grep '^void Test' | 
    sed -e 's/(.*$//' \
        -e 's/$/(CuTest*);/' \
        -e 's/^/extern /'

echo \
'

int RunAllTests(void) 
{
    CuString *output = CuStringNew();
    CuSuite* suite = CuSuiteNew();

'
cat $FILES | grep '^void Test' | 
    sed -e 's/^void //' \
        -e 's/(.*$//' \
        -e 's/^/    SUITE_ADD_TEST(suite, /' \
        -e 's/$/);/'

echo \
'
    CuSuiteRun(suite);
    CuSuiteSummary(suite, output);
    CuSuiteDetails(suite, output);
    if (suite->failCount > 0)
      fprintf(stderr, "%s%c", output->buffer, 0x0A);
    else
      fprintf(stdout, "%s%c", output->buffer, 0x0A);
    return suite->failCount;
}

int main(void)
{
#if !defined(USE_SYSTEM_MALLOC)
    typedef void assert_handler_tp(const char * error, const char *file, int line);
    extern assert_handler_tp *dnmalloc_set_handler(assert_handler_tp *new);
    extern void safe_fatal  (const char * details, const char *f, int l);
#endif
#if !defined(USE_SYSTEM_MALLOC) && defined(USE_MALLOC_LOCK)
    extern int dnmalloc_pthread_init(void);
    dnmalloc_pthread_init();
#endif
#if !defined(USE_SYSTEM_MALLOC)
    (void) dnmalloc_set_handler(safe_fatal);
#endif
    int retval;
    retval = RunAllTests();
    return (retval == 0) ? 0 : 1;
}
'
