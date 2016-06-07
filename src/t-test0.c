/*
* Copyright (c) 1996-1999, 2001-2004 Wolfram Gloger

Permission to use, copy, modify, distribute, and sell this software
and its documentation for any purpose is hereby granted without fee,
provided that (i) the above copyright notices and this permission
notice appear in all copies of the software and related documentation,
and (ii) the name of Wolfram Gloger may not be used in any advertising
or publicity relating to the software.

THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.

IN NO EVENT SHALL WOLFRAM GLOGER BE LIABLE FOR ANY SPECIAL,
INCIDENTAL, INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER OR NOT ADVISED OF THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY
OF LIABILITY, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
*/

/*
 * $Id: t-test1.c,v 1.2 2004/11/04 14:58:45 wg Exp $
 * by Wolfram Gloger 1996-1999, 2001, 2004
 * A multi-thread test for malloc performance, maintaining one pool of
 * allocated bins per thread.
 */
/*
  t-test[12] <n-total> <n-parallel> <n-allocs> <size-max> <bins>

    n-total = total number of threads executed (default 10)
    n-parallel = number of threads running in parallel (2)
    n-allocs = number of malloc()'s / free()'s per thread (10000)
    size-max = max. size requested with malloc() in bytes (10000)
    bins = number of bins to maintain
*/

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#if (defined __STDC__ && __STDC__) || defined __cplusplus
# include <stdlib.h>
#endif
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/mman.h>

/*
#if !USE_MALLOC
#include <malloc.h>
#else
#include "malloc.h"
#endif
*/

#ifdef USE_SYSTEM_MALLOC
extern void *memalign(size_t boundary, size_t size);
/* #define memalign(a,b)  malloc(b) */
#else
extern void *memalign(size_t boundary, size_t size);
#endif

static int verbose = 1;

/* dummy for the samhain safe_fatal logger 
 */
void safe_fatal(const char * details, 
				const char * file, int line)
{
  (void) file;
  (void) line;
  fputs("assert failed: ", stderr);
  puts(details);
  _exit(EXIT_FAILURE);
}

/* lran2.h
 * by Wolfram Gloger 1996.
 *
 * A small, portable pseudo-random number generator.
 */

#ifndef _LRAN2_H
#define _LRAN2_H

#define LRAN2_MAX 714025l /* constants for portable */
#define IA	  1366l	  /* random number generator */
#define IC	  150889l /* (see e.g. `Numerical Recipes') */

struct lran2_st {
    long x, y, v[97];
};

static void
lran2_init(struct lran2_st* d, long seed)
{
    long x;
    int j;

    x = (IC - seed) % LRAN2_MAX;
    if(x < 0) x = -x;
    for(j=0; j<97; j++) {
	x = (IA*x + IC) % LRAN2_MAX;
	d->v[j] = x;
    }
    d->x = (IA*x + IC) % LRAN2_MAX;
    d->y = d->x;
}

#ifdef __GNUC__
__inline__
#endif
static long
lran2(struct lran2_st* d)
{
    int j = (d->y % 97);

    d->y = d->v[j];
    d->x = (IA*d->x + IC) % LRAN2_MAX;
    d->v[j] = d->x;
    return d->y;
}

#undef IA
#undef IC

#endif

/*
 * $Id: t-test.h,v 1.1 2004/11/04 14:32:21 wg Exp $
 * by Wolfram Gloger 1996.
 * Common data structures and functions for testing malloc performance.
 */

/* Testing level */
#ifndef TEST
#define TEST 99
#endif

/* For large allocation sizes, the time required by copying in
   realloc() can dwarf all other execution times.  Avoid this with a
   size threshold. */
#ifndef REALLOC_MAX
#define REALLOC_MAX	2000
#endif

struct bin {
	unsigned char *ptr;
	unsigned long size;
};

#if TEST > 0

static void
mem_init(unsigned char *ptr, unsigned long size)
{
	unsigned long i, j;

	if(size == 0) return;
#if TEST > 3
	memset(ptr, '\0', size);
#endif
	for(i=0; i<size; i+=2047) {
		j = (unsigned long)ptr ^ i;
		ptr[i] = ((j ^ (j>>8)) & 0xFF);
	}
	j = (unsigned long)ptr ^ (size-1);
	ptr[size-1] = ((j ^ (j>>8)) & 0xFF);
}

static int
mem_check(unsigned char *ptr, unsigned long size)
{
	unsigned long i, j;

	if(size == 0) return 0;
	for(i=0; i<size; i+=2047) {
		j = (unsigned long)ptr ^ i;
		if(ptr[i] != ((j ^ (j>>8)) & 0xFF)) return 1;
	}
	j = (unsigned long)ptr ^ (size-1);
	if(ptr[size-1] != ((j ^ (j>>8)) & 0xFF)) return 2;
	return 0;
}

static int
zero_check(unsigned* ptr, unsigned long size)
{
	unsigned char* ptr2;

	while(size >= sizeof(*ptr)) {
		if(*ptr++ != 0)
			return -1;
		size -= sizeof(*ptr);
	}
	ptr2 = (unsigned char*)ptr;
	while(size > 0) {
		if(*ptr2++ != 0)
			return -1;
		--size;
	}
	return 0;
}

#endif /* TEST > 0 */

/* Allocate a bin with malloc(), realloc() or memalign().  r must be a
   random number >= 1024. */
int n_malloc=0, n_memalign=0, n_realloc=0, n_calloc=0;

static void
bin_alloc(struct bin *m, unsigned long size, int r)
{
#if TEST > 0
	if(mem_check(m->ptr, m->size)) {
	  fprintf(stderr, "memory corrupt!\n");
	  exit(1);
	}
#endif
	r %= 1024;
	/*printf("%d ", r);*/
	if(r < 4) { /* memalign */
		if(m->size > 0) free(m->ptr);
		m->ptr = (unsigned char *)memalign(sizeof(int) << r, size);
		++n_memalign;
	} else if(r < 20) { /* calloc */
		if(m->size > 0) free(m->ptr);
		m->ptr = (unsigned char *)calloc(size, 1);
#if TEST > 0
		if(zero_check((unsigned*)m->ptr, size)) {
			unsigned long i;
			for(i=0; i<size; i++)
				if(m->ptr[i] != 0)
					break;
			fprintf(stderr, "calloc'ed memory non-zero (ptr=%p, i=%ld)!\n", m->ptr, i);
			exit(1);
		}
#endif
		++n_calloc;
	} else if(r < 100 && m->size < REALLOC_MAX) { /* realloc */
		if(m->size == 0) m->ptr = NULL;
		m->ptr = realloc(m->ptr, size);
		++n_realloc;
	} else { /* plain malloc */
		if(m->size > 0) free(m->ptr);
		m->ptr = (unsigned char *)malloc(size);
		++n_malloc;
	}
	if(!m->ptr) {
	  fprintf(stderr, "out of memory (r=%d, size=%ld)!\n", r, (long)size);
	  exit(1);
	}
	m->size = size;
#if TEST > 0
	mem_init(m->ptr, m->size);
#endif
}

/* Free a bin. */

static void
bin_free(struct bin *m)
{
	if(m->size == 0) return;
#if TEST > 0
	if(mem_check(m->ptr, m->size)) {
	  fprintf(stderr, "memory corrupt!\n");
	  exit(1);
	}
#endif
	free(m->ptr);
	m->size = 0;
}

/*
 * Local variables:
 * tab-width: 4
 * End:
 */


struct user_data {
	int bins, max;
	unsigned long size;
	long seed;
};

/*
 * $Id: thread-st.h$
 * pthread version
 * by Wolfram Gloger 2004
 */

#include <pthread.h>
#include <stdio.h>

pthread_cond_t finish_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t finish_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifndef USE_PTHREADS_STACKS
#define USE_PTHREADS_STACKS 0
#endif

#ifndef STACKSIZE
#define STACKSIZE	32768
#endif




/*
 * Local variables:
 * tab-width: 4
 * End:
 */


#define N_TOTAL		10
#ifndef N_THREADS
#define N_THREADS	2
#endif
#ifndef N_TOTAL_PRINT
#define N_TOTAL_PRINT 50
#endif
#ifndef MEMORY
#define MEMORY		8000000l
#endif
#define SIZE		10000
#define I_MAX		10000
#define ACTIONS_MAX	30
#ifndef TEST_FORK
#define TEST_FORK 0
#endif

#define RANDOM(d,s)	(lran2(d) % (s))

struct bin_info {
	struct bin *m;
	unsigned long size, bins;
};

#if TEST > 0

void
bin_test(struct bin_info *p)
{
	unsigned int b;

	for(b=0; b<p->bins; b++) {
		if(mem_check(p->m[b].ptr, p->m[b].size)) {
		  fprintf(stderr, "memory corrupt!\n");
		  abort();
		}
	}
}

#endif

void
malloc_test(unsigned long size, int bins, int max)
{
    unsigned int b;
	int i, j, actions;
	struct bin_info p;
	struct lran2_st ld; /* data for random number generator */

	lran2_init(&ld, ((long)max*size + getpid()) ^ bins);

	p.m = (struct bin *)malloc(bins*sizeof(*p.m));
	p.bins = bins;
	p.size = size;

	for(b=0; b<p.bins; b++) {
		p.m[b].size = 0;
		p.m[b].ptr = NULL;
		if(RANDOM(&ld, 2) == 0)
			bin_alloc(&p.m[b], RANDOM(&ld, p.size) + 1, lran2(&ld));
	}
	for(i=0; i<=max;) {
#if TEST > 1
		bin_test(&p);
#endif
		actions = RANDOM(&ld, ACTIONS_MAX);
#if USE_MALLOC && MALLOC_DEBUG
		if(actions < 2) { mallinfo(); }
#endif
		for(j=0; j<actions; j++) {
			b = RANDOM(&ld, p.bins);
			bin_free(&p.m[b]);
		}
		i += actions;
		actions = RANDOM(&ld, ACTIONS_MAX);
		for(j=0; j<actions; j++) {
			b = RANDOM(&ld, p.bins);
			bin_alloc(&p.m[b], RANDOM(&ld, p.size) + 1, lran2(&ld));
#if TEST > 2
			bin_test(&p);
#endif
		}

		i += actions;
	}
	for(b=0; b<p.bins; b++)
		bin_free(&p.m[b]);
	free(p.m);
	return;
}

int n_total=0, n_total_max=N_TOTAL, n_running;

int
main(int argc, char *argv[])
{
	int bins;
	int n_thr=N_THREADS;
	int i_max=I_MAX;
	unsigned long size=SIZE;

#if USE_MALLOC && USE_STARTER==2
	ptmalloc_init();
	printf("ptmalloc_init\n");
#endif

	if((argc > 1) && (0 == strcmp(argv[1], "-h") || 0 == strcmp(argv[1], "--help")))
	  {
		printf("%s <n-total> <n-parallel> <n-allocs> <size-max> <bins>\n\n", argv[0]);
		printf(" n-total = total number of threads executed (default 10)\n");
		printf(" UNUSED n-parallel = number of threads running in parallel (2)\n");
		printf(" n-allocs = number of malloc()'s / free()'s per thread (10000)\n");
		printf(" size-max = max. size requested with malloc() in bytes (10000)\n");
		printf(" bins = number of bins to maintain\n");
		return 0;
	  }

	if(argc > 1) n_total_max = atoi(argv[1]);
	if(n_total_max < 1) n_thr = 1;
	if(argc > 2) n_thr = atoi(argv[2]);
	if(n_thr < 1) n_thr = 1;
	if(n_thr > 100) n_thr = 100;
	if(argc > 3) i_max = atoi(argv[3]);

	if(argc > 4) size = atol(argv[4]);
	if(size < 2) size = 2;

	bins = MEMORY/(size*n_thr);
	if(argc > 5) bins = atoi(argv[5]);
	if(bins < 4) bins = 4;

	printf("[total=%d threads=%d] i_max=%d size=%ld bins=%d\n",
		   n_total_max, n_thr, i_max, size, bins);

	do {
	  n_total++;
	  malloc_test(size, bins, i_max);
	  if (verbose)
		if(n_total%N_TOTAL_PRINT == 0)
		  printf("n_total = %8d - malloc %12d / memalign %12d / realloc %12d / calloc %12d\n", 
				 n_total, 
				 n_malloc, n_memalign, n_realloc, n_calloc);
	} while (n_total < n_total_max);


#if USE_MALLOC
	malloc_stats();
#endif
	if (verbose)
	  printf("Done.\n");
	return 0;
}

/*
 * Local variables:
 * tab-width: 4
 * End:
 */
