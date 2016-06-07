#ifndef SH_PTHREAD_H
#define SH_PTHREAD_H

#ifdef HAVE_PTHREAD

#include <pthread.h>

#define SH_MUTEX(M)				pthread_mutex_t M
#define SH_MUTEX_INIT(M,I)			pthread_mutex_t M = I
#define SH_MUTEX_STATIC(M,I)			static pthread_mutex_t M = I
#define SH_MUTEX_EXTERN(M)			extern pthread_mutex_t M

#define SH_SETSIGMASK(A, B, C)                  sh_pthread_setsigmask(A,B,C)

int sh_pthread_setsigmask(int how, const void *set, void *oldset);

/* pthread_mutex_unlock() has the wrong type (returns int), so
 * we need to wrap it in this function.
 */
extern void sh_pthread_mutex_unlock (void *arg);

#define SH_MUTEX_LOCK(M)						   \
	do {                                                               \
                int oldtype;                                               \
		int executeStack = 1;                                      \
		pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &oldtype);  \
                pthread_cleanup_push(sh_pthread_mutex_unlock, (void*)&(M));\
                pthread_mutex_lock(&(M))

#define SH_MUTEX_TRYLOCK(M)						   \
	do {                                                               \
                int oldtype;                                               \
		volatile int executeStack = 0;                             \
		pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &oldtype);  \
                pthread_cleanup_push(sh_pthread_mutex_unlock, (void*)&(M));\
                if (0 == pthread_mutex_trylock(&(M))) {		           \
		  executeStack = 1

#define SH_MUTEX_TRYLOCK_UNLOCK(M)					   \
                }                                                          \
		pthread_cleanup_pop(executeStack);                         \
                pthread_setcanceltype(oldtype, NULL);                      \
	} while (0)

#define SH_MUTEX_UNLOCK(M)						   \
		pthread_cleanup_pop(executeStack);                         \
                pthread_setcanceltype(oldtype, NULL);                      \
	} while (0)

#define SH_MUTEX_LOCK_UNSAFE(M) pthread_mutex_lock(&(M))
#define SH_MUTEX_TRYLOCK_UNSAFE(M) pthread_mutex_trylock(&(M))
#define SH_MUTEX_UNLOCK_UNSAFE(M) pthread_mutex_unlock(&(M))


/*
 * ----   Recursive mutex  ----
 */
#if defined(HAVE_PTHREAD_MUTEX_RECURSIVE)

#define SH_MUTEX_RECURSIVE(M)                                          \
static pthread_mutex_t M;                                              \
static void M ## _init (void)                                          \
{                                                                      \
  pthread_mutexattr_t   mta;                                           \
  pthread_mutexattr_init(&mta);                                        \
  pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE);            \
  pthread_mutex_init(&(M), &mta);                                      \
  pthread_mutexattr_destroy(&mta);                                     \
  return;                                                              \
}                                                                      \
static pthread_once_t  M ## _initialized = PTHREAD_ONCE_INIT

#define SH_MUTEX_RECURSIVE_INIT(M)                                     \
(void) pthread_once(&(M ## _initialized), (M ## _init))

#define SH_MUTEX_RECURSIVE_LOCK(M)					   \
	do {                                                               \
                int oldtype;                                               \
		pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &oldtype);  \
                pthread_cleanup_push(sh_pthread_mutex_unlock, (void*)&(M));\
                pthread_mutex_lock(&(M))

#define SH_MUTEX_RECURSIVE_UNLOCK(M)					   \
		pthread_cleanup_pop(1);                                    \
                pthread_setcanceltype(oldtype, NULL);                      \
	} while (0)

#else
/* !defined(PTHREAD_MUTEX_RECURSIVE) */
 struct sh_RMutex {

  pthread_mutex_t lock;
  unsigned int    held;
  unsigned int    waiters;
  pthread_t       tid;
  pthread_cond_t  cv;
};

void sh_RMutexLock(struct sh_RMutex * tok);
void sh_RMutexUnlock(void * arg);
void sh_InitRMutex(struct sh_RMutex * tok);

#define SH_MUTEX_RECURSIVE(M)                                          \
static struct sh_RMutex M;                                             \
static void M ## _init (void)                                          \
{                                                                      \
  sh_InitRMutex(&(M));                                                 \
  return;                                                              \
}                                                                      \
static pthread_once_t  M ## _initialized = PTHREAD_ONCE_INIT

#define SH_MUTEX_RECURSIVE_INIT(M)                                     \
(void) pthread_once(&(M ## _initialized), (M ## _init))

#define SH_MUTEX_RECURSIVE_LOCK(M)					   \
	do {                                                               \
                int oldtype;                                               \
		pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &oldtype);  \
                pthread_cleanup_push(sh_RMutexUnlock, (void*)&(M));        \
                sh_RMutexLock(&(M))

#define SH_MUTEX_RECURSIVE_UNLOCK(M)					   \
		pthread_cleanup_pop(1);                                    \
                pthread_setcanceltype(oldtype, NULL);                      \
	} while (0)

#endif
/* 
 * ----   Global mutexes   ----
 */
SH_MUTEX_EXTERN(mutex_skey);
SH_MUTEX_EXTERN(mutex_resolv);
SH_MUTEX_EXTERN(mutex_pwent);
SH_MUTEX_EXTERN(mutex_readdir);
/* Prevent threads from logging while we are in suspend */
SH_MUTEX_EXTERN(mutex_thread_nolog);

/*
 * ----   Initialize thread-specific conversion area   ----
 */
extern int sh_g_thread(void);


/*
 * ----   Functions for threaded modules   ----
 */
int sh_pthread_create(void *(*start_routine)(void*), void *arg);
int sh_pthread_cancel_all(void);
void sh_threaded_module_reconf(void *arg);
void * sh_threaded_module_run(void *arg);

#else

#define SH_SETSIGMASK(A, B, C)                  sh_pthread_setsigmask(A,B,C)

int sh_pthread_setsigmask(int how, const void *set, void *oldset);

#define PTHREAD_MUTEX_INITIALIZER               NULL
#define SH_MUTEX(M)				void *SH_MUTEX_DUMMY_ ## M
#define SH_MUTEX_INIT(M,I)			extern void *SH_MUTEX_DUMMY_ ## M
#define SH_MUTEX_STATIC(M,I)			extern void *SH_MUTEX_DUMMY_ ## M
#define SH_MUTEX_EXTERN(M)			extern void *SH_MUTEX_DUMMY_ ## M
#define SH_MUTEX_LOCK(M)			((void)0)
#define SH_MUTEX_TRYLOCK(M)			((void)0)
#define SH_MUTEX_UNLOCK(M)			((void)0)
#define SH_MUTEX_TRYLOCK_UNLOCK(M)		((void)0)
#define SH_MUTEX_LOCK_UNSAFE(M)			((void)0)
#define SH_MUTEX_TRYLOCK_UNSAFE(M)		(0)
#define SH_MUTEX_UNLOCK_UNSAFE(M)		((void)0)

#define SH_MUTEX_RECURSIVE(M)                   extern void *SH_MUTEX_DUMMY_ ## M
#define SH_MUTEX_RECURSIVE_INIT(M)              ((void)0)
#define SH_MUTEX_RECURSIVE_LOCK(M)		((void)0)
#define SH_MUTEX_RECURSIVE_UNLOCK(M)		((void)0)

/* #ifdef HAVE_PTHREAD */
#endif

/* #ifndef SH_PTHREAD_H */
#endif
