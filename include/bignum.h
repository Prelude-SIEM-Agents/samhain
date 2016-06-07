#ifndef _BIGNUM_H_
#define _BIGNUM_H_

#include "internal.h"

typedef struct big_struct bignum;

#define BIG_SIGN_0 0
#define BIG_SIGN_PLUS 1
#define BIG_SIGN_MINUS -1

#define BIG_OK 0
#define BIG_MEMERR 1
#define BIG_DIV_ZERO 2
#define BIG_ARGERR 3

#ifdef BIG_SHORT_NAMES
#define big_set_big	big_sb
#define big_set_long	big_sl
#define big_set_ulong	big_usl
#define big_string	big_rs
#define big_leqp	big_lq
#define big_expt	big_x
#endif

/* External variables to take care about when using the bignums */
typedef int bigerr_t;
extern int big_errno;
extern char *big_end_string;

/* External functions to enable use of bignums */
extern bigerr_t big_init_pkg(void);
extern void big_release_pkg(void);

extern bigerr_t big_create(bignum *a);
extern void big_destroy(bignum *a);

extern unsigned long big_bitcount(bignum *a);

extern bigerr_t big_set_big(bignum *a, bignum *b);
extern void big_set_long(long n, bignum *a);
extern void big_set_ulong(unsigned long n, bignum *a);
extern bigerr_t big_set_string(char *numstr, int base, bignum *a);

extern int big_long(bignum *a, long *n);
extern int big_ulong(bignum *a, unsigned long *n);
extern char *big_string(bignum *a, int base);

extern int big_sign(bignum *a);
extern bigerr_t big_abs(bignum *a, bignum *b);

extern bigerr_t big_negate(bignum *a, bignum *b);

extern int big_compare(bignum *a, bignum *b);
extern int big_lessp(bignum *a, bignum *b);
extern int big_leqp(bignum *a, bignum *b);
extern int big_equalp(bignum *a, bignum *b);
extern int big_geqp(bignum *a, bignum *b);
extern int big_greaterp(bignum *a, bignum *b);

extern int big_zerop(bignum *a);
extern int big_evenp(bignum *a);
extern int big_oddp(bignum *a);

extern bigerr_t big_add(bignum *a, bignum *b, bignum *c);
extern bigerr_t big_sub(bignum *a, bignum *b, bignum *c);

extern bigerr_t big_mul(bignum *a, bignum *b, bignum *c);

extern bigerr_t big_trunc(bignum *a, bignum *b, bignum *c, bignum *r);
extern bigerr_t big_floor(bignum *a, bignum *b, bignum *c, bignum *r);
extern bigerr_t big_ceil(bignum *a, bignum *b, bignum *c, bignum *r);
extern bigerr_t big_round(bignum *a, bignum *b, bignum *c, bignum *r);

extern bigerr_t big_random(bignum *a, bignum *b);

extern bigerr_t big_expt(bignum *a, unsigned long z, bignum *x);
extern bigerr_t big_exptmod(bignum *a_in, bignum *z_in, bignum *n, bignum *x);
extern bigerr_t big_gcd(bignum *a, bignum *b, bignum *g);

#ifndef NULL
#define NULL 0
#endif

#endif /* _BIGNUM_H_ */
