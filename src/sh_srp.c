/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999, 2000 Rainer Wichmann                                */
/*                                                                         */
/*  This program is free software; you can redistribute it                 */
/*  and/or modify                                                          */
/*  it under the terms of the GNU General Public License as                */
/*  published by                                                           */
/*  the Free Software Foundation; either version 2 of the License, or      */
/*  (at your option) any later version.                                    */
/*                                                                         */
/*  This program is distributed in the hope that it will be useful,        */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of         */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          */
/*  GNU General Public License for more details.                           */
/*                                                                         */
/*  You should have received a copy of the GNU General Public License      */
/*  along with this program; if not, write to the Free Software            */
/*  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.              */

#include "config_xor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "samhain.h"

#ifdef USE_SRP_PROTOCOL

#if (defined (SH_WITH_CLIENT) || defined (SH_WITH_SERVER))

#include "sh_tiger.h"
#include "sh_mem.h"
#include "sh_utils.h"
#include "sh_srp.h"

#if !defined(HAVE_LIBGMP) || !defined(HAVE_GMP_H)
#include "bignum.h"
#else

#include <gmp.h>

#define BIG_OK 0
#define bigerr_t int
int big_errno = BIG_OK;

#define bignum MP_INT

inline
int big_create (bignum * a)
{
  mpz_init(a);
  return 0;
}

inline
int big_zerop (bignum * a)
{
  mpz_t b;
  int   i;
  mpz_init_set_str(b, "0", 10);
  i = mpz_cmp(a, b);
  mpz_clear(b);
  if (i)
    return 0;
  else
    return 1;
}

inline
int big_trunc (bignum * a, bignum * b, bignum * q, bignum *r)
{
  mpz_tdiv_qr(q, r, a, b);
  return 0;
}

inline
int big_exptmod (bignum * a, bignum * b, bignum * c, bignum *d)
{
  mpz_powm(d, a, b, c);
  return 0;
}

char * get_str_internal = NULL;
int    siz_str_internal = 0;

static
char * big_string (bignum * a, int base)
{
  char * str = NULL;
  int    size;
  int    i;
  str = mpz_get_str (str, base, a);

  if (get_str_internal == NULL)
    {
      get_str_internal = calloc(1,512);   /* only once */
      if (get_str_internal)
	{
	  siz_str_internal = 512;
	}
      else
	{
	  if (str != NULL)
	    free(str);
	  return 0;
	}
      get_str_internal[0] = '\0';
    }

  if (str != NULL)
    {
      size = strlen(str) + 1;
      if (size > siz_str_internal)
	{
	  char * ptr = realloc (get_str_internal, size);
	  if (ptr)
	    get_str_internal = ptr;
	  else
	    { free(get_str_internal); get_str_internal = NULL; }
	}
      if (get_str_internal == NULL)
	{
	  free(str);
	  return NULL;
	}
      siz_str_internal = size;
      sl_strlcpy (get_str_internal, str, siz_str_internal);
      for (i = 0; i < (size-1); ++i)
	if (get_str_internal[i] >= 'a' && get_str_internal[i] <= 'f' )
	  get_str_internal[i] = get_str_internal[i] - 'a' + 'A';
      free (str);
    }
  return get_str_internal;
}

inline 
int big_add(bignum * a, bignum * b, bignum * c)
{
  mpz_add(c, a, b);
  return 0;
}

inline 
int big_sub(bignum * a, bignum * b, bignum * c)
{
  mpz_sub(c, a, b);
  return 0;
}

inline 
int big_mul(bignum * a, bignum * b, bignum * c)
{
  mpz_mul(c, a, b);
  return 0;
}

inline 
int big_greaterp(bignum * a, bignum * b)
{
  return mpz_cmp(a, b) > 0;
}

inline 
int big_set_big(bignum * a, bignum * b)
{
    mpz_set(b, a);
    return 0;
}


inline 
int big_set_string(const char * str, int base, bignum * a)
{
  mpz_set_str (a, str, base);
  return 0;
}


#define big_init_pkg() 0
#define big_release_pkg() 
#define big_destroy mpz_clear

/* #if defined(HAVE_LIBGMP) 
 */
#endif

#undef  FIL__
#define FIL__  _("sh_srp.c")

typedef struct sh_srp_struc {
  char   x[KEY_LEN+1];
  bignum a;
  bignum p;
  bignum g;
} sh_srp_t;

static sh_srp_t sh_srp;

void sh_srp_x (char * salt, char * password)
{

  char           *combi;
  size_t          len, l2;
  register int i;
  unsigned char * dez = NULL;
  char hashbuf[KEYBUF_SIZE];

  SL_ENTER(_("sh_srp_x"));

  /* patch by Andreas Piesk
   */
  if (password == NULL)
    dez = (unsigned char *) &(skey->pw[0]);
  else 
    dez = (unsigned char *) password;

  for (i = 0; i < PW_LEN; ++i)
    {
      skey->vernam[i] = (char)(*dez); 
      ++dez;
    }
  skey->vernam[PW_LEN] = '\0';

  (void) sl_strlcpy (skey->vernam,
		     sh_tiger_hash(skey->vernam, TIGER_DATA, PW_LEN, 
				   hashbuf, sizeof(hashbuf)), 
		     KEY_LEN);
  skey->vernam[KEY_LEN] = '\0';

  len = sl_strlen(salt) + 1;
  l2  = sl_strlen(skey->vernam);
  if (sl_ok_adds(len, l2))
    len += l2;

  /* H(s,P)
   */
  combi = SH_ALLOC(len);
  (void) sl_strlcpy (combi, salt, len);
  (void) sl_strlcat (combi, skey->vernam, len);
  (void) sl_strlcpy (sh_srp.x, 
		     sh_tiger_hash(combi, TIGER_DATA, 
				   (unsigned long) sl_strlen(combi),
				   hashbuf, sizeof(hashbuf)),
		     KEY_LEN+1);
  SH_FREE (combi);

  SL_RET0(_("sh_srp_x"));
}

char * sh_srp_M (char * x1, char * x2, char * x3, char * hash, size_t size)
{
  char           *combi;
  size_t          len, l2, l3;
  
  SL_ENTER(_("sh_srp_M"));

  ASSERT_RET((x1 != NULL && x2 != NULL && x3 !=NULL),
	     _("x1 != NULL && x2 != NULL && x3 !=NULL"), NULL);

  len = sl_strlen(x1) + 1;
  l2  = sl_strlen(x2); 
  l3  = sl_strlen(x3);

  if (sl_ok_adds(len, l2))
    len += l2;
  if (sl_ok_adds(len, l3))
    len += l3;
  
  /* H(x1,x2,x3)
   */
  combi = SH_ALLOC(len);
  (void) sl_strlcpy (combi, x1, len);
  (void) sl_strlcat (combi, x2, len);
  (void) sl_strlcat (combi, x3, len);
  (void) sh_tiger_hash(combi, TIGER_DATA, (unsigned long) (len-1),
		       hash, size);
  SH_FREE (combi);
  
  SL_RETURN(hash, _("sh_srp_M"));
}


void sh_srp_exit()
{
  SL_ENTER(_("sh_srp_exit"));
  big_destroy(&sh_srp.g);	     
  big_destroy(&sh_srp.p);
  big_destroy(&sh_srp.a);

  big_release_pkg();

  big_errno = BIG_OK;
  SL_RET0(_("sh_srp_exit"));
}


int sh_srp_init()
{
  bigerr_t res;
  char     modulus[80*4];

  SL_ENTER(_("sh_srp_init"));
  
  big_errno = BIG_OK; 

  res = big_init_pkg();
  
  if (res == BIG_OK)
    {
      res = big_create(&sh_srp.p);
      if (res == BIG_OK)
	res = big_create(&sh_srp.g);
      if (res == BIG_OK)
        res = big_create(&sh_srp.a);
      if (res == BIG_OK)
	{
	  (void) sl_strlcpy(modulus, SRP_MODULUS_1024_1, sizeof(modulus));
	  (void) sl_strlcat(modulus, SRP_MODULUS_1024_2, sizeof(modulus));
	  (void) sl_strlcat(modulus, SRP_MODULUS_1024_3, sizeof(modulus));
	  (void) sl_strlcat(modulus, SRP_MODULUS_1024_4, sizeof(modulus));
	}
      if (res == BIG_OK)
	res = big_set_string (modulus,                  16, &sh_srp.p);
      if (res == BIG_OK)
	res = big_set_string (SRP_GENERATOR_1024,       16, &sh_srp.g);
      if (res == BIG_OK)
	{
	  SL_RETURN (0, _("sh_srp_init"));
	}
      else
	sh_srp_exit();
    }
  SL_RETURN ((-1), _("sh_srp_init"));
}


int sh_srp_make_a ()
{
  UINT32 randl[6];
  int    i;
  int    res;
  char   hash[KEY_LEN+1];
  char hashbuf[KEYBUF_SIZE];

  SL_ENTER(_("sh_srp_make_a"));

  for (i = 0; i < 6; ++i)
    randl[i] = (UINT32) taus_get ();

  (void) sl_strlcpy (hash, 
		     sh_tiger_hash((char *)&randl[0], TIGER_DATA, 
				   (unsigned long) 6*sizeof(UINT32),
				   hashbuf, sizeof(hashbuf)), 
		     KEY_LEN+1);

  hash[KEY_LEN] = '\0';

  res = big_set_string (hash,       16, &sh_srp.a);
  if (res == BIG_OK)
    {
      SL_RETURN((0), _("sh_srp_make_a"));
    }
  else
    {
      SL_RETURN((-1), _("sh_srp_make_a"));
    }
}

/* return 0 if AB is NOT zero
 */
int sh_srp_check_zero (char * AB_str)
{
  bignum   AB, q, r;
  bigerr_t res;
  int      val;

  SL_ENTER(_("sh_srp_check_zero"));

  ASSERT_RET((AB_str != NULL), _("AB_str != NULL"), (-1));

  res = big_create(&AB);
  if (res == BIG_OK)
    res = big_create(&q);
  if (res == BIG_OK)
    res = big_create(&r);

  if (res == BIG_OK)
    res = big_set_string (AB_str,       16, &AB);
  if (res == BIG_OK)
    res = big_trunc(&AB, &sh_srp.p, &q, &r); /* is last one the remainder ? */
  
  if (res != BIG_OK)             val = (-1);
  else if (0 != big_zerop(&AB) ) val = (-1); /* 0 != (sign == 0) */
  else if (0 != big_zerop(&r) )  val = (-1); /* 0 != (sign == 0) */
  else                           val =    0;

  big_destroy(&AB);	
  big_destroy(&q);	
  big_destroy(&r);	
  
  SL_RETURN((val), _("sh_srp_check_zero"));
}

#if defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER)
  

char * sh_srp_A ()
{
  bignum   A;
  char    *str;
  char    *combi;
  bigerr_t res;

  SL_ENTER(_("sh_srp_A"));

  res = big_create(&A);
  
  if (res == BIG_OK)
    res = big_exptmod (&sh_srp.g, &sh_srp.a, &sh_srp.p, &A);
  
  if (res == BIG_OK)
    str = big_string (&A, 16);
  else
    str = NULL;
  
  if (str != NULL)
    combi = sh_util_strdup(str);
  else
    combi = NULL;
  
  big_destroy(&A);	     
  SL_RETURN(combi, _("sh_srp_A"));
}

/* #ifdef SH_WITH_CLIENT */
#endif  
  
#ifdef SH_WITH_SERVER

char * sh_srp_B (char * verifier)
{
  bignum   B, v, t, dummy;
  char    *str;
  char    *combi;
  bigerr_t res;

  SL_ENTER(_("sh_srp_B"));

  ASSERT_RET((verifier != NULL), _("verifier != NULL"), (NULL));

  res = big_create(&dummy);

  if (res == BIG_OK)
    res = big_create(&t);
  if (res == BIG_OK)
    res = big_create(&v);
  if (res == BIG_OK)
    res = big_create(&B);

  if (res == BIG_OK)
    res = big_exptmod (&sh_srp.g, &sh_srp.a, &sh_srp.p, &t);
  
  if (res == BIG_OK)
    big_set_string (verifier,       16, &v);

  if (res == BIG_OK)
    res = big_add (&t, &v, &dummy);

  if (res == BIG_OK)
    {
      if ( big_greaterp(&dummy, &sh_srp.p) ) 
	res = big_sub(&dummy, &sh_srp.p, &B);
      else                                   
	res = big_set_big(&dummy, &B);
    }

  if (res == BIG_OK)
    str = big_string (&B, 16);
  else
    str = NULL;
  
  if (str != NULL)
    combi = sh_util_strdup(str);
  else
    combi = NULL;
  
  big_destroy(&B);	
  big_destroy(&v);	
  big_destroy(&t);	
  big_destroy(&dummy);	
  
  SL_RETURN(combi, _("sh_srp_B"));
}
/* #ifdef SH_WITH_SERVER */
#endif  
  
  
#if defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER)
  
char * sh_srp_S_c (char * u_str, char * B_str)
{
  bignum   u, B, x, t, base, z1, z2;
  char    *str;
  char    *combi;
  bigerr_t res;

  SL_ENTER(_("sh_srp_S_c"));

  ASSERT_RET((u_str != NULL && B_str != NULL),
	     _("u_str != NULL && B_str != NULL"), (NULL));

  big_errno = BIG_OK;

  res = big_create(&z2);
  if (res == BIG_OK)
   res = big_create(&z1);
  if (res == BIG_OK)
   res = big_create(&base);
  if (res == BIG_OK)
   res = big_create(&t);
  if (res == BIG_OK)
   res = big_create(&x);
  if (res == BIG_OK)
   res = big_create(&B);
  if (res == BIG_OK)
   res = big_create(&u);
  
  if (res == BIG_OK)
   res = big_set_string (B_str,          16, &B);
  if (res == BIG_OK)
   res = big_set_string (sh_srp.x,       16, &x);
  if (res == BIG_OK)
   res = big_set_string (u_str,          16, &u);
  
  /* the base  (B - g^x)
   */
  if (res == BIG_OK)
    res = big_exptmod (&sh_srp.g, &x, &sh_srp.p, &t);

  if (res == BIG_OK)
    {
      if ( big_greaterp(&B, &t) != 0) 
	{
	  res = big_sub(&B, &t, &base);
	}
      else 
	{
	  res = big_add(&B, &sh_srp.p, &z2);
	  if (res == BIG_OK)
	    res = big_sub(&z2, &t, &base);
	}
    }

  /* the exponent (a + ux)
   */
  if (res == BIG_OK)
    res = big_mul (&u, &x, &t);
  if (res == BIG_OK)
    res = big_trunc(&t, &sh_srp.p, &z1, &z2); /* is last one the remainder ? */
  if (res == BIG_OK)
    res = big_add(&sh_srp.a, &z2, &z1);
  if (res == BIG_OK)
    {
      if ( big_greaterp(&z1, &sh_srp.p) != 0) 
	res = big_sub(&z1, &sh_srp.p, &z2);
      else 
	res = big_set_big(&z1, &z2);
    }

  if (res == BIG_OK)
    res = big_exptmod (&base, &z2, &sh_srp.p, &t);

  if (res == BIG_OK)
    str = big_string (&t, 16);
  else
    str = NULL;

  if (str != NULL)
    combi = sh_util_strdup(str);
  else
    combi = NULL;

  big_destroy(&z1);	     
  big_destroy(&z2);	     
  big_destroy(&base);	     
  big_destroy(&t);	
  big_destroy(&x);	
  big_destroy(&B);	
  big_destroy(&u);	
  
  SL_RETURN(combi, _("sh_srp_S_c"));
}
  
/* #ifdef SH_WITH_CLIENT */
#endif  
  
#ifdef SH_WITH_SERVER

  
char * sh_srp_S_s (char * u_str, char * A_str, char * v_str)
{
  bignum   u, A, v, t, base, z1, z2;
  char    *str;
  char    *combi;
  bigerr_t res;

  SL_ENTER(_("sh_srp_S_s"));

  ASSERT_RET((u_str != NULL && A_str != NULL && v_str != NULL),
	     _("u_str != NULL && A_str != NULL && v_str != NULL"),
	     (NULL));

  big_errno = BIG_OK;

  res = big_create(&z2);
  if (res == BIG_OK)
    res = big_create(&z1);
  if (res == BIG_OK)
    res = big_create(&base);
  if (res == BIG_OK)
    res = big_create(&t);
  if (res == BIG_OK)
    res = big_create(&v);
  if (res == BIG_OK)
    res = big_create(&A);
  if (res == BIG_OK)
    res = big_create(&u);
  
  if (res == BIG_OK)
    res = big_set_string (A_str,          16, &A);
  if (res == BIG_OK)
    res = big_set_string (v_str,          16, &v);
  if (res == BIG_OK)
    res = big_set_string (u_str,          16, &u);
  
  /* the base  (Av^u)
   */
  if (res == BIG_OK)
    res = big_exptmod (&v, &u, &sh_srp.p, &t);
  if (res == BIG_OK)
    res = big_mul (&A, &t, &z1);
  if (res == BIG_OK)
    res = big_trunc(&z1, &sh_srp.p, &z2, &base); /* is last the remainder ? */

  if (res == BIG_OK)
    res = big_exptmod (&base, &sh_srp.a, &sh_srp.p, &t);

  if (res == BIG_OK)
    str = big_string (&t, 16);
  else
    str = NULL;
  
  if (str != NULL)
    combi = sh_util_strdup(str);
  else
    combi = NULL;
  
  big_destroy(&z1);	     
  big_destroy(&z2);	     
  big_destroy(&base);	     
  big_destroy(&t);	
  big_destroy(&v);	
  big_destroy(&A);	
  big_destroy(&u);	
  
  SL_RETURN(combi, _("sh_srp_S_s"));
}

/* #ifdef SH_WITH_SERVER */
#endif  


char * sh_srp_verifier (void)
{
  bignum   x, v;
  char    *combi;
  char    *str;
  bigerr_t res;
  
  SL_ENTER(_("sh_srp_verifier"));
  
  res = big_create(&x);
  if (res == BIG_OK)
    res = big_create(&v);
  
  if (res == BIG_OK)
    res = big_set_string (sh_srp.x,               16, &x);
  
  if (res == BIG_OK)
    res = big_exptmod (&sh_srp.g, &x, &sh_srp.p, &v);
  
  if (res == BIG_OK)
    str = big_string (&v, 16);
  else
    str = NULL;
  
  if (str != NULL)
    combi = sh_util_strdup(str);
  else
    combi = NULL;
  
  big_destroy(&x);	     
  big_destroy(&v);	     
  
  SL_RETURN(combi, _("sh_srp_verifier"));
}
  

/* #if (defined (SH_WITH_CLIENT) || defined (SH_WITH_SERVER)) */

#endif

/* #ifdef USE_SRP_PROTOCOL */

#endif


#ifdef SH_CUTEST
#include "CuTest.h"

void Test_srp (CuTest *tc)
{
#if defined(USE_SRP_PROTOCOL) && (defined (SH_WITH_CLIENT) || defined (SH_WITH_SERVER))

  int result;
  char     modulus[80*4];
  bignum   a, b, c;
  bigerr_t res;
  char    *str = NULL;

  res = sh_srp_init();
  CuAssertTrue(tc, res == 0);

  (void) sl_strlcpy(modulus, SRP_MODULUS_1024_1, sizeof(modulus));
  (void) sl_strlcat(modulus, SRP_MODULUS_1024_2, sizeof(modulus));
  (void) sl_strlcat(modulus, SRP_MODULUS_1024_3, sizeof(modulus));
  (void) sl_strlcat(modulus, SRP_MODULUS_1024_4, sizeof(modulus));

  res = big_create(&a);
  CuAssertTrue(tc, res == BIG_OK);

  /* Check plain zero 
   */
  result = sh_srp_check_zero ("0");
  CuAssertTrue(tc, result != 0);
  
  res = big_set_string ("0",  16, &a);
  CuAssertTrue(tc, res == BIG_OK);

  result = sh_srp_check_zero (big_string(&a, 16));
  CuAssertTrue(tc, result != 0);

  /* Check modulus (equals 0 % M) 
   */
  result = sh_srp_check_zero (modulus);
  CuAssertTrue(tc, result != 0);

  res = big_set_string (modulus,  16, &a);
  CuAssertTrue(tc, res == BIG_OK);

  result = sh_srp_check_zero (big_string(&a, 16));
  CuAssertTrue(tc, result != 0);

  /* Check non-zero 
   */
  modulus[0] = 'a';

  result = sh_srp_check_zero (modulus);
  CuAssertTrue(tc, result == 0);

  res = big_set_string (modulus,  16, &a);
  CuAssertTrue(tc, res == BIG_OK);

  result = sh_srp_check_zero (big_string(&a, 16));
  CuAssertTrue(tc, result == 0);

  modulus[0] = 'f';

  /* Check multiple of modulus 
   */
  res = big_set_string (modulus,  16, &a);
  CuAssertTrue(tc, res == BIG_OK);

  res = big_create(&b);
  CuAssertTrue(tc, res == BIG_OK);

  res = big_create(&c);
  CuAssertTrue(tc, res == BIG_OK);

  res = big_set_string ("deadbeef", 16, &b);
  CuAssertTrue(tc, res == BIG_OK);

  res = big_mul (&a, &b, &c);
  CuAssertTrue(tc, res == BIG_OK);

  str = strdup(big_string (&c, 16));
  CuAssertPtrNotNull(tc, str);

  result = sh_srp_check_zero (str);
  CuAssertTrue(tc, result != 0);

#else
  (void) tc; /* fix compiler warning */
#endif
  return;
}
#endif



