/* Do not include ANY system headers here. The implementation is    */
/* somehow flawed - maybe something gets overlayed by definitions   */
/* in the system headers. Results will become incorrect.            */

#include "config_xor.h"

#if defined(__clang__)
#undef TIGER_OPT_ASM
#endif

#if defined(TIGER_64_BIT)

#if defined(GCC_VERSION_MAJOR) && !defined(__clang__)
#if ((GCC_VERSION_MAJOR == 4) && (GCC_VERSION_MINOR > 6))
#pragma GCC optimize ("O1")
#endif
#endif


/* #if defined(HAVE_LONG_64) || defined(HAVE_LONG_LONG_64) */

#undef USE_MEMSET

/* Big endian:                                         */
#ifdef WORDS_BIGENDIAN
#define BIG_ENDIAN
#endif

/* Tiger: A Fast New Hash Function
 *
 * Ross Anderson and Eli Biham
 *
 * From the homepage (http://www.cs.technion.ac.il/~biham/Reports/Tiger/):
 *
 * Tiger has no usage restrictions nor patents. It can be used freely, 
 * with the reference implementation, with other implementations or with 
 * a modification to the reference implementation (as long as it still 
 * implements Tiger). We only ask you to let us know about your 
 * implementation and to cite the origin of Tiger and of the reference 
 * implementation. 
 *
 *
 * The authors' home pages can be found both in 
 * http://www.cs.technion.ac.il/~biham/ and in 
 * http://www.cl.cam.ac.uk/users/rja14/.
 * The authors' email addresses are biham@cs.technion.ac.il 
 * and rja14@cl.cam.ac.uk.
 */ 

#if defined(HAVE_LONG_64)
typedef unsigned long int word64;
#elif defined(HAVE_LONG_LONG_64)
typedef unsigned long long int word64;
#else
#error No 64 bit type found !
#endif

#if defined(HAVE_INT_32)
typedef unsigned int sh_word32;
#elif defined(HAVE_LONG_32)
typedef unsigned long sh_word32;
#elif defined(HAVE_SHORT_32)
typedef unsigned short sh_word32;
#else
#error No 32 bit type found !
#endif

typedef unsigned char sh_byte;

#if defined(TIGER_OPT_ASM)
#define TIGER_ASM64_2 1
#else
#define TIGER_C 1
#endif

/* The number of passes of the hash function.		   */
/* Three passes are recommended.			   */
/* Use four passes when you need extra security.	   */
/* Must be at least three.				   */
#define PASSES 3

extern word64 tiger_table[4*256];

/* Volatile can help if compiler is smart enough to use memory operand */
static /*volatile*/ const word64 XOR_CONST1=0xA5A5A5A5A5A5A5A5LL;
static /*volatile*/ const word64 XOR_CONST2=0x0123456789ABCDEFLL;

#define t1 (tiger_table)
#define t2 (tiger_table+256)
#define t3 (tiger_table+256*2)
#define t4 (tiger_table+256*3)

#define pass_start
#define pass_end



#define save_abc \
	  aa = a; \
	  bb = b; \
	  cc = c;

#ifdef TIGER_C

#define BN(x,n) (((x)>>((n)*8))&0xFF)


/* Depending on outer code one of these two can be better*/
#define roundX(a,b,c,x) \
	c ^= x; \
	a -= t1[BN(c,0)] ^ t2[BN(c,2)] ^ \
	     t3[BN(c,4)] ^ t4[BN(c,6)] ; \
	b += t4[BN(c,1)] ^ t3[BN(c,3)] ^ \
	     t2[BN(c,5)] ^ t1[BN(c,7)] ;

#define round5(a,b,c,x) roundX(a,b,c,x) b = b+b*4;
#define round7(a,b,c,x) roundX(a,b,c,x) b = b*8-b;
#define round9(a,b,c,x) roundX(a,b,c,x) b = b+b*8;

#endif


#ifdef TIGER_OPT_ASM

#define MASK0		0xFFL
#define MASK8		0xFF00L
#define MASK16		0xFF0000L
#define MASK32		0xFF00000000LL
#define MASK40		0xFF0000000000LL
#define MASK48		0xFF000000000000LL

#define roundstart	__asm__ (

/* a will be moved into different reg each round
 * using register substitution feature of  GCC asm
 * b will be moved in 2-nd pass rounds only
 */


#define roundend(a,b,c,x) \
 : "+r" (a), "+r" (b), "+r" (c) \
 : "r" (a), "r" (b), "r" (c), "m" (x), "r" (&tiger_table),\
  "i" (MASK0), "i" (MASK8), "i" (MASK16), "r" (MASK32), "r" (MASK40), "r" (MASK48) \
 : "3", "%rax","%rbx","%rcx","%rdx","%rsi", "%edi", "%r8"  );


/*	c ^= x; 
	a -= t1[BN(c,0)] ^ t2[BN(c,2)] ^ 
	t3[BN(c,4)] ^ t4[BN(c,6)] ; 
	b += t4[BN(c,1)] ^ t3[BN(c,3)] ^ 
	t2[BN(c,5)] ^ t1[BN(c,7)] ; 	*/

#define roundX(a,b,c,x)   \
"	movl	%10, %%ebx	\n"\
"	movq	%11, %%rcx	\n"\
"	movq	%13, %%rdx	\n"\
"	movq	%6, %%r8  \n"\
"	xorq	%%r8, %2		 \n" \
"	andq	%2, %%rbx  \n"\
"	andq	%2, %%rcx  \n"\
"	andq	%2, %%rdx  \n"\
"	shrl	$(16-3), %%ebx	\n"\
"	shrq	$(32-3), %%rcx	\n"\
"	shrq	$(48-3), %%rdx	\n"\
"	movzbl	%2b, %%eax	\n"\
"	movzwl	%2w, %%edi	\n"\
"	movq	(%7,%%rax,8), %%rsi  \n"\
"	shrl	$(8), %%edi  \n" \
"	movq	%2, %%rax  \n" \
"	xorq	(2048*1)(%7,%%rbx), %%rsi  \n"\
"	movq	%2, %%rbx  \n"\
"	shrl	$24, %%eax \n"\
"	andq	%12, %%rbx	\n"\
"	xorq	(2048*2)(%7,%%rcx), %%rsi  \n"\
"	shrq	$(40-3), %%rbx \n"\
"	movq	%2, %%rcx  \n"\
"	xorq	(2048*3)(%7,%%rdx), %%rsi  \n"\
"	movq	(2048*3)(%7,%%rdi,8), %%rdx  \n"\
"	shrq	$56, %%rcx \n"\
"	xorq	(2048*2)(%7,%%rax,8), %%rdx  \n"\
"	xorq	(2048*1)(%7,%%rbx), %%rdx  \n" \
"	subq	 %%rsi, %0 \n"\
"	xorq	(%7,%%rcx,8), %%rdx  \n"\
"	addq	 %%rdx, %1 \n"

#define round5(a,b,c,x) \
	roundstart \
	roundX(a,b,c,x) \
	/* b*=5; */ \
	"leaq	(%1,%1,4), %1\n" \
	roundend(a,b,c,x)


#define round7(a,b,c,x) \
	roundstart \
	roundX(a,b,c,x) \
	roundend(a,b,c,x) \
	/* b*=7; */ \
	__asm__ ( \
	"leaq	(%1,%1,8), %0\n" \
	"addq  %1, %1 \n" \
	"subq  %1, %0 " \
	:"=&r" (b): "r"(b): "1" );

#define round9(a,b,c,x) \
	roundstart \
	roundX(a,b,c,x) \
	"leaq	(%1,%1,8), %1\n" \
	roundend(a,b,c,x)

#endif




/* ============== Common macros ================== */

#define key_schedule \
	x0 -= x7 ^ XOR_CONST1; \
	x1 ^= x0; \
	x2 += x1;\
	x3 -= x2 ^ ((~x1)<<19);\
	x4 ^= x3;\
	x5 += x4;\
	x6 -= x5 ^ ((~x4)>>23); \
	x7 ^= x6; \
	x0 += x7; \
	x1 -= x0 ^ ((~x7)<<19); \
	x2 ^= x1; \
	x3 += x2; \
	x4 -= x3 ^ ((~x2)>>23); \
	x5 ^= x4; \
	x6 += x5; \
	x7 -= x6 ^ XOR_CONST2;

#define pass5n(a,b,c) \
	  round5(a,b,c,x0) \
	x0 -= x7 ^ XOR_CONST1; \
	  round5(b,c,a,x1) \
	x1 ^= x0; \
	  round5(c,a,b,x2) \
	x2 += x1; \
	  round5(a,b,c,x3) \
	x3 -= x2 ^ ((~x1)<<19); \
	  round5(b,c,a,x4) \
	x4 ^= x3; \
	  round5(c,a,b,x5) \
	x5 += x4; \
	  round5(a,b,c,x6) \
	x6 -= x5 ^ ((~x4)>>23); \
	  round5(b,c,a,x7) \
	x7 ^= x6; \
	x0 += x7; \
	x1 -= x0 ^ ((~x7)<<19); \
	x2 ^= x1; \
	x3 += x2; \
	x4 -= x3 ^ ((~x2)>>23); \
	x5 ^= x4; \
	x6 += x5; \
	x7 -= x6 ^ XOR_CONST2;

#define pass7n(a,b,c) \
	  round7(a,b,c,x0) \
	x0 -= x7 ^ XOR_CONST1; \
	  round7(b,c,a,x1) \
	x1 ^= x0; \
	  round7(c,a,b,x2) \
	x2 += x1; \
	  round7(a,b,c,x3) \
	x3 -= x2 ^ ((~x1)<<19); \
	  round7(b,c,a,x4) \
	x4 ^= x3; \
	  round7(c,a,b,x5) \
	x5 += x4; \
	  round7(a,b,c,x6) \
	x6 -= x5 ^ ((~x4)>>23); \
	  round7(b,c,a,x7) \
	x7 ^= x6; \
	x0 += x7; \
	x1 -= x0 ^ ((~x7)<<19); \
	x2 ^= x1; \
	x3 += x2; \
	x4 -= x3 ^ ((~x2)>>23); \
	x5 ^= x4; \
	x6 += x5; \
	x7 -= x6 ^ XOR_CONST2;

#define pass5(a,b,c) \
	pass_start \
	  round5(a,b,c,x0) \
	  round5(b,c,a,x1) \
	  round5(c,a,b,x2) \
	  round5(a,b,c,x3) \
	  round5(b,c,a,x4) \
	  round5(c,a,b,x5) \
	  round5(a,b,c,x6) \
	  round5(b,c,a,x7) \
	pass_end

#define pass7(a,b,c) \
	pass_start \
	  round7(a,b,c,x0) \
	  round7(b,c,a,x1) \
	  round7(c,a,b,x2) \
	  round7(a,b,c,x3) \
	  round7(b,c,a,x4) \
	  round7(c,a,b,x5) \
	  round7(a,b,c,x6) \
	  round7(b,c,a,x7) \
	pass_end


#define pass9(a,b,c) \
	pass_start \
	  round9(a,b,c,x0) \
	  round9(b,c,a,x1) \
	  round9(c,a,b,x2) \
	  round9(a,b,c,x3) \
	  round9(b,c,a,x4) \
	  round9(c,a,b,x5) \
	  round9(a,b,c,x6) \
	  round9(b,c,a,x7) \
	pass_end

#define feedforward \
	  a ^= aa; \
	  b -= bb; \
	  c += cc;


/* This version works ok with C variant and also with new asm version 
 * that just wastes a register r8 
 * reason? who knows, write forwarding is faster than keeping value 
 * in register? :) 
 */
#define compress \
	save_abc \
	  pass5n(a,b,c) \
	  pass7n(c,a,b) \
	  pass9(b,c,a) \
	  for(pass_no=3; pass_no<PASSES; pass_no++) { \
		key_schedule \
		pass9(a,b,c) \
		tmpa=a; a=c; c=b; b=tmpa; \
	  } \
	feedforward

#define compress_old \
	save_abc \
	  pass5(a,b,c) \
	  key_schedule \
	  pass7(c,a,b) \
	  key_schedule \
	  pass9(b,c,a) \
	  for(pass_no=3; pass_no<PASSES; pass_no++) { \
		key_schedule \
		pass9(a,b,c) \
		tmpa=a; a=c; c=b; b=tmpa; \
	  } \
	feedforward

#define tiger_compress_macro(str, state) \
{ \
  register word64 a, b, c; \
  register word64 tmpa; \
  word64 aa, bb, cc; \
  word64 x0, x1, x2, x3, x4, x5, x6, x7; \
  int pass_no; \
\
  a = state[0]; \
  b = state[1]; \
  c = state[2]; \
\
  x0=str[0]; x1=str[1]; x2=str[2]; x3=str[3]; \
  x4=str[4]; x5=str[5]; x6=str[6]; x7=str[7]; \
\
  compress; \
\
  state[0] = a; \
  state[1] = b; \
  state[2] = c; \
}

void tiger_compress(const word64 *str, word64 state[3])
{
  tiger_compress_macro(((const word64*)str), ((word64*)state));
}

void tiger_t(const word64 *str, word64 length, word64 res[3])
{
  register word64 i;

#ifdef BIG_ENDIAN
  register word64 j = 0;
  unsigned char temp[64];
#endif

  /*
   * res[0]=0x0123456789ABCDEFLL;
   * res[1]=0xFEDCBA9876543210LL;
   * res[2]=0xF096A5B4C3B2E187LL;
   */

  for(i=length; i>=64; i-=64)
    {
#ifdef BIG_ENDIAN
      for(j=0; j<64; j++)
        temp[j^7] = ((sh_byte*)str)[j];
      tiger_compress(((word64*)temp), res);
#else
      tiger_compress(str, res);
#endif
      str += 8;
    }
}

void tiger(const word64 *str, word64 length, word64 res[3])
{
  register word64 i;
  register word64 j = 0;
  union {
    word64 w64_temp[8];
    unsigned char temp[64];
  } dd;
  union {
    word64 itmp;
    unsigned char ctmp[8];
  } uu;

  /*
   * res[0]=0x0123456789ABCDEFLL;
   * res[1]=0xFEDCBA9876543210LL;
   * res[2]=0xF096A5B4C3B2E187LL;
   */

  for(i=length; i>=64; i-=64)
    {
#ifdef BIG_ENDIAN
      for(j=0; j<64; j++)
        dd.temp[j^7] = ((sh_byte*)str)[j];
      tiger_compress((dd.w64_temp), res);
#else
      tiger_compress(str, res);
#endif
      str += 8;
    }

#ifdef BIG_ENDIAN
  for(j=0; j<i; j++)
    dd.temp[j^7] = ((sh_byte*)str)[j];

  dd.temp[j^7] = 0x01;
  j++;
  for(; j&7; j++)
    dd.temp[j^7] = 0;
#else

#ifndef USE_MEMSET
  for(j=0; j<i; j++)
    dd.temp[j] = ((const sh_byte*)str)[j];
#else
  memcpy( dd.temp, str, j=i );
#endif
  dd.temp[j++] = 0x01;
  for(; j&7; j++)
	dd.temp[j] = 0;

#endif

  if(j>56)
    {
#ifndef USE_MEMSET
      for(; j<64; j++)
	dd.temp[j] = 0;
#else
      memset( (dd.temp)+j, 0, 64-j);
#endif
      tiger_compress((dd.w64_temp), res);
      j=0;
    }

#ifndef USE_MEMSET
  for(; j<56; j++)
    dd.temp[j] = 0;
#else
  memset( (dd.temp)+j, 0, 56-j);
#endif

  /* Avoid gcc warning for type-punned pointer 
   */
  uu.itmp = ((word64)length)<<3;
  for (j=0; j<8; j++)
        dd.temp[56+j] = uu.ctmp[j];

  tiger_compress((dd.w64_temp), res);
}

#endif
