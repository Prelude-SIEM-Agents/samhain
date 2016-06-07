/* Do not include ANY system headers here. The implementation is    */
/* somehow flawed - maybe something gets overlayed by definitions   */
/* in the system headers. Results will become incorrect.            */

#include "config_xor.h"

/* we already inline in the function used for file checksums */
/* #define UNROLL_COMPRESS */
#undef UNROLL_COMPRESS

#if !defined(TIGER_64_BIT)

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

/* Big endian:                                         */
#ifdef WORDS_BIGENDIAN
#define BIG_ENDIAN
#endif

/* The number of passes of the hash function.          */
/* Three passes are recommended.                       */
/* Use four passes when you need extra security.       */
/* Must be at least three.                             */
#define PASSES 3

extern sh_word32 tiger_table[4*256][2];

#define t1 (tiger_table)
#define t2 (tiger_table+256)
#define t3 (tiger_table+256*2)
#define t4 (tiger_table+256*3)

#define sub64(s0, s1, p0, p1) \
      temps0 = (p0); \
      tcarry = s0 < temps0; \
      s0 -= temps0; \
      s1 -= (p1) + tcarry;

#define add64(s0, s1, p0, p1) \
      temps0 = (p0); \
      s0 += temps0; \
      tcarry = s0 < temps0; \
      s1 += (p1) + tcarry;

#define xor64(s0, s1, p0, p1) \
      s0 ^= (p0); \
      s1 ^= (p1);

#define mul5(s0, s1) \
      tempt0 = s0<<2; \
      tempt1 = (s1<<2)|(s0>>30); \
      add64(s0, s1, tempt0, tempt1);

#define mul7(s0, s1) \
      tempt0 = s0<<3; \
      tempt1 = (s1<<3)|(s0>>29); \
      sub64(tempt0, tempt1, s0, s1); \
      s0 = tempt0; \
      s1 = tempt1;

#define mul9(s0, s1) \
      tempt0 = s0<<3; \
      tempt1 = (s1<<3)|(s0>>29); \
      add64(s0, s1, tempt0, tempt1);

#define save_abc \
      aa0 = a0; \
      aa1 = a1; \
      bb0 = b0; \
      bb1 = b1; \
      cc0 = c0; \
      cc1 = c1;

#define roundX(a0,a1,b0,b1,c0,c1,x0,x1) \
      xor64(c0, c1, x0, x1); \
      temp0  = t1[((c0)>>(0*8))&0xFF][0] ; \
      temp1  = t1[((c0)>>(0*8))&0xFF][1] ; \
      temp0 ^= t2[((c0)>>(2*8))&0xFF][0] ; \
      temp1 ^= t2[((c0)>>(2*8))&0xFF][1] ; \
      temp0 ^= t3[((c1)>>(0*8))&0xFF][0] ; \
      temp1 ^= t3[((c1)>>(0*8))&0xFF][1] ; \
      temp0 ^= t4[((c1)>>(2*8))&0xFF][0] ; \
      temp1 ^= t4[((c1)>>(2*8))&0xFF][1] ; \
      sub64(a0, a1, temp0, temp1); \
      temp0  = t4[((c0)>>(1*8))&0xFF][0] ; \
      temp1  = t4[((c0)>>(1*8))&0xFF][1] ; \
      temp0 ^= t3[((c0)>>(3*8))&0xFF][0] ; \
      temp1 ^= t3[((c0)>>(3*8))&0xFF][1] ; \
      temp0 ^= t2[((c1)>>(1*8))&0xFF][0] ; \
      temp1 ^= t2[((c1)>>(1*8))&0xFF][1] ; \
      temp0 ^= t1[((c1)>>(3*8))&0xFF][0] ; \
      temp1 ^= t1[((c1)>>(3*8))&0xFF][1] ; \
      add64(b0, b1, temp0, temp1); 


#define round5(a0,a1,b0,b1,c0,c1,x0,x1) \
      roundX(a0,a1,b0,b1,c0,c1,x0,x1); \
      mul5(b0, b1);

#define round7(a0,a1,b0,b1,c0,c1,x0,x1) \
      roundX(a0,a1,b0,b1,c0,c1,x0,x1); \
      mul7(b0, b1);

#define round9(a0,a1,b0,b1,c0,c1,x0,x1) \
      roundX(a0,a1,b0,b1,c0,c1,x0,x1); \
      mul9(b0, b1);


/* mixed with key_schedule
 */
#define pass5(a0,a1,b0,b1,c0,c1) \
      round5(a0,a1,b0,b1,c0,c1,x00,x01); \
      sub64(x00, x01, x70^0xA5A5A5A5, x71^0xA5A5A5A5); \
      round5(b0,b1,c0,c1,a0,a1,x10,x11); \
      xor64(x10, x11, x00, x01); \
      round5(c0,c1,a0,a1,b0,b1,x20,x21); \
      add64(x20, x21, x10, x11); \
      round5(a0,a1,b0,b1,c0,c1,x30,x31); \
      sub64(x30, x31, x20^((~x10)<<19), ~x21^(((x11)<<19)|((x10)>>13))); \
      round5(b0,b1,c0,c1,a0,a1,x40,x41); \
      xor64(x40, x41, x30, x31); \
      round5(c0,c1,a0,a1,b0,b1,x50,x51); \
      add64(x50, x51, x40, x41); \
      round5(a0,a1,b0,b1,c0,c1,x60,x61); \
      sub64(x60, x61, ~x50^(((x40)>>23)|((x41)<<9)), x51^((~x41)>>23)); \
      round5(b0,b1,c0,c1,a0,a1,x70,x71);

/* mixed with key_schedule
 */
#define pass7(a0,a1,b0,b1,c0,c1) \
      round7(a0,a1,b0,b1,c0,c1,x00,x01); \
      sub64(x00, x01, x70^0xA5A5A5A5, x71^0xA5A5A5A5); \
      round7(b0,b1,c0,c1,a0,a1,x10,x11); \
      xor64(x10, x11, x00, x01); \
      round7(c0,c1,a0,a1,b0,b1,x20,x21); \
      add64(x20, x21, x10, x11); \
      round7(a0,a1,b0,b1,c0,c1,x30,x31); \
      sub64(x30, x31, x20^((~x10)<<19), ~x21^(((x11)<<19)|((x10)>>13))); \
      round7(b0,b1,c0,c1,a0,a1,x40,x41); \
      xor64(x40, x41, x30, x31); \
      round7(c0,c1,a0,a1,b0,b1,x50,x51); \
      add64(x50, x51, x40, x41); \
      round7(a0,a1,b0,b1,c0,c1,x60,x61); \
      sub64(x60, x61, ~x50^(((x40)>>23)|((x41)<<9)), x51^((~x41)>>23)); \
      round7(b0,b1,c0,c1,a0,a1,x70,x71);

/* mixed with key_schedule
 */
#define pass9(a0,a1,b0,b1,c0,c1) \
      round9(a0,a1,b0,b1,c0,c1,x00,x01); \
      sub64(x00, x01, x70^0xA5A5A5A5, x71^0xA5A5A5A5); \
      round9(b0,b1,c0,c1,a0,a1,x10,x11); \
      xor64(x10, x11, x00, x01); \
      round9(c0,c1,a0,a1,b0,b1,x20,x21); \
      add64(x20, x21, x10, x11); \
      round9(a0,a1,b0,b1,c0,c1,x30,x31); \
      sub64(x30, x31, x20^((~x10)<<19), ~x21^(((x11)<<19)|((x10)>>13))); \
      round9(b0,b1,c0,c1,a0,a1,x40,x41); \
      xor64(x40, x41, x30, x31); \
      round9(c0,c1,a0,a1,b0,b1,x50,x51); \
      add64(x50, x51, x40, x41); \
      round9(a0,a1,b0,b1,c0,c1,x60,x61); \
      sub64(x60, x61, ~x50^(((x40)>>23)|((x41)<<9)), x51^((~x41)>>23)); \
      round9(b0,b1,c0,c1,a0,a1,x70,x71);

#define key_schedule \
      xor64(x70, x71, x60, x61); \
      add64(x00, x01, x70, x71); \
      sub64(x10, x11, x00^((~x70)<<19), ~x01^(((x71)<<19)|((x70)>>13))); \
      xor64(x20, x21, x10, x11); \
      add64(x30, x31, x20, x21); \
      sub64(x40, x41, ~x30^(((x20)>>23)|((x21)<<9)), x31^((~x21)>>23)); \
      xor64(x50, x51, x40, x41); \
      add64(x60, x61, x50, x51); \
      sub64(x70, x71, x60^0x89ABCDEF, x61^0x01234567);

#define feedforward \
      xor64(a0, a1, aa0, aa1); \
      sub64(b0, b1, bb0, bb1); \
      add64(c0, c1, cc0, cc1);

#define compress \
      pass5(a0,a1,b0,b1,c0,c1); \
      key_schedule; \
      pass7(c0,c1,a0,a1,b0,b1); \
      key_schedule; \
      pass9(b0,b1,c0,c1,a0,a1); \
      feedforward

#define tiger_compress_macro(str, state) \
{ \
  register sh_word32 a0, a1, b0, b1, c0, c1; \
  sh_word32 aa0, aa1, bb0, bb1, cc0, cc1; \
  sh_word32 x00, x01, x10, x11, x20, x21, x30, x31, \
                  x40, x41, x50, x51, x60, x61, x70, x71; \
  sh_word32 temp0, temp1, tempt0, tempt1, temps0, tcarry; \
\
  a0 = state[0]; \
  a1 = state[1]; \
  b0 = state[2]; \
  b1 = state[3]; \
  c0 = state[4]; \
  c1 = state[5]; \
\
      save_abc \
\
  x00=str[0*2]; x01=str[0*2+1]; x10=str[1*2]; x11=str[1*2+1]; \
  x20=str[2*2]; x21=str[2*2+1]; x30=str[3*2]; x31=str[3*2+1]; \
  x40=str[4*2]; x41=str[4*2+1]; x50=str[5*2]; x51=str[5*2+1]; \
  x60=str[6*2]; x61=str[6*2+1]; x70=str[7*2]; x71=str[7*2+1]; \
\
  compress; \
\
  state[0] = a0; \
  state[1] = a1; \
  state[2] = b0; \
  state[3] = b1; \
  state[4] = c0; \
  state[5] = c1; \
}

#if defined(UNROLL_COMPRESS)
/* The compress function is inlined */
#define tiger_compress(str, state) \
  tiger_compress_macro(((sh_word32*)str), ((sh_word32*)state))

#else

void
tiger_compress(sh_word32 *str, sh_word32 state[6])
{
  tiger_compress_macro(((sh_word32*)str), ((sh_word32*)state));
}
#endif

void
tiger_t(const sh_word32 *str, sh_word32 length, sh_word32 res[6])
{
  register sh_word32 i;
#ifdef BIG_ENDIAN
  register sh_word32 j;
  sh_byte temp[64];
#endif

  for(i=length; i>=64; i-=64)
    {
#ifdef BIG_ENDIAN
      for(j=0; j<64; j++)
        temp[j^3] = ((sh_byte*)str)[j];
      tiger_compress_macro(((sh_word32*)temp), res);
#else
      tiger_compress_macro(str, res);
#endif
      str += 16;
    }
}


void tiger(sh_word32 *str, sh_word32 length, sh_word32 res[6])
{
  register sh_word32 i, j;
  sh_byte temp[64];

  /*
   * res[0]=0x89ABCDEF;
   * res[1]=0x01234567;
   * res[2]=0x76543210;
   * res[3]=0xFEDCBA98;
   * res[4]=0xC3B2E187;
   * res[5]=0xF096A5B4;
   */

  for(i=length; i>=64; i-=64)
    {
#ifdef BIG_ENDIAN
      for(j=0; j<64; j++)
	temp[j^3] = ((sh_byte*)str)[j];
      tiger_compress(((sh_word32*)temp), res);
#else
      tiger_compress(str, res);
#endif
      str += 16;
    }

#ifdef BIG_ENDIAN
  for(j=0; j<i; j++)
    temp[j^3] = ((sh_byte*)str)[j];

  temp[j^3] = 0x01;
  j++;
  for(; j&7; j++)
    temp[j^3] = 0;
#else
  for(j=0; j<i; j++)
    temp[j] = ((sh_byte*)str)[j];

  temp[j++] = 0x01;
  for(; j&7; j++)
    temp[j] = 0;
#endif
  if(j>56)
    {
      for(; j<64; j++)
	temp[j] = 0;
      tiger_compress(((sh_word32*)temp), res);
      j=0;
    }

  for(; j<56; j++)
    temp[j] = 0;
  ((sh_word32*)(&(temp[56])))[0] = ((sh_word32)length)<<3;
  ((sh_word32*)(&(temp[56])))[1] = 0;
  tiger_compress(((sh_word32*)temp), res);
}

#endif

