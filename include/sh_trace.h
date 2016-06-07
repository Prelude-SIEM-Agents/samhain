#ifndef SH_TRACE_H
#define SH_TRACE_H


/* This file should be included via samhain.h only.
 */

#ifdef SL_DEBUG
#define ASSERT(expr, expr1) \
      if (!(expr)) \
	{ \
         fprintf(stderr,	    \
		 SDG_AERRO, \
		 FIL__, __LINE__, expr1 ); \
          abort(); \
	}


#define ASSERT_RET(expr, expr1, rr) \
      if (!(expr)) \
        { \
         fprintf(stderr, \
		 SDG_AERRO, \
		 FIL__, __LINE__, expr1 ); \
         TPT(( (-1), FIL__, __LINE__, SDG_0RETU))      \
         return (rr); \
        }
#else
#define ASSERT(expr, expr1)
  
#define ASSERT_RET(expr, expr1, rr) \
      if (!(expr)) return (rr);
#endif


#ifdef SL_DEBUG
#define TX1(expr1) \
  fprintf(stderr, \
	SDG_TERRO, \
		 FIL__, __LINE__, expr1 ); 
#else
#define TX1(expr1)
#endif

/* #ifndef SH_TRACE_H */
#endif

