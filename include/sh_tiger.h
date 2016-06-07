
#ifndef SH_TIGER_H
#define SH_TIGER_H 

#include "config_xor.h"
#include "slib.h"
#include "samhain.h"

typedef long int TigerType;

#define TIGER_FILE -1
#define TIGER_DATA -2

/****************
typedef long int TigerType;
typedef enum {
  TIGER_FILE,
  TIGER_FD,
  TIGER_DATA
} TigerType;
*****************/

#define TIGER_NOLIM ((UINT64)-1)

/* the checksum function
 */
char * sh_tiger_hash (const char * filename, TigerType what, 
		      UINT64 Length, char * out, size_t len);

/* NEW Thu Oct 18 19:59:08 CEST 2001
 */
int sh_tiger_hashtype (const char * c);
char * sh_tiger_generic_hash (char * filename, TigerType what, 
			      UINT64 * Length, int timeout, 
			      char * out, size_t len);

UINT32 * sh_tiger_hash_uint32 (char * filename, 
			       TigerType what, 
			       UINT64 Length, UINT32 * out, size_t len);

/* get the type of hash function used
 * 0 = tiger192, 1 = sha1, 2 = md5
 */
int sh_tiger_get_hashtype (void);

/* set the hash fuction in use in the mask
 */
void sh_tiger_get_mask_hashtype(unsigned long * mask);


/* reset the hash function to the one in the mask
 */
void sh_tiger_set_hashtype_mask(unsigned long mask);

/* GnuPG-like format, returns allocated memory
 */
/*@owned@*/ char * sh_tiger_hash_gpg (const char * filename, TigerType what, 
				      UINT64 Length);
#endif
