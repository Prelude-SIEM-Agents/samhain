#ifndef SH_CHECKSUM_H
#define SH_CHECKSUM_H

typedef unsigned char sha2_byte  ;
typedef UINT32        sha2_word32;
typedef UINT64        sha2_word64;


#define SHA256_BLOCK_LENGTH             64
#define SHA256_SHORT_BLOCK_LENGTH       (SHA256_BLOCK_LENGTH - 8)
#define SHA256_DIGEST_LENGTH            32
#define SHA256_DIGEST_STRING_LENGTH     (SHA256_DIGEST_LENGTH * 2 + 1)

typedef struct _SHA256_CTX {
        sha2_word32     state[8];
        sha2_word64     bitcount;
        sha2_byte       buffer[SHA256_BLOCK_LENGTH];
} SHA256_CTX;

void SHA256_Init(SHA256_CTX *);
void SHA256_Update(SHA256_CTX*, const sha2_byte*, size_t);
void SHA256_Final(sha2_byte[SHA256_DIGEST_LENGTH], SHA256_CTX*);
char* SHA256_End(SHA256_CTX*, char[KEYBUF_SIZE]);
char* SHA256_Data(const sha2_byte*, size_t, char[KEYBUF_SIZE]);
char* SHA256_Base2Hex(char * b64digest, char * hexdigest); 
char * SHA256_ReplaceBaseByHex(const char * str, char * before, char after);
#endif
