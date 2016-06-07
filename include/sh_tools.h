#ifndef SH_TOOLS_H
#define SH_TOOLS_H

#define SH_DO_WRITE 0
#define SH_DO_READ  1

/* protocols
 */
#define SH_PROTO_SRP (1 << 0)
#define SH_PROTO_IVA (1 << 1)
#define SH_PROTO_MSG (1 << 2)
#define SH_PROTO_BIG (1 << 3)
#define SH_PROTO_END (1 << 4)
#define SH_PROTO_EN1 (1 << 5)
#define SH_PROTO_EN2 (1 << 6)
#define SH_PROTO_ENC (SH_PROTO_EN1|SH_PROTO_EN2)
#define SH_MASK_ENC (SH_PROTO_ENC|SH_PROTO_EN2)

#ifdef SH_ENCRYPT
/* returns pointer to errbuf
 */
char * errorExplain (int err_num, char * errbuf, size_t len);
#endif

/* Returns non-zero if interface exists
 */
int sh_tools_iface_is_present(char *str);

/* returns allocated buffer
 */
char * sh_tools_safe_name(const char * str, int flag);

int connect_port (char * address, int port, 
		  char * ecall, int * errnum, char * errmsg, int errsiz);
int connect_port_2 (char * address1, char * address2, int port, 
		    char * ecall, int * errnum, char * errmsg, int errsiz);
void delete_cache(void);

/* returns pointer to errbuf
 */
char * sh_tools_errmessage (int tellme, char * errbuf, size_t len);


void   sh_tools_show_header (unsigned char * head, char sign);

#if defined (SH_WITH_SERVER)

unsigned char sh_tools_probe_store(unsigned char protocol, int * probe_flag);

int get_open_max (void);

void put_header (/*@out@*/unsigned char * head, const int protocol, 
		 unsigned long * length, char * u);

int check_request_s (char * have, char * need, char * clt);
int check_request_nerr (char * have, char * need);

/* returns allocated buffer
 */
char * hash_me (char * key, char * buf,   int buflen);
int sh_tools_hash_vfy(char * key, char * buf, int buflen);

/* returns allocated buffer
 */
char * get_client_conf_file (const char * peer, unsigned long * length);

/* returns allocated buffer
 */
char * get_client_data_file (const char * peer, unsigned long * length);

/* returns allocated buffer
 */
char * get_client_uuid_file (const char * peer, unsigned long * length, const char * uuid);
#endif


unsigned long read_port (int sockfd, char *buf, unsigned long nbytes, 
	       int * w_error, int timeout);


#if defined (SH_WITH_CLIENT) || defined(SH_WITH_SERVER)

void sh_tools_probe_reset();

unsigned long write_port (int sockfd, char *buf, unsigned long nbytes, 
			  int * w_error, int timeout);

int check_request (char * have, char * need);
int check_request_nerr (char * have, char * need);

void get_header (unsigned char * head, unsigned long * bytes, char * u);
void put_header (unsigned char * head, int protocol, 
		 unsigned long * length, char * u);

/*
  SL_TICKET open_tmp (void);
  int close_tmp (SL_TICKET fd);
  int rewind_tmp (SL_TICKET fd);
*/

void sh_tools_server_cmd(const char * srvcmd);

int hash_check(char * key, 
	       char * buf,   int buflen);

int sh_tools_hash_add(char * key, char * buf, int buflen);
#endif

#if defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER) || defined(SH_STEALTH) || defined(WITH_GPG) || defined(WITH_PGP)
SL_TICKET open_tmp (void);
int close_tmp (SL_TICKET fd);
int rewind_tmp (SL_TICKET fd);
#endif

#endif
