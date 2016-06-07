#ifndef SH_IPVX_H
#define SH_IPVX_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(USE_IPVX)
#define SH_SSP_LEN(a) ((a)->ss_family == AF_INET) ? \
	sizeof(struct sockaddr_in) : \
	sizeof(struct sockaddr_in6)

#define SH_SS_LEN(a) ((a).ss_family == AF_INET) ? \
	sizeof(struct sockaddr_in) : \
	sizeof(struct sockaddr_in6)
#else
#define SH_SSP_LEN(a) sizeof(struct sockaddr_in)
#define SH_SS_LEN(a)  sizeof(struct sockaddr_in)
#endif

struct sh_sockaddr {
  int ss_family;

  struct sockaddr_in  sin;
#if defined(USE_IPVX)
  struct sockaddr_in6 sin6;
#endif
};

/* Cast a sockaddress
 */
struct sockaddr * sh_ipvx_sockaddr_cast (struct sh_sockaddr * ss);

/* Compare with any_address
 */
int sh_ipvx_isany (struct sh_sockaddr * a);

/* Compare two addresses
 */
int sh_ipvx_cmp(struct sh_sockaddr * a, struct sh_sockaddr * b);

/* Set the port
 */
int sh_ipvx_set_port(struct sh_sockaddr * ss, int port);

/* Get the port
 */
int sh_ipvx_get_port(struct sockaddr * ss, int sa_family);

/* Save a sockaddress
 */
void sh_ipvx_save(struct sh_sockaddr * ss, int sa_family, struct sockaddr * sa);

/* Ascii numerical sockaddress
 */
char * sh_ipvx_print_sockaddr (struct sockaddr * sa, int sa_family);

/* Determine whether the given address is numeric
 */
int sh_ipvx_is_numeric (const char * addr);

/* Convert a network address to an ascii numeric address
 */
int sh_ipvx_ntoa (char * name, size_t name_size, struct sh_sockaddr * ss);

/* Convert an ascii numeric address to a network address
 */
int sh_ipvx_aton (const char * name, struct sh_sockaddr * ss);

/* Try to find canonical hostname
 */
char * sh_ipvx_canonical(const char * hostname, char * numeric, size_t nlen);

/* Convert address to hostname
 */
char * sh_ipvx_addrtoname(struct sh_sockaddr * ss);

/* Try a reverse lookup
 */
int sh_ipvx_reverse_check_ok (char * peer, int port, struct sh_sockaddr * ss);
#endif
