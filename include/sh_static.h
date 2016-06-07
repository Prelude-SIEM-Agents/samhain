#ifndef SH_STATIC_H
#define SH_STATIC_H

#include "config_xor.h"

#if defined(SH_COMPILE_STATIC) && defined(__linux__)

#ifdef SH_NEED_PWD_GRP
int  sh_initgroups(const char *user, gid_t gid);
struct group * sh_getgrent(void);
struct passwd * sh_getpwent(void);
void  sh_endgrent(void);
void  sh_setgrent(void);
void  sh_endpwent(void);
void  sh_setpwent(void);
struct group * sh_getgrnam(const char *name);
int sh_getgrnam_r(const char *name, struct group *gbuf,
               char *buf, size_t buflen, struct group **gbufp);

struct passwd * sh_getpwnam(const char *name);
int sh_getpwnam_r(const char *name, struct passwd *pwbuf,
               char *buf, size_t buflen, struct passwd **pwbufp);

struct group * sh_getgrgid(gid_t gid);
int sh_getgrgid_r(gid_t gid, struct group *gbuf,
	       char *buf, size_t buflen, struct group **gbufp);

struct passwd * sh_getpwuid(uid_t uid);
int sh_getpwuid_r(uid_t uid, struct passwd *pwbuf,
               char *buf, size_t buflen, struct passwd **pwbufp);

#endif

#ifdef SH_NEED_GETHOSTBYXXX
struct hostent * sh_gethostbyaddr (const void *addr, socklen_t len, int type);
struct hostent * sh_gethostbyname(const char *name);
#endif

#else

#define sh_initgroups initgroups
#define sh_getgrnam   getgrnam
#define sh_getgrnam_r getgrnam_r
#define sh_getgrgid   getgrgid
#define sh_getgrgid_r getgrgid_r
#define sh_getpwnam   getpwnam
#define sh_getpwnam_r getpwnam_r
#define sh_getpwuid   getpwuid
#define sh_getpwuid_r getpwuid_r
#define sh_getpwent   getpwent
#define sh_endpwent   endpwent
#define sh_setpwent   setpwent

#define sh_gethostbyaddr gethostbyaddr
#define sh_gethostbyname gethostbyname

#endif 

#endif

