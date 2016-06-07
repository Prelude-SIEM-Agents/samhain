#ifndef SH_SOCKET_H
#define SH_SOCKET_H

/* 63 (cmd) + 1 (':') + 63 (host) + 1 ('\0') + 81
 */
#define SH_MAXMSG 209
#define SH_MAXMSGLEN 64

#if defined (SH_WITH_CLIENT)
char * sh_socket_get_uuid(int * errflag, unsigned int * count, time_t * last);
int    sh_socket_store_uuid(const char * cmd);
int    sh_socket_return_uuid(const char * uuid, unsigned int count, time_t last);
void   sh_socket_server_cmd(const char * srvcmd);
int    set_delta_retry_interval(const char * str);
int    set_delta_retry_count(const char * str);
#endif

#if defined (SH_WITH_SERVER)


int    sh_socket_open_int (void);
int    sh_socket_remove (void);
char * sh_socket_check(const char * client_name);
int    sh_socket_poll(void);
void   sh_socket_add2reload (const char * clt);

#endif


#endif
