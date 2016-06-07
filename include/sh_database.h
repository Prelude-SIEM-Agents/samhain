#ifndef SH_DATABASE_H
#define SH_DATABASE_H

void sh_database_reset(void);
int sh_database_insert (char * message);

int sh_database_use_persistent (const char * str);

int sh_database_set_database (const char * str);
int sh_database_set_table (const char * str);
int sh_database_set_host (const char * str);
int sh_database_set_user (const char * str);
int sh_database_set_password (const char * str);
int sh_database_add_to_hash  (const char * str);
int set_enter_wrapper (const char * str);
#endif
