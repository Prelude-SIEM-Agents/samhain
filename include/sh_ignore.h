#ifndef SH_IGNORE_H
#define SH_IGNORE_H

int sh_ignore_add_del (const char * addpath);
int sh_ignore_add_new (const char * addpath);
int sh_ignore_add_mod (const char * addpath);

int sh_ignore_chk_del (const char * chkpath);
int sh_ignore_chk_new (const char * chkpath);
int sh_ignore_chk_mod (const char * chkpath);

int sh_ignore_clean (void);

#endif
