#ifndef SH_SUB_H
#define SH_SUB_H

void sh_kill_sub ();
int sh_sub_stat  (const char *path, struct stat *buf);
int sh_sub_lstat (const char *path, struct stat *buf);

#endif
