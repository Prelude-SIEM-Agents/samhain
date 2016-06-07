#ifndef SH_RESTRICT_H
#define SH_RESTRICT_H

int  sh_restrict_define(const char * str);
void sh_restrict_purge ();
int  sh_restrict_this(const char * path, UINT64 size, UINT64 perm, SL_TICKET fh);
int  sh_restrict_add_ftype(const char * str);

#endif
