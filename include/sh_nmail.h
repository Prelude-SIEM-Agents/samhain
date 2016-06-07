#ifndef SH_NMAIL_H
#define SH_NMAIL_H

int sh_nmail_pushstack (int level, const char * message, 
			const char * alias);
int sh_nmail_msg (int level, const char * message, 
		  const char * alias);
int sh_nmail_flush ();
void sh_nmail_free();

int sh_nmail_set_severity (const char * str);
int sh_nmail_add_not (const char * str);
int sh_nmail_add_and (const char * str);
int sh_nmail_add_or  (const char * str);

int sh_nmail_close_recipient(const char * str);
int sh_nmail_add_compiled_recipient(const char * str);
int sh_nmail_add_recipient(const char * str);
int sh_nmail_add_alias(const char * str);
#endif
