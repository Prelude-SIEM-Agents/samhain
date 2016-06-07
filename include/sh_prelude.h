#ifndef SH_PRELUDE_H
#define SH_PRELUDE_H

void sh_prelude_reset(void);
void sh_prelude_stop(void);
int  sh_prelude_init(void);

int sh_prelude_set_profile(const char *arg);

int sh_prelude_alert (int priority, int class, char * message,
		      long msgflags, unsigned long msgid, char * inet_peer_ip);

/* map severity levels
 */
int sh_prelude_map_info (const char * str);
int sh_prelude_map_low (const char * str);
int sh_prelude_map_medium (const char * str);
int sh_prelude_map_high (const char * str);

#endif
