#ifndef SH_LOG_REPEAT_H
#define SH_LOG_REPEAT_H

int sh_repeat_set_trigger (const char * str);

int sh_repeat_set_queue (const char * str);

int sh_repeat_set_cron (const char * str);

int sh_repeat_message_check (const sh_string * host, 
			     const sh_string * msg, 
			     time_t ltime);

#endif
