#ifndef SH_LOG_MARK_H
#define SH_LOG_MARK_H

void sh_log_mark_destroy();

int sh_log_mark_add (const char * label, time_t interval, const char * qlabel);

void sh_log_mark_update (sh_string * label, time_t timestamp);

void sh_log_mark_check();

int sh_log_set_mark_severity (const char * str);

#endif
