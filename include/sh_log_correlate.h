#ifndef SH_LOG_CORRELATE_H
#define SH_LOG_CORRELATE_H

/* Clean up everything.
 */
void sh_keep_destroy();

/* Add an event 
 */
int sh_keep_add(sh_string * label, unsigned long delay, time_t last);

/* Add an event sequence matching rule 
 */
int sh_keep_match_add(const char * str, const char * queue, const char * pattern);

/* Delete the list of event sequence matching rules
 */
void sh_keep_match_del();

/* Try to find correlated events
 */
void sh_keep_match();

/* Deadtime for a correlation rule
 */
int sh_keep_deadtime (const char * str);

#endif
