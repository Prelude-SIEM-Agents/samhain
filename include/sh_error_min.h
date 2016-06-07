#ifndef SH_ERROR_MIN_H
#define SH_ERROR_MIN_H

/* Level of severity
 */
typedef enum {
  
  SH_ERR_ALL     = (1 << 0),  /* debug   */
  SH_ERR_INFO    = (1 << 1),  /* info    */
  SH_ERR_NOTICE  = (1 << 2),  /* notice  */
  SH_ERR_WARN    = (1 << 3),  /* warning */
  SH_ERR_STAMP   = (1 << 4),  /* mark    */
  SH_ERR_ERR     = (1 << 5),  /* error   */
  SH_ERR_SEVERE  = (1 << 6),  /* crit    */
  SH_ERR_FATAL   = (1 << 7),  /* alert   */

  SH_ERR_NOT     = (1 << 8),
  SH_ERR_INET    = (1 << 9),
  SH_ERR_MAX     = (1 << 9)
 } ShErrLevel;

/* this function should be called to report an error
 */
void sh_error_handle (int flag, const char * file, long line, 
		      long errnum, unsigned long  msg_index, ...);

/* this function should be called to (only) send mail
 */
void sh_error_mail (const char * alias, int sev, 
		    const char * file, long line, 
		    long status, unsigned long msg_id, ...);

/* convert a string to a numeric priority
 */ 
int sh_error_convert_level (const char * str_s);

/* error messages
 */
char * sh_error_message (int tellme, char * str, size_t len);

#endif
