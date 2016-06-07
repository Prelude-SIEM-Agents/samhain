#ifndef SH_PRELINK_H
#define SH_PRELINK_H

/* path: full path to file; 
 * file_hash: allocated storage for checksum;
 * alert_timeout: timeout for read
 */
int sh_prelink_run (char * path, char * file_hash, int alert_timeout, unsigned long mask);

/* return S_TRUE if ELF file, S_FALSE otherwise
 */
int sh_prelink_iself (SL_TICKET fd, off_t size, int alert_timeout, char * path);

/* configuration
 */
int sh_prelink_set_path (const char * str);
int sh_prelink_set_hash (const char * str);
#endif
