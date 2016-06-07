#ifndef SH_MAIL_INT_H
#define SH_MAIL_INT_H

extern int sh_mail_all_in_one;

/* MX Resolver Struct
 */
typedef struct mx_ {
  int    pref;
  char * address;
} mx;

typedef struct dnsrep_ {
  int    count;
  mx   * reply;
} dnsrep;

int free_mx (dnsrep * answers);

/* adress struct
 */
struct alias {
  sh_string        * recipient;
  struct alias     * recipient_list;
  dnsrep           * mx_list;
  int                severity;
  short              send_mail;
  short              isAlias;
  sh_filter_type   * mail_filter;
  struct alias     * next;
  struct alias     * all_next;
};

extern struct alias * all_recipients;

int sh_mail_msg (const char * message);

/* Per recipient mail key
 */

int sh_nmail_get_mailkey (const char * alias, char * buf, size_t bufsiz,
			  time_t * id_audit);

SH_MUTEX_EXTERN(mutex_listall);
SH_MUTEX_EXTERN(mutex_fifo_mail);
extern SH_FIFO * fifo_mail;

#endif
