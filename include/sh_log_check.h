#ifndef SH_LOGCHECK_H
#define SH_LOGCHECK_H

#include <sys/types.h>
#include <time.h>

/* Convert a struct tm to unix timestamp with caching 
 */
time_t conv_timestamp (struct tm * btime, 
		       struct tm * old_tm, time_t * old_time);

/* Definition of a log record entry, to be returned from parsing function.
 */
#define PID_INVALID 0
struct sh_logrecord 
{
  char      * filename;
  sh_string * host;
  sh_string * timestr;
  pid_t       pid;
  time_t      timestamp;
  sh_string * message;
};

#define SH_LOGFILE_MOVED  (1<<0)
#define SH_LOGFILE_REWIND (1<<1)
#define SH_LOGFILE_PIPE   (1<<2)
#define SH_LOGFILE_NOFILE (1<<3)

struct sh_logfile 
{
  FILE * fp;
  int    flags;
  char * filename;
  dev_t  device_id;
  ino_t  inode;
  fpos_t offset;

  /* Info for the parser, e.g. a regular expression
   */
  void * fileinfo;

  /* Callback function to read the next record
   */
  sh_string *           (*get_record)  (sh_string * record, 
					struct sh_logfile * logfile);

  /* Callback function to parse the record into standard format
   */
  struct sh_logrecord * (*parse_record)(sh_string * logline, void * fileinfo);

  struct sh_logfile * next;
};

/* Generic callback function to parse fileinfo. 
 */
void * sh_eval_fileinfo_generic(char * str);

/* Generic parser info. 
 */
struct sh_logrecord * sh_parse_generic (sh_string * logline, void * fileinfo);


/****************************************************************
 **
 ** Parsing and reading functions
 **/

/* Open file, position at stored offset. */
int sh_open_for_reader (struct sh_logfile * logfile);

/* Simple line reader for executed shell command   */ 
sh_string * sh_command_reader (sh_string * record, 
			       struct sh_logfile * logfile);

/* Wrapper for sh_command_reader */
sh_string * sh_read_shell (sh_string * record, struct sh_logfile * logfile);

/* Parses a shell command reply. */
struct sh_logrecord * sh_parse_shell (sh_string * logline, void * fileinfo);

/* Simple line reader.   */ 
sh_string * sh_default_reader (sh_string * record, 
			       struct sh_logfile * logfile);

/* Continued line reader.   */ 
sh_string * sh_cont_reader (sh_string * record, 
			    struct sh_logfile * logfile, char * cont);

/* Binary reader */
sh_string * sh_binary_reader (void * s, size_t size, struct sh_logfile * logfile);

/* Parses a syslog-style line. */
struct sh_logrecord * sh_parse_syslog (sh_string * logline, void * fileinfo);

/* Format info for apache log. */
void * sh_eval_fileinfo_apache(char * str);

/* Parses a apache-style line. */
struct sh_logrecord * sh_parse_apache (sh_string * logline, void * fileinfo);

/* Get a pacct record */
sh_string * sh_read_pacct (sh_string * record, struct sh_logfile * logfile);

/* Parses a pacct record. */
struct sh_logrecord * sh_parse_pacct (sh_string * logline, void * fileinfo);

/* Get a samba record */
sh_string * sh_read_samba (sh_string * record, struct sh_logfile * logfile);

/* Parses a samba record. */
struct sh_logrecord * sh_parse_samba (sh_string * logline, void * fileinfo);


/**
*****************************************************************/

int sh_get_hidepid();
int sh_set_hidepid(const char *s);

#define SH_MAX_LCODE_SIZE 16

struct sh_logfile_type 
{
  char code[SH_MAX_LCODE_SIZE];

  /* read callback */
  /*@null@*/sh_string * (*get_record)  (sh_string * record,
					struct sh_logfile * logfile);
  /* parsing callback */
  struct sh_logrecord * (*parse_record)(sh_string * logline, void * fileinfo);

  /* evaluate fileinfo */
  void * (*eval_fileinfo)(char * str); 
};


#endif
