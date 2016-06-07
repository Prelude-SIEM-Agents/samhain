#ifndef SH_EXTERN_H
#define SH_EXTERN_H

#include <stdarg.h>

typedef struct 
{
  char   *  command;
  int       argc;
  char   *  argv[32];
  int       envc;
  char   *  envv[32];
  char      checksum[KEY_LEN + 1];
#if 0
  uid_t     trusted_users[32];
#endif
  uid_t     run_user_uid;
  gid_t     run_user_gid;
  int       privileged;

  int       pipeFD;
  SL_TICKET pipeTI;
  pid_t     pid;
  FILE   *  pipe;
  char      rw;
  int       exit_status;
  int       fork_twice;

  int       com_fd;
  SL_TICKET com_ti;

} sh_tas_t;


/*
 * -- generic safe popen; returns 0 on success, -1 otherwise
 */
int sh_ext_popen (sh_tas_t * task);

/*
 * -- generic simple safe popen; returns 0 on success, -1 otherwise,
 *    executes shell command
 */
int sh_ext_popen_init (sh_tas_t * task, const char * command, char * argv0, ...) SH_GNUC_SENTINEL;

/*
 * -- Execute command, return first line of output
 */
int sh_ext_system (char * command, char * argv0, ...) SH_GNUC_SENTINEL;

/*
 * -- Execute command, return first line of output
 */
char * sh_ext_popen_str (const char * command);

/*
 * -- close the pipe, clear and return task->exit_status
 */
int sh_ext_pclose (sh_tas_t * task);

/*
 * -- add CL argument, return # of arguments
 */
int sh_ext_tas_add_argv(sh_tas_t * tas, const char * val);
/*
 * -- remove last CL argument
 */
int sh_ext_tas_rm_argv(sh_tas_t * tas);
/*
 * -- add environment variable, return # of variables
 */
int sh_ext_tas_add_envv(sh_tas_t * tas, const char * key, const char * val);
/*
 * -- set command
 */
void sh_ext_tas_command(sh_tas_t * tas, const char * command);
/*
 * -- initialize task structure
 */
void sh_ext_tas_init (sh_tas_t * tas);
/*
 * -- free task structure
 */
void sh_ext_tas_free(sh_tas_t * tas);


#if defined(WITH_EXTERNAL)

/* 
 * -- start a new external command, and add it to the list
 */ 
int sh_ext_setcommand(const char * cmd);

/*
 * -- explicitely close a command
 */
int sh_ext_close_command (const char * str);

/* 
 * -- clean up the command list
 */
int sh_ext_cleanup(void);

/*
 * -- set deadtime
 */
int sh_ext_deadtime (const char * str);

/*
 * -- add keywords to the OR filter
 */
int sh_ext_add_or (const char * str);

/*
 * -- add keywords to the AND filter
 */
int sh_ext_add_and (const char * str);

/*
 * -- add keywords to the NOT filter
 */
int sh_ext_add_not (const char * str);

/*
 * -- add keywords to the CL argument list
 */
int sh_ext_add_argv (const char * str);

/*
 * -- add a path to the environment
 */
int sh_ext_add_default (const char * str);

/*
 * -- add an environment variable
 */
int sh_ext_add_environ (const char * str);

/*
 * -- define type
 */
int sh_ext_type (const char * str);

/*
 * -- define checksum
 */
int sh_ext_checksum (const char * str);

/*
 * -- choose privileges
 */
int sh_ext_priv (const char * c);

/*
 * -- execute external script/program
 */
int sh_ext_execute (char t1, char t2, char t3, /*@null@*/char * message, 
		    size_t msg_siz);

#endif

#endif
