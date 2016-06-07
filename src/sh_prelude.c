/*
 *
 * Copyright (C) 2005 Yoann Vandoorselaere, Prelude IDS Technologies
 *                    Rainer Wichmann
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/*
 * 28/04/2005 : R.W.:
 *       move libprelude 0.8 code to seperate file
 *
 * 23/04/2005 : R.W.: 
 *       include libprelude 0.9 code from Yoann Vandoorselaere
 */


/*
 * for strptime()
 */
#define _GNU_SOURCE 1 

#include "config_xor.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#if TIME_WITH_SYS_TIME

# include <sys/time.h>
# include <time.h>

#else

# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif

#endif

#include <unistd.h>
#include <syslog.h>
#include <pwd.h>

int     sh_argc_store;
char ** sh_argv_store;

#if defined(HAVE_LIBPRELUDE)


/*
 * _() macros are samhain specific; they are used to replace string
 * constants at runtime. This is part of the samhain stealth mode
 * (fill string constants with encoded strings, decode at runtime).
 */
#define FIL__  _("sh_prelude.c")


#include <libprelude/idmef.h>
#include <libprelude/prelude.h>

/* 
 * includes for samhain-specific functions (sl_strstr, sh_error_handle)
 */
#include "samhain.h"
#include "sh_cat.h"
#include "sh_error_min.h"
#include "sh_prelude.h"
#define SH_NEED_PWD_GRP 1
#include "sh_static.h"
char * sh_util_strdup (const char * str) SH_GNUC_MALLOC;
/*
 * When SH_USE_XML is set, value are formated using name="value".
 * Otherwise, value is formatted using the format name=<value>.
 */
#ifdef SH_USE_XML
# define VALUE_DELIM_START '"'
# define VALUE_DELIM_END   '"'
#else
# define VALUE_DELIM_START '<'
# define VALUE_DELIM_END   '>'
#endif

#define IDMEF_ANALYZER_MODEL _("Samhain")
#define IDMEF_ANALYZER_CLASS _("Integrity Checker")
#define IDMEF_ANALYZER_VERSION VERSION
#define IDMEF_ANALYZER_MANUFACTURER _("http://www.la-samhna.de/samhain/")



/* 
 * 0 = not initialized; -1 = failed; 1 = initialized
 */
static int initialized = 0;
static int ready_for_init = 0;

static char *profile = NULL;
static prelude_client_t *client = NULL;

static int severity_map[1 + (unsigned int) IDMEF_IMPACT_SEVERITY_HIGH] = { 
        /* 0: unused (?) */ 0, 
        /* 1: INFO       */ 0, 
        /* 2: LOW        */ SH_ERR_ALL|SH_ERR_INFO,
        /* 3: MEDIUM     */ SH_ERR_NOTICE|SH_ERR_WARN|SH_ERR_STAMP|SH_ERR_ERR,
        /* 4: HIGH       */ SH_ERR_SEVERE|SH_ERR_FATAL
};

/* returns 0/tiger, 1/sha1, or 2/md5
 */
extern int sh_tiger_get_hashtype(void);

static void clear_and_set (int setpos, int flag)
{
        unsigned int i;
	/* clear everywhere, and set at correct position */
        for (i = 1; i < (1 + (unsigned int) IDMEF_IMPACT_SEVERITY_HIGH); ++i)
                severity_map[i] &= ~flag;
        severity_map[setpos] |= flag;
        return;
}

static int set_prelude_severity_int (const char * str, int prelude_sev)
{
        char * p;
	char * dup = strdup (str);
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
	char * saveptr;
#endif

	if (!dup) 
	        return -1;

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
	p = strtok_r (dup, ", \t", &saveptr);
#else
	p = strtok (dup, ", \t");
#endif
        if (p) {
                do {
                        if      (0 == strcmp (p, _("alert")))
                                clear_and_set (prelude_sev, SH_ERR_FATAL);
                        else if (0 == strcmp (p, _("crit")))
                                clear_and_set (prelude_sev, SH_ERR_SEVERE);
                        else if (0 == strcmp (p, _("err")))
                                clear_and_set (prelude_sev, SH_ERR_ERR);
                        else if (0 == strcmp (p, _("mark")))
	                        clear_and_set (prelude_sev, SH_ERR_STAMP);
                        else if (0 == strcmp (p, _("warn")))
	                        clear_and_set (prelude_sev, SH_ERR_WARN);
                        else if (0 == strcmp (p, _("notice")))
                                clear_and_set (prelude_sev, SH_ERR_NOTICE);
                        else if (0 == strcmp (p, _("debug")))
	                        clear_and_set (prelude_sev, SH_ERR_ALL);
                        else if (0 == strcmp (p, _("info")))
	                        clear_and_set (prelude_sev, SH_ERR_INFO);
                        else {
			        free (dup);
	                        return -1;
			}
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
                        p = strtok_r (NULL, ", \t", &saveptr);
#else
                        p = strtok (NULL, ", \t");
#endif
                } while (p);
        }
	free(dup);
        return 0;
}

int sh_prelude_map_info (const char * str)
{
        return (set_prelude_severity_int(str,(int)IDMEF_IMPACT_SEVERITY_INFO));
}
int sh_prelude_map_low (const char * str)
{
        return (set_prelude_severity_int(str,(int)IDMEF_IMPACT_SEVERITY_LOW));
}
int sh_prelude_map_medium (const char * str)
{
        return (set_prelude_severity_int(str,(int)IDMEF_IMPACT_SEVERITY_MEDIUM));
}
int sh_prelude_map_high (const char * str)
{
        return (set_prelude_severity_int(str,(int)IDMEF_IMPACT_SEVERITY_HIGH));
}

static idmef_impact_severity_t map_severity (int sam_sev)
{
        int i;
        int max = 1 + (unsigned int) IDMEF_IMPACT_SEVERITY_HIGH;
        idmef_impact_severity_t retval = IDMEF_IMPACT_SEVERITY_MEDIUM;

        for (i = 0; i < max; ++i) {
	        if (severity_map[i] & sam_sev) {
	                retval = (idmef_impact_severity_t) i;
	        }
	}
	return retval; 
} 

static char *do_get_value(char *ptr, char delim_start, char delim_end)
{
        char *ret = NULL;
#if defined(SH_WITH_SERVER)
        int    delim_start_count = 0;
        int    found = 0;
#endif                

        ptr = strchr(ptr, delim_start);
        if ( ! ptr )
                return NULL;

        ret = ++ptr;
#if defined(SH_WITH_SERVER)
        while ((*ptr != '\0') && (!found)){
		if (*ptr == delim_end) {
		        if (delim_start_count == 0)
			        found = 1;
			delim_start_count--;
		}
		else if (*ptr == delim_start) 
		        delim_start_count++;
		ptr++;
        }
        ptr = (found) ? ptr-1 : NULL ;
#else
        ptr = strchr(ptr, delim_end);
#endif
        if ( ! ptr )
                return NULL;
        
        *ptr = '\0';
        ret = strdup(ret);
        *ptr = delim_end;
        
        return ret;
}



static char *get_value(char *msg, const char *toktmp, const char *toksuffix)
{
        char *ptr, tok[128];
        
        snprintf(tok, sizeof(tok), "%s%s=", toktmp, (toksuffix) ? toksuffix : "");

        ptr = strstr(msg, tok);
        if ( ! ptr )
                return NULL;

        return do_get_value(ptr, VALUE_DELIM_START, VALUE_DELIM_END);
}



static char *get_time_value(char *msg, const char *toktmp, const char *toksuffix)
{
        
        char *ret, *ptr, tok[128];
                 
        snprintf(tok, sizeof(tok), "%s%s=", toktmp, (toksuffix) ? toksuffix : "");

        ptr = strstr(msg, tok);
        if ( ! ptr )
                return NULL;

#ifndef SH_USE_XML
        ret = do_get_value(ptr, '[', ']');
#else
        ret = do_get_value(ptr, VALUE_DELIM_START, VALUE_DELIM_END);
#endif

        return ret;
}




#if 0
void debug_print_message(idmef_message_t *msg)
{
        int ret;
        prelude_io_t *fd;

        ret = prelude_io_new(&fd);
        if ( ret < 0 )
                return;
        
        prelude_io_set_file_io(fd, stderr);
        idmef_message_print(idmef, fd);

        prelude_io_destroy(fd);
}
#endif



static int idmef_time_from_samhain(idmef_time_t **time, const char *str)
{
        int ret;
        char *ptr;
        time_t utc;
        struct tm lt;
        
        /*
         * Samhain stamp are encoded in UTC.
         */
        ptr = strptime(str, _("%Y-%m-%dT%H:%M:%S"), &lt);
        if ( ! ptr ) {
                sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
                                _("could not format Samhain time"), _("idmef_time_from_samhain"));
                return -1;
        }

        utc = prelude_timegm(&lt);
        
        ret = idmef_time_new_from_time(time, &utc);
        if ( ret < 0 )
                return ret;
                        
        return 0;
}

/* flawfinder: ignore *//* is part of name, not access() */
static void get_access_info(idmef_file_access_t *access, char * mode, int pos, int mpos)
{
        int got = 0;
	int ret;
	prelude_string_t *str;

	do {
	        if ( mode[pos] == 'r' ) {
			/* flawfinder: ignore *//* is part of name, not access() */
	                ret = idmef_file_access_new_permission(access, &str, IDMEF_LIST_APPEND);
	                if ( ret < 0 )
	                        return;
	                prelude_string_set_dup(str, _("read"));
	                ++got;
	        }
	        else if ( mode[pos] == 'w' ) {
			/* flawfinder: ignore *//* is part of name, not access() */
	                ret = idmef_file_access_new_permission(access, &str, IDMEF_LIST_APPEND);
	                if ( ret < 0 )
	                        return;
	                prelude_string_set_dup(str, _("write"));
	                ++got;
	        }
	        else if ( mode[pos] == 'x' || mode[pos] == 's' || mode[pos] == 't') {
			/* flawfinder: ignore *//* is part of name, not access() */
	                ret = idmef_file_access_new_permission(access, &str, IDMEF_LIST_APPEND);
	                if ( ret < 0 )
	                        return;
                        
	                if ( mode[pos] == 'x' && mode[0] == 'd' )
	                        prelude_string_set_dup(str, _("search"));

                        else if ( mode[pos] == 'x' || mode[pos] == 't' )
	                        prelude_string_set_dup(str, _("execute"));

                        else /* 's' */
	                        prelude_string_set_dup(str, _("executeAs"));
	                ++got;
	        }
	        ++pos;
	} while (pos <= mpos);

	if ( got == 0 ) {
	        /* flawfinder: ignore *//* is part of name, not access() */
	        ret = idmef_file_access_new_permission(access, &str, IDMEF_LIST_APPEND);
	        if ( ret < 0 )
	                return;
	        prelude_string_set_dup(str, _("noAccess"));
	}
	return;
}


static void get_file_infos(idmef_target_t *target, char *msg, 
			   idmef_file_category_t category)
{
        int ret;
        int hashtype = 0;
        char *ptr;
        idmef_time_t *time;
        idmef_file_t *file;
        idmef_inode_t *inode;
        prelude_string_t *str;
        idmef_checksum_t *checksum;
        idmef_file_access_t *access; /* flawfinder: ignore */
        idmef_user_id_t *userid;
        const char *suffix = (category == IDMEF_FILE_CATEGORY_CURRENT) ? "_new" : "_old";
	char *mode = NULL;
                
        ret = idmef_target_new_file(target, &file, IDMEF_LIST_APPEND);
        if ( ret < 0  )
                return;
        idmef_file_set_category(file, category);

        ptr = get_value(msg, _("path"), NULL);
        if ( ptr ) {
                /*
                 * In term of IDMEF, this is the full path,
                 * including the name.
                 */
                ret = idmef_file_new_path(file, &str);
                if ( ret < 0 ) {
		        free(ptr);
                        return;
		}
                prelude_string_set_nodup(str, ptr);

                ptr = strrchr(ptr, '/');
                if ( ptr ) {
                        ret = idmef_file_new_name(file, &str);
                        if ( ret == 0 ) {
			        prelude_string_set_dup(str, ptr + 1);
			}
                }
        }
                
        ptr = get_value(msg, _("size"), suffix);
	if ( ptr ) {
                idmef_file_set_data_size(file, strtoul(ptr, NULL, 10));
                free(ptr);
        }
        
        ptr = get_time_value(msg, _("mtime"), suffix);
        if ( ptr ) {
                ret = idmef_time_from_samhain(&time, ptr);
                if ( ret == 0 ) {
                        idmef_file_set_modify_time(file, time);
		}
                free(ptr);
        }

        ptr = get_time_value(msg, _("ctime"), suffix);
        if ( ptr ) {
                ret = idmef_time_from_samhain(&time, ptr);
                if ( ret == 0 ) {
                        idmef_file_set_create_time(file, time);
		}
                free(ptr);
        }
                
        ptr = get_value(msg, _("inode"), suffix);
        if ( ptr ) {
                ret = idmef_file_new_inode(file, &inode);
                if ( ret == 0 ) {
			char * dev = get_value(msg, _("dev"), suffix);
			if (dev) {
			        char * q = strchr(dev, ',');
				if (*q) {
				         *q = '\0'; ++q;
					 idmef_inode_set_major_device(inode, strtoul(dev, NULL, 0));
					 idmef_inode_set_minor_device(inode, strtoul(  q, NULL, 0));
				}
				free(dev);
			}
			idmef_inode_set_number(inode, strtoul(ptr, NULL, 10));
		}
                free(ptr);
        }

        ptr = get_value(msg, _("chksum"), suffix);
        if ( ptr ) {
                ret = idmef_file_new_checksum(file, &checksum, IDMEF_LIST_APPEND);
                if ( ret < 0 ) {
			free(ptr);
			goto get_mode;
		}

		hashtype = sh_tiger_get_hashtype();

		if (hashtype == 0)
			idmef_checksum_set_algorithm(checksum, IDMEF_CHECKSUM_ALGORITHM_TIGER);

		else if (hashtype == 1)
			idmef_checksum_set_algorithm(checksum, IDMEF_CHECKSUM_ALGORITHM_SHA1);
		
		else if (hashtype == 2)
			idmef_checksum_set_algorithm(checksum, IDMEF_CHECKSUM_ALGORITHM_MD5);
		
		else
			idmef_checksum_set_algorithm(checksum, IDMEF_CHECKSUM_ALGORITHM_TIGER);


		ret = idmef_checksum_new_value(checksum, &str);
		if ( ret < 0 ) {
			free(ptr);
			goto get_mode;
		}

		/* will be freed on destroy()
		 */
		prelude_string_set_nodup(str, ptr);
	}

 get_mode:

	mode = get_value(msg, _("mode"), suffix);
        if ( mode ) {
	        /* flawfinder: ignore *//* is part of name, not access() */
                ret = idmef_file_new_file_access(file, &access, IDMEF_LIST_APPEND);
                if ( ret < 0 )
                        goto get_owner;

	        /* flawfinder: ignore *//* is part of name, not access() */
                ret = idmef_file_access_new_user_id(access, &userid);
                if ( ret < 0 )
                        goto get_owner;
                idmef_user_id_set_type(userid, IDMEF_USER_ID_TYPE_OTHER_PRIVS);

	        /* flawfinder: ignore *//* is part of name, not access() */
		get_access_info ( access, mode, 7, 9 );
        }

 get_owner:
 
        ptr = get_value(msg, _("owner"), suffix);
        if ( ptr ) {
	        char * uid;
                
	        /* flawfinder: ignore *//* is part of name, not access() */
                ret = idmef_file_new_file_access(file, &access, IDMEF_LIST_APPEND);
                if ( ret < 0 ) {
                        free(ptr);
                        goto get_group;
		}

	        /* flawfinder: ignore *//* is part of name, not access() */
                ret = idmef_file_access_new_user_id(access, &userid);
                if ( ret < 0 ) {
                        free(ptr);
                        goto get_group;
		}
                idmef_user_id_set_type(userid, IDMEF_USER_ID_TYPE_USER_PRIVS);
                
                ret = idmef_user_id_new_name(userid, &str);
                if ( ret < 0 ) {
                        free(ptr);
                        goto get_group;
                }
                prelude_string_set_nodup(str, ptr);
                
                uid = get_value(msg, _("iowner"), suffix);
                if ( ! uid )
                        goto get_group;
                
                idmef_user_id_set_number(userid, strtoul(uid, NULL, 0));

		if ( mode ) {
		        /* flawfinder: ignore *//* is part of name, not access() */
		        get_access_info ( access, mode, 1, 3 );
		}

		free(uid);
		/* Don't free(ptr) because of prelude_string_set_nodup(str, ptr) */
        }

 get_group:

        ptr = get_value(msg, _("group"), suffix);
        if ( ptr ) {
                char *gid;
                
	        /* flawfinder: ignore *//* is part of name, not access() */
                ret = idmef_file_new_file_access(file, &access, IDMEF_LIST_APPEND);
                if ( ret < 0 ) {
                        free(ptr);
                        goto mode_free;
		}

                ret = idmef_file_access_new_user_id(access, &userid);/* flawfinder: ignore *//* is part of name, not access() */
                if ( ret < 0 ) {
                        free(ptr);
                        goto mode_free;
		}

                idmef_user_id_set_type(userid, IDMEF_USER_ID_TYPE_GROUP_PRIVS);
                
                ret = idmef_user_id_new_name(userid, &str);
                if ( ret < 0 ) {
                        free(ptr);
                        goto mode_free;
		}
                
                prelude_string_set_nodup(str, ptr);

                gid = get_value(msg, _("igroup"), suffix);
                if ( ! gid )
                        goto mode_free;

                idmef_user_id_set_number(userid, strtoul(gid, NULL, 0));

		if ( mode ) {
		        get_access_info ( access, mode, 4, 6 ); /* flawfinder: ignore */
		}

		free(gid);
		/* Don't free(ptr) because of prelude_string_set_nodup(str, ptr) */
        }

 mode_free:

	if ( mode ) {
	        free ( mode );
	}

	return;
}



static int map_policy_to_class(char *msg, unsigned long msgid, idmef_impact_t *impact, prelude_string_t *out)
{
        char *ptr;
        int ret, i;
        struct tbl {
                unsigned int msgid;
                const char *name;
                idmef_impact_type_t type;
        } tbl[] = {

#ifdef SH_USE_UTMP
                { MSG_UT_LG1X, N_("User Login"), IDMEF_IMPACT_TYPE_USER },
                { MSG_UT_LG1A, N_("User Login"), IDMEF_IMPACT_TYPE_USER },
                { MSG_UT_LG1B, N_("User Login"), IDMEF_IMPACT_TYPE_USER },
                { MSG_UT_LG2X, N_("Multiple User Login"), IDMEF_IMPACT_TYPE_USER },
                { MSG_UT_LG2A, N_("Multiple User Login"), IDMEF_IMPACT_TYPE_USER },
                { MSG_UT_LG2B, N_("Multiple User Login"), IDMEF_IMPACT_TYPE_USER },
                { MSG_UT_LG3X, N_("User Logout"), IDMEF_IMPACT_TYPE_USER },
                { MSG_UT_LG3A, N_("User Logout"), IDMEF_IMPACT_TYPE_USER },
                { MSG_UT_LG3B, N_("User Logout"), IDMEF_IMPACT_TYPE_USER },
                { MSG_UT_LG3C, N_("User Logout"), IDMEF_IMPACT_TYPE_USER },
#endif

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
                { MSG_FI_MISS,  N_("File Missing"), IDMEF_IMPACT_TYPE_FILE },
                { MSG_FI_MISS2, N_("File Missing"), IDMEF_IMPACT_TYPE_FILE },
                { MSG_FI_ADD, N_("File Added"), IDMEF_IMPACT_TYPE_FILE },
                { MSG_FI_ADD2, N_("File Added"), IDMEF_IMPACT_TYPE_FILE },
                { MSG_FI_CHAN, N_("File Modified"), IDMEF_IMPACT_TYPE_FILE },
                { MSG_FI_NODIR, N_("File found where directory was expected"), IDMEF_IMPACT_TYPE_FILE },
#endif

#ifdef SH_USE_KERN
                { MSG_KERN_POLICY, N_("Kernel Modified"), IDMEF_IMPACT_TYPE_OTHER },
                { MSG_KERN_POL_CO, N_("Kernel Modified"), IDMEF_IMPACT_TYPE_OTHER },
                { MSG_KERN_PROC, N_("Kernel Modified"), IDMEF_IMPACT_TYPE_OTHER },
                { MSG_KERN_GATE, N_("Kernel Modified"), IDMEF_IMPACT_TYPE_OTHER },
                { MSG_KERN_IDT, N_("Kernel Modified"), IDMEF_IMPACT_TYPE_OTHER },
                { MSG_KERN_SYSCALL, N_("Kernel Modified"), IDMEF_IMPACT_TYPE_OTHER },
#endif

#ifdef SH_USE_PORTCHECK
		{ MSG_PORT_MISS, N_("Service closed"), IDMEF_IMPACT_TYPE_OTHER },
		{ MSG_PORT_NEW, N_("Service opened"), IDMEF_IMPACT_TYPE_OTHER },
		{ MSG_PORT_RESTART, N_("Service restarted"), IDMEF_IMPACT_TYPE_OTHER },
		{ MSG_PORT_NEWPORT, N_("Service restarted"), IDMEF_IMPACT_TYPE_OTHER },
#endif

#ifdef SH_USE_SUIDCHK
                { MSG_SUID_POLICY, N_("SUID/SGID File Detected"), IDMEF_IMPACT_TYPE_FILE },
#endif
		/* 
		 * This must be the last table entry
		 */
		{ 0, NULL,  IDMEF_IMPACT_TYPE_OTHER }, 
        };
        
        for ( i = 0; tbl[i].name != NULL; i++ ) {
                if ( tbl[i].msgid != msgid )
                        continue;

                idmef_impact_set_type(impact, tbl[i].type);
                return prelude_string_cat(out, _(tbl[i].name));
        }
                
        /* some other message
         */
        ptr = get_value(msg, _("msg"), NULL);
        if ( ! ptr ) {
                sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
                                _("could not format Samhain message"), _("map_policy_to_class"));
                return -1;
        }

#if defined(SH_WITH_SERVER)
        /* when using yule, theres a msg=<... msg=<...> >*/
	while ( (msg = get_value(ptr, _("msg"), NULL)) ) {
	        free(ptr);
		ptr = msg;
	}
#endif        

        ret = prelude_string_cat(out, ptr);
        free(ptr);
        
        return ret;
}


#ifdef SH_USE_PORTCHECK
static int get_service_info(char *msg, idmef_alert_t *alert)
{
        int ret;
	long port;
	char *ptr, *new, *tmp, *ip, *srv, *protocol, *end;
        prelude_string_t *str;
        idmef_address_t *address;
        idmef_node_t *node;
	idmef_user_t *user;
	idmef_process_t *process;
        idmef_service_t *service;
        idmef_source_t *source = idmef_alert_get_next_source(alert, NULL);
        struct passwd *pw;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
	struct passwd pwd;
	char * buffer;
#endif

        new = sh_util_strdup(msg);
 
        ptr = strstr(new, _("port: "));
        if ( ! ptr ) {
                sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
                                _("malformed Samhain port check message"), _("get_service_info"));
		SH_FREE( new );
                return -1;
        }

        ptr += 6; /* skip 'port: ', position on first byte of interface */
        tmp = strchr(ptr, ':');
        if ( ! tmp ) {
                sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
                                _("malformed Samhain port check message (no port)"), _("get_service_info"));
		SH_FREE( new );
                return -1;
        }
	*tmp = '\0';

	/* Get interface 
	 */
	ip = strdup(ptr);
        if ( ip ) {
                if ( ! source ) {
                        ret = idmef_alert_new_source(alert, &source, IDMEF_LIST_APPEND);
                        if ( ret < 0 ) {
                                free(ip);
				SH_FREE( new );
                                return ret;
                        }
                }

                ret = idmef_source_new_node(source, &node);
                if ( ret < 0 ) {
                        free(ip);
			SH_FREE( new );
                        return ret;
                }
                
                ret = idmef_node_new_address(node, &address, IDMEF_LIST_APPEND);
                if ( ret < 0 ) {
                        free(ip);
			SH_FREE( new );
                        return ret;
                }
                
                ret = idmef_address_new_address(address, &str);
                if ( ret < 0 ) {
                        free(ip);
			SH_FREE( new );
                        return ret;
                }
                
                prelude_string_set_nodup(str, ip);
        }

	ptr = tmp;
	++ptr;
        tmp = strchr(ptr, '/');
        if ( ! tmp ) {
                sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
                                _("malformed Samhain port check message (no protocol)"), _("get_service_info"));
		SH_FREE( new );
                return -1;
        }
	*tmp = '\0';

	/* Get port number
	 */
	port = strtol(ptr, &end, 0);
        if ( *ptr && *end == '\0' && port >= 0 && port < 65536) {

	        char * tmpw;

                if ( ! source ) {
                        ret = idmef_alert_new_source(alert, &source, IDMEF_LIST_APPEND);
                        if ( ret < 0 ) {
				SH_FREE( new );
                                return ret;
                        }
                }

                ret = idmef_source_new_service(source, &service);
                if ( ret < 0 ) {
			SH_FREE( new );
                        return ret;
                }

		idmef_service_set_port(service, port);

                ret = idmef_service_new_protocol(service, &str);
                if ( ret < 0 ) {
			SH_FREE( new );
                        return ret;
                }
                
		++tmp; 
		if (*tmp) { 
		        char * tmpw = tmp;
			char tmpw_store;
			while (*tmpw && !isblank((int) *tmpw)) ++tmpw;
			tmpw_store = *tmpw; *tmpw = '\0';
		        protocol = strdup(tmp);
			*tmpw = tmpw_store;
			prelude_string_set_nodup(str, protocol);
		}

	}

	ptr = tmp;
	++ptr;
        ptr = strchr(ptr, '(');
        if ( ! ptr ) {
                sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
                                _("malformed Samhain port check message (no service)"), _("get_service_info"));
		SH_FREE( new );
                return -1;
        }
	++ptr;
        tmp = strchr(ptr, ')');
        if ( ! tmp ) {
                sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
                                _("malformed Samhain port check message (service not closed)"), _("get_service_info"));
		SH_FREE( new );
                return -1;
        }
	*tmp = '\0';

	/* Get service
	 */
	srv = strdup(ptr);
        if ( srv ) {
                if ( ! source ) {
                        ret = idmef_alert_new_source(alert, &source, IDMEF_LIST_APPEND);
                        if ( ret < 0 ) {
                                free(srv);
				SH_FREE( new );
                                return ret;
                        }
                }

		if ( ! service ) {
                        ret = idmef_source_new_service(source, &service);
			if ( ret < 0 ) {
                                free(srv);
				SH_FREE( new );
				return ret;
			}
                }

                ret = idmef_service_new_name(service, &str);
                if ( ret < 0 ) {
                        free(srv);
			SH_FREE( new );
                        return ret;
                }
                
                prelude_string_set_nodup(str, srv);
        }

	SH_FREE( new );

        ptr = get_value(msg, _("userid"), NULL);

        if ( ptr ) {

	        idmef_user_id_t * user_id;

	        ret = idmef_source_new_user(source, &user);
                if ( ret < 0 ) {
                        free(ptr);
                        return ret;
                }

                idmef_user_set_category(user, IDMEF_USER_CATEGORY_APPLICATION);
                
                ret = idmef_user_new_user_id(user, &user_id, IDMEF_LIST_APPEND);
                if ( ret < 0 ) {
                        free(ptr);
                        return ret;
                }
                
                idmef_user_id_set_type(user_id, IDMEF_USER_ID_TYPE_CURRENT_USER);

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
		buffer = SH_ALLOC(SH_PWBUF_SIZE);
		sh_getpwnam_r(ptr, &pwd, buffer, SH_PWBUF_SIZE, &pw);
#else
		pw = sh_getpwnam(ptr);
#endif
                if ( pw )
                        idmef_user_id_set_number(user_id, pw->pw_uid);

                ret = idmef_user_id_new_name(user_id, &str);
                if ( ret < 0 ) {
                        free(ptr);
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
			SH_FREE(buffer);
#endif
                        return ret;
                }
                prelude_string_set_nodup(str, ptr);

#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
		SH_FREE(buffer);
#endif
	}


        ptr = get_value(msg, _("path"), NULL);
        tmp = get_value(msg, _("pid"), NULL);

        if ( ptr ) {

                /*
                 * In term of IDMEF, this is the full path,
                 * including the name.
                 */
                ret = idmef_source_new_process(source, &process);
                if ( ret < 0 ) {
		        free(ptr);
                        return ret;
		}

		ret = idmef_process_new_path(process, &str);
                if ( ret < 0 ) {
		        free(ptr);
                        return ret;
		}
                prelude_string_set_nodup(str, ptr);

                
                if ( NULL != strrchr(ptr, '/') ) {
                        ret = idmef_process_new_name(process, &str);
                        if ( ret == 0 ) {
			        ptr = strrchr(ptr, '/');
			        prelude_string_set_dup(str, ptr + 1);
			}
                } else {
		        ret = idmef_process_new_name(process, &str);
                        if ( ret == 0 ) {
			        prelude_string_set_dup(str, ptr);
			}
		}

		idmef_process_set_pid(process, strtoul(tmp, NULL, 0));
        }

	if (tmp)
	  free(tmp);

	return 0;
}
#endif

static int get_login_info(char *msg, idmef_alert_t *alert)
{
        int ret;
        char *ptr, *ip;
        idmef_user_t *user;
        idmef_node_t *node;
        struct passwd *pw;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
	struct passwd pwd;
	char * buffer;
#endif
        prelude_string_t *str;
        idmef_user_id_t *user_id;
        idmef_address_t *address;
        idmef_target_t *target = idmef_alert_get_next_target(alert, NULL);
        idmef_source_t *source = idmef_alert_get_next_source(alert, NULL);
          
        ip = ptr = get_value(msg, _("ip"), NULL);
        if ( ptr ) {
                if ( ! source ) {
                        ret = idmef_alert_new_source(alert, &source, IDMEF_LIST_APPEND);
                        if ( ret < 0 ) {
                                free(ptr);
                                return ret;
                        }
                }

                ret = idmef_source_new_node(source, &node);
                if ( ret < 0 ) {
                        free(ptr);
                        return ret;
                }
                
                ret = idmef_node_new_address(node, &address, IDMEF_LIST_APPEND);
                if ( ret < 0 ) {
                        free(ptr);
                        return ret;
                }
                
                ret = idmef_address_new_address(address, &str);
                if ( ret < 0 ) {
                        free(ptr);
                        return ret;
                }
                
                prelude_string_set_nodup(str, ptr);
        }

        ptr = get_value(msg, _("host"), NULL);
        if ( ptr ) {
                if ( ip && strcmp(ptr, ip) == 0 )
                        free(ptr);
                else {
                        if ( ! source ) {
                                ret = idmef_alert_new_source(alert, &source, IDMEF_LIST_APPEND);
                                if ( ret < 0 ) {
                                        free(ptr);
                                        return ret;
                                }
                        }

                        ret = idmef_source_new_node(source, &node);
                        if ( ret < 0 ) {
                                free(ptr);
                                return ret;
                        }
                
                        ret = idmef_node_new_name(node, &str);
                        if ( ret < 0 ) {
                                free(ptr);
                                return ret;
                        }
                
                        prelude_string_set_nodup(str, ptr);
                }
        }
        
        ptr = get_value(msg, _("name"), NULL);
        if ( ptr ) {
                ret = idmef_target_new_user(target, &user);
                if ( ret < 0 ) {
                        free(ptr);
                        return ret;
                }
                
                idmef_user_set_category(user, IDMEF_USER_CATEGORY_OS_DEVICE);
                
                ret = idmef_user_new_user_id(user, &user_id, IDMEF_LIST_APPEND);
                if ( ret < 0 ) {
                        free(ptr);
                        return ret;
                }
                
                idmef_user_id_set_type(user_id, IDMEF_USER_ID_TYPE_TARGET_USER);
                
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
		buffer = SH_ALLOC(SH_PWBUF_SIZE);
		sh_getpwnam_r(ptr, &pwd, buffer, SH_PWBUF_SIZE, &pw);
#else
		pw = sh_getpwnam(ptr);
#endif
                if ( pw )
                        idmef_user_id_set_number(user_id, pw->pw_uid);

                ret = idmef_user_id_new_name(user_id, &str);
                if ( ret < 0 ) {
                        free(ptr);
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
			SH_FREE(buffer);
#endif
                        return ret;
                }
                prelude_string_set_nodup(str, ptr);

                ptr = get_value(msg, _("tty"), NULL);
                if ( ptr ) {
                        ret = idmef_user_id_new_tty(user_id, &str);
                        if ( ret < 0 ) {
                                free(ptr);
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
				SH_FREE(buffer);
#endif
                                return ret;
                        }
                        
                        prelude_string_set_nodup(str, ptr);
                }
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
		SH_FREE(buffer);
#endif
        }

        ptr = get_time_value(msg, _("time"), NULL);
        if ( ptr ) {
                idmef_time_t *time;
                
                ret = idmef_time_from_samhain(&time, ptr);
                free(ptr);
                
                if ( ret < 0 )
                        return ret;

                idmef_alert_set_detect_time(alert, time);
        }

        return 0;
}

#if defined(SH_WITH_SERVER)
static int node_set_address(idmef_node_t *node, const char *addr)
{
        int ret;
	prelude_string_t *prelude_str;
	idmef_address_t *idmef_addr;

	ret = prelude_string_new(&prelude_str);
	if ( ret < 0 ) 
                goto err;
      
	ret = prelude_string_set_ref(prelude_str, addr);
	if ( ret < 0 ) 
                goto err;

	ret = idmef_address_new(&idmef_addr);
	if ( ret < 0 ) 
                goto err;
      
	idmef_address_set_category(idmef_addr, IDMEF_ADDRESS_CATEGORY_IPV4_ADDR);
	idmef_address_set_address(idmef_addr, prelude_str);
	idmef_node_set_address(node, idmef_addr, 0);

	return 0;
 err:
        return -1;
}
#endif
                                          

static int samhain_alert_prelude(int priority, int sh_class, 
				 char *message, unsigned long msgid, 
				 char * inet_peer_ip)
{
        int ret;
        idmef_time_t *time;
        idmef_alert_t *alert;
        idmef_message_t *idmef;
        idmef_classification_t *classification;
        idmef_assessment_t *assessment;
        idmef_additional_data_t *data;
        idmef_impact_t *impact;
        idmef_target_t *target;
        idmef_confidence_t *confidence;
        prelude_string_t *str;
#if defined(SH_WITH_SERVER)
        idmef_node_t *node;
#else
	(void) inet_peer_ip;
#endif
                
        if ( !client || sh_class == STAMP)
                return 0;
        
        ret = idmef_message_new(&idmef);
        if ( ret < 0 )
                goto err;
        
        ret = idmef_message_new_alert(idmef, &alert);
        if ( ret < 0 )
                goto err;

        idmef_alert_set_analyzer(alert, idmef_analyzer_ref(prelude_client_get_analyzer(client)), IDMEF_LIST_PREPEND);
        
        ret = idmef_time_new_from_gettimeofday(&time);
        if ( ret < 0 )
                goto err;
        idmef_alert_set_detect_time(alert, time);
        
        ret = idmef_time_new_from_gettimeofday(&time);
        if ( ret < 0 )
                goto err;
        idmef_alert_set_create_time(alert, time);
        
        ret = idmef_alert_new_classification(alert, &classification);
        if ( ret < 0 )
                goto err;
        
        ret = idmef_alert_new_target(alert, &target, IDMEF_LIST_APPEND);
        if ( ret < 0 )
                goto err;

        idmef_target_set_decoy(target, IDMEF_TARGET_DECOY_NO);

#if defined(SH_WITH_SERVER)
        if ( inet_peer_ip != NULL){
                ret = idmef_target_new_node(target, &node);
		if ( ret < 0 )
                          goto err;
        
		ret = node_set_address(node, inet_peer_ip); 
		if ( ret < 0 )
                          goto err;
                          
		idmef_target_set_node(target, idmef_node_ref(node));
        }
        else
#endif        
        if ( idmef_analyzer_get_node(prelude_client_get_analyzer(client)) ) {
                idmef_node_ref(idmef_analyzer_get_node(prelude_client_get_analyzer(client)));
                idmef_target_set_node(target, idmef_analyzer_get_node(prelude_client_get_analyzer(client)));
        }

        if ( strstr(message, _("path=")) ) {
#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
                if ( msgid != MSG_FI_ADD && msgid != MSG_FI_ADD2 )
                        get_file_infos(target, message, IDMEF_FILE_CATEGORY_ORIGINAL);
#endif
                
                get_file_infos(target, message, IDMEF_FILE_CATEGORY_CURRENT);
        }
        
        ret = idmef_alert_new_assessment(alert, &assessment);
        if ( ret < 0 )
                goto err;
        
        ret = idmef_assessment_new_impact(assessment, &impact);
        if ( ret < 0 )
                goto err;

        ret = idmef_classification_new_text(classification, &str);
        if ( ret < 0 )
                goto err;

        ret = get_login_info(message, alert);
        if ( ret < 0 )
                goto err;
        
#ifdef SH_USE_PORTCHECK
	if (msgid == MSG_PORT_MISS || msgid == MSG_PORT_NEW || msgid == MSG_PORT_RESTART || msgid == MSG_PORT_NEWPORT) {
	        ret = get_service_info(message, alert);
		if ( ret < 0 )
		        goto err;
        }
#endif
   
        map_policy_to_class(message, msgid, impact, str);

#if 0
        if ( priority == SH_ERR_SEVERE || priority == SH_ERR_FATAL )
                idmef_impact_set_severity(impact, IDMEF_IMPACT_SEVERITY_HIGH);
        
        else if ( priority == SH_ERR_ALL || priority == SH_ERR_INFO || priority == SH_ERR_NOTICE )
                idmef_impact_set_severity(impact, IDMEF_IMPACT_SEVERITY_LOW);

        else
                idmef_impact_set_severity(impact, IDMEF_IMPACT_SEVERITY_MEDIUM);
#endif
	idmef_impact_set_severity(impact, map_severity(priority));
        
        idmef_impact_set_completion(impact, IDMEF_IMPACT_COMPLETION_SUCCEEDED);
                
        ret = idmef_assessment_new_confidence(assessment, &confidence);
        if ( ret < 0 )
                goto err;

        idmef_confidence_set_rating(confidence, IDMEF_CONFIDENCE_RATING_HIGH);
        
        ret = idmef_alert_new_additional_data(alert, &data, IDMEF_LIST_APPEND);
        if ( ret < 0 )
                goto err;

        ret = idmef_additional_data_new_meaning(data, &str);
        if ( ret < 0 )
                goto err;

        prelude_string_set_dup(str, _("Message generated by Samhain"));
        idmef_additional_data_set_type(data, IDMEF_ADDITIONAL_DATA_TYPE_STRING);
        idmef_additional_data_set_string_ref(data, message);
        
        /* debug_print_message(idmef); */
        
        prelude_client_send_idmef(client, idmef);
        idmef_message_destroy(idmef);
        
        return 0;
        
 err:
        idmef_message_destroy(idmef);
        return -1;
}


int sh_prelude_alert(int priority, int sh_class, char *message, long msgflags, unsigned long msgid, char *inet_peer_ip)
{
        int ret;
        
	(void) msgflags; /* fix compiler warning */

        if ( initialized < 1 )
                return -1;
        
        ret = samhain_alert_prelude(priority, sh_class, message, msgid, inet_peer_ip);
        if ( ret < 0 ) {
                sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
                                _("Problem with IDMEF for prelude-ids support: alert lost"), 
                                _("sh_prelude_alert"));
        }

        return ret;
}



int sh_prelude_set_profile(const char *arg)
{
        if ( profile ) {
                free(profile);
                profile = NULL;
	}
        
        if ( arg ) {
                profile = strdup(arg);
                if ( ! profile )
                        return -1;
        }
        
        return 0;
}

/* Allow initialization of prelude; to be called
 * after forking the daemon. Delays heartbeat
 * start after config read until it is safe.
 */
void sh_prelude_reset(void)
{
        extern void sh_error_init_prelude();

        ready_for_init = 1;
	sh_error_init_prelude();
        return;
}



void sh_prelude_stop(void)
{
        if (initialized < 1)
                return;

	if (sh.flag.isdaemon == S_TRUE)
	        prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_FAILURE);
	else
	        prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);

	client = NULL;

	prelude_deinit();

        initialized = 0;
        return;
}



int sh_prelude_init(void)
{
        int ret;
        prelude_string_t *str;
        idmef_analyzer_t *analyzer;
        prelude_client_flags_t flags;
#ifdef SH_NOFAILOVER
	prelude_connection_pool_t *pool;
	prelude_connection_pool_flags_t conn_flags;
#endif

	if (ready_for_init == 0)
	  return initialized;

	if (initialized > 0)
	  return initialized;

	prelude_thread_init(NULL);
        prelude_init(&sh_argc_store, sh_argv_store);

        ret = prelude_client_new(&client, profile ? profile : _("samhain"));
        if ( ret < 0 ) {
                sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
                                _("Failed to initialize Prelude"), _("sh_prelude_init"));
		initialized = -1;
                return -1;
        }

        /*
         * Enable automatic heartbeat sending.
         */
        flags = prelude_client_get_flags(client);
        ret = prelude_client_set_flags(client, flags | PRELUDE_CLIENT_FLAGS_ASYNC_TIMER);
        
        analyzer = prelude_client_get_analyzer(client);

        ret = idmef_analyzer_new_model(analyzer, &str);
        prelude_string_set_dup(str, IDMEF_ANALYZER_MODEL);

        ret = idmef_analyzer_new_class(analyzer, &str);
        prelude_string_set_dup(str, IDMEF_ANALYZER_CLASS);
        
	ret = idmef_analyzer_new_version(analyzer, &str);
        prelude_string_set_dup(str, IDMEF_ANALYZER_VERSION);
        
#ifdef SH_NOFAILOVER
	pool = prelude_client_get_connection_pool(client);
	conn_flags = prelude_connection_pool_get_flags(pool);

	conn_flags &= ~PRELUDE_CONNECTION_POOL_FLAGS_FAILOVER;
	prelude_connection_pool_set_flags(pool, conn_flags);
#endif

        ret = prelude_client_start(client);
        if ( ret < 0 ) {
                prelude_perror(ret, _("error starting prelude client"));

                if ( prelude_client_is_setup_needed(ret) )
                        prelude_client_print_setup_error(client);
                
                sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
                                _("Failed to start Prelude"), _("sh_prelude_init"));
		initialized = -1;
                return -1;
        }
                        
	initialized = 1;
        return 1;
}

/* HAVE_LIBPRELUDE_9 */
#endif

