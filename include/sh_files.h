/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999, 2000 Rainer Wichmann                                */
/*                                                                         */
/*  This program is free software; you can redistribute it                 */
/*  and/or modify                                                          */
/*  it under the terms of the GNU General Public License as                */
/*  published by                                                           */
/*  the Free Software Foundation; either version 2 of the License, or      */
/*  (at your option) any later version.                                    */
/*                                                                         */
/*  This program is distributed in the hope that it will be useful,        */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of         */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          */
/*  GNU General Public License for more details.                           */
/*                                                                         */
/*  You should have received a copy of the GNU General Public License      */
/*  along with this program; if not, write to the Free Software            */
/*  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.              */

#ifndef SH_FILES_H
#define SH_FILES_H

void sh_audit_mark (const char * file);
void sh_audit_commit ();
void sh_audit_delete_all ();
char * sh_audit_fetch (char * file, time_t mtime, time_t ctime, char * result, size_t rsize);

struct sh_dirent {
  char             * sh_d_name;
  struct sh_dirent * next;
};

/* Fix the check flags
 */
void sh_files_fixup_mask (int class, unsigned long * check_flags);

/* Dequote a filename in the config file
 */
char * sh_files_parse_input(const char * str_s, size_t * len);

/* Check whether a file is in the config 
 */
char * sh_files_findfile(const char * path);

/* Find the most specific directory in the config
 */
char * sh_files_find_mostspecific_dir(const char * path);

/* free a directory listing
 */
void kill_sh_dirlist (struct sh_dirent * dirlist);

#ifdef NEED_ADD_DIRENT
/* add an entry to a directory listing
 */
struct sh_dirent * addto_sh_dirlist (struct dirent * thisEntry, 
				     struct sh_dirent * dirlist);
#endif

/* register exceptions to hardlink check
 */
int sh_files_hle_reg (const char * str);

/* Check for new files/dirs matching configured glob patterns.
 */
void sh_files_check_globPatterns();

/* Check for new files (only) matching configured glob patterns.
 */
void sh_files_check_globFilePatterns();

/* check the setup
 */
int sh_files_test_setup (void);

/* check if allignore
 */
int sh_files_is_allignore (char * str);

/* activate hardlink check
 */
int sh_files_check_hardlinks (const char * opt);

/* check  rsrc fork (Mac OS X)
 */
int sh_files_use_rsrc(const char * str);

/* set recursion depth
 */
int sh_files_setrec (void);

/* report only once
 */
int sh_files_reportonce(const char * c);

/* report full details
 */
int sh_files_fulldetail(const char * c);

/* reset the 'checked' flag
 */
void sh_dirs_reset(void);

/* reset the 'checked' flag
 */
void sh_files_reset(void);

/* set maximum recursion level
 */
int sh_files_setrecursion (const char * flag_s);

/* select a directory stack 2=Two, else One (standard)
 */
int set_dirList (int which);

/* push a directory on the stack USER0
 */
int  sh_files_pushdir_user0 (const char * dirName);

/* push a directory on the stack USER1
 */
int  sh_files_pushdir_user1 (const char * dirName);

/* push a directory on the stack USER2
 */
int  sh_files_pushdir_user2 (const char * dirName);

/* push a directory on the stack USER3
 */
int  sh_files_pushdir_user3 (const char * dirName);

/* push a directory on the stack USER4
 */
int  sh_files_pushdir_user4 (const char * dirName);

/* push a directory on the stack PRELINK
 */
int  sh_files_pushdir_prelink (const char * dirName);

/* push a directory on the stack ATTR
 */
int  sh_files_pushdir_attr (const char * dirName);

/* push a directory on the stack READONLY
 */
int  sh_files_pushdir_ro (const char * dirName);

/* push a directory on the stack LOGFILE
 */
int  sh_files_pushdir_log (const char * dirName);

/* push a directory on the stack GROWING LOGFILE
 */
int  sh_files_pushdir_glog (const char * dirName);

/* push a directory on the stack IGNORE NONE
 */
int  sh_files_pushdir_noig (const char * dirName);

/* push a directory on the stack IGNORE ALL 
 */
int  sh_files_pushdir_allig (const char * dirName);


/* push a file on the stack USER0
 */
int  sh_files_pushfile_user0 (const char * dirName);

/* push a file on the stack USER1
 */
int  sh_files_pushfile_user1 (const char * dirName);

/* push a file on the stack USER2
 */
int  sh_files_pushfile_user2 (const char * dirName);

/* push a file on the stack USER3
 */
int  sh_files_pushfile_user3 (const char * dirName);

/* push a file on the stack USER4
 */
int  sh_files_pushfile_user4 (const char * dirName);

/* push a file on the stack PRELINK
 */
int  sh_files_pushfile_prelink (const char * dirName);

/* push a file on the stack ATTR
 */
int  sh_files_pushfile_attr (const char * dirName);

/* push a file on the stack READONLY
 */
int  sh_files_pushfile_ro (const char * dirName);

/* push a file on the stack LOGFILE
 */
int  sh_files_pushfile_log (const char * dirName);

/* push a file on the stack GROWING LOGFILE
 */
int  sh_files_pushfile_glog (const char * dirName);

/* push a file on the stack IGNORE NONE
 */
int  sh_files_pushfile_noig (const char * dirName);

/* push a file on the stack IGNORE ALL
 */
int  sh_files_pushfile_allig (const char * dirName);


/* check directories on the stack
 */
unsigned long sh_dirs_chk       (int which);

/* check files on the stack
 */
unsigned long sh_files_chk       (void);

int sh_files_delglobstack (void);

int sh_files_deldirstack (void);

int sh_files_delfilestack (void);

/* redefine policies
 */
int sh_files_redef_user0(const char * str);
int sh_files_redef_user1(const char * str);
int sh_files_redef_user2(const char * str);
int sh_files_redef_user3(const char * str);
int sh_files_redef_user4(const char * str);
int sh_files_redef_prelink(const char * str);
int sh_files_redef_readonly(const char * str);
int sh_files_redef_loggrow(const char * str);
int sh_files_redef_logfiles(const char * str);
int sh_files_redef_attributes(const char * str);
int sh_files_redef_noignore(const char * str);
int sh_files_redef_allignore(const char * str);

ShFileType sh_files_filecheck (int class, unsigned long check_flags,
			       const char * dirName, 
			       const char * infileName,
			       int * reported, 
			       int rsrcflag);

int sh_files_checkdir (int iclass, unsigned long check_flags, 
		       int idepth, char * iname, 
		       char * relativeName);

int sh_files_search_file(char * name, int * class, 
			 unsigned long *check_flags, int * reported);
int sh_files_search_dir(char * name, int * class, 
			unsigned long *check_flags, int *reported,
			int * rdepth);
void sh_files_set_file_reported(const char * name);
void sh_files_clear_file_reported(const char * name);

#endif




