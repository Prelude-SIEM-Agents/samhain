/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2015 Rainer Wichmann                                      */
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


#ifndef SH_DBIO_H
#define SH_DBIO_H



/* Read one line, trim newline. Return char count, or -1 on error or eof.
 */
int sh_dbIO_getline (FILE * fd, char * line, const size_t sizeofline);

/* Read given database file for listing
 */
int sh_dbIO_list_db (const char * db_file);

/* Write single record to database
 */
void sh_dbIO_data_write (file_type * buf, char * fileHash);

/* Write whole default database
 */
int sh_dbIO_writeout_update ();

/* write database to given path
 */
int sh_dbIO_writeout_to_path(const char * path);

/* write database to stdout
 */
int sh_dbIO_writeout_stdout (const char * str);

/* version string for database
 */
int sh_dbIO_version_string(const char * str);

/* Load a delta database
 */
int sh_dbIO_load_delta();

int sh_dbIO_list_binary (const char * c);
int sh_dbIO_list_filter (const char * c);

#endif
