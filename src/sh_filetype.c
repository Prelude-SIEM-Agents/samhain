/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2011 Rainer Wichmann                                      */
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

#include "config_xor.h"

#ifndef NULL
#if !defined(__cplusplus)
#define NULL ((void*)0)
#else
#define NULL (0)
#endif
#endif

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)

#include "samhain.h"
#include "sh_mem.h"
#include "sh_error_min.h"
#include "sh_utils.h"

#define FIL__ _("sh_filetype.c")

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* #define SH_FILE_MAIN 1 */
#ifdef  SH_FILE_MAIN
#include <stdio.h>
#define _(a) a
#define N_(a) a
#define sl_strlcpy strncpy
#endif

#define SH_FTYPE_MAX 32

/* List of filetype description, in the format: 
 * offset : type(0=text, 1=binary) : length(if binary) : G1 : G2 : G3 : Name : Teststring
 *
 * This list is mostly taken from the 'filetype' library by Paul L Daniels.
 *
 * Copyright (c) 2003, PLD
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or 
 * without modification, are permitted provided that the 
 * following conditions are met:
 * 
 *  * Redistributions of source code must retain the above 
 *  copyright notice, this list of conditions and the following 
 *  disclaimer.
 *  
 *  * Redistributions in binary form must reproduce the above 
 *  copyright notice, this list of conditions and the following 
 *  disclaimer in the documentation and/or other materials provided 
 *  with the distribution.
 *  
 *  * Neither the name of the PLD nor the names of its contributors 
 *  may be used to endorse or promote products derived from this software 
 *  without specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 *  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *  COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN 
 *  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 */


char * sh_ftype_list[] = {

  N_("6:0:0:IMAGE:COMPRESSED:JPG:JFIF Jpeg:JFIF"),
  N_("0:0:0:IMAGE:COMPRESSED:PNG:PNG:=89PNG=0d=0a=1a=0a"),
  N_("0:0:0:IMAGE:COMPRESSED:JPG:JFIF Jpeg:=FF=D8=FF"),
  N_("0:0:0:IMAGE:COMPRESSED:GIF:GIF:GIF97a"),
  N_("0:0:0:IMAGE:COMPRESSED:GIF:GIF:GIF89a"),
  N_("0:0:0:IMAGE:COMPRESSED:GIF:GIF:GIF87a"),
  N_("0:1:4:IMAGE:COMPRESSED:TIFF:TIFF-LE:II=2A=00"),
  N_("0:1:4:IMAGE:COMPRESSED:TIFF:TIFF-BE:MM=00=2A"),
  N_("0:1:2:IMAGE:COMPRESSED:PCX:PCX25:=0A=00"),
  N_("0:1:2:IMAGE:COMPRESSED:PCX:PCX28WP:=0A=02"),
  N_("0:1:2:IMAGE:COMPRESSED:PCX:PCX28NP:=0A=03"),
  N_("0:1:2:IMAGE:COMPRESSED:PCX:PCX30:=0A=05"),
  N_("0:0:0:IMAGE:RAW:BMP:Bitmap:BM"),
  N_("0:0:0:IMAGE:RAW:XPM:XPM:/* XPM */"),
  N_("0:0:0:IMAGE:SPECIAL:AUTOCAD:DWT:AC=31=30=31"),
  N_("0:0:0:IMAGE:SPECIAL:AUTOCAD:DWF:(DWF V"),
  N_("0:0:0:IMAGE:SPECIAL:AUTOCAD:WMF:=D7=CD=C6=9A"),
  N_("0:0:0:IMAGE:SPECIAL:AUTOCAD:DWG:AC10"),
  N_("8:0:0:IMAGE:SPECIAL:COREL:CorelDraw:CDR"),
  N_("0:0:0:IMAGE:SPECIAL:FITS:Fits file:SIMPLE=20=20="),
  N_("1536:0:0:IMAGE:SPECIAL:VISIO:VisioDraw:Visio"),
  N_("128:0:0:IMAGE:SPECIAL:DICM:DICOM medical:DICM"),
  N_("0:0:0:IMAGE:SPECIAL:PHS:Photoshop:8BPS"),
  N_("0:0:0:IMAGE:SPECIAL:XCF:Gimp XCF:gimp xcf"),
  N_("0:0:0:MOVIE:COMPRESSED:RIFF:RIFF/AVI Movie:RIFF"),
  N_("0:0:0:MOVIE:RAW:MOV:SGI Movie:MOVI:.mov SGI Movie"),
  N_("0:1:4:MOVIE:COMPRESSED:MPG:Mpeg 2:=00=00=01=BA"),
  N_("0:1:4:MOVIE:COMPRESSED:MPG:Mpeg 2:=00=00=01=B3"),
  N_("4:0:0:MOVIE:COMPRESSED:QT:QuickTime:moov"),
  N_("4:0:0:MOVIE:COMPRESSED:QT:QuickTime:mdat"),
  N_("36:0:0:MOVIE:COMPRESSED:QT:QuickTime:moov"),
  N_("36:0:0:MOVIE:COMPRESSED:QT:QuickTime:mdat"),
  N_("68:0:0:MOVIE:COMPRESSED:QT:QuickTime:moov"),
  N_("68:0:0:MOVIE:COMPRESSED:QT:QuickTime:mdat"),
  N_("0:1:3:MOVIE:COMPRESSED:FLI:FLIC animation:=00=11=AF"),
  N_("0:0:0:MOVIE:COMPRESSED:FLASH:Flash data:FWS"),
  N_("0:0:0:MOVIE:COMPRESSED:FLASH:Flash data:CWS"),
  N_("0:0:0:MOVIE:COMPRESSED:FLASH:Flash video:FLV"),
  N_("0:0:0:MOVIE:COMPRESSED:WMV:WMV:=30=26=B2=75=8E=66=CF"),
  N_("0:0:0:AUDIO:RAW:SND:Sun Audio:.snd"),
  N_("0:0:0:AUDIO:RAW:EMOD:EMOD:Mod"),
  N_("1080:0:0:AUDIO:RAW:MOD:SoundTracker (.M.K):.M.K"),
  N_("1080:0:0:AUDIO:RAW:MOD:SoundTracker (M.K.):M.K."),
  N_("1080:0:0:AUDIO:RAW:MOD:NoiseTracker:N.T."),
  N_("1080:0:0:AUDIO:RAW:MOD:SoundTracker (M!K!):M!K!"),
  N_("1080:0:0:AUDIO:RAW:MOD:SoundTracker (M&K!):M&K!"),
  N_("8:0:0:AUDIO:RAW:WAVE:Wave:WAVE"),
  N_("0:1:4:AUDIO:RAW:DEC:DEC-Audio:=00=64=73=2E"),
  N_("0:0:0:AUDIO:STANDARD:MIDI:Midi:MThd"),
  N_("0:0:0:AUDIO:COMPRESSED:REAL:RealMedia:.RMF"),
  N_("0:0:0:AUDIO:COMPRESSED:OGG:Ogg Vorbis:OggS"),
  N_("0:0:0:AUDIO:COMPRESSED:FLAC:Flac:fLaC"),
  N_("0:1:5:AUDIO:COMPRESSED:MP3:MP3 Audio:=49=44=33=02=00"),
  N_("0:1:5:AUDIO:COMPRESSED:MP3:MP3 Audio:=49=44=33=03=00"),
  N_("0:1:5:AUDIO:COMPRESSED:MP3:MP3 Audio:=49=44=33=04=00"),
  N_("0:1:2:AUDIO:COMPRESSED:MP3:MP3 Audio:=ff=fb"),
  N_("0:1:2:AUDIO:COMPRESSED:MP3:MP3 Audio:=ff=fa"),
  N_("2:0:0:ARCHIVE:COMPRESSED:LHA:Lha 0:-lh0-"),
  N_("2:0:0:ARCHIVE:COMPRESSED:LHA:Lha 1:-lh1-"),
  N_("2:0:0:ARCHIVE:COMPRESSED:LHA:Lha 4:-lz4-"),
  N_("2:0:0:ARCHIVE:COMPRESSED:LHA:Lha z5:-lz5-"),
  N_("2:0:0:ARCHIVE:COMPRESSED:LHA:Lha 5:-lh5-"),
  N_("0:0:0:ARCHIVE:COMPRESSED:RAR:RarArchive:Rar!"),
  N_("0:0:0:ARCHIVE:COMPRESSED:ZIP:PkZip:PK=03=04"),
  N_("0:0:0:ARCHIVE:COMPRESSED:7Z:7-Zip:=37=7A=BC=AF=27=1C"),
  N_("0:0:0:ARCHIVE:COMPRESSED:COMPRESS:Compress:=1F=89"),
  N_("0:0:0:ARCHIVE:COMPRESSED:GZIP:Gzip:=1F=8B"),
  N_("0:0:0:ARCHIVE:COMPRESSED:BZIP2:Bzip2:BZh"),
  N_("0:0:0:ARCHIVE:COMPRESSED:ARJ:ARJ:=60=ea"),
  N_("0:0:0:ARCHIVE:COMPRESSED:ARJ:ARJ:=ea=60"),
  N_("0:0:0:ARCHIVE:COMPRESSED:HPAK:HPack:HPAK"),
  N_("0:0:0:ARCHIVE:COMPRESSED:JAM:Jam:=E9,=01JAM"),
  N_("0:0:0:ARCHIVE:COMPRESSED:SQUISH:Squish:SQSH"),
  N_("0:1:8:ARCHIVE:COMPRESSED:CAB:MS Cabinet:MSCF=00=00=00=00"),
  N_("20:0:0:ARCHIVE:COMPRESSED:ZOO:Zoo:=FD=C4=A7=DC"),
  N_("0:0:0:ARCHIVE:COMPRESSED:XPK:Amiga XPK Archive:XPKF"),
  N_("0:0:0:ARCHIVE:PACKAGE:RPM:RPM:=ED=AB=EE=DB"),
  N_("0:0:0:ARCHIVE:PACKAGE:DEB:DEB:!<arch>=0A""debian"),
  N_("0:0:0:ARCHIVE:UNIX:AR:AR:!<arch>"),
  N_("0:0:0:ARCHIVE:UNIX:AR:AR:<ar>"),
  N_("257:1:8:ARCHIVE:UNIX:TAR:TAR:ustar=20=20=00"),
  N_("257:1:6:ARCHIVE:UNIX:TAR:TAR:ustar=00"),
  N_("0:0:0:LIBRARY:JAVA:CLASS:Java:=CA=FE=BA=BE"),
  N_("2108:0:0:DOCUMENT:OFFICE:WORD:Word v5:MSWordDoc"),
  N_("2112:0:0:DOCUMENT:OFFICE:WORD:Word v5:MSWordDoc"),
  N_("2080:0:0:DOCUMENT:OFFICE:EXCEL:Excel v4:Microsoft Excel"),
  N_("2080:0:0:DOCUMENT:OFFICE:WORD:MS Word:Microsoft Word"),
  N_("0:0:0:DOCUMENT:OFFICE:WORD:Word:=94=A6=2E"),
  N_("512:1:19:DOCUMENT:OFFICE:WORD:Word:R=00o=00o=00t=00 =00""E=00n=00t=00r=00y"),
  N_("0:1:9:DOCUMENT:OFFICE:ALL:MSOffice:=D0=CF=11=E0=A1=B1=1A=E1=00"),
  N_("0:0:0:DOCUMENT:ADOBE:PDF:PortableDocument:%PDF-"),
  N_("0:0:0:DOCUMENT:ADOBE:EPS:EncapsulatedPS:%!PS-ADOBE EPS"),
  N_("0:0:0:DOCUMENT:STANDARD:RTF:RichText:{\\rtf"),
  N_("6:1:4:DOCUMENT:STANDARD:RTF:RichText Compressed:=00=00LZ"),
  N_("6:0:0:DOCUMENT:ID:VCARD:VCARD:vcard"),
  N_("0:0:0:EXECUTABLE:DOS:EXE:DosExe:MZ"),
  N_("0:0:0:EXECUTABLE:DOS:EXE:DosExe:LZ"),
  N_("0:0:0:EXECUTABLE:DOS:COM:DosCom 1:=E9"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Bourne:#!/bin/sh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Bourne:#! /bin/sh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Bourne:#!/bin/bash"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Bourne:#! /bin/bash"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Bourne:#!/usr/bin/bash"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Bourne:#! /usr/bin/bash"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Csh:#!/usr/bin/csh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Csh:#! /usr/bin/csh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Csh:#!/bin/csh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Csh:#! /bin/csh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Korn:#! /usr/bin/ksh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Korn:#!/usr/bin/ksh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Korn:#! /bin/ksh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Korn:#!/bin/ksh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Tenex:#!/usr/bin/tcsh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Tenex:#! /usr/bin/tcsh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Tenex:#!/bin/tcsh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Tenex:#! /bin/tcsh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Zsh:#!/usr/bin/zsh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Zsh:#! /usr/bin/zsh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Zsh:#!/bin/zsh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Zsh:#! /bin/zsh"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:ash:#!/usr/bin/ash"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:ash:#! /usr/bin/ash"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:ash:#!/bin/ash"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:ash:#! /bin/ash"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:awk:#!/usr/bin/nawk"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:awk:#! /usr/bin/nawk"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:awk:#!/bin/nawk"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:awk:#! /bin/nawk"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:awk:#!/bin/gawk"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:awk:#! /bin/gawk"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:awk:#!/bin/awk"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:awk:#! /bin/awk"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:perl:#!/usr/bin/perl"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:perl:#! /usr/bin/perl"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:perl:#!/bin/perl"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:perl:#! /bin/perl"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Shell script:#!/"),
  N_("0:0:0:EXECUTABLE:UNIX:SHELL:Shell script:#! /"),
  N_("0:0:0:EXECUTABLE:UNIX:ELF:Linux ELF32:=7f""ELF=01"),
  N_("0:0:0:EXECUTABLE:UNIX:ELF:Linux ELF:=7f""ELF=02"),
  N_("0:0:0:EXECUTABLE:DOS:COM:DosCom 2:=8c"),
  N_("0:0:0:EXECUTABLE:DOS:COM:DosCom 3:=eb"),
  N_("0:0:0:EXECUTABLE:DOS:COM:DosCom 4:=b8"),
  N_("0:1:4:EXECUTABLE:AMIGAOS:EXECUTABLE:AmigaOS Executable:=00=00=03=F3"),
  N_("0:1:20:DATABASE:ANY:ACCESS:MSAccess:=00=01=00=00Standard=20Jet=20""DB=00"),
  N_("0:1:2:DATABASE:ANY:MYSQL:MySQL database:=fe=01"),
  N_("0:1:4:DATABASE:ANY:MYSQL:MySQL database:=fe=fe=03=00"),
  N_("0:1:4:DATABASE:ANY:MYSQL:MySQL database:=fe=fe=07=00"),
  N_("0:1:4:DATABASE:ANY:MYSQL:MySQL database:=fe=fe=05=00"),
  N_("0:1:4:DATABASE:ANY:MYSQL:MySQL database:=fe=fe=06=00"),
  
  NULL, 
  NULL, 
  NULL, 
  NULL, 

  NULL, 
  NULL, 
  NULL, 
  NULL, 

  NULL, 
  NULL, 
  NULL, 
  NULL, 

  NULL, 
  NULL, 
  NULL, 
  NULL, 

  NULL,
};

static unsigned int    sh_ftype_def = 0;

#define SH_FTYPE_ADD  16

struct sh_ftype_rec {
  size_t offset;
  size_t length;
  char   pattern[SH_FTYPE_MAX];

  char   type[SH_FTYPE_MAX];
};


struct sh_ftype_rec ** sh_ftype_arr = NULL;
static unsigned int    sh_ftype_nn  = 0;

#if !defined(SH_FILE_MAIN)

static unsigned int    sh_ftype_usr = 0;

extern char * unquote_string (const char * str, size_t len);

int sh_restrict_add_ftype(const char * str)
{
  size_t len;
  char * cond;

  if (sh_ftype_def == 0)
    {
      while(sh_ftype_list[sh_ftype_def] != NULL) ++sh_ftype_def;
    }

  if (!str) 
    {
      if (sh_ftype_usr > 0)
	{
	  unsigned int i, j = sh_ftype_def;
	  
	  for (i = 0; i < sh_ftype_usr; ++i)
	    {
	      SH_FREE(sh_ftype_list[j+i]);
	      sh_ftype_list[j+i] = NULL;
	    }   
	  sh_ftype_usr = 0;
	}

      if (sh_ftype_arr)
	{
	  unsigned int i = 0;
	  
	  while(sh_ftype_arr[i] != NULL)
	    {
	      SH_FREE(sh_ftype_arr[i]);
	      ++i;
	    }
	  SH_FREE(sh_ftype_arr);
	  sh_ftype_arr = NULL;
	}
    }
  else if (sh_ftype_usr < SH_FTYPE_ADD)
    {
      len = strlen(str);
      cond = unquote_string(str, len);
      sh_ftype_list[sh_ftype_def+sh_ftype_usr] = cond;
      ++sh_ftype_usr;
    }
  else
    {
      return -1;
    }
  return 0;
}


#endif


static int init_record(unsigned int n, char * define,
		       struct sh_ftype_rec * record)
{
  unsigned int offset, dtype, length, i = 0, xn = 0;
  char type[SH_FTYPE_MAX];
  char pattern[SH_FTYPE_MAX];

  char * end;
  char * start;
  
  offset = strtoul(define, &end, 0);
  if (*end != ':')
    return -1;

  start = end; ++start;
  dtype  = strtoul(start,  &end, 0);
  if (*end != ':')
    return -1;

  start = end; ++start;
  length = strtoul(start,  &end, 0);
  if (*end != ':')
    return -1;
  
  start = end; ++start;

  while (*start && (i < sizeof(type)))
    {
      type[i] = *start; ++start;
      if (type[i] == ':') 
	++xn;
      if (xn == 3)
	{
	  type[i] = '\0';
	  break;
	}
      ++i;
    }
  if (xn != 3)
    return -1;

  start = strchr(start, ':');

  if (!start)
    return -1;

  ++start;

  if (dtype == 0)
    {
      sl_strlcpy(pattern, start, sizeof(pattern));
      length = strlen(pattern);
    }
  else if (length <= sizeof(pattern))
    {
      memcpy(pattern, start, length);
    }
  else
    {
      return -1;
    }

  for (i = 0; i < n; ++i)
    {
      if (sh_ftype_arr[i]->length <= length &&
	  sh_ftype_arr[i]->offset == offset)
	{
	  if (0 == memcmp(sh_ftype_arr[i]->pattern, pattern, 
			  sh_ftype_arr[i]->length))
	    {
#ifdef  SH_FILE_MAIN
	      fprintf(stderr, 
		      "Pattern %d (%s / %s) override by earlier pattern %d (%s / %s)\n",
		      n, type, pattern,
		      i, sh_ftype_arr[i]->type, sh_ftype_arr[i]->pattern);
#else
	      char errbuf[256];
	      
	      sl_snprintf(errbuf, sizeof(errbuf),
			  _("Pattern %d (%s) override by earlier pattern %d (%s)"),
			  n, type,
			  i, sh_ftype_arr[i]->type);
	      sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
			      errbuf,
			      _("init_record"));
#endif
	    }
	}
    }


  record->offset = offset;
  record->length = length;
  memcpy(record->pattern, pattern, length);
  sl_strlcpy(record->type, type, SH_FTYPE_MAX);

  return 0;
}

static void file_arr_init()
{
  unsigned int i, nn = 0;

  if (sh_ftype_def == 0)
    {
      while(sh_ftype_list[sh_ftype_def] != NULL) ++sh_ftype_def;
    }

  while (sh_ftype_list[nn] != NULL) ++nn;

#ifdef  SH_FILE_MAIN
  printf("%d definitions found, defined = %d\n", nn, sh_ftype_def);
#endif

#ifdef  SH_FILE_MAIN
  sh_ftype_arr = calloc((nn+1), sizeof(struct sh_ftype_rec *));
#else
  sh_ftype_arr = SH_ALLOC((nn+1) * sizeof(struct sh_ftype_rec *));
#endif

  for(i = 0; i < nn; i++)
    {
#ifdef  SH_FILE_MAIN
      sh_ftype_arr[i] = calloc(1, sizeof(struct sh_ftype_rec));
#else
      sh_ftype_arr[i] = SH_ALLOC(sizeof(struct sh_ftype_rec));
#endif

      memset(sh_ftype_arr[i], 0, sizeof(struct sh_ftype_rec));
      if (i < sh_ftype_def) 
	{
	  char   * p  = _(sh_ftype_list[i]);
	  size_t len  = strlen(p);
	  char * cond = unquote_string(p, len); 
	  
	  init_record(i,             cond, sh_ftype_arr[i]);
	}
      else 
	{
	  init_record(i, sh_ftype_list[i], sh_ftype_arr[i]);
	}
    }
  sh_ftype_arr[nn] = NULL;
  sh_ftype_nn      = nn;

  return;
}

static char * check_filetype(char * filetype, 
			     const char * buffer, size_t buflen)
{
  unsigned int i;
  const char * p;

  if (!sh_ftype_arr)
    {
      file_arr_init();
    }
  
  for (i = 0; i < sh_ftype_nn; ++i)
    {
      if (sh_ftype_arr[i]->length > 0 && 
	  (sh_ftype_arr[i]->length + sh_ftype_arr[i]->offset) < buflen)
	{
	  p = &buffer[sh_ftype_arr[i]->offset];

	  if (0 == memcmp(p, sh_ftype_arr[i]->pattern, sh_ftype_arr[i]->length))
	    {
	      sl_strlcpy(filetype, sh_ftype_arr[i]->type, SH_FTYPE_MAX);
	      return (filetype);
	    }
	}
    }

  if (buflen > 0) {

    int flag = 0;

    p = buffer;
    for (i = 0; i < buflen; ++i) {
      if (*p == '\0')
	{
	  sl_strlcpy(filetype, _("FILE:BINARY:UNKNOWN"), SH_FTYPE_MAX);
	  goto out;
	}
      else if (!isgraph((int)*p) && !isspace((int)*p))
	{
	  flag = 1;
	}
      ++p;
    }
    if (flag == 0)
      {
	sl_strlcpy(filetype, _("FILE:TEXT:ASCII"), SH_FTYPE_MAX);
	goto out;
      }
  }
  sl_strlcpy(filetype, _("FILE:UNKNOWN:UNKNOWN"), SH_FTYPE_MAX);
 out:
  return filetype;
}

#if !defined(SH_FILE_MAIN)

int matches_filetype(SL_TICKET ft, char * test_type)
{
  char buffer[3072];
  char filetype[SH_FTYPE_MAX];
  long len;

  len = sl_read_timeout (ft, buffer, sizeof(buffer), 12, S_TRUE);

  sl_rewind(ft);

  if (len > 0)
    {
      check_filetype(filetype, buffer, len);
    }
  else
    {
      sl_strlcpy(filetype, _("FILE:UNKNOWN:UNKNOWN"), SH_FTYPE_MAX);
    }

  if (0 == strcmp(filetype, test_type))
    {
      return 1;
    }

  return 0;
}

#else
/* SH_FILE_MAIN */
#include <unistd.h>

int main (int argc, char * argv[])
{
  char buffer[3072];
  char filetype[SH_FTYPE_MAX];
  size_t len;

  FILE * fh = fopen(argv[1], "r");

  if (fh)
    {
      int fd = fileno(fh);

      len = read(fd, buffer, 3072);

      check_filetype(filetype, buffer, len);

      fprintf(stdout, "%s: %s\n", argv[1], filetype);

      return 0;
    }
  return 1;
}
#endif

#endif
/* #if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE) */
