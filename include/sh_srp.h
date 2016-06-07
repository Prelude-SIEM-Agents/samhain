/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999 Rainer Wichmann                                      */
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


void sh_srp_x (char * salt, char * password);
int  sh_srp_make_a (void);
char * sh_srp_M (char * x1, char * x2, char * x3, char * buf, size_t size);

char * sh_srp_verifier (void);
int sh_srp_check_zero (char * AB_str);

int sh_srp_init(void);
void sh_srp_exit(void);
char * sh_srp_A (void);
char * sh_srp_B (char * verifier);
char * sh_srp_S_c (char * u_str, char * B_str);
char * sh_srp_S_s (char * u_str, char * A_str, char * v_str);


