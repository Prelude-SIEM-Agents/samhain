/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2003 Rainer Wichmann                                      */
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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <ctype.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <signal.h>
#include <pwd.h>

#if !defined(AF_FILE)
#define AF_FILE AF_UNIX
#endif

#define SH_MAXMSG 209

#if !defined(HAVE_GETPEEREID) && !defined(SO_PEERCRED) && \
  !defined(HAVE_STRUCT_CMSGCRED) && !defined(HAVE_STRUCT_FCRED) && \
  !(defined(HAVE_STRUCT_SOCKCRED) && defined(LOCAL_CREDS))
#define SH_REQ_PASSWORD 1
#endif

static int    sock     = -1;
static char   password[15] = "";
static int    verbose = 0;

#ifdef SH_STEALTH
char * globber(const char * string);
#define _(string) globber(string) 
#define N_(string) string
#else
#define _(string)  string 
#define N_(string) string
#endif

#ifdef SH_STEALTH
#ifndef SH_MAX_GLOBS
#define SH_MAX_GLOBS 32
#endif
char * globber(const char * str)
{
  register int i, j;
  static int  count = -1;
  static char glob[SH_MAX_GLOBS][128];

  ++count; if (count > (SH_MAX_GLOBS-1) ) count = 0;
  j = strlen(str);
  if (j > 127) j = 127;

  for (i = 0; i < j; ++i)
    {
      if (str[i] != '\n' && str[i] != '\t') 
	glob[count][i] = str[i] ^ XOR_CODE;
      else
	glob[count][i] = str[i];
    }
  glob[count][j] = '\0';
  return glob[count];
}
#endif

#define CLIENT _("yulectl")


static int 
create_unix_socket ()
{
  int sock;

  /* Create the socket. */
  
  sock = socket (PF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    {
      perror (_("ERROR: socket"));
      return -1;
    }

  return sock;
}

static void
termination_handler (int signum)
{
  /* Clean up. */
  if (signum != 0)
    {
      if (verbose)
	fprintf(stdout, _("# Terminated on signal %d\n"), signum);
    }
  if (sock   >= 0 ) 
    close  (sock);
  return;
}

static char * safe_copy(char * to, const char * from, size_t size)
{
  if (to && from)
    {
      strncpy (to, from, size);
      if (size > 0)
	to[size-1] = '\0';
      else 
	*to = '\0';
    }
  return to;
}
 

static int send_to_server (char * serversock, char * message)
{
  struct sockaddr_un name;
  int size;
  int nbytes;

  /* Initialize the server socket address. 
   */
  name.sun_family = AF_UNIX;
  strncpy (name.sun_path, serversock, sizeof(name.sun_path) - 1);
  size = (offsetof (struct sockaddr_un, sun_path)
          + strlen (name.sun_path) + 1);

  nbytes = connect(sock, (struct sockaddr *) & name, size);
  if (nbytes < 0)
    {
      perror (_("ERROR: connect"));
      return -1;
    }

  /* Send the data. 
   */
  nbytes = send (sock, message, strlen (message) + 1, 0);
  if (nbytes < 0)
    {
      perror (_("ERROR: send"));
      return -1;
    }
  return 0;
}

static int getline_from_server (int sock, char * buf, int size)
{
  int nbytes = 0;
  int status = 0;
  char * p   = buf;

  do {
    status = read (sock, p, 1);
    if (status <= 0)
      {
	buf[nbytes] = '\0';
	return ((status == 0) ? nbytes : status);
      }
    else if (*p == '\0')
      {
	return nbytes;
      }
    ++nbytes; ++p;
  } while (nbytes < size);
  buf[size-1] = '\0';
  return 0;
}

static int recv_from_server (char * message)
{
  int nbytes = 0;
  char recvmsg[SH_MAXMSG];
  int  num = 0;
  int  good = -1;
  char * p;

  if (password[0] == '\0')
    p = message;
  else
    p = &message[strlen(password)+1];

  if (0 == strncmp(p, _("PROBE"), 5) ||
      0 == strncmp(p, _("LIST"),  4))
    {
      do {
	nbytes = getline_from_server (sock, recvmsg, SH_MAXMSG);
	if (nbytes < 0)
	  {
	    if (errno == EAGAIN)
	      return 0;
	    else
	      {
		perror (_("ERROR: recv"));
		return -1;
	      }
	  }
	else if (nbytes == 0)
	  return 0;

	if (recvmsg[0] == 'E' && recvmsg[1] == 'N' && recvmsg[2] == 'D')
	  {
	    if (verbose && (num == 0))
	      fprintf (stdout, "%s", _("# There are no pending commands.\n"));
	    return 0;
	  }
	++num;
	fprintf (stdout, _("%03d: %s\n"), num, recvmsg);
      } while (nbytes >= 0);
    }
  else
    {
      nbytes = recv (sock, recvmsg, SH_MAXMSG, 0);
      if (nbytes < 0)
	{
	  perror (_("ERROR: recv"));
	  return -1;
	}
    }

  /* Print a diagnostic message. */
  if (password[0] == '\0')
    good = strcmp (message, recvmsg);
  else
    good = strcmp (&message[strlen(password)+1], recvmsg);

  if (0 != good)
    {
      if (0 == strncmp(recvmsg, _("!E:"), 3))
	{ 
	  fputs(recvmsg, stderr); 
	  fputc('\n', stderr); 
	}
      else
	{
	  fputs (_("ERROR: Bounced message != original message.\n"), stderr);
	}
      return -1;
    }
  else
    {
      if (verbose)
	fprintf (stdout, "%s", _("# Message received by server.\n"));
    }

  return 0;
}

static int check_uuid(const char * in)
{
  int 		i;
  const char	*cp;

  if (!in || strlen(in) != 36)
    return -1;
  for (i=0, cp = in; i <= 36; i++,cp++) {
    if ((i == 8) || (i == 13) || (i == 18) ||
	(i == 23)) {
      if (*cp == '-')
	continue;
      else
	return -1;
    }
    if (i== 36)
      if (*cp == 0)
	continue;
    if (!isxdigit(*cp))
      return -1;
  }
  return 0;
}

static int check_command(const char * str)
{
  unsigned int i = 0;
  char * commands[] = { N_("DELTA:"), N_("RELOAD"),  N_("STOP"), N_("SCAN"),
			N_("CANCEL"), N_("LISTALL"), N_("LIST"), N_("PROBE"), NULL };

  while (commands[i])
    {
      size_t len = strlen(_(commands[i]));

      if (0 == strncmp(_(commands[i]), str, len))
	{
	  if (i == 0)
	    {
	      char * p = strchr(str, ':'); ++p;
	      if ( 0 == check_uuid(p) )
		return 0;
	    }
	  else
	    {
	      if (len == strlen(str))
		return 0;
	    }
	}
      ++i;
    }

  fprintf (stderr, _("ERROR: invalid command <%s>\n\n"), str);
  return -1;
}

static void print_usage_and_exit(char * name, int exit_status)
{
  printf(_("\nUsage : %s [-v][-s server_socket] -c command <client_hostname>\n\n"), 
	 name);

  printf("%s", _("Purpose : send commands to the server via a socket,\n"));
  printf("%s", _("          in particular commands that the server would\n"));
  printf("%s", _("          transfer to the client <client_hostname> when\n"));
  printf("%s", _("          this client connects to deliver a message.\n\n"));
  printf("%s", _("          If password is required, it is read from\n"));
  printf("%s", _("          $HOME/.yulectl_cred or taken from the environment\n"));
  printf("%s", _("          variable YULECTL_PASSWORD (not recommended).\n\n"));

  printf("%s", _("Commands: RELOAD         reload configuration\n"));
  printf("%s", _("          DELTA:<uuid>   load delta database with given uuid\n"));
  printf("%s", _("          STOP           terminate\n"));
  printf("%s", _("          SCAN           initiate file system check\n"));
  printf("%s", _("          CANCEL         cancel pending command(s)\n"));
  printf("%s", _("          LIST           list queued commands\n"));
  printf("%s", _("          LISTALL        list queued and last sent commands\n"));
  printf("%s", _("          PROBE          probe all clients for necessity of reload\n"));
  exit(exit_status);
}

char * rtrim(char * str)
{
  size_t len;

  if (!str) return str;

  len = strlen(str);
  while (len > 0)
    {
      --len;
      if (str[len] == '\n' || str[len] == '\r')
	str[len] = '\0';
      else
	break;
    }
  return str;
}

static int get_home(char * home, size_t size)
{
  struct passwd * pwent;

  pwent = getpwuid(geteuid());
  if ((pwent == 0) || (pwent->pw_dir == NULL))
    {
      if (verbose)
	fprintf (stderr, _("WARNING: no home directory for euid %ld\n"), 
		 (long) geteuid()); 
      if (NULL != getenv(_("HOME")))
	{
	  safe_copy(home, getenv(_("HOME")), size);
	}
      else
	{
	  fprintf (stderr, _("ERROR: no home directory for euid %ld (tried $HOME and password database).\n"), (long) geteuid());
	  return -1;
	}
    }
  else
    {
      safe_copy(home, pwent->pw_dir, size);
    }
  return 0;
}

static int get_passwd(char * message2, size_t size)
{
  char home[4096];
  FILE * fp;
  char * pw;

  /* 1) Password from environment
   */
  pw = getenv(_("YULECTL_PASSWORD"));
  if (pw && strlen(pw) < 15)
    {
      strcpy(password, pw);
      strcpy(message2, password);
      return 0;
    }

  /* 2) Password from $HOME/.yule_cred
   */
  if (get_home(home, sizeof(home)) < 0)
    return -1;

  if ( (strlen(home) + strlen(_("/.yulectl_cred")) + 1) > 4096)
    {
      fprintf (stderr, "%s", _("ERROR: path for $HOME is too long.\n"));
      return -1;
    }
  strcat(home, _("/.yulectl_cred"));
  fp = fopen(home, "r");

#if defined(SH_REQ_PASSWORD)
  if (fp == NULL)
    {
      if (errno == ENOENT) {
	fprintf (stderr, 
		 _("ERROR No password file (%s) exists\n"),
		 home);
      }
      else {
	fprintf (stderr, 
		 _("ERROR: Password file (%s) not accessible for euid %ld uid %ld\n"),
		 home, (long)geteuid(), (long)getuid());
      }
      return -1;
    }
#else
  if (fp == NULL)
    return 0;
#endif

  if (NULL == fgets(message2, size, fp))
    {
      fprintf (stderr,
	       _("ERROR: empty or unreadable password file (%s).\n"),
	       home);
      return -1;
    }

  (void) rtrim(message2);

  if (strlen(message2) > 14)
    {
      fprintf (stderr, "%s", 
	       _("ERROR: Password too long (max. 14 characters).\n"));
      return -1;
    }
  strcpy(password, message2);
  fclose(fp);

  return 0;
}

static int fixup_message (char * message)
{
  char message_fixed[SH_MAXMSG] = { 0 };

  if (get_passwd(message_fixed, sizeof(message_fixed)) < 0)
    return -1;

  if (strlen(message_fixed) > 0)
    {
      strcat(message_fixed, "@");

      strncat(message_fixed, message, SH_MAXMSG - strlen(message_fixed) -1);
      message_fixed[SH_MAXMSG-1] = '\0';
      strcpy(message, message_fixed);
    }
  return 0;
}

static int fill_serversock(char * serversock, size_t size)
{
  int status;

#ifdef HAVE_VSNPRINTF
  status = snprintf(serversock, size, _("%s/%s.sock"), 
		    DEFAULT_PIDDIR, SH_INSTALL_NAME);
#else
  if ((strlen(DEFAULT_PIDDIR) + strlen(SH_INSTALL_NAME) + 1 + 6) > size)
    status = -1;
  else
    status = sprintf (serversock, _("%s/%s.sock"), 
		      DEFAULT_PIDDIR, SH_INSTALL_NAME);
#endif

  if ((status < 0) || (status > (int)(size-1)))
    {
      fprintf(stderr, _("ERROR: Path too long (maximum %d): %s/%s.sock\n"), 
	      (int) (size-1), DEFAULT_PIDDIR, SH_INSTALL_NAME);
      return -1;
    }
  return 0;
}

static void checklen(char * command, char * str, size_t maxlen)
{
  if (strlen(str) > maxlen) 
    {
      fprintf(stderr, _("ERROR: String too long (max %d): %s\n\n"), 
	      (int) maxlen, str);
      print_usage_and_exit (command, EXIT_FAILURE);
    }
  return;
}

static void checknull(char * command, char * str)
{
  if (str == NULL || str[0] == '\0') {
    fprintf(stderr, "%s", _("ERROR: option with missing argument\n\n"));
    print_usage_and_exit(command, EXIT_FAILURE);
  }
  return;
}

int
main (int argc, char * argv[])
{

  char   message[SH_MAXMSG] = "";
  char   serversock[256];
  int    status;
  int    num = 1;
  int    flag = 0;

  if (fill_serversock(serversock, sizeof(serversock)) < 0)
    return (EXIT_FAILURE);


  while (argc > 1 && argv[num][0] == '-')
    {
      switch (argv[num][1]) 
	{
	  case 'h':
	    print_usage_and_exit(argv[0], EXIT_SUCCESS);
	    break;
	  case 'v':
	    ++verbose;
	    break;
	  case 's':
	    --argc; ++num;
	    checknull(argv[0], argv[num]);
	    checklen(argv[0], argv[num], sizeof(serversock)-1);
	    safe_copy (serversock, argv[num], sizeof(serversock));
	    break;
	  case 'c':
	    --argc; ++num;
	    checknull(argv[0], argv[num]);
	    checklen(argv[0], argv[num], SH_MAXMSG-1);
	    if (0 != check_command(argv[num]))
	      print_usage_and_exit(argv[0], EXIT_FAILURE);
	    safe_copy(message, argv[num], SH_MAXMSG);
	    strncat(message, ":", SH_MAXMSG-strlen(message)-1);
	    message[SH_MAXMSG-1] = '\0';
	    flag = 1;
	    break;
	  default:
	    fprintf(stderr, _("ERROR: unknown option -%c\n\n"), argv[num][1]);
	    print_usage_and_exit(argv[0], EXIT_FAILURE);
	    break;
	}
      --argc; ++num;
    }

  if (flag == 0) /* no command given */
    print_usage_and_exit(argv[0], EXIT_FAILURE);

  if (argc > 1)
    {
      checklen(argv[0], argv[num], SH_MAXMSG - strlen(message) - 1);
      strncat (message, argv[num], SH_MAXMSG - strlen(message) - 1);
      message[SH_MAXMSG-1] = '\0';
    }
  else
    {
      if (0 == strncmp(message, _("PROBE"), 5) ||
	  0 == strncmp(message, _("LIST"),  4))
	{
	  strncat (message, _("dummy"), SH_MAXMSG -strlen(message) - 1);
	  message[SH_MAXMSG-1] = '\0';
	}
      else
	{
	  fprintf(stderr, "%s", _("ERROR: this command requires a hostname\n"));
	  print_usage_and_exit(argv[0], EXIT_FAILURE);
	}
    }

  if (fixup_message(message) < 0)
    return (EXIT_FAILURE);

  /* Make the socket.
   */
  sock = create_unix_socket ();
  if (sock < 0)
    return (EXIT_FAILURE);

  /* Set up termination handler.
   */
  signal (SIGINT,  termination_handler);
  signal (SIGHUP,  termination_handler);
  signal (SIGTERM, termination_handler);
  signal (SIGQUIT, termination_handler);

  /* Send the datagram. 
   */
  status = send_to_server (serversock, message);
  if (status < 0)
    {
      fprintf(stderr, "%s", _("ERROR: sending command to server failed\n"));
      (void) termination_handler(0);
      return (EXIT_FAILURE);
    }

  /* Wait for a reply. 
   */
  if (verbose)
    {
      if (0 == strncmp(message, "LIST", 4))
	fprintf(stdout, "%s", _("# Waiting for listing.\n"));
      else
	fprintf(stdout, "%s", _("# Waiting for confirmation.\n"));
    }

  status = recv_from_server (message);

  if (status < 0)
    {
      fputs(_("ERROR: unexpected or no reply from server.\n"), stderr);
      (void) termination_handler(0);
      return (EXIT_FAILURE);
    }

  /* Clean up. */
  (void) termination_handler(0);
  return (EXIT_SUCCESS);
}

