/*  mingetty.c
 *
 *  Copyright (C) 1996 Florian La Roche  <laroche@redhat.com>
 *  Copyright (C) 2002, 2003 Red Hat, Inc
 *
 *  This getty can only be used as a small console getty. Look at mgetty
 *  for a real modem getty.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 */

/* TODO:
 * - autologin only at first login
 * - /etc/mingetty.conf that can be used instead of /etc/inittab for
 *   command line options
 * - Can UTF-8 setup be done within mingetty?
 * - Also add /bin/login-type functionality in here?
 */

#define _GNU_SOURCE 1		       /* Needed to get setsid() */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <signal.h>
#include <fcntl.h>
#include <stdarg.h>
#include <ctype.h>
#include <utmp.h>
#include <getopt.h>
#include <sys/param.h>
#include <syslog.h>
#include <sys/utsname.h>
#include <time.h>

#include <emscripten.h>

/* name of this program (argv[0]) */
static char *progname;
/* on which tty line are we sitting? (e.g. tty1) */
static char *tty;
/* some information about this host */
static struct utsname uts;
/* the hostname */
static char hn[MAXHOSTNAMELEN + 1];
/* process and session ID of this program */
static pid_t pid, sid;
/* login program invoked */
static char *loginprog = "/bin/login";
/* Do not send a reset string to the terminal. */
static int noclear = 0;
/* Do not print a newline. */
static int nonewline = 0;
/* Do not print /etc/issue. */
static int noissue = 0;
/* Do not call vhangup() on the tty. */
static int nohangup = 0;
/* Do not print any hostname. */
static int nohostname = 0;
/* Print the whole string of gethostname() instead of just until the next "." */
static int longhostname = 0;
/* time to wait, seconds */
static int delay = 0;
/* chroot directory */
static char *ch_root = NULL;
/* working directory to change into */
static char *ch_dir = NULL;
/* 'nice' level of the program */
static int priority = 0;
/* automatic login with this user */
static char *autologin = NULL;

/* error() - output error messages */
static void error (const char *fmt, ...)
{
	va_list va_alist;

	va_start (va_alist, fmt);
	openlog (progname, LOG_PID, LOG_AUTH);
	vsyslog (LOG_ERR, fmt, va_alist);
	/* no need, we exit anyway: closelog (); */
	va_end (va_alist);
	sleep (5);
	exit (EXIT_FAILURE);
}

/* update_utmp() - update our utmp entry */
static void update_utmp (void)
{

  emscripten_log(EM_LOG_CONSOLE, "--> update_utmp");
  
	struct utmp ut;
	struct utmp *utp;
	time_t cur_time;

	setutent ();
	while ((utp = getutent ()))
		if (utp->ut_type == INIT_PROCESS && utp->ut_pid == pid)
			break;

	if (utp) {
		memcpy (&ut, utp, sizeof (ut));
	} else {
		/* some inits don't initialize utmp... */
		const char *x = tty;
		memset (&ut, 0, sizeof (ut));
		if (strncmp (x, "tty", 3) == 0)
			x += 3;
		if (strlen (x) > sizeof (ut.ut_id))
			x += strlen (x) - sizeof (ut.ut_id);
		strncpy (ut.ut_id, x, sizeof (ut.ut_id));
	}

	strncpy (ut.ut_user, "LOGIN", sizeof (ut.ut_user));
	strncpy (ut.ut_line, tty, sizeof (ut.ut_line));
	time (&cur_time);
	ut.ut_time = cur_time;
	ut.ut_type = LOGIN_PROCESS;
	ut.ut_pid = pid;
	ut.ut_session = sid;

	pututline (&ut);
	endutent ();

	updwtmp (_PATH_WTMP, &ut);

	emscripten_log(EM_LOG_CONSOLE, "<-- update_utmp");
}

/* open_tty - set up tty as standard { input, output, error } */
static void open_tty (void)
{

  emscripten_log(EM_LOG_CONSOLE, "--> open_tty");
  
	struct sigaction sa, sa_old;
	char buf[40];
	int fd;

	/* Reset permissions on the console device */
	if ((strncmp(tty, "tty", 3) == 0) && (isdigit(tty[3]))) {
		strcpy (buf, "/dev/vcs");
		strcat (buf, &tty[3]);
		if (chown (buf, 0, 3) || chmod (buf, 0600))
			if (errno != ENOENT)
				error ("%s: %s", buf, strerror(errno));

		strcpy (buf, "/dev/vcsa");
		strcat (buf, &tty[3]);
		if (chown (buf, 0, 3) || chmod (buf, 0600))
			if (errno != ENOENT)
				error ("%s: %s", buf, strerror(errno));
	}

	/* Set up new standard input. */
	if (tty[0] == '/') {
		strncpy (buf, tty, sizeof(buf)-1);
		buf[sizeof(buf)-1] = '\0';
	} else {
		strcpy (buf, "/dev/");
		strncat (buf, tty, sizeof(buf)-strlen(buf)-1);
	}
	/* There is always a race between this reset and the call to
	   vhangup() that s.o. can use to get access to your tty. */
	if (chown (buf, 0, 0) || chmod (buf, 0600))
		if (errno != EROFS)
			error ("%s: %s", tty, strerror (errno));

	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	sigemptyset (&sa.sa_mask);
	sigaction (SIGHUP, &sa, &sa_old);

	/* vhangup() will replace all open file descriptors in the kernel
	   that point to our controlling tty by a dummy that will deny
	   further reading/writing to our device. It will also reset the
	   tty to sane defaults, so we don't have to modify the tty device
	   for sane settings. We also get a SIGHUP/SIGCONT.
	 */
	if ((fd = open (buf, O_RDWR, 0)) < 0)
		error ("%s: cannot open tty: %s", tty, strerror (errno));
	if (ioctl (fd, TIOCSCTTY, (void *) 1) == -1)
		error ("%s: no controlling tty: %s", tty, strerror (errno));
	if (!isatty (fd))
		error ("%s: not a tty", tty);

	if (nohangup == 0) {
	  /* Modified by Benoit Baudaux 19/1/2023 */
	  /*if (vhangup ())
	    error ("%s: vhangup() failed", tty);*/
		/* Get rid of the present stdout/stderr. */
		close (2);
		close (1);
		close (0);
		close (fd);
		if ((fd = open (buf, O_RDWR, 0)) != 0)
			error ("%s: cannot open tty: %s", tty,
				strerror (errno));
		if (ioctl (fd, TIOCSCTTY, (void *) 1) == -1)
			error ("%s: no controlling tty: %s", tty,
				strerror (errno));
	}
	/* Set up stdin/stdout/stderr. */
	if (dup2 (fd, 0) != 0 || dup2 (fd, 1) != 1 || dup2 (fd, 2) != 2)
		error ("%s: dup2(): %s", tty, strerror (errno));
	if (fd > 2)
		close (fd);

	/* Write a reset string to the terminal. This is very linux-specific
	   and should be checked for other systems. */
	if (noclear == 0)
		write (0, "\033c", 2);

	sigaction (SIGHUP, &sa_old, NULL);

	emscripten_log(EM_LOG_CONSOLE, "<-- open_tty");
}

static void output_special_char (unsigned char c)
{
	switch (c) {
	case 's':
		printf ("%s", uts.sysname);
		break;
	case 'n':
		printf ("%s", uts.nodename);
		break;
	case 'r':
		printf ("%s", uts.release);
		break;
	case 'v':
		printf ("%s", uts.version);
		break;
	case 'm':
		printf ("%s", uts.machine);
		break;
	case 'o':
		printf ("%s", uts.domainname);
		break;
	case 'd':
	case 't':
		{
			time_t cur_time;
			struct tm *tm;
#if	0
			char buff[20];

			time (&cur_time);
			tm = localtime (&cur_time);
			strftime (buff, sizeof (buff),
				c == 'd'? "%a %b %d %Y" : "%X", tm);
			fputs (buff, stdout);
			break;
#else
			time (&cur_time);
			tm = localtime (&cur_time);
			if (c == 'd') /* ISO 8601 */
				printf ("%d-%02d-%02d", 1900 + tm->tm_year,
					tm->tm_mon + 1, tm->tm_mday);
			else
				printf ("%02d:%02d:%02d", tm->tm_hour,
					tm->tm_min, tm->tm_sec);
			break;
#endif
		}

	case 'l':
		printf ("%s", tty);
		break;
	case 'u':
	case 'U':
		{
			int users = 0;
			struct utmp *ut;
			setutent ();
			while ((ut = getutent ()))
				if (ut->ut_type == USER_PROCESS)
					users++;
			endutent ();
			printf ("%d", users);
			if (c == 'U')
				printf (" user%s", users == 1 ? "" : "s");
			break;
		}
	default:
		putchar (c);
	}
}

/* do_prompt - show login prompt, optionally preceded by /etc/issue contents */
static void do_prompt (int showlogin)
{
	FILE *fd;
	int c;

	if (nonewline == 0)
		putchar ('\n');
	if (noissue == 0 && (fd = fopen ("/etc/issue", "r"))) {
		while ((c = getc (fd)) != EOF) {
			if (c == '\\')
				output_special_char (getc (fd));
			else
				putchar (c);
		}
		fclose (fd);
	}
	if (nohostname == 0)
		printf ("%s ", hn);
	if (showlogin)
		printf ("login: ");
	fflush (stdout);
}

static char *get_logname (void)
{
	static char logname[40];
	char *bp;
	unsigned char c;

	tcflush (0, TCIFLUSH);		/* flush pending input */
	for (*logname = 0; *logname == 0;) {
		do_prompt (1);
		for (bp = logname;;) {
			if (read (0, &c, 1) < 1) {
				if (errno == EINTR || errno == EIO
					|| errno == ENOENT)
					exit (EXIT_SUCCESS);
				error ("%s: read: %s", tty, strerror (errno));
			}
			if (c == '\n' || c == '\r') {
				*bp = 0;
				break;
			} else if (!isprint (c))
				error ("%s: invalid character 0x%x in login"
					" name", tty, c);
			else if ((size_t)(bp - logname) >= sizeof (logname) - 1)
				error ("%s: too long login name", tty);
			else
				*bp++ = c;
		}
	}
	return logname;
}

static void usage (void)
{
	error ("usage: '%s [--noclear] [--nonewline] [--noissue] "
		"[--nohangup] [--nohostname] [--long-hostname] "
		"[--loginprog=/bin/login] [--nice=10] [--delay=10] "
		"[--chdir=/home] [--chroot=/chroot] [--autologin=user] "
		"tty' with e.g. tty=tty1", progname);
}

static struct option const long_options[] = {
	{ "autologin", required_argument, NULL, 'a' },
	{ "chdir", required_argument, NULL, 'w' },
	{ "chroot", required_argument, NULL, 'r' },
	{ "delay", required_argument, NULL, 'd' },
	{ "noclear", no_argument, &noclear, 1 },
	{ "nonewline", no_argument, &nonewline, 1 },
	{ "noissue", no_argument, &noissue, 1 },
	{ "nohangup", no_argument, &nohangup, 1 },
	{ "no-hostname", no_argument, &nohostname, 1 }, /* compat option */
	{ "nohostname", no_argument, &nohostname, 1 },
	{ "loginprog", required_argument, NULL, 'l' },
	{ "long-hostname", no_argument, &longhostname, 1 },
	{ "nice", required_argument, NULL, 'n' },
	{ 0, 0, 0, 0 }
};

int main (int argc, char **argv)
{
	char *logname, *s;
	int c;

	progname = argv[0];
	if (!progname)
		progname = "mingetty";
	uname (&uts);
	gethostname (hn, MAXHOSTNAMELEN);
	hn[MAXHOSTNAMELEN] = '\0';
	pid = getpid ();
	sid = getsid (0);

	emscripten_log(EM_LOG_CONSOLE, "mingetty: pid=%d sid=%d", pid, sid);
	
#if	defined(s390) || defined(__s390__)
	putenv ("TERM=dumb");
#else
	putenv ("TERM=linux");
#endif

	while ((c = getopt_long (argc, argv, "a:d:l:n:w:r:", long_options,
		(int *) 0)) != EOF) {
		switch (c) {
		case 0:
			break;
		case 'a':
			autologin = optarg;
			break;
		case 'd':
			delay = atoi (optarg);
			break;
		case 'l':
			loginprog = optarg;
			break;
		case 'n':
			priority = atoi (optarg);
			break;
		case 'r':
			ch_root = optarg;
			break;
		case 'w':
			ch_dir = optarg;
			break;
		default:
			usage ();
		}
	}
	
	if (longhostname == 0 && (s = strchr (hn, '.')))
		*s = '\0';
	tty = argv[optind];
	if (!tty)
		usage ();

	if (strncmp (tty, "/dev/", 5) == 0) /* ignore leading "/dev/" */
		tty += 5;

	update_utmp ();
	if (delay)
		sleep (delay);
	open_tty ();
	if (autologin) {
		do_prompt (0);
		printf ("login: %s (automatic login)\n", autologin);
		logname = autologin;
	} else
		while ((logname = get_logname ()) == 0)
			/* do nothing */ ;

	if (ch_root) {
		if (chroot (ch_root))
			error ("chroot(): %s", strerror (errno));
		if (chdir("/"))
			error ("chdir(\"/\"): %s", strerror (errno));
	}
	if (ch_dir) {
		if (chdir (ch_dir))
			error ("chdir(): %s", strerror (errno));
	}
	if (priority) {
		errno = 0; /* see the nice(2) NOTES for why we do this */
		if ((nice(priority) == -1) && (errno != 0))
			error ("nice(): %s", strerror (errno));
	}

	execl (loginprog, loginprog, autologin? "-f" : "--", logname, NULL);
	error ("%s: can't exec %s: %s", tty, loginprog, strerror (errno));
	sleep (5);
	exit (EXIT_FAILURE);
}
