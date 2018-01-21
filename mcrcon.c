/*-
 * Copyright (c) 2017 - 2018 MAEKAWA Masahide @ M-Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netdb.h>
#include <netinet/in.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#define	MCRCON_TYPE_RESPONSE	(0)
#define	MCRCON_TYPE_COMMAND	(2)
#define	MCRCON_TYPE_LOGIN	(3)

#define	MCRCON_DEFAULT_PORT	"25575" /* Java edition */
#define	MCRCON_DEFAULT_TIMEOUT	(30) /* sec */

#define	MCRCON_RECV_BUFSIZE	(2048) /* > 1460 */

/* Minecraft RCON Subroutines */
static int mcrcon_script_execute(int, const char *);
static int mcrcon_command_execute(int, uint32_t, const void *);
static uint32_t mcrcon_command_issue_request_id(void);
static size_t mcrcon_command_setup(uint8_t *, size_t, uint32_t, uint32_t, const void *);
static ssize_t mcrcon_command_send(int, const uint8_t *, size_t);
static ssize_t mcrcon_command_recv(int, uint8_t *, size_t);

/* Network Subroutines */
static int mcrcon_connect(const char *, const char *, int);
static void mcrcon_close(int);
static ssize_t mcrcon_send(int, const void *, size_t, int);
static ssize_t mcrcon_recv(int, void *, size_t, int);
static int mcrcon_peek(int, int, short);

/* Miscellaneous Subroutines */
static void mcrcon_print(const char *, ...);
static void mcrcon_dump(uint32_t, const uint8_t *, size_t);
static void usage(void);

static int verbose;

int
main(int argc, char *argv[])
{
	const char *host, *serv, *pass, *scrname;
	int sock, ch, i;

	host = NULL;
	serv = MCRCON_DEFAULT_PORT;
	pass = NULL;

	scrname = NULL;

	verbose = 0;

	while ((ch = getopt(argc, argv, "a:f:h:p:v")) != -1) {
		switch (ch) {
		case 'a':
			pass = optarg;
			break;
		case 'f':
			scrname = optarg;
			break;
		case 'h':
			host = optarg;
			break;
		case 'p':
			serv = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (host == NULL) {
		usage();
		exit(EXIT_FAILURE);
	}

	if ((scrname == NULL) && (argc == 0)) {
		usage();
		exit(EXIT_FAILURE);
	}

	sock = mcrcon_connect(host, serv, MCRCON_DEFAULT_TIMEOUT);
	if (sock == -1) {
		(void)fprintf(stderr, "No connection to %s:%s\n", host, serv);
		exit(EXIT_FAILURE);
	}

	mcrcon_print("Connected to %s:%s\n", host, serv);

	if (pass != NULL) {
		if (mcrcon_command_execute(sock, MCRCON_TYPE_LOGIN, pass) == -1) {
			(void)fprintf(stderr, "Login failure\n");
			mcrcon_close(sock);
			exit(EXIT_FAILURE);
		}
	}

	if (scrname != NULL) {
		/* script mode */
		if (mcrcon_script_execute(sock, scrname) == -1) {
			(void)fprintf(stderr, "Script failure\n");
			mcrcon_close(sock);
			exit(EXIT_FAILURE);
		}
	} else {
		/* command line mode */
		for (i = 0 ; i < argc ; i++) {
			if (mcrcon_command_execute(sock, MCRCON_TYPE_COMMAND, argv[i]) == -1) {
				(void)fprintf(stderr, "Command failure\n");
				mcrcon_close(sock);
				exit(EXIT_FAILURE);
			}
		}
	}

	mcrcon_close(sock);

	exit(EXIT_SUCCESS);
}

static int
mcrcon_script_execute(int sock, const char *scrname)
{
	struct stat st;
	uint8_t *p, *c, *sp, *bp, *sv_sp;
	size_t n, nc;
	int fd;

	fd = open(scrname, O_RDONLY, 0);
	if (fd == -1)
		return (-1);

	if (fstat(fd, &st) == -1) {
		(void)close(fd);
		return (-1);
	}

	n = (size_t)st.st_size;

	p = mmap(NULL, n, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == NULL) {
		(void)close(fd);
		return (-1);
	}

	sp = p;
	bp = sp + n;

	while (sp < bp) {
		sv_sp = sp;

		if (isspace((int)(*sp))) {
			/* Ignore the spaces of the beginning of a line. */
			sp++;
			continue;
		}
		while (sp < bp) {
			if (*sp == '\n') {
				sp++;
				break;
			}
			sp++;
		}
		if (*sv_sp == '#') {
			/* Ignore a comment. */
			continue;
		}
		nc = (size_t)(sp - sv_sp);
		if (nc == 1) {
			/* Ignore a blank line. */
			continue;
		}
		c = malloc(nc);
		if (c == NULL)
			break;
		(void)memmove(c, sv_sp, nc);
		c[nc - 1] = '\0';
		if (mcrcon_command_execute(sock, MCRCON_TYPE_COMMAND, c) == -1) {
			free(c);
			break;
		}
		free(c);
	}

	if (munmap((void *)p, n) == -1) {
		(void)close(fd);
		return (-1);
	}

	if (close(fd) == -1)
		return (-1);

	return (0);
}

/*
 * Minecraft RCON Subroutines
 */
static int
mcrcon_command_execute(int sock, uint32_t type, const void *cmd)
{
	uint32_t rid;
	uint8_t *buffer;
	size_t bufsize, n;
	ssize_t rv;

	mcrcon_print("RCON command: \"%s\"\n", cmd);

	/* wait 100msec to prevent Minecraft Server hang up */
	(void)usleep(100 * 1000);

	/* Request ID */
	rid = mcrcon_command_issue_request_id();

	/* Send Command */
	bufsize  = (cmd != NULL) ? strlen(cmd) : 0;
	bufsize += sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + 2;

	buffer = malloc(bufsize);
	if (buffer == NULL)
		return (-1);

	n = mcrcon_command_setup(buffer, bufsize, rid, type, cmd);
	if (n != bufsize) {
		free(buffer);
		return (-1);
	}

	rv = mcrcon_command_send(sock, buffer, n);
	if ((size_t)rv != n) {
		free(buffer);
		return (-1);
	}

	free(buffer);

	/* Receive Result */
	bufsize = MCRCON_RECV_BUFSIZE;
	buffer = malloc(bufsize);
	if (buffer == NULL)
		return (-1);
	(void)memset(buffer, 0, bufsize);

	rv = mcrcon_command_recv(sock, buffer, bufsize);
	if (rv == -1) {
		free(buffer);
		return (-1);
	}

	mcrcon_dump(rid, buffer, (size_t)rv);

	free(buffer);

	return (0);
}

static uint32_t
mcrcon_command_issue_request_id(void)
{
	static uint32_t McrconRequestID = 0;

	McrconRequestID++;
	if (McrconRequestID > (uint32_t)INT32_MAX) {
		McrconRequestID = 0;
	}

	return (McrconRequestID);
}

static size_t
mcrcon_command_setup(uint8_t *buffer, size_t bufsize, uint32_t rid, uint32_t type, const void *cmd)
{
	uint8_t *sp;
	size_t n, nc;

	nc = (cmd != NULL) ? strlen(cmd) : 0;
	if ((sizeof(uint32_t) + nc) > bufsize)
		return (0);

	(void)memset(buffer, 0, bufsize);

	sp = buffer;

	/* Length */
	n = sizeof(uint32_t) + sizeof(uint32_t) + nc + 2;
	*sp++ = (uint8_t)((n >>  0) & 0xFF);
	*sp++ = (uint8_t)((n >>  8) & 0xFF);
	*sp++ = (uint8_t)((n >> 16) & 0xFF);
	*sp++ = (uint8_t)((n >> 24) & 0xFF);

	/* Request ID */
	*sp++ = (uint8_t)((rid >>  0) & 0xFF);
	*sp++ = (uint8_t)((rid >>  8) & 0xFF);
	*sp++ = (uint8_t)((rid >> 16) & 0xFF);
	*sp++ = (uint8_t)((rid >> 24) & 0xFF);

	/* Type */
	*sp++ = (uint8_t)((type >>  0) & 0xFF);
	*sp++ = (uint8_t)((type >>  8) & 0xFF);
	*sp++ = (uint8_t)((type >> 16) & 0xFF);
	*sp++ = (uint8_t)((type >> 24) & 0xFF);

	/* Payload */
	(void)memmove(sp, cmd, nc);
	sp += nc;

	/* Padding */
	*sp++ = 0x00;
	*sp++ = 0x00;

	return ((size_t)(sp - buffer));
}

static ssize_t
mcrcon_command_send(int sock, const uint8_t *buffer, size_t bufsize)
{
	const uint8_t *sp, *bp;
	ssize_t n;

	sp = buffer;
	bp = sp + bufsize;

	while (sp < bp) {
		n = mcrcon_send(sock, sp, (size_t)(bp - sp), MCRCON_DEFAULT_TIMEOUT);
		if (n == -1)
			return (-1);
		sp += n;
	}

	return ((ssize_t)(sp - buffer));
}

static ssize_t
mcrcon_command_recv(int sock, uint8_t *buffer, size_t bufsize)
{
	ssize_t n;

	n = mcrcon_recv(sock, buffer, bufsize, MCRCON_DEFAULT_TIMEOUT);
	if (n == -1)
		return (-1);

	return (n);
}

/*
 * Network Subroutines
 */
static int
mcrcon_connect(const char *host, const char *serv, int timeout)
{
	struct addrinfo hints, *ai, *res;
	int sock, flags, error;

	(void)memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	error = getaddrinfo(host, serv, &hints, &res);
	if (error != 0)
		return (-1);

	sock = -1;
	for (ai = res ; ai != NULL ; ai = ai->ai_next) {
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock == -1)
			continue;
		if (timeout >= 0) {
			flags = fcntl(sock, F_GETFL, 0);
			if (flags < 0) {
				(void)close(sock);
				sock = -1;
				continue;
			}
			flags |= O_NONBLOCK;
			if (fcntl(sock, F_SETFL, flags) == -1) {
				(void)close(sock);
				sock = -1;
				continue;
			}
		}
		if (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			if (errno != EINPROGRESS) {
				(void)close(sock);
				sock = -1;
				continue;
			}
			if (mcrcon_peek(sock, timeout, POLLWRNORM) <= 0) {
				(void)close(sock);
				sock = -1;
				continue;
			}
		}
		break;
	}

	freeaddrinfo(res);

	return (sock);
}

static void
mcrcon_close(int sock)
{
	(void)close(sock);
}

static ssize_t
mcrcon_send(int sock, const void *buffer, size_t bufsize, int timeout)
{
	ssize_t n;
	int rv;

	if (sock == -1)
		return (-1);

	rv = mcrcon_peek(sock, timeout, POLLWRNORM);
	if (rv <= 0)
		return (-1);
	n = send(sock, buffer, bufsize, 0);
	if (n == -1) {
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
			return (0);
		return (-1);
	}

	return (n);
}

static ssize_t
mcrcon_recv(int sock, void *buffer, size_t bufsize, int timeout)
{
	ssize_t n;
	int rv;

	if (sock == -1)
		return (-1);

	rv = mcrcon_peek(sock, timeout, POLLRDNORM);
	if (rv <= 0)
		return (-1);
	n = recv(sock, buffer, bufsize, 0);
	if (n == -1)
		return (-1);

	return (n);
}

static int
mcrcon_peek(int sock, int timeout, short events)
{
	struct pollfd fds[1];
	int rv;

	fds[0].fd      = sock;
	fds[0].events  = events;
	fds[0].revents = 0;

	if (timeout < 0)
		timeout = -1;
	else
		timeout *= 1000; /* sec -> msec */

	rv = poll(fds, 1, timeout);
	if (rv == -1)
		return (-1);

	return (rv);
}

/*
 * Miscellaneous Subroutines
 */
static void
mcrcon_print(const char *fmt, ...)
{
	va_list ap;

	if (!verbose)
		return;

	va_start(ap, fmt);
	(void)vprintf(fmt, ap);
	va_end(ap);
}

static void
mcrcon_dump(uint32_t rid, const uint8_t *buffer, size_t bufsize)
{
	const uint8_t *sp, *bp;
	uint32_t L, R, T;

	if (!verbose)
		return;

	if (bufsize < (sizeof(uint32_t) * 3)) {
		(void)fprintf(stderr, "Data Buffer Size error %zu\n", bufsize);
		return;
	}

	sp = buffer;
	bp = sp + bufsize;

	/* Length */
	L  = ((uint32_t)*sp++) <<  0;
	L += ((uint32_t)*sp++) <<  8;
	L += ((uint32_t)*sp++) << 16;
	L += ((uint32_t)*sp++) << 24;

	/* Request ID */
	R  = ((uint32_t)*sp++) <<  0;
	R += ((uint32_t)*sp++) <<  8;
	R += ((uint32_t)*sp++) << 16;
	R += ((uint32_t)*sp++) << 24;

	/* Type  */
	T  = ((uint32_t)*sp++) <<  0;
	T += ((uint32_t)*sp++) <<  8;
	T += ((uint32_t)*sp++) << 16;
	T += ((uint32_t)*sp++) << 24;

	if (bufsize < (L + sizeof(uint32_t))) {
		(void)fprintf(stderr, "Data Buffer Size error %zu (Length=%" PRIu32 ")\n", bufsize, L);
		return;
	}

	/* Padding */
	if ((sp[L - 2] != 0x00) || (sp[L - 1] != 0x00)) {
		(void)fprintf(stderr, "Data Padding error %02x %02x\n", sp[L - 2], sp[L - 1]);
		return;
	}
	bp -= 2;

	(void)printf("Length=%" PRIu32 ", "
		     "Request ID=%" PRIx32 "%s, "
		     "Type=%" PRIu32 "\n",
		     L,
		     R, (R == rid) ? "" : "(Not Match)",
		     T);

	if (sp < bp) {
		(void)printf("ASCII: %.*s\n", (int)(bp - sp), sp);
		(void)printf("Binary:\n");
		while ((bp - sp) >= 8) {
			(void)printf(" %02x %02x %02x %02x %02x %02x %02x %02x\n", sp[0], sp[1], sp[2], sp[3], sp[4], sp[5], sp[6], sp[7]);
			sp += 8;
		}
	}
	if (sp < bp) {
		while (sp < bp) {
			(void)printf(" %02x", *sp);
			sp++;
		}
		(void)printf("\n");
	}
}

static void
usage(void)
{
	(void)printf("Usage: mcrcon [-v] [-a <password>] [-f <script file>] [-p <port>] -h <hostname>\n");
	(void)printf(" password: empty (default)\n");
	(void)printf(" port: 25575 (default)\n");
}
