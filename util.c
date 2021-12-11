/*
 * Copyright (c) 2021 Matthias Schmidt <xhr@giessen.ccc.de>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "jrnlc.h"

int
get_number(const char *buf)
{
	char *ep;
	long lval;
	int ival;

	errno = 0;
	lval = strtol(buf, &ep, 10);

	if (buf[0] == '\0' || *ep != '\0')
		log_fatal(1, "Please enter a number\n");
	if ((errno == ERANGE && (lval == LONG_MAX || lval == LONG_MIN)) ||
		(lval > INT_MAX || lval < INT_MIN))
		log_fatal(1, "Number out of range\n");

	ival = lval;

	return ival;
}

int
create_date(char *tbuf, size_t buflen)
{
	struct tm tm;
	time_t t;

	if (buflen > MAX_DATE)
		return -1;

	t = time(NULL);
	tm = *localtime(&t);

	if (strftime(tbuf, buflen, "%Y-%m-%d", &tm) == 0) {
		return -1;
	}

	return 0;
}

int
create_time(char *tbuf, size_t buflen)
{
	struct tm tm;
	time_t t;

	if (buflen > MAX_TIME)
		return -1;

	t = time(NULL);
	tm = *localtime(&t);

	if (strftime(tbuf, buflen, "%H:%M", &tm) == 0) {
		return -1;
	}

	return 0;
}

void *
malloc_wrapper(size_t size)
{
	void *ptr;

	if (size == 0)
		log_fatal(1, "Cannot allocate nothing\n");
	ptr = malloc(size);
	if (ptr == NULL)
		log_fatal(1, "Cannot allocate memory\n");
	return ptr;
}

void *
calloc_wrapper(size_t nmemb, size_t size)
{
	void *ptr;

	if (size == 0 || nmemb == 0)
		log_fatal(1, "Cannot allocate nothing\n");
	if (SIZE_MAX / nmemb < size)
		log_fatal(1, "Cannot allocate more than available\n");
	ptr = calloc(nmemb, size);
	if (ptr == NULL)
		log_fatal(1, "Cannot allocate memory\n");
	return ptr;
}



#ifdef __OpenBSD__
void
sandbox()
{
	if (pledge("stdio rpath wpath cpath tty", NULL) == -1)
		log_fatal(1, "pledge");
}
#else
void sandbox()
{
}
#endif /* __OpenBSD__ */

