/*
 * log.c: Miscellaneous logging functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2003  Antti Tapaninen <aet@cc.hut.fi>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "log.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

static void sc_do_log_va(int level, const char *file, int line, const char *func, const char *format, va_list args);

void sc_do_log(int level, const char *file, int line, const char *func, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	sc_do_log_va(level, file, line, func, format, ap);
	va_end(ap);
}

void sc_do_log_noframe(int level, const char *format, va_list args)
{
	sc_do_log_va(level, NULL, 0, NULL, format, args);
}

static void sc_do_log_va(int level, const char *file, int line, const char *func, const char *format, va_list args)
{
	char	buf[4096], *p;
	int	r;
	size_t	left;
#ifdef _WIN32
	SYSTEMTIME st;
#else
	struct tm *tm;
	struct timeval tv;
	char time_string[40];
#endif
	int		n;

	p = buf;
	left = sizeof(buf);

#ifdef _WIN32
	GetLocalTime(&st);
	r = snprintf(p, left,
			"%i-%02i-%02i %02i:%02i:%02i.%03i ",
			st.wYear, st.wMonth, st.wDay,
			st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
#else
	gettimeofday (&tv, NULL);
	tm = localtime (&tv.tv_sec);
	strftime (time_string, sizeof(time_string), "%H:%M:%S", tm);
	r = snprintf(p, left, "0x%lx %s.%03ld ", (unsigned long)pthread_self(), time_string, (long)tv.tv_usec / 1000);
#endif
	p += r;
	left -= r;

	if (file != NULL) {
		r = snprintf(p, left, "%s:%d:%s: ",
			file, line, func ? func : "");
		if (r < 0 || (unsigned int)r > sizeof(buf))
			return;
	}
	else {
		r = 0;
	}
	p += r;
	left -= r;

	r = vsnprintf(p, left, format, args);
	if (r < 0)
		return;

	return;
}

void _sc_debug(int level, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	sc_do_log_va(level, NULL, 0, NULL, format, ap);
	va_end(ap);
}

void _sc_log(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	sc_do_log_va(SC_LOG_DEBUG_NORMAL, NULL, 0, NULL, format, ap);
	va_end(ap);
}

void _sc_debug_hex(int type, const char *file, int line,
		const char *func, const char *label, const uint8_t *data, size_t len)
{
	size_t blen = len * 5 + 128;
	char *buf = malloc(blen);
	if (buf == NULL)
		return;

	sc_hex_dump(type, data, len, buf, blen);

	if (label)
		sc_do_log(type, file, line, func,
			"\n%s (%u byte%s):\n%s",
			label, (unsigned int) len, len==1?"":"s", buf);
	else
		sc_do_log(type, file, line, func,
			"%u byte%s:\n%s",
			(unsigned int) len, len==1?"":"s", buf);

	free(buf);
}

/* Although not used, we need this for consistent exports */
void sc_hex_dump(int level, const uint8_t * in, size_t count, char *buf, size_t len)
{
	char *p = buf;
	int lines = 0;

	if (buf == NULL || (in == NULL && count != 0)) {
		return;
	}
	buf[0] = 0;
	if ((count * 5) > len)
		return;
	while (count) {
		char ascbuf[17];
		size_t i;

		for (i = 0; i < count && i < 16; i++) {
			sprintf(p, "%02X ", *in);
			if (isprint(*in))
				ascbuf[i] = *in;
			else
				ascbuf[i] = '.';
			p += 3;
			in++;
		}
		count -= i;
		ascbuf[i] = 0;
		for (; i < 16 && lines; i++) {
			strcat(p, "   ");
			p += 3;
		}
		strcat(p, ascbuf);
		p += strlen(p);
		sprintf(p, "\n");
		p++;
		lines++;
	}
}

char *
sc_dump_hex(const uint8_t * in, size_t count)
{
	static char dump_buf[0x1000];
	size_t ii, size = sizeof(dump_buf) - 0x10;
	size_t offs = 0;

	memset(dump_buf, 0, sizeof(dump_buf));
	if (in == NULL)
		return dump_buf;

	for (ii=0; ii<count; ii++) {
		if (ii && !(ii%16))   {
			if (!(ii%48))
				snprintf(dump_buf + offs, size - offs, "\n");
			else
				snprintf(dump_buf + offs, size - offs, " ");
			offs = strlen(dump_buf);
		}

		snprintf(dump_buf + offs, size - offs, "%02X", *(in + ii));
		offs += 2;

		if (offs > size)
			break;
	}

	if (ii<count)
		snprintf(dump_buf + offs, sizeof(dump_buf) - offs, "....\n");

	return dump_buf;
}