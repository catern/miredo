/*
 * checkconf.cpp - Miredo conf parser unit test
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2005-2006 Rémi Denis-Courmont.                         *
 *  This program is free software; you can redistribute and/or modify  *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; version 2 of the license.         *
 *                                                                     *
 *  This program is distributed in the hope that it will be useful,    *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.               *
 *  See the GNU General Public License for more details.               *
 *                                                                     *
 *  You should have received a copy of the GNU General Public License  *
 *  along with this program; if not, you can get it from:              *
 *  http://www.gnu.org/copyleft/gpl.html                               *
 ***********************************************************************/

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <gettext.h>
#include <locale.h>
#include "binreloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <unistd.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#else
# include <inttypes.h>
#endif
#include <netinet/in.h>
#include "conf.h"

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

class MiredoCheckConf : public MiredoConf
{
	private:
		bool fail;

	protected:
		virtual void Log (bool, const char *fmt, va_list ap)
		{
			fail = true;
			vfprintf (stderr, fmt, ap);
			fputc ('\n', stderr);
		}

	public:
		MiredoCheckConf (void) : MiredoConf (), fail (false)
		{
		}

		bool HasFailed (void) const
		{
			return fail;
		}
};

/* FIXME: use same more clever code as in main.c */
static const char conffile[] = SYSCONFDIR"/miredo.conf";

static int miredo_checkconf (MiredoConf& conf)
{
	int i, res = 0;
	if (!ParseSyslogFacility (conf, "SyslogFacility", &i))
		res = -1;

	bool client = true;

	unsigned line;
	char *val = conf.GetRawValue ("RelayType", &line);

	if (val != NULL)
	{
		if ((strcasecmp (val, "client") == 0)
		 || (strcasecmp (val, "autoclient") == 0))
			client = true;
		else
		if ((strcasecmp (val, "cone") == 0)
		 || (strcasecmp (val, "restricted") == 0))
			client = false;
		else
		{
			fprintf (stderr, _("Invalid relay type \"%s\" at line %u"),
			         val, line);
			fputc ('\n', stderr);
			res = -1;
		}
		free (val);
	}

	uint32_t u32;
	uint16_t u16;

	if (client)
	{
#ifdef MIREDO_TEREDO_CLIENT
		if (!miredo_conf_parse_IPv4 (conf, "ServerAddress", &u32)
		 || !miredo_conf_parse_IPv4 (conf, "ServerAddress2", &u32))
			res = -1;
#else
		fputs (_("Unsupported Teredo client mode"), stderr);
		fputc ('\n', stderr);
		res = -1;
#endif
	}
	else
	{
		struct in6_addr ip6;
		if (!miredo_conf_parse_IPv6 (conf, "Prefix", &ip6)
		 || !conf.GetInt16 ("InterfaceMTU", &u16))
			res = -1;
	}

	bool b;
	if (!miredo_conf_parse_IPv4 (conf, "BindAddress", &u32)
	 || !conf.GetInt16 ("BindPort", &u16)
	 || !conf.GetBoolean ("IgnoreConeBit", &b))
		res = -1;

	char *str = conf.GetRawValue ("InterfaceName");
	if (str != NULL)
		free (str);

	conf.Clear (5);
	return res;
}


static int miredo_checkconffile (const char *filename)
{
	MiredoCheckConf conf;

	if (!conf.ReadFile (filename))
		return -1;

	return (miredo_checkconf (conf) || conf.HasFailed ()) ? -1 : 0;
}


static int usage (const char *path)
{
	printf ("Usage: %s [CONF_FILE]\n", path);
	return 0;
}

static int version (void)
{
	puts (PACKAGE_NAME" v"PACKAGE_VERSION);
	return 0;
}

int main(int argc, char *argv[])
{
	(void)br_init (NULL);
	(void)setlocale (LC_ALL, "");
	char *path = br_find_locale_dir (LOCALEDIR);
	(void)bindtextdomain (PACKAGE_NAME, path);
	free (path);

	static const struct option opts[] =
	{
		{ "help",       no_argument,       NULL, 'h' },
		{ "version",    no_argument,       NULL, 'V' },
		{ NULL,         no_argument,       NULL, '\0'}
	};

	int c;
	while ((c = getopt_long (argc, argv, "hV", opts, NULL)) != -1)
		switch (c)
		{
			case 'h':
				return usage(argv[0]);

			case 'V':
				return version();
		}

	const char *filename = NULL;
	char *str = NULL;

	if (optind < argc)
		filename = argv[optind++];
	else
	{
		/* No parameters provided - attempt in source tree test */
		const char *srcdir = getenv ("srcdir");

		if (srcdir != NULL)
		{

			if (asprintf (&str, "%s/../misc/miredo.conf-dist",
			              srcdir) == -1)
				filename = str = NULL;
			else
				filename = str;
		}
		else
			filename = conffile;
	}

	int res = miredo_checkconffile (filename);

	if (str != NULL)
		free (str);

	return res;
}
