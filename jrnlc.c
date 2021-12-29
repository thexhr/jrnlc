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

#include <sys/stat.h>
#include <sys/types.h>

#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef __OpenBSD__
#include <readpassphrase.h>
#endif

#include "jrnlc.h"

static int debug    = 0;
static int backup 	= 0;
static struct config conf;
static char jrnlc_config[_POSIX_PATH_MAX];
static unsigned char nonce[crypto_secretbox_NONCEBYTES];
extern char *__progname;

static void
usage(void)
{
	log_fatal(1, "%s [-aBde] [-DIn number]\n", __progname);
}

int
main(int argc, char **argv)
{
	char *passbuf;
	int encrypt 	= 0;
	int decrypt 	= 0;
	int last 		= 0;
	int entry 		= 0;
	int to_delete 	= 0;
	int ch;

	conf.jrnlc_journal[0] = '\0';

	while ((ch = getopt(argc, argv, "aBdD:ef:I:n:vV")) != -1) {
		switch (ch) {
		case 'a':
			last = -1;
			break;
		case 'B':
			backup = 1;
			break;
		case 'd':
			decrypt = 1;
			break;
		case 'D':
			to_delete = get_number(optarg);
			break;
		case 'e':
			encrypt = 1;
			break;
		case 'I':
			entry = get_number(optarg);
			break;
		case 'n':
			last = get_number(optarg);
			break;
		case 'v':
			debug++;
			break;
		case 'V':
			printf("Version %s\n", VERSION);
			exit(0);
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (decrypt && encrypt) {
		log_fatal(1, "Please specify either -d or -e, but not both\n");
	}

	if (entry > 0 && last > 0) {
		log_fatal(1, "Please specify either -I or -n, but not both\n");
	}

	/* Check if base directory exists, if not create it */
	setup_base_dir();

	sandbox();

	/* Load existing config file or create a new one with default values */
	(void)load_config();

	if (sodium_init() == -1)
		log_fatal(1, "Cannot initialize sodium crypto library\n");

	passbuf = calloc_wrapper(1, MAX_PASS_LEN);

	/* User supplied either -e or -d */
	if (encrypt && conf.encrypted) {
		log_fatal(1, "Journal is already encrypted\n");
	} else if (decrypt && !conf.encrypted) {
		log_fatal(1, "Journal is already decrypted\n");
	} else if (encrypt && !conf.encrypted) {
		/* User wants to encrypt and journal is unencrypted */
		printf("Encrypting journal...\n");

		int res = get_initial_passphrase(passbuf);
		if (res == 2) {
			sodium_memzero(passbuf, sizeof(passbuf));
			log_fatal(1, "No blank password allowed\n");
		} else if (res == 3) {
			sodium_memzero(passbuf, sizeof(passbuf));
			log_fatal(1, "Passwords do not match\n");
		}

		/* Generate a new random key and nonce ... */
		crypto_secretbox_keygen(conf.key);
		randombytes_buf(nonce, sizeof nonce);

		/* ... and save both in the key pass file */
		write_pass_file((unsigned char *)conf.key, passbuf);
		sodium_memzero(passbuf, sizeof(passbuf));
		free(passbuf);
		passbuf = NULL;

		load_journal_from_disk();

		/* Make journal as encrypted and save it to disk */
		conf.encrypted = 1;
		shutdown(0);
	} else if (decrypt && conf.encrypted) {
		/* User wants to decrypt and journal is encrypted */
		printf("Decrypting journal...\n");

		read_password("Enter Password: ", passbuf);

		/* Load the nonce first, otherwise decryption of the key fails */
		load_nonce(nonce);
		/* Load key from disk, encrypt it and save it to memory */
		memcpy(conf.key, load_pass_file(passbuf), crypto_secretbox_KEYBYTES);
		sodium_memzero(passbuf, sizeof(passbuf));
		free(passbuf);
		passbuf = NULL;

		load_journal_from_disk();

		/* Make journal as decrypted and save it to disk */
		conf.encrypted = 0;
		shutdown(0);
	}

	if (is_encrypted()) {
		read_password("Enter Password: ", passbuf);
		/* Load the nonce first, otherwise decryption of the key fails */
		load_nonce(nonce);
		/* Load key from disk, encrypt it and save it to memory */
		memcpy(conf.key, load_pass_file(passbuf), crypto_secretbox_KEYBYTES);
		sodium_memzero(passbuf, sizeof(passbuf));
		free(passbuf);
		passbuf = NULL;
	}

	/* Load the journal file into memory */
	load_journal_from_disk();

	if (to_delete > 0) {
		if (!delete_entry(to_delete)) {
			log_fatal(1, "Entry %d not found.  Nothing to delete\n", to_delete);
		}
		shutdown(0);
	} else if (entry > 0) {
		print_single_journal_entry(entry);
	} else if (last < 0) {
		/* Show all entries */
		print_journal_entries(-1);
	} else if (last > 0) {
		print_journal_entries(last);
	} else {
		create_new_journal_entry();
	}

	shutdown(0);

	return 0;
}

void
shutdown(int prio)
{
	/* User requested a plain text backup with -B */
	if (backup)
		save_journal_to_disk(NULL, 1);

	save_journal_to_disk(get_jrnlc_journal(), 0);
	write_config();

	sodium_memzero(conf.key, crypto_secretbox_KEYBYTES);

	exit(prio);
}

void
setup_base_dir()
{
	struct stat sb;
	char *home, *xdg_home;
	int ret;

	if ((xdg_home = getenv("XDG_CONFIG_HOME")) != NULL) {
		ret = snprintf(conf.jrnlc_dir, sizeof(conf.jrnlc_dir), "%s/jrnlc", xdg_home);
		if (ret < 0 || (size_t)ret >= sizeof(conf.jrnlc_dir)) {
			log_fatal(1, "Path truncation happened.  Buffer to short to fit %s\n", conf.jrnlc_dir);
		}
	} else if ((home = getenv("HOME")) != NULL) {
		ret = snprintf(conf.jrnlc_dir, sizeof(conf.jrnlc_dir), "%s/.jrnlc", home);
		if (ret < 0 || (size_t)ret >= sizeof(conf.jrnlc_dir)) {
			log_fatal(1, "Path truncation happened.  Buffer to short to fit %s\n", conf.jrnlc_dir);
		}
	} else {
		log_fatal(1, "Neither $XDG_CONFIG_HOME nor $HOME is set!\n");
	}

	if (stat(conf.jrnlc_dir, &sb) == 0 && S_ISDIR(sb.st_mode)) {
		log_debug(1, "%s already exists\n", conf.jrnlc_dir);
	} else {
		log_debug(1, "%s does not exists.  Attempt to create it\n", conf.jrnlc_dir);
		if (mkdir(conf.jrnlc_dir, 0700) == -1) {
			log_fatal(1, "Cannot create %s directory\n", conf.jrnlc_dir);
		}
	}

	/* Set up path to the journal JSON file */
	ret = snprintf(conf.jrnlc_journal, _POSIX_PATH_MAX, "%s/journal.json", conf.jrnlc_dir);
	if (ret < 0 || (size_t)ret >= sizeof(conf.jrnlc_journal)) {
		log_fatal(1, "Path truncation happened.  Buffer to short to fit %s\n", conf.jrnlc_dir);
	}

	/* Set up path for config JSON file */
	ret = snprintf(jrnlc_config, _POSIX_PATH_MAX, "%s/config.json", conf.jrnlc_dir);
	if (ret < 0 || (size_t)ret >= sizeof(jrnlc_config)) {
		log_fatal(1, "Path truncation happened.  Buffer to short to fit %s\n", conf.jrnlc_dir);
	}

	/* Set up path for key JSON file */
	ret = snprintf(conf.key_path, _POSIX_PATH_MAX, "%s/key.json", conf.jrnlc_dir);
	if (ret < 0 || (size_t)ret >= sizeof(conf.key_path)) {
		log_fatal(1, "Path truncation happened.  Buffer to short to fit %s\n", conf.jrnlc_dir);
	}

}

const unsigned char *
get_nonce()
{
	return nonce;
}

const char*
get_jrnlc_journal()
{
	return conf.jrnlc_journal;
}

int
is_encrypted()
{
	return conf.encrypted;
}

struct config *
get_config()
{
	return &conf;
}

const char*
get_config_path()
{
	return jrnlc_config;
}

void
log_debug(int prio, const char *fmt, ...)
{
	va_list ap;

	if (debug == 0)
		return;

	if (debug < prio)
		return;

	va_start(ap, fmt);
	fprintf(stdout, "[*] ");
	vfprintf(stdout, fmt, ap);
	va_end(ap);
}

void
log_fatal(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(prio);
}

