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

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <termios.h>

#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
#include <readpassphrase.h>
#else

#define RPP_REQUIRE_TTY 0x02

#endif

#include <json-c/json.h>

#include "jrnlc.h"
#include "sodium.h"

/*
 * Load key from key.json, decrypt it with pass
 * and return it to the caller.
 *
 * Allocated memory needs to be freed by the caller
 */
char *
load_pass_file(const char *pass)
{
	struct config *conf = get_config();
	json_object *root, *cval;
	char *k;
	int len;

	if ((root = json_object_from_file(conf->key_path)) == NULL) {
		log_fatal(1, "No passkey file found.  Abort\n");
	}

	if (!json_object_object_get_ex(root, "key", &cval)) {
		log_fatal(1, "Cannot get key value from JSON\n");
	}

	len = json_object_get_string_len(cval);

	/* decrypt_msg allocates as much memory as is needed for the original
	 * hex string, so much more than needed for the decoded key */
	k = decrypt_msg(json_object_get_string(cval), len, crypto_secretbox_KEYBYTES,
		(const unsigned char *)pass);
	if (k == NULL)
		log_fatal(1, "Wrong password, try again.\n");

	json_object_put(root);

	return k;
}

/*
 * Load nonce from key.json, convert from hex encoding to binary
 * and return it to the caller.
 *
 * Allocated memory needs to be freed by the caller
 */
void
load_nonce(unsigned char *nonce_buf)
{
	struct config *conf = get_config();
	json_object *root, *nval;
	int len;
	size_t bin_len = crypto_secretbox_NONCEBYTES;

	if ((root = json_object_from_file(conf->key_path)) == NULL) {
		log_fatal(1, "No passkey file found.  Abort\n");
	}

	if (!json_object_object_get_ex(root, "nonce", &nval)) {
		log_fatal(1, "Cannot get key nonce value from JSON\n");
	}

	len = json_object_get_string_len(nval);

	if (sodium_hex2bin(
		(unsigned char * const)nonce_buf,
		crypto_secretbox_NONCEBYTES+1,
		(const char * const)json_object_get_string(nval),
		len,
		NULL,
		(size_t * const) &bin_len,
		NULL) != 0)
	{
		log_fatal(1, "Cannot decode hex encoded nonce to binary\n");
	}

	json_object_put(root);
}

/*
 * Encrypt key with the password and save it to key.json.  Do the same with
 * the nonce, expect that the nonce has to be converted to hex before
 */
void
write_pass_file(unsigned char *key, const char *pass)
{
	struct config *conf = get_config();
	json_object *root;
	char *c, *hex;
	size_t hex_len;

	root = json_object_new_object();
	if (!root) {
		printf("Cannot create JSON object\n");
		exit(1);
	}
	c = encrypt_msg((const char *)key, strlen((const char *)key),
		(const unsigned char *)	pass);
	if (c == NULL) {
		log_fatal(1, "Encryption of key failed\n");
	}

	json_object_object_add(root, "key", json_object_new_string(c));
	free(c);
	c = NULL;

	hex_len = crypto_secretbox_NONCEBYTES * 2 + 1;
	hex = calloc_wrapper(1, hex_len);

	if (sodium_bin2hex(hex, hex_len, get_nonce(), crypto_secretbox_NONCEBYTES)
		== NULL) {
		log_fatal(1, "Conversion of nonce to HEX failed\n");
	}
	json_object_object_add(root, "nonce", json_object_new_string(hex));
	free(hex);
	hex = NULL;

	if (json_object_to_file(conf->key_path, root)) {
		log_fatal(1, "Error saving key file %s: %s\n", conf->key_path,
			json_util_get_last_err());
	}

	json_object_put(root);
}

int
get_initial_passphrase(char *passbuf)
{
	char second[MAX_PASS_LEN];

	memset(second, 0, MAX_PASS_LEN);

	read_password("Enter Password: ", passbuf);
	if (strlen(passbuf) == 0)
		return 2;

	read_password("Enter Password again: ", second);
	if (strlen(second) == 0)
		return 2;

	if (strcmp(passbuf, second) != 0) {
		sodium_memzero(second, sizeof(second));
		return 3;
	}
	sodium_memzero(second, sizeof(second));

	return 1;
}

void
read_password(const char *msg, char *passbuf)
{
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
	if (readpassphrase(msg, passbuf, sizeof(passbuf),
		RPP_REQUIRE_TTY) == NULL) {
			log_fatal(1, "Unable to read password\n");
		}
#else
	if (read_passphrase(msg, passbuf, sizeof(passbuf),
		RPP_REQUIRE_TTY) == NULL) {
			log_fatal(1, "Unable to read password\n");
	}
#endif
}

