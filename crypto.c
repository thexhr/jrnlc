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

#include <string.h>

#include "sodium.h"
#include "jrnlc.h"

/*
 * Decrypt hex encoded message hex with key k and return to caller.
 *
 * Allocated memory must be freed by the caller.
 */
char *
decrypt_msg(const char *hex, unsigned long long hex_len, size_t d_len,
	const unsigned char *k)
{
	char *d;

	d = calloc_wrapper(1, hex_len);

	log_debug(3, "[decrypt] hex_len: %ld, d_len: %ld\n", hex_len, d_len);

	if (sodium_hex2bin(
		(unsigned char * const)d, 	/* buffer for binary result */
		hex_len, 					/* max characters to put in d */
		hex, 						/* orginal hex string */
		hex_len, 					/* characters to parse */
		NULL, 						/* chars to ignore */
		(size_t * const) &hex_len, 	/* len of d */
		NULL) != 0) 				/* can be NULL */
	{
		log_debug(1, "Converting HEX to binary failed\n");
		free(d);
		return NULL;
	}

	/* original length of the string plus length of the authentication tag */
	d_len += crypto_secretbox_MACBYTES;

	log_debug(4, "[decrypt] hex: %s\n", hex);
	log_debug(3, "[decrypt] hex_len: %ld, d_len: %ld\n", hex_len, d_len);

	/* According to https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox
	 * overlapping regions for d are fine */
	if (crypto_secretbox_open_easy(
		(unsigned char *)d, 		/* buffer for plain text */
		(unsigned char *)d, 		/* enc message + auth tag */
		d_len, 						/* length of enc message + auth tag */
		get_nonce(),
		k) != 0)
	{
		log_debug(1, "Error decrypting message\n");
		free(d);
		return NULL;
	}

	return d;
}

/*
 * Encrypt message m with key k and return hex encoded string.
 *
 * Allocated memory must be freed by the caller.
 */
char *
encrypt_msg(const char *m, unsigned long long m_len, 
	const unsigned char *k)
{
	unsigned char *c;
	char *hex;
	size_t c_len, hex_len;

	c_len = m_len + crypto_secretbox_MACBYTES;
	c = malloc_wrapper(c_len);

	if (crypto_secretbox_easy(c, (const unsigned char*)m, m_len, get_nonce(), k) != 0) {
		log_debug(1, "Error decrypting %s\n", m);
		free(c);
		return NULL;
	}

	/* Size according to https://libsodium.gitbook.io/doc/helpers */
	hex_len = c_len * 2 + 1;
	hex = malloc_wrapper(hex_len);

	/* bin2hex guarantees NUL termination */
	if (sodium_bin2hex(hex, hex_len, c, c_len) == NULL) {
		log_debug(1, "Converting ciphertext to HEX failed\n");
		free(c);
		free(hex);
		return NULL;
	}

	free(c);

	return hex;
}
