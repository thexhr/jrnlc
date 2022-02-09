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

#include <sys/queue.h>

#include <limits.h>

#include <json-c/json.h>

#include "sodium.h"

#define MAX_DATE 11
#define MAX_TIME 6
#define MAX_TITLE 512
#define MAX_LINE 80
#define MAX_PASS_LEN 255

#define VERSION "2022.a"

struct journal_entry {
	LIST_ENTRY(journal_entry) entries;
	int number;
	char *date;
	char *time;
	char *title;
	int title_len;
	char *body;
	int body_len;
};

struct config {
	char jrnlc_dir[_POSIX_PATH_MAX];
	char jrnlc_journal[_POSIX_PATH_MAX];
	char key_path[_POSIX_PATH_MAX];
	unsigned char key[crypto_secretbox_KEYBYTES];
	int encrypted;
};

/* jrnlc. */
void shutdown(int);
void setup_base_dir(void);
const char *get_jrnlc_journal(void);
const char *get_config_path(void);
const unsigned char *get_nonce(void);
struct config *get_config(void);
void log_debug(int, const char *, ...);
void log_fatal(int, const char *, ...);
int is_encrypted(void);

/* json.c */
void print_journal_entry(const struct journal_entry *);
void create_new_journal_entry(void);
void load_journal_from_disk(void);
void save_journal_to_disk(const char *, int);
void print_journal_entries(int);
void print_single_journal_entry(int);
int delete_entry(int);
char *validate_string(json_object *, const char *, const char *);
char *validate_body(json_object *);
int validate_int(json_object *, const char *, int, int, int);

/* config.c */
int load_config(void);
void write_config(void);

/* util.c */
int get_number(const char *);
int create_date(char *, size_t);
int create_time(char *, size_t);
void sandbox(void);
void *malloc_wrapper(size_t);
void *calloc_wrapper(size_t, size_t);

/* crypt.c */
char* encrypt_msg(const char *, unsigned long long, const unsigned char *);
char* decrypt_msg(const char *, unsigned long long, size_t,
	const unsigned char *);

/* key.c */
char *load_pass_file(const char *);
void write_pass_file(unsigned char *, const char *);
int get_initial_passphrase(char *) __attribute((warn_unused_result));
void load_nonce(unsigned char *);
void simple_password_reader(const char *, char *);
void read_password(const char *, char *);

/* recallocarray.c */
#ifndef recallocarray
void *recallocarray(void *, size_t, size_t, size_t);
#endif

/* readpassphrase.c */
#if !defined(__OpenBSD__) || !defined(__FreeBSD__) || !defined(__DragonFly__)
char *read_passphrase(const char *, char *, size_t, int);
#endif
