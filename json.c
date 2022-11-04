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

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <json-c/json.h>

#include "sodium.h"
#include "jrnlc.h"

static LIST_HEAD(listhead, journal_entry) head = LIST_HEAD_INITIALIZER(head);
static struct journal_entry *last_entry = NULL;
static int list_total = 0;

void
print_journal_entry(const struct journal_entry *e)
{
	printf("[%d] [%s %s] %s\n\n%s\n\n", e->number, e->date, e->time,
		e->title, e->body);
}

void
print_journal_entries(int last)
{
	struct journal_entry *e;
	int when;

	/* Show all entries */
	if (last == -1)
		when = 0;
	else
		when = list_total - last;

	/* If the user wants to see more entries than available, show all of them */
	if (when < 0)
		when = 0;

	LIST_FOREACH(e, &head, entries) {
		if (e->number <= when)
			continue;
		print_journal_entry(e);
	}
}

void
print_single_journal_entry(int id)
{
	struct journal_entry *e;

	LIST_FOREACH(e, &head, entries) {
		if (e->number == id)
			print_journal_entry(e);
	}
}

int
delete_entry(int id)
{
	struct journal_entry *e;

	LIST_FOREACH(e, &head, entries) {
		if (e->number == id) {
			LIST_REMOVE(e, entries);
			return 1;
		}
	}

	return 0;
}

void
create_new_journal_entry()
{
	struct journal_entry *e;
	char buf[MAX_LINE];
	char *input_buf, *ptr;
	int i = 1, input_len = 0;

	printf("[One title line, one blank line, then the body. End with ^D on a blank line]\n");
	input_buf = NULL;

	while(fgets(buf, sizeof(buf), stdin)) {
		input_buf = recallocarray(input_buf, i-1, i, MAX_LINE + 1);
		if (input_buf == NULL) {
			log_fatal(1, "memory allocation failed\n");
		}
		input_buf = strcat(input_buf, buf);
		i++;
	}

	if (input_buf == NULL) {
		printf("Empty entry, abort\n");
		free(input_buf);
		input_buf = NULL;
		return;
	}

	/* fgets() ensures that input_buf is NUL terminated */
	input_len = strlen(input_buf);

	e = malloc_wrapper(sizeof(struct journal_entry));

	ptr = input_buf;
	i = 0;

	/* Skip over the title line */
	while (*ptr++ != '\n') {
		/* Seems we found no newline and all input is in one line */
		if (i >= input_len) {
			log_fatal(1, "Please enter one title line, followed by a blank line, "\
				"then the body\n");
		}
		i++;
	}

	/* The length of the title line is longer than expected, cut it */
	if (i > MAX_TITLE-1)
		i = MAX_TITLE;

	log_debug(3, "i: %d, len: %d\n", i, input_len);

	e->title = calloc_wrapper(1, i+1);
	snprintf(e->title, i+1, "%s", input_buf);

	/* Should never happen, but better be safe than sorry */
	assert(input_len - i > 0);

	e->body = calloc_wrapper(1, input_len - i);

	/* Skip over newlines at the beginning */
	while (*ptr == '\n') ptr++;

	snprintf(e->body, input_len - i, "%s", ptr);

	free(input_buf);
	input_buf = NULL;

	e->time = calloc_wrapper(1, MAX_TIME);
	create_time(e->time, MAX_TIME);

	e->date = calloc_wrapper(1, MAX_DATE);
	create_date(e->date, MAX_DATE);

	e->number = list_total + 1;

	if (last_entry != NULL)
		LIST_INSERT_AFTER(last_entry, e, entries);
	else
		LIST_INSERT_HEAD(&head, e, entries);
}

void
load_journal_from_disk()
{
	struct config *conf = get_config();
	struct journal_entry *e, *temp_e = NULL;
	char *m;
	json_object *root;
	size_t i, temp_n, temp_len;
	int ret;

	LIST_INIT(&head);

	if ((root = json_object_from_file(get_jrnlc_journal())) == NULL) {
		log_debug(1, "No journal JSON file found: %s\n", get_jrnlc_journal());
		return;
	}

	json_object *journal_entries;
	if (!json_object_object_get_ex(root, "entries", &journal_entries)) {
		log_fatal(1, "Cannot find a [entries] array in %s\n", get_jrnlc_journal());
	}

	temp_n = json_object_array_length(journal_entries);
	for (i=0; i < temp_n; i++) {
		json_object *temp = json_object_array_get_idx(journal_entries, i);
		assert(temp != NULL);

		e = malloc_wrapper(sizeof(struct journal_entry));

		/* Length of the plain text title and body */
		e->title_len = validate_int(temp, "title_len", 0, MAX_TITLE, 0);
		e->body_len  = validate_int(temp, "body_len", 0, -1, 0);

		e->number = validate_int(temp, "number", 0, 1, i+1);

		if (is_encrypted()) {
			e->time = validate_string(temp, "time", "HH:MM");
			temp_len = strlen(e->time);

			m = decrypt_msg(e->time, temp_len, MAX_TIME-1, conf->key);
			if (m == NULL) {
				log_fatal(1, "Cannot decrypt message time\n");
			}

			ret = snprintf(e->time, MAX_TIME, "%s", m);
			log_debug(3, "decrypted time: %s with len %ld\n", e->time, strlen(e->time));
			if (ret < 0 || (size_t)ret >= MAX_TIME) {
				log_debug(2, "Path truncation for time happened.  Buffer to short to fit %d\n", ret);
			}

			free(m);
			m = NULL;
			/* --------------------------------------------------------------------- */
			e->date = validate_string(temp, "date", "YYYY-MM-DD");
			temp_len = strlen(e->date);

			m = decrypt_msg(e->date, temp_len, MAX_DATE-1, conf->key);
			if (m == NULL) {
				log_fatal(1, "Cannot decrypt message date\n");
			}

			ret = snprintf(e->date, MAX_DATE, "%s", m);
			if (ret < 0 || (size_t)ret >= MAX_DATE) {
				log_debug(2, "Path truncation for date happened.  Buffer to short to fit %d\n", ret);
			}

			free(m);
			m = NULL;
			/* --------------------------------------------------------------------- */
			e->title = validate_string(temp, "title", "Empty title");
			/* e->title is always NUL terminated */
			temp_len = strlen(e->title);

			m = decrypt_msg(e->title, temp_len, e->title_len, conf->key);
			if (m == NULL) {
				log_fatal(1, "Cannot decrypt message title\n");
			}

			ret = snprintf(e->title, e->title_len + 1, "%s", m);
			if (ret < 0 || (size_t)ret >= MAX_TITLE) {
				log_debug(2, "Path truncation for title happened.  Buffer to short to fit %d\n", ret);
			}

			free(m);
			m = NULL;

			/* --------------------------------------------------------------------- */
			e->body = validate_body(temp);
			/* Only try to decrypt if body was properly parsed */
			if (e->body != NULL) {
				/* e->body is always NUL terminated */
				temp_len = strlen(e->body);

				m = decrypt_msg(e->body, temp_len, e->body_len, conf->key);
				if (m == NULL) {
					log_fatal(1, "Cannot decrypt message body\n");
				}

				ret = snprintf(e->body, e->body_len+1, "%s", m);
				if (ret < 0) {
					log_debug(2, "Path truncation happened.  Buffer to short to fit %d\n", ret);
				}
				free(m);
				m = NULL;
			} else {
				/* body couldn't be read form the JSON, so store an empty NUL
				 * terminated string */
				e->body = strndup("", 0);
			}
		} else {
			e->time = validate_string(temp, "time", "HH:MM");
			e->date = validate_string(temp, "date", "YYYY-MM-DD");
			e->title = validate_string(temp, "title", "Empty title");
			e->body = validate_body(temp);
			if (e->body == NULL) {
				/* body couldn't be read form the JSON, so store an empty NUL
				 * terminated string */
				e->body = strndup("", 0);
			}
		}

		/* Insert first element at head, then one after another to preserve
		 * the order */
		if (temp_e == NULL)
			LIST_INSERT_HEAD(&head, e, entries);
		else
			LIST_INSERT_AFTER(temp_e, e, entries);

		temp_e = e;

 		list_total++;
	}

	if (temp_e != NULL)
		last_entry = temp_e;

	json_object_put(root);
}

void
save_journal_to_disk(const char *path, int always_plain)
{
	struct config *conf = get_config();
	struct journal_entry *e;
	json_object *root;
	char *c;

	root = json_object_new_object();
	if (!root)
		log_fatal(1, "Cannot create JSON object\n");

	json_object *entries = json_object_new_array();
	json_object_object_add(root, "entries", entries);

	/* Create JSON array containing all entries */
	LIST_FOREACH(e, &head, entries) {
		json_object *cobj = json_object_new_object();
		assert(cobj != NULL);

		/*
		 * Store length of plain text entries.  Needed for proper decryption later on.
		 * This is an information leak since an attacker can see the length of the
		 * plain text.  However, since the cipher texts are not padded to have an
		 * uniform length, an attacker could still distinguish a shorter plain text
		 * from a longer, so I consider this risk acceptable.
		 */
		e->title_len = strlen(e->title);
		e->body_len  = strlen(e->body);
		json_object_object_add(cobj, "title_len", json_object_new_int(e->title_len));
		json_object_object_add(cobj, "body_len", json_object_new_int(e->body_len));
		json_object_object_add(cobj, "number", json_object_new_int(e->number));


		/* The user requested a plain text backup with -B */
		if (always_plain) {
			json_object_object_add(cobj, "time", json_object_new_string(e->time));
			json_object_object_add(cobj, "date", json_object_new_string(e->date));
			json_object_object_add(cobj, "title", json_object_new_string(e->title));
			json_object_object_add(cobj, "body", json_object_new_string(e->body));
			goto again;
		} else if (is_encrypted()) {
			log_debug(4, "Encrypt time %s with len %ld\n", e->time, strlen(e->time));
			c = encrypt_msg(e->time, strlen(e->time), conf->key);
			if (c == NULL) {
				log_fatal(1, "Encryption of time failed\n");
			}
			json_object_object_add(cobj, "time", json_object_new_string(c));
			free(c);
			c = NULL;

			/* --------------------------------------------------------------------- */
			log_debug(4, "Encrypt date %s with len %ld\n", e->date, strlen(e->date));
			c = encrypt_msg(e->date, strlen(e->date), conf->key);
			if (c == NULL) {
				log_fatal(1, "Encryption of date failed\n");
			}
			json_object_object_add(cobj, "date", json_object_new_string(c));
			free(c);
			c = NULL;

			/* --------------------------------------------------------------------- */
			c = encrypt_msg(e->title, strlen(e->title), conf->key);
			if (c == NULL) {
				log_fatal(1, "Encryption of title failed\n");
			}
			json_object_object_add(cobj, "title", json_object_new_string(c));
			free(c);
			c = NULL;

			/* --------------------------------------------------------------------- */
			c = encrypt_msg(e->body, strlen(e->body), conf->key);
			if (c == NULL) {
				log_fatal(1, "Encryption of body failed\n");
			}
			json_object_object_add(cobj, "body", json_object_new_string(c));
			free(c);
			c = NULL;
		} else {
			json_object_object_add(cobj, "time", json_object_new_string(e->time));
			json_object_object_add(cobj, "date", json_object_new_string(e->date));
			json_object_object_add(cobj, "title", json_object_new_string(e->title));
			json_object_object_add(cobj, "body", json_object_new_string(e->body));
		}
again:
		json_object_array_add(entries, cobj);
	}

	if (always_plain) {
		fprintf(stderr, "%s", json_object_to_json_string(root));
	} else {
		if (json_object_to_file(path, root) == -1) {
			printf("Error saving %s: %s\n", path, json_util_get_last_err());
		}
	}

	json_object_put(root);

}

char *
validate_string(json_object *jobj, const char *desc, const char *def)
{
	char *s;
	json_object *cval;
	int len;

	if (jobj == NULL) {
		log_debug(1, "Empty JSON object for %s.  Using default\n", desc);
		return strndup(def, strlen(def));
	}

	if (!json_object_object_get_ex(jobj, desc, &cval)) {
		log_debug(1, "Cannot get value for %s from JSON.  Using default\n", desc);
		return strndup(def, strlen(def));
	}

	len = json_object_get_string_len(cval);
	if (len <= 0) {
		log_debug(1, "Received empty string for %s.  Using default\n", desc);
		return strndup(def, strlen(def));
	}

	s = strndup(json_object_get_string(cval), len);
	if (s == NULL) {
		log_fatal(1, "Memory allocation for %s failed.\n", desc);
	}

	return s;
}


char *
validate_body(json_object *jobj)
{
	char *s;
	json_object *cval;
	int len;

	if (jobj == NULL) {
		log_debug(1, "Empty JSON object\n");
		return NULL;
	}

	if (!json_object_object_get_ex(jobj, "body", &cval)) {
		log_debug(1, "Cannot get body from JSON.\n");
		return NULL;
	}

	len = json_object_get_string_len(cval);
	if (len <= 0) {
		log_debug(1, "Received empty body\n");
		return NULL;
	}

	s = strndup(json_object_get_string(cval), len);
	if (s == NULL) {
		log_fatal(1, "Memory allocation for body failed.\n");
	}

	return s;
}

int
validate_int(json_object *jobj, const char *desc, int min, int max, int def)
{
	json_object *cval;
	int value;

	if (jobj == NULL) {
		log_debug(1, "Empty JSON object for %s.  Using default\n", desc);
		return def;
	}

	if (!json_object_object_get_ex(jobj, desc, &cval)) {
		log_debug(1, "Cannot get value for %s from JSON.  Using default\n", desc);
		return def;
	}

	value = json_object_get_int(cval);

	if (max == -1)
		return value;

	if (value < min || value > max) {
		log_debug(1, "Error.  Value for %s (%d) is out of range [%d, %d]\n",
			desc, value, min, max);
		log_debug(1, "Resetting to a default value: %d\n", def);
		return def;
	}

	return value;
}


