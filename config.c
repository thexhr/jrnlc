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

#include <json-c/json.h>

#include "jrnlc.h"

int
load_config(void)
{
	struct config *conf = get_config();
	json_object *root;

	if ((root = json_object_from_file(get_config_path())) == NULL) {
		log_debug(1, "No config JSON file found, writing one\n");
		write_config();
		return -1;
	}

	log_debug(2, "Loading JSON config from %s\n", get_config_path());

	conf->encrypted = validate_int(root, "encrypted", 0, 1, 0);

	json_object_put(root);

	return 0;
}

void
write_config(void)
{
	struct config *conf = get_config();
	json_object *root;

	root = json_object_new_object();
	if (!root) {
		log_fatal(1, "Cannot create JSON object\n");
	}

	/* Add meta data for all entries */
	json_object_object_add(root, "encrypted", json_object_new_int(conf->encrypted));

	if (json_object_to_file(get_config_path(), root)) {
		log_fatal(1, "Error saving config file %s\n", get_config_path());
	}

	json_object_put(root);
}

