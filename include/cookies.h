/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Cookies
 *
 * Copyright 2018, IBM Corporation.
 *
 */

#ifndef COOKIES_H
#define COOKIES_H

#include <hlist.h>

/**
 * Hash table entry for active cookies used for exception reflection and
 * start-cpu RTAS calls. i.e maps a pointer to a cookie and vice-versa.
 */
struct cookie_table_entry {
	uint64_t cookie;
	void *data;
	struct hlist_node link;
};

#define COOKIE_HASHBITS	8
#define COOKIE_HASHSIZE	(1 << COOKIE_HASHBITS)

uint64_t cookie_generate(struct hlist_head *cookie_table, size_t cookie_hashbits,
			void *data, uint64_t mask, uint64_t minval);
void *cookie_find_del(struct hlist_head *cookie_table, uint64_t cookie,
			size_t cookie_hashbits);
void cookie_cleanup(struct hlist_head *cookie_table, size_t num_entries);

#endif /* COOKIES_H */
