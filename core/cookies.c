// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright 2018-2019 IBM Corp.  */

#include <stdint.h>
#include <compiler.h>
#include <hlist.h>
#include <cookies.h>
#include <ccan/container_of/container_of.h>
#include <mem_region-malloc.h>
#include <utils.h>

static int cookie_is_valid(struct hlist_head *head, uint64_t cookie)
{
	struct hlist_node *node;
	struct hlist_node *next;
	struct cookie_table_entry *cte;

	if (cookie == 0ULL)
		return 0;

	hlist_for_each_safe(node, next, head) {
		cte = hlist_entry(node, struct cookie_table_entry, link);
		if (cte->cookie == cookie)
			return 0;
	}

	return 1;
}

/*
 * generate a cookie value. The value of the cookie must have
 * bits in the non-mask locations set to zero, and cannot
 * be lower than the min_value.
 */
uint64_t cookie_generate(struct hlist_head *cookie_table,
			size_t cookie_hashbits, void *data,
			uint64_t mask,
			uint64_t min_value)
{
	uint32_t key;
	uint64_t cookie;
	struct hlist_head *head;
	struct cookie_table_entry *cte;

	cte = zalloc(sizeof(struct cookie_table_entry));
	if (!cte)
		return 0;

	/*
	 * Ensure a unique cookie so that we can recover the
	 * pointer provided by the user.
	 */
	do {
		do {
			cookie = generate_random_number() & mask;
		} while (cookie < min_value);

		key = hash_64_generic(cookie, cookie_hashbits);

		head = &cookie_table[key];

	} while(! cookie_is_valid(head, cookie));

	cte->cookie = cookie;
	cte->data = data;
	hlist_add_head(&cte->link, head);

	return cookie;
}

void *cookie_find_del(struct hlist_head *cookie_table, uint64_t cookie,
			size_t cookie_hashbits)
{
	void *data;
	uint32_t key;
	struct hlist_node *node;
	struct hlist_node *next;
	struct hlist_head *head;
	struct cookie_table_entry *cte;

	key = hash_64_generic(cookie, cookie_hashbits);

	head = &cookie_table[key];

	data = NULL;
	hlist_for_each_safe(node, next, head) {
		cte = hlist_entry(node, struct cookie_table_entry, link);
		if (cte->cookie == cookie) {
			hlist_del(&cte->link);
			data = cte->data;
			free(cte);
			break;
		}
	}

	return data;
}

void cookie_cleanup(struct hlist_head *cookie_table, size_t num_entries)
{
	uint32_t key;
	struct hlist_node *node, *next;
	struct hlist_head *head;
	struct cookie_table_entry *cte;

	for (key=0; key < num_entries; key++) {
		head = &cookie_table[key];
		hlist_for_each_safe(node, next, head) {
			cte = hlist_entry(node, struct cookie_table_entry,
					  link);
			hlist_del(&cte->link);
			free(cte);
		}
	}
}
