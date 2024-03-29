/*
 * Lock-less NULL terminated single linked list
 *
 * modified from <lib/llist.c>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/interrupt.h>
#include "skb_llist.h"

/**
 * skb_llist_reverse_order - reverse order of a skb_llist chain
 * @head:	first item of the list to be reversed
 *
 * Reverse the order of a chain of skb_llist entries and return the
 * new first entry.
 */
struct sk_buff *skb_llist_reverse_order(struct sk_buff *head)
{
	struct sk_buff *new_head = NULL;

	while (head) {
		struct sk_buff *tmp = head;
		head = head->next;
		tmp->next = new_head;
		new_head = tmp;
	}

	return new_head;
}
EXPORT_SYMBOL(skb_llist_reverse_order);
