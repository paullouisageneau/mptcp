/*
 *	MPTCP implementation - Random Linear Coding
 *
 *	Paul-Louis Ageneau <paul-louis.ageneau@polytechnique.org>
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/kconfig.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <net/mptcp.h>

#define MPTCP_RLC_MAX_COMPONENTS	1024
#define MPTCP_RLC_MAX_GENERATION	256
#define MPTCP_FLAGS_FREE_SKB		0x01
#define MPTCP_FLAGS_PADDED		0x02

typedef struct mptcp_rlc_combination {
	struct mptcp_rlc_combination *next;
	uint64_t sequence;
	uint32_t first;					/* first component number */
	uint16_t count;					/* number of components */
	uint16_t len;					/* real data length */
	struct sk_buff *skb;				/* buffer */
	uint8_t flags;					/* flags */
	uint8_t coeffs[MPTCP_RLC_MAX_COMPONENTS];	/* coefficients */

} mptcp_rlc_combination_t;

uint8_t mptcp_rlc_generate(uint64_t *seed)
{
	uint8_t value;

	if(!seed)
		return 0;

	do {
		/* Knuth's 64-bit linear congruential generator */
		*seed = (uint64_t)(*seed*6364136223846793005 + 1442695040888963407);
		value = (uint8_t)(*seed >> 56);
	} while(!value);

	return value;
}

uint8_t mptcp_rlc_gadd(uint8_t a, uint8_t b)
{
	return a ^ b;
}

uint8_t mptcp_rlc_gmul(uint8_t a, uint8_t b)
{
	uint8_t p = 0;
	uint8_t i;
	uint8_t carry;

	for(i = 0; i < 8; ++i) {
		if (b & 1) p ^= a;
		carry = (a & 0x80);
		a <<= 1;
		if (carry) a ^= 0x1b;	 /* 0x1b is x^8 modulo x^8 + x^4 + x^3 + x + 1 */
		b >>= 1;
	}

	return p;
}

uint8_t mptcp_rlc_add(uint8_t a, uint8_t b)
{
	return mptcp_rlc_gadd(a, b);
}

uint8_t mptcp_rlc_mul(uint8_t a, uint8_t b)
{
	static uint8_t *table = NULL;

	if(!table) {
		unsigned i, j;

		table = kmalloc(256*256, GFP_ATOMIC);
		BUG_ON(!table);

		for(i = 0; i < 256; ++i) {
			for(j = 0; j < 256; ++j) {
				table[i*256+j] = mptcp_rlc_gmul((uint8_t)i, (uint8_t)j);
			}
		}
	}

	return table[a*256+b];
}

uint8_t mptcp_rlc_inv(uint8_t a)
{
	static uint8_t *table = NULL;

	if(!table) {
		unsigned i, j;

		table = kmalloc(256, GFP_ATOMIC);
		BUG_ON(!table);

		table[0] = 0;
		for(i = 1; i < 256; ++i) {
			for(j = i; j < 256; ++j) {
				if(mptcp_rlc_mul((uint8_t)i, (uint8_t)j) == 1) { /* then mptcp_rlc_mul(j,i) == 1 */
					table[i] = (uint8_t)j;
					table[j] = (uint8_t)i;
					break;
				}
			}
		}
	}

	BUG_ON(a == 0);
	return table[a];
}

/* Optimized memory XOR */
void *mptcp_rlc_memadd(void *a, const void *b, size_t len)
{
	const size_t n = len / sizeof(unsigned long);
	size_t i;

	for(i = 0; i < n; ++i)
		((unsigned long*)a)[i]^= ((const unsigned long*)b)[i];
	for(i = n*sizeof(unsigned long); i < len; ++i)
		((unsigned char*)a)[i]^= ((const unsigned char*)b)[i];

	return a;
}

mptcp_rlc_combination_t *mptcp_rlc_combination_create_null(void)
{
	mptcp_rlc_combination_t *combination = kmalloc(sizeof(mptcp_rlc_combination_t), GFP_ATOMIC);
	if(!combination)
		return NULL;

	combination->next = NULL;
	combination->sequence = 0;
	combination->first = 0;
	combination->count = 0;
	combination->len = 0;
	combination->skb = NULL;
	combination->flags = 0;
	return combination;
}

mptcp_rlc_combination_t *mptcp_rlc_combination_create(uint32_t component, struct sk_buff *skb, bool copy)
{
	mptcp_rlc_combination_t *combination = kmalloc(sizeof(mptcp_rlc_combination_t), GFP_ATOMIC);
	if(!combination)
		return NULL;

	combination->next = NULL;
	combination->sequence = 0;
	combination->first = component;
	combination->count = 1;
	combination->len = skb->len;
	combination->flags = 0;
	combination->coeffs[0] = 1;

	if(copy) {
		combination->skb = skb_copy(skb, GFP_ATOMIC);
		if(!combination->skb) {
			kfree(combination);
			return NULL;
		}

		combination->flags|= MPTCP_FLAGS_FREE_SKB;	/* skb must be freed on deletion */
	}
	else {
		combination->skb = skb;
	}

	skb_linearize(combination->skb);
	return combination;
}

void mptcp_rlc_combination_free(mptcp_rlc_combination_t *combination)
{
	if(!combination)
		return;

	if(combination->flags & MPTCP_FLAGS_FREE_SKB)
		dev_kfree_skb_any(combination->skb);

	kfree(combination->next);
	kfree(combination);
}

void mptcp_rlc_combination_clean(mptcp_rlc_combination_t *combination)
{
	uint32_t offset;

	/* Remove zeros at the end of coeffs */
	while(combination->count && combination->coeffs[combination->count-1] == 0)
		--combination->count;

	/* Remove zeros at the beginning of coeffs */
	offset = 0;
	while(offset < combination->count && combination->coeffs[offset] == 0)
		++offset;
	if(offset) {
		combination->first+= offset;
		combination->count-= offset;
		memmove(combination->coeffs, combination->coeffs + offset, combination->count);
	}
}

int mptcp_rlc_combination_clean_padding(mptcp_rlc_combination_t *combination)
{
	/* Remove padding if necessary */
	if(combination->flags & MPTCP_FLAGS_PADDED) {
		if(combination->count == 1 && combination->coeffs[0] == 1	/* do not call is_coded here */
			&& combination->skb && combination->skb->len > 0) {

			unsigned int last = combination->skb->len - 1;
			while(last > 0 && combination->skb->data[last] == 0x00)
				--last;

			/* TODO */
			/*if(last > 0 && combination->skb->data[last] != 0x80)
				printk(KERN_NOTICE "MPTCP-RLC: Invalid padding in decoded buffer\n");*/

			combination->flags&= ~MPTCP_FLAGS_PADDED;
			combination->len = last + 1;
			skb_trim(combination->skb, combination->len);
		}
	}
	else {
		if(combination->skb)
			combination->len = combination->skb->len;
		else
			combination->len = 0;
	}

	return true;
}

bool mptcp_rlc_combination_shift(mptcp_rlc_combination_t *combination, uint32_t first)
{
	if(combination->count) {
		if(first > combination->first) {
			mptcp_rlc_combination_clean(combination);
			if(first > combination->first)
				return false;
		}

		if(first < combination->first) {
			uint32_t offset = combination->first - first;

			BUG_ON(offset + combination->count >= MPTCP_RLC_MAX_COMPONENTS);

			memmove(combination->coeffs + offset, combination->coeffs, combination->count);
			memset (combination->coeffs, 0, offset);

			combination->first = first;
			combination->count+= offset;
		}
	}
	else {
		combination->first = first;
	}

	return true;
}

void mptcp_rlc_combination_add_component(mptcp_rlc_combination_t *combination, uint32_t component, uint8_t coefficient)
{
	if(combination->count) {
		uint32_t offset;

		if(component < combination->first)
			BUG_ON(!mptcp_rlc_combination_shift(combination, component));

		BUG_ON(component >= combination->first + MPTCP_RLC_MAX_COMPONENTS);

		/* component >= combination->first here */
		offset = component - combination->first;
		if(offset >= combination->count) {
			uint32_t i;
			for(i = combination->count; i <= offset; ++i)
				combination->coeffs[i] = 0;

			combination->count = offset + 1;
		}

		combination->coeffs[offset] = mptcp_rlc_add(combination->coeffs[offset], coefficient);
	}
	else {
		combination->first = component;
		combination->count = 1;
		combination->coeffs[0] = coefficient;
	}
}

uint8_t mptcp_rlc_combination_coeff(mptcp_rlc_combination_t *combination, uint32_t component)
{
	if(component >= combination->first && component < combination->first + combination->count)
		return combination->coeffs[component-combination->first];
	else
		return 0;
}

bool mptcp_rlc_combination_is_coded(mptcp_rlc_combination_t *combination)
{
	mptcp_rlc_combination_clean(combination);

	if(combination->count != 1)
		return true;

	if(combination->coeffs[0] != 1)
		return true;

	return false;
}

/* c = c*kc + d*kd */
bool mptcp_rlc_combination_combine(mptcp_rlc_combination_t *c, uint8_t kc, const mptcp_rlc_combination_t *d, uint8_t kd)
{
	uint32_t i;

	BUG_ON(!c);

	if(!d || !d->skb)
		kd = 0;

	if(kc == 1 && kd == 0)
		return true;	/* nothing to do */

	/* Add values */
	if(kd != 0) {
		if(!c->skb) {
			/* Allocate */
			if((d->flags & MPTCP_FLAGS_PADDED) || skb_tailroom(d->skb) >= 1)
				c->skb = skb_copy(d->skb, GFP_ATOMIC);
			else
				c->skb = skb_copy_expand(d->skb, skb_headroom(d->skb), 1, GFP_ATOMIC);

			if(!c->skb)
				return false;

			c->flags|= MPTCP_FLAGS_FREE_SKB;

			if(kd == 1) {
				/* Direct copy */
				memcpy(c->skb->data, d->skb->data, d->skb->len);
			}
			else {
				/* Multiply and copy */
				for(i = 0; i < d->skb->len; ++i)
					c->skb->data[i] = mptcp_rlc_mul(d->skb->data[i], kd);
			}

			if(!(d->flags & MPTCP_FLAGS_PADDED)) {
				/* 1-byte ISO/IEC 7816-4 padding*/
				*skb_put(c->skb, 1) = mptcp_rlc_mul(0x80, kd);
				c->flags|= MPTCP_FLAGS_PADDED;
			}
		}
		else {
			unsigned int padded_len = d->skb->len + (d->flags & MPTCP_FLAGS_PADDED ? 0 : 1);

			if(c->skb->len < padded_len) {
				unsigned int padding = padded_len - c->skb->len;

				/* Reallocate if necessary */
				if(skb_tailroom(c->skb) < padding) {
					struct sk_buff *newskb = skb_copy_expand(c->skb, skb_tailroom(c->skb), padding, GFP_ATOMIC);
					if(!newskb)
						return false;

					dev_kfree_skb_any(c->skb);
					c->skb = newskb;
					c->flags|= MPTCP_FLAGS_FREE_SKB;
				}

				if(mptcp_rlc_combination_is_coded(c) || (c->flags & MPTCP_FLAGS_PADDED)) {
					/* Zero padding */
					memset(skb_put(c->skb, padding), 0x00, padding);
				}
				else {
					/* ISO/IEC 7816-4 padding */
					*skb_put(c->skb, 1) = 0x80;
					memset(skb_put(c->skb, padding-1), 0x00, padding-1);
				}
			}

			/* Add */
			if(kc == 1 && kd == 1) {
				mptcp_rlc_memadd(c->skb->data, d->skb->data, d->skb->len);
			}
			else if(kc == 1) {	/* optimization since kc == 1 and kd != 1 is probable here */
				for(i = 0; i < d->skb->len; ++i)
					c->skb->data[i] = mptcp_rlc_add(c->skb->data[i], mptcp_rlc_mul(d->skb->data[i], kd));
			}
			else {
				for(i = 0; i < d->skb->len; ++i)
					c->skb->data[i] = mptcp_rlc_add(mptcp_rlc_mul(c->skb->data[i], kc), mptcp_rlc_mul(d->skb->data[i], kd));
			}

			if(!(d->flags & MPTCP_FLAGS_PADDED)) {
				/* 1-byte ISO/IEC 7816-4 padding*/
				c->skb->data[d->skb->len] = mptcp_rlc_add(mptcp_rlc_mul(c->skb->data[d->skb->len], kc), mptcp_rlc_mul(0x80, kd));
				c->flags|= MPTCP_FLAGS_PADDED;
			}
		}
	}
	else {
		if(!c || !c->skb)
			return true;	/* nothing to do */

		/* Add padding to c if necessary */
		if(!(mptcp_rlc_combination_is_coded(c) || (c->flags & MPTCP_FLAGS_PADDED))) {

			/* Reallocate if necessary */
			if(skb_tailroom(c->skb) < 1) {
				struct sk_buff *newskb = skb_copy_expand(c->skb, 0, 1, GFP_ATOMIC);
				if(!newskb)
					return false;

				dev_kfree_skb_any(c->skb);
				c->skb = newskb;
				c->flags|= MPTCP_FLAGS_FREE_SKB;
			}

			/* 1-byte ISO/IEC 7816-4 padding */
			*skb_put(c->skb, 1) = 0x80;
			c->flags|= MPTCP_FLAGS_PADDED;
		}

		/* kc != 1 here */
		for(i = 0; i < c->skb->len; ++i)
			c->skb->data[i] = mptcp_rlc_mul(c->skb->data[i], kc);
	}

	/* Add coefficients */
	if(kc != 1) {
		for(i = 0; i < c->count; ++i)
			c->coeffs[i] = mptcp_rlc_mul(c->coeffs[i], kc);
	}

	if(kd != 0) {
		for(i = 0; i < d->count; ++i)
			mptcp_rlc_combination_add_component(c, d->first + i, mptcp_rlc_mul(d->coeffs[i], kd));
	}

	return true;
}

/* c = c + d */
bool mptcp_rlc_combination_add(mptcp_rlc_combination_t *c, const mptcp_rlc_combination_t *d)
{
	return mptcp_rlc_combination_combine(c, 1, d, 1);
}

/* c = c*k */
bool mptcp_rlc_combination_mul(mptcp_rlc_combination_t *c, uint8_t k)
{
	return mptcp_rlc_combination_combine(c, k, NULL, 0);
}

/* c = c/k */
bool mptcp_rlc_combination_div(mptcp_rlc_combination_t *c, uint8_t k)
{
	return mptcp_rlc_combination_combine(c, mptcp_rlc_inv(k), NULL, 0);
}

mptcp_rlc_combination_t *mptcp_rlc_combination_random_combine(mptcp_rlc_combination_t *list)
{
	mptcp_rlc_combination_t *c;

	uint64_t seed;
	get_random_bytes(&seed, sizeof(seed));

	c = mptcp_rlc_combination_create_null();
	if(!c)
		return NULL;

	while(list) {
		uint8_t coeff = mptcp_rlc_generate(&seed);
		if(!mptcp_rlc_combination_combine(c, 1, list, coeff)) {
			mptcp_rlc_combination_free(c);
			return NULL;
		}

		list = list->next;
	}

	return c;
}

mptcp_rlc_combination_t *mptcp_rlc_combination_create_from_sequence(uint64_t sequence, struct sk_buff *skb)
{
	mptcp_rlc_combination_t *c;
	uint64_t seed = sequence;
	uint32_t first  = (uint32_t)sequence;
	uint16_t count = (uint16_t)(sequence >> 32);
	uint32_t i;
	uint8_t coeff;

	if(sequence == 0 || count > MPTCP_RLC_MAX_COMPONENTS)
		return NULL;

	if(count == 0)
		return mptcp_rlc_combination_create_null();

	/* Kind of a hack, the coefficient for the first component is set after creation */
	c = mptcp_rlc_combination_create(first, skb, 1);
	if(!c)
		return NULL;

	coeff = mptcp_rlc_generate(&seed);
	c->coeffs[0] = coeff;	/* first coefficient set here */
	c->sequence = sequence;

	for(i = first + 1; i < first + count; ++i) {
		coeff = mptcp_rlc_generate(&seed);
		mptcp_rlc_combination_add_component(c, i, coeff);
	}

	/*printk("mptcp_rlc_combination_create_from_sequence: expanded combination: first=%u, count=%u\n", first, count);*/
	c->flags|= MPTCP_FLAGS_PADDED;
	return c;
}

mptcp_rlc_combination_t *mptcp_rlc_update(mptcp_rlc_combination_t *list, uint32_t next_dropped)
{
	mptcp_rlc_combination_t *tmp, *l, *p;

	/* Drop deprecated equations */
	l = list;
	p = NULL;
	while(l) {
		if(l->first < next_dropped || l->count == 0) {

			if(!p) list = l->next;
			else p->next = l->next;

			tmp = l;
			l = l->next;

			tmp->next = NULL;
			mptcp_rlc_combination_free(tmp);
		}
		else {
			p = l;
			l = l->next;
		}
	}

	return list;
}

/* Recursive Gauss-Jordan elimination */
mptcp_rlc_combination_t *mptcp_rlc_solve_rec(mptcp_rlc_combination_t *list, mptcp_rlc_combination_t *incoming, unsigned i)
{
	if(!incoming || incoming == list)
		return list;

	if(!list) {
		mptcp_rlc_combination_clean(incoming);

		if(incoming->count != 0 && incoming->first >= i) {

			/* Normalize and add to the system */
			uint8_t c = mptcp_rlc_combination_coeff(incoming, incoming->first);
			mptcp_rlc_combination_div(incoming, c);

			BUG_ON(incoming->next != NULL);

			/*printk("mptcp_rlc_solve_rec: inserting incoming at end (position %u), new pivot for %u\n", i, (unsigned)incoming->first);*/
			return incoming;
		}
		else {
			/* Combination is now null, meaning it was redundant */
			mptcp_rlc_combination_free(incoming);

			/*printk("mptcp_rlc_solve_rec: incoming is redundant\n");*/
			return NULL;
		}
	}

	BUG_ON(incoming == NULL);
	BUG_ON(list == NULL);
	BUG_ON(list->count == 0);
	BUG_ON(list->coeffs[0] != 1);
	
	if(list->first < i)
	{
		mptcp_rlc_combination_free(incoming);
		return list;
	}

	if(incoming->count != 0 && incoming->first + incoming->count > list->first) {
		if(list->first == i) {
			uint8_t c = mptcp_rlc_combination_coeff(incoming, list->first);
			if(c) {
				/*printk("mptcp_rlc_solve_rec: eliminating component %u in incoming\n", (unsigned)i);*/
				if(!mptcp_rlc_combination_combine(incoming, 1, list, c)) {
					mptcp_rlc_combination_free(incoming);
					return list;
				}
			}
		}
		else {
			/* list->first > i here */
			if(mptcp_rlc_combination_coeff(incoming, i) != 0) {

				/* incoming is the new pivot equation for i */
				uint8_t c = mptcp_rlc_combination_coeff(incoming, i);
				if(!mptcp_rlc_combination_div(incoming, c)) {
					mptcp_rlc_combination_free(incoming);
					return list;
				}

				mptcp_rlc_combination_clean(incoming);

				BUG_ON(incoming->next != NULL);
				incoming->next = list;

				/*printk("mptcp_rlc_solve_rec: inserting incoming at position %u, new pivot for %u\n", (unsigned)i, (unsigned)i);*/
				return incoming;
			}
		}

		list->next = mptcp_rlc_solve_rec(list->next, incoming, i+1);

		/* Warning: incoming might be freed now ! */
		if(list->next && list->count > 1) {
			mptcp_rlc_combination_t *l = list->next;
			while(l && l->count == 1 && l->first < list->first + list->count) {
				uint8_t c = mptcp_rlc_combination_coeff(list, l->first);
				if(c) {
					/*printk("mptcp_rlc_solve_rec: eliminating %u in pivot for %u\n", (unsigned)l->first, (unsigned)list->first);*/
					if(!mptcp_rlc_combination_combine(list, 1, l, c)) {
						mptcp_rlc_combination_free(incoming);
						return list;
					}
				}
				l = l->next;
			}

			mptcp_rlc_combination_clean(list);
		}
	}

	return list;
}

/* count returns the number of *undecoded* combinations */
mptcp_rlc_combination_t *mptcp_rlc_solve(mptcp_rlc_combination_t *list, mptcp_rlc_combination_t *incoming, uint32_t *count, uint32_t *next_seen)
{
	mptcp_rlc_combination_t *l, *p;
	uint32_t i;

	/* Debug: print combinations */
	/*l = list;
	p = NULL;
	i = 0;
	while(1) {
		char buffer[1024];
		int size = 1024;
		char *ptr = buffer;
		int ret;
		uint32_t k;

		if(!l)
			l = incoming;

		ret = snprintf(ptr, size, "%u +%u (", l->count, l->first);
		ptr+= ret;
		size-= ret;

		for(k=l->first; k<l->first+l->count; ++k) {
			ret = snprintf(ptr, size, "%u ", mptcp_rlc_combination_coeff(l, k));
			ptr+= ret;
			size-= ret;
		}

		snprintf(ptr, size, ")");

		if(l != incoming) printk("mptcp_rlc_solve: combination %u: %s\n", i, buffer);
		else {
			printk("mptcp_rlc_solve: incoming: %s\n", buffer);
			break;
		}

		l = l->next;
		++i;
	}*/

	/* First pass to solve the system */
	i = incoming->first;
	if(list && i > list->first) i = list->first;
	list = mptcp_rlc_solve_rec(list, incoming, i);

	/* Second pass to remove padding and update decoded and seen counters */
	l = list;
	p = NULL;
	*count = 0;
	while(l) {
		BUG_ON(l->count == 0);

		/* Count undecoded combinations */
		if(mptcp_rlc_combination_is_coded(l)) {
			++*count;
		}
		else {
			/* Remove padding if needed */
			mptcp_rlc_combination_clean_padding(l);
		}

		if(l->first >= *next_seen) {
			/* seen a new packet */
			*next_seen = l->first + 1;
		}

		p = l;
		l = l->next;
	}

	return list;
}

mptcp_rlc_combination_t *mptcp_rlc_drop(mptcp_rlc_combination_t *list, uint32_t next_seen)
{
	mptcp_rlc_combination_t *tmp, *l, *p;

	if(next_seen == 0)
		return list;

	l = list;
	p = NULL;
	while(l) {
		if(l->first + l->count < next_seen) {
			if(!p) list = l->next;
			else p->next = l->next;

			tmp = l;
			l = l->next;

			tmp->next = NULL;
			mptcp_rlc_combination_free(tmp);
		}
		else {
			p = l;
			l = l->next;
		}
	}

	return list;
}

uint16_t mptcp_rlc_combination_len(mptcp_rlc_combination_t *list)
{
	uint16_t len = 0;

	mptcp_rlc_combination_t *l = list;
	while(l) {
		if(l->skb->len > len)
			len = l->skb->len;

		l = l->next;
	}

	return len;
}

struct sk_buff *mptcp_rlc_combine_skb(struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb;
	struct tcp_skb_cb *tcb;
	mptcp_rlc_combination_t *c;
	uint16_t count;
	uint16_t nonce;
	uint64_t seed;
	uint32_t i;
	__u32 seq = 0;

	do get_random_bytes(&nonce, sizeof(nonce));
	while(nonce == 0);

	/* Compute count */
	count = 0;
        tcp_for_write_queue(skb, meta_sk) {
                ++count;
		if(count == MPTCP_RLC_MAX_GENERATION)
			break;
        }

        /*printk("mptcp_rlc_combine_skb: generation size: %u\n", count);*/

	if(count == 0)
		return NULL;

	/* Create null combination */
	c = mptcp_rlc_combination_create_null();
	if(!c)
		return NULL;

	/* Compute sequence */
	c->sequence = ((uint64_t)mpcb->rlc_first_component) + (((uint64_t)count) << 32) + (((uint64_t)nonce) << 48);

	/* Iterate on socket write queue */
	seed = c->sequence;
	i = mpcb->rlc_first_component;
	tcp_for_write_queue(skb, meta_sk) {
		mptcp_rlc_combination_t *tmp;
		uint8_t coeff;

		coeff = mptcp_rlc_generate(&seed);
		BUG_ON(coeff == 0);

		/* TODO: inefficient, combination should not be reallocated each time */
		tmp = mptcp_rlc_combination_create(i, skb, false);		/* skb not copied */
		if(!tmp || !mptcp_rlc_combination_combine(c, 1, tmp, coeff)) {	/* skb is not modified */
			mptcp_rlc_combination_free(tmp);
			mptcp_rlc_combination_free(c);
			return NULL;
		}

		mptcp_rlc_combination_free(tmp);

		if(c->count >= count)
			break;

		if(i == mpcb->rlc_first_component)
			seq = TCP_SKB_CB(skb)->seq;
		++i;
	}

	BUG_ON(c->first != mpcb->rlc_first_component);
	BUG_ON(c->count != count);
	/*printk("mptcp_rlc_combine_skb: generated combination: first=%u, count=%u\n", c->first, c->count);*/

	skb = c->skb;
	c->flags&= ~MPTCP_FLAGS_FREE_SKB;	/* so skb is not freed */

	tcb = TCP_SKB_CB(skb);
	tcb->mptcp_rlc_seq = c->sequence;
	tcb->seq = seq;
	tcb->end_seq = seq + skb->len;

	mptcp_rlc_combination_free(c);
	return skb;
}
EXPORT_SYMBOL(mptcp_rlc_combine_skb);

void mptcp_rlc_push_skb(struct sock *meta_sk, struct sk_buff *skb)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	unsigned long flags;
	
	BUG_ON(!skb);
	
	spin_lock_irqsave(&mpcb->rlc_lock, flags);
	
	skb_queue_tail(&mpcb->rlc_queue, skb);
	
	spin_unlock_irqrestore(&mpcb->rlc_lock, flags);
}
EXPORT_SYMBOL(mptcp_rlc_push_skb);

void mptcp_rlc_solve_pending(struct sock *meta_sk)
{
	struct tcp_sock *tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = tp->mpcb;
	mptcp_rlc_combination_t *list, *c;
	uint64_t sequence;
	struct sk_buff *skb;
	unsigned long flags;
	
	spin_lock_irqsave(&mpcb->rlc_lock, flags);
	
	list = (mptcp_rlc_combination_t *)mpcb->rlc_ptr;

	while(!skb_queue_empty(&mpcb->rlc_queue))
	{
		skb = skb_dequeue(&mpcb->rlc_queue);

		BUG_ON(!skb);
		BUG_ON(!mptcp_is_rlc(skb));

		if(tcp_hdr(skb)->fin)
			mpcb->rlc_fin_pending = true;

		sequence = mptcp_get_data_seq(skb);
		c = mptcp_rlc_combination_create_from_sequence(sequence, skb);
		if(c) {
			uint32_t count = 0;
			uint32_t next_seen = mpcb->rlc_next_seen;

			/* Remove old combinations */
			mpcb->rlc_next_dropped = c->first;
			if(mpcb->rlc_next_dropped > mpcb->rlc_next_decoded)
				mpcb->rlc_next_dropped = mpcb->rlc_next_decoded;
			list = mptcp_rlc_update(list, mpcb->rlc_next_dropped);

			/* Solve and update counters */
			list = mptcp_rlc_solve(list, c, &count, &next_seen);

			/* We do not acknowledge seen packets when decoding buffer is full */
			if(count <= MPTCP_RLC_MAX_GENERATION) {
				mpcb->rlc_next_seen = next_seen;
			} else {
				uint32_t r = count - MPTCP_RLC_MAX_GENERATION;
				if(r > next_seen)
					r = next_seen;
				mpcb->rlc_next_seen = next_seen - r;
			}

			mpcb->rlc_ptr = (void*)list;

			/*printk("mptcp_rlc_solve_skb: count=%u, next_seen=%u (acknowledging %u)\n", count, next_seen, mpcb->rlc_next_seen);*/
		}

		dev_consume_skb_any(skb);
	}
	
	spin_unlock_irqrestore(&mpcb->rlc_lock, flags);
}
EXPORT_SYMBOL(mptcp_rlc_solve_pending);

struct sk_buff *mptcp_rlc_pull_skb(struct sock *meta_sk)
{
	struct tcp_sock *tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	mptcp_rlc_combination_t *list, *l;
	unsigned long flags;
	
	spin_lock_irqsave(&mpcb->rlc_lock, flags);
	
	list = (mptcp_rlc_combination_t *)mpcb->rlc_ptr;

	l = list;
	while(l) {
		if(l->first == mpcb->rlc_next_decoded && !mptcp_rlc_combination_is_coded(l)) {
			struct sk_buff *skb;
			struct tcp_skb_cb *tcb;

			/*printk("mptcp_rlc_pull_skb: next_decoded=%u (decoded size=%u)\n", mpcb->rlc_next_decoded, l->len);*/

			/* Clone and trim skb */
			skb = skb_copy(l->skb, GFP_ATOMIC); /* clone ? */
			if(skb)
			{
				skb_trim(skb, l->len);

				/* Fill control block */
				tcb = TCP_SKB_CB(skb);
				tcb->seq = tp->rcv_nxt;
				tcb->end_seq = tcb->seq + skb->len;
				tcb->ack_seq = tp->snd_una - 1;	/* dummy */
				tcb->tcp_flags = 0;

				/* Fin flag handling */
				if(mpcb->rlc_fin_pending && !l->next) {
					tcb->tcp_flags|= TCPHDR_FIN;
					tcb->end_seq+= 1;
				}

				/* Decoded a new packet */
				mpcb->rlc_next_decoded = l->first + 1;
			}

			spin_unlock_irqrestore(&mpcb->rlc_lock, flags);
			return skb;
		}

		l = l->next;
	}

	spin_unlock_irqrestore(&mpcb->rlc_lock, flags);
	return NULL;
}
EXPORT_SYMBOL(mptcp_rlc_pull_skb);
