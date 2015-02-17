/*
 * Copyright (c) 2015 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "hsa-match.h"

#include "util.h"

/* Given 'hsbm' and 'match', initializes 'hsbm' with 'match'.
 * Caller must guarantee, 'hsbm->values' is not assigned. */
void
hsbm_init(struct hsbm *hsbm, const struct match *match)
{
    uint32_t *flow = (uint32_t *) &match->flow;
    uint32_t *wc = (uint32_t *) &match->wc;
    size_t sz = 0;
    size_t i, j;

    hsbm->map = 0;
    hsbm->values = NULL;

    /* Encodes every 4 bytes from 'match' to to 8 bytes and sets the
     * 'hsbm->map' and 'hsbm->values' correctly. */
    for (i = 0; i < HSBM_VALUES_MAX; i++) {
        uint64_t encoded_value = 0;

        for (j = 0; j < 32; j++) {
            uint8_t flow_bit = (flow[i] >> j) & 0x1;
            uint8_t wc_bit = (wc[i] >> j) & 0x1;

            /* If wc_bit is set, checks the bit.  Otherwise, sets to 'x'. */
            if (wc_bit) {
                encoded_value |= ((uint64_t) (flow_bit ? HSBM_VALUE_BIT_EM_ONE
                                     : HSBM_VALUE_BIT_EM_ZERO) << (2*j));
            } else {
                encoded_value |= ((uint64_t) HSBM_VALUE_BIT_WC << (2*j));
            }
        }

        if (encoded_value == UINT64_MAX) {
            hsbm->map |= (uint64_t) 0x1 << i;
        } else {
            hsbm->values = xrealloc(hsbm->values,
                                       (++sz) * sizeof *hsbm->values);
            hsbm->values[sz-1] = encoded_value;
        }
    }
}

/* Initializes 'hsbm' such that only one bit 'map_idx' in 'hsbm->map' is
 * HSBM_MAP_BIT_NOT_WC.  Correspondingly, sets the 'values[0]' so that
 * the 'bit_idx' bit is set to 'bit_val'. */
void
hsbm_init_one_bit(struct hsbm *hsbm, size_t map_idx, size_t bit_idx,
                  size_t bit_val)
{
    ovs_assert(map_idx < HSBM_VALUES_MAX);
    hsbm->map = ((uint64_t) 1 << HSBM_VALUES_MAX) - 1;
    hsbm->map &= ~((uint64_t) 1 << map_idx);
    hsbm->values = xzalloc(sizeof *hsbm->values);
    hsbm->values[0] = ~((uint64_t) HSBM_VALUE_BIT_WC << 2*bit_idx)
        | ((uint64_t) bit_val << 2*bit_idx);
}

/* Frees the 'values' pointer if it is non-NULL. */
void
hsbm_uninit(struct hsbm *hsbm)
{
    if (hsbm->values) {
        free(hsbm->values);
    }
}

/* Destroys the 'hsbm'. */
void
hsbm_destroy(struct hsbm *hsbm)
{
    hsbm_uninit(hsbm);
    free(hsbm);
}

/* Converts the 'hsbm' back to 'match'.  */
void
hsbm_to_match(struct match *match, const struct hsbm *hsbm)
{
    uint32_t *flow = (uint32_t *) &match->flow;
    uint32_t *wc = (uint32_t *) &match->wc;
    size_t idx = 0;
    size_t i;

    for (i = 0; i < HSBM_VALUES_MAX; i++) {
        if ((hsbm->map >> i) & 0x1) {
            flow[i] = wc[i] = 0;
        } else {
            uint64_t encoded_value = hsbm->values[idx++];
            uint32_t flow_value = 0;
            uint32_t wc_value = 0;
            size_t j;

            for (j = 0; j < 32; j++) {
                switch ((encoded_value >> (2*j)) & 0x3) {
                /* wildcard unmasked (don't care), sets wc bit to '0'. */
                case HSBM_VALUE_BIT_WC:
                    wc_value = wc_value | ((uint32_t) 0x0 << j);
                    break;
                /* exact match '1'. */
                case HSBM_VALUE_BIT_EM_ONE:
                    flow_value = flow_value | ((uint32_t) 0x1 << j);
                    wc_value = wc_value | ((uint32_t) 0x01 << j);
                    break;
                /* exact match '0'. */
                case HSBM_VALUE_BIT_EM_ZERO:
                    flow_value = flow_value | ((uint32_t) 0x0 << j);
                    wc_value = wc_value | ((uint32_t) 0x1 << j);
                    break;
                /* no intersection, error! */
                default:
                    ovs_assert(false);
                }
            }
            flow[i] = flow_value;
            wc[i] = wc_value;
        }
    }
}

/* Returns true if 'hsbm1' is a subset of 'hsbm2'. */
bool
hsbm_check_subset(const struct hsbm *hsbm1,
                     const struct hsbm *hsbm2)
{
    uint64_t *vals1 = hsbm1->values;
    uint64_t *vals2 = hsbm2->values;
    size_t i;

    for (i = 0; i < HSBM_VALUES_MAX; i++) {
        uint8_t bit1 = hsbm1->map >> i & 0x1;
        uint8_t bit2 = hsbm2->map >> i & 0x1;

        if (bit1 == HSBM_MAP_BIT_WC && bit2 == HSBM_MAP_BIT_WC) {
            /* Do nothing. */
        } else if (bit1 == HSBM_MAP_BIT_WC && bit2 == HSBM_MAP_BIT_NOT_WC) {
            /* 'hsbm2' is more specific, 'hsbm1' cannot be its subset. */
            return false;
        } else if (bit1 == HSBM_MAP_BIT_NOT_WC && bit2 == HSBM_MAP_BIT_WC) {
            /* 'hsbm1' is more specific, skips the exact value. */
            vals1++;
        } else {
            /* if both have specific values at index i, compares the values. */
            if (*vals1++ & ~(*vals2++)) {
                return false;
            }
        }
    }

    return true;
}

/* Creates and returns a 'hsbm_list'. */
struct hsbm_list *
hsbm_list_create(void)
{
    struct hsbm_list *ret = xmalloc(sizeof *ret);

    list_init(&ret->list);

    return ret;
}

/* Destroys the 'hsbm_list' and all its elements. */
void
hsbm_list_destroy(struct hsbm_list *hsbm_list)
{
    struct hsbm *iter, *next;

    LIST_FOR_EACH_SAFE (iter, next, list_node, &hsbm_list->list) {
        list_remove(&iter->list_node);
        hsbm_destroy(iter);
    }
    free(hsbm_list);
}

/* Inserts the 'hsbm' to 'hsbm_list' while removing all duplicate, superset
 * and subset.  This function will take ownership of 'hsbm'. */
void
hsbm_insert_without_duplicate(struct hsbm_list *hsbm_list, struct hsbm *hsbm)
{
    struct hsbm *comp, *next;

    LIST_FOR_EACH_SAFE (comp, next, list_node, &hsbm_list->list) {
        bool is_subset = hsbm_check_subset(hsbm, comp);
        bool is_superset = hsbm_check_subset(comp, hsbm);

        if (is_subset) {
            hsbm_destroy(hsbm);

            return;
        } else if (is_superset) {
            /* If the to-be-inserted 'hsbm' is a superset of
             * existing element, removes the existing one. */
            list_remove(&comp->list_node);
            hsbm_destroy(comp);
        }
    }
    list_insert(&hsbm_list->list, &hsbm->list_node);
}

/* Given the 'hsbm', returns the complement of 'hsbm' as a list (union). */
struct hsbm_list *
hsbm_complement(struct hsbm *hsbm)
{
    struct hsbm_list *result = hsbm_list_create();
    uint64_t *values = hsbm->values;
    size_t i;

    for (i = 0; i < HSBM_VALUES_MAX; i++) {
        uint8_t map_bit = hsbm->map >> i & 0x1;

        if (map_bit == 0) {
            size_t j;

            for (j = 0; j < 32; j++) {
                struct hsbm *flap = NULL;

                /* If a non-wildcarded bit is found, creates a flap. */
                if (((*values >> 2*j) & 0x3) == HSBM_VALUE_BIT_EM_ZERO) {
                    flap = xmalloc(sizeof *flap);
                    hsbm_init_one_bit(flap, i, j, HSBM_VALUE_BIT_EM_ONE);
                } else if (((*values >> 2*j) & 0x3) == HSBM_VALUE_BIT_EM_ONE) {
                    flap = xmalloc(sizeof *flap);
                    hsbm_init_one_bit(flap, i, j, HSBM_VALUE_BIT_EM_ZERO);
                }
                if (flap) {
                    list_insert(&result->list, &flap->list_node);
                }
            }
            /* Jumps to next value. */
            values++;
        }
    }

    return result;
}

/* Given two 'hsbm's, returns the intersection of them.
 * Returns NULL when the intersection is empty. */
struct hsbm *
hsbm_intersect(struct hsbm *comp_1, struct hsbm *comp_2)
{
    struct hsbm *result = xmalloc(sizeof *result);
    uint64_t *vals_1 = comp_1->values;
    uint64_t *vals_2 = comp_2->values;
    uint64_t *vals_result;
    size_t n_vals = 0;
    size_t i, j;

    result->map = comp_1->map & comp_2->map;
    for (i = 0; i < HSBM_VALUES_MAX; i++) {
        if ((result->map >> i & 0x1) == 0) {
            n_vals++;
        }
    }
    vals_result = result->values = xmalloc(n_vals * sizeof *result->values);

    for (i = 0; i < HSBM_VALUES_MAX; i++) {
        uint8_t map_bit_1 = comp_1->map >> i & 0x1;
        uint8_t map_bit_2 = comp_2->map >> i & 0x1;

        if (map_bit_1 == HSBM_MAP_BIT_WC && map_bit_2 == HSBM_MAP_BIT_WC) {
            /* Do nothing. */
        } else if (map_bit_1 == HSBM_MAP_BIT_WC
                   && map_bit_2 == HSBM_MAP_BIT_NOT_WC) {
            *vals_result++ = *vals_2++;
        } else if (map_bit_1 == HSBM_MAP_BIT_NOT_WC
                   && map_bit_2 == HSBM_MAP_BIT_WC) {
            *vals_result++ = *vals_1++;
        } else {
            uint64_t val = *vals_1++ & *vals_2++;

            for (j = 0; j < 32; j++) {
                /* If intersection results in empty, returns NULL. */
                if (((val >> 2*j) & 0x3) == 0) {
                    hsbm_destroy(result);

                    return NULL;
                }
            }
            *vals_result++ = val;
        }
    }

    return result;
}

/* Given two 'hsbm's, calculates the diff (hsbm_1 - hsbm_2) and returns
 * the result in 'hsbm_list'. */
struct hsbm_list *
hsbm_diff(struct hsbm *hsbm_1, struct hsbm *hsbm_2)
{
    struct hsbm_list *result = hsbm_list_create();
    struct hsbm_list *complement;
    struct hsbm *iter;

    complement = hsbm_complement(hsbm_2);

    LIST_FOR_EACH (iter, list_node, &complement->list) {
        struct hsbm *intersect = hsbm_intersect(hsbm_1, iter);

        if (intersect) {
            list_insert(&result->list, &intersect->list_node);
        }
    }
    hsbm_list_destroy(complement);

    return result;
}

/* Given the 'hsbm_list', checks if 'hsbm' can still find a match
 * (non-NULL intersection) in 'hsbm_list'.  Returns true if a match
 * can be found, otherwise, false. */
bool
hsbm_list_check_hsbm(struct hsbm_list *hsbm_list, struct hsbm *hsbm)
{
    struct hsbm *iter;
    bool ret = false;

    LIST_FOR_EACH (iter, list_node, &hsbm_list->list) {
        struct hsbm *intersect = hsbm_intersect(iter, hsbm);

        if (intersect) {
            hsbm_destroy(intersect);
            ret = true;
            break;
        }
    }

    return ret;
}

/* Subtracts 'hsbm' from each element of 'hsbm_list', returns the result
 * in another hsbm_list.  The function will take ownership of 'hsbm_list'. */
struct hsbm_list *
hsbm_list_apply_hsbm(struct hsbm_list *hsbm_list, struct hsbm *hsbm)
{
    struct hsbm_list *result = hsbm_list_create();
    struct hsbm *iter;

    LIST_FOR_EACH (iter, list_node, &hsbm_list->list) {
        struct hsbm_list *diff = hsbm_diff(iter, hsbm);
        struct hsbm *tmp, *next;

        LIST_FOR_EACH_SAFE (tmp, next, list_node, &diff->list) {
            hsbm_insert_without_duplicate(result, tmp);
        }
        hsbm_list_destroy(diff);
    }
    hsbm_list_destroy(hsbm_list);

    return result;
}
