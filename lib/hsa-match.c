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

/* Given 'mini_bm' and 'match', initializes 'mini_bm' with 'match'.
 * Caller must guarantee, 'mini_bm->values' is not assigned. */
void
mini_bm_init(struct mini_bm *mini_bm, const struct match *match)
{
    uint32_t *flow = (uint32_t *) &match->flow;
    uint32_t *wc = (uint32_t *) &match->wc;
    size_t sz = 0;
    size_t i, j;

    mini_bm->map = 0;
    mini_bm->values = NULL;

    /* Encodes every 4 bytes from 'match' to to 8 bytes and sets the
     * 'mini_bm->map' and 'mini_bm->values' correctly. */
    for (i = 0; i < sizeof(struct flow)/sizeof(uint32_t); i++) {
        uint64_t encoded_value = 0;

        for (j = 0; j < 32; j++) {
            uint8_t flow_bit = (flow[i] >> j) & 0x01;
            uint8_t wc_bit = (wc[i] >> j) & 0x01;

            /* If wc_bit is set, checks the bit.  Otherwise, sets to 'x'. */
            if (wc_bit) {
                encoded_value |= ((uint64_t) (flow_bit ? 0x0002 : 0x0001) << (2*j));
            } else {
                encoded_value |= ((uint64_t) 0x0003 << (2*j));
            }
        }

        if (encoded_value == UINT64_MAX) {
            mini_bm->map |= (uint64_t) 0x1 << i;
        } else {
            mini_bm->values = xrealloc(mini_bm->values,
                                       (++sz) * sizeof *mini_bm->values);
            mini_bm->values[sz-1] = encoded_value;
        }
    }
}

/* Initializes 'mini_bm' such that only one bit in 'map' is 0.
 * Correspondingly, sets the 'values[0]' to zero. */
void
mini_bm_init_one_bit(struct mini_bm *mini_bm, size_t bit_idx)
{
    ovs_assert(bit_idx < MINI_BM_VALUES_MAX);
    mini_bm->map = UINT64_MAX & (((uint64_t) 1 << MINI_BM_VALUES_MAX) - 1);
    mini_bm->map &= ~((uint64_t) 1 << bit_idx);
    mini_bm->values = xzalloc(sizeof *mini_bm->values);
}

/* Frees the 'values' pointer if it is non-NULL. */
void
mini_bm_uninit(struct mini_bm *mini_bm)
{
    if (mini_bm->values) {
        free(mini_bm->values);
    }
}

/* Converts the 'mini_bm' back to 'match'.  */
void
mini_bm_to_match(struct match *match, const struct mini_bm *mini_bm)
{
    uint32_t *flow = (uint32_t *) &match->flow;
    uint32_t *wc = (uint32_t *) &match->wc;
    size_t idx = 0;
    size_t i;

    for (i = 0; i < MINI_BM_VALUES_MAX; i++) {
        if ((mini_bm->map >> i) & 0x1) {
            flow[i] = wc[i] = 0;
        } else {
            uint64_t encoded_value = mini_bm->values[idx++];
            uint32_t flow_value = 0;
            uint32_t wc_value = 0;
            size_t j;

            for (j = 0; j < 32; j++) {
                switch ((encoded_value >> (2*j)) & 0x0003) {
                /* wildcard unmasked (don't care), sets wc bit to '0'. */
                case 0x03:
                    wc_value = wc_value | ((uint32_t) 0x0 << j);
                    break;
                /* exact match '1'. */
                case 0x02:
                    flow_value = flow_value | ((uint32_t) 0x1 << j);
                    wc_value = wc_value | ((uint32_t) 0x01 << j);
                    break;
                /* exact match '0'. */
                case 0x01:
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

/* Returns true if 'mini_bm1' is a subset of 'mini_bm2'. */
bool
mini_bm_check_subset(const struct mini_bm *mini_bm1,
                     const struct mini_bm *mini_bm2)
{
    uint64_t *vals1 = mini_bm1->values;
    uint64_t *vals2 = mini_bm2->values;
    size_t i;

    for (i = 0; i < MINI_BM_VALUES_MAX; i++) {
        uint8_t bit1 = mini_bm1->map >> i & 0x1;
        uint8_t bit2 = mini_bm2->map >> i & 0x1;

        if (bit1 == 1 && bit2 == 1) {
            /* Do nothing. */
        } else if (bit1 == 1 && bit2 == 0) {
            /* 'mini_bm2' is more specific, 'mini_bm1' cannot be its subset. */
            return false;
        } else if (bit1 == 0 && bit2 == 1) {
            /* 'mini_bm1' is more specific, skips the exact value. */
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
