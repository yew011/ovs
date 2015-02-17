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

#ifndef HSA_MATCH_H
#define HSA_MATCH_H 1

#include "flow.h"
#include "match.h"

/*
 * For conducting Header Space Analysis (HSA), we convert the wildcarded
 * OpenFlow flow represented by 'struct match' into a byte array.
 * Specifically, each bit in the OpenFlow flow is encoded into two bits:
 *
 *    exact match 0 -> 01
 *    exact match 1 -> 10
 *    wildcard    * -> 11
 *    empty         -> 00
 *
 * We use '00' to indicate the empty bit resulted when intersecting two
 * OpenFlow flows with exact match '0' and exact match '1' at same index.
 *
 * This conversion will generate a struct same size as 'struct match'.
 * To save more space, we will use a sparse array to represent such byte
 * array in the same way as 'struct miniflow'.
 */

/* A sparse representation of a byte array derived from "struct match".
 *
 * The 'map' member holds one bit for each uint64_t in the byte array.  Each
 * 0-bit indicates that the corresponding uint64_t is UINT64_MAX, each 1-bit
 * that it is not all-one.
 *
 * The 'values' member is an array that has one element for each 1-bit in
 * 'map'.  The least-numbered 1-bit is in the first element of 'values', the
 * next 1-bit is in the next array element, and so on.
 */
struct mini_bm {
    uint64_t map;
    uint64_t *values;
};

/* Based on the description above, the maximum size of 'mini_bm->values'
 * is the double of FLOW_U64S. */
#define MINI_BM_VALUES_MAX (FLOW_U64S * 2)

void mini_bm_init(struct mini_bm *, const struct match *);
void mini_bm_init_one_bit(struct mini_bm *, size_t bit_idx);
void mini_bm_uninit(struct mini_bm *);
void mini_bm_to_match(struct match *, const struct mini_bm *);
bool mini_bm_check_subset(const struct mini_bm *, const struct mini_bm *);

#endif /* hsa-match.h */
