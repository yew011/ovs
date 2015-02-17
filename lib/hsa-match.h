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
#include "list.h"

struct match;

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
#define HSBM_MAP_BIT_WC          1
#define HSBM_MAP_BIT_NOT_WC      0

#define HSBM_VALUE_BIT_EMPTY     0x0
#define HSBM_VALUE_BIT_EM_ZERO   0x1
#define HSBM_VALUE_BIT_EM_ONE    0x2
#define HSBM_VALUE_BIT_WC        0x3

/* A sparse representation of a byte array derived from "struct match".
 *
 * The 'map' member holds one bit for each uint64_t in the byte array.  Each
 * 1-bit indicates that the corresponding uint64_t is UINT64_MAX (i.e. all
 * HSBM_VALUE_BIT_WC), each 0-bit that it is not all-one.
 *
 * The 'values' member is an array that has one element for each 0-bit in
 * 'map'.  The least-numbered 0-bit is in the first element of 'values', the
 * next 0-bit is in the next array element, and so on.
 */
struct hsbm {
    struct ovs_list list_node;  /* In 'hsbm_list'. */
    uint64_t map;
    uint64_t *values;
};

/* Based on the description above, the maximum size of 'hsbm->values'
 * is twice FLOW_U64S. */
#define HSBM_VALUES_MAX (FLOW_U64S * 2)
BUILD_ASSERT_DECL(HSBM_VALUES_MAX < 64);

void hsbm_init(struct hsbm *, const struct match *);
void hsbm_init_one_bit(struct hsbm *, size_t map_idx, size_t bit_idx,
                       size_t bit_val);
void hsbm_uninit(struct hsbm *);
void hsbm_destroy(struct hsbm *);
void hsbm_to_match(struct match *, const struct hsbm *);
bool hsbm_check_subset(const struct hsbm *, const struct hsbm *);

/* List of 'struct hsbm's. */
struct hsbm_list {
    struct ovs_list list;
};

struct hsbm_list *hsbm_list_create(void);
void hsbm_list_destroy(struct hsbm_list *);
void hsbm_insert_without_duplicate(struct hsbm_list *, struct hsbm *);
struct hsbm_list *hsbm_complement(struct hsbm *);
struct hsbm *hsbm_intersect(struct hsbm *, struct hsbm *);
struct hsbm_list *hsbm_diff(struct hsbm *, struct hsbm *);
bool hsbm_list_check_hsbm(struct hsbm_list *, struct hsbm *);
struct hsbm_list *hsbm_list_apply_hsbm(struct hsbm_list *, struct hsbm *);

#endif /* hsa-match.h */
