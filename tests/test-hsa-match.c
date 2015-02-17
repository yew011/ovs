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
#undef NDEBUG
#include "hsa-match.h"
#include "util.h"
#include <assert.h>
#include "ovstest.h"

static void
test_init(void)
{
    struct hsbm hsbm, hsbm_one_bit;
    struct match match, result;
    uint64_t map, val, val0, val1;

    /* Sets some fields. */
    memset(&match, 0, sizeof match);
    memset(&result, 0, sizeof result);
    match_set_tun_id_masked(&match, 0x0123, 0xFFFF);
    match_set_reg(&match, 3, 0x1);

    /* Expected results, please check lib/hsa-match.h for encoding details. */
    map = UINT64_MAX & (((uint64_t) 1 << HSBM_VALUES_MAX) - 1);
    map = map & ~((uint64_t) 1 << (offsetof(struct match, flow.tunnel.tun_id) / 4))
        & ~((uint64_t) 1 << (offsetof(struct match, flow.regs[3]) / 4));
    val0 = (uint64_t) 0xFFFFFFFF5556595A;
    val1 = (uint64_t) 0x5555555555555556;

    /* Checks the conversion. */
    hsbm_init(&hsbm, &match);
    assert(hsbm.map == map && hsbm.values[0] == val0 && hsbm.values[1] == val1);
    hsbm_to_match(&result, &hsbm);
    assert(match_equal(&match, &result));

    /* Tests just set one bit.  */
    hsbm_init_one_bit(&hsbm_one_bit, 10, 10, HSBM_VALUE_BIT_EM_ONE);
    map = UINT64_MAX & (((uint64_t) 1 << HSBM_VALUES_MAX) - 1);
    map = map & ~((uint64_t) 1 << 10);
    val = ~((uint64_t) 0x3 << 20) | ((uint64_t) HSBM_VALUE_BIT_EM_ONE << 20);
    assert(hsbm_one_bit.map == map && hsbm_one_bit.values[0] == val);

    /* Cleans up. */
    hsbm_uninit(&hsbm);
    hsbm_uninit(&hsbm_one_bit);
}

static void
test_check_subset(void)
{
    struct hsbm hsbm_superset, hsbm_subset;
    struct match match_superset, match_subset;

    memset(&match_superset, 0, sizeof match_superset);
    memset(&match_subset, 0, sizeof match_subset);
    /* Sets superset fields. */
    match_set_tun_id_masked(&match_superset, 0x1200, 0xFF00);
    match_set_reg_masked(&match_superset, 3, 0x00FF0000, 0x00FF0000);
    /* Sets subset fields. */
    match_set_tun_id_masked(&match_subset, 0x1234, 0xFFFF);
    match_set_reg_masked(&match_subset, 3, 0x12FF3200, 0xFFFFFF00);

    hsbm_init(&hsbm_superset, &match_superset);
    hsbm_init(&hsbm_subset, &match_subset);

    /* Checks subset. */
    assert(hsbm_check_subset(&hsbm_subset, &hsbm_superset));
    hsbm_uninit(&hsbm_superset);
    hsbm_uninit(&hsbm_subset);
}

static void
test_hsbm_complement(void)
{
    struct hsbm_list *result;
    struct match match;
    struct hsbm hsbm;
    struct hsbm *iter;
    size_t bit_idx = 0;

    /* Sets just one field to all zero. */
    memset(&match, 0, sizeof match);
    match_set_reg(&match, 3, 0);
    hsbm_init(&hsbm, &match);

    result = hsbm_complement(&hsbm);

    assert(list_size(&result->list) == 32);
    LIST_FOR_EACH (iter, list_node, &result->list) {
        assert(iter->map == hsbm.map);
        assert(iter->values[0] ==
               (~((uint64_t) HSBM_VALUE_BIT_WC << 2*bit_idx)
                | ((uint64_t) HSBM_VALUE_BIT_EM_ONE << 2*bit_idx)));
        bit_idx++;
    }

    hsbm_list_destroy(result);
    hsbm_uninit(&hsbm);
}

static void
test_hsbm_intersect(void)
{
    struct match match1, match2;
    struct hsbm hsbm1, hsbm2;
    struct hsbm *result;
    uint64_t map, val0, val1, val2, val3;

    memset(&match1, 0, sizeof match1);
    match_set_tun_id_masked(&match1, 0x0123, 0xFFFF);
    match_set_reg(&match1, 3, 0x1);
    hsbm_init(&hsbm1, &match1);

    memset(&match2, 0, sizeof match2);
    match_set_tun_id_masked(&match2, 0xABCD000000000000, 0xFFFF000000000000);
    match_set_reg(&match2, 4, 0);
    hsbm_init(&hsbm2, &match2);

    map = UINT64_MAX & (((uint64_t) 1 << HSBM_VALUES_MAX) - 1);
    map = map
        & ~((uint64_t) 1 << (offsetof(struct match, flow.tunnel.tun_id) / 4))
        & ~((uint64_t) 1 << (offsetof(struct match, flow.tunnel.tun_id) / 4 + 1))
        & ~((uint64_t) 1 << (offsetof(struct match, flow.regs[3]) / 4))
        & ~((uint64_t) 1 << (offsetof(struct match, flow.regs[4]) / 4));
    val0 = (uint64_t) 0xFFFFFFFF5556595A;
    val1 = (uint64_t) 0x999AA5A6FFFFFFFF;
    val2 = (uint64_t) 0x5555555555555556;
    val3 = (uint64_t) 0x5555555555555555;

    result = hsbm_intersect(&hsbm1, &hsbm2);
    assert(result->map == map && result->values[0] == val0
           && result->values[1] == val1 && result->values[2] == val2
           && result->values[3] == val3);

    hsbm_uninit(&hsbm1);
    hsbm_uninit(&hsbm2);
    hsbm_destroy(result);
}

static void
run_test(void (*function)(void))
{
    function();
    printf(".");
}

static void
test_hsa_match_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    run_test(test_init);
    run_test(test_check_subset);
    run_test(test_hsbm_complement);
    run_test(test_hsbm_intersect);
    printf("\n");
}

OVSTEST_REGISTER("test-hsa-match", test_hsa_match_main);
