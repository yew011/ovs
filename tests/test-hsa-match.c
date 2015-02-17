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
    struct mini_bm bm, bm_one_bit;
    struct match match, result;
    uint64_t map, val0, val1;

    /* Sets some fields. */
    memset(&match, 0, sizeof match);
    memset(&result, 0, sizeof result);
    match_set_tun_id_masked(&match, 0x0123, 0xFFFF);
    match_set_reg(&match, 3, 0x1);

    /* Expected results, please check lib/hsa-match.h for encoding details. */
    map = UINT64_MAX & (((uint64_t) 1 << MINI_BM_VALUES_MAX) - 1);
    map = map & ~((uint64_t) 1 << (offsetof(struct match, flow.tunnel.tun_id) / 4))
        & ~((uint64_t) 1 << (offsetof(struct match, flow.regs[3]) / 4));
    val0 = (uint64_t) 0xFFFFFFFF5556595A;
    val1 = (uint64_t) 0x5555555555555556;

    /* Checks the conversion. */
    mini_bm_init(&bm, &match);
    assert(bm.map == map && bm.values[0] == val0 && bm.values[1] == val1);
    mini_bm_to_match(&result, &bm);
    assert(match_equal(&match, &result));

    /* Tests just set one bit.  */
    mini_bm_init_one_bit(&bm_one_bit, 10);
    map = UINT64_MAX & (((uint64_t) 1 << MINI_BM_VALUES_MAX) - 1);
    map = map & ~((uint64_t) 1 << 10);
    assert(bm_one_bit.map == map && bm_one_bit.values[0] == 0);

    /* Cleans up. */
    mini_bm_uninit(&bm);
    mini_bm_uninit(&bm_one_bit);
}

static void
test_check_subset(void)
{
    struct mini_bm bm_superset, bm_subset;
    struct match match_superset, match_subset;

    memset(&match_superset, 0, sizeof match_superset);
    memset(&match_subset, 0, sizeof match_subset);
    /* Sets superset fields. */
    match_set_tun_id_masked(&match_superset, 0x1200, 0xFF00);
    match_set_reg_masked(&match_superset, 3, 0x00FF0000, 0x00FF0000);
    /* Sets subset fields. */
    match_set_tun_id_masked(&match_subset, 0x1234, 0xFFFF);
    match_set_reg_masked(&match_subset, 3, 0x12FF3200, 0xFFFFFF00);

    mini_bm_init(&bm_superset, &match_superset);
    mini_bm_init(&bm_subset, &match_subset);

    /* Checks subset. */
    assert(mini_bm_check_subset(&bm_subset, &bm_superset));
    mini_bm_uninit(&bm_superset);
    mini_bm_uninit(&bm_subset);
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
    printf("\n");
}

OVSTEST_REGISTER("test-hsa-match", test_hsa_match_main);
