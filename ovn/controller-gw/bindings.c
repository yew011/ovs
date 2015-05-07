/* Copyright (c) 2015 Nicira, Inc.
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
#include "bindings.h"

#include "lib/sset.h"
#include "lib/util.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "vtep/vtep-idl.h"
#include "ovn-controller-gw.h"

VLOG_DEFINE_THIS_MODULE(bindings);

void
bindings_run(struct controller_gw_ctx *ctx)
{
    const struct sbrec_chassis *chassis_rec;
    const struct sbrec_bindings *bindings_rec;
    struct ovsdb_idl_txn *txn;
    struct sset lports;
    const char *name;
    int retval, i;

    sset_init(&lports);

    SBREC_CHASSIS_FOR_EACH(chassis_rec, ctx->ovnsb_idl) {
        if (!strcmp(chassis_rec->name, ctx->chassis_id)) {
            break;
        }
    }
    ovs_assert(chassis_rec);

    /* Collects all logical ports of the gateway. */
    for (i = 0; i < chassis_rec->n_gateway_ports; i++) {
        const struct sbrec_gateway *gw_rec = chassis_rec->value_gateway_ports[i];
        int j;

        for (j = 0; j < gw_rec->n_vlan_map; j++) {
            sset_add(&lports, gw_rec->value_vlan_map[j]);
        }
    }

    txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
    ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller: updating bindings for '%s'",
                              ctx->chassis_id);

    SBREC_BINDINGS_FOR_EACH(bindings_rec, ctx->ovnsb_idl) {
        if (sset_find_and_delete(&lports, bindings_rec->logical_port)) {
            if (!strcmp(bindings_rec->chassis, ctx->chassis_id)) {
                continue;
            }
            if (bindings_rec->chassis[0]) {
                VLOG_INFO("Changing chassis for lport %s from %s to %s",
                          bindings_rec->logical_port, bindings_rec->chassis,
                          ctx->chassis_id);
            }
            sbrec_bindings_set_chassis(bindings_rec, ctx->chassis_id);
        } else if (!strcmp(bindings_rec->chassis, ctx->chassis_id)) {
            sbrec_bindings_set_chassis(bindings_rec, "");
        }
    }

    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval == TXN_ERROR) {
        VLOG_INFO("Problem committing bindings information: %s",
                  ovsdb_idl_txn_status_to_string(retval));
    }

    ovsdb_idl_txn_destroy(txn);

    SSET_FOR_EACH (name, &lports) {
        VLOG_DBG("No binding record for lport %s", name);
    }
    sset_destroy(&lports);
}

void
bindings_destroy(struct controller_gw_ctx *ctx)
{
    int retval = TXN_TRY_AGAIN;

    ovs_assert(ctx->ovnsb_idl);

    while (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        const struct sbrec_bindings *bindings_rec;
        struct ovsdb_idl_txn *txn;

        txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
        ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller-gw: removing all bindings for '%s'",
                              ctx->chassis_id);

        SBREC_BINDINGS_FOR_EACH(bindings_rec, ctx->ovnsb_idl) {
            if (!strcmp(bindings_rec->chassis, ctx->chassis_id)) {
                sbrec_bindings_set_chassis(bindings_rec, "");
            }
        }

        retval = ovsdb_idl_txn_commit_block(txn);
        if (retval == TXN_ERROR) {
            VLOG_INFO("Problem removing bindings: %s",
                      ovsdb_idl_txn_status_to_string(retval));
        }

        ovsdb_idl_txn_destroy(txn);
    }
}
