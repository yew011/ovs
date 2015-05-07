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
#include "binding.h"

#include "lib/sset.h"
#include "lib/util.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "vtep/vtep-idl.h"
#include "ovn-controller-gw.h"

VLOG_DEFINE_THIS_MODULE(binding);

void
binding_run(struct controller_gw_ctx *ctx)
{
    const struct sbrec_chassis *chassis_rec;
    const struct sbrec_binding *binding_rec;
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
                              "ovn-controller: updating binding for '%s'",
                              ctx->chassis_id);

    SBREC_BINDING_FOR_EACH(binding_rec, ctx->ovnsb_idl) {
        if (sset_find_and_delete(&lports, binding_rec->logical_port)) {
            if (binding_rec->chassis == chassis_rec) {
                continue;
            }
            if (binding_rec->chassis) {
                VLOG_INFO("Changing chassis for lport %s from %s to %s",
                          binding_rec->logical_port, binding_rec->chassis->name,
                          chassis_rec->name);
            }
            sbrec_binding_set_chassis(binding_rec, chassis_rec);
        } else if (binding_rec->chassis == chassis_rec) {
            sbrec_binding_set_chassis(binding_rec, NULL);
        }
    }

    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval == TXN_ERROR) {
        VLOG_INFO("Problem committing binding information: %s",
                  ovsdb_idl_txn_status_to_string(retval));
    }

    ovsdb_idl_txn_destroy(txn);

    SSET_FOR_EACH (name, &lports) {
        VLOG_DBG("No binding record for lport %s", name);
    }
    sset_destroy(&lports);
}

void
binding_destroy(struct controller_gw_ctx *ctx)
{
    const struct sbrec_chassis *chassis_rec;
    int retval = TXN_TRY_AGAIN;

    ovs_assert(ctx->ovnsb_idl);

    SBREC_CHASSIS_FOR_EACH(chassis_rec, ctx->ovnsb_idl) {
        if (!strcmp(chassis_rec->name, ctx->chassis_id)) {
            break;
        }
    }
    ovs_assert(chassis_rec);

    while (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        const struct sbrec_binding *binding_rec;
        struct ovsdb_idl_txn *txn;

        txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
        ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller-gw: removing all binding for '%s'",
                              ctx->chassis_id);

        SBREC_BINDING_FOR_EACH(binding_rec, ctx->ovnsb_idl) {
            if (binding_rec->chassis == chassis_rec) {
                sbrec_binding_set_chassis(binding_rec, NULL);
            }
        }

        retval = ovsdb_idl_txn_commit_block(txn);
        if (retval == TXN_ERROR) {
            VLOG_INFO("Problem removing binding: %s",
                      ovsdb_idl_txn_status_to_string(retval));
        }

        ovsdb_idl_txn_destroy(txn);
    }
}
