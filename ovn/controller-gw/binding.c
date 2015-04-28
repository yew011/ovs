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

#include "lib/hash.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "vtep/vtep-idl.h"
#include "ovn-controller-gw.h"

VLOG_DEFINE_THIS_MODULE(binding);

/* Checks and updates bindings for each physical switch in VTEP. */
void
binding_run(struct controller_gw_ctx *ctx)
{
    const struct vteprec_physical_switch *pswitch;
    struct ovsdb_idl_txn *txn;
    int retval;

    txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
    ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller-gw: updating bindings");

    VTEPREC_PHYSICAL_SWITCH_FOR_EACH (pswitch, ctx->vtep_idl) {
        const struct sbrec_chassis *chassis_rec
            = get_chassis_by_name(ctx->ovnsb_idl, pswitch->name);
        const struct sbrec_binding *binding_rec;
        struct sset lports;
        const char *name;
        int i;

        sset_init(&lports);
        /* Collects all logical ports of the gateway. */
        for (i = 0; i < chassis_rec->n_gateway_ports; i++) {
            const struct sbrec_gateway *gw_rec = chassis_rec->value_gateway_ports[i];
            int j;

            for (j = 0; j < gw_rec->n_vlan_map; j++) {
                sset_add(&lports, gw_rec->value_vlan_map[j]);
            }
        }

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
        SSET_FOR_EACH (name, &lports) {
            VLOG_DBG("No binding record for lport %s", name);
        }
        sset_destroy(&lports);
    }

    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval == TXN_ERROR) {
        VLOG_INFO("Problem committing binding information: %s",
                  ovsdb_idl_txn_status_to_string(retval));
    }
    ovsdb_idl_txn_destroy(txn);
}

/* Removes the chassis reference for each gw related binding. */
void
binding_destroy(struct controller_gw_ctx *ctx)
{
    struct hmap bindings_with_chassis = HMAP_INITIALIZER(&bindings_with_chassis);
    const struct sbrec_binding *binding_rec;
    int retval = TXN_TRY_AGAIN;

    struct bd {
        struct hmap_node hmap_node;  /* Inside 'bindings_with_chassis'. */

        const struct sbrec_binding *binding;
    };

    /* Collects all bindings with chassis, this is to avoid multiple
     * linear iterations of Binding table. */
    SBREC_BINDING_FOR_EACH(binding_rec, ctx->ovnsb_idl) {
        if (binding_rec->chassis) {
            struct bd *bd = xmalloc(sizeof *bd);

            bd->binding = binding_rec;
            hmap_insert(&bindings_with_chassis, &bd->hmap_node,
                        hash_string(binding_rec->chassis->name, 0));
        }
    }

    while (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        const struct vteprec_physical_switch *pswitch;
        struct ovsdb_idl_txn *txn;

        txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
        ovsdb_idl_txn_add_comment(txn, "ovn-controller-gw: removing bindings");

        VTEPREC_PHYSICAL_SWITCH_FOR_EACH (pswitch, ctx->vtep_idl) {
            const struct sbrec_chassis *chassis_rec
                = get_chassis_by_name(ctx->ovnsb_idl, pswitch->name);
            struct bd *bd;

            HMAP_FOR_EACH_WITH_HASH (bd, hmap_node,
                                     hash_string(chassis_rec->name, 0),
                                     &bindings_with_chassis) {
                if (!strcmp(bd->binding->chassis->name, chassis_rec->name)) {
                    sbrec_binding_set_chassis(bd->binding, NULL);
                }
            }
        }

        retval = ovsdb_idl_txn_commit_block(txn);
        if (retval == TXN_ERROR) {
            VLOG_INFO("Problem removing binding: %s",
                      ovsdb_idl_txn_status_to_string(retval));
        }
        ovsdb_idl_txn_destroy(txn);
    }

    struct bd *iter, *next;

    HMAP_FOR_EACH_SAFE (iter, next, hmap_node, &bindings_with_chassis) {
        hmap_remove(&bindings_with_chassis, &iter->hmap_node);
        free(iter);
    }
    hmap_destroy(&bindings_with_chassis);
}
