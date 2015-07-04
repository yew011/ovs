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
#include "lib/uuid.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "vtep/vtep-idl.h"
#include "ovn-controller-vtep.h"

VLOG_DEFINE_THIS_MODULE(binding);

/*
 * This module scans through the Binding table in ovnsb.  If there is a
 * row for the logical port on vtep gateway chassis's "logical_switches" map,
 * sets the binding's chassis column to the vtep gateway chassis.
 *
 * Caution: each logical datapath can only have up to one logical port
 *          attached to it from each vtep gateway.
 *
 */

/* Checks and updates bindings for each physical switch in VTEP. */
void
binding_run(struct controller_vtep_ctx *ctx)
{
    const struct vteprec_physical_switch *pswitch;
    struct ovsdb_idl_txn *txn;
    int retval;

    txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
    ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller-vtep: updating bindings");

    VTEPREC_PHYSICAL_SWITCH_FOR_EACH (pswitch, ctx->vtep_idl) {
        const struct sbrec_chassis *chassis_rec
            = get_chassis_by_name(ctx->ovnsb_idl, pswitch->name);
        const struct sbrec_binding *binding_rec;
        struct sset attached_ldps;
        struct sset gw_lports;
        struct smap_node *iter;
        const char *name;

        /* 'attached_ldps' is used to guarantee that each logical datapath
         * can only have up to one logical port attached from the same
         * gateway chassis.
         *
         * If a lport is first added to a logical datapath, we add the
         * logical datapath's uuid to 'attached_ldps' as string.  Then for
         * each following lport, we always first check if the logical
         * datapath has already been attached, and warn if it has.
         * (since it is not allowed)!
         *
         */
        sset_init(&attached_ldps);
        sset_init(&gw_lports);
        /* Collects all logical port names on the vtep gateway. */
        SMAP_FOR_EACH (iter, &chassis_rec->logical_switches) {
            sset_add(&gw_lports, iter->value);
        }

        SBREC_BINDING_FOR_EACH(binding_rec, ctx->ovnsb_idl) {
            /* Finds a binding entry for the lport. */
            if (sset_find_and_delete(&gw_lports, binding_rec->logical_port)) {
                char *ldp_uuid;

                /* Converts uuid to string. */
                ldp_uuid = xasprintf(UUID_FMT,
                                     UUID_ARGS(&binding_rec->logical_datapath));
                /* Warns if the logical datapath has already
                 * been attached. */
                if (sset_find(&attached_ldps, ldp_uuid)) {
                    VLOG_WARN("Logical datapath ("UUID_FMT") already has "
                              "logical port from the same chassis "
                              "(%s) attached to it, so clear the "
                              "chassis column from binding (%s)",
                              UUID_ARGS(&binding_rec->logical_datapath),
                              chassis_rec->name,
                              binding_rec->logical_port);
                    sbrec_binding_set_chassis(binding_rec, NULL);
                } else {
                    if (binding_rec->chassis != chassis_rec) {
                        if (binding_rec->chassis) {
                            VLOG_DBG("Changing chassis for lport (%s) from "
                                     "(%s) to (%s)",
                                     binding_rec->logical_port,
                                     binding_rec->chassis->name,
                                     chassis_rec->name);
                        }
                        sbrec_binding_set_chassis(binding_rec, chassis_rec);
                    }
                    /* Records the attachment in 'attached_ldps'. */
                    sset_add(&attached_ldps, ldp_uuid);
                }
                free(ldp_uuid);
            } else if (binding_rec->chassis == chassis_rec) {
                /* The logical port no longer exist, so clear
                 * the binding->chassis. */
                sbrec_binding_set_chassis(binding_rec, NULL);
            }
        }
        SSET_FOR_EACH (name, &gw_lports) {
            VLOG_DBG("No binding record for lport %s", name);
        }
        sset_destroy(&attached_ldps);
        sset_destroy(&gw_lports);
    }

    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval == TXN_ERROR) {
        VLOG_INFO("Problem committing binding information: %s",
                  ovsdb_idl_txn_status_to_string(retval));
    }
    ovsdb_idl_txn_destroy(txn);
}

/* Removes the chassis reference for each binding to the vtep gateway. */
void
binding_destroy(struct controller_vtep_ctx *ctx)
{
    struct hmap bd_map = HMAP_INITIALIZER(&bd_map);
    const struct sbrec_binding *binding_rec;
    int retval = TXN_TRY_AGAIN;

    struct binding_hash_node {
        struct hmap_node hmap_node;  /* Inside 'bd_map'. */
        const struct sbrec_binding *binding;
    };

    /* Collects all bindings with chassis. */
    SBREC_BINDING_FOR_EACH(binding_rec, ctx->ovnsb_idl) {
        if (binding_rec->chassis) {
            struct binding_hash_node *bd = xmalloc(sizeof *bd);

            bd->binding = binding_rec;
            hmap_insert(&bd_map, &bd->hmap_node,
                        hash_string(binding_rec->chassis->name, 0));
        }
    }

    while (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        const struct vteprec_physical_switch *pswitch;
        struct ovsdb_idl_txn *txn;

        txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
        ovsdb_idl_txn_add_comment(txn, "ovn-controller-vtep: removing bindings");

        VTEPREC_PHYSICAL_SWITCH_FOR_EACH (pswitch, ctx->vtep_idl) {
            const struct sbrec_chassis *chassis_rec
                = get_chassis_by_name(ctx->ovnsb_idl, pswitch->name);
            struct binding_hash_node *bd;

            HMAP_FOR_EACH_WITH_HASH (bd, hmap_node,
                                     hash_string(chassis_rec->name, 0),
                                     &bd_map) {
                if (!strcmp(bd->binding->chassis->name, chassis_rec->name)) {
                    sbrec_binding_set_chassis(bd->binding, NULL);
                }
            }
        }

        retval = ovsdb_idl_txn_commit_block(txn);
        if (retval == TXN_ERROR) {
            VLOG_DBG("Problem removing binding: %s",
                      ovsdb_idl_txn_status_to_string(retval));
        }
        ovsdb_idl_txn_destroy(txn);
    }

    struct binding_hash_node *iter, *next;

    HMAP_FOR_EACH_SAFE (iter, next, hmap_node, &bd_map) {
        hmap_remove(&bd_map, &iter->hmap_node);
        free(iter);
    }
    hmap_destroy(&bd_map);
}
