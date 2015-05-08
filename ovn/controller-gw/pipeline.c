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
#include "pipeline.h"

#include "dynamic-string.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "lib/uuid.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "vtep/vtep-idl.h"
#include "ovn-controller-gw.h"

VLOG_DEFINE_THIS_MODULE(pipeline_gw);

/* One for each 'mac' in the binding. */
struct mac_to_binding {
    struct hmap_node hmap_node;

    const char *mac;
    const struct sbrec_binding *binding;
};

/* Stores all info related to one logical switch to program vtep. */
struct lswitch {
    struct hmap_node hmap_node;

    /* logical switch reference in vtep. */
    const struct vteprec_logical_switch *lswitch;
    /* corresponding logical datapath uuid in ovn-sb. */
    struct uuid *ldp_uuid;
    struct hmap bindings;       /* stores 'struct mac_to_binding's. */
};

/* An 'Ucast_Macs_Remote' entry in vtep. */
struct ucast_macs_rmt {
    struct hmap_node hmap_node;

    struct vteprec_ucast_macs_remote *umr;
};

/* An 'Physical_Locator' entry in vtep. */
struct physical_locator {
    struct hmap_node hmap_node;

    struct vteprec_physical_locator *pl;
};


/* Returns true if the 'binding's logical datapath has already been
 * stored in 'ls_map', also saves found record in 'lsp'.  Otherwise,
 * returns false.*/
static bool
binding_in_hmap(const struct sbrec_bindings *binding, struct hmap *ls_map,
                struct lswitch **lsp)
{
    struct lswitch *ls;

    HMAP_FOR_EACH_WITH_HASH (ls, hmap_node,
                             uuid_hash(binding->logical_datapath), ls_map) {
        if (uuid_equals(ls->ldp_uuid, binding->logical_datapath)) {
            *lsp = ls;
            return true;
        }
    }

    return false;
}

/* Finds and returns the reference to logical switch in vtep  with same name
 * as 'uuid'. */
static const struct vteprec_logical_switch *
find_lswitch_from_vtep(struct controller_gw_ctx *ctx, const struct uuid *uuid)
{
    const struct vteprec_logical_switch *lswitch;

    VTEPREC_LOGICAL_SWITCH_FOR_EACH (lswitch, ctx->vtep_idl) {
        struct uuid uuid;

        uuid_from_string(&uuid, lswitch->name);
        if (uuid == *uuid) {
            return lswitch;
        }
    }

    return NULL;
}

/* Returns true if the logical switch containing the logical port represented
 * by 'binding_rec' is also defined in VTEP. */
static bool
binding_pipeline_use_vtep(struct controller_gw_ctx *ctx,
                          const struct sbrec_bindings *binding)
{
    return find_lswitch_from_vtep(ctx, binding->logical_datapath)
           ? true : false;
}

/* Creates an entry in 'ls->bindings' for each mac in 'binding_rec'. */
static void
add_binding_macs(struct lswitch *ls, const struct sbrec_bindings *binding)
{
    int i;

    for (i = 0; i < binding->n_mac; i++) {
        struct mac_to_binding *mb;
        char *mac = binding->mac[i];

        /* Duplication check. */
        HMAP_FOR_EACH_WITH_HASH (mb, hmap_node, hash_string(mac, 0),
                                 &ls->bindings) {
            /* TODO: It is actually possible to have duplicate MACs. */
            if (!strcmp(mac, mb->mac)) {
                VLOG_ERR("MAC address (%s) already exists in logical "
                         "switch (%s)", mac, ls->lswitch->name);
                return;
            }
        }
        mb = xmalloc(sizeof *mb);
        mb->mac = mac;
        mb->binding = binding;
        hmap_insert(&ls->bindings, &mb->hmap_node, hash_string(mb->mac, 0));
    }
}

/* Destroys the 'ls'. */
static void
lswitch_destroy(struct lswitch *ls)
{
    struct mac_to_binding *mb;

    HMAP_FOR_EACH_SAFE (mb, hmap_node, &ls->bindings) {
        hmap_remove(&ls->bindings, &mb->hmap_node);
        free(mb);
    }
}

/* Destroys the 'map' containing 'struct lswitch *'. */
static void
lswitch_map_destroy(struct hmap *map)
{
    struct lswitch *iter;

    HMAP_FOR_EACH_SAFE (iter, hmap_node, map) {
        hmap_remove(map, &iter->hmap_node);
        lswitch_destory(iter);
        free(iter);

    }
    hmap_destroy(map);
}

/* Creates and adds an 'struct ucast_macs_rmt' entry to 'map'. */
static void
ucast_macs_remote_map_add(struct vteprec_ucast_macs_remote *vteprec_umr,
                          struct hmap *map)
{
    struct ucast_macs_rmt *umr = xmalloc(sizeof *umr);

    umr->umr = vteprec_umr;
    hmap_insert(map, &umr->hmap_node, hash_string(vteprec_umr->MAC, 0));
}

/* Destroys the 'map' containing 'struct ucast_macs_remote *'. */
static void
ucast_macs_remote_map_destory(struct hmap *map)
{
    struct ucast_macs_remote *iter;

    HMAP_FOR_EACH_SAFE (iter, hmap_node, map) {
        hmap_remove(map, &iter->hmap_node);
        free(iter);
    }
    hmap_destroy(map);
}

/* Creates and adds an 'struct physical_locator' entry to 'map'. */
static void
physical_locator_map_add(struct vteprec_physical_locator *vteprec_pl,
                          struct hmap *map)
{
    struct physical_locator *pl = xmalloc(sizeof *pl);

    pl->pl = vteprec_pl;
    hmap_insert(map, &pl->hmape_node, hash_string(vteprec_pl->dst_ip, 0));
}

/* Destroys the 'map' containing 'struct physical_locator *'. */
static void
physical_locator_map_destory(struct hmap *map)
{
    struct physical_locator *iter;

    HMAP_FOR_EACH_SAFE (iter, hmap_node, map) {
        hmap_remove(map, &iter->hmap_node);
        free(iter);
    }
    hmap_destroy(map);
}


/* Collects and categorizes bindings from ovnsb.  Returns a hmap
 * containing 'struct lswitch's for bindings in the same logical
 * switch as the vtep. */
static struct hmap *
collect_bindings(struct controller_gw_ctx *ctx)
{
    struct hmap *vtep_lswitches, *other_lswitches;
    const struct sbrec_bindings *binding_rec;

    vtep_lswitches = xmalloc(sizeof *vtep_lswitches);
    other_lswitches = xmalloc(sizeof *other_lswitches);
    hmap_init(vtep_lswitches);
    hmap_init(other_lswitches);
    SBREC_BINDINGS_FOR_EACH (binding_rec, ctx->ovnsb_idl) {
        struct lswitch *ls;

        if (binding_in_hmap(binding_rec, other_pipelines, &ls)) {
            /* Do not care if 'binding_rec' is not on a logical switch
             * specified in vtep. */
            continue;
        } else if (binding_in_hmap(binding_rec, vtep_lswitches)) {
            /* The logical switch is already registered, just update the
             * bindings. */
            add_binding_macs(ls, vtep_lswitches);
        } else {
            struct lswitch *ls = xmalloc(sizeof *ls);

            hmap_init(&ls->bindings);
            /* If the binding is in the same logical switch as vtep,
             * add 'ls' to 'vtep_lswitches'. */
            if (binding_pipeline_use_vtep(binding_rec, ctx)) {
                ls->ldp_uuid = binding_rec->logical_datapath;
                ls->lswitch = find_lswitch_from_vtep(ctx, ls->ldp_uuid);
                hmap_insert(vtep_lswitches, &ls->hmap_node,
                            uuid_hash(ls->ldp_uuid));
                add_binding_macs(ls, binding_rec);
            } else {
                *ls->ldp_uuid = *binding_rec->logical_datapath;
                hmap_insert(other_lswitches, &ls->hmap_node,
                            uuid_hash(ls->ldp_uuid));
            }
        }
    }
    lswitch_destroy(other_lswitches);
    free(other_lswitches);

    return vtep_lswitches;
}

/* Collects all 'ucast_macs_remote's from vtep. */
static struct hmap *
collect_umrs(struct controller_gw_ctx *ctx)
{
    struct vteprec_ucast_macs_remote *vteprec_umr;
    struct hmap *ucast_mac_rmts = xmalloc(sizeof *ucast_mac_rmts);

    hmap_init(ucast_macs_rmts);
    VTEPREC_UCAST_MACS_REMOTE_FOR_EACH (vteprec_umr, ctx->vtep_idl) {
        ucast_macs_remote_map_add(vteprec_umr, ucast_macs_rmts);
    }

    return ucast_macs_rmts;
}

/* Collects all 'physical_locator's from vtep. */
static struct hmap *
collect_pl(struct controller_gw_ctx *ctx)
{
    struct vteprec_physical_locator *vteprec_pl;
    struct hmap *physical_locators = xmalloc(sizeof *physical_locators);

    hmap_init(physical_locators);
    VTEPREC_PHYSICAL_LOCATOR_FOR_EACH (vteprec_pl, ctx->vtep_idl) {
        physical_locator_map_add(vteprec_pl, physical_locators);
    }

    return physical_locators;
}


/* First collects required info from ovnsb and vtep.  Then updates the
 * 'Ucast_Macs_Remote' and 'Physical_Locator' tables in vtep. */
void
pipeline_run(struct controller_gw_ctx *ctx)
{
    struct hmap *vtep_lswitches = collect_bindings(ctx);
    struct hmap *ucast_mac_rmts = collect_umrs(ctx);
    struct hmap *physical_locators = collect_pl(ctx);

    txn = ovsdb_idl_txn_create(ctx->vtep_idl);
    ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller-gw: update Ucast_Macs_Remote and "
                              "to Physical_Locator");
    /* Updates the 'Ucast_Macs_Remote' table and 'Physical_Locator' table. */
    struct lswitch *lswitch;
    HMAP_FOR_EACH (lswitch, hmap_node, vtep_lswitches) {
        struct mac_to_binding *mb;

        HMAP_FOR_EACH (mb, hmap_node, &lswitch->bindings) {
            struct ucast_macs_rmt *umr;

            /* Checks if there is a 'Ucast_Macs_Remote' entry. */
            if (find_umr_by_mac(ucast_macs_rmts, mb->mac, &umr)) {
                /* Checks if 'chassis' entry is empty. */
                if (mb->binding->chassis[0]) {
                    struct physical_locator *pl;

                    /* Checks the logical_switch consistency. */
                    if (umr->logical_switch != lswitch->lswitch) {
                        vteprec_ucast_macs_remote_set_logical_switch(umr->umr, lswitch->lswitch);
                    }

                    /* Checks the physical_locator consistency. */
                    if (find_pl_by_dst_ip(physical_locators,
                                          chassis->encaps[0]->ip, &pl)) {
                        /* Do nothing, since ucast_macs_remote entry,
                           chassis and physical_locator are all there. */
                    } else {
                        struct vteprec_physical_locator *new_pl;

                        /* Creates a new 'Physical_Locator' row and updates
                         * the umr. */
                        new_pl = vteprec_physical_locator_insert(txn);
                        vteprec_physical_locator_set_dst_ip(new_pl, chassis->encaps[0]->ip);
                        vteprec_physical_locator_set_encapsulation_type(new_pl, "vxlan_over_ipv4");
                        vteprec_ucast_macs_remote_set_locator(umr->umr, new_pl);

                        physical_locator_map_add(new_pl, physical_locators);
                    }
                } else {
                    /* Removes the 'Ucast_Macs_Remote' entry in vtep. */
                    vteprec_ucast_macs_remote_delete(umr->umr);
                }
            } else {
                /* Checks if 'chassis' entry is empty. */
                if (mb->binding->chassis[0]) {
                    struct vteprec_ucast_macs_remote *new_umr;
                    struct physical_locator *pl;

                    new_umr = vteprec_ucast_macs_remote_insert(txn);
                    vteprec_ucast_macs_remote_set_mac(new_umr, mb->mac);
                    vteprec_ucast_macs_remote_set_logical_switch(new_umr, lswitch->lswitch);
                    /* Checks the physical_locator consistency. */
                    if (find_pl_by_dst_ip(physical_locators,
                                          chassis->encaps[0]->ip, &pl)) {
                        vteprec_ucast_macs_remote_set_locator(umr->umr, pl->pl);
                    } else {
                        struct vteprec_physical_locator *new_pl;

                        /* Creates a new 'Physical_Locator' row and updates
                         * the umr. */
                        new_pl = vteprec_physical_locator_insert(txn);
                        vteprec_physical_locator_set_dst_ip(new_pl, chassis->encaps[0]->ip);
                        vteprec_physical_locator_set_encapsulation_type(new_pl, "vxlan_over_ipv4");
                        vteprec_ucast_macs_remote_set_locator(umr->umr, new_pl);

                        physical_locator_map_add(new_pl, physical_locators);
                    }
                    ucast_macs_remote_map_add(new_umr, ucast_macs_rmts);
                } else {
                    /* Do nothing, since the chassis has not been identified
                     * yet. */
                }
            }
        }
    }

    int retval;
    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        VLOG_INFO("Problem registering chassis: %s",
                  ovsdb_idl_txn_status_to_string(retval));
        poll_immediate_wake();
    }
    ovsdb_idl_txn_destroy(txn);

    /* Cleans up. */
    lswitch_map_destroy(vtep_lswitches);
    ucast_macs_remote_map_destory(ucast_mac_rmts);
    physical_locator_map_destory(physical_locators);
    free(vtep_lswitches);
    free(ucast_mac_rmts);
    free(physical_locators);
}

/* First collects required info from ovnsb and vtep.  Then remove the
 * unused 'Ucast_Macs_Remote' and 'Physical_Locator' entries in vtep. */
void
pipeline_destroy(struct controller_gw_ctx *ctx)
{

}
