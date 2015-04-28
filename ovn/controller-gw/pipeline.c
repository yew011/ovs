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
#include "lib/hash.h"
#include "lib/poll-loop.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "lib/uuid.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "vtep/vtep-idl.h"
#include "ovn-controller-gw.h"

VLOG_DEFINE_THIS_MODULE(pipeline);

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
    struct uuid ldp_uuid;
    struct hmap bindings;       /* stores 'struct mac_to_binding's. */
};

/* An 'Ucast_Macs_Remote' entry in vtep. */
struct ucast_macs_rmt {
    struct hmap_node hmap_node;

    const struct vteprec_ucast_macs_remote *umr;
};

/* An 'Physical_Locator' entry in vtep. */
struct physical_locator {
    struct hmap_node hmap_node;

    const struct vteprec_physical_locator *pl;
};


/* Returns true if the 'binding's logical datapath has already been
 * stored in 'ls_map', also saves found record in 'lsp'.  Otherwise,
 * returns false.*/
static bool
get_lswitch_from_binding(struct hmap *ls_map,
                         const struct sbrec_binding *binding,
                         struct lswitch **lsp)
{
    struct lswitch *ls;

    HMAP_FOR_EACH_WITH_HASH (ls, hmap_node,
                             uuid_hash(&binding->logical_datapath), ls_map) {
        if (uuid_equals(&ls->ldp_uuid, &binding->logical_datapath)) {
            *lsp = ls;
            return true;
        }
    }
    return false;
}

/* Finds and returns the reference to logical switch in vtep with same name
 * as 'uuid'. */
static const struct vteprec_logical_switch *
find_vtep_lswitch(struct controller_gw_ctx *ctx, const struct uuid *uuid)
{
    const struct vteprec_logical_switch *vlswitch;

    VTEPREC_LOGICAL_SWITCH_FOR_EACH (vlswitch, ctx->vtep_idl) {
        struct uuid uuid_;

        uuid_from_string(&uuid_, vlswitch->name);
        if (!memcmp(uuid, &uuid_, sizeof *uuid)) {
            return vlswitch;
        }
    }
    return NULL;
}

/* Finds and returns the reference to 'struct lswitch' with the same name. */
static const struct lswitch *
find_struct_lswitch(const struct hmap *ls_map,
                    const struct vteprec_logical_switch *vlswitch)
{
    struct lswitch *ls;
    struct uuid uuid_;

    uuid_from_string(&uuid_, vlswitch->name);
    HMAP_FOR_EACH_WITH_HASH (ls, hmap_node, uuid_hash(&uuid_), ls_map) {
        if (uuid_equals(&ls->ldp_uuid, &uuid_)) {
            return ls;
        }
    }

    return NULL;
}

/* Returns true if the logical switch containing the logical port represented
 * by 'binding_rec' is also defined in VTEP. */
static bool
binding_pipeline_use_vtep(struct controller_gw_ctx *ctx,
                          const struct sbrec_binding *binding)
{
    return find_vtep_lswitch(ctx, &binding->logical_datapath)
           ? true : false;
}

/* If there is already an 'mb' entry for 'mac' in 'ls->bindings',
 * returns the true and sets 'mbp' to 'mb'.  Otherwise, returns NULL
 * and leaves 'mbp' unchanged. */
static bool
get_mb_from_lswitch(const struct lswitch *ls, const char *mac,
                    struct mac_to_binding **mbp)
{
    struct mac_to_binding *mb;

    HMAP_FOR_EACH_WITH_HASH (mb, hmap_node, hash_string(mac, 0),
                             &ls->bindings) {
        if (!strcmp(mac, mb->mac)) {
            *mbp = mb;
            return true;
        }
    }
    return false;
}

/* Creates an entry in 'ls->bindings' for each mac in 'binding'. */
static void
add_binding_macs(struct lswitch *ls, const struct sbrec_binding *binding)
{
    int i;

    for (i = 0; i < binding->n_mac; i++) {
        struct mac_to_binding *mb;
        char *mac = binding->mac[i];

        /* Duplication check. */
        /* TODO: It is actually possible to have duplicate MACs. */
        if (get_mb_from_lswitch(ls, mac, &mb)) {
            VLOG_ERR("MAC address (%s) already exists in logical "
                     "switch (%s)", mac, ls->lswitch->name);
            continue;
        } else {
            mb = xmalloc(sizeof *mb);
            mb->mac = mac;
            mb->binding = binding;
            hmap_insert(&ls->bindings, &mb->hmap_node, hash_string(mb->mac, 0));
        }
    }
}

/* Destroys the 'ls'. */
static void
lswitch_destroy(struct lswitch *ls)
{
    struct mac_to_binding *mb, *next;

    HMAP_FOR_EACH_SAFE (mb, next, hmap_node, &ls->bindings) {
        hmap_remove(&ls->bindings, &mb->hmap_node);
        free(mb);
    }
}

/* Destroys the 'ls_map' containing 'struct lswitch *'. */
static void
lswitch_map_destroy(struct hmap *ls_map)
{
    struct lswitch *ls, *next;

    HMAP_FOR_EACH_SAFE (ls, next, hmap_node, ls_map) {
        hmap_remove(ls_map, &ls->hmap_node);
        lswitch_destroy(ls);
        free(ls);

    }
    hmap_destroy(ls_map);
}

/* Creates and adds an 'struct ucast_macs_rmt' entry to 'umr_map'. */
static void
ucast_macs_rmt_map_add(const struct vteprec_ucast_macs_remote *vteprec_umr,
                       struct hmap *umr_map)
{
    struct ucast_macs_rmt *umr = xmalloc(sizeof *umr);

    umr->umr = vteprec_umr;
    hmap_insert(umr_map, &umr->hmap_node, hash_string(vteprec_umr->MAC, 0));
}

/* Destroys the 'umr_map' containing 'struct ucast_macs_remote *'. */
static void
ucast_macs_rmt_map_destory(struct hmap *umr_map)
{
    struct ucast_macs_rmt *umr, *next;

    HMAP_FOR_EACH_SAFE (umr, next, hmap_node, umr_map) {
        hmap_remove(umr_map, &umr->hmap_node);
        free(umr);
    }
    hmap_destroy(umr_map);
}

/* Creates and adds an 'struct physical_locator' entry to 'pl_map'. */
static void
physical_locator_map_add(const struct vteprec_physical_locator *vteprec_pl,
                         struct hmap *pl_map)
{
    struct physical_locator *pl = xmalloc(sizeof *pl);

    pl->pl = vteprec_pl;
    hmap_insert(pl_map, &pl->hmap_node, hash_string(vteprec_pl->dst_ip, 0));
}

/* Destroys the 'pl_map' containing 'struct physical_locator *'. */
static void
physical_locator_map_destory(struct hmap *pl_map)
{
    struct physical_locator *pl, *next;

    HMAP_FOR_EACH_SAFE (pl, next, hmap_node, pl_map) {
        hmap_remove(pl_map, &pl->hmap_node);
        free(pl);
    }
    hmap_destroy(pl_map);
}

/* Returns true if there is 'umr' with same 'mac' in 'umr_map'
 * and sets the 'umrp'.  Returns false otherwise. */
static bool
get_umr_by_mac(struct hmap *umr_map, const char *mac,
               struct ucast_macs_rmt **umrp)
{
    struct ucast_macs_rmt *umr;

    HMAP_FOR_EACH_WITH_HASH (umr, hmap_node, hash_string(mac, 0), umr_map) {
        if (!strcmp(mac, umr->umr->MAC)) {
            *umrp = umr;
            return true;
        }
    }
    return false;
}

/* Returns true if there is 'pl' with same 'ip' in 'pl_map'
 * and sets the 'plp'.  Returns false otherwise. */
static bool
get_pl_by_ip(struct hmap *pl_map, const char *ip,
             struct physical_locator **plp)
{
    struct physical_locator *pl;

    HMAP_FOR_EACH_WITH_HASH (pl, hmap_node, hash_string(ip, 0), pl_map) {
        if (!strcmp(ip, pl->pl->dst_ip)) {
            *plp = pl;
            return true;
        }
    }
    return false;
}


/* Collects and categorizes bindings from ovnsb.  Returns a hmap
 * containing 'struct lswitch's for bindings in the same logical
 * switch as the vtep. */
static struct hmap *
collect_bindings(struct controller_gw_ctx *ctx)
{
    struct hmap *vtep_lswitches, *other_lswitches;
    const struct sbrec_binding *binding_rec;

    vtep_lswitches = xmalloc(sizeof *vtep_lswitches);
    other_lswitches = xmalloc(sizeof *other_lswitches);
    hmap_init(vtep_lswitches);
    hmap_init(other_lswitches);
    SBREC_BINDING_FOR_EACH (binding_rec, ctx->ovnsb_idl) {
        struct lswitch *ls;

        if (get_lswitch_from_binding(other_lswitches, binding_rec, &ls)) {
            /* Do not care if 'binding_rec' is not on a logical switch
             * specified in vtep. */
            continue;
        } else if (get_lswitch_from_binding(vtep_lswitches, binding_rec, &ls)) {
            /* The logical switch is already registered, just update the
             * bindings. */
            add_binding_macs(ls, binding_rec);
        } else {
            struct lswitch *ls = xmalloc(sizeof *ls);

            hmap_init(&ls->bindings);
            /* If the binding is in the same logical switch as vtep,
             * add 'ls' to 'vtep_lswitches'. */
            if (binding_pipeline_use_vtep(ctx, binding_rec)) {
                ls->ldp_uuid = binding_rec->logical_datapath;
                ls->lswitch = find_vtep_lswitch(ctx, &ls->ldp_uuid);
                hmap_insert(vtep_lswitches, &ls->hmap_node,
                            uuid_hash(&ls->ldp_uuid));
                add_binding_macs(ls, binding_rec);
            } else {
                ls->ldp_uuid = binding_rec->logical_datapath;
                hmap_insert(other_lswitches, &ls->hmap_node,
                            uuid_hash(&ls->ldp_uuid));
            }
        }
    }
    lswitch_map_destroy(other_lswitches);
    free(other_lswitches);

    return vtep_lswitches;
}

/* Collects all 'ucast_macs_remote's from vtep. */
static struct hmap *
collect_umrs(struct controller_gw_ctx *ctx)
{
    const struct vteprec_ucast_macs_remote *vteprec_umr;
    struct hmap *ucast_macs_rmts = xmalloc(sizeof *ucast_macs_rmts);

    hmap_init(ucast_macs_rmts);
    VTEPREC_UCAST_MACS_REMOTE_FOR_EACH (vteprec_umr, ctx->vtep_idl) {
        ucast_macs_rmt_map_add(vteprec_umr, ucast_macs_rmts);
    }

    return ucast_macs_rmts;
}

/* Collects all 'physical_locator's from vtep. */
static struct hmap *
collect_pl(struct controller_gw_ctx *ctx)
{
    const struct vteprec_physical_locator *vteprec_pl;
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
    struct hmap *ucast_macs_rmts = collect_umrs(ctx);
    struct hmap *physical_locators = collect_pl(ctx);
    struct ovsdb_idl_txn *txn;
    struct lswitch *ls;

    txn = ovsdb_idl_txn_create(ctx->vtep_idl);
    ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller-gw: update Ucast_Macs_Remote and "
                              "Physical_Locator");
    /* Updates the 'Ucast_Macs_Remote' table and 'Physical_Locator' table. */
    HMAP_FOR_EACH (ls, hmap_node, vtep_lswitches) {
        struct mac_to_binding *mb;

        HMAP_FOR_EACH (mb, hmap_node, &ls->bindings) {
            struct ucast_macs_rmt *umr;

            /* Checks if there is a 'Ucast_Macs_Remote' entry. */
            if (get_umr_by_mac(ucast_macs_rmts, mb->mac, &umr)) {
                /* Checks if 'chassis' entry is empty. */
                if (mb->binding->chassis) {
                    const struct sbrec_chassis *chassis_rec;
                    struct physical_locator *pl;

                    chassis_rec = mb->binding->chassis;
                    /* Checks the logical_switch consistency. */
                    if (umr->umr->logical_switch != ls->lswitch) {
                        vteprec_ucast_macs_remote_set_logical_switch(umr->umr, ls->lswitch);
                    }

                    /* Checks the physical_locator consistency. */
                    if (get_pl_by_ip(physical_locators,
                                     chassis_rec->encaps[0]->ip, &pl)) {
                        if (umr->umr->locator != pl->pl) {
                            vteprec_ucast_macs_remote_set_locator(umr->umr,
                                                                  pl->pl);
                        } else {
                            /* Do nothing, since ucast_macs_remote entry,
                             * chassis and physical_locator are all there. */
                        }
                    } else {
                        struct vteprec_physical_locator *new_pl;

                        /* Creates a new 'Physical_Locator' row and updates
                         * the umr. */
                        new_pl = vteprec_physical_locator_insert(txn);
                        vteprec_physical_locator_set_dst_ip(new_pl, chassis_rec->encaps[0]->ip);
                        vteprec_physical_locator_set_encapsulation_type(new_pl, "vxlan_over_ipv4");
                        vteprec_ucast_macs_remote_set_locator(umr->umr, new_pl);
                        physical_locator_map_add(new_pl, physical_locators);
                    }
                } else {
                    /* Removes the 'Ucast_Macs_Remote' entry in vtep, since
                     * there is no chassis. */
                    vteprec_ucast_macs_remote_delete(umr->umr);
                }
            } else {
                /* Checks if 'chassis' entry is empty. */
                if (mb->binding->chassis) {
                    const struct sbrec_chassis *chassis_rec;
                    struct vteprec_ucast_macs_remote *new_umr;
                    struct physical_locator *pl;

                    chassis_rec = mb->binding->chassis;
                    new_umr = vteprec_ucast_macs_remote_insert(txn);
                    vteprec_ucast_macs_remote_set_MAC(new_umr, mb->mac);
                    vteprec_ucast_macs_remote_set_logical_switch(new_umr, ls->lswitch);
                    /* Checks if physical_locator already exists. */
                    if (get_pl_by_ip(physical_locators,
                                     chassis_rec->encaps[0]->ip, &pl)) {
                        vteprec_ucast_macs_remote_set_locator(new_umr, pl->pl);
                    } else {
                        struct vteprec_physical_locator *new_pl;

                        /* Creates a new 'Physical_Locator' row and updates
                         * the umr. */
                        new_pl = vteprec_physical_locator_insert(txn);
                        vteprec_physical_locator_set_dst_ip(new_pl, chassis_rec->encaps[0]->ip);
                        vteprec_physical_locator_set_encapsulation_type(new_pl, "vxlan_over_ipv4");
                        vteprec_ucast_macs_remote_set_locator(new_umr, new_pl);
                        physical_locator_map_add(new_pl, physical_locators);
                    }
                    ucast_macs_rmt_map_add(new_umr, ucast_macs_rmts);
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
    ucast_macs_rmt_map_destory(ucast_macs_rmts);
    physical_locator_map_destory(physical_locators);
    free(vtep_lswitches);
    free(ucast_macs_rmts);
    free(physical_locators);
}

/* First collects required info from ovnsb and vtep.  Then remove the
 * unused 'Ucast_Macs_Remote' and 'Physical_Locator' entries in vtep. */
void
pipeline_destroy(struct controller_gw_ctx *ctx)
{
    struct hmap *vtep_lswitches = collect_bindings(ctx);
    struct hmap *ucast_macs_rmts = collect_umrs(ctx);
    struct ucast_macs_rmt *umr;
    struct ovsdb_idl_txn *txn;

    txn = ovsdb_idl_txn_create(ctx->vtep_idl);
    ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller-gw: clean up Ucast_Macs_Remote and "
                              "Physical_Locator");
    /* Cleans up all unused 'Ucast_Macs_Remote' entires. */
    HMAP_FOR_EACH (umr, hmap_node, ucast_macs_rmts) {
        const struct lswitch *ls;
        struct mac_to_binding *mb;

        /* Finds 'ls' corresponding to the same logical switch. */
        ls = find_struct_lswitch(vtep_lswitches, umr->umr->logical_switch);
        ovs_assert(ls);

        /* If could not find 'mb' from lswitch or binding's chassis is empty,
         * removes the 'umr'. */
        if (!get_mb_from_lswitch(ls, umr->umr->MAC, &mb)) {
            vteprec_ucast_macs_remote_delete(umr->umr);
        } else if (mb->binding->chassis) {
            vteprec_ucast_macs_remote_delete(umr->umr);
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

    lswitch_map_destroy(vtep_lswitches);
    ucast_macs_rmt_map_destory(ucast_macs_rmts);
    free(vtep_lswitches);
    free(ucast_macs_rmts);
}
