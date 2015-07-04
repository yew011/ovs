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
#include "list.h"
#include "lib/poll-loop.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "lib/uuid.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "vtep/vtep-idl.h"
#include "ovn-controller-vtep.h"

VLOG_DEFINE_THIS_MODULE(pipeline);

/*
 * Scans through the Binding table in ovnsb and creates the Ucast_Macs_Remote
 * rows in vtep database for each logical port's MACs in the same logical
 * datapath (logical datapath in ovnsb = logical switch in vtep).  Also,
 * creates the Physical_Locator rows to each HV chassis in the logical
 * datapath.
 *
 * xxx: take advantage of Ucast_Macs_Local.
 *
 *    vtep gateway will create entries in the Ucast_Macs_Local for
 *    each MAC learned.  ovn-controller-vtep should take advantage of
 *    this and notify the ovn-sb database in some way so that all HVs
 *    (in the same logical datapath) are aware of these MACs and will
 *    send all related packets to the vtep gateway.  We should achieve
 *    this in the near future.
 *
 */

/* A binding within a logical datapath. */
struct binding_list_node {
    struct ovs_list list_node;
    const struct sbrec_binding *binding;
};

/* Stores all info related to one logical switch in vtep. */
struct lswitch {
    struct hmap_node hmap_node;
    /* logical switch reference in vtep. */
    const struct vteprec_logical_switch *lswitch;
    /* corresponding logical datapath uuid in ovn-sb. */
    struct uuid ldp_uuid;
    /* all macs in the logical datapath */
    struct sset macs;
    struct ovs_list bd_list;       /* stores 'struct binding_list_node's. */
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
 * as 'name'. */
static const struct vteprec_logical_switch *
find_vtep_lswitch(struct controller_vtep_ctx *ctx, const char *name)
{
    const struct vteprec_logical_switch *vtep_lswitch;

    VTEPREC_LOGICAL_SWITCH_FOR_EACH (vtep_lswitch, ctx->vtep_idl) {
        if (!strcmp(vtep_lswitch->name, name)) {
            return vtep_lswitch;
        }
    }
    return NULL;
}

/* Creates an entry in 'ls->bd_list' for each mac in 'binding'. */
static void
lswitch_add_binding(struct lswitch *ls, const struct sbrec_binding *binding)
{
    struct binding_list_node *bd;
    int i;

    for (i = 0; i < binding->n_mac; i++) {
        char *mac = binding->mac[i];

        if (!strcmp(mac, "unknown")) {
            continue;
        }
        if (sset_find(&ls->macs, mac)) {
            VLOG_ERR("MAC address (%s) already exists in logical "
                     "switch (%s), ignore all macs from binding (%s)",
                     mac, ls->lswitch->name, binding->logical_port);
            return;
        }
    }
    bd = xmalloc(sizeof *bd);
    bd->binding = binding;
    /* Uses chassis name as hash key. */
    list_insert(&ls->bd_list, &bd->list_node);
}

/* Destroys the 'ls'. */
static void
lswitch_destroy(struct lswitch *ls)
{
    struct binding_list_node *iter, *next;

    sset_destroy(&ls->macs);
    LIST_FOR_EACH_SAFE (iter, next, list_node, &ls->bd_list) {
        list_remove(&iter->list_node);
        free(iter);
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

/* Searches the 'chassis_rec->encaps' for the first vtep tunnel
 * configuration, returns the 'ip'. */
static const char *
get_chassis_vtep_ip(const struct sbrec_chassis *chassis_rec)
{
    size_t i;

    for (i = 0; i < chassis_rec->n_encaps; i++) {
        if (!strcmp(chassis_rec->encaps[i]->type, "vxlan")) {
            return chassis_rec->encaps[i]->ip;
        }
    }

    return NULL;
}


/* Collects and categorizes bindings from ovnsb based on their
 * logical datapath. Returns a hmap containing 'struct lswitch's. */
static struct hmap *
collect_lswitch(struct controller_vtep_ctx *ctx)
{
    const struct vteprec_physical_switch *pswitch;
    const struct sbrec_binding *binding_rec;
    struct hmap *vtep_lswitches;
    struct sset vtep_ls = SSET_INITIALIZER(&vtep_ls);
    struct hmap binding_map = HMAP_INITIALIZER(&binding_map);

    vtep_lswitches = xmalloc(sizeof *vtep_lswitches);
    hmap_init(vtep_lswitches);

    struct binding_hash_node {
        struct hmap_node hmap_node;
        const struct sbrec_binding *binding;
    };
    /* Iterates through all bindings and creates the 'binding_map'
     * with 'logical_port' as hash. */
    SBREC_BINDING_FOR_EACH(binding_rec, ctx->ovnsb_idl) {
        struct binding_hash_node *bd = xmalloc(sizeof *bd);

        bd->binding = binding_rec;
        hmap_insert(&binding_map, &bd->hmap_node,
                    hash_string(bd->binding->logical_port, 0));
    }

    /* Discovers all vtep logical switches. */
    VTEPREC_PHYSICAL_SWITCH_FOR_EACH (pswitch, ctx->vtep_idl) {
        const struct sbrec_chassis *chassis_rec
            = get_chassis_by_name(ctx->ovnsb_idl, pswitch->name);
        struct smap_node *iter;

        /* For each undiscovered vtep logical switch, creates a
         * 'struct lswitch' instance and assigns the corresponding
         * vtep logcal switch. */
        SMAP_FOR_EACH (iter, &chassis_rec->logical_switches) {
            if (sset_find(&vtep_ls, iter->key)) {
                continue;
            } else {
                struct binding_hash_node *bd = NULL;

                /* Finds the binding entry using logical port name in
                 * 'iter->value'. */
                HMAP_FOR_EACH_WITH_HASH (bd, hmap_node,
                                         hash_string(iter->value, 0),
                                         &binding_map) {
                    if (!strcmp(bd->binding->logical_port, iter->value)) {
                        break;
                    }
                }

                /* If 'bd' is not found, just ignores this logical switch,
                 * since it is not added to OVN. */
                if (bd) {
                    struct lswitch *ls = xmalloc(sizeof *ls);

                    ls->ldp_uuid = bd->binding->logical_datapath;
                    ls->lswitch = find_vtep_lswitch(ctx, iter->key);
                    hmap_insert(vtep_lswitches, &ls->hmap_node,
                                uuid_hash(&ls->ldp_uuid));
                    sset_init(&ls->macs);
                    list_init(&ls->bd_list);

                    /* Remembers this vtep logical switch. */
                    sset_add(&vtep_ls, iter->key);
                }
            }
        }
    }
    sset_destroy(&vtep_ls);

    struct binding_hash_node *iter, *next;
    /* Now, registers the MACs for bindings belonging to discovered
     * logical switches. */
    HMAP_FOR_EACH_SAFE (iter, next, hmap_node, &binding_map) {
        struct lswitch *ls;

        /* The logical switch is discovered, updates the bindings.
         * otherwise, do nothing. */
        if (get_lswitch_from_binding(vtep_lswitches, iter->binding, &ls)) {
            lswitch_add_binding(ls, binding_rec);
        }
        hmap_remove(&binding_map, &iter->hmap_node);
        free(iter);
    }
    ovs_assert(hmap_is_empty(&binding_map));
    hmap_destroy(&binding_map);

    return vtep_lswitches;
}

/* Collects all 'ucast_macs_remote's from vtep. */
static struct hmap *
collect_umrs(struct controller_vtep_ctx *ctx)
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
collect_pl(struct controller_vtep_ctx *ctx)
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
pipeline_run(struct controller_vtep_ctx *ctx)
{
    struct hmap *vtep_lswitches = collect_lswitch(ctx);
    struct hmap *ucast_macs_rmts = collect_umrs(ctx);
    struct hmap *physical_locators = collect_pl(ctx);
    struct ovsdb_idl_txn *txn;
    struct lswitch *ls;

    txn = ovsdb_idl_txn_create(ctx->vtep_idl);
    ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller-vtep: update Ucast_Macs_Remote "
                              "and Physical_Locator");
    /* Updates the 'Ucast_Macs_Remote' table and 'Physical_Locator' table. */
    HMAP_FOR_EACH (ls, hmap_node, vtep_lswitches) {
        struct binding_list_node *bd;

        LIST_FOR_EACH (bd, list_node, &ls->bd_list) {
            const struct sbrec_chassis *chassis_rec;
            struct ucast_macs_rmt *umr;
            const char *chassis_ip;
            int i;

            chassis_rec = bd->binding->chassis;
            chassis_ip = get_chassis_vtep_ip(chassis_rec);
            for (i = 0; i < bd->binding->n_mac; i++) {
                char *mac = bd->binding->mac[i];

                /* Checks if there is a 'Ucast_Macs_Remote' entry. */
                if (get_umr_by_mac(ucast_macs_rmts, mac, &umr)) {
                    /* Checks if 'chassis' entry is empty. */
                    if (chassis_rec && chassis_ip) {
                        struct physical_locator *pl;

                        /* Checks the logical_switch consistency. */
                        if (umr->umr->logical_switch != ls->lswitch) {
                            vteprec_ucast_macs_remote_set_logical_switch(umr->umr,
                                                                         ls->lswitch);
                        }
                        /* Checks the physical_locator consistency. */
                        if (get_pl_by_ip(physical_locators, chassis_ip, &pl)) {
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
                            vteprec_physical_locator_set_dst_ip(new_pl, chassis_ip);
                            vteprec_physical_locator_set_encapsulation_type(new_pl,
                                                                            VTEP_ENCAP_TYPE);
                            vteprec_ucast_macs_remote_set_locator(umr->umr, new_pl);
                            physical_locator_map_add(new_pl, physical_locators);
                        }
                    } else {
                        /* Removes the 'Ucast_Macs_Remote' entry in vtep, since
                         * there is no chassis or no vxlan encap. */
                        vteprec_ucast_macs_remote_delete(umr->umr);
                    }

                    /* Removes umr from 'ucast_macs_rmts', since it is
                     * either renewed or deleted. */
                    hmap_remove(ucast_macs_rmts, &umr->hmap_node);
                    free(umr);
                } else {
                    /* Checks if 'chassis' entry is empty. */
                    if (chassis_rec && chassis_ip) {
                        struct vteprec_ucast_macs_remote *new_umr;
                        struct physical_locator *pl;

                        new_umr = vteprec_ucast_macs_remote_insert(txn);
                        vteprec_ucast_macs_remote_set_MAC(new_umr, mac);
                        vteprec_ucast_macs_remote_set_logical_switch(new_umr,
                                                                     ls->lswitch);
                        /* Checks if physical_locator already exists. */
                        if (get_pl_by_ip(physical_locators, chassis_ip, &pl)) {
                            vteprec_ucast_macs_remote_set_locator(new_umr,
                                                                  pl->pl);
                        } else {
                            struct vteprec_physical_locator *new_pl;

                            /* Creates a new 'Physical_Locator' row and updates
                             * the umr. */
                            new_pl = vteprec_physical_locator_insert(txn);
                            vteprec_physical_locator_set_dst_ip(new_pl,
                                                                chassis_ip);
                            vteprec_physical_locator_set_encapsulation_type(new_pl,
                                                                            VTEP_ENCAP_TYPE);
                            vteprec_ucast_macs_remote_set_locator(new_umr,
                                                                  new_pl);
                            physical_locator_map_add(new_pl, physical_locators);
                        }
                        ucast_macs_rmt_map_add(new_umr, ucast_macs_rmts);
                    } else {
                        /* Do nothing, since the chassis has not been
                         * identified yet. */
                    }
                }
            }
        }
    }

    struct ucast_macs_rmt *iter;
    /* Removes all remaining 'umr's, since they do not exist anymore. */
    HMAP_FOR_EACH (iter, hmap_node, ucast_macs_rmts) {
        vteprec_ucast_macs_remote_delete(iter->umr);
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

/* First collects required info from vtep.  Then remove the
 * unused 'Ucast_Macs_Remote' and 'Physical_Locator' entries in vtep. */
void
pipeline_destroy(struct controller_vtep_ctx *ctx)
{
    struct hmap *ucast_macs_rmts = collect_umrs(ctx);
    struct ucast_macs_rmt *umr;
    struct ovsdb_idl_txn *txn;

    txn = ovsdb_idl_txn_create(ctx->vtep_idl);
    ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller-vtep: clean up Ucast_Macs_Remote "
                              "and Physical_Locator");
    /* Cleans up all 'Ucast_Macs_Remote' entires. */
    HMAP_FOR_EACH (umr, hmap_node, ucast_macs_rmts) {
        vteprec_ucast_macs_remote_delete(umr->umr);
    }

    int retval;
    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        VLOG_INFO("Problem registering chassis: %s",
                  ovsdb_idl_txn_status_to_string(retval));
        poll_immediate_wake();
    }
    ovsdb_idl_txn_destroy(txn);

    ucast_macs_rmt_map_destory(ucast_macs_rmts);
    free(ucast_macs_rmts);
}
