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
#include "gateway.h"

#include "lib/hash.h"
#include "lib/hmap.h"
#include "lib/poll-loop.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "vtep/vtep-idl.h"
#include "ovn-controller-gw.h"

VLOG_DEFINE_THIS_MODULE(gateway);

/* Global revalidation sequence number, incremented at each call to
 * 'revalidate_gateway()'. */
static uint64_t gw_reval_seq;

/* Represents a chassis added by the gateway module.  The 'reval_seq'
 * is increment each time a chassis is revalidated.  Chassis whose 'reval_seq'
 * not equal to 'gw_reval_seq' will be removed. */
struct gw_chassis {
    struct hmap_node hmap_node; /* In 'gw_chassis'. */
    char *name;                 /* Name of the Chassis. */
    uint64_t reval_seq;         /* Chassis revalidation sequence number. */
};

/* Contains all chassis created by the gateway module. */
static struct hmap gw_chassis_map = HMAP_INITIALIZER(&gw_chassis_map);

/* Searchs 'gw_chassis_map' for chassis 'name' and returns the pointer.
 * Returns NULL, if the chassis is not found. */
static struct gw_chassis *
get_gw_chassis(const char *name)
{
    struct gw_chassis *gw_chassis;

    HMAP_FOR_EACH_WITH_HASH (gw_chassis, hmap_node, hash_string(name, 0),
                             &gw_chassis_map) {
        if (!strcmp(gw_chassis->name, name)) {
            return gw_chassis;
        }
    }

    return NULL;
}

/* Creates and returns a new instance of 'struct sbrec_chassis'. */
static const struct sbrec_chassis *
create_chassis_rec(struct ovsdb_idl_txn *txn, const char *name,
                   const char *encap_ip)
{
    const struct sbrec_chassis *chassis_rec;
    struct sbrec_encap *encap_rec;

    chassis_rec = sbrec_chassis_insert(txn);
    sbrec_chassis_set_name(chassis_rec, name);
    encap_rec = sbrec_encap_insert(txn);
    sbrec_encap_set_type(encap_rec, OVN_SB_ENCAP_TYPE);
    sbrec_encap_set_ip(encap_rec, encap_ip);
    sbrec_chassis_set_encaps(chassis_rec, &encap_rec, 1);

    return chassis_rec;
}

/* Revalidates chassis in ovnsb against vtep.  Creates chassis for new
 * vtep physical switch.  And removes chassis which no longer have physical
 * switch in vtep.
 *
 * xxx: Support multiple tunnel encaps.
 *
 * */
static void
revalidate_gateway(struct controller_gw_ctx *ctx)
{
    const struct vteprec_physical_switch *pswitch;
    struct ovsdb_idl_txn *txn;
    struct gw_chassis *iter, *next;
    int retval;

    /* Increments the global revalidation sequence number. */
    gw_reval_seq++;

    txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
    ovsdb_idl_txn_add_comment(txn, "ovn-controller-gw: updating vtep chassis");

    VTEPREC_PHYSICAL_SWITCH_FOR_EACH (pswitch, ctx->vtep_idl) {
        const struct sbrec_chassis *chassis_rec;
        struct gw_chassis *gw_chassis;
        const char *encap_ip;

        encap_ip = pswitch->n_tunnel_ips ? pswitch->tunnel_ips[0] : "";
        gw_chassis = get_gw_chassis(pswitch->name);
        chassis_rec = get_chassis_by_name(ctx->ovnsb_idl, pswitch->name);
        if (gw_chassis && !chassis_rec) {
            VLOG_WARN("Chassis for VTEP physical switch (%s) disappears, "
                      "maybe deleted by ovn-sbctl, adding it back",
                      pswitch->name);
            create_chassis_rec(txn, pswitch->name, encap_ip);
        } else if (!gw_chassis && chassis_rec) {
            VLOG_WARN("Chassis for new VTEP physical switch (%s) has already "
                      "been added, maybe by ovn-sbctl", pswitch->name);
            if (strcmp(chassis_rec->encaps[0]->type, OVN_SB_ENCAP_TYPE)
                && strcmp(chassis_rec->encaps[0]->ip, encap_ip)) {
                VLOG_WARN("Chassis config changing on startup, make sure "
                          "multiple chassis are not configured : %s/%s->%s/%s",
                          chassis_rec->encaps[0]->type,
                          chassis_rec->encaps[0]->ip,
                          OVN_SB_ENCAP_TYPE, encap_ip);
                VLOG_WARN("Skip adding chassis for physical switch (%s)",
                          pswitch->name);
                continue;
            }
            gw_chassis = xmalloc(sizeof *gw_chassis);
            gw_chassis->name = xstrdup(pswitch->name);
            hmap_insert(&gw_chassis_map, &gw_chassis->hmap_node,
                        hash_string(gw_chassis->name, 0));
        } else if (gw_chassis && chassis_rec) {
            /* Updates chassis's encap if anything changed. */
            if (strcmp(chassis_rec->encaps[0]->type, OVN_SB_ENCAP_TYPE)) {
                VLOG_WARN("Chassis for physical switch (%s) can only have "
                          "encap type \"%s\"", pswitch->name, OVN_SB_ENCAP_TYPE);
                sbrec_encap_set_type(chassis_rec->encaps[0], OVN_SB_ENCAP_TYPE);
            }
            if (strcmp(chassis_rec->encaps[0]->ip, encap_ip)) {
                sbrec_encap_set_ip(chassis_rec->encaps[0], encap_ip);
            }
        } else {
            /* Creates a new chassis for the VTEP physical switch and a new
             * gw_chassis record. */
            create_chassis_rec(txn, pswitch->name, encap_ip);
            gw_chassis = xmalloc(sizeof *gw_chassis);
            gw_chassis->name = xstrdup(pswitch->name);
            hmap_insert(&gw_chassis_map, &gw_chassis->hmap_node,
                        hash_string(gw_chassis->name, 0));
        }
        /* Updates the 'gw_chassis's revalidation seq number to prevent
         * it from being garbage collected. */
        gw_chassis->reval_seq = gw_reval_seq;
    }

    /* For 'gw_chassis' in 'gw_chassis_map' whose reval_seq is not
     * 'gw_chassis_map', it means the corresponding physical switch no
     * longer exist.  So, garbage collects them. */
    HMAP_FOR_EACH_SAFE (iter, next, hmap_node, &gw_chassis_map) {
        if (iter->reval_seq != gw_reval_seq) {
            const struct sbrec_chassis *chassis_rec;

            chassis_rec = get_chassis_by_name(ctx->ovnsb_idl, iter->name);
            if (chassis_rec) {
                sbrec_chassis_delete(chassis_rec);
            }
            hmap_remove(&gw_chassis_map, &iter->hmap_node);
            free(iter->name);
            free(iter);
        }
    }

    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        VLOG_INFO("Problem registering chassis: %s",
                  ovsdb_idl_txn_status_to_string(retval));
        poll_immediate_wake();
    }
    ovsdb_idl_txn_destroy(txn);
}

/* Updates the gateway_ports map in chassis table based on physical
 * port configuration of each VTEP physical switch. */
static void
update_physical_ports(struct controller_gw_ctx *ctx)
{
    const struct vteprec_physical_switch *pswitch;
    struct ovsdb_idl_txn *txn;
    int retval;

    txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
    ovsdb_idl_txn_add_comment(txn, "ovn-controller-gw: updating physcial ports");

    VTEPREC_PHYSICAL_SWITCH_FOR_EACH (pswitch, ctx->vtep_idl) {
        const struct sbrec_chassis *chassis_rec =
            get_chassis_by_name(ctx->ovnsb_idl, pswitch->name);
        struct sset sset = SSET_INITIALIZER(&sset);
        struct sbrec_gateway **gws;
        char **pp_names;
        bool changed = false;
        int idx = 0;
        int i;

        /* Collects all physical ports from physical switch. */
        for (i = 0; i < pswitch->n_ports; i++) {
            sset_add(&sset, pswitch->ports[i]->name);
        }

        gws = xmalloc(sizeof *gws * pswitch->n_ports);
        pp_names = xmalloc(sizeof *pp_names * pswitch->n_ports);
        /* Keeps existing rows. */
        for (i = 0; i < chassis_rec->n_gateway_ports; i++) {
            if (sset_find_and_delete(&sset, chassis_rec->key_gateway_ports[i])) {
                pp_names[i] = xstrdup(chassis_rec->key_gateway_ports[i]);
                gws[i] = chassis_rec->value_gateway_ports[i];
                idx = i + 1;
            } else {
                /* Finds a deleted entry, reports changed. */
                changed = true;
            }
        }

        /* Deletes non-existing rows and adds new rows.  */
        if (changed || !sset_is_empty(&sset)) {
            const char *iter;

            /* Adds new rows. */
            SSET_FOR_EACH (iter, &sset) {
                pp_names[idx] = xstrdup(iter);
                gws[idx] = sbrec_gateway_insert(txn);
                idx++;
            }
            sbrec_chassis_set_gateway_ports(chassis_rec,
                                            (const char **)pp_names,
                                            gws, pswitch->n_ports);
        }

        for (i = 0; i < idx; i++) {
            free(pp_names[i]);
        }
        free(pp_names);
        free(gws);
        sset_destroy(&sset);
    }

    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        VLOG_INFO("Problem registering chassis: %s",
                  ovsdb_idl_txn_status_to_string(retval));
        poll_immediate_wake();
    }
    ovsdb_idl_txn_destroy(txn);
}

/* Updates the vlan_map in gateway table based on vlan bindings
 * of physical ports. */
static void
update_vlan_map(struct controller_gw_ctx *ctx)
{
    const struct vteprec_physical_switch *pswitch;
    struct ovsdb_idl_txn *txn;
    int retval;

    txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
    ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller-gw: updating vlan map");

    struct pp {
        struct hmap_node hmap_node;  /* Inside 'physical_ports'. */

        struct vteprec_physical_port *pp;
    };

    VTEPREC_PHYSICAL_SWITCH_FOR_EACH (pswitch, ctx->vtep_idl) {
        const struct sbrec_chassis *chassis_rec =
            get_chassis_by_name(ctx->ovnsb_idl, pswitch->name);
        struct hmap physical_ports = HMAP_INITIALIZER(&physical_ports);
        int i;

        /* Collects 'physical_port's from pswitch, to avoid multiple
         * linear searches. */
        for (i = 0; i < pswitch->n_ports; i++) {
            struct pp *pp = xmalloc(sizeof *pp);

            pp->pp = pswitch->ports[i];
            hmap_insert(&physical_ports, &pp->hmap_node,
                        hash_string(pp->pp->name, 0));
        }

        /* Checks each row in Gateway table. */
        for (i = 0; i < chassis_rec->n_gateway_ports; i++) {
            struct sbrec_gateway *gw = chassis_rec->value_gateway_ports[i];
            char *port_name = chassis_rec->key_gateway_ports[i];
            struct pp *pp = NULL;
            struct pp *iter;

            HMAP_FOR_EACH_WITH_HASH (iter, hmap_node,
                                     hash_string(port_name, 0),
                                     &physical_ports) {
                if (!strcmp(iter->pp->name, port_name)) {
                    pp = iter;
                    break;
                }
            }
            /* 'pp' must exist, since the update_physical_ports() already
             * cleans up all non-exist ports. */
            ovs_assert(pp);

            /* If length or content is different, we need to recreate
             * the 'vlan_map' in 'gw'. */
            if (gw->n_vlan_map != pp->pp->n_vlan_bindings
                || memcmp(gw->key_vlan_map, pp->pp->key_vlan_bindings, gw->n_vlan_map)) {
                int64_t *vlans = xmalloc(sizeof *vlans * pp->pp->n_vlan_bindings);
                char **lports = xmalloc(sizeof *lports * pp->pp->n_vlan_bindings);
                int j;

                for (j = 0; j < pp->pp->n_vlan_bindings; j++) {
                    vlans[j] = pp->pp->key_vlan_bindings[j];
                    lports[j] = xasprintf("%s_%s_%"PRId64, pswitch->name,
                                          pp->pp->name, vlans[j]);
                }
                sbrec_gateway_set_vlan_map(gw, vlans, (const char **)lports,
                                           pp->pp->n_vlan_bindings);

                for (j = 0; j < pp->pp->n_vlan_bindings; j++) {
                    free(lports[j]);
                }
                free(lports);
                free(vlans);
            }
            hmap_remove(&physical_ports, &pp->hmap_node);
            free(pp);
        }
        /* hmap must be empty, otherwise the update_physical_port() is
         * buggy. */
        ovs_assert(hmap_is_empty(&physical_ports));
        hmap_destroy(&physical_ports);
    }

    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        VLOG_INFO("Problem registering chassis: %s",
                  ovsdb_idl_txn_status_to_string(retval));
        poll_immediate_wake();
    }
    ovsdb_idl_txn_destroy(txn);
}


void
gateway_run(struct controller_gw_ctx *ctx)
{
    revalidate_gateway(ctx);
    update_physical_ports(ctx);
    update_vlan_map(ctx);
}

void
gateway_destroy(struct controller_gw_ctx *ctx)
{
    int retval = TXN_TRY_AGAIN;

    ovs_assert(ctx->ovnsb_idl);
    while (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        const struct vteprec_physical_switch *pswitch;
        struct ovsdb_idl_txn *txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);

        ovsdb_idl_txn_add_comment(txn,
                                  "ovn-controller-gw: unregistering vtep chassis");
        VTEPREC_PHYSICAL_SWITCH_FOR_EACH (pswitch, ctx->vtep_idl) {
            const struct sbrec_chassis *chassis_rec;

            chassis_rec = get_chassis_by_name(ctx->ovnsb_idl, pswitch->name);
            if (!chassis_rec) {
                continue;
            }
            sbrec_chassis_delete(chassis_rec);
        }
        retval = ovsdb_idl_txn_commit_block(txn);
        if (retval == TXN_ERROR) {
            VLOG_INFO("Problem unregistering chassis: %s",
                      ovsdb_idl_txn_status_to_string(retval));
        }
        ovsdb_idl_txn_destroy(txn);
    }
}
