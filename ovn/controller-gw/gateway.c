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
#include "lib/poll-loop.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "vtep/vtep-idl.h"
#include "ovn-controller-gw.h"

VLOG_DEFINE_THIS_MODULE(gateway);

/* VTEP needs what VTEP needs. */
#define ENCAP_TYPE "vxlan"

/* Registers the VTEP gateway in ovn-sb. */
static void
register_gateway(struct controller_gw_ctx *ctx)
{
    const struct sbrec_chassis *chassis_rec;
    const struct vteprec_physical_switch *pswitch;
    struct sbrec_encap *encap_rec;
    struct ovsdb_idl_txn *txn;
    const char *encap_ip;
    int retval = TXN_TRY_AGAIN;
    static bool inited = false;

    chassis_rec = get_chassis_by_name(ctx->ovnsb_idl, ctx->chassis_id);

    /* xxx Need to support more than one encap ip. */
    pswitch = vteprec_physical_switch_first(ctx->vtep_idl);
    if (!pswitch) {
        VLOG_INFO("No Physical_vSwitch row defined.");
        return;
    }

    /* xxx: Allow multiple tunnel_ips. */
    if (!pswitch->n_tunnel_ips) {
        VLOG_INFO("Could not find tunnel ip");
        return;
    }
    encap_ip = pswitch->tunnel_ips[0];

    if (chassis_rec) {
        if (!strcmp(chassis_rec->encaps[0]->type, ENCAP_TYPE)
            && !strcmp(chassis_rec->encaps[0]->ip, encap_ip)) {
            /* Nothing changed. */
            inited = true;
            return;
        } else if (!inited) {
            VLOG_WARN("Gateway chassis config changing on startup, make sure "
                      "multiple chassis are not configured : %s/%s->%s/%s",
                      chassis_rec->encaps[0]->type,
                      chassis_rec->encaps[0]->ip,
                      ENCAP_TYPE, encap_ip);
        }
    }

    txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
    ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller-gw: registering gateway chassis '%s'",
                              ctx->chassis_id);

    if (!chassis_rec) {
        chassis_rec = sbrec_chassis_insert(txn);
        sbrec_chassis_set_name(chassis_rec, ctx->chassis_id);
    }

    encap_rec = sbrec_encap_insert(txn);
    sbrec_encap_set_type(encap_rec, ENCAP_TYPE);
    sbrec_encap_set_ip(encap_rec, encap_ip);
    sbrec_chassis_set_encaps(chassis_rec, &encap_rec, 1);

    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        VLOG_INFO("Problem registering chassis: %s",
                  ovsdb_idl_txn_status_to_string(retval));
        poll_immediate_wake();
    }
    ovsdb_idl_txn_destroy(txn);

    inited = true;
}

/* Updates the gateway_ports map in chassis table based on physical
 * port configuration in VTEP. */
static void
update_physical_ports(struct controller_gw_ctx *ctx)
{
    const struct sbrec_chassis *chassis_rec;
    const struct vteprec_physical_switch *pswitch;
    char **pp_names;
    struct sbrec_gateway **gws;
    struct sset sset = SSET_INITIALIZER(&sset);
    bool changed = false;
    int idx = 0;
    int i;

    chassis_rec = get_chassis_by_name(ctx->ovnsb_idl, ctx->chassis_id);
    if (!chassis_rec) {
        return;
    }

    pswitch = vteprec_physical_switch_first(ctx->vtep_idl);
    if (!pswitch) {
        return;
    }

    /* Collects all physical ports from vtep. */
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
            changed = true;
        }
    }

    /* Deletes non-existing rows and adds new rows.  */
    if (changed || !sset_is_empty(&sset)) {
        struct ovsdb_idl_txn *txn;
        const char *iter;
        int retval;

        txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);

        /* Adds new rows. */
        SSET_FOR_EACH (iter, &sset) {
            pp_names[idx] = xstrdup(iter);
            gws[idx] = sbrec_gateway_insert(txn);;
            sbrec_gateway_set_attached_port(gws[idx], pp_names[idx]);
            idx++;
        }
        sbrec_chassis_set_gateway_ports(chassis_rec, (const char **)pp_names,
                                        gws, pswitch->n_ports);
        retval = ovsdb_idl_txn_commit_block(txn);
        if (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
            VLOG_INFO("Problem registering chassis: %s",
                      ovsdb_idl_txn_status_to_string(retval));
            poll_immediate_wake();
        }
        ovsdb_idl_txn_destroy(txn);
    }

    for (i = 0; i < idx; i++) {
        free(pp_names[i]);
    }
    free(pp_names);
    free(gws);
    sset_destroy(&sset);
}

/* Updates the vlan_map in gateway table based on vlan bindings
 * in VTEP. */
static void
update_vlan_map(struct controller_gw_ctx *ctx)
{
    struct pp {
        struct hmap_node node;  /* Inside 'physical_ports'. */

        struct vteprec_physical_port *pp;
    };

    const struct sbrec_chassis *chassis_rec;
    const struct vteprec_physical_switch *pswitch;
    struct hmap physical_ports = HMAP_INITIALIZER(&physical_ports);
    int i;

    chassis_rec = get_chassis_by_name(ctx->ovnsb_idl, ctx->chassis_id);
    if (!chassis_rec) {
        return;
    }

    pswitch = vteprec_physical_switch_first(ctx->vtep_idl);
    if (!pswitch) {
        return;
    }

    /* Collects 'physical_port's from pswitch, to avoid multiple
     * linear searches. */
    for (i = 0; i < chassis_rec->n_gateway_ports; i++) {
        struct pp *pp = xmalloc(sizeof *pp);

        pp->pp = pswitch->ports[i];
        hmap_insert(&physical_ports, &pp->node, hash_string(pp->pp->name, 0));
    }

    /* Checks each row in Gateway table. */
    for (i = 0; i < chassis_rec->n_gateway_ports; i++) {
        struct sbrec_gateway *gw = chassis_rec->value_gateway_ports[i];
        char *port_name = chassis_rec->key_gateway_ports[i];
        struct pp *pp = NULL;
        struct pp *iter;

        HMAP_FOR_EACH_WITH_HASH (iter, node, hash_string(port_name, 0),
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
            struct ovsdb_idl_txn *txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
            int64_t *vlans = xmalloc(sizeof *vlans * pp->pp->n_vlan_bindings);
            char **lports = xmalloc(sizeof *lports * pp->pp->n_vlan_bindings);
            int j, retval;

            for (j = 0; j < pp->pp->n_vlan_bindings; j++) {
                vlans[j] = pp->pp->key_vlan_bindings[j];
                lports[j] = xasprintf("%s_%s_%"PRId64, pswitch->name,
                                      pp->pp->name, vlans[j]);
            }
            sbrec_gateway_set_vlan_map(gw, vlans, (const char **)lports,
                                       pp->pp->n_vlan_bindings);

            retval = ovsdb_idl_txn_commit_block(txn);
            if (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
                VLOG_INFO("Problem registering chassis: %s",
                          ovsdb_idl_txn_status_to_string(retval));
                poll_immediate_wake();
            }
            ovsdb_idl_txn_destroy(txn);
            for (j = 0; j < pp->pp->n_vlan_bindings; j++) {
                free(lports[j]);
            }
            free(lports);
            free(vlans);
        }
        hmap_remove(&physical_ports, &pp->node);
        free(pp);
    }
    /* hmap must be empty, otherwise the update_physical_port() is
     * buggy. */
    ovs_assert(hmap_is_empty(&physical_ports));
    hmap_destroy(&physical_ports);
}


void
gateway_run(struct controller_gw_ctx *ctx)
{
    register_gateway(ctx);
    update_physical_ports(ctx);
    update_vlan_map(ctx);
}

void
gateway_destroy(struct controller_gw_ctx *ctx)
{
    int retval = TXN_TRY_AGAIN;

    ovs_assert(ctx->ovnsb_idl);

    while (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        const struct sbrec_chassis *chassis_rec;
        struct ovsdb_idl_txn *txn;

        chassis_rec = get_chassis_by_name(ctx->ovnsb_idl, ctx->chassis_id);

        if (!chassis_rec) {
            break;
        }

        txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
        ovsdb_idl_txn_add_comment(txn,
                                  "ovn-controller: unregistering chassis '%s'",
                                  ctx->chassis_id);
        sbrec_chassis_delete(chassis_rec);

        retval = ovsdb_idl_txn_commit_block(txn);
        if (retval == TXN_ERROR) {
            VLOG_INFO("Problem unregistering chassis: %s",
                      ovsdb_idl_txn_status_to_string(retval));
        }
        ovsdb_idl_txn_destroy(txn);
    }
}
