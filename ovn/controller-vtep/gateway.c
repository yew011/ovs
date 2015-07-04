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
#include "ovn-controller-vtep.h"

VLOG_DEFINE_THIS_MODULE(gateway);

/*
 * Registers the physical switches in vtep to ovnsb as chassis.  For each
 * physical switch in the vtep database, finds all logical switches that
 * are associated with the physical switch, and updates the corresponding
 * chassis's 'logical_switches' column.
 *
 */

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

/* Revalidates chassis in ovnsb against vtep database.  Creates chassis for
 * new vtep physical switch.  And removes chassis which no longer have
 * physical switch in vtep.
 *
 * xxx: Support multiple tunnel encaps.
 *
 * */
static void
revalidate_gateway(struct controller_vtep_ctx *ctx)
{
    const struct vteprec_physical_switch *pswitch;
    struct ovsdb_idl_txn *txn;
    struct gw_chassis *iter, *next;
    int retval;

    /* Increments the global revalidation sequence number. */
    gw_reval_seq++;

    txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
    ovsdb_idl_txn_add_comment(txn, "ovn-controller-vtep: updating vtep chassis");

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
                VLOG_WARN("Chassis for VTEP physical switch (%s) can only have "
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
     * 'gw_reval_seq', it means the corresponding physical switch no
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

/* Updates the logical switches in the Chassis table based on vtep database
 * configuration. */
static void
update_logical_switches(struct controller_vtep_ctx *ctx)
{
    const struct vteprec_physical_switch *pswitch;
    struct ovsdb_idl_txn *txn;
    int retval;

    txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
    ovsdb_idl_txn_add_comment(txn, "ovn-controller-vtep: "
                              "updating logical switches");

    VTEPREC_PHYSICAL_SWITCH_FOR_EACH (pswitch, ctx->vtep_idl) {
        const struct sbrec_chassis *chassis_rec =
            get_chassis_by_name(ctx->ovnsb_idl, pswitch->name);
        struct smap lswitches = SMAP_INITIALIZER(&lswitches);
        size_t i;

        for (i = 0; i < pswitch->n_ports; i++) {
            const struct vteprec_physical_port *port = pswitch->ports[i];
            size_t j;

            for (j = 0; j < port->n_vlan_bindings; j++) {
                const struct vteprec_logical_switch *ls;

                ls = port->value_vlan_bindings[j];
                /* If not already in 'lswitches', adds the logical switch
                 * to logical port map.  The logical port is defined as
                 * {pswitch->name}_{ls->name}. */
                if (!smap_get(&lswitches, ls->name)) {
                    char *lport = xasprintf("%s_%s", pswitch->name, ls->name);

                    smap_add(&lswitches, ls->name, lport);
                    free(lport);
                }
            }
        }
        sbrec_chassis_set_logical_switches(chassis_rec, &lswitches);
        smap_destroy(&lswitches);
    }

    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        VLOG_INFO("Problem updating chassis's logical_switches: %s",
                  ovsdb_idl_txn_status_to_string(retval));
        poll_immediate_wake();
    }
    ovsdb_idl_txn_destroy(txn);
}


void
gateway_run(struct controller_vtep_ctx *ctx)
{
    revalidate_gateway(ctx);
    update_logical_switches(ctx);
}

/* Destroys the chassis table entries of the vtep physical switches. */
void
gateway_destroy(struct controller_vtep_ctx *ctx)
{
    int retval = TXN_TRY_AGAIN;

    ovs_assert(ctx->ovnsb_idl);
    while (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        const struct vteprec_physical_switch *pswitch;
        struct ovsdb_idl_txn *txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);

        ovsdb_idl_txn_add_comment(txn,
                                  "ovn-controller-vtep: "
                                  "unregistering vtep chassis");
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
