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

#define ENCAP_TYPE "vxlan"

/* Registers the VTEP gateway in ovn-sb.
 * TODO: Allow constant updating. */
static void
register_gw(struct controller_gw_ctx *ctx)
{
    const struct sbrec_chassis *chassis_rec;
    const struct vteprec_physical_switch *pswitch;
    struct sbrec_encap *encap_rec;
    struct ovsdb_idl_txn *txn;
    const char *encap_ip;
    int retval = TXN_TRY_AGAIN;
    static bool inited = false;
    int i;

    if (inited) {
        return;
    }

    SBREC_CHASSIS_FOR_EACH(chassis_rec, ctx->ovnsb_idl) {
        if (!strcmp(chassis_rec->name, ctx->chassis_id)) {
            break;
        }
    }
    ovs_assert(!chassis_rec);

    /* xxx Need to support more than one encap ip. */
    pswitch = vteprec_physical_switch_first(ctx->vtep_idl);
    if (!pswitch) {
        VLOG_INFO("No Open_vSwitch row defined.");
        return;
    }

    /* TODO: Allow multiple tunnel_ips. */
    if (!pswitch->n_tunnel_ips) {
        VLOG_INFO("Could not find tunnel ip");
        return;
    }
    encap_ip = pswitch->tunnel_ips[0];

    if (!pswitch->n_ports) {
        VLOG_INFO("Could not find any physical ports");
        return;
    }

    txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
    ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller-gw: registering gateway chassis '%s'",
                              ctx->chassis_id);

    chassis_rec = sbrec_chassis_insert(txn);

    sbrec_chassis_set_name(chassis_rec, ctx->chassis_id);
    encap_rec = sbrec_encap_insert(txn);
    sbrec_encap_set_type(encap_rec, ENCAP_TYPE);
    sbrec_encap_set_ip(encap_rec, encap_ip);
    sbrec_chassis_set_encaps(chassis_rec, &encap_rec, 1);

    const char **pp_names = xmalloc(sizeof *pp_names * pswitch->n_ports);
    struct sbrec_gateway **gws = xmalloc(sizeof *gws * pswitch->n_ports);

    for (i = 0; i < pswitch->n_ports; i++) {
        pp_names[i] = pswitch->ports[i]->name;
        gws[i] = sbrec_gateway_insert(txn);
        sbrec_gateway_set_attached_port(gws[i], pp_names[i]);
    }
    sbrec_chassis_set_gateway_ports(chassis_rec, pp_names, gws,
                                    pswitch->n_ports);
    free(pp_names);
    free(gws);

    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        VLOG_INFO("Problem registering chassis: %s",
                  ovsdb_idl_txn_status_to_string(retval));
        poll_immediate_wake();
    }
    ovsdb_idl_txn_destroy(txn);

    inited = true;
}

void
gateway_run(struct controller_gw_ctx *ctx)
{
    register_gw(ctx);
}

void
gateway_destroy(struct controller_gw_ctx *ctx)
{
    int retval = TXN_TRY_AGAIN;

    ovs_assert(ctx->ovnsb_idl);

    while (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        const struct sbrec_chassis *chassis_rec;
        struct ovsdb_idl_txn *txn;

        SBREC_CHASSIS_FOR_EACH(chassis_rec, ctx->ovnsb_idl) {
            if (!strcmp(chassis_rec->name, ctx->chassis_id)) {
                break;
            }
        }

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

    /* TODO: (maybe not necessary) remove the config in vtep? */
}
