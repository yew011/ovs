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

/* Registers the VTEP gateway in ovn-sb. */
static void
register_gw(struct controller_gw_ctx *ctx)
{
    const struct sbrec_chassis *chassis_rec;
    const struct vteprec_physical_switch *cfg;
    const char *encap_ip;
    struct sbrec_encap *encap_rec;
    static bool inited = false;
    int retval = TXN_TRY_AGAIN;
    struct ovsdb_idl_txn *txn;

    SBREC_CHASSIS_FOR_EACH(chassis_rec, ctx->ovnsb_idl) {
        if (!strcmp(chassis_rec->name, ctx->chassis_id)) {
            break;
        }
    }

    /* xxx Need to support more than one encap ip. */
    cfg = vteprec_physical_switch_first(ctx->vtep_idl);
    if (!cfg) {
        VLOG_INFO("No Open_vSwitch row defined.");
        return;
    }

    /* TODO: Allow multiple tunnel_ips. */
    if (!cfg->n_tunnel_ips) {
        VLOG_INFO("Could not find tunnel ip");
        return;
    }
    encap_ip = cfg->tunnel_ips[0];

    if (chassis_rec) {
        int i;

        for (i = 0; i < chassis_rec->n_encaps; i++) {
            if (!strcmp(chassis_rec->encaps[i]->type, ENCAP_TYPE)
                && !strcmp(chassis_rec->encaps[i]->ip, encap_ip)) {
                /* Nothing changed. */
                inited = true;
                return;
            } else if (!inited) {
                VLOG_WARN("Chassis config changing on startup, make sure "
                          "multiple chassis are not configured : %s/%s->%s/%s",
                          chassis_rec->encaps[i]->type,
                          chassis_rec->encaps[i]->ip,
                          ENCAP_TYPE, encap_ip);
            }

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


    /* TODO: update the gateway_ports column and the Gateway table. */

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
