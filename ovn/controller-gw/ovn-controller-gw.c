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

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "poll-loop.h"
#include "fatal-signal.h"
#include "vtep/vtep-idl.h"
#include "smap.h"
#include "stream.h"
#include "stream-ssl.h"
#include "unixctl.h"
#include "util.h"

#include "gateway.h"
#include "ovn-controller-gw.h"

VLOG_DEFINE_THIS_MODULE(ovn_gw);

static unixctl_cb_func ovn_controller_gw_exit;
static unixctl_cb_func ovn_controller_gw_add_lswitch;
static unixctl_cb_func ovn_controller_gw_add_lport;

static void parse_options(int argc, char *argv[]);
OVS_NO_RETURN static void usage(void);

static char *vtep_remote;
static char *ovnsb_remote;


static void
get_initial_snapshot(struct ovsdb_idl *idl)
{
    while (1) {
        ovsdb_idl_run(idl);
        if (ovsdb_idl_has_ever_connected(idl)) {
            return;
        }
        ovsdb_idl_wait(idl);
        poll_block();
    }
}

/* Retrieve the VTEP physical bridge name.
 * xxx ovn-controller-gw does not support changing any of these mid-run,
 * xxx but that should be addressed later. */
static void
get_core_config(struct controller_gw_ctx *ctx)
{
    const struct vteprec_physical_switch *cfg;

    cfg = vteprec_physical_switch_first(ctx->vtep_idl);
    if (!cfg) {
        VLOG_ERR("No Physical Switch row defined.");
        goto err;
    }

    if (!cfg->name) {
        VLOG_ERR("Could not get Physical Switch name.");
        goto err;
    }
    ctx->chassis_id = xstrdup(cfg->name);
    return;

err:
    ovsdb_idl_destroy(ctx->vtep_idl);
    exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    struct controller_gw_ctx ctx = { .chassis_id = NULL };
    bool exiting;
    int retval;

    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    parse_options(argc, argv);
    fatal_ignore_sigpipe();

    daemonize_start();

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, ovn_controller_gw_exit,
                             &exiting);
    unixctl_command_register("add-lswitch", "name tunnel_key", 2, 2,
                             ovn_controller_gw_add_lswitch, &ctx);
    unixctl_command_register("add-lport", "lswitch_name lport_name phy_port vlan",
                             4, 4, ovn_controller_gw_add_lport, &ctx);

    daemonize_complete();

    vteprec_init();
    sbrec_init();

    /* Connect to VTEP OVSDB instance.  We monitor all tables by
     * default */
    ctx.vtep_idl = ovsdb_idl_create(vtep_remote, &vteprec_idl_class, true, true);

    get_initial_snapshot(ctx.vtep_idl);

    get_core_config(&ctx);

    /* TODO: Change this 'get_core_config(&ctx)' to unixctl command for
     * setting e.g., system-ids. */

    ctx.ovnsb_idl = ovsdb_idl_create(ovnsb_remote, &sbrec_idl_class,
                                     true, true);

    get_initial_snapshot(ctx.ovnsb_idl);

    ovs_assert(vteprec_global_first(ctx.vtep_idl));

    exiting = false;
    while (!exiting) {
        ovsdb_idl_run(ctx.vtep_idl);
        ovsdb_idl_run(ctx.ovnsb_idl);

        if (!ovsdb_idl_is_alive(ctx.ovnsb_idl)) {
            int retval = ovsdb_idl_get_last_error(ctx.ovnsb_idl);
            VLOG_ERR("%s: database connection failed (%s)",
                     ovnsb_remote, ovs_retval_to_string(retval));
            retval = EXIT_FAILURE;
            break;
        }

        if (!ovsdb_idl_is_alive(ctx.vtep_idl)) {
            int retval = ovsdb_idl_get_last_error(ctx.vtep_idl);
            VLOG_ERR("%s: database connection failed (%s)",
                     vtep_remote, ovs_retval_to_string(retval));
            retval = EXIT_FAILURE;
            break;
        }

        gateway_run(&ctx);

        /* TODO: call chassis_run(&ctx); to register/update chassis. */
        unixctl_server_run(unixctl);

        unixctl_server_wait(unixctl);
        if (exiting) {
            poll_immediate_wake();
        }

        ovsdb_idl_wait(ctx.vtep_idl);
        ovsdb_idl_wait(ctx.ovnsb_idl);
        poll_block();
    }

    unixctl_server_destroy(unixctl);
    /* TODO: call chassis_destroy(&ctx); to detroy chassis. */

    ovsdb_idl_destroy(ctx.vtep_idl);
    ovsdb_idl_destroy(ctx.ovnsb_idl);

    free(ovnsb_remote);
    free(vtep_remote);

    exit(retval);
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_PEER_CA_CERT = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS
    };

    static struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        DAEMON_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {"peer-ca-cert", required_argument, NULL, OPT_PEER_CA_CERT},
        {NULL, 0, NULL, 0}
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'V':
            ovs_print_version(OFP13_VERSION, OFP13_VERSION);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS
        STREAM_SSL_OPTION_HANDLERS

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    if (argc == 1) {
        vtep_remote = xasprintf("unix:%s/db.sock", ovs_rundir());
        ovnsb_remote = xstrdup(argv[0]);
    } else if (argc == 2) {
        vtep_remote = xstrdup(argv[0]);
        ovnsb_remote = xstrdup(argv[1]);
    } else {
        VLOG_FATAL("exactly one or two non-option argument required; "
                   "use --help for usage");
    }
}

static void
usage(void)
{
    printf("%s: OVN controller GW\n"
           "usage %s [OPTIONS] [VTEP-DATABASE] OVNSB-DATABASE\n"
           "where VTEP-DATABASE is a socket on which the VTEP OVSDB server is listening.\n",
               program_name, program_name);
    stream_usage("VTEP-DATABASE", true, false, false);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}


static void
ovn_controller_gw_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                       const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;

    unixctl_command_reply(conn, NULL);
}

/* TODO: Remove lswitch?  */
static void
ovn_controller_gw_add_lswitch(struct unixctl_conn *conn, int argc OVS_UNUSED,
                              const char *argv[], void *ctx_)
{
    const struct vteprec_logical_switch *ls_rec;
    struct controller_gw_ctx *ctx = ctx_;
    struct ovsdb_idl_txn *txn;
    const char *ls_name = argv[1];
    const int64_t key = strtoll(argv[2], NULL, 0);
    struct ds result;
    int retval = TXN_TRY_AGAIN;

    ds_init(&result);
    VTEPREC_LOGICAL_SWITCH_FOR_EACH(ls_rec, ctx->vtep_idl) {
        if (!strcmp(ls_name, ls_rec->name)) {
            ds_put_format(&result, "Logical Switch (%s) already exists",
                          ls_rec->name);
            goto ret;
        }
        if (ls_rec->tunnel_key[0] == key) {
            ds_put_format(&result, "key (%"PRId64") already used by Logical"
                          " Switch (%s)", ls_rec->tunnel_key[0], ls_rec->name);
            goto ret;
        }
    }
    txn = ovsdb_idl_txn_create(ctx->vtep_idl);
    ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller-gw: create logical switch '%s'",
                              ls_name);
    ls_rec = vteprec_logical_switch_insert(txn);
    vteprec_logical_switch_set_name(ls_rec, ls_name);
    vteprec_logical_switch_set_tunnel_key(ls_rec, &key, 1);

    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        VLOG_INFO("Problem registering chassis: %s",
                  ovsdb_idl_txn_status_to_string(retval));
        poll_immediate_wake();
    }
    ovsdb_idl_txn_destroy(txn);

ret:
    unixctl_command_reply(conn, ds_cstr(&result));
    ds_destroy(&result);
}

/* TODO: Remove lport?  */
static void
ovn_controller_gw_add_lport(struct unixctl_conn *conn, int argc OVS_UNUSED,
                            const char *argv[], void *ctx_)
{
    const struct vteprec_logical_switch *ls_rec;
    const struct vteprec_logical_switch *ls_target = NULL;
    const struct vteprec_physical_port *pp_rec;
    const struct vteprec_physical_port *pp_target = NULL;
    struct controller_gw_ctx *ctx = ctx_;
    struct ovsdb_idl_txn *txn;
    const char *ls_name = argv[1];
    const char *lp_name = argv[2];
    const char *pp_name = argv[3];
    const int64_t vlan = strtoull(argv[4], NULL, 0);
    struct ds result;
    int retval = TXN_TRY_AGAIN;
    int i;

    ds_init(&result);
    /* Checks the existence of lswitch. */
    VTEPREC_LOGICAL_SWITCH_FOR_EACH(ls_rec, ctx->vtep_idl) {
        if (!strcmp(ls_name, ls_rec->name)) {
            ls_target = ls_rec;
            break;
        }
    }
    if (!ls_target) {
        ds_put_format(&result, "could not find Logical Switch (%s)",
                      ls_name);
        goto ret;
    }

    /* TODO: Checks for duplication of lport. */

    /* Checks the existence of Physical Port. */
    VTEPREC_PHYSICAL_PORT_FOR_EACH(pp_rec, ctx->vtep_idl) {
        if (!strcmp(pp_name, pp_rec->name)) {
            pp_target = pp_rec;
            break;
        }
    }
    if (!pp_target) {
        ds_put_format(&result, "could not find Physical Port (%s)",
                      pp_name);
        goto ret;
    }

    /* Checks the duplication of vlan_binding. */
    for (i = 0; i < pp_target->n_vlan_bindings; i++) {
        const int64_t vlan_tmp = pp_target->key_vlan_bindings[i];
        const struct vteprec_logical_switch *ls_tmp = pp_target->value_vlan_bindings[i];

        if (vlan == vlan_tmp) {
            if (ls_tmp != ls_target) {
                ds_put_format(&result, "vlan (%"PRId64") has already been mapped to "
                              "Logical Switch (%s)", vlan, ls_target->name);
            }
            goto ret;
        }
    }

    txn = ovsdb_idl_txn_create(ctx->vtep_idl);
    ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller-gw: add vlan_binding: vlan (%"PRId64") "
                              "to Logical Switch (%s)", vlan, ls_target->name);

    int64_t *key_vlan_bindings;
    struct vteprec_logical_switch **value_vlan_bindings;

    key_vlan_bindings = xmalloc(sizeof *key_vlan_bindings * (pp_target->n_vlan_bindings + 1));
    value_vlan_bindings = xmalloc(sizeof *value_vlan_bindings * (pp_target->n_vlan_bindings + 1));

    for (i = 0; i < pp_target->n_vlan_bindings; i++) {
        key_vlan_bindings[i] = pp_target->key_vlan_bindings[i];
        value_vlan_bindings[i] = pp_target->value_vlan_bindings[i];
    }
    key_vlan_bindings[pp_target->n_vlan_bindings] = vlan;
    value_vlan_bindings[pp_target->n_vlan_bindings] = ls_target;

    vteprec_physical_port_set_vlan_bindings(pp_target, key_vlan_bindings,
                                            value_vlan_bindings,
                                            pp_target->n_vlan_bindings + 1);

    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        VLOG_INFO("Problem registering chassis: %s",
                  ovsdb_idl_txn_status_to_string(retval));
        poll_immediate_wake();
    }

    ovsdb_idl_txn_destroy(txn);
    free(key_vlan_bindings);
    free(value_vlan_bindings);

ret:
    unixctl_command_reply(conn, ds_cstr(&result));
    ds_destroy(&result);
}
