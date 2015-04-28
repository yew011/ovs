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
