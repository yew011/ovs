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

#include "binding.h"
#include "gateway.h"
#include "pipeline.h"
#include "ovn-controller-vtep.h"

VLOG_DEFINE_THIS_MODULE(ovn_vtep);

static unixctl_cb_func ovn_controller_vtep_exit;

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

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    struct controller_vtep_ctx ctx;
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
    unixctl_command_register("exit", "", 0, 0, ovn_controller_vtep_exit,
                             &exiting);

    daemonize_complete();

    vteprec_init();
    sbrec_init();

    /* Connect to VTEP OVSDB instance.  We monitor all tables by
     * default */
    ctx.vtep_idl = ovsdb_idl_create(vtep_remote, &vteprec_idl_class, true, true);
    get_initial_snapshot(ctx.vtep_idl);
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
        binding_run(&ctx);
        pipeline_run(&ctx);
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
    gateway_destroy(&ctx);
    binding_destroy(&ctx);
    pipeline_destroy(&ctx);

    ovsdb_idl_destroy(ctx.vtep_idl);
    ovsdb_idl_destroy(ctx.ovnsb_idl);

    free(ovnsb_remote);
    free(vtep_remote);

    exit(retval);
}

static char *
default_db(void)
{
    static char *def;
    if (!def) {
        def = xasprintf("unix:%s/db.sock", ovs_rundir());
    }
    return def;
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
        {"ovnsb-db", required_argument, NULL, 'd'},
        {"vtep-db", required_argument, NULL, 'D'},
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
        case 'd':
            ovnsb_remote = optarg;
            break;

        case 'D':
            vtep_remote = optarg;
            break;

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

    if (!ovnsb_remote) {
        ovnsb_remote = default_db();
    }

    if (!vtep_remote) {
        vtep_remote = default_db();
    }
}

static void
usage(void)
{
    printf("\
%s: OVN controller VTEP\n\
usage %s [OPTIONS]\n\
\n\
Options:\n\
  --vtep-db=DATABASE        connect to vtep database at DATABASE\n\
                            (default: %s)\n\
  --ovnsb-db=DATABASE       connect to ovn-sb database at DATABASE\n\
                            (default: %s)\n\
  -h, --help                display this help message\n\
  -o, --options             list available options\n\
  -V, --version             display version information\n\
", program_name, program_name, default_db(), default_db());
    stream_usage("database", true, false, false);
    daemon_usage();
    vlog_usage();
    exit(EXIT_SUCCESS);
}


static void
ovn_controller_vtep_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                       const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;

    unixctl_command_reply(conn, NULL);
}
