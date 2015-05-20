/*
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

#include <getopt.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "command-line.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "poll-loop.h"
#include "process.h"
#include "stream.h"
#include "stream-ssl.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovn_sbctl);

struct sbctl_context {
    struct ovsdb_idl *idl;
    struct ovsdb_idl_txn *txn;
};

static const char *db;

static const char *default_db(void);

static void
usage(void)
{
    printf("\
%s: OVN northbound DB management utility\n\
usage: %s [OPTIONS] COMMAND [ARG...]\n\
\n\
General commands:\n\
  show                      print overview of database contents\n\
                            similar to `ovsdb-client dump unix:db.sock\n\
                            OVN_Southbound` output\n\
\n\
Chassis commands:\n\
  chassis-add name encap_type encap_ip\n\
                            create a logical switch named LSWITCH\n\
\n\
Binding commands:\n\
  binding-set lport_name chassis_name\n\
                            assign chassis to binding for lport\n\
\n\
Options:\n\
  --db=DATABASE             connect to DATABASE\n\
                            (default: %s)\n\
  -h, --help                display this help message\n\
  -o, --options             list available options\n\
  -V, --version             display version information\n\
", program_name, program_name, default_db());
    vlog_usage();
    stream_usage("database", true, true, false);
}

static void
do_show(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct ds cmd = DS_EMPTY_INITIALIZER;

    ds_put_format(&cmd, "ovsdb-client dump %s OVN_Southbound", db);
    execl("/bin/bash", "bash", "-c", ds_cstr(&cmd), (char *)0);
    ds_destroy(&cmd);
}

static void
do_chassis_add(struct ovs_cmdl_context *ctx)
{
    struct sbctl_context *sb_ctx = ctx->pvt;
    const struct sbrec_chassis *chassis_rec;
    struct sbrec_encap *encap_rec;
    char *chassis_name = ctx->argv[1];
    char *encap_type = ctx->argv[2];
    char *encap_ip = ctx->argv[3];

    SBREC_CHASSIS_FOR_EACH(chassis_rec, sb_ctx->idl) {
        if (!strcmp(chassis_rec->name, chassis_name)) {
            break;
        }
    }
    if (chassis_rec) {
        printf("Chassis (%s) already exists, no-op", chassis_rec->name);
        return;
    }
    chassis_rec = sbrec_chassis_insert(sb_ctx->txn);
    sbrec_chassis_set_name(chassis_rec, chassis_name);
    encap_rec = sbrec_encap_insert(sb_ctx->txn);
    sbrec_encap_set_type(encap_rec, encap_type);
    sbrec_encap_set_ip(encap_rec, encap_ip);
    sbrec_chassis_set_encaps(chassis_rec, &encap_rec, 1);
}

static void
do_binding_set(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct sbctl_context *sb_ctx = ctx->pvt;
    const struct sbrec_chassis *chassis_rec;
    const struct sbrec_binding *binding_rec;
    char *lport_name = ctx->argv[1];
    char *chassis_name = ctx->argv[2];

    SBREC_CHASSIS_FOR_EACH(chassis_rec, sb_ctx->idl) {
        if (!strcmp(chassis_rec->name, chassis_name)) {
            break;
        }
    }
    if (!chassis_rec) {
        printf("Chassis (%s) could not be found, no-op", chassis_name);
        return;
    }
    SBREC_BINDING_FOR_EACH(binding_rec, sb_ctx->idl) {
        if (!strcmp(binding_rec->logical_port, lport_name)) {
            break;
        }
    }
    if (!binding_rec) {
        printf("Binding for lport (%s) could not be found, no-op", lport_name);
        return;
    }

    sbrec_binding_set_chassis(binding_rec, chassis_rec);
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        VLOG_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"db", required_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {"options", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        VLOG_OPTION_HANDLERS;
        STREAM_SSL_OPTION_HANDLERS;

        case 'd':
            db = optarg;
            break;

        case 'h':
            usage();
            exit(EXIT_SUCCESS);

        case 'o':
            ovs_cmdl_print_options(long_options);
            exit(EXIT_SUCCESS);

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        default:
            break;
        }
    }

    if (!db) {
        db = default_db();
    }

    free(short_options);
}

static const struct ovs_cmdl_command all_commands[] = {
    {
        .name = "show",
        .usage = "",
        .min_args = 0,
        .max_args = 0,
        .handler = do_show,
    },
    {
        .name = "chassis-add",
        .usage = "name encap_type encap_ip",
        .min_args = 3,
        .max_args = 3,
        .handler = do_chassis_add,
    },
    {
        .name = "binding-set",
        .usage = "lport_name chassis_name",
        .min_args = 2,
        .max_args = 2,
        .handler = do_binding_set,
    },
    {
        /* sentinel */
        .name = NULL,
    },
};

static const struct ovs_cmdl_command *
get_all_commands(void)
{
    return all_commands;
}

static const char *
default_db(void)
{
    static char *def;
    if (!def) {
        def = xasprintf("unix:%s/db.sock", ovs_rundir());
    }
    return def;
}

int
main(int argc, char *argv[])
{
    extern struct vlog_module VLM_reconnect;
    struct ovs_cmdl_context ctx;
    struct sbctl_context sb_ctx = { .idl = NULL, };
    enum ovsdb_idl_txn_status txn_status;
    unsigned int seqno;
    int res = 0;
    char *args;

    fatal_ignore_sigpipe();
    set_program_name(argv[0]);
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels(&VLM_reconnect, VLF_ANY_DESTINATION, VLL_WARN);
    parse_options(argc, argv);
    sbrec_init();

    args = process_escape_args(argv);

    sb_ctx.idl = ovsdb_idl_create(db, &sbrec_idl_class, true, false);
    ctx.pvt = &sb_ctx;
    ctx.argc = argc - optind;
    ctx.argv = argv + optind;

    seqno = ovsdb_idl_get_seqno(sb_ctx.idl);
    for (;;) {
        ovsdb_idl_run(sb_ctx.idl);

        if (!ovsdb_idl_is_alive(sb_ctx.idl)) {
            int retval = ovsdb_idl_get_last_error(sb_ctx.idl);
            VLOG_ERR("%s: database connection failed (%s)",
                    db, ovs_retval_to_string(retval));
            res = 1;
            break;
        }

        if (seqno != ovsdb_idl_get_seqno(sb_ctx.idl)) {
            sb_ctx.txn = ovsdb_idl_txn_create(sb_ctx.idl);
            ovsdb_idl_txn_add_comment(sb_ctx.txn, "ovn-sbctl: %s", args);
            ovs_cmdl_run_command(&ctx, get_all_commands());
            txn_status = ovsdb_idl_txn_commit_block(sb_ctx.txn);
            if (txn_status == TXN_TRY_AGAIN) {
                ovsdb_idl_txn_destroy(sb_ctx.txn);
                sb_ctx.txn = NULL;
                continue;
            } else {
                break;
            }
        }

        if (seqno == ovsdb_idl_get_seqno(sb_ctx.idl)) {
            ovsdb_idl_wait(sb_ctx.idl);
            poll_block();
        }
    }

    if (sb_ctx.txn) {
        ovsdb_idl_txn_destroy(sb_ctx.txn);
    }
    ovsdb_idl_destroy(sb_ctx.idl);
    free(args);

    exit(res);
}
