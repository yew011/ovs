/*
 * Copyright (c) 2015 Nicira, Inc.
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

#ifndef DB_CTL_BASE_H
#define DB_CTL_BASE_H 1

#include "dynamic-string.h"
#include "shash.h"

/* ctl_fatal() also logs the error, so it is preferred in this file. */
#define ovs_fatal please_use_ctl_fatal_instead_of_ovs_fatal

struct ctl_context;
struct ovsdb_idl;
struct ovsdb_idl_txn;
struct ovsdb_symbol_table;
struct table;

extern struct ovsdb_idl *the_idl;
extern struct ovsdb_idl_txn *the_idl_txn;

void ctl_init(void);
void ctl_exit(int status);
void ctl_fatal(const char *, ...) OVS_PRINTF_FORMAT(1, 2);
char *ctl_default_db(void);

struct ctl_command_syntax {
    const char *name;           /* e.g. "add-br" */
    int min_args;               /* Min number of arguments following name. */
    int max_args;               /* Max number of arguments following name. */

    /* Names that roughly describe the arguments that the command
     * uses.  These should be similar to the names displayed in the
     * man page or in the help output. */
    const char *arguments;

    /* If nonnull, calls ovsdb_idl_add_column() or ovsdb_idl_add_table() for
     * each column or table in ctx->idl that it uses. */
    void (*prerequisites)(struct ctl_context *ctx);

    /* Does the actual work of the command and puts the command's output, if
     * any, in ctx->output or ctx->table.
     *
     * Alternatively, if some prerequisite of the command is not met and the
     * caller should wait for something to change and then retry, it may set
     * ctx->try_again to true.  (Only the "wait-until" command currently does
     * this.) */
    void (*run)(struct ctl_context *ctx);

    /* If nonnull, called after the transaction has been successfully
     * committed.  ctx->output is the output from the "run" function, which
     * this function may modify and otherwise postprocess as needed.  (Only the
     * "create" command currently does any postprocessing.) */
    void (*postprocess)(struct ctl_context *ctx);

    /* A comma-separated list of supported options, e.g. "--a,--b", or the
     * empty string if the command does not support any options. */
    const char *options;

    enum { RO, RW } mode;       /* Does this command modify the database? */
};

struct ctl_command {
    /* Data that remains constant after initialization. */
    const struct ctl_command_syntax *syntax;
    int argc;
    char **argv;
    struct shash options;

    /* Data modified by commands. */
    struct ds output;
    struct table *table;
};

const char *ctl_get_db_cmd_usage(void);
void ctl_print_commands(void);
void ctl_print_options(const struct option *);
struct option *ctl_add_cmd_options(struct option **, size_t *n_options_p,
                                   size_t *allocated_options_p);
void ctl_register_commands(const struct ctl_command_syntax *);
const struct shash *ctl_get_all_commands(void);
struct ctl_command *ctl_parse_commands(int argc, char *argv[],
                                       struct shash *local_options,
                                       size_t *n_commandsp);

struct ctl_context {
    /* Read-only. */
    int argc;
    char **argv;
    struct shash options;

    /* Modifiable state. */
    struct ds output;
    struct table *table;
    struct ovsdb_idl *idl;
    struct ovsdb_idl_txn *txn;
    struct ovsdb_symbol_table *symtab;

    /* A command may set this member to true if some prerequisite is not met
     * and the caller should wait for something to change and then retry. */
    bool try_again;

    void (*invalidate_cache)(struct ctl_context *);
    void (*populate_cache)(struct ctl_context *);
};

struct ctl_row_id {
    const struct ovsdb_idl_table_class *table;
    const struct ovsdb_idl_column *name_column;
    const struct ovsdb_idl_column *uuid_column;
};

struct ctl_table_class {
    struct ovsdb_idl_table_class *class;
    struct ctl_row_id row_ids[2];
};

/* User must define the all tables in the schema. */
extern const struct ctl_table_class *tables;

#endif /* db-ctl-base.h */
