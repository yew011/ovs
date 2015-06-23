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

#include <config.h>

#include "ofproto/ofproto-dpif-hsa.h"
#include "ofproto/ofproto-provider.h"

#include "dynamic-string.h"
#include "flow.h"
#include "hash.h"
#include "hmap.h"
#include "hsa-match.h"
#include "list.h"
#include "match.h"
#include "meta-flow.h"
#include "nx-match.h"
#include "ofproto.h"
#include "ofp-actions.h"
#include "sort.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(hsa);

/* Supported operations. */
enum operation_types {
    HSA_LOOP_DETECT,
    HSA_UNUSED_DETECT
};

/* Internal table id, do not subject to unused check. */
#define INTERNAL_TABLE_ID 254
/* Always starts the analysis from OpenFlow table 0. */
#define TABLE_DEFAULT 0
/* Default indent level for output. */
#define INDENT_DEFAULT 0
/* Indicates no in_port given from cmdline. */
#define OFP_PORT_NULL 0

/* A stack entry for the HSA analysis. */
struct hsa_stack_entry {
    struct ovs_list list_node;      /* In owning header_space's 'stack'. */
    union mf_subvalue value;
    union mf_subvalue mask;
};

/* Rule used for head space analysis. */
struct hsa_rule {
    struct ovs_list node;           /* In owning table's 'rules'. */

    bool matched;                   /* Rule has been matched. */
    uint8_t table_id;               /* OpenFlow table id. */
    int prio;                       /* Priority. */
    struct match match;             /* Flow and wildcards. */
    const struct rule_actions *actions;/* Actions. */
    struct hsbm hsbm;               /* Compressed bit map representation of */
                                    /* match. */
};

/* Rule table for header space analysis. */
struct hsa_table {
    struct ovs_list rules;          /* Contains 'struct hsa_rule's. */
    size_t n_rules;                 /* Number of rules in the table. */
};

/* Representation of Header Space. */
struct header_space {
    struct ovs_list list_node;
    /*
     * match_hs represents the input header space as it is transformed by
     * matched rules and rule actions.
     */
    struct match match_hs;          /* Current header space. */

    struct ovs_list stack;          /* Contains 'hsa_stack_entry's. */

    /* For HSA_LOOP_DETECT operation, indexed using previously matched
     * 'struct hsa_rule' pointers.  If a particular rule is matched more
     * than once, there is a loop.  If the matched time reaches
     * MATCHED_COUNT_INFINITE, we find an infinite loop. */
    struct hmap matched_map;        /* Stores 'struct matched_count's. */
    struct hsa_rule **matched_rules;/* Stores all previous matched rules. */
    size_t n_rules;
    bool in_loop;
};

#define MATCHED_COUNT_INFINITE 16

/* Matched counter. */
struct matched_entry {
    struct hmap_node hmap_node;
    struct hsa_rule *r;
    size_t count;                   /* Count the time of matched. */
};

/* Contains list of 'struct header_space's. */
struct hs_list {
    struct ovs_list list;
};

/* Global control of debugging and the hsa thread id. */
static bool debug_enabled;
static pthread_t hsa_tid;

/* Global 'struct hsa_table's, one for each OpenFlow table. */
static struct hsa_table *hsa_tables;
static int n_hsa_tables;

/* Operation type. */
static int op_type;
/* Execution error? */
bool run_error;

/* HSA operations. */
static struct header_space *hs_create(void);
static struct header_space *hs_clone(const struct header_space *);
static void hs_destroy(struct header_space *);
static struct hs_list *hs_list_create(void);
static void hs_list_destroy(struct hs_list *);
static void hsa_rule_swap(size_t a, size_t b, void *aux);
static int  hsa_rule_compare(size_t a, size_t b, void *aux);
static bool hsa_rule_check_match(struct header_space *, struct hsa_rule *,
                                 ofp_port_t in_port);
static void hsa_match_print(struct ds *, struct match *, bool new_line);
static void hsa_rule_print(struct ds *, struct hsa_rule *, bool new_line);
static void hsa_log_invalid_rule(struct hsa_rule *);

static void hsa_rule_apply_match(struct header_space *, struct hsa_rule *);

static void hsa_init(struct ofproto *, struct ds *, ofp_port_t in_port,
                     struct header_space *);
static void hsa_finish(void);
static void hsa_debug_dump_flows(struct ds *, const char *);
static struct hs_list *hsa_rule_apply_actions(struct header_space *,
                                              struct hsa_rule *,
                                              uint8_t cur_table_id,
                                              struct hs_list *, int indent,
                                              struct ds *);
static void hsa_record_matched_rule(struct header_space *, struct hsa_rule *);
static size_t hsa_matched_rule_count(struct header_space *, struct hsa_rule *);
static bool hsa_try_detect_loop(struct header_space *, struct hsa_rule *,
                                struct hs_list *);
static struct hs_list *hsa_calculate(struct header_space *, uint8_t table_id,
                                     ofp_port_t in_port, bool nested,
                                     struct hs_list *, int indent, struct ds *);
static void hsa_mf_set_flow_value_masked(const struct mf_field *,
                                         const union mf_value *,
                                         const union mf_value *,
                                         const union mf_value *,
                                         struct match *);


/* Creates and returns a newly zalloc'ed 'hs'. */
static struct header_space *
hs_create(void)
{
    struct header_space *hs = xzalloc(sizeof *hs);

    list_init(&hs->stack);
    hmap_init(&hs->matched_map);

    return hs;
}

/* Clones the header space 'hs' and returns the copy. */
static struct header_space *
hs_clone(const struct header_space *hs)
{
    struct header_space *clone = xmalloc(sizeof *hs);

    clone->match_hs = hs->match_hs;

    /* Copies the stack. */
    list_init(&clone->stack);
    if (!list_is_empty(&hs->stack)) {
        struct hsa_stack_entry *iter;

        LIST_FOR_EACH (iter, list_node, &hs->stack) {
            struct hsa_stack_entry *copy = xmalloc(sizeof *copy);

            copy->value = iter->value;
            copy->mask = iter->mask;
            list_push_back(&clone->stack, &copy->list_node);
        }
    }

    hmap_init(&clone->matched_map);
    /* Copies the previous matched rules. */
    if (!hmap_is_empty(&hs->matched_map)) {
        struct matched_entry *entry;

        HMAP_FOR_EACH (entry, hmap_node, &hs->matched_map) {
            struct matched_entry *copy = xmalloc(sizeof *copy);

            copy->r = entry->r;
            copy->count = entry->count;
            hmap_insert(&clone->matched_map, &copy->hmap_node,
                        hash_pointer(copy->r, 0));
        }
        clone->matched_rules = xmalloc(hs->n_rules
                                       * sizeof *clone->matched_rules);
        memcpy(clone->matched_rules, hs->matched_rules,
               hs->n_rules * sizeof *clone->matched_rules);
        clone->n_rules = hs->n_rules;
        clone->in_loop = hs->in_loop;
    } else {
        clone->matched_rules = NULL;
        clone->n_rules = 0;
        clone->in_loop = false;
    }

    return clone;
}

/* Destroys a header space.  */
static void
hs_destroy(struct header_space *hs)
{
    struct matched_entry *m_iter, *m_next;
    struct hsa_stack_entry *s_iter, *s_next;

    /* Destorys the stack. */
    LIST_FOR_EACH_SAFE (s_iter, s_next, list_node, &hs->stack) {
        list_remove(&s_iter->list_node);
        free(s_iter);
    }

    /* Destroys the matched_map. */
    HMAP_FOR_EACH_SAFE (m_iter, m_next, hmap_node, &hs->matched_map) {
        hmap_remove(&hs->matched_map, &m_iter->hmap_node);
        free(m_iter);
    }
    free(hs->matched_rules);
    free(hs);
}

/* Creates and returns a 'hs_list'.  */
static struct hs_list *
hs_list_create(void)
{
    struct hs_list *hs_list = xmalloc(sizeof *hs_list);

    list_init(&hs_list->list);

    return hs_list;
}

/* Destroys 'hs_list'. */
static void
hs_list_destroy(struct hs_list *hs_list)
{
    struct header_space *iter, *next;

    LIST_FOR_EACH_SAFE (iter, next, list_node, &hs_list->list) {
        list_remove(&iter->list_node);
        hs_destroy(iter);
    }
    free(hs_list);
}

/* Swaps the two elements at position 'a' and 'b'. */
static void
hsa_rule_swap(size_t a, size_t b, void *aux)
{
    struct ovs_list *rules = aux;

    list_swap(list_at_position(rules, a), list_at_position(rules, b));
}

/* This comparison is implemented for sorting in descending order. */
static int
hsa_rule_compare(size_t a, size_t b, void *aux)
{
    struct ovs_list *rules = aux;
    struct hsa_rule *r1, *r2;

    r1 = CONTAINER_OF(list_at_position(rules, a), struct hsa_rule, node);
    r2 = CONTAINER_OF(list_at_position(rules, b), struct hsa_rule, node);

    return r2->prio < r1->prio ? -1 : r2->prio > r1->prio;
}

/* Returns true if the 'hs->match_hs' applied with 'rule' wildcards can match
 * the flow in 'rule'.  Use 'in_port' as input port if its value is not
 * OFPP_IN_PORT.  This is to workaround the resubmit action. */
static bool
hsa_rule_check_match(struct header_space *hs, struct hsa_rule *rule,
                     ofp_port_t in_port)
{
    struct flow_wildcards wc;
    ofp_port_t orig_in_port = hs->match_hs.flow.in_port.ofp_port;
    bool ret;

    if (in_port != OFPP_IN_PORT) {
        hs->match_hs.flow.in_port.ofp_port = in_port;
    }

    flow_wildcards_and(&wc, &hs->match_hs.wc, &rule->match.wc);
    ret = flow_equal_except(&hs->match_hs.flow, &rule->match.flow, &wc);
    if (in_port != OFPP_IN_PORT) {
        hs->match_hs.flow.in_port.ofp_port = orig_in_port;
    }

    return ret;
}

/* Prints the match in 'out'. */
static void
hsa_match_print(struct ds *out, struct match *match, bool new_line)
{
    match_format(match, out, OFP_DEFAULT_PRIORITY);
    if (new_line) {
        ds_put_cstr(out, "\n");
    }
}

/* Prints the OpenFlow rule in 'out'. */
static void
hsa_rule_print(struct ds *out, struct hsa_rule *rule, bool new_line)
{
    ds_put_format(out, "table_id=%"PRIu8", ", rule->table_id);
    match_format(&rule->match, out, rule->prio);
    ds_put_cstr(out, ",actions=");
    ofpacts_format(rule->actions->ofpacts, rule->actions->ofpacts_len, out);
    if (new_line) {
        ds_put_cstr(out, "\n");
    }
}

static void
hsa_log_invalid_rule(struct hsa_rule *rule)
{
    struct ds tmp = DS_EMPTY_INITIALIZER;

    run_error = true;
    hsa_rule_print(&tmp, rule, false);
    VLOG_WARN("Rule (%s) move/load action that does not satisfy "
              "prerequisite", ds_cstr(&tmp));
    ds_destroy(&tmp);
}


#define FLOW_ATTRS                               \
    /* tunnel. */                                \
    FLOW_ATTR(tunnel.tun_id)                     \
    FLOW_ATTR(tunnel.ip_src)                     \
    FLOW_ATTR(tunnel.ip_dst)                     \
    FLOW_ATTR(tunnel.flags)                      \
    FLOW_ATTR(tunnel.ip_tos)                     \
    FLOW_ATTR(tunnel.ip_ttl)                     \
    FLOW_ATTR(tunnel.tp_src)                     \
    FLOW_ATTR(tunnel.tp_dst)                     \
    /* metadata and regs. */                     \
    FLOW_ATTR(metadata)                          \
    FLOW_ATTR(regs[0])                           \
    FLOW_ATTR(regs[1])                           \
    FLOW_ATTR(regs[2])                           \
    FLOW_ATTR(regs[3])                           \
    FLOW_ATTR(regs[4])                           \
    FLOW_ATTR(regs[5])                           \
    FLOW_ATTR(regs[6])                           \
    FLOW_ATTR(regs[7])                           \
    FLOW_ATTR(skb_priority)                      \
    FLOW_ATTR(pkt_mark)                          \
    FLOW_ATTR(dp_hash)                           \
    FLOW_ATTR(in_port.ofp_port)                  \
    FLOW_ATTR(recirc_id)                         \
    FLOW_ATTR(conj_id)                           \
    FLOW_ATTR(actset_output)                     \
    /* L2. */                                    \
    FLOW_ATTR(dl_dst)                            \
    FLOW_ATTR(dl_src)                            \
    FLOW_ATTR(dl_type)                           \
    FLOW_ATTR(vlan_tci)                          \
    FLOW_ATTR(mpls_lse)                          \
    /* L3. */                                    \
    FLOW_ATTR(nw_src)                            \
    FLOW_ATTR(nw_dst)                            \
    FLOW_ATTR(ipv6_src)                          \
    FLOW_ATTR(ipv6_dst)                          \
    FLOW_ATTR(ipv6_label)                        \
    FLOW_ATTR(nw_frag)                           \
    FLOW_ATTR(nw_tos)                            \
    FLOW_ATTR(nw_ttl)                            \
    FLOW_ATTR(nw_proto)                          \
    FLOW_ATTR(nd_target)                         \
    FLOW_ATTR(arp_sha)                           \
    FLOW_ATTR(arp_tha)                           \
    FLOW_ATTR(tcp_flags)                         \
    /* L4. */                                    \
    FLOW_ATTR(tp_src)                            \
    FLOW_ATTR(tp_dst)                            \
    FLOW_ATTR(igmp_group_ip4)


/* Applies the 'rule's flow format and wildcards to header
 * space 'hs'. */
static void
hsa_rule_apply_match(struct header_space *hs, struct hsa_rule *rule)
{
    struct flow *masks = &rule->match.wc.masks;
    struct flow *flow = &rule->match.flow;

    /* If the field in rule is masked, applies 'field & field mask'
     * to header space. */
#define FLOW_ATTR(ATTR)                                                 \
    if (!flow_wildcard_is_fully_unmasked(&masks->ATTR,                  \
                                         sizeof masks->ATTR)) {         \
        flow_apply_field(&hs->match_hs.flow.ATTR,                       \
                         &hs->match_hs.wc.masks.ATTR,                   \
                         &flow->ATTR, &masks->ATTR, sizeof flow->ATTR); \
    }
    FLOW_ATTRS
#undef FLOW_ATTR
}


/* Masks metadata, regs and ipv6. */
static void
hs_init__(struct header_space *hs, ofp_port_t in_port)
{
    if (in_port != OFP_PORT_NULL) {
        hs->match_hs.flow.in_port.ofp_port = in_port;
        WC_MASK_FIELD(&hs->match_hs.wc, in_port);
    }
    WC_MASK_FIELD(&hs->match_hs.wc, regs);
    WC_MASK_FIELD(&hs->match_hs.wc, metadata);
    WC_MASK_FIELD(&hs->match_hs.wc, ipv6_src);
    WC_MASK_FIELD(&hs->match_hs.wc, ipv6_dst);
}

/* Given the 'ofproto' of a bridge, copies all rules from each oftable
 * into a sorted list with descending priority.  Also, initilizes 'hs_start'. */
static void
hsa_init(struct ofproto *ofproto, struct ds *out, ofp_port_t in_port,
         struct header_space *hs_start)
{
    struct oftable *oftable;
    uint8_t table_id = 0;
    size_t i;

    n_hsa_tables = ofproto->n_tables;
    hsa_tables = xmalloc(n_hsa_tables * sizeof *hsa_tables);
    for (i = 0; i < n_hsa_tables; i++) {
        list_init(&hsa_tables[i].rules);
    }

    OFPROTO_FOR_EACH_TABLE (oftable, ofproto) {
        struct hsa_table *tbl = &hsa_tables[table_id];
        struct ovs_list *rules = &tbl->rules;
        struct rule *rule;

        tbl->n_rules = oftable->cls.n_rules;
        CLS_FOR_EACH (rule, cr, &oftable->cls) {
            struct hsa_rule *hsa_rule = xmalloc(sizeof *hsa_rule);

            hsa_rule->matched = false;
            hsa_rule->table_id = table_id;
            hsa_rule->prio = rule->cr.priority;
            minimatch_expand(&rule->cr.match, &hsa_rule->match);
            /* Since actions are rcu-protected, do not need to worry
             * about race. */
            hsa_rule->actions = rule_get_actions(rule);
            hsbm_init(&hsa_rule->hsbm, &hsa_rule->match);
            list_insert(rules, &hsa_rule->node);
        }
        sort(tbl->n_rules, hsa_rule_compare, hsa_rule_swap, rules);
        table_id++;
    }

    /* Initializes the 'hs_start', sets and masks the 'metadata' and 'regs'. */
    hs_init__(hs_start, in_port);

    if (debug_enabled) {
        ds_put_char_multiple(out, '\t', INDENT_DEFAULT);
        ds_put_cstr(out, "Header-Space init done:\n");
        hsa_match_print(out, &hs_start->match_hs, true);
        ds_put_cstr(out, "\n");
    }
}

/* Destroys all created 'hsa_rule's and 'hsa_table's. */
static void
hsa_finish(void)
{
    size_t i;

    for (i = 0; i < n_hsa_tables; i++) {
        struct ovs_list *rules = &hsa_tables[i].rules;
        struct hsa_rule *rule, *next;

        if (list_is_empty(rules)) {
            continue;
        }
        LIST_FOR_EACH_SAFE (rule, next, node, rules) {
            list_remove(&rule->node);
            hsbm_uninit(&rule->hsbm);
            free(rule);
        }
    }
    free(hsa_tables);
}

static void
hsa_debug_dump_flows(struct ds *out, const char *ofproto_name)
{
    if (debug_enabled) {
        size_t i;

        ds_put_char_multiple(out, '\t', INDENT_DEFAULT);
        ds_put_format(out, "Flows dump from bridge (%s):\n", ofproto_name);
        for (i = 0; i < n_hsa_tables; i++) {
            struct ovs_list *rules = &hsa_tables[i].rules;
            struct hsa_rule *rule;

            if (list_is_empty(rules)) {
                continue;
            }
            LIST_FOR_EACH(rule, node, rules) {
                hsa_rule_print(out, rule, true);
            }
        }
        ds_put_cstr(out, "\n");
    }
}

/* Applies various output actions. */
static void
hsa_rule_apply_output_action__(struct header_space *hs OVS_UNUSED,
                               ofp_port_t port OVS_UNUSED,
                               struct hs_list *result OVS_UNUSED)
{
    return;
}

/* Applies the 'rule's actions to header space 'input_hs'.  This may generate
 * more header spaces (i.e. via the resubmit action).  When the expected action
 * (e.g. output to port or loop found in resubmit) is met, attaches the
 * resulting 'hs' to 'result'.  Returns the 'hs_list' of header spaces after
 * action application.
 *
 * This function takes ownership of 'input_hs'. */
static struct hs_list *
hsa_rule_apply_actions(struct header_space *input_hs, struct hsa_rule *rule,
                       uint8_t cur_table_id, struct hs_list *result,
                       int indent, struct ds *out)
{
    const struct ofpact *ofpacts = rule->actions->ofpacts;
    size_t ofpacts_len = rule->actions->ofpacts_len;
    struct hs_list *ret = hs_list_create();
    const struct ofpact *a;

    /* 'ret' could be changed during processing of multiple 'resubmit'
     * actions. */
    list_insert(&ret->list, &input_hs->list_node);

    /* TODO: actions other than 'load' and 'move' are not changing
     *       the 'hs->move_map'.  should make them do it. */
    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        struct header_space *hs, *next;
        struct hs_list *new_ret = hs_list_create();

        /* Executes action for each 'hs'. */
        LIST_FOR_EACH_SAFE (hs, next, list_node, &ret->list) {
            struct flow *hs_flow = &hs->match_hs.flow;
            struct flow_wildcards *hs_wc = &hs->match_hs.wc;
            const struct ofpact_set_field *set_field;
            const struct mf_field *mf;

            switch (a->type) {
            /* Output. */
            case OFPACT_OUTPUT:
                hsa_rule_apply_output_action__(hs, ofpact_get_OUTPUT(a)->port,
                                               result);
                break;

            case OFPACT_OUTPUT_REG: {
                const struct ofpact_output_reg *or = ofpact_get_OUTPUT_REG(a);
                uint64_t port = mf_get_subfield(&or->src, &hs->match_hs.flow);

                if (port <= UINT16_MAX) {
                    union mf_subvalue value;

                    memset(&value, 0xFF, sizeof value);
                    mf_write_subfield_flow(&or->src, &value,
                                           &hs->match_hs.wc.masks);
                    hsa_rule_apply_output_action__(hs, u16_to_ofp(port),
                                                   result);
                }
                break;
            }

            case OFPACT_BUNDLE: {
                const struct ofpact_bundle *bundle = ofpact_get_BUNDLE(a);
                int i;

                /* Assumes all slaves are enabled and subject to selection.
                 * So, sets the 'bundle->dst' for each slave. */
                for (i = 0; i < bundle->n_slaves; i++) {
                    struct header_space *clone = hs_clone(hs);
                    ofp_port_t port = bundle->slaves[i];

                    if (bundle->dst.field) {
                        /* bundle_load. */
                        nxm_reg_load(&bundle->dst, ofp_to_u16(port),
                                     &clone->match_hs.flow,
                                     &clone->match_hs.wc);
                        list_insert(&new_ret->list, &clone->list_node);
                    } else {
                        /* Does not support bundle action. */
                        VLOG_INFO("bundle action not supported");
                    }
                }
                break;
            }

            /* Resubmit. */
            case OFPACT_RESUBMIT: {
                const struct ofpact_resubmit *resubmit = ofpact_get_RESUBMIT(a);
                struct hs_list *list;
                uint8_t table_id;

                table_id = resubmit->table_id;
                if (table_id == 255) {
                    table_id = cur_table_id;
                }

                list = hsa_calculate(hs, table_id, resubmit->in_port, true,
                                     result, indent + 1, out);
                if(!list_is_empty(&list->list)) {
                    list_splice(&new_ret->list, list_front(&list->list),
                                &list->list);
                    hs_list_destroy(list);
                }

                break;
            }

            /* Move and Load. */
            case OFPACT_REG_MOVE: {
                const struct ofpact_reg_move *move = ofpact_get_REG_MOVE(a);

                if (mf_are_prereqs_ok(move->dst.field, &rule->match.flow)) {
                    union mf_value src_value;
                    union mf_value dst_value;
                    union mf_value src_mask;
                    union mf_value dst_mask;

                    /* Saves the src/dst values/masks. */
                    mf_get_value(move->dst.field, hs_flow, &dst_value);
                    mf_get_value(move->src.field, hs_flow, &src_value);
                    mf_get_value(move->dst.field, &hs_wc->masks, &dst_mask);
                    mf_get_value(move->src.field, &hs_wc->masks, &src_mask);

                    /* Sets the dst field. */
                    bitwise_copy(&src_value, move->src.field->n_bytes,
                                 move->src.ofs, &dst_value,
                                 move->dst.field->n_bytes, move->dst.ofs,
                                 move->src.n_bits);
                    bitwise_copy(&src_mask, move->src.field->n_bytes,
                                 move->src.ofs, &dst_mask,
                                 move->dst.field->n_bytes, move->dst.ofs,
                                 move->src.n_bits);
                    mf_set_flow_value(move->dst.field, &dst_value, hs_flow);
                    mf_set_flow_value(move->dst.field, &dst_mask,
                                      &hs_wc->masks);
                } else {
                    hsa_log_invalid_rule(rule);
                }
                break;
            }

            case OFPACT_SET_FIELD:
                /* Load action, only support load of exact-match value. */
                set_field = ofpact_get_SET_FIELD(a);
                mf = set_field->field;

                if (mf_are_prereqs_ok(mf, &rule->match.flow)) {
                    hsa_mf_set_flow_value_masked(mf, &set_field->value,
                                                 &set_field->mask,
                                                 &set_field->mask,
                                                 &hs->match_hs);
                } else {
                    hsa_log_invalid_rule(rule);
                }
                break;

            /* Set fields. */
            case OFPACT_SET_VLAN_VID:
                hs_wc->masks.vlan_tci |= htons(VLAN_VID_MASK | VLAN_CFI);
                if (hs_flow->vlan_tci & htons(VLAN_CFI) ||
                    ofpact_get_SET_VLAN_VID(a)->push_vlan_if_needed) {
                    hs_flow->vlan_tci &= ~htons(VLAN_VID_MASK);
                    hs_flow->vlan_tci |=
                        (htons(ofpact_get_SET_VLAN_VID(a)->vlan_vid)
                         | htons(VLAN_CFI));
                }
                break;

            case OFPACT_SET_ETH_SRC:
                memset(&hs_wc->masks.dl_src, 0xff, sizeof hs_wc->masks.dl_src);
                memcpy(&hs_flow->dl_src, ofpact_get_SET_ETH_SRC(a)->mac,
                       ETH_ADDR_LEN);
                break;

            case OFPACT_SET_ETH_DST:
                memset(&hs_wc->masks.dl_dst, 0xff, sizeof hs_wc->masks.dl_dst);
                memcpy(&hs_flow->dl_dst, ofpact_get_SET_ETH_DST(a)->mac,
                       ETH_ADDR_LEN);
                break;

            case OFPACT_DEC_TTL:
                /* Decrements only when TTL is exact-matched. */
                if (hs_wc->masks.nw_ttl == 0xff && hs_flow->nw_ttl) {
                    hs_flow->nw_ttl--;
                }
                break;

            case OFPACT_STACK_PUSH: {
                struct hsa_stack_entry *entry = xmalloc(sizeof *entry);

                mf_read_subfield(&ofpact_get_STACK_PUSH(a)->subfield,
                                 hs_flow, &entry->value);
                mf_read_subfield(&ofpact_get_STACK_PUSH(a)->subfield,
                                 &hs_wc->masks, &entry->mask);
                list_push_back(&hs->stack, &entry->list_node);
                break;
            }

            case OFPACT_STACK_POP:
                if (!list_is_empty(&hs->stack)) {
                    struct hsa_stack_entry *entry;

                    entry = CONTAINER_OF(list_pop_front(&hs->stack),
                                         struct hsa_stack_entry, list_node);
                    mf_write_subfield_flow(&ofpact_get_STACK_POP(a)->subfield,
                                           &entry->value, hs_flow);
                    mf_write_subfield_flow(&ofpact_get_STACK_POP(a)->subfield,
                                           &entry->mask, &hs_wc->masks);
                    free(entry);
                } else {
                    VLOG_WARN("Failed to pop from an empty stack");
                }
                break;

            case OFPACT_NOTE:
            case OFPACT_CONTROLLER:
                /* noop. */
                break;

            /* DO NOT SUPPORT. */
            case OFPACT_SET_VLAN_PCP:
                VLOG_INFO("OFPACT_SET_VLAN_PCP not supported");
                break;
            case OFPACT_STRIP_VLAN:
                VLOG_INFO("OFPACT_STRIP_VLAN not supported");
                break;
            case OFPACT_PUSH_VLAN:
                VLOG_INFO("OFPACT_PUSH_VLANP not supported");
                break;
            case OFPACT_SET_IPV4_SRC:
                VLOG_INFO("OFPACT_SET_IPV4_SRC not supported");
                break;
            case OFPACT_SET_IPV4_DST:
                VLOG_INFO("OFPACT_SET_IPV4_DST not supported");
                break;
            case OFPACT_SET_IP_DSCP:
                VLOG_INFO("OFPACT_SET_IP_DSCP not supported");
                break;
            case OFPACT_SET_IP_ECN:
                VLOG_INFO("OFPACT_SET_IP_ECN not supported");
                break;
            case OFPACT_SET_IP_TTL:
                VLOG_INFO("OFPACT_SET_IP_TTL not supported");
                break;
            case OFPACT_SET_L4_SRC_PORT:
                VLOG_INFO("OFPACT_SET_L4_SRC_PORT not supported");
                break;
            case OFPACT_SET_L4_DST_PORT:
                VLOG_INFO("OFPACT_SET_L4_DST_PORT not supported");
                break;
            case OFPACT_SET_TUNNEL:
                VLOG_INFO("OFPACT_SET_TUNNEL not supported");
                break;
            case OFPACT_GROUP:
                VLOG_INFO("OFPACT_GROUP not supported");
                break;
            case OFPACT_PUSH_MPLS:
                VLOG_INFO("OFPACT_PUSH_MPLS not supported");
                break;
            case OFPACT_POP_MPLS:
                VLOG_INFO("OFPACT_POP_MPLS not supported");
                break;
            case OFPACT_SET_MPLS_LABEL:
                VLOG_INFO("OFPACT_SET_MPLS_LABEL not supported");
                break;
            case OFPACT_SET_MPLS_TC:
                VLOG_INFO("OFPACT_SET_MPLS_TC not supported");
                break;
            case OFPACT_SET_MPLS_TTL:
                VLOG_INFO("OFPACT_SET_MPLS_TTL not supported");
                break;
            case OFPACT_DEC_MPLS_TTL:
                VLOG_INFO("OFPACT_DEC_MPLS_TTL not supported");
                break;
            case OFPACT_MULTIPATH:
                VLOG_INFO("OFPACT_MULTIPATH not supported");
                break;
            case OFPACT_LEARN:
                VLOG_INFO("OFPACT_LEARN not supported");
                break;
            case OFPACT_CLEAR_ACTIONS:
                VLOG_INFO("OFPACT_CLEAR_ACTIONS not supported");
                break;
            case OFPACT_EXIT:
                VLOG_INFO("OFPACT_EXIT not supported");
                break;
            case OFPACT_WRITE_ACTIONS:
                VLOG_INFO("OFPACT_WRITE_ACTIONS not supported");
                break;
            case OFPACT_METER:
                VLOG_INFO("OFPACT_METER not supported");
                break;
            case OFPACT_SAMPLE:
                VLOG_INFO("OFPACT_SAMPLE not supported");
                break;
            case OFPACT_SET_QUEUE:
                VLOG_INFO("OFPACT_SET_QUEUE not supported");
                break;
            case OFPACT_ENQUEUE:
                VLOG_INFO("OFPACT_SET_ENQUEUE not supported");
                break;
            case OFPACT_POP_QUEUE:
                VLOG_INFO("OFPACT_POP_QUEUE not supported");
                break;
            case OFPACT_WRITE_METADATA:
                VLOG_INFO("OFPACT_WRITE_METEDATA not supported");
                break;
            case OFPACT_GOTO_TABLE:
                VLOG_INFO("OFPACT_GOTO_TABLE not supported");
                break;
            case OFPACT_FIN_TIMEOUT:
                VLOG_INFO("OFPACT_FIN_TIMEOUT not supported");
                break;
            case OFPACT_CONJUNCTION:
                VLOG_INFO("OFPACT_CONJUNCTION not supported");
                break;
            case OFPACT_UNROLL_XLATE:
                VLOG_INFO("OFPACT_UNROLL_XLATE not supported");
                break;
            }
        }

        if (!list_is_empty(&new_ret->list)) {
            hs_list_destroy(ret);
            ret = new_ret;
        } else {
            hs_list_destroy(new_ret);
        }
    }

    return ret;
}

/* Records the matched rule 'rule' in 'hs'.  */
static void
hsa_record_matched_rule(struct header_space *hs, struct hsa_rule *rule)
{
    struct matched_entry *entry, *new;

    hs->n_rules++;
    hs->matched_rules = xrealloc(hs->matched_rules,
                                 hs->n_rules * sizeof *hs->matched_rules);
    hs->matched_rules[hs->n_rules - 1] = rule;

    HMAP_FOR_EACH_WITH_HASH (entry, hmap_node, hash_pointer(rule, 0),
                             &hs->matched_map) {
        if (entry->r == rule) {
            entry->count++;
            return;
        }
    }
    new = xmalloc(sizeof *new);
    new->r = rule;
    new->count = 1;
    hmap_insert(&hs->matched_map, &new->hmap_node, hash_pointer(rule, 0));
}

/* Returns the number of times the 'rule' has been matched.  */
static size_t
hsa_matched_rule_count(struct header_space *hs, struct hsa_rule *rule)
{
    struct matched_entry *entry;
    size_t ret = 0;

    HMAP_FOR_EACH_WITH_HASH (entry, hmap_node, hash_pointer(rule, 0),
                             &hs->matched_map) {
        if (entry->r == rule) {
            ret = entry->count;
        }
    }

    return ret;
}

/* Tries detecting loop from currect match sequence.  Returns true if
 * a loop path is generated by attaching 'hs' to 'result'.  Returns
 * false if there is no loop or if we are still tracing down the entire
 * loop path. */
static bool
hsa_try_detect_loop(struct header_space *hs, struct hsa_rule *rule,
                    struct hs_list *result)
{
    bool ret = false;

    hsa_record_matched_rule(hs, rule);
    if (hsa_matched_rule_count(hs, rule) > 1) {
        if (hs->in_loop) {
            /* Still in loop, checks infinite loop. */
            if (hsa_matched_rule_count(hs, rule) == MATCHED_COUNT_INFINITE) {
                list_insert(&result->list, &hs->list_node);
                ret = true;
            }
        } else {
            hs->in_loop = true;
        }
    } else {
        if (hs->in_loop) {
            /* If jump out of loop, records the loop. */
            list_insert(&result->list, &hs->list_node);
            /* Uses this to indicate this is a finite loop. */
            hs->in_loop = false;
            ret = true;
        } else {
            /* No, loop found so far, do nothing. */
        }
    }

    return ret;
}

/* Given header space 'hs', finds matches from 'hsa_table' with id
 * 'table_id' and applies the actions of matched rules to 'hs'.
 * When the expected action (e.g. output to port or loop found in
 * resubmit) is met, attaches the resulting 'hs' to 'result'.
 * If nested is true, returns a list of all new 'hs's.  Otherwise,
 * cleans up all 'hs' generated via previous nested invocation and
 * returns NULL.
 */
static struct hs_list *
hsa_calculate(struct header_space *hs, uint8_t table_id, ofp_port_t in_port,
              bool nested, struct hs_list *result, int indent, struct ds *out)
{
    struct hsa_table *hsa_tbl = &hsa_tables[table_id];
    struct hsbm_list *hsbm_list = hsbm_list_create();
    struct hsbm *hsbm = xmalloc(sizeof *hsbm);
    struct hs_list *ret = hs_list_create();
    struct hsbm *iter;
    struct hsa_rule *rule;

    /* Initializes the list containing partitioned header space. */
    hsbm_init(hsbm, &hs->match_hs);
    list_insert(&hsbm_list->list, &hsbm->list_node);

    if (debug_enabled) {
        ds_put_char_multiple(out, '\t', indent);
        ds_put_format(out, "Lookup from table %"PRIu8", for header space:\n",
                      table_id);
        ds_put_char_multiple(out, '\t', indent);
        hsa_match_print(out, &hs->match_hs, true);
    }

    LIST_FOR_EACH(rule, node, &hsa_tbl->rules) {
        /* Found a match from the remaining header space, clones the 'hs' and
         * applies match's wc to 'hs'. */
        if (hsa_rule_check_match(hs, rule, in_port)
            && hsbm_list_check_hsbm(hsbm_list, &rule->hsbm)) {
            struct header_space *clone = hs_clone(hs);
            struct hs_list *tmp;

            /* Marks the rule as matched. */
            rule->matched = true;

            /* Updates the remaining header space. */
            hsbm_list = hsbm_list_apply_hsbm(hsbm_list, &rule->hsbm);

            /* Detects loops. */
            if (op_type == HSA_LOOP_DETECT) {
                if (hsa_try_detect_loop(clone, rule, result)) {
                    continue;
                }
            }

            /* Applies the flow fields. */
            hsa_rule_apply_match(clone, rule);

            if (debug_enabled) {
                ds_put_char_multiple(out, '\t', indent);
                ds_put_cstr(out, "Found match rule:");
                hsa_rule_print(out, rule, true);
                ds_put_char_multiple(out, '\t', indent);
                ds_put_cstr(out, "Header-Space changed to (before apply "
                            "actions):");
                hsa_match_print(out, &clone->match_hs, true);
            }

            if (debug_enabled || true) {
                struct ds tmp = DS_EMPTY_INITIALIZER;

                ds_put_format(&tmp, "Found match rule: ");
                hsa_rule_print(&tmp, rule, false);
                VLOG_INFO("%s", ds_cstr(&tmp));
                ds_destroy(&tmp);
            }

            /* Applies the actions. */
            tmp = hsa_rule_apply_actions(clone, rule, table_id, result,
                                          indent, out);

            if (!list_is_empty(&tmp->list)) {
                /* Splices the 'action_list' to 'ret'. */
                list_splice(&ret->list, list_front(&tmp->list), &tmp->list);
            }
            hs_list_destroy(tmp);
        }
    }

    /* Now, what left in 'hsbm_list' are the header space partitions
     * that will not match any rules in this table.  And we should
     * save them to 'ret'. */
    LIST_FOR_EACH (iter, list_node, &hsbm_list->list) {
        struct header_space *clone = hs_clone(hs);

        hsbm_to_match(&clone->match_hs, iter);
        list_insert(&ret->list, &clone->list_node);
    }
    hsbm_list_destroy(hsbm_list);

    /* If not nested, return NULL, cleans up ret. */
    if (nested) {
        return ret;
    } else {
        hs_list_destroy(ret);

        return NULL;
    }
}


/* Sets match's flow and wc to 'set_value' and 'set_mask' respectively. */
static void
hsa_mf_set_flow_value_masked(const struct mf_field *field,
                             const union  mf_value *set_value,
                             const union  mf_value *set_mask,
                             const union  mf_value *mask,
                             struct match *match)
{
    /* Sets the value. */
    mf_set_flow_value_masked(field, set_value, mask, &match->flow);

    /* Sets the mask. */
    mf_set_flow_value_masked(field, set_mask, mask, &match->wc.masks);
}


static void
hsa_print_result(struct ds *out, struct hs_list *result)
{
    if (run_error) {
        ds_put_cstr(out, "Run error detected, please check the log\n");
        return;
    }

    ds_put_cstr(out, "\n\n\nOUTPUT\n======\n");
    if (op_type == HSA_LOOP_DETECT) {
        struct header_space *hs;

        LIST_FOR_EACH (hs, list_node, &result->list) {
            size_t i;

            ds_put_format(out, "Final Flow: ");
            hsa_match_print(out, &hs->match_hs, true);
            ds_put_format(out, "Loop Path (%s Loop)\n",
                          hs->in_loop ? "Infinite" : "Finite");
            ds_put_cstr(out, "=========\n");
            for (i = 0; i < hs->n_rules; i ++) {
                hsa_rule_print(out, hs->matched_rules[i], true);
            }
        }
    } else if (op_type == HSA_UNUSED_DETECT) {
        size_t i;

        ds_put_cstr(out, "UNUSED FLOWS\n============\n");
        for (i = 0; i < n_hsa_tables; i++) {
            struct hsa_rule *rule;

            if (i == INTERNAL_TABLE_ID) {
                continue;
            }
            LIST_FOR_EACH(rule, node, &hsa_tables[i].rules) {
                if (!rule->matched) {
                    hsa_rule_print(out, rule, true);
                }
            }
        }
    } else {
        OVS_NOT_REACHED();
    }
    ds_put_cstr(out, "\n");
}


/* Context for conducting hsa.
 * 'argv' is dynamically allocated, user must free it. */
struct hsa_context {
    struct unixctl_conn *conn;
    int argc;
    const char **argv;
};

static void *
hsa_do_analysis(void *ctx_)
{
    struct hsa_context *ctx = ctx_;
    struct ds out = DS_EMPTY_INITIALIZER;
    struct hs_list *result = hs_list_create();
    struct ofproto *ofproto = ofproto_lookup(ctx->argv[1]);
    ofp_port_t in_port = OFP_PORT_NULL;
    struct header_space *hs_start;

    if (!ofproto) {
        ds_put_cstr(&out, "no such bridge");
        goto finish;
    }
    /* Parses the in_port and --debug. */
    if (ctx->argc > 2) {
        if (!strcmp(ctx->argv[2], "--verbose")) {
            debug_enabled = true;
        } else {
            in_port = OFP_PORT_C(atoi(CONST_CAST(char *, ctx->argv[2])));
            if (ctx->argc == 4 && !strcmp(ctx->argv[3], "--verbose")) {
                debug_enabled = true;
            }
        }
    }

    hs_start = hs_create();
    hsa_init(ofproto, &out, in_port, hs_start);
    hsa_debug_dump_flows(&out, ctx->argv[1]);
    hsa_calculate(hs_start, TABLE_DEFAULT, OFPP_IN_PORT, false, result,
                  INDENT_DEFAULT, &out);
    hsa_print_result(&out, result);
    hs_list_destroy(result);
    hs_destroy(hs_start);
    hsa_finish();
    debug_enabled = false;

finish:
    unixctl_command_reply(ctx->conn, ds_cstr(&out));
    ds_destroy(&out);
    hsa_tid = 0;

    return NULL;
}

static void
hsa_unixctl_start(struct unixctl_conn *conn, int argc,
                  const char *argv[], void *aux)
{
    struct hsa_context *ctx;
    size_t i;

    if (hsa_tid) {
        unixctl_command_reply_error(conn, "Already running HSA please wait");
        return;
    }
    op_type = *(int *)aux;
    ctx = xmalloc(sizeof *ctx);
    ctx->conn = conn;
    ctx->argc = argc;
    ctx->argv = xmalloc(argc * sizeof *ctx->argv);
    for (i = 0; i < argc; i++) {
        ctx->argv[i] = xstrdup(argv[i]);
    }
    hsa_tid = ovs_thread_create("hsa", hsa_do_analysis, ctx);
}

static void
hsa_unixctl_init(void)
{
    static int loop_detect = HSA_LOOP_DETECT;
    static int unused_detect = HSA_UNUSED_DETECT;

    unixctl_command_register("hsa/detect-loop", "bridge [in_port] [--verbose]",
                             1, 3, hsa_unixctl_start, &loop_detect);
    unixctl_command_register("hsa/detect-unused", "bridge [--verbose]",
                             1, 2, hsa_unixctl_start, &unused_detect);
}

/* Public functions. */
void
ofproto_dpif_hsa_init(void)
{
    static bool registered;

    if (registered) {
        return;
    }
    registered = true;
    hsa_unixctl_init();
}
