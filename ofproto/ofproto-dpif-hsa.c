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
    HSA_LEAK_DETECT,
    HSA_LOOP_DETECT,
    HSA_UNUSED_DETECT
};

/* Always starts the analysis from OpenFlow table 0. */
#define TABLE_DEFAULT 0
/* Default indent level for output. */
#define INDENT_DEFAULT 0

/* Rule used for head space analysis. */
struct hsa_rule {
    struct ovs_list node;           /* In owning table's 'rules'. */

    bool hit;                       /* If the rule will be hit. */
    uint8_t table_id;               /* OpenFlow table id. */
    int prio;                       /* Priority. */
    struct match match;             /* Flow and wildcards. */
    const struct rule_actions *actions;/* Actions. */
    struct hsbm hsbm;               /* Compressed bit map representation of */
                                    /* match. */
};

/* Records a previously matched rule's match. */
struct hs_constraint {
    struct ovs_list list_node;
    struct match match;
};

/* Rule table for header space analysis. */
struct hsa_table {
    struct ovs_list rules;          /* Contains 'struct hsa_rule's. */
    size_t n_rules;                 /* Number of rules in the table. */
};

/* Macros for the 'move_map' member of 'struct header_space'. */
#define MOVE_MAP_LEN   (sizeof(struct flow) * 8)
#define BIT_UNSET      0xFF
#define BIT_SET        0xFE

/* Representation of Header Space. */
struct header_space {
    struct ovs_list list_node;

    /* Difference between match_hs and match_src.
     *
     *    - match_hs represents the input header space as it is transformed by
     *      matched rules and rule actions.
     *
     *    - match_src represents the input header space that will result in
     *      the match_hs.
     */
    struct match match_hs;          /* Current header space. */
    struct match match_src;         /* Input header space.*/
    ofp_port_t output;              /* Output port. */

    /* Delayed Subtraction (Partition)
     * ===============================
     *
     * To avoid partition of header space immediately after matching a rule,
     * we store the previously matched rules from same table as constraints
     * and delay partition until the output generation stage.
     */
    struct ovs_list constraints;    /* Stores 'struct hs_constraint's. */

    /* For actions like OFPACT_REG_MOVE and OFPACT_SET_FIELD, we need to
     * record the origin of the set bits.  So, when later rule matches on
     * those bits, we can adjust the 'match_src' correctly.
     *
     * Assume all fields in 'struct flow' are in big endian.  This is to
     * formalize the transition between field bit and the move_map element.
     *
     * Each row element consists of two parts (columns), 8-bit meta-flow field
     * id and 8-bit index of the bit in original field.
     *
     * The first column's value is 'BIT_UNSET' if the field has never been set,
     * or 'BIT_SET' if the field has been set by aciton.
     * */
    uint8_t move_map[MOVE_MAP_LEN][2];

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

/* Global 'struct hsa_table's, one for each OpenFlow table. */
static struct hsa_table *hsa_tables;
/* Number of tables in 'hsa_tables'. */
static int n_hsa_tables;
/* Initial 'struct header_space' for conducting analysis. */
static struct header_space *hs_start;
/* Global control of debugging mode. */
static bool debug_enabled = false;
/* Operation type. */
static int op_type;

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
static void hsa_match_print(struct ds *, struct match *);
static void hsa_rule_print(struct ds *, struct hsa_rule *);

static void hsa_rule_apply_match(struct header_space *, struct hsa_rule *);
static void hsa_hs_apply_constraint(struct header_space *, struct hsa_rule *);
static bool hs_constraint_is_exact_match(struct match *);

static void hsa_init(struct ofproto *, ofp_port_t in_port, struct ds *);
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

static bool hsa_mf_are_prereqs_ok(const struct mf_field *,
                                  struct header_space *);
static void hsa_mf_set_flow_value_masked(const struct mf_field *,
                                         const union mf_value *,
                                         const union mf_value *,
                                         const union mf_value *,
                                         struct match *);
static void hsa_set_move_map_bit(struct header_space *, size_t idx,
                                 uint8_t mf_id, uint8_t bit_idx);
static size_t hsa_field_offset_from_mf(const struct mf_field *);
static void hsa_move_map_set_field_by_mask(struct header_space *,
                                           const struct mf_field *,
                                           const union mf_value *);
static void hsa_move_map_set_field_by_subfield(struct header_space *,
                                               const struct mf_subfield *,
                                               const struct mf_subfield *);
static void hsa_move_map_apply_matched_field(struct header_space *,
                                             const struct mf_field *);
static void hsa_mf_set_value(struct header_space *, const struct mf_field *,
                             union mf_value *, union mf_value *);
static const struct mf_field *hsa_flow_offset_to_mf(size_t offset);


/* Creates and returns a newly zalloc'ed 'hs'. */
static struct header_space *
hs_create(void)
{
    struct header_space *hs = xzalloc(sizeof *hs);

    hs->output = OFPP_NONE;
    list_init(&hs->constraints);
    memset(hs->move_map, 0xff, sizeof hs->move_map);
    hmap_init(&hs->matched_map);

    return hs;
}

/* Clones the header space 'hs' and returns the copy. */
static struct header_space *
hs_clone(const struct header_space *hs)
{
    struct header_space *clone = xmalloc(sizeof *hs);
    struct hs_constraint *iter;

    clone->match_hs = hs->match_hs;
    clone->match_src = hs->match_src;
    clone->output = hs->output;

    list_init(&clone->constraints);
    /* Copies the constraints. */
    LIST_FOR_EACH (iter, list_node, &hs->constraints) {
        struct hs_constraint *copy = xmalloc(sizeof *copy);

        copy->match = iter->match;
        list_push_back(&clone->constraints, &copy->list_node);
    }

    memcpy(clone->move_map, hs->move_map, sizeof hs->move_map);

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
    struct hs_constraint *c_iter, *c_next;
    struct matched_entry *m_iter, *m_next;

    /* Destroys constraints. */
    LIST_FOR_EACH_SAFE (c_iter, c_next, list_node, &hs->constraints) {
        list_remove(&c_iter->list_node);
        free(c_iter);
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
    hs->match_hs.flow.in_port.ofp_port = orig_in_port;

    return ret;
}

/* Prints the match in 'out'. */
static void
hsa_match_print(struct ds *out, struct match *match)
{
    match_format(match, out, OFP_DEFAULT_PRIORITY);
    ds_put_cstr(out, "\n");
}

/* Prints the OpenFlow rule in 'out'. */
static void
hsa_rule_print(struct ds *out, struct hsa_rule *rule)
{
    ds_put_format(out, "table_id=%"PRIu8", ", rule->table_id);
    match_format(&rule->match, out, rule->prio);
    ds_put_cstr(out, ",actions=");
    ofpacts_format(rule->actions->ofpacts, rule->actions->ofpacts_len, out);
    ds_put_cstr(out, "\n");
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
     * to header space.  If the 'field' in 'match_src' and 'match_hs'
     * are different, does not set 'match_src', since that indicates
     * the 'field' has been set by action. */
#define FLOW_ATTR(ATTR)                                                 \
    if (!flow_wildcard_is_fully_unmasked(&masks->ATTR,                  \
                                         sizeof masks->ATTR)) {         \
        const struct mf_field *mf;                                      \
                                                                        \
        if (!memcmp(&hs->match_src.flow.ATTR, &hs->match_hs.flow.ATTR,  \
                    sizeof hs->match_src.flow.ATTR)                     \
            && !memcmp(&hs->match_src.wc.masks.ATTR,                    \
                       &hs->match_hs.wc.masks.ATTR,                     \
                       sizeof hs->match_src.wc.masks.ATTR)) {           \
            flow_apply_field(&hs->match_src.flow.ATTR,                  \
                             &hs->match_src.wc.masks.ATTR,              \
                             &flow->ATTR, &masks->ATTR, sizeof flow->ATTR); \
        }                                                               \
        flow_apply_field(&hs->match_hs.flow.ATTR,                       \
                         &hs->match_hs.wc.masks.ATTR,                   \
                         &flow->ATTR, &masks->ATTR, sizeof flow->ATTR); \
        mf = hsa_flow_offset_to_mf(offsetof(struct flow, ATTR));        \
        if (mf) {                                                       \
            hsa_move_map_apply_matched_field(hs, mf);                   \
        }                                                               \
    }
    FLOW_ATTRS
#undef FLOW_ATTR
}

/* Returns true if the 'constraint' match is an exact-match rule. */
static bool
hs_constraint_is_exact_match(struct match *match)
{
#define FLOW_ATTR(ATTR)                                                   \
    if (!is_all_ones(&match->wc.masks.ATTR, sizeof match->wc.masks.ATTR)  \
        && !is_all_zeros(&match->wc.masks.ATTR, sizeof match->wc.masks.ATTR)) { \
        return false;                                                     \
    }
    FLOW_ATTRS
#undef FLOW_ATTR

    return true;
}

/* Appends the 'rule' as constraint to 'hs'.  Caution, only the
 * 'valid' fields of 'rule' are used. */
static void
hsa_hs_apply_constraint(struct header_space *hs, struct hsa_rule *rule)
{
    struct hs_constraint *c = xmalloc(sizeof *c);

    c->match = rule->match;

    /* TODO: Use the move_map here. */
    /* If the 'ATTR' in 'match_src' and 'match_hs' are different,
     * unmask the 'ATTR' in 'c->match.wc'.  This is to avoid
     * adding 'ATTR's set by actions as constraint. */
#define FLOW_ATTR(ATTR)                                                 \
    if (memcmp(&hs->match_src.flow.ATTR, &hs->match_hs.flow.ATTR,      \
               sizeof hs->match_src.flow.ATTR)                         \
        || memcmp(&hs->match_src.wc.masks.ATTR,                        \
                  &hs->match_hs.wc.masks.ATTR,                          \
                  sizeof hs->match_src.wc.masks.ATTR)) {               \
        WC_UNMASK_FIELD(&c->match.wc, ATTR);                            \
    }
    FLOW_ATTRS
#undef FLOW_ATTR

    list_insert(&hs->constraints, &c->list_node);
}


/* Masks in_port, metadata, regs and ipv6. */
static void
hs_init__(struct header_space *hs, ofp_port_t in_port)
{
    hs->match_hs.flow.in_port.ofp_port = in_port;
    WC_MASK_FIELD(&hs->match_hs.wc, in_port);
    WC_MASK_FIELD(&hs->match_hs.wc, regs);
    WC_MASK_FIELD(&hs->match_hs.wc, metadata);
    WC_MASK_FIELD(&hs->match_hs.wc, ipv6_src);
    WC_MASK_FIELD(&hs->match_hs.wc, ipv6_dst);

    hs->match_src.flow.in_port.ofp_port = in_port;
    WC_MASK_FIELD(&hs->match_src.wc, in_port);
    WC_MASK_FIELD(&hs->match_src.wc, regs);
    WC_MASK_FIELD(&hs->match_src.wc, metadata);
    WC_MASK_FIELD(&hs->match_src.wc, ipv6_src);
    WC_MASK_FIELD(&hs->match_src.wc, ipv6_dst);
}

/* Given the 'ofproto' of a bridge, copies all rules from each oftable
 * into a sorted list with descending priority.  Also, initilizes 'hs'. */
static void
hsa_init(struct ofproto *ofproto, ofp_port_t in_port, struct ds *out)
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

            hsa_rule->hit = false;
            hsa_rule->table_id = table_id;
            hsa_rule->prio = rule->cr.priority;
            minimatch_expand(&rule->cr.match, &hsa_rule->match);
            /* TODO: When hsa is moved into a dedicated thread, use ref_count
             * to avoid actions being deleted by other threads. */
            hsa_rule->actions = rule_get_actions(rule);
            hsbm_init(&hsa_rule->hsbm, &hsa_rule->match);
            list_insert(rules, &hsa_rule->node);
        }
        sort(tbl->n_rules, hsa_rule_compare, hsa_rule_swap, rules);
        table_id++;
    }

    /* Initializes the 'hs_start', sets and masks the 'in_port' and 'regs'. */
    hs_start = hs_create();
    hs_init__(hs_start, in_port);

    if (debug_enabled) {
        ds_put_char_multiple(out, '\t', INDENT_DEFAULT);
        ds_put_cstr(out, "Header-Space init done:\n");
        hsa_match_print(out, &hs_start->match_hs);
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
    hs_destroy(hs_start);
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
                hsa_rule_print(out, rule);
            }
        }
        ds_put_cstr(out, "\n");
    }
}

/* Applies various output actions. */
static void
hsa_rule_apply_output_action__(struct header_space *hs, ofp_port_t port,
                               struct hs_list *result)
{
    if (op_type != HSA_LEAK_DETECT) {
        return;
    }

    switch (port) {
    /* Just assume the architecture of having one integration bridge */
    case OFPP_IN_PORT:
    case OFPP_TABLE:
    case OFPP_FLOOD:
    case OFPP_ALL:
    case OFPP_NONE:
    case OFPP_LOCAL:
    case OFPP_NORMAL:
        /* Should not see such actions installed from controller. */
        OVS_NOT_REACHED();
    case OFPP_CONTROLLER:
        /* Do nothing. */
        break;
    default:
        if (port != hs->match_src.flow.in_port.ofp_port) {
            /* Clones the 'hs' with the output, attachs to the result
             * list. */
            struct header_space *clone = hs_clone(hs);

            clone->output = port;
            list_insert(&result->list, &clone->list_node);
        } else {
            VLOG_ERR("output to input port: %"PRIu16, port);
        }
        break;
    }
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

                if (hsa_mf_are_prereqs_ok(move->dst.field, hs)) {
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

                    hsa_move_map_set_field_by_subfield(hs, &move->src,
                                                       &move->dst);
                }
                break;
            }

            case OFPACT_SET_FIELD:
                /* Load action, only support load of exact-match value. */
                set_field = ofpact_get_SET_FIELD(a);
                mf = set_field->field;

                if (hsa_mf_are_prereqs_ok(mf, hs)) {
                    hsa_mf_set_flow_value_masked(mf, &set_field->value,
                                                 &set_field->mask,
                                                 &set_field->mask,
                                                 &hs->match_hs);
                    hsa_move_map_set_field_by_mask(hs, mf, &set_field->mask);
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
            case OFPACT_SET_ETH_SRC:
                VLOG_INFO("OFPACT_SET_ETH_SRC not supported");
                break;
            case OFPACT_SET_ETH_DST:
                VLOG_INFO("OFPACT_SET_ETH_DST not supported");
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
            case OFPACT_CONTROLLER:
                VLOG_INFO("OFPACT_CONTROLLER not supported");
                break;
            case OFPACT_GROUP:
                VLOG_INFO("OFPACT_GROUP not supported");
                break;
            case OFPACT_STACK_PUSH:
                VLOG_INFO("OFPACT_STACK_PUSH not supported");
                break;
            case OFPACT_STACK_POP:
                VLOG_INFO("OFPACT_STACK_POP not supported");
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
            case OFPACT_DEC_TTL:
                VLOG_INFO("OFPACT_DEC_TTL not supported");
                break;
            case OFPACT_NOTE:
                VLOG_INFO("OFPACT_NOTE not supported");
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
        hsa_match_print(out, &hs->match_hs);
    }

    LIST_FOR_EACH(rule, node, &hsa_tbl->rules) {
        /* Found a match from the remaining header space, clones the 'hs' and
         * applies match's wc to 'hs'. */
        if (hsa_rule_check_match(hs, rule, in_port)
            && hsbm_list_check_hsbm(hsbm_list, &rule->hsbm)) {
            struct header_space *clone = hs_clone(hs);
            struct hs_list *tmp;

            /* Marks the rule as matched. */
            rule->hit = true;

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
            hsa_hs_apply_constraint(hs, rule);

            if (debug_enabled) {
                ds_put_char_multiple(out, '\t', indent);
                ds_put_cstr(out, "Found match rule:");
                hsa_rule_print(out, rule);
                ds_put_char_multiple(out, '\t', indent);
                ds_put_cstr(out, "Header-Space changed to (before apply "
                            "actions):");
                hsa_match_print(out, &clone->match_hs);
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
     * save them to 'ret'.  Each of them will have all flows in the
     * table as constraints. */
    LIST_FOR_EACH (iter, list_node, &hsbm_list->list) {
        struct header_space *clone = hs_clone(hs);

        hsbm_to_match(&clone->match_hs, iter);
        /* Add all flows as constraint. */
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


/* Returns true if 'flow' meets the prerequisites for 'mf', false otherwise. */
static bool
hsa_mf_are_prereqs_ok(const struct mf_field *mf,
                      struct header_space *hs OVS_UNUSED)
{
    switch (mf->prereqs) {
    case MFP_NONE:
        return true;
    /* Do not support other prereqs yet. */
    case MFP_IPV4:
    case MFP_IP_ANY:
    case MFP_TCP:
    case MFP_UDP:
    case MFP_ARP:
    case MFP_VLAN_VID:
    case MFP_IPV6:
    case MFP_MPLS:
    case MFP_SCTP:
    case MFP_ICMPV4:
    case MFP_ICMPV6:
    case MFP_ND:
    case MFP_ND_SOLICIT:
    case MFP_ND_ADVERT:
        OVS_NOT_REACHED();
    }
    OVS_NOT_REACHED();
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

    /* TODO: if move bit is set, abort!. */
}

/* Sets a bit in 'hs->move_map' to 'value'. */
static void
hsa_set_move_map_bit(struct header_space *hs, size_t idx, uint8_t mf_id,
                     uint8_t bit_idx)
{
    hs->move_map[idx][0] = mf_id;
    hs->move_map[idx][1] = bit_idx;
}

/* Given 'mf', returns the offset of field corresponding to the
 * 'mf->if' in byte. */
static size_t
hsa_field_offset_from_mf(const struct mf_field *mf)
{
    switch (mf->id) {
    case MFF_TUN_ID:
        return offsetof(struct flow, tunnel.tun_id);
    case MFF_METADATA:
        return offsetof(struct flow, metadata);
    CASE_MFF_REGS:
        return offsetof(struct flow, regs[mf->id - MFF_REG0]);
    /* Do not support other mf_id yet. */
    case MFF_DP_HASH:
    case MFF_RECIRC_ID:
    case MFF_CONJ_ID:
    case MFF_TUN_SRC:
    case MFF_TUN_DST:
    case MFF_TUN_FLAGS:
    case MFF_TUN_TTL:
    case MFF_TUN_TOS:
    case MFF_TUN_GBP_ID:
    case MFF_TUN_GBP_FLAGS:
    case MFF_IN_PORT:
    case MFF_IN_PORT_OXM:
    case MFF_ACTSET_OUTPUT:
    case MFF_SKB_PRIORITY:
    case MFF_PKT_MARK:
    CASE_MFF_XREGS:
    case MFF_ETH_SRC:
    case MFF_ETH_DST:
    case MFF_ETH_TYPE:
    case MFF_VLAN_TCI:
    case MFF_DL_VLAN:
    case MFF_VLAN_VID:
    case MFF_DL_VLAN_PCP:
    case MFF_VLAN_PCP:
    case MFF_MPLS_LABEL:
    case MFF_MPLS_TC:
    case MFF_MPLS_BOS:
    case MFF_IPV4_SRC:
    case MFF_IPV4_DST:
    case MFF_IPV6_SRC:
    case MFF_IPV6_DST:
    case MFF_IPV6_LABEL:
    case MFF_IP_PROTO:
    case MFF_IP_DSCP:
    case MFF_IP_DSCP_SHIFTED:
    case MFF_IP_ECN:
    case MFF_IP_TTL:
    case MFF_IP_FRAG:
    case MFF_ARP_OP:
    case MFF_ARP_SPA:
    case MFF_ARP_TPA:
    case MFF_ARP_SHA:
    case MFF_ND_SLL:
    case MFF_ARP_THA:
    case MFF_ND_TLL:
    case MFF_TCP_SRC:
    case MFF_UDP_SRC:
    case MFF_SCTP_SRC:
    case MFF_TCP_DST:
    case MFF_UDP_DST:
    case MFF_SCTP_DST:
    case MFF_TCP_FLAGS:
    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV6_TYPE:
    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_CODE:
    case MFF_ND_TARGET:
    case MFF_N_IDS:
    default:
        OVS_NOT_REACHED();
    }

    return 0;
}

/* Given the 'mf' and 'mask', sets the corresponding bits in 'hs->move_map'
 * to 'BIT_SET'.  Assumes all fields are in big endian and 'mf' has already
 * passed the prerequisite check. */
static void
hsa_move_map_set_field_by_mask(struct header_space *hs,
                               const struct mf_field *mf,
                               const union  mf_value *mask)
{
    const uint8_t *bytes = (const uint8_t *) mask;
    size_t field_offset = hsa_field_offset_from_mf(mf);
    size_t field_len = mf->n_bytes;
    int i;

    /* Starts from the least significant byte. */
    for (i = field_len - 1; i >= 0; i--) {
        size_t byte_offset_in_bits = field_offset * 8 + i * 8;
        const uint8_t byte = bytes[i];
        size_t j;

        for (j = 0; j < 8; j++) {
            if ((byte >> j) & 0x1) {
                hsa_set_move_map_bit(hs, byte_offset_in_bits + 7 - j,
                                     BIT_SET, 0);
            }
        }
    }
}

/* Caller must guarantee the 'dst->mf' has already passed the
 * prerequisite check.  The 'src' and 'dst' already use big
 * endian. */
static void
hsa_move_map_set_field_by_subfield(struct header_space *hs,
                                   const struct mf_subfield *src,
                                   const struct mf_subfield *dst)
{
    size_t dst_fd_offset = hsa_field_offset_from_mf(dst->field);
    size_t dst_set_start;
    size_t i;

    /* Computes the starting position in 'hs->move_map' for dst field. */
    dst_set_start = dst_fd_offset * 8 + dst->field->n_bytes * 8 - 1 - dst->ofs;

    for (i = 0; i < src->n_bits; i++) {
        hsa_set_move_map_bit(hs, dst_set_start - i,
                             (uint8_t) src->field->id,
                             src->ofs + i);
    }
}

/* Checks if the just applied 'mf' field in 'hs->match_hs' is copied
 * from other field.  If so, applied same match to the original field. */
static void
hsa_move_map_apply_matched_field(struct header_space *hs,
                                 const struct mf_field *mf)
{
    union mf_value cur_value;
    union mf_value cur_mask;
    size_t ofs = hsa_field_offset_from_mf(mf);
    int i;

    mf_get_value(mf, &hs->match_hs.flow, &cur_value);
    mf_get_value(mf, &hs->match_hs.wc.masks, &cur_mask);

    /* Starts checking from bit zero of the field.  Again, assumes
     * using big endian. */
    for (i = 0; i < mf->n_bits; i++) {
        uint8_t orig_mf_id = hs->move_map[ofs * 8 + mf->n_bytes * 8 - 1 - i][0];
        uint8_t orig_bit_idx = hs->move_map[ofs * 8 + mf->n_bytes * 8 - 1 - i][1];

        /* Finds a moved bit.  The original bit must be 'BIT_UNSET'. */
        if (orig_mf_id != BIT_SET && orig_mf_id != BIT_UNSET) {
            const struct mf_field *orig_mf;
            union mf_value orig_mask;
            union mf_value orig_value;
            size_t orig_ofs;
            size_t idx;

            orig_mf = mf_from_id(orig_mf_id);
            orig_ofs = hsa_field_offset_from_mf(mf);
            idx = orig_ofs * 8 + orig_mf->n_bytes * 8 - 1 - orig_bit_idx;

            /* TODO: fix this. */
            /* Does not support BIT_SET, since no idea if the bit
             * is copied before/after the set. */
            if (hs->move_map[idx][0] != BIT_UNSET) {
                VLOG_INFO("The origin of moved bit is also a moved bit, "
                          "do not support this.");
            }

            mf_get_value(orig_mf, &hs->match_hs.flow, &orig_value);
            mf_get_value(orig_mf, &hs->match_hs.wc.masks, &orig_mask);
            bitwise_copy(&cur_value, mf->n_bytes, i,
                         &orig_value, orig_mf->n_bytes, orig_bit_idx, 1);
            bitwise_copy(&cur_mask, mf->n_bytes, i,
                         &orig_mask, orig_mf->n_bytes, orig_bit_idx, 1);
            hsa_mf_set_value(hs, orig_mf, &orig_value, &orig_mask);
        }
    }
}

/* Sets the field 'mf' in both 'hs->match_hs' and 'hs->match_src'. */
static void
hsa_mf_set_value(struct header_space *hs, const struct mf_field *mf,
                 union mf_value *value, union mf_value *mask)
{
    mf_set_flow_value(mf, value, &hs->match_hs.flow);
    mf_set_flow_value(mf, mask, &hs->match_hs.wc.masks);
    mf_set_flow_value(mf, value, &hs->match_src.flow);
    mf_set_flow_value(mf, mask, &hs->match_src.wc.masks);
}

/* Converts 'struct flow' field offset to 'mf'. */
static const struct mf_field *
hsa_flow_offset_to_mf(size_t offset)
{
    switch (offset) {
    case offsetof(struct flow, tunnel.tun_id):
        return mf_from_id(MFF_TUN_ID);
    case offsetof(struct flow, metadata):
        return mf_from_id(MFF_METADATA);
    case offsetof(struct flow, regs[0]):
        return mf_from_id(MFF_REG0);
    case offsetof(struct flow, regs[1]):
        return mf_from_id(MFF_REG1);
    case offsetof(struct flow, regs[2]):
        return mf_from_id(MFF_REG2);
    case offsetof(struct flow, regs[3]):
        return mf_from_id(MFF_REG3);
    case offsetof(struct flow, regs[4]):
        return mf_from_id(MFF_REG4);
    case offsetof(struct flow, regs[5]):
        return mf_from_id(MFF_REG5);
    case offsetof(struct flow, regs[6]):
        return mf_from_id(MFF_REG6);
    case offsetof(struct flow, regs[7]):
        return mf_from_id(MFF_REG7);
    }

    return NULL;
}


static void
generate_flow_output(struct ds *out, struct match *match, ofp_port_t out_port)
{
    /* regs and metadata must be all 0, since we input them as is. */
    if (!is_all_zeros(&match->flow.metadata, sizeof match->flow.metadata)
        || !is_all_zeros(&match->flow.regs, sizeof match->flow.regs)) {
        VLOG_WARN("Input regs/metadata not all-zero, possible analysis bug");
    }
    /* Unmasks regs and metadata to make the print clean. */
    WC_UNMASK_FIELD(&match->wc, metadata);
    WC_UNMASK_FIELD(&match->wc, regs);

    if (op_type == HSA_LEAK_DETECT) {
        ds_put_format(out, "%-16"PRIu16"   ", out_port);
    }
    hsa_match_print(out, match);
}

static void
hsa_print_unused(struct ds *out)
{
    size_t i;

    ds_put_cstr(out, "\n\n\nUNUSED FLOWS\n============\n");
    for (i = 0; i < n_hsa_tables; i++) {
        struct hsa_rule *rule;

        LIST_FOR_EACH(rule, node, &hsa_tables[i].rules) {
            if (!rule->hit) {
                ds_put_format(out, "table_id=%"PRIu8", ", rule->table_id);
                generate_flow_output(out, &rule->match, 0);
                ds_put_char(out, ',');
                ds_put_cstr(out, "actions=");
                ofpacts_format(rule->actions->ofpacts,
                               rule->actions->ofpacts_len, out);
                ds_put_cstr(out, "\n");
            }
        }
    }
    ds_put_cstr(out, "\n============\n");
}

static void
hsa_print_result(struct ds *out, struct hs_list *result)
{
    struct header_space *hs;

    ds_put_cstr(out, "\n\n\nOUTPUT\n======\n");
    LIST_FOR_EACH (hs, list_node, &result->list) {
        if (op_type == HSA_LEAK_DETECT) {
            ds_put_cstr(out, "Output Port No      Input Header Space\n");
            ds_put_cstr(out, "==============      ==================\n");
        } else if (op_type == HSA_LOOP_DETECT) {
            ds_put_cstr(out, "Input Header Space\n");
            ds_put_cstr(out, "==================\n");
        }

        if (list_is_empty(&hs->constraints)) {
            generate_flow_output(out, &hs->match_src, hs->output);
        } else {
            struct hsbm *hsbm = xmalloc(sizeof *hsbm);
            struct hsbm_list *hsbm_list = hsbm_list_create();
            struct hs_constraint *c;

            hsbm_init(hsbm, &hs->match_src);
            list_insert(&hsbm_list->list, &hsbm->list_node);

            LIST_FOR_EACH (c, list_node, &hs->constraints) {
                struct hsbm hsbm_c;

                hsbm_init(&hsbm_c, &c->match);
                /* If the constraint is a exact match, put it on the
                 * exact match list for succinct output. */
                if (hs_constraint_is_exact_match(&c->match)) {
                    ds_put_cstr(out, "constraint:");
                    hsa_match_print(out, &c->match);
                } else {
                    hsbm_list = hsbm_list_apply_hsbm(hsbm_list, &hsbm_c);
                    if (list_is_empty(&hsbm_list->list)) {
                        break;
                    }
                }
                hsbm_uninit(&hsbm_c);
            }

            if (!list_is_empty(&hsbm_list->list)) {
                struct hsbm *iter;

                /* Restores the 'match' from 'iter'. */
                LIST_FOR_EACH (iter, list_node, &hsbm_list->list) {
                    struct match out_match;

                    hsbm_to_match(&out_match, iter);
                    generate_flow_output(out, &out_match, hs->output);
                }
            }
            hsbm_list_destroy(hsbm_list);
        }

        if (op_type == HSA_LOOP_DETECT) {
            size_t i;

            ds_put_cstr(out, "=========\n");
            ds_put_format(out, "Loop Path (%s Loop)\n",
                          hs->in_loop ? "Infinite" : "Finite");
            ds_put_cstr(out, "=========\n");
            for (i = 0; i < hs->n_rules; i ++) {
                hsa_rule_print(out, hs->matched_rules[i]);
            }
        }
        ds_put_cstr(out, "\n");
    }
}


static void
hsa_do_analysis(struct ds *out, const char *ofproto_name, const char *port_)
{
    struct hs_list *result = hs_list_create();
    struct ofproto *ofproto;
    ofp_port_t in_port;

    ofproto = ofproto_lookup(ofproto_name);
    if (!ofproto) {
        ds_put_cstr(out, "no such bridge");
        return;
    }
    in_port = OFP_PORT_C(atoi(CONST_CAST(char *, port_)));
    hsa_init(ofproto, in_port, out);
    hsa_debug_dump_flows(out, ofproto_name);
    /* Starts the HSA with global header space and table 0. */
    hsa_calculate(hs_start, TABLE_DEFAULT, OFPP_IN_PORT, false, result,
                  INDENT_DEFAULT, out);
    /* Prints output. */
    if (op_type == HSA_UNUSED_DETECT) {
        hsa_print_unused(out);
    } else {
        hsa_print_result(out, result);
    }
    hs_list_destroy(result);
    /* Finishes up. */
    hsa_finish();
}

static void
hsa_unixctl_leak_detect(struct unixctl_conn *conn, int argc OVS_UNUSED,
                        const char *argv[], void *aux OVS_UNUSED)
{
    struct ds out = DS_EMPTY_INITIALIZER;

    op_type = HSA_LEAK_DETECT;
    hsa_do_analysis(&out, argv[1], argv[2]);
    unixctl_command_reply(conn, ds_cstr(&out));
    ds_destroy(&out);
}

static void
hsa_unixctl_loop_detect(struct unixctl_conn *conn, int argc OVS_UNUSED,
                        const char *argv[], void *aux OVS_UNUSED)
{
    struct ds out = DS_EMPTY_INITIALIZER;

    op_type = HSA_LOOP_DETECT;
    hsa_do_analysis(&out, argv[1], argv[2]);
    unixctl_command_reply(conn, ds_cstr(&out));
    ds_destroy(&out);
}

static void
hsa_unixctl_unused_detect(struct unixctl_conn *conn, int argc OVS_UNUSED,
                        const char *argv[], void *aux OVS_UNUSED)
{
    struct ds out = DS_EMPTY_INITIALIZER;

    op_type = HSA_UNUSED_DETECT;
    hsa_do_analysis(&out, argv[1], argv[2]);
    unixctl_command_reply(conn, ds_cstr(&out));
    ds_destroy(&out);
}

static void
hsa_unixctl_init(void)
{
    unixctl_command_register("hsa/detect-leak", "bridge ofport", 2, 2,
                             hsa_unixctl_leak_detect, NULL);
    unixctl_command_register("hsa/detect-loop", "bridge ofport", 2, 2,
                             hsa_unixctl_loop_detect, NULL);
    unixctl_command_register("hsa/detect-unused", "bridge ofport", 2, 2,
                             hsa_unixctl_unused_detect, NULL);
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
