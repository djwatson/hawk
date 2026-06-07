#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bigint.h"
#include "gc.h"
#include "hawk.h"
#include "types.h"
#include "util/array.h"
#include "util/hashtable.h"

bool profile = false;
bool jit_dump_flag = false;
int64_t max_trace = 0;

void profiler_set_in_gc(bool active) { (void)active; }
void vm_trace_reset(void) {}

typedef struct {
  gc_header *key;
  bool value;
} seen_entry;

typedef struct {
  gc_header *key;
  uint64_t value;
} idx_entry;

typedef struct {
  gc_header *header;
  gc_header **edges;
} obj_node;

typedef struct {
  uint64_t **succ;
  uint64_t **pred;
} dag;

typedef struct {
  symbol *sym;
  const char *name;
  uint64_t retained_bytes;
} symbol_score;

typedef struct {
  uint64_t idx;
  uint64_t size;
} object_score;

typedef struct {
  gc_header **children;
} child_list_ctx;

typedef struct {
  char const *name;
  uint64_t count;
} name_count;

typedef struct {
  char const *image_path;
  char const *symbol_name;
} explorer_options;

static obj_node *obj_nodes;
static gc_header **obj_list;
static idx_entry *header_to_idx;

static uint64_t *obj_scc;
static uint64_t scc_count;
static uint64_t *scc_size;

static uint64_t *scc_retained_bytes;
static uint64_t *scc_reachable;

static size_t object_size(gc_header *header) {
  switch (header->type) {
  case FLONUM_TAG:
    return sizeof(flonum_s);
  case BIGNUM_TAG: {
    auto bn = (bn_t *)header;
    return heap_align(sizeof(bn_t) + (size_t)bn->alloc * sizeof(uint64_t));
  }
  case RATNUM_TAG:
    return sizeof(ratnum_s);
  case COMPNUM_TAG:
    return sizeof(compnum_s);
  case STRING_TAG: {
    auto str = (string_s *)header;
    return heap_align(sizeof(string_s) + (size_t)to_fixnum(str->len) + 1);
  }
  case SYMBOL_TAG:
    return sizeof(symbol);
  case BOX_TAG:
    return sizeof(gc_obj);
  case VECTOR_TAG:
  case CONT_TAG:
  case RECORD_TAG: {
    auto vec = (vector_s *)header;
    return heap_align(sizeof(vector_s) +
                      (size_t)to_fixnum(vec->len) * sizeof(gc_obj));
  }
  case CONS_TAG:
    return sizeof(cons_s);
  case CLOSURE_TAG: {
    auto clo = (closure_s *)header;
    return heap_align(sizeof(closure_s) +
                      (size_t)to_fixnum(clo->len) * sizeof(gc_obj));
  }
  case FUNC_TAG: {
    auto func = (bcfunc *)header;
    return heap_align(sizeof(bcfunc) + (func->const_cnt * sizeof(gc_obj)) +
                      (func->bc_cnt * sizeof(bc)));
  }
  default:
    return heap_object_size(header);
  }
}

static uint64_t header_index(gc_header *header) {
  auto *entry = hm_getp_null(header_to_idx, header);
  if (!entry) {
    return UINT64_MAX;
  }
  return entry->value;
}

static bool symbol_has_name(symbol *sym, const char *want) {
  auto name = get_sym_name(sym);
  return name && strcmp(name->str, want) == 0;
}

static bool gc_obj_is_symbol_named(gc_obj obj, char const *want) {
  return is_symbol(obj) && symbol_has_name(to_symbol(obj), want);
}

typedef struct {
  seen_entry *seen;
  gc_header **worklist;
} collect_ctx;

static void collect_trace_cb(gc_obj *slot, void *ctx) {
  auto c = (collect_ctx *)ctx;
  if (!is_heap_object(*slot)) {
    return;
  }
  auto header = to_gc_header(*slot);
  if (hm_contains(c->seen, header)) {
    return;
  }
  hm_put(c->seen, header, true);
  arrput(c->worklist, header);
}

static symbol *collect_objects(gc_obj start) {
  auto worklist = (gc_header **)nullptr;
  auto seen = (seen_entry *)nullptr;
  symbol *symbol_table = nullptr;

  if (is_heap_object(start)) {
    auto header = to_gc_header(start);
    hm_put(seen, header, true);
    arrput(worklist, header);
  }

  while (arrlen(worklist) > 0) {
    gc_header *header = arrpop_last(worklist);
    arrput(obj_list, header);

    if (header->type == SYMBOL_TAG && !symbol_table) {
      auto sym = (symbol *)header;
      if (symbol_has_name(sym, "symbol-table")) {
        symbol_table = sym;
      }
    }

    collect_ctx ctx = {.seen = seen, .worklist = worklist};
    trace_heap_object(header, collect_trace_cb, &ctx);
    seen = ctx.seen;
    worklist = ctx.worklist;
  }

  arrfree(worklist);
  hm_free(seen);
  return symbol_table;
}

typedef struct {
  obj_node *node;
  symbol *symbol_table;
} edge_ctx;

static void build_edges_trace_cb(gc_obj *slot, void *ctx) {
  auto ectx = (edge_ctx *)ctx;
  if (!is_heap_object(*slot)) {
    return;
  }
  if (ectx->node->header == (gc_header *)ectx->symbol_table &&
      slot == &ectx->symbol_table->val) {
    return;
  }
  auto child = to_gc_header(*slot);
  if (hm_contains(header_to_idx, child)) {
    arrput(ectx->node->edges, child);
  }
}

static void build_graph(symbol *symbol_table) {
  for (uint64_t i = 0; i < arrlen(obj_list); i++) {
    hm_put(header_to_idx, obj_list[i], i);
    arrput(obj_nodes, ((obj_node){.header = obj_list[i], .edges = nullptr}));
  }

  for (uint64_t i = 0; i < arrlen(obj_nodes); i++) {
    edge_ctx ctx = {.node = &obj_nodes[i], .symbol_table = symbol_table};
    trace_heap_object(obj_nodes[i].header, build_edges_trace_cb, &ctx);
  }
}

static void collect_child_trace_cb(gc_obj *slot, void *ctx) {
  auto cctx = (child_list_ctx *)ctx;
  if (!is_heap_object(*slot)) {
    return;
  }
  auto child = to_gc_header(*slot);
  if (child && header_index(child) != UINT64_MAX) {
    arrput(cctx->children, child);
  }
}

static gc_header **collect_immediate_children(gc_header *header) {
  child_list_ctx ctx = {.children = nullptr};
  trace_heap_object(header, collect_child_trace_cb, &ctx);
  return ctx.children;
}

static bool supported_header(gc_header *header) {
  if (!header) {
    return false;
  }
  if ((header->type & PORT_IDENTITY) == PORT_IDENTITY) {
    return true;
  }
  switch (header->type) {
  case FLONUM_TAG:
  case BIGNUM_TAG:
  case RATNUM_TAG:
  case COMPNUM_TAG:
  case STRING_TAG:
  case SYMBOL_TAG:
  case BOX_TAG:
  case PORT_TAG:
  case FLVECTOR_TAG:
  case VECTOR_TAG:
  case CONT_TAG:
  case RECORD_TAG:
  case CONS_TAG:
  case CLOSURE_TAG:
  case FUNC_TAG:
    return true;
  default:
    return false;
  }
}

static bool descend_into_header(gc_header *header) {
  if (!supported_header(header)) {
    return false;
  }
  switch (header->type) {
  case FUNC_TAG:
    return false;
  default:
    return true;
  }
}

typedef struct {
  int64_t index;
  int64_t lowlink;
  bool on_stack;
} tarjan_info;

static tarjan_info *t_info;
static uint64_t *tarjan_stack;
static int64_t tarjan_sp;

static void tarjan_strongconnect(uint64_t v) {
  t_info[v].index = tarjan_sp;
  t_info[v].lowlink = tarjan_sp;
  t_info[v].on_stack = true;
  tarjan_stack[tarjan_sp++] = v;

  auto node = &obj_nodes[v];
  for (uint64_t i = 0; i < arrlen(node->edges); i++) {
    uint64_t w = header_index(node->edges[i]);
    if (w == UINT64_MAX) {
      continue;
    }
    if (t_info[w].index < 0) {
      tarjan_strongconnect(w);
      if (t_info[w].lowlink < t_info[v].lowlink) {
        t_info[v].lowlink = t_info[w].lowlink;
      }
    } else if (t_info[w].on_stack) {
      if (t_info[w].index < t_info[v].lowlink) {
        t_info[v].lowlink = t_info[w].index;
      }
    }
  }

  if (t_info[v].lowlink == t_info[v].index) {
    uint64_t scc_id = scc_count++;
    uint64_t total = 0;
    uint64_t w;
    do {
      w = tarjan_stack[--tarjan_sp];
      t_info[w].on_stack = false;
      obj_scc[w] = scc_id;
      total += object_size(obj_nodes[w].header);
    } while (w != v);
    scc_size[scc_id] = total;
  }
}

static void run_tarjan(void) {
  uint64_t n = arrlen(obj_nodes);
  t_info = calloc(n, sizeof(tarjan_info));
  tarjan_stack = calloc(n, sizeof(uint64_t));
  obj_scc = calloc(n, sizeof(uint64_t));
  scc_size = calloc(n, sizeof(uint64_t));
  for (uint64_t i = 0; i < n; i++) {
    t_info[i].index = -1;
  }
  for (uint64_t i = 0; i < n; i++) {
    if (t_info[i].index < 0) {
      tarjan_strongconnect(i);
    }
  }
  free(t_info);
  free(tarjan_stack);
}

static dag build_scc_dag(void) {
  dag g = {.succ = calloc(scc_count, sizeof(uint64_t *)),
           .pred = calloc(scc_count, sizeof(uint64_t *))};
  for (uint64_t i = 0; i < arrlen(obj_nodes); i++) {
    uint64_t from = obj_scc[i];
    for (uint64_t j = 0; j < arrlen(obj_nodes[i].edges); j++) {
      uint64_t to_idx = header_index(obj_nodes[i].edges[j]);
      if (to_idx == UINT64_MAX) {
        continue;
      }
      uint64_t to = obj_scc[to_idx];
      if (to == from) {
        continue;
      }
      bool exists = false;
      for (uint64_t k = 0; k < arrlen(g.succ[from]); k++) {
        if (g.succ[from][k] == to) {
          exists = true;
          break;
        }
      }
      if (!exists) {
        arrput(g.succ[from], to);
        arrput(g.pred[to], from);
      }
    }
  }
  return g;
}

static void dag_dfs_post(uint64_t node, uint64_t **succ, uint8_t *vis,
                         uint64_t **post) {
  if (vis[node]) {
    return;
  }
  vis[node] = 1;
  for (uint64_t i = 0; i < arrlen(succ[node]); i++) {
    dag_dfs_post(succ[node][i], succ, vis, post);
  }
  arrput(*post, node);
}

static void compute_symbol_retained_sizes(uint64_t start_scc,
                                          uint64_t val_root_scc,
                                          bool has_val_root, dag g) {
  uint64_t super = scc_count;
  uint64_t dom_nodes = scc_count + 1;
  uint64_t words = (dom_nodes + 63) / 64;

  uint64_t **dom_succ = calloc(dom_nodes, sizeof(uint64_t *));
  for (uint64_t i = 0; i < scc_count; i++) {
    dom_succ[i] = g.succ[i];
  }
  arrput(dom_succ[super], start_scc);
  if (has_val_root && val_root_scc != start_scc) {
    arrput(dom_succ[super], val_root_scc);
  }

  uint8_t *vis = calloc(dom_nodes, sizeof(uint8_t));
  uint64_t *post = (uint64_t *)nullptr;
  dag_dfs_post(super, dom_succ, vis, &post);

  uint8_t *reachable = calloc(dom_nodes, sizeof(uint8_t));
  uint64_t *topo = (uint64_t *)nullptr;
  for (int64_t i = (int64_t)arrlen(post) - 1; i >= 0; i--) {
    arrput(topo, post[i]);
    reachable[post[i]] = 1;
  }
  arrfree(post);

  uint8_t *root_scc = calloc(scc_count, sizeof(uint8_t));
  root_scc[start_scc] = 1;
  if (has_val_root) {
    root_scc[val_root_scc] = 1;
  }

  uint64_t **dom = calloc(dom_nodes, sizeof(uint64_t *));
  for (uint64_t n = 0; n < dom_nodes; n++) {
    dom[n] = calloc(words, sizeof(uint64_t));
  }

  uint64_t *all_reachable = calloc(words, sizeof(uint64_t));
  for (uint64_t n = 0; n < dom_nodes; n++) {
    if (reachable[n]) {
      all_reachable[n / 64] |= (1ULL << (n % 64));
    }
  }

  dom[super][super / 64] |= (1ULL << (super % 64));
  for (uint64_t n = 0; n < scc_count; n++) {
    if (!reachable[n]) {
      continue;
    }
    for (uint64_t w = 0; w < words; w++) {
      dom[n][w] = all_reachable[w];
    }
  }

  bool changed = true;
  while (changed) {
    changed = false;
    for (uint64_t ti = 1; ti < arrlen(topo); ti++) {
      uint64_t n = topo[ti];
      if (n >= scc_count) {
        continue;
      }
      uint64_t new_bits[words];
      bool have_pred = false;
      for (uint64_t w = 0; w < words; w++) {
        new_bits[w] = 0;
      }

      if (root_scc[n]) {
        for (uint64_t w = 0; w < words; w++) {
          new_bits[w] = dom[super][w];
        }
        have_pred = true;
      }

      for (uint64_t i = 0; i < arrlen(g.pred[n]); i++) {
        uint64_t p = g.pred[n][i];
        if (!reachable[p]) {
          continue;
        }
        if (!have_pred) {
          for (uint64_t w = 0; w < words; w++) {
            new_bits[w] = dom[p][w];
          }
          have_pred = true;
        } else {
          for (uint64_t w = 0; w < words; w++) {
            new_bits[w] &= dom[p][w];
          }
        }
      }

      if (!have_pred) {
        for (uint64_t w = 0; w < words; w++) {
          new_bits[w] = 0;
        }
      }

      new_bits[n / 64] |= (1ULL << (n % 64));

      bool diff = false;
      for (uint64_t w = 0; w < words; w++) {
        if (dom[n][w] != new_bits[w]) {
          diff = true;
          dom[n][w] = new_bits[w];
        }
      }
      if (diff) {
        changed = true;
      }
    }
  }

  scc_retained_bytes = calloc(scc_count, sizeof(uint64_t));
  scc_reachable = calloc(scc_count, sizeof(uint64_t));
  for (uint64_t n = 0; n < scc_count; n++) {
    if (!reachable[n]) {
      continue;
    }
    scc_reachable[n] = 1;
    for (uint64_t d = 0; d < scc_count; d++) {
      if (dom[n][d / 64] & (1ULL << (d % 64))) {
        scc_retained_bytes[d] += scc_size[n];
      }
    }
  }

  free(all_reachable);
  arrfree(topo);
  free(reachable);
  free(root_scc);
  for (uint64_t n = 0; n < dom_nodes; n++) {
    free(dom[n]);
  }
  free(dom);
  arrfree(dom_succ[super]);
  free(dom_succ);
}

static int compare_symbol_scores(const void *a, const void *b) {
  auto sa = (const symbol_score *)a;
  auto sb = (const symbol_score *)b;
  if (sa->retained_bytes < sb->retained_bytes) {
    return 1;
  }
  if (sa->retained_bytes > sb->retained_bytes) {
    return -1;
  }
  return strcmp(sa->name, sb->name);
}

static char const *object_type_name(gc_header *header) {
  if ((header->type & PORT_IDENTITY) == PORT_IDENTITY) {
    return "port";
  }
  switch (header->type) {
  case FLONUM_TAG:
    return "flonum";
  case BIGNUM_TAG:
    return "bignum";
  case RATNUM_TAG:
    return "ratnum";
  case COMPNUM_TAG:
    return "compnum";
  case STRING_TAG:
    return "string";
  case SYMBOL_TAG:
    return "symbol";
  case BOX_TAG:
    return "box";
  case VECTOR_TAG:
    return "vector";
  case FLVECTOR_TAG:
    return "flvector";
  case PORT_TAG:
    return "port";
  case CONT_TAG:
    return "cont";
  case RECORD_TAG:
    return "record";
  case CONS_TAG:
    return "cons";
  case CLOSURE_TAG:
    return "closure";
  case FUNC_TAG:
    return "func";
  default:
    return "other";
  }
}

static bool is_nil_obj(gc_obj obj) { return get_imm_tag(obj) == NIL_TAG; }

static void describe_gc_obj_depth(gc_obj obj, char *buf, size_t buf_size,
                                  int depth);
static void describe_gc_obj(gc_obj obj, char *buf, size_t buf_size) {
  describe_gc_obj_depth(obj, buf, buf_size, 2);
}

static bool list_length_bounded(gc_obj obj, uint64_t limit, uint64_t *len_out,
                                gc_obj *tail_out) {
  uint64_t len = 0;
  gc_obj cur = obj;
  while (is_cons(cur) && len < limit) {
    len++;
    cur = to_cons(cur)->b;
  }
  *len_out = len;
  *tail_out = cur;
  return is_nil_obj(cur);
}

static bool describe_small_list(gc_obj obj, char *buf, size_t buf_size) {
  uint64_t len = 0;
  gc_obj tail = NIL;
  if (!list_length_bounded(obj, 5, &len, &tail) || len == 0 || len > 4) {
    return false;
  }

  size_t off = 0;
  off += snprintf(buf + off, buf_size - off, "(");
  gc_obj cur = obj;
  for (uint64_t i = 0; i < len && is_cons(cur) && off + 1 < buf_size; i++) {
    if (i > 0) {
      off += snprintf(buf + off, buf_size - off, " ");
    }
    auto cell = to_cons(cur);
    char item[64];
    if (is_symbol(cell->a)) {
      auto sym = to_symbol(cell->a);
      auto name = get_sym_name(sym);
      snprintf(item, sizeof(item), "%s", name ? name->str : "(unnamed)");
    } else if (is_string(cell->a)) {
      auto str = to_string(cell->a);
      snprintf(item, sizeof(item), "\"%.*s\"",
               (int)((to_fixnum(str->len) > 16) ? 16 : to_fixnum(str->len)),
               str->str);
    } else if (is_fixnum(cell->a)) {
      snprintf(item, sizeof(item), "%ld", to_fixnum(cell->a));
    } else {
      return false;
    }
    off += snprintf(buf + off, buf_size - off, "%s", item);
    cur = cell->b;
  }
  snprintf(buf + off, buf_size - off, ")");
  return true;
}

static void describe_header_depth(gc_header *header, char *buf, size_t buf_size,
                                  int depth) {
  if ((header->type & PORT_IDENTITY) == PORT_IDENTITY) {
    auto p = (port_s *)header;
    snprintf(buf, buf_size, "port fd=%ld pos=%ld len=%ld", to_fixnum(p->fd),
             to_fixnum(p->pos), to_fixnum(p->len));
    return;
  }
  switch (header->type) {
  case STRING_TAG: {
    auto str = (string_s *)header;
    snprintf(buf, buf_size, "string len=%ld \"%.*s\"", to_fixnum(str->len),
             (int)((to_fixnum(str->len) > 24) ? 24 : to_fixnum(str->len)),
             str->str);
    return;
  }
  case SYMBOL_TAG: {
    auto sym = (symbol *)header;
    auto name = get_sym_name(sym);
    snprintf(buf, buf_size, "symbol %s", name ? name->str : "(unnamed)");
    return;
  }
  case VECTOR_TAG: {
    auto vec = (vector_s *)header;
    snprintf(buf, buf_size, "vector len=%ld", to_fixnum(vec->len));
    return;
  }
  case FLVECTOR_TAG: {
    auto vec = (flvector_s *)header;
    snprintf(buf, buf_size, "flvector len=%ld", to_fixnum(vec->len));
    return;
  }
  case PORT_TAG: {
    auto p = (port_s *)header;
    snprintf(buf, buf_size, "port fd=%ld pos=%ld len=%ld", to_fixnum(p->fd),
             to_fixnum(p->pos), to_fixnum(p->len));
    return;
  }
  case RECORD_TAG: {
    auto vec = (vector_s *)header;
    if (depth > 0 && to_fixnum(vec->len) > 0 && to_fixnum(vec->len) <= 5) {
      char fields[160];
      size_t off = 0;
      off += snprintf(fields + off, sizeof(fields) - off, "[");
      for (int64_t i = 0; i < to_fixnum(vec->len) && off + 1 < sizeof(fields);
           i++) {
        if (i > 0) {
          off += snprintf(fields + off, sizeof(fields) - off, ", ");
        }
        char item[48];
        describe_gc_obj_depth(vec->v[i], item, sizeof(item), depth - 1);
        off += snprintf(fields + off, sizeof(fields) - off, "%s", item);
      }
      snprintf(fields + off, sizeof(fields) - off, "]");
      snprintf(buf, buf_size, "record len=%ld %s", to_fixnum(vec->len), fields);
    } else {
      snprintf(buf, buf_size, "record len=%ld", to_fixnum(vec->len));
    }
    return;
  }
  case CONS_TAG: {
    auto cons = (cons_s *)header;
    uint64_t len = 0;
    gc_obj cur = NIL;
    bool proper = list_length_bounded(tag_cons(cons), 32, &len, &cur);
    if (proper) {
      snprintf(buf, buf_size, "cons proper-list len=%lu", len);
    } else if (is_cons(cur)) {
      snprintf(buf, buf_size, "cons list-prefix=%lu+", len);
    } else {
      char tail[96];
      describe_gc_obj_depth(cur, tail, sizeof(tail), depth - 1);
      snprintf(buf, buf_size, "cons dotted len=%lu tail=%s", len, tail);
    }
    return;
  }
  case CLOSURE_TAG: {
    auto clo = (closure_s *)header;
    snprintf(buf, buf_size, "closure slots=%ld", to_fixnum(clo->len));
    return;
  }
  case FUNC_TAG: {
    auto func = (bcfunc *)header;
    char name[96];
    describe_gc_obj_depth(func->name, name, sizeof(name), depth - 1);
    snprintf(buf, buf_size, "func consts=%lu bc=%lu name=%s", func->const_cnt,
             func->bc_cnt, name);
    return;
  }
  case BOX_TAG: {
    snprintf(buf, buf_size, "box");
    return;
  }
  case FLONUM_TAG: {
    auto fl = (flonum_s *)header;
    snprintf(buf, buf_size, "flonum %.17g", fl->x);
    return;
  }
  default:
    snprintf(buf, buf_size, "%s", object_type_name(header));
    return;
  }
}

static void describe_gc_obj_depth(gc_obj obj, char *buf, size_t buf_size,
                                  int depth) {
  if (depth < 0) {
    snprintf(buf, buf_size, "...");
    return;
  }
  if (is_fixnum(obj)) {
    snprintf(buf, buf_size, "fixnum %ld", to_fixnum(obj));
    return;
  }
  if (is_bool(obj)) {
    snprintf(buf, buf_size, "%s", obj.value == TRUE_REP.value ? "#t" : "#f");
    return;
  }
  if (is_nil_obj(obj)) {
    snprintf(buf, buf_size, "()");
    return;
  }
  if (is_char(obj)) {
    snprintf(buf, buf_size, "#\\%c", to_char(obj));
    return;
  }
  if (is_undefined(obj)) {
    snprintf(buf, buf_size, "#<undefined>");
    return;
  }
  if (!is_heap_object(obj)) {
    snprintf(buf, buf_size, "#<imm 0x%lx>", (unsigned long)obj.value);
    return;
  }
  if (depth > 0 && is_cons(obj) && describe_small_list(obj, buf, buf_size)) {
    return;
  }
  describe_header_depth(to_gc_header(obj), buf, buf_size, depth);
}

static int compare_object_scores(const void *a, const void *b) {
  auto oa = (const object_score *)a;
  auto ob = (const object_score *)b;
  if (oa->size < ob->size) {
    return 1;
  }
  if (oa->size > ob->size) {
    return -1;
  }
  if (oa->idx < ob->idx) {
    return -1;
  }
  if (oa->idx > ob->idx) {
    return 1;
  }
  return 0;
}

static void count_name(name_count **counts, char const *name) {
  for (uint64_t i = 0; i < arrlen(*counts); i++) {
    if (strcmp((*counts)[i].name, name) == 0) {
      (*counts)[i].count++;
      return;
    }
  }
  auto copy = strdup(name);
  if (!copy) {
    fprintf(stderr, "out of memory\n");
    exit(EXIT_FAILURE);
  }
  arrput(*counts, ((name_count){.name = copy, .count = 1}));
}

static int compare_name_counts(const void *a, const void *b) {
  auto na = (const name_count *)a;
  auto nb = (const name_count *)b;
  if (na->count < nb->count) {
    return 1;
  }
  if (na->count > nb->count) {
    return -1;
  }
  return strcmp(na->name, nb->name);
}

static bool is_named_vector(gc_obj obj, char const *name) {
  if (!is_vector(obj)) {
    return false;
  }
  auto vec = to_vector(obj);
  return to_fixnum(vec->len) > 0 && gc_obj_is_symbol_named(vec->v[0], name);
}

static bool is_rib_obj(gc_obj obj) {
  return is_cons(obj) && gc_obj_is_symbol_named(to_cons(obj)->a, "rib");
}

static bool is_wrap_like_obj(gc_obj obj) {
  if (!is_cons(obj)) {
    return false;
  }
  uint64_t len = 0;
  gc_obj tail = NIL;
  if (!list_length_bounded(obj, 32, &len, &tail)) {
    return false;
  }
  if (len == 0) {
    return false;
  }
  gc_obj cur = obj;
  uint64_t rib_count = 0;
  while (is_cons(cur)) {
    auto item = to_cons(cur)->a;
    if (is_rib_obj(item)) {
      rib_count++;
    } else if (!is_symbol(item) && !is_nil_obj(item) && !is_bool(item)) {
      return false;
    }
    cur = to_cons(cur)->b;
  }
  return rib_count > 0;
}

static gc_header *find_descendant_header(gc_header *root, bool (*pred)(gc_obj),
                                         int depth) {
  if (depth < 0 || !supported_header(root)) {
    return nullptr;
  }
  gc_obj root_obj = tag_header(root, root->type);
  if (pred(root_obj)) {
    return root;
  }
  if (!descend_into_header(root)) {
    return nullptr;
  }
  auto children = collect_immediate_children(root);
  for (uint64_t i = 0; i < arrlen(children); i++) {
    auto found = find_descendant_header(children[i], pred, depth - 1);
    if (found) {
      arrfree(children);
      return found;
    }
  }
  arrfree(children);
  return nullptr;
}

static char const *binding_type_name(gc_obj binding_type) {
  if (!is_symbol(binding_type)) {
    return "(non-symbol)";
  }
  auto name = get_sym_name(to_symbol(binding_type));
  return name ? name->str : "(unnamed)";
}

static char const *binding_library_name(gc_obj binding) {
  if (!is_named_vector(binding, "binding")) {
    return "#f";
  }
  auto vec = to_vector(binding);
  gc_obj lib = vec->v[5];
  if (is_nil_obj(lib)) {
    return "()";
  }
  if (is_bool(lib) && lib.value == FALSE_REP.value) {
    return "#f";
  }
  static char buf[128];
  if (describe_small_list(lib, buf, sizeof(buf))) {
    return buf;
  }
  if (is_symbol(lib)) {
    auto name = get_sym_name(to_symbol(lib));
    return name ? name->str : "(unnamed)";
  }
  return "(other)";
}

static void print_rib_analysis(gc_obj rib_obj) {
  if (!is_rib_obj(rib_obj)) {
    return;
  }
  uint64_t subst_count = 0;
  uint64_t binding_count = 0;
  uint64_t global_count = 0;
  name_count *binding_types = nullptr;
  name_count *binding_libs = nullptr;

  printf("  rib analysis:\n");
  gc_obj cur = to_cons(rib_obj)->b;
  while (is_cons(cur)) {
    subst_count++;
    gc_obj subst = to_cons(cur)->a;
    if (is_named_vector(subst, "subst")) {
      auto subst_vec = to_vector(subst);
      gc_obj binding = subst_vec->v[3];
      if (is_named_vector(binding, "binding")) {
        binding_count++;
        auto binding_vec = to_vector(binding);
        count_name(&binding_types, binding_type_name(binding_vec->v[1]));
        count_name(&binding_libs, binding_library_name(binding));
        if (is_bool(binding_vec->v[6]) &&
            binding_vec->v[6].value == TRUE_REP.value) {
          global_count++;
        }
      }
    }
    cur = to_cons(cur)->b;
  }

  printf("    substitutions: %lu\n", subst_count);
  printf("    bindings: %lu\n", binding_count);
  printf("    globals: %lu\n", global_count);

  qsort(binding_types, arrlen(binding_types), sizeof(name_count),
        compare_name_counts);
  printf("    binding types:\n");
  for (uint64_t i = 0; i < arrlen(binding_types); i++) {
    printf("      %s: %lu\n", binding_types[i].name, binding_types[i].count);
  }

  qsort(binding_libs, arrlen(binding_libs), sizeof(name_count),
        compare_name_counts);
  printf("    binding libraries:\n");
  uint64_t limit = arrlen(binding_libs) < 12 ? arrlen(binding_libs) : 12;
  for (uint64_t i = 0; i < limit; i++) {
    printf("      %s: %lu\n", binding_libs[i].name, binding_libs[i].count);
  }

  for (uint64_t i = 0; i < arrlen(binding_types); i++) {
    free((void *)binding_types[i].name);
  }
  for (uint64_t i = 0; i < arrlen(binding_libs); i++) {
    free((void *)binding_libs[i].name);
  }
  arrfree(binding_types);
  arrfree(binding_libs);
}

static void print_wrap_analysis(gc_obj wrap_obj) {
  if (!is_wrap_like_obj(wrap_obj)) {
    return;
  }
  uint64_t len = 0;
  gc_obj tail = NIL;
  uint64_t rib_count = 0;
  uint64_t mark_count = 0;
  uint64_t antimark_count = 0;
  uint64_t other_count = 0;
  list_length_bounded(wrap_obj, UINT64_MAX, &len, &tail);

  printf("  wrap analysis:\n");
  printf("    items: %lu\n", len);
  gc_obj cur = wrap_obj;
  while (is_cons(cur)) {
    auto item = to_cons(cur)->a;
    if (is_rib_obj(item)) {
      rib_count++;
    } else if (is_symbol(item)) {
      mark_count++;
    } else if (is_bool(item) && item.value == FALSE_REP.value) {
      antimark_count++;
    } else {
      other_count++;
    }
    cur = to_cons(cur)->b;
  }
  printf("    ribs: %lu\n", rib_count);
  printf("    marks: %lu\n", mark_count);
  printf("    antimarks: %lu\n", antimark_count);
  printf("    other: %lu\n", other_count);
}

static void print_object_children(gc_obj obj, int depth, int max_depth,
                                  uint64_t indent) {
  if (!is_heap_object(obj) || depth > max_depth) {
    return;
  }
  auto children = collect_immediate_children(to_gc_header(obj));
  if (arrlen(children) == 0) {
    arrfree(children);
    return;
  }
  for (uint64_t i = 0; i < arrlen(children); i++) {
    char desc[160];
    if (!supported_header(children[i])) {
      continue;
    }
    gc_obj child = tag_header(children[i], children[i]->type);
    describe_header_depth(children[i], desc, sizeof(desc), 2);
    printf("%*schild[%lu]: %s\n", (int)indent, "", i, desc);
    if (descend_into_header(children[i])) {
      print_object_children(child, depth + 1, max_depth, indent + 2);
    }
  }
  arrfree(children);
}

static void print_focus_analysis(char const *name, gc_obj value) {
  if (strncmp(name, "*global-rib*", 12) == 0 ||
      strncmp(name, "*global-wrap*", 13) == 0) {
    printf("  immediate children:\n");
    print_object_children(value, 0, 2, 4);

    auto *rib_header =
        find_descendant_header(to_gc_header(value), is_rib_obj, 4);
    if (rib_header) {
      gc_obj rib = tag_header(rib_header, rib_header->type);
      char desc[160];
      describe_gc_obj_depth(rib, desc, sizeof(desc), 2);
      printf("  found rib: %s\n", desc);
      print_rib_analysis(rib);
    }

    auto *wrap_header =
        find_descendant_header(to_gc_header(value), is_wrap_like_obj, 4);
    if (wrap_header) {
      gc_obj wrap = tag_header(wrap_header, wrap_header->type);
      char desc[160];
      describe_gc_obj_depth(wrap, desc, sizeof(desc), 2);
      printf("  found wrap: %s\n", desc);
      print_wrap_analysis(wrap);
    }
  }
}

static void print_list_preview(gc_obj obj, uint64_t limit) {
  uint64_t len = 0;
  gc_obj tail = NIL;
  bool proper = list_length_bounded(obj, limit + 1, &len, &tail);
  if (!proper && !is_cons(tail)) {
    return;
  }

  printf("  value items:\n");
  gc_obj cur = obj;
  for (uint64_t i = 0; i < limit && is_cons(cur); i++) {
    auto cell = to_cons(cur);
    char item_desc[160];
    if (is_cons(cell->a)) {
      auto entry = to_cons(cell->a);
      char car_desc[80];
      char cdr_desc[80];
      describe_gc_obj(entry->a, car_desc, sizeof(car_desc));
      describe_gc_obj(entry->b, cdr_desc, sizeof(cdr_desc));
      snprintf(item_desc, sizeof(item_desc), "pair car=%s cdr=%s", car_desc,
               cdr_desc);
    } else {
      describe_gc_obj(cell->a, item_desc, sizeof(item_desc));
    }
    printf("    [%lu] %s\n", i, item_desc);
    cur = cell->b;
  }
  if (is_cons(cur)) {
    printf("    ...\n");
  }
}

static symbol *find_symbol_by_name(char const *name) {
  for (uint64_t i = 0; i < arrlen(obj_list); i++) {
    auto header = obj_list[i];
    if (header->type != SYMBOL_TAG) {
      continue;
    }
    auto sym = (symbol *)header;
    if (symbol_has_name(sym, name)) {
      return sym;
    }
  }
  return nullptr;
}

static void print_symbol_report(char const *name) {
  auto sym = find_symbol_by_name(name);
  if (!sym) {
    printf("\n[symbol report] %s: not found\n", name);
    return;
  }
  if (!is_heap_object(sym->val)) {
    printf("\n[symbol report] %s: value is immediate\n", name);
    return;
  }

  uint64_t val_idx = header_index(to_gc_header(sym->val));
  if (val_idx == UINT64_MAX) {
    printf("\n[symbol report] %s: value missing from graph\n", name);
    return;
  }

  uint64_t scc = obj_scc[val_idx];
  uint64_t obj_count = 0;
  printf("\n[symbol report] %s\n", name);
  printf("  scc: %lu\n", scc);
  printf("  scc bytes: %lu\n", scc_size[scc]);
  printf("  retained bytes: %lu\n", scc_retained_bytes[scc]);
  {
    char value_desc[160];
    describe_gc_obj(sym->val, value_desc, sizeof(value_desc));
    printf("  value: %s\n", value_desc);
  }
  print_focus_analysis(name, sym->val);
  print_list_preview(sym->val, 8);

  printf("  member symbols:\n");
  for (uint64_t i = 0; i < arrlen(obj_list); i++) {
    if (obj_scc[i] != scc) {
      continue;
    }
    obj_count++;
    auto header = obj_list[i];
    if (header->type == SYMBOL_TAG) {
      auto member = (symbol *)header;
      auto member_name = get_sym_name(member);
      printf("    %s\n", member_name ? member_name->str : "(unnamed)");
    }
  }
  printf("  object count: %lu\n", obj_count);

  printf("  object types:\n");
  uint64_t type_counts[16] = {0};
  for (uint64_t i = 0; i < arrlen(obj_list); i++) {
    if (obj_scc[i] != scc) {
      continue;
    }
    uint8_t type = obj_list[i]->type;
    if (type < 16) {
      type_counts[type]++;
    }
  }
  for (uint8_t type = 0; type < 16; type++) {
    if (type_counts[type] == 0) {
      continue;
    }
    gc_header header = {.type = type};
    printf("    %s: %lu\n", object_type_name(&header), type_counts[type]);
  }

  printf("  member symbol values:\n");
  for (uint64_t i = 0; i < arrlen(obj_list); i++) {
    if (obj_scc[i] != scc || obj_list[i]->type != SYMBOL_TAG) {
      continue;
    }
    auto member = (symbol *)obj_list[i];
    auto member_name = get_sym_name(member);
    char value_desc[160];
    describe_gc_obj(member->val, value_desc, sizeof(value_desc));
    printf("    %s -> %s\n", member_name ? member_name->str : "(unnamed)",
           value_desc);
  }

  auto largest = (object_score *)nullptr;
  for (uint64_t i = 0; i < arrlen(obj_list); i++) {
    if (obj_scc[i] != scc) {
      continue;
    }
    arrput(largest,
           ((object_score){.idx = i, .size = object_size(obj_list[i])}));
  }
  qsort(largest, arrlen(largest), sizeof(object_score), compare_object_scores);

  printf("  largest objects:\n");
  uint64_t limit = arrlen(largest) < 12 ? arrlen(largest) : 12;
  for (uint64_t i = 0; i < limit; i++) {
    char desc[160];
    describe_header_depth(obj_list[largest[i].idx], desc, sizeof(desc), 1);
    printf("    %2lu  %8lu  %s\n", i + 1, largest[i].size, desc);
  }
  arrfree(largest);
}

static explorer_options parse_options(int argc, char **argv) {
  explorer_options opts = {0};
  if (argc == 2) {
    opts.image_path = argv[1];
    return opts;
  }
  if (argc == 4 && strcmp(argv[1], "--symbol") == 0) {
    opts.symbol_name = argv[2];
    opts.image_path = argv[3];
    return opts;
  }
  fprintf(stderr, "usage: %s [--symbol NAME] <image.bc>\n", argv[0]);
  exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
  explorer_options opts = parse_options(argc, argv);

  gc_init();
  gc_obj start = gc_read_image_file((char *)opts.image_path);
  if (!is_heap_object(start)) {
    fprintf(stderr, "start is not a heap object\n");
    gc_free();
    return EXIT_FAILURE;
  }

  fprintf(stderr, "Collecting reachable objects from start...\n");
  auto symbol_table = collect_objects(start);
  if (!symbol_table) {
    fprintf(stderr, "symbol-table symbol not found\n");
    gc_free();
    return EXIT_FAILURE;
  }
  fprintf(stderr, "Found %zu objects\n", arrlen(obj_list));

  auto symbol_table_val = symbol_table->val;
  bool has_val_root = is_heap_object(symbol_table_val);

  fprintf(stderr, "Building graph with symbol-table.val detached...\n");
  build_graph(symbol_table);

  fprintf(stderr, "Running Tarjan SCC...\n");
  run_tarjan();
  fprintf(stderr, "Found %lu SCCs\n", scc_count);

  uint64_t start_idx = header_index(to_gc_header(start));
  if (start_idx == UINT64_MAX) {
    fprintf(stderr, "start object missing from graph\n");
    gc_free();
    return EXIT_FAILURE;
  }
  uint64_t start_scc = obj_scc[start_idx];

  uint64_t val_root_scc = start_scc;
  if (has_val_root) {
    uint64_t val_idx = header_index(to_gc_header(symbol_table_val));
    if (val_idx != UINT64_MAX) {
      val_root_scc = obj_scc[val_idx];
    } else {
      has_val_root = false;
    }
  }

  auto g = build_scc_dag();
  fprintf(stderr, "Computing dominators and retained sizes...\n");
  compute_symbol_retained_sizes(start_scc, val_root_scc, has_val_root, g);

  auto scores = (symbol_score *)nullptr;
  for (uint64_t i = 0; i < arrlen(obj_list); i++) {
    auto h = obj_list[i];
    if (h->type != SYMBOL_TAG) {
      continue;
    }
    auto sym = (symbol *)h;
    auto sym_name = get_sym_name(sym);
    auto name = sym_name ? sym_name->str : "(unnamed)";
    uint64_t retained = 0;

    if (sym != symbol_table && is_heap_object(sym->val)) {
      uint64_t val_idx = header_index(to_gc_header(sym->val));
      if (val_idx != UINT64_MAX) {
        uint64_t val_scc = obj_scc[val_idx];
        if (scc_reachable[val_scc]) {
          retained = scc_retained_bytes[val_scc];
        }
      }
    }

    arrput(scores, ((symbol_score){
                       .sym = sym,
                       .name = name,
                       .retained_bytes = retained,
                   }));
  }

  qsort(scores, arrlen(scores), sizeof(symbol_score), compare_symbol_scores);

  if (opts.symbol_name) {
    print_symbol_report(opts.symbol_name);
  } else {
    printf("# symbols: %zu\n", arrlen(scores));
    printf("# roots: start%s\n", has_val_root ? ", symbol-table.val" : "");
    printf("# note: symbol-table.val edge is treated as detached (#f)\n");
    for (uint64_t i = 0; i < arrlen(scores); i++) {
      if (scores[i].retained_bytes > 0) {
        printf("%4lu  %12lu  %s\n", i + 1, scores[i].retained_bytes,
               scores[i].name);
      }
    }
  }

  arrfree(scores);
  for (uint64_t i = 0; i < arrlen(obj_nodes); i++) {
    arrfree(obj_nodes[i].edges);
  }
  arrfree(obj_nodes);
  arrfree(obj_list);
  hm_free(header_to_idx);

  if (g.succ) {
    for (uint64_t i = 0; i < scc_count; i++) {
      arrfree(g.succ[i]);
      arrfree(g.pred[i]);
    }
  }
  free(g.succ);
  free(g.pred);
  free(scc_retained_bytes);
  free(scc_reachable);
  free(scc_size);
  free(obj_scc);
  gc_free();
  return EXIT_SUCCESS;
}
