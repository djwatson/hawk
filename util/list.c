#include <assert.h>

#include "list.h"

void init_list_head(list_head *list) {
  list->prev = list;
  list->next = list;
}

void __list_add(list_head *list, list_head *prev, list_head *next) {
  assert(list->prev == list);
  assert(list->next == list);

  next->prev = list;
  list->next = next;
  list->prev = prev;
  prev->next = list;
}

void list_add(list_head *list, list_head *after) {
  return __list_add(list, after, after->next);
}

void list_add_tail(list_head *list, list_head *before) {
  __list_add(list, before->prev, before);
}

void __list_del(list_head *prev, list_head *next) {
  next->prev = prev;
  prev->next = next;
}

void list_del(list_head *list) {
  __list_del(list->prev, list->next);
  list->prev = list;
  list->next = list;
}

bool list_empty(list_head *list) { return list->next == list; }
