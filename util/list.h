#pragma once

#include <stddef.h>

typedef struct list_head {
  struct list_head *prev;
  struct list_head *next;
} list_head;

#define LIST_HEAD_INIT(name) {&(name), &(name)}

#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

void init_list_head(list_head *);
void list_add(list_head *list, list_head *after);
void list_add_tail(list_head *list, list_head *before);
void list_del(list_head *list);
bool list_empty(list_head *list);

#define list_first_entry_or_null(ptr, type, member)                            \
  ({                                                                           \
    list_head *head = (ptr);                                                   \
    list_head *pos = head->next;                                               \
    pos != head ? list_entry(pos, type, member) : nullptr;                     \
  })

#define list_entry(ptr, type, member) container_of(ptr, type, member)

#define container_of(ptr, type, member)                                        \
  ({                                                                           \
    void *__mptr = (void *)(ptr);                                              \
    ((type *)(__mptr - offsetof(type, member)));                               \
  })

static inline int list_is_head(const struct list_head *list,
                               const struct list_head *head) {
  return list == head;
}
#define list_for_each(pos, head)                                               \
  for ((pos) = (head)->next; !list_is_head(pos, (head)); (pos) = (pos)->next)
