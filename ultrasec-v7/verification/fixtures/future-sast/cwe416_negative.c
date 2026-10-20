#include <stdlib.h>
struct Item { int value; };
void good(struct Item *ptr) {
    ptr->value = 10;
    free(ptr);
}
