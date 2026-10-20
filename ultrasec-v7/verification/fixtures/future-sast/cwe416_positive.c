#include <stdlib.h>
struct Item { int value; };
void bad(struct Item *ptr) {
    free(ptr);
    ptr->value = 10;
}
