#include <stdio.h>
void copy(char *dest, unsigned long capacity, const char *source) {
    snprintf(dest, capacity, "%s", source);
}
