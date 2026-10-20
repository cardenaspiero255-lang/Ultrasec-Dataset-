#include <stdio.h>
void write_result(char *dest, unsigned long cap, const char *value) {
    snprintf(dest, cap, "%s", value);
}
