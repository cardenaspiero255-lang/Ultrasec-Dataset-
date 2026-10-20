#include <string.h>
void copy(char *dest, const char *source) {
    memcpy(dest, source, sizeof(dest));
}
