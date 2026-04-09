#include <stddef.h>
#include <stdint.h>

#if BOOTSTRAP
const uint8_t embedded_image[1] = {0};
const size_t embedded_image_size = 0;
#else
const uint8_t embedded_image[] = {
#embed "lib/img.scm.bc"
};
const size_t embedded_image_size = sizeof(embedded_image);
#endif
