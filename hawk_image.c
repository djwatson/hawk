#include <stddef.h>
#include <stdint.h>

#if BOOTSTRAP
const uint8_t embedded_image[1] = {0};
const size_t embedded_image_size = 0;
#else
const uint8_t embedded_image[] = {
#ifdef HAVE_ZSTD
#embed "boot/img.scm.bc.zstd"
#else
#embed "boot/img.scm.bc"
#endif
};
const size_t embedded_image_size = sizeof(embedded_image);
#endif
const bool embedded_image_compressed =
#ifdef HAVE_ZSTD
    true;
#else
    false;
#endif
const bool embedded_image_is_program = false;
