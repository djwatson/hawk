#pragma once

typedef struct bcfunc bcfunc;

#ifdef __cplusplus
extern "C" {
#endif
bcfunc *readbc_file(const char *filename);
bcfunc *readbc_image(unsigned char *mem, unsigned int len);
void free_script();
#ifdef __cplusplus
}
#endif
