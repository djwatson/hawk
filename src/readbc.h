// Copyright 2023 Dave Watson

#pragma once

typedef struct bcfunc bcfunc;

bcfunc *readbc_file(const char *filename);
bcfunc *readbc_image(unsigned char *mem, unsigned int len);
void free_script();
void load_bootstrap();
