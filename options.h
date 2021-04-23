#pragma once

#include <bemenu.h>

struct options;

void parse_options(int argc, const char **argv);
bool is_debug(void);
void apply_options(struct bm_menu *menu);
void free_options(void);
