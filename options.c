#define _GNU_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <popt.h>

#include "options.h"

#define COLORS \
	X("tb", "Title background color", title_background_color, BM_COLOR_TITLE_BG) \
	X("tf", "Title foreground color", title_foreground_color, BM_COLOR_TITLE_FG) \
	X("fb", "Filter background color", filter_background_color, BM_COLOR_FILTER_BG) \
	X("ff", "Filter foreground color", filter_foreground_color, BM_COLOR_FILTER_FG) \
	X("nb", "Normal background color", normal_background_color, BM_COLOR_ITEM_BG) \
	X("nf", "Normal foreground color", normal_foreground_color, BM_COLOR_ITEM_FG) \
	X("hb", "Highlighted background color", highlighted_background_color, BM_COLOR_HIGHLIGHTED_BG) \
	X("hf", "Highlighted foreground color", highlighted_foreground_color, BM_COLOR_HIGHLIGHTED_FG) \
	X("sb", "Selected background color", selected_background_color, BM_COLOR_SELECTED_BG) \
	X("sf", "Selected foreground color", selected_foreground_color, BM_COLOR_SELECTED_FG) \
	X("scb", "Scrollbar background color", scollbar_background_color, BM_COLOR_SCROLLBAR_BG) \
	X("scf", "Scrollbar foreground color", scollbar_foreground_color, BM_COLOR_SCROLLBAR_FG) \

static int debug;
static int bottom;
static int no_overlap;
static int monitor;
static int height;
static char *font;
static char *display;
#define X(option, help, var, setting) static char *var;
COLORS
#undef X

static struct poptOption optionsTable[] = {
	{ "debug", '\0', POPT_ARG_NONE, &debug, 0, NULL, NULL },
	{ "bottom", 'b', POPT_ARG_NONE, &bottom, 0, NULL, NULL },
	{ "no-overlap", 'n', POPT_ARG_NONE, &no_overlap, 0, NULL, NULL },
	{ "monitor", 'm', POPT_ARG_INT, &monitor, 0, "Monitor", NULL },
	{ "line-height", 'H', POPT_ARG_INT, &height, 0, "Height for each menu line", NULL },
	{ "fn", '\0', POPT_ARG_STRING, &font, 0, "Font", NULL },
	{ "display", 'D', POPT_ARG_STRING, &display, 0, "Set the X display", NULL },
#define X(option, help, var, setting) \
	{ option, '\0', POPT_ARG_STRING, &var, 0, help, "#RRGGBB" },
	COLORS
#undef X
	POPT_AUTOHELP
	POPT_TABLEEND
};

void validate_option_parsing(int rc, poptContext ctx) {
	if (rc != -1) {
		fprintf(stderr, "%s: %s\n",
				poptBadOption(ctx, POPT_BADOPTION_NOALIAS),
				poptStrerror(rc));
		poptPrintUsage(ctx, stderr, 0);
		exit(1);
	}
}

void parse_environment_options(void) {
	const char *opts = getenv("BEMENU_OPTS");

	if (!opts || !opts[0])
		return;

	int env_argc;
	const char **env_argv;
	int rc = poptParseArgvString(opts, &env_argc, &env_argv);
	poptContext ctx = poptGetContext(NULL,
			env_argc, env_argv,
			optionsTable, POPT_CONTEXT_KEEP_FIRST);
	rc = poptGetNextOpt(ctx);
	validate_option_parsing(rc, ctx);
	poptFreeContext(ctx);
	free(env_argv);
}

void parse_options(int argc, const char **argv) {
	parse_environment_options();

	poptContext ctx = poptGetContext(NULL, argc, argv, optionsTable, 0);

	int rc = poptGetNextOpt(ctx);
	validate_option_parsing(rc, ctx);

	poptFreeContext(ctx);
}

void free_options(void) {
	free(font);
#define X(option, help, var, setting) free(var);
	COLORS
#undef X
}

bool is_debug(void) {
	return debug;
}

void apply_global_options() {
	if (display) {
		setenv("DISPLAY", display, 1);
	}
}

void apply_options(struct bm_menu *menu) {
	assert(menu);

	bm_menu_set_bottom(menu, bottom);
	bm_menu_set_panel_overlap(menu, !no_overlap);
	bm_menu_set_monitor(menu, monitor);
	bm_menu_set_line_height(menu, height);
	bm_menu_set_font(menu, font);
#define X(option, help, var, setting) \
	if (var) \
		bm_menu_set_color(menu, setting, var);
	COLORS
#undef X
}
