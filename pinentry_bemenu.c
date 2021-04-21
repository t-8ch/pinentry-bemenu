#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <assert.h>
#include <assuan.h>
#include <bemenu.h>

#include "config.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

static char *prompt, *desc;

static struct {
	char *ok;
	char *not_ok;
	char *cancel;
} buttons;

static gpg_error_t set_ok(assuan_context_t ctx, char *message) {
	(void) ctx;

	free(buttons.ok);
	buttons.ok = strdup(message);
	return GPG_ERR_NO_ERROR;
}

static gpg_error_t set_cancel(assuan_context_t ctx, char *message) {
	(void) ctx;

	free(buttons.cancel);
	buttons.cancel = strdup(message);
	return GPG_ERR_NO_ERROR;
}

static gpg_error_t set_not_ok(assuan_context_t ctx, char *message) {
	(void) ctx;

	free(buttons.not_ok);
	buttons.not_ok = strdup(message);
	return GPG_ERR_NO_ERROR;
}

static struct bm_item *run_menu(struct bm_menu *menu) {
	assert(menu);

	bm_menu_grab_keyboard(menu, true);
	bm_menu_set_prefix(menu, prompt);
	bm_menu_set_title(menu, desc);
	bm_menu_set_filter_mode(menu, BM_FILTER_MODE_DMENU_CASE_INSENSITIVE);
#ifdef HAS_BM_MENU_SET_PASSWORD
	bm_menu_set_password(menu, true);
#endif

	uint32_t unicode;
	enum bm_key key;
	enum bm_run_result status = BM_RUN_RESULT_RUNNING;
	do {
		bm_menu_render(menu);
		key = bm_menu_poll_key(menu, &unicode);
	} while ((status = bm_menu_run_with_key(menu, key, unicode)) == BM_RUN_RESULT_RUNNING);

	if (status == BM_RUN_RESULT_SELECTED) {
		uint32_t n_selected;
		struct bm_item **selected = bm_menu_get_selected_items(menu, &n_selected);
		assert(n_selected == 1);
		return selected[0];
	} else if (status == BM_RUN_RESULT_CANCEL) {
		return NULL;
	}
	assert(0);
}

static gpg_error_t get_pin(assuan_context_t ctx, char *message) {
	(void) message;

	gpg_error_t ret = GPG_ERR_GENERAL;

	struct bm_menu *menu = bm_menu_new(NULL);
	if (!menu)
		return gpg_error(GPG_ERR_ENOMEM);

	struct bm_item *selected = run_menu(menu);
	if (!selected) {
		ret = gpg_error(GPG_ERR_ASS_CANCELED);
	} else {
		const char *pin = bm_item_get_text(selected);
		if (pin) {
			assuan_begin_confidential(ctx);
			ret = assuan_send_data(ctx, pin, strlen(pin));
			// flush data to force confidential logging
			assuan_send_data(ctx, NULL, 0);
			assuan_end_confidential(ctx);
		} else {
			ret = GPG_ERR_NO_ERROR;
		}
	}

	bm_menu_free(menu);
	return ret;
}

static gpg_error_t message(assuan_context_t ctx, char *message) {
	(void) ctx;
	(void) message;

	gpg_error_t ret;
	struct bm_menu *menu = bm_menu_new(NULL);
	bool b;

	struct bm_item *ok = bm_item_new(buttons.ok);
	assert(ok);

	b = bm_menu_add_item(menu, ok);
	assert(b);

	struct bm_item *selected = run_menu(menu);
	if (selected) {
		ret = GPG_ERR_NO_ERROR;
	} else {
		ret = gpg_error(GPG_ERR_ASS_CANCELED);
	}

	bm_menu_free(menu);

	return ret;
}

static gpg_error_t confirm(assuan_context_t ctx, char *message) {
	(void) ctx;
	(void) message;

	gpg_error_t ret;
	struct bm_menu *menu = bm_menu_new(NULL);
	bool b;

	struct bm_item *ok = bm_item_new(buttons.ok);
	assert(ok);
	struct bm_item *cancel = bm_item_new(buttons.cancel);
	assert(cancel);

	b = bm_menu_add_item(menu, ok);
	assert(b);
	b = bm_menu_add_item(menu, cancel);
	assert(b);

	struct bm_item *selected = run_menu(menu);
	if (selected) {
		if (selected == ok)
			ret = GPG_ERR_NO_ERROR;
		else if (selected == cancel)
			ret = gpg_error(GPG_ERR_ASS_CANCELED);
		else
			assert(false);
	} else {
		ret = gpg_error(GPG_ERR_ASS_CANCELED);
	}

	bm_menu_free(menu);

	return ret;
}

static gpg_error_t set_prompt(assuan_context_t ctx, char *message) {
	(void) ctx;

	free(prompt);
	prompt = strdup(message);
	return GPG_ERR_NO_ERROR;
}

static bool is_hex(char c) {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static uint8_t from_hex_char(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	assert(false);
}

static uint8_t from_hex(char c1, char c2) {
	return 16 * from_hex_char(c1) + from_hex_char(c2);
}

static void unescape_inplace(char *data) {
	char c;
	size_t l = strlen(data);
	for (int i = 0; (c = data[i]); i++) {
		if (c == '%') {
			if (is_hex(data[i+1]) && is_hex(data[i+2])) {
				char new = from_hex(data[i+1], data[i+2]);
				memmove(&data[i], &data[i+2], l - i - 2);
				data[i] = (char) new;
				l -= 2;
			}
		}
	}
	data[l] = '\0';
}

static gpg_error_t set_desc(assuan_context_t ctx, char *message) {
	(void) ctx;

	free(desc);
	unescape_inplace(message);
	desc = strdup(message);
	return GPG_ERR_NO_ERROR;
}

static gpg_error_t option_handler (assuan_context_t ctx, const char *name, const char *value) {
	(void) ctx;
	(void) value;

	if (strcmp(name, "no-grab") == 0)
		; // we always grab
	else if (strcmp(name, "ttyname") == 0)
		;
	else if (strcmp(name, "ttytype") == 0)
		;
	else if (strncmp(name, "lc-", 3) == 0)
		;
	else
		return gpg_error(GPG_ERR_UNKNOWN_OPTION);;

	return GPG_ERR_NO_ERROR;
}

static gpg_error_t get_info(assuan_context_t ctx, char *message) {
	(void) ctx;
	(void) message;

	return GPG_ERR_NO_ERROR;
}

static struct {
	const char *command;
	assuan_handler_t handler;
} commands[] = {
	{"SETPROMPT", &set_prompt},
	{"GETPIN", &get_pin},
	{"SETDESC", &set_desc},
	{"GETINFO", &get_info},
	{"MESSAGE", &message},
	{"CONFIRM", &confirm},
	{"SETOK", &set_ok},
	{"SETCANCEL", &set_cancel},
	{"SETNOTOK", &set_not_ok},
};

#define GPG_NO_ERROR_OR_RETURN_ERRNO(err) \
	if (r) return gpg_err_code_to_errno(gpg_err_code(err))


int main(int argc, char **argv) {
	(void) argc;
	(void) argv;

	if (!bm_init())
		return EXIT_FAILURE;

	buttons.ok = strdup("OK");
	buttons.cancel = strdup("Cancel");
	buttons.not_ok = strdup("Not OK");

	gpg_error_t r;
	assuan_context_t ctx;

	r = assuan_new(&ctx);
	GPG_NO_ERROR_OR_RETURN_ERRNO(r);

	assuan_fd_t in_fd = assuan_fdopen(STDIN_FILENO);
	assuan_fd_t out_fd = assuan_fdopen(STDOUT_FILENO);
	assuan_fd_t fds[] = { in_fd, out_fd };

	assuan_set_hello_line(ctx, PROJECT_NAME " v" PROJECT_VERSION);

	r = assuan_init_pipe_server(ctx, fds);
	GPG_NO_ERROR_OR_RETURN_ERRNO(r);

	r = assuan_register_option_handler(ctx, &option_handler);
	GPG_NO_ERROR_OR_RETURN_ERRNO(r);

	// assuan_set_log_stream(ctx, stderr);

	for (int i = 0; i < (int) ARRAY_SIZE(commands); i++) {
		r = assuan_register_command(ctx,
				commands[i].command,
				commands[i].handler,
				NULL);
		GPG_NO_ERROR_OR_RETURN_ERRNO(r);
	}

	while (true) {
		r = assuan_accept(ctx);
		if (r == (gpg_error_t) -1) {
			break;
		}
		GPG_NO_ERROR_OR_RETURN_ERRNO(r);
		r = assuan_process(ctx);
		GPG_NO_ERROR_OR_RETURN_ERRNO(r);
	}

	free(buttons.ok);
	free(buttons.cancel);
	free(buttons.not_ok);
	assuan_release(ctx);

	return EXIT_SUCCESS;
}
