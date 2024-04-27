project('pinentry-bemenu', 'c',
  default_options : ['warning_level=3', 'c_std=c11'],
  version : '0.13.2',
)


version_h = vcs_tag(
  input : 'version.h.in',
  output : 'version.h',
  command : ['git', 'describe', '--tag', '--dirty', '--broken'],
)

compiler = meson.get_compiler('c')

bemenu = dependency('bemenu', version : '>= 0.6.10')
assuan = dependency('libassuan')
gpg_error = dependency('gpg-error')
popt = dependency('popt')

have_bemenu_set_bottom = compiler.has_function(
  'bm_menu_set_bottom',
  prefix : '#include <bemenu.h>',
  dependencies : [ bemenu ],
)

have_bemenu_set_align = compiler.has_function(
  'bm_menu_set_align',
  prefix : '#include <bemenu.h>',
  dependencies : [ bemenu ],
)

bemenu_password_indicator_code = '''#include<bemenu.h>
int main(void) {
  return BM_PASSWORD_INDICATOR;
}
'''
have_bemenu_password_indicator = compiler.compiles(
  bemenu_password_indicator_code,
  name : 'BM_PASSWORD_INDICATOR'
)

conf_data = configuration_data()

conf_data.set_quoted('PROJECT_NAME', meson.project_name())
conf_data.set10('HAVE_BEMENU_SET_BOTTOM', have_bemenu_set_bottom)
conf_data.set10('HAVE_BEMENU_SET_ALIGN', have_bemenu_set_align)
conf_data.set10('HAVE_BEMENU_PASSWORD_INDICATOR', have_bemenu_password_indicator)

configure_file(configuration: conf_data, output : 'config.h')

exe = executable('pinentry-bemenu', 'pinentry_bemenu.c', 'options.c',
  version_h,
  dependencies : [bemenu, assuan, gpg_error, popt],
  install : true)
