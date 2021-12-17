project('pinentry-bemenu', 'c',
  default_options : ['warning_level=3', 'c_std=c11'])


vcs_tag(
  input : 'version.h.in',
  output : 'version.h',
  command : ['git', 'describe', '--tag', '--dirty', '--broken'],
)

compiler = meson.get_compiler('c')

bemenu = dependency('bemenu', version : '>= 0.6.0')
assuan = dependency('libassuan')
gpg_error = dependency('gpg-error')
popt = dependency('popt')

have_bemenu_set_bottom = compiler.has_function(
  'bm_menu_set_bottom',
  prefix : '#include <bemenu.h>',
  dependencies : [ bemenu ],
)

conf_data = configuration_data()

conf_data.set_quoted('PROJECT_NAME', meson.project_name())
conf_data.set10('HAVE_BEMENU_SET_BOTTOM', have_bemenu_set_bottom)

configure_file(configuration: conf_data, output : 'config.h')

exe = executable('pinentry-bemenu', 'pinentry_bemenu.c', 'options.c',
  dependencies : [bemenu, assuan, gpg_error, popt],
  install : true)
