project('pinentry-bemenu', 'c',
  version : '0.1',
  default_options : ['warning_level=3', 'c_std=c11'])

compiler = meson.get_compiler('c')

bemenu = dependency('bemenu')
assuan = dependency('libassuan')
gpg_error = dependency('gpg-error')

conf_data = configuration_data()

has_bm_menu_set_password = compiler.has_function('bm_menu_set_password',
  dependencies : [bemenu])

conf_data.set('HAS_BM_MENU_SET_PASSWORD', has_bm_menu_set_password)
conf_data.set_quoted('PROJECT_NAME', meson.project_name())
conf_data.set_quoted('PROJECT_VERSION', meson.project_version())

configure_file(configuration: conf_data, output : 'config.h')

exe = executable('pinentry-bemenu', 'pinentry_bemenu.c',
  dependencies : [bemenu, assuan, gpg_error],
  install : true)
