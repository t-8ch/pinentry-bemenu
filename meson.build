project('pinentry-bemenu', 'c',
  version : '0.6.0',
  default_options : ['warning_level=3', 'c_std=c11'])

compiler = meson.get_compiler('c')

bemenu = dependency('bemenu', version : '>= 0.6.0')
assuan = dependency('libassuan')
gpg_error = dependency('gpg-error')
popt = dependency('popt')

conf_data = configuration_data()

conf_data.set_quoted('PROJECT_NAME', meson.project_name())
conf_data.set_quoted('PROJECT_VERSION', meson.project_version())

configure_file(configuration: conf_data, output : 'config.h')

exe = executable('pinentry-bemenu', 'pinentry_bemenu.c', 'options.c',
  dependencies : [bemenu, assuan, gpg_error, popt],
  install : true)
