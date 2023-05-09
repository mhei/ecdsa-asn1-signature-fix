project(
  'ecdsa-asn1-signature-fix',
  'c',
  version: '0.1',
  license: 'BSD-2-Clause',
)

conf = configuration_data()
conf.set_quoted('PACKAGE_NAME', 'ecdsa-asn1-signature-fix')

prefixdir = get_option('prefix')
if not prefixdir.startswith('/')
  error('Prefix is not absolute: "@0@"'.format(prefixdir))
endif
bindir = join_paths(prefixdir, get_option('bindir'))
conf.set('bindir', bindir)

asn1lib = library('asn1fix', 'asn1.c')

e = executable('unittest', 'check.c', link_with: asn1lib, install: false)

test('simple unit test', e)

executable('ecdsa-asn1-signature-fix', 'main.c', link_with: asn1lib, install: true)
