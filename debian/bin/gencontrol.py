#!/usr/bin/python3

import sys
sys.path.append(sys.argv[1] + "/lib/python")

from debian_linux.config import ConfigCoreDump
from debian_linux.debian import Changelog, PackageDescription, VersionLinux, \
    Package, PackageRelationGroup
from debian_linux.gencontrol import Gencontrol as Base, merge_packages
from debian_linux.utils import Templates, read_control

import os.path, re, codecs, io, subprocess

class Gencontrol(Base):
    def __init__(self, config, image_version, signed_version_suffix):
        super(Gencontrol, self).__init__(ConfigCoreDump(fp = open(config, "rb")), Templates(["debian/templates"]))

        config_entry = self.config['version',]
        self.version = VersionLinux(config_entry['source'])

        # Check current linux-support version
        assert self.version.complete == re.sub(r'\+b\d+$', r'', image_version)

        self.abiname = config_entry['abiname']
        self.binary_version = image_version + signed_version_suffix
        self.vars = {
            'upstreamversion': self.version.linux_upstream,
            'version': self.version.linux_version,
            'source_upstream': self.version.upstream,
            'abiname': self.abiname,
            'imageversion': image_version,
            'imagesourceversion': self.version.complete,
            'binaryversion': self.binary_version,
        }

    def _substitute_file(self, template, vars, target, append=False):
        with codecs.open(target, 'a' if append else 'w', 'utf-8') as f:
            f.write(self.substitute(self.templates[template], vars))

    def do_main_setup(self, vars, makeflags, extra):
        makeflags['VERSION'] = self.version.linux_version
        makeflags['GENCONTROL_ARGS'] = (
            '-v%(binaryversion)s -DBuilt-Using="linux (= %(imagesourceversion)s)"'
            % vars)
        makeflags['PACKAGE_VERSION'] = self.binary_version

    def do_main_packages(self, packages, vars, makeflags, extra):
        # Assume that arch:all packages do not get binNMU'd
        packages['source']['Build-Depends'].append(
            'linux-support-%(abiname)s (= %(imagesourceversion)s)' % vars)

    def do_arch_setup(self, vars, makeflags, arch, extra):
        super(Gencontrol, self).do_main_setup(vars, makeflags, extra)

        if self.version.linux_modifier is None:
            abiname_part = '-%s' % self.config.merge('abi', arch)['abiname']
        else:
            abiname_part = ''
        makeflags['ABINAME'] = vars['abiname'] = \
            self.config['version', ]['abiname_base'] + abiname_part

    def do_arch_packages(self, packages, makefile, arch, vars, makeflags, extra):
        if os.getenv('DEBIAN_KERNEL_DISABLE_INSTALLER'):
            if self.changelog[0].distribution == 'UNRELEASED':
                import warnings
                warnings.warn('Disable installer modules on request (DEBIAN_KERNEL_DISABLE_INSTALLER set)')
            else:
                raise RuntimeError('Unable to disable installer modules in release build (DEBIAN_KERNEL_DISABLE_INSTALLER set)')
        elif (self.config.merge('packages').get('installer', True) and
              self.config.merge('build', arch).get('signed-modules', False)):
            # Add udebs using kernel-wedge
            installer_def_dir = ('/usr/share/linux-support-%s/installer' %
                                 self.abiname)
            installer_arch_dir = os.path.join(installer_def_dir, arch)
            if os.path.isdir(installer_arch_dir):
                kw_env = os.environ.copy()
                kw_env['KW_DEFCONFIG_DIR'] = installer_def_dir
                kw_env['KW_CONFIG_DIR'] = installer_arch_dir
                kw_proc = subprocess.Popen(
                    ['kernel-wedge', 'gen-control', vars['abiname']],
                    stdout=subprocess.PIPE,
                    env=kw_env)
                if not isinstance(kw_proc.stdout, io.IOBase):
                    udeb_packages = read_control(io.open(kw_proc.stdout.fileno(), encoding='utf-8', closefd=False))
                else:
                    udeb_packages = read_control(io.TextIOWrapper(kw_proc.stdout, 'utf-8'))
                kw_proc.wait()
                if kw_proc.returncode != 0:
                    raise RuntimeError('kernel-wedge exited with code %d' %
                                       kw_proc.returncode)

                merge_packages(packages, udeb_packages, arch)

                # These packages must be built after the per-flavour/
                # per-featureset packages.  Also, this won't work
                # correctly with an empty package list.
                if udeb_packages:
                    makefile.add(
                        'binary-arch_%s' % arch,
                        cmds=["$(MAKE) -f debian/rules.real install-udeb_%s %s "
                              "PACKAGE_NAMES='%s'" %
                              (arch, makeflags,
                               ' '.join(p['Package'] for p in udeb_packages))])

    def do_flavour_setup(self, vars, makeflags, arch, featureset, flavour, extra):
        super(Gencontrol, self).do_flavour_setup(vars, makeflags, arch, featureset, flavour, extra)

        config_image = self.config.merge('image', arch, featureset, flavour)
        makeflags['IMAGE_INSTALL_STEM'] = vars['image-stem'] = config_image.get('install-stem')

    def do_flavour_packages(self, packages, makefile, arch, featureset, flavour, vars, makeflags, extra):
        if not (self.config.merge('build', arch, featureset, flavour)
                .get('signed-modules', False)):
            return

        makeflags['IMAGEVERSION'] = vars['imageversion']

        packages['source']['Build-Depends'].append(
            'linux-image-%(abiname)s%(localversion)s-unsigned (= %(imageversion)s) [%(arch)s]' % vars)

        packages_signed = self.process_packages(
            self.templates["control.image"], vars)

        for package in packages_signed:
            name = package['Package']
            if name in packages:
                package = packages.get(name)
                package['Architecture'].add(arch)
            else:
                package['Architecture'] = arch
                packages.append(package)

        cmds_binary_arch = []
        for i in packages_signed:
            cmds_binary_arch += ["$(MAKE) -f debian/rules.real install-signed PACKAGE_NAME='%s' %s" % (i['Package'], makeflags)]
        makefile.add('binary-arch_%s_%s_%s_real' % (arch, featureset, flavour), cmds = cmds_binary_arch)

        for name in ['postinst', 'postrm', 'preinst', 'prerm']:
            self._substitute_file('image.%s' % name, vars,
                                  'debian/linux-image-%s%s.%s' %
                                  (vars['abiname'], vars['localversion'], name))

if __name__ == '__main__':
    Gencontrol(sys.argv[1] + "/config.defines.dump", sys.argv[2], sys.argv[3])()
