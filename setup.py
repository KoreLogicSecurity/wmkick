#!/usr/bin/env python3
"""Configuration script for packaging project."""

from distutils.command.sdist import sdist
from pkgutil import find_loader
from sys import platform, stderr, version_info
from setuptools import find_packages, setup

from wmkick_lib import get_release_string_pep440

# Disable version normalization performed by setup(). This code
# indirectly depends on the CustomSDist class to handle our 'rc'
# version numbers, which have the following format: 'X.Y.Z.rcN'.
# The desired package name format is: 'package-X.Y.Z.rcN.tar.gz'.
# Without CustomSDist, we get: 'package-X.Y.ZrcN.tar.gz' (i.e.,
# the '.' separator between 'Z' and 'rcN' has been eliminated.
# The patch/workaround below is documented here:
#
#   https://github.com/pypa/setuptools/issues/308
#
try:
    # Try the approach of using sic(), added in setuptools 46.1.0.
    from setuptools import sic
except ImportError:
    # Try the approach of replacing packaging.version.Version.
    sic = lambda v: v
    try:
        # Note that setuptools >=39.0.0 uses packaging from setuptools.extern.
        from setuptools.extern import packaging
    except ImportError:
        # Note that setuptools <39.0.0 uses packaging from pkg_resources.extern.
        from pkg_resources.extern import packaging
    packaging.version.Version = packaging.version.LegacyVersion

class CustomSDist(sdist):

    def run(self):
        super().run()

    def prune_file_list(self):
        """Prune off branches that might slip into the file list as created
        by 'read_template()', but really don't belong there:
          * the build tree (typically "build")
          * the release tree itself (only an issue if we ran "sdist"
            previously with --keep-temp, or it aborted)
          * any RCS, CVS, .svn, .hg, .git*, .bzr, _darcs directories
        """
        build = self.get_finalized_command('build')
        base_dir = self.distribution.get_fullname()

        self.filelist.exclude_pattern(None, prefix=build.build_base)
        self.filelist.exclude_pattern(None, prefix=base_dir)

        # pruning out vcs directories
        # both separators are used under win32
        if platform == 'win32':
            seps = r'/|\\'
        else:
            seps = '/'

        vcs_dirs = ['RCS', 'CVS', r'\.svn', r'\.hg', r'\.git.*', r'\.bzr', '_darcs']
        vcs_ptrn = r'(^|%s)(%s)(%s).*' % (seps, '|'.join(vcs_dirs), seps)
        self.filelist.exclude_pattern(vcs_ptrn, is_regex=1)

def get_install_requires():
    """Returns a list of required modules."""
    install_requires = ['coloredlogs', 'scapy']
    if find_loader('kargparse'):
        install_requires.append('kargparse')
    return install_requires

if version_info < (3, 3, 0):
    print("This project requires Python version 3.3.0 or higher.", file=stderr)
    exit(2)

setup(
    author='Houston Hunt',
    author_email='hhunt.git@korelogic.com',
    classifiers=['Operating System :: POSIX :: Linux'],
    cmdclass={'sdist': CustomSDist},
    description="""A WMI and Powershell-Remoting/WSMan/WinRM TCP protocol redirector/MITM tool to capture NetNTLMv2 hashes.""",
    install_requires=get_install_requires(),
    license='GPL-3',
    long_description=
        """
        WMkick is a TCP protocol redirector/MITM tool that targets
        NTLM authentication message flows in WMI (135/tcp) and
        Powershell-Remoting/WSMan/WinRM (5985/tcp) to capture NetNTLMv2
        hashes. Once a hash has been captured, popular cracking tools such
        as Hashcat and JtR can be used to recover plaintext passwords.
        WMkick automates the hash extraction process and alleviates the
        need to build/use a WMI (or WSMAN) Auth Server or perform manual
        packet analysis.
        """,
    name='wmkick',
    packages=find_packages(),
    platforms=['Linux'],
    scripts=['wmkick.py'],
    url='https://www.korelogic.com',
    version=sic(get_release_string_pep440())
)

