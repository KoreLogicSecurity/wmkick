#!/usr/bin/env python3
"""Configuration script for packaging project."""

from pkgutil import find_loader
from sys import stderr, version_info
from setuptools import setup, find_packages

from wmkick_lib import get_release_string_pep440

# NormalizationPatchBegin
# Attempt to disable version normalization performed by setup().
# Unfortunately, this code is not effective for our 'rc' version
# numbers, which have the following format: 'X.Y.Z.rcN'. The
# expected package name format is: 'package-X.Y.Z.rcN.tar.gz',
# but instead of that, we get: 'package-X.Y.ZrcN.tar.gz' (i.e.,
# the '.' separator between 'Z' and 'rcN' has been eliminated.
# The patch/workaround below was documented from here:
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
# NormalizationPatchEnd

def get_install_requires():
    """Returns a list of required modules."""
    install_requires = ['coloredlogs', 'scapy']
    if find_loader('kargparse'):
        install_requires.append('kargparse')
    return install_requires

if version_info < (3, 3, 0):
    stderr.write("This project requires Python 3.3.0 or higher.\n")
    exit(2)

setup(
    author='Houston Hunt',
    author_email='hhunt.git@korelogic.com',
    classifiers=['Operating System :: POSIX :: Linux'],
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
# NormalizationPatchBegin
#   version=get_release_string_pep440(),
    version=sic(get_release_string_pep440()),
# NormalizationPatchEnd
)

