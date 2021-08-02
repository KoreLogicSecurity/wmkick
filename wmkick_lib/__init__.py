"""
Copyright 2020-2021 The WMkick Project, All Rights Reserved.

This software, having been partly or wholly developed and/or
sponsored by KoreLogic, Inc., is hereby released under the terms
and conditions set forth in the project's "README.LICENSE" file.
For a list of all contributors and sponsors, please refer to the
project's "README.CREDITS" file.
"""

VERSION = 0x00302800

def get_release_number():
    """Return the current release version as a number."""
    return VERSION

def get_release_string_pep440():
    """Return the current release version as a string (PEP 440 compliant)."""
    major = (VERSION >> 28) & 0x0f
    minor = (VERSION >> 20) & 0xff
    patch = (VERSION >> 12) & 0xff
    state = (VERSION >> 10) & 0x03
    build = VERSION & 0x03ff
    if state == 0:
        state_string = "dev"
    elif state == 1:
        state_string = "rc"
    elif state == 2:
        state_string = "post"
    elif state == 3:
        state_string = "post"
    release_string = "unknown"
    if state == 2 and build == 0:
        release_string = '%d.%d.%d' % (major, minor, patch)
    else:
        if state == 3:
            build = build + 0x400
        release_string = '%d.%d.%d.%s%d' % (major, minor, patch, state_string, build)
    return release_string

