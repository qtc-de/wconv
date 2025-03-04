#!/usr/bin/env python3

from __future__ import annotations

import re

from wconv import WConvException
from colorama import Fore, Style


# sid_mapping_file and type_mapping_file are populated by main.py
# and represent optional user specified files that contain mapping
# data. Both variables are used within the default resolvers.
sid_mapping_file = None
type_mapping_file = None

# sid_mappings and obj_type_mappings are used for caching the data
# read in throuh the sid_mapping_file and type_mapping_file.
sid_mappings = {}
obj_type_mappings = {}


def default_sid_resolver(sid: str) -> str:
    '''
    When SIDs are printed, wconv.helpers.sid_resolver is called
    to obtain the display name. This is the default implementation
    for an resolver, that checks whether the SID can be found in
    a user specified mapping file.

    Parameters:
        sid             the SID string to resolve

    Returns:
        resolved or original SID
    '''
    if sid_mappings:
        return sid_mappings.get(sid, sid)

    if sid_mapping_file is None:
        return sid

    for line in sid_mapping_file.readlines():

        try:
            sid, name = line.split(':', 1)
            sid_mappings[sid] = name.strip()

        except ValueError:
            pass

    return sid_mappings.get(sid, sid)


def default_obj_type_resolver(guid: str) -> str:
    '''
    When Object Types are printed, wconv.helpers.obj_type_resolver
    is called to obtain the display name. This is the default
    implementation for an resolver, that checks whether the type
    can be found in a user specified mapping file.

    Parameters:
        guid             the GUID string to resolve

    Returns:
        resolved or original GUID
    '''
    if obj_type_mappings:
        return obj_type_mappings.get(guid, guid)

    if type_mapping_file is None:
        return guid

    for line in type_mapping_file.readlines():

        try:
            guid, name = line.split(':', 1)
            obj_type_mappings[guid] = name.strip()

        except ValueError:
            pass

    return obj_type_mappings.get(guid, guid)


# Use the default resolvers by default. If wconv is consumed as
# a library, these variables can be overwritten to modify the
# SID and Object Type printing behavior
sid_resolver = default_sid_resolver
obj_type_resolver = default_obj_type_resolver


def get_int(integer: str | int) -> int:
    '''
    Helper function to convert a value into an integer, but
    do not throw an error if it already is an integer.

    Parameters:
        integer         value to convert

    Returns:
        integer value
    '''
    if isinstance(integer, int):
        return integer

    else:

        try:
            return int(integer, 0)

        except ValueError:
            raise WConvException(f"from_int(... - Specified value '{integer}' is not an integer.")


def print_blue(string: str, **kwargs) -> None:
    '''
    Wrapper around regular print which prints text
    in blue color.

    Parameters:
        string          the string to print
        **kwargs        same as for regular print

    Returns:
        None
    '''
    print(Fore.BLUE + str(string) + Style.RESET_ALL, **kwargs)


def print_yellow(string: str, **kwargs) -> None:
    '''
    Wrapper around regular print which prints text
    in yellow color.

    Parameters:
        string          the string to print
        **kwargs        same as for regular print

    Returns:
        None
    '''
    print(Fore.YELLOW + str(string) + Style.RESET_ALL, **kwargs)
