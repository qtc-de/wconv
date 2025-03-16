#!/usr/bin/python3

from __future__ import annotations

import struct
import base64
import binascii

from wconv import WConvException
from wconv.acl import Acl
from wconv.ace import Ace
from wconv.sid import SecurityIdentifier
from wconv.helpers import print_yellow, print_blue


class SecurityDescriptor:
    '''
    Class for a SecurityDescripor
    '''

    def __init__(self, owner_sid: SecurityIdentifier, group_sid: SecurityIdentifier, sacl, dacl) -> None:
        '''
        '''
        self.owner = owner_sid
        self.group = group_sid
        self.sacl = sacl
        self.dacl = dacl

    def pretty_print(self, indent: str = ' ') -> None:
        '''
        Prints the formatted security descriptor

        Parameters:
            indent          Spaces after the '[+]' prefix

        Returns:
            None
        '''
        print_blue(f'[+]{indent}Owner:\t', end='')
        self.owner.pretty_print()

        print_blue(f'[+]{indent}Group:\t', end='')
        self.group.pretty_print()

        print_blue(f'[+]{indent}Ace Count:\t', end='')
        print_yellow(self.dacl.ace_count)

        print_blue('[+] ACE list:')
        for ace in self.dacl.aces:
            print_blue('[+]')
            ace.pretty_print()

    def filter_sid(self, sid: str) -> list[Ace]:
        '''
        Filter ACE objects by a specified SID.

        Parameters:
            sid             return only ACEs including this sid

        Returns:
            filtered ACE list
        '''
        for ace in self.dacl.aces:
            if sid in str(ace.trustee):

                yield ace

    def filter_inherited(self) -> list[Ace]:
        '''
        Filter out inherited ACEs. This is usefule for AdminSDHolder
        type of objects, as inherited ACEs do not apply here.

        Parameters:
            None

        Returns:
            filtered ACE list
        '''
        for ace in self.dacl.aces:

            if 'INHERITED' not in ace.ace_flags:
                yield ace

    def from_base64(b64_string: str, perm_type: str = 'file') -> SecurityDescriptor:
        '''
        Parses an SecurityDescriptor from a base64 string.

        Parameters:
            b64_string      Securitydescriptor string in base64 format
            perm_type       Object type the descriptor applies to (file, service, ...)

        Returns:
            SecurityDescriptor
        '''
        try:
            byte_data = base64.b64decode(b64_string)

        except binascii.Error:
            raise WConvException(f"from_base64(... - No base64 content '{b64_string}'.")

        hex_string = binascii.hexlify(byte_data)
        return SecurityDescriptor.from_hex(hex_string, perm_type)

    def from_hex(hex_string: str, perm_type: str = 'file') -> SecurityDescriptor:
        '''
        Parses an SecurityDescriptor from a hex string.

        Parameters:
            hex_string      Securitydescriptor string in hex format
            perm_type       Object type the descriptor applies to (file, service, ...)

        Returns:
            SecurityDescriptor
        '''
        try:
            byte_data = binascii.unhexlify(hex_string)

        except binascii.Error:
            raise WConvException(f"from_hex(... - No hex content '{hex_string}'.")

        revision = struct.unpack("<c", byte_data[0:1])
        rm_control_flags = struct.unpack("<c", byte_data[1:2])
        control_flags = struct.unpack("<H", byte_data[2:4])

        (owner_offset, group_offset, sacl_offset, dacl_offset) = struct.unpack("<IIII", byte_data[4:20])

        owner_sid = None
        group_sid = None
        sacl = None
        dacl = None

        if owner_offset != 0:
            owner_sid = SecurityIdentifier(byte_data[owner_offset:], False)

        if group_offset != 0:
            group_sid = SecurityIdentifier(byte_data[group_offset:], False)

        if sacl_offset != 0:
            pass  # TODO

        if dacl_offset != 0:
            dacl = Acl.from_bytes(byte_data[dacl_offset:], perm_type)

        return SecurityDescriptor(owner_sid, group_sid, sacl, dacl)
