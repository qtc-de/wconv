#!/usr/bin/python3

from __future__ import annotations

import struct
import base64
import binascii

from wconv import WConvException
from wconv.acl import Acl
from wconv.sid import SecurityIdentifier


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
            raise WConvException(f"from_hex(... - No hex content '{hex_string}'.")

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
            pass # TODO

        if dacl_offset != 0:
            Acl.from_bytes(byte_data[dacl_offset:])

        return SecurityDescriptor(owner_sid, group_sid, sacl, dacl)
