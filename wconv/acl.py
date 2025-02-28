#!/usr/bin/python3

from __future__ import annotations

import struct
import base64
import binascii

from wconv import WConvException
from wconv.ace import Ace
from wconv.sid import SecurityIdentifier


class Acl:
    '''
    Class for a ACL
    '''

    def __init__(self, version: int, ace_count: int, aces: list[Ace]) -> None:
        '''
        '''
        self.version = version
        self.ace_count = ace_count
        self.aces = aces

    def from_bytes(byte_data: bytes, perm_type: str = 'file') -> ACL:
        '''
        Pars ean ACL from binary data

        Parameters:
            byte_data       byte data containing the ACL
            perm_type       Object type the descriptor applies to (file, service, ...)

        Returns:
            Acl
        '''
        revision = struct.unpack("<c", byte_data[0:1])[0]
        ace_count = struct.unpack("<H", byte_data[4:6])[0]

        pos = 8
        ace_list = []

        while len(ace_list) != ace_count:

            ace_length = struct.unpack("<H", byte_data[pos + 2:pos + 4])[0]
            ace = Ace.from_bytes(byte_data[pos:pos + ace_length])

            ace_list.append(ace)
            pos += ace_length

            ace.pretty_print()
