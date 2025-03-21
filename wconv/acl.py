#!/usr/bin/python3

from __future__ import annotations

import struct

from wconv.ace import Ace


class Acl:
    '''
    Class for an ACL.
    '''

    def __init__(self, version: int, ace_count: int, aces: list[Ace]) -> None:
        '''
        '''
        self.version = version
        self.ace_count = ace_count
        self.aces = aces

    def from_bytes(byte_data: bytes, perm_type: str = 'file') -> Acl:
        '''
        Parse an Acl from binary data.

        Parameters:
            byte_data       byte data containing the Acl
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
            ace = Ace.from_bytes(byte_data[pos:pos + ace_length], perm_type)

            ace_list.append(ace)
            pos += ace_length

        return Acl(revision, ace_count, ace_list)
