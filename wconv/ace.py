#!/usr/bin/python3

from __future__ import annotations

import struct
import binascii
import wconv.sddl

from uuid import UUID

from wconv import WConvException
from wconv.objecttype import ObjectType
from wconv.sid import SecurityIdentifier
from wconv.helpers import print_yellow, print_blue, print_magenta, get_int


ACE_TYPES = {
    0x00: 'ACCESS_ALLOWED',
    0x01: 'ACCESS_DENIED',
    0x02: 'SYSTEM_AUDIT',
    0x03: 'SYSTEM_ALARM',
    0x04: 'ACCESS_ALLOWED_COMPOUND',
    0x05: 'ACCESS_ALLOWED_OBJECT',
    0x06: 'ACCESS_DENIED_OBJECT',
    0x07: 'SYSTEM_AUDIT_OBJECT',
    0x08: 'SYSTEM_ALARM_OBJECT',
    0x09: 'ACCESS_ALLOWED_CALLBACK',
    0x0A: 'ACCESS_DENIED_CALLBACK',
    0x0B: 'ACCESS_ALLOWED_CALLBACK_OBJECT',
    0x0C: 'ACCESS_DENIED_CALLBACK_OBJECT',
    0x0D: 'SYSTEM_AUDIT_CALLBACK',
    0x0E: 'SYSTEM_ALARM_CALLBACK',
    0x0F: 'SYSTEM_AUDIT_CALLBACK_OBJECT',
    0x10: 'SYSTEM_ALARM_CALLBACK_OBJECT',
    0x11: 'SYSTEM_MANDATORY_LABEL',
    0x12: 'SYSTEM_RESOURCE_ATTRIBUTE',
    0x13: 'SYSTEM_SCOPED_POLICY_ID'
}


ACE_FLAGS = {
    0x01: 'OBJECT_INHERIT',
    0x02: 'CONTAINER_INHERIT',
    0x04: 'NO_PROPAGATE_INHERIT',
    0x08: 'INHERIT_ONLY',
    0x10: 'INHERITED',
    0x20: 'CRITICAL_ACE_FLAG',
    0x40: 'SUCCESSFUL_ACCESS',
    0x80: 'FAILED_ACCESS',
}


GENERIC_PERMISSIONS = {
    # generic permissions
    0x10000000: 'GENERIC_ALL',
    0x20000000: 'GENERIC_EXECUTE',
    0x40000000: 'GENERIC_WRITE',
    0x80000000: 'GENERIC_READ',

    # standard permissions
    0x00010000: 'DELETE',
    0x00020000: 'READ_CONTROL',
    0x00040000: 'WRITE_DAC',
    0x00080000: 'WRITE_OWNER',

    # Non ACE / SDDL
    0x00100000: 'SYNCHRONIZE',
    0x01000000: 'ACCESS_SYSTEM_SECURITY',
    0x02000000: 'MAXIMUM_ALLOWED',
}


PERMISSIONS_FILE = {
    0x00000001: 'READ',
    0x00000002: 'WRITE',
    0x00000004: 'APPEND',
    0x00000008: 'READ_EXTENDED_ATTRIBUTES',
    0x00000010: 'WRITE_EXTENDED_ATTRIBUTES',
    0x00000020: 'EXECUTE',
    0x00000040: 'MEANINGLESS',
    0x00000080: 'READ_ATTRIBUTES',
    0x00000100: 'WRITE_ATTRIBUTES'
}


PERMISSIONS_DIRECTORY = {
    0x00000001: 'LIST',
    0x00000002: 'ADD_FILE',
    0x00000004: 'ADD_SUB_DIR',
    0x00000008: 'READ_EXTENDED_ATTRIBUTES',
    0x00000010: 'WRITE_EXTENDED_ATTRIBUTES',
    0x00000020: 'TRAVERSE',
    0x00000040: 'DELETE_CHILD',
    0x00000080: 'READ_ATTRIBUTES',
    0x00000100: 'WRITE_ATTRIBUTES'
}


PERMISSIONS_FILE_MAP = {
    0x00000001: 'FILE_MAP_COPY',
    0x00000002: 'FILE_MAP_WRITE',
    0x00000004: 'FILE_MAP_READ',
    0x00000008: 'FILE_MAP_EXECUTE',
    0x00000010: 'FILE_MAP_EXTEND_MAX_SIZE',
    0x00000020: 'SECTION_MAP_EXECUTE_EXPLICIT'
}


PERMISSIONS_REGISTRY = {
    0x00000001: 'QUERY_VALUE',
    0x00000002: 'SET_VALUE',
    0x00000004: 'CREATE_SUB_KEY',
    0x00000008: 'ENUMERATE_SUB_KEYS',
    0x00000010: 'NOTIFY',
    0x00000020: 'CREATE_LINK'
}


PERMISSIONS_SERVICE_CONTROL = {
    0x00000001: 'CONNECT',
    0x00000002: 'CREATE_SERVICE',
    0x00000004: 'ENUM_SERVICE',
    0x00000008: 'LOCK',
    0x00000010: 'QUERY_LOCK',
    0x00000020: 'MODIFY_BOOT_CFG'
}


PERMISSIONS_SERVICE = {
    0x00000001: 'QUERY_CONFIG',
    0x00000002: 'CHANGE_CONFIG',
    0x00000004: 'QUERY_STATISTIC',
    0x00000008: 'ENUM_DEPENDENCIES',
    0x00000010: 'START',
    0x00000020: 'STOP',
    0x00000040: 'PAUSE',
    0x00000080: 'INTERROGATE',
    0x00000100: 'USER_DEFINIED'
}


PERMISSIONS_PROCESS = {
    0x00000001: 'TERMINATE',
    0x00000002: 'CREATE_THREAD',
    0x00000004: 'SET_SESSION_ID',
    0x00000008: 'VM_OPERATION',
    0x00000010: 'VM_READ',
    0x00000020: 'VM_WRITE',
    0x00000040: 'DUP_HANDLE',
    0x00000080: 'CREATE_PROCESS',
    0x00000100: 'SET_QUOTA',
    0x00000200: 'SET_INFORMATION',
    0x00000400: 'QUERY_INFORMATION',
    0x00000800: 'SUSPEND_RESUME',
    0x00001000: 'QUERY_LIMITED_INFORMATION',
    0x00002000: 'SET_LIMITED_INFORMATION',
}


PERMISSIONS_THREAD = {
    0x00000001: 'TERMINATE',
    0x00000002: 'SUSPEND',
    0x00000004: 'ALERT',
    0x00000008: 'GET_CONTEXT',
    0x00000010: 'SET_CONTEXT',
    0x00000020: 'SET_INFO',
    0x00000040: 'QUERY_INFO',
    0x00000080: 'SET_TOKEN',
    0x00000100: 'IMPERSONATE',
    0x00000200: 'DIRECT_IMPERSONATION',
    0x00000400: 'SET_LIMITED_INFORMATION',
    0x00000800: 'QUERY_LIMITED_INFORMATION',
    0x00001000: 'RESUME',
}


PERMISSIONS_WINDOW_STATION = {
    0x00000001: 'ENUM_DESKTOPS',
    0x00000002: 'READ_ATTRIBUTE',
    0x00000004: 'CLIPBOARD',
    0x00000008: 'CREATE_DESKTOP',
    0x00000010: 'WRITE_ATTRIBUTE',
    0x00000020: 'GLOBAL_ATOMS',
    0x00000040: 'EXIT_WINDOWS',
    0x00000080: '',
    0x00000100: 'ENUM_WINSTA'
}


PERMISSIONS_DESKTOP = {
    0x00000001: 'READ_OBJECTS',
    0x00000002: 'CREATE_WINDOW',
    0x00000004: 'CREATE_MENU',
    0x00000008: 'HOOK_CONTROL',
    0x00000010: 'JOURNAL_RECORD',
    0x00000020: 'JOURNAL_PLAYBACK',
    0x00000040: 'ENUM',
    0x00000080: 'WRITE_OBJECTS',
    0x00000100: 'SWITCH_DESKTOP'
}


PERMISSIONS_PIPE = {
    0x00000001: 'READ',
    0x00000002: 'WRITE',
    0x00000004: 'CREATE_INSTANCE',
    0x00000008: 'READ_EXTENDED_ATTRIBUTES',
    0x00000010: 'WRITE_EXTENDEN_ATTRIBUTES',
    0x00000020: 'EXECUTE',
    0x00000040: 'DELETE',
    0x00000080: 'READ_ATTRIBUTES',
    0x00000100: 'WRITE_ATTRIBUTES'
}


PERMISSIONS_TOKEN = {
    0x00000001: 'ASSIGN_PRIMARY',
    0x00000002: 'DUPLICATE',
    0x00000004: 'IMPERSONATE',
    0x00000008: 'QUERY',
    0x00000010: 'QUERY_SOURCE',
    0x00000020: 'ADJUST_PRIVELEGES',
    0x00000040: 'ADJUST_GROUPS',
    0x00000080: 'ADJUST_DEFAULT',
    0x00000100: 'ADJUST_SESSION_ID'
}


PERMISSIONS_AD = {
    0x00000001: 'DS_CREATE_CHILD',
    0x00000002: 'DS_DELETE_CHILD',
    0x00000004: 'ACTRL_DS_LIST',
    0x00000008: 'DS_SELF',
    0x00000010: 'DS_READ_PROP',
    0x00000020: 'DS_WRITE_PROP',
    0x00000040: 'DS_DELETE_TREE',
    0x00000080: 'DS_LIST_OBJECT',
    0x00000100: 'DS_CONTROL_ACCESS',
}


PERM_TYPE_MAPPING = {
    'ad':               GENERIC_PERMISSIONS | PERMISSIONS_AD,
    'file':             GENERIC_PERMISSIONS | PERMISSIONS_FILE,
    'directory':        GENERIC_PERMISSIONS | PERMISSIONS_DIRECTORY,
    'file_map':         GENERIC_PERMISSIONS | PERMISSIONS_FILE_MAP,
    'registry':         GENERIC_PERMISSIONS | PERMISSIONS_REGISTRY,
    'service':          GENERIC_PERMISSIONS | PERMISSIONS_SERVICE,
    'service_control':  GENERIC_PERMISSIONS | PERMISSIONS_SERVICE_CONTROL,
    'process':          GENERIC_PERMISSIONS | PERMISSIONS_PROCESS,
    'thread':           GENERIC_PERMISSIONS | PERMISSIONS_THREAD,
    'window_station':   GENERIC_PERMISSIONS | PERMISSIONS_WINDOW_STATION,
    'desktop':          GENERIC_PERMISSIONS | PERMISSIONS_DESKTOP,
    'pipe':             GENERIC_PERMISSIONS | PERMISSIONS_PIPE,
    'token':            GENERIC_PERMISSIONS | PERMISSIONS_TOKEN,
}


def get_permission_dict(permission_type: str) -> dict[int, str]:
    '''
    The meaning of permission shortnames like 'CC' change depending on the resource
    they are assigned to. This function returns the corresponding dictionary for
    the requested permission type.

    Parameters:
        permission_type         Permission type (file, service, ...)

    Returns:
        Dictionary containing permission map
    '''
    try:
        mapping = PERM_TYPE_MAPPING[permission_type]
        return mapping

    except KeyError:
        raise WConvException(f"get_permissions_dict(... - Unknown permission type '{permission_type}'")


class Ace:
    '''
    The Ace class represents a single ACE entry inside a SDDL string.
    '''

    def __init__(self, ace_type: int, ace_flags: list[str], permissions: int, object_type: str,
                 inherited_object_type: str, trustee: str | SecurityIdentifier) -> None:
        '''
        The init function takes the six different ACE components and constructs an object out of them.

        Parameters:
            ace_type        integer that specifies the ACE type (see ACE_TYPES)
            ace_flags       ace_flags according to the ACE specifications
            permissions     ACE permissions as integer
            object_type     object_type according to the sddl specifications
            i_object_type   inherited_object_type according to the sddl specifications
            trustee         trustee the ACE applies to

        Returns:
            None
        '''
        self.ace_type = ace_type
        self.ace_flags = ace_flags
        self.permissions = permissions
        self.object_type = object_type
        self.inherited_object_type = inherited_object_type
        self.trustee = trustee

    def __str__(self) -> str:
        '''
        Outputs a simple string represenation of the ACE.
        Only used for debugging purposes.

        Paramaters:
            None

        Returns:
            String representation of ACE
        '''
        result = f'ACE Type:\t {ACE_TYPES[self.ace_type]}\n'
        permissions = self.get_permissions()

        if self.trustee:
            result += f'Trustee:\t {self.trustee}\n'

        if permissions:

            result += 'Permissions:\n'

            for perm in permissions:
                result += f'\t\t+ {perm}\n'

        if self.ace_flags:

            result += 'ACE Flags:\n'

            for flag in self.ace_flags:
                result += f'\t\t+ {flag}\n'

        return result[:-1]

    def pretty_print(self, indent: str = ' ', perm_type: str = 'file') -> None:
        '''
        Prints some formatted and colored output that represents the ACE. Probably not really
        ideal to be placed inside a library, but for now we can live with that.

        Parameters:
            indent          Spaces after the '[+]' prefix
            perm_type       which resource the ACE is attached to

        Returns:
            None
        '''
        if self.ace_type:
            print_blue(f'[+]{indent}ACE Type:\t', end='')
            print_yellow(ACE_TYPES[self.ace_type])

        if self.trustee:
            print_blue(f'[+]{indent}Trustee:\t', end='')

            if type(self.trustee) is SecurityIdentifier:
                self.trustee.pretty_print()

            else:
                print_yellow(self.trustee)

        if self.numeric:
            print_blue(f'[+]{indent}Numeric:\t', end='')
            print_yellow('0x{:08x}'.format(self.numeric))

        if self.ace_flags:

            print_blue(f'[+]{indent}ACE Flags:')

            for flag in self.ace_flags:
                print_blue('[+]', end='')
                print_yellow(f'{indent}\t\t+ {flag}')

        if self.object_type:
            print_blue(f'[+]{indent}Obj Type:\t', end='')
            self.object_type.pretty_print()

        if self.inherited_object_type:
            print_blue(f'[+]{indent}IObj Type:\t', end='')
            self.inherited_object_type.pretty_print()

        permissions = self.get_permissions(perm_type)

        if permissions:

            print_blue(f'[+]{indent}Permissions:')

            for perm in permissions:
                print_blue('[+]', end='')
                print_yellow(f'{indent}\t\t+ {perm}')

    def get_permissions(self, perm_type: str = 'file') -> list[str]:
        '''
        Returns the permissions contained within the ACE as a list
        of strings.

        Parameters:
            None

        Returns:
            list of permissions as strings
        '''
        perm_dict = get_permission_dict(perm_type)
        permissions = []

        for key, value in ACCESS_MASK_HEX.items():

            if key & self.permissions:

                try:
                    permission = perm_dict[value]
                    permissions.append(permission)

                except KeyError:
                    pass

        return permissions

    def toggle_permission(self, permissions: list[str]) -> None:
        '''
        Toggles the specified permissions for this ACE.

        Parameters:
            permissions     List of permission to toggle (GA, GR, GW, GE, CC, ...)

        Returns:
            None
        '''
        for permission in permissions:

            try:
                hex_value = wconv.sddl.ACCESS_MASK_HEX[permission]
                self.permissions ^= hex_value

            except KeyError:
                raise WConvException(f'Ace.toggle_permission(... - Unknown permission name: {permission}')

    def from_sddl(ace_string: str) -> Ace:
        '''
        Parses an ace from a string in SDDL representation (e.g. A;OICI;FA;;;BA).

        Parameters:
            ace_string      ACE string in sddl format

        Returns:
            ace_object
        '''
        try:
            ace_string = wconv.helpers.clear_parentheses(ace_string)
            ace_type, ace_flags, perms, object_type, inherited_object_type, trustee = ace_string.split(';', 5)

        except KeyError:
            raise WConvException(f'Ace.from_sddl(... - Invalid sddl input: {ace_string}')

        ace_type = wconv.sddl.SDDL_ACE_TYPES[ace_type]
        ace_flags = wconv.sddl.map_ace_flags(ace_flags)
        permissions = wconv.sddl.get_ace_numeric(perms)
        ace_int = wconv.sddl.get_ace_numeric(perms)

        if object_type:
            object_type = ObjectType(object_type)

        if inherited_object_type:
            inherited_object_type = ObjectType(inherited_object_type)

        if trustee in wconv.sddl.TRUSTEES:
            trustee = wconv.sddl.TRUSTEES[trustee]

        return Ace(ace_type, ace_flags, permissions, object_type, inherited_object_type, trustee)

    def from_int(integer: str | int) -> Ace:
        '''
        Parses an ace from an integer value in string representation.

        Parameters:
            integer         Integer value as string (hex also allowed)

        Returns:
            ace_object
        '''
        permissions = get_int(integer)

        return Ace(None, None, permissions, None, None, None)

    def from_bytes(byte_data: bytes) -> Ace:
        '''
        Parses an ACE from a bytes object.

        Parameters:
            byte_data       byte data of the ACE

        Returns:
            ace_object
        '''
        ace_type = ord(struct.unpack('<c', byte_data[0:1])[0])
        ace_flags = ord(struct.unpack('<c', byte_data[1:2])[0])

        ace_flag_list = []

        for key, value in ACE_FLAGS.items():

            if ace_flags & key != 0:
                ace_flag_list.append(value)

        position = 8
        object_type = None
        object_type_inherited = None

        if ACE_TYPES[ace_type].endswith('OBJECT'):

            object_flags = struct.unpack('<I', byte_data[position:position + 4])[0]
            position += 4

            if object_flags & 0x00000001:  # OBJECT_TYPE_PRESENT
                object_type = ObjectType(byte_data[position:position + 16])
                position += 16

            if object_flags & 0x00000002:  # INHERITED_OBJECT_TYPE_PRESENT
                object_type_inherited = ObjectType(byte_data[position:position + 16])
                position += 16

        ace_perms = struct.unpack('<I', byte_data[4:8])[0]
        trustee = SecurityIdentifier(byte_data[position:], False)

        return Ace(ace_type, ace_flag_list, ace_perms, object_type, object_type_inherited, trustee)

    def from_hex(hex_str: str) -> Ace:
        '''
        Parses an ACE from a hex string.

        Parameters:
            hex_string      hex string representing an ACE

        Returns:
            ace_object
        '''
        try:
            data = binascii.unhexlify(hex_str)
            return Ace.from_bytes(data)

        except binascii.Error:
            raise WConvException(f'Ace.from_hex(... - Invalid hex string: {hex_string}')
