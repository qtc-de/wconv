#!/usr/bin/python3

from __future__ import annotations

import struct

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


ACE_SDDL = {
    'A': 0x00,
    'D': 0x01,
    'AU': 0x02,
    'AL': 0x03,
    'CA': 0x04,
    'OA': 0x05,
    'OD': 0x06,
    'OU': 0x07,
    'OL': 0x08,
    'XA': 0x09,
    'XD': 0x0A,
    'ZA': 0x0B,
    'ZD': 0x0C,
    'XU': 0x0D,
    'XL': 0x0E,
    'ZU': 0x0F,
    'ZL': 0x10,
    'ML': 0x11,
    'RA': 0x12,
    'SP': 0x13,
}


ACE_FLAGS = {
    0x01: 'OBJECT_INHERIT',
    0x02: 'CONTAINER_INHERIT',
    0x04: 'NO_PROPAGATE_INHERIT',
    0x08: 'INHERIT_ONLY',
    0x10: 'INHERITED',
    0x40: 'SUCCESSFUL_ACCESS',
    0x80: 'FAILED_ACCESS',
}


ACE_FLAGS_SDDL = {
    'OI': 0x01,
    'CI': 0x02,
    'NP': 0x04,
    'IO': 0x08,
    'ID': 0x10,
    'SA': 0x40,
    'FA': 0x80,
}


GENERIC_PERMISSIONS = {
    "GA": "GENERIC_ALL",
    "GX": "GENERIC_EXECUTE",
    "GW": "GENERIC_WRITE",
    "GR": "GENERIC_READ",

    "SD": "DELETE",
    "RC": "READ_CONTROL",
    "WD": "WRITE_DAC",
    "WO": "WRITE_OWNER"
}


PERMISSIONS_FILE = {
    "CC": "READ",
    "DC": "WRITE",
    "LC": "APPEND",
    "SW": "READ_EXTENDED_ATTRIBUTES",
    "RP": "WRITE_EXTENDED_ATTRIBUTES",
    "WP": "EXECUTE",
    "DT": "MEANINGLESS",
    "LO": "READ_ATTRIBUTES",
    "CR": "WRITE_ATTRIBUTES"
}


PERMISSIONS_DIRECTORY = {
    "CC": "LIST",
    "DC": "ADD_FILE",
    "LC": "ADD_SUB_DIR",
    "SW": "READ_EXTENDED_ATTRIBUTES",
    "RP": "WRITE_EXTENDED_ATTRIBUTES",
    "WP": "TRAVERSE",
    "DT": "DELETE_CHILD",
    "LO": "READ_ATTRIBUTES",
    "CR": "WRITE_ATTRIBUTES"
}


PERMISSIONS_FILE_MAP = {
    "CC": "FILE_MAP_COPY",
    "DC": "FILE_MAP_WRITE",
    "LC": "FILE_MAP_READ",
    "SW": "FILE_MAP_EXECUTE",
    "RP": "FILE_MAP_EXTEND_MAX_SIZE",
    "WP": "SECTION_MAP_EXECUTE_EXPLICIT"
}


PERMISSIONS_REGISTRY = {
    "CC": "QUERY",
    "DC": "SET",
    "LC": "CREATE_SUB_KEY",
    "SW": "ENUM_SUB_KEY",
    "RP": "NOTIFY",
    "WP": "CREATE_LINK"
}


PERMISSIONS_SERVICE_CONTROL = {
    "CC": "CONNECT",
    "DC": "CREATE_SERVICE",
    "LC": "ENUM_SERVICE",
    "SW": "LOCK",
    "RP": "QUERY_LOCK",
    "WP": "MODIFY_BOOT_CFG"
}


PERMISSIONS_SERVICE = {
    "CC": "QUERY_CONFIG",
    "DC": "CHANGE_CONFIG",
    "LC": "QUERY_STATISTIC",
    "SW": "ENUM_DEPENDENCIES",
    "RP": "START",
    "WP": "STOP",
    "DT": "PAUSE",
    "LO": "INTERROGATE",
    "CR": "USER_DEFINIED"
}


PERMISSIONS_PROCESS = {
    "CC": "TERMINATE",
    "DC": "CREATE_THREAD",
    "LC": "SET",
    "SW": "VM_OPERATE",
    "RP": "VM_READ",
    "WP": "VM_WRITE",
    "DT": "DUP_HANDLE",
    "LO": "CREATE_PROCESS",
    "CR": "SET_QUOTA"
}


PERMISSIONS_THREAD = {
    "CC": "TERMINATE",
    "DC": "SUSPEND",
    "LC": "ALERT",
    "SW": "GET_CONTEXT",
    "RP": "SET_CONTEXT",
    "WP": "SET_INFO",
    "DT": "QUERY_INFO",
    "LO": "SET_TOKEN",
    "CR": "IMPERSONATE"
}


PERMISSIONS_WINDOW_STATION = {
    "CC": "ENUM_DESKTOPS",
    "DC": "READ_ATTRIBUTE",
    "LC": "CLIPBOARD",
    "SW": "CREATE_DESKTOP",
    "RP": "WRITE_ATTRIBUTE",
    "WP": "GLOBAL_ATOMS",
    "DT": "EXIT_WINDOWS",
    "LO": "",
    "CR": "ENUM_WINSTA"
}


PERMISSIONS_DESKTOP = {
    "CC": "READ_OBJECTS",
    "DC": "CREATE_WINDOW",
    "LC": "CREATE_MENU",
    "SW": "HOOK_CONTROL",
    "RP": "JOURNAL_RECORD",
    "WP": "JOURNAL_PLAYBACK",
    "DT": "ENUM",
    "LO": "WRITE_OBJECTS",
    "CR": "SWITCH_DESKTOP"
}


PERMISSIONS_PIPE = {
    "CC": "READ",
    "DC": "WRITE",
    "LC": "CREATE_INSTANCE",
    "SW": "READ_EXTENDED_ATTRIBUTES",
    "RP": "WRITE_EXTENDEN_ATTRIBUTES",
    "WP": "EXECUTE",
    "DT": "DELETE",
    "LO": "READ_ATTRIBUTES",
    "CR": "WRITE_ATTRIBUTES"
}


PERMISSIONS_TOKEN = {
    "CC": "ASSIGN_PRIMARY",
    "DC": "DUPLICATE",
    "LC": "IMPERSONATE",
    "SW": "QUERY",
    "RP": "QUERY_SOURCE",
    "WP": "ADJUST_PRIVELEGES",
    "DT": "ADJUST_GROUPS",
    "LO": "ADJUST_DEFAULT",
    "CR": "ADJUST_SESSION"
}


PERMISSIONS_AD = {
    'SD': 'DELETE',
    'RC': 'READ_CONTROL',
    'WD': 'WRITE_DACL',
    'WO': 'WRITE_OWNER',
    'SY': 'SYNCHRONIZE',
    'AS': 'ACCESS_SYSTEM_SECURITY',
    'MA': 'MAXIMUM_ALLOWED',
    'GR': 'GENERIC_READ',
    'GW': 'GENERIC_WRITE',
    'GX': 'GENERIC_EXECUTE',
    'GA': 'GENERIC_ALL',
    'CC': 'DS_CREATE_CHILD',
    'DC': 'DS_DELETE_CHILD',
    'LC': 'ACTRL_DS_LIST',
    'SW': 'DS_SELF',
    'RP': 'DS_READ_PROP',
    'WP': 'DS_WRITE_PROP',
    'DT': 'DS_DELETE_TREE',
    'LO': 'DS_LIST_OBJECT',
    'CR': 'DS_CONTROL_ACCESS',
}


GROUPED_PERMISSIONS = {
    "FA": "READ_CONTROL,DELETE,WRITE_DAC,WRITE_OWNER,SYNCHRONIZE,READ,WRITE,APPEND,READ_EXTENDED_ATTRIBUTES,\
WRITE_EXTENDED_ATTRIBUTES,EXECUTE,MEANINGLESS,READ_ATTRIBUTES,WRITE_ATTRIBUTES",
    "FR": "READ_CONTROL,READ,READ_ATTRIBUTES,READ_EXTENDED_ATTRIBUES,SYNCHRONIZE",
    "FW": "READ_CONTROL,WRITE,WRITE_ATTRIBUTES,WRITE_EXTENDED_ATTRIBUES,APPEND,SYNCHRONIZE",
    "FX": "READ_CONTROL,READ_ATTRIBUTES,EXECUTE,SYNCHRONIZE",
    "KA": "READ_CONTROL,DELETE,WRITE_DAC,WRITE_OWNER,QUERY,SET,CREATE_SUB_KEY,ENUM_SUB_KEYS,NOTIFY,CREATE_LINK",
    "KR": "READ_CONTROL,QUERY,ENUM_SUB_KEYS,NOTIFY",
    "KW": "READ_CONTROL,SET,CREATE_SUB_KEY",
    "KE": "READ_CONTROL,QUERY,ENUM_SUB_KEYS,NOTIFY"
}


TRUSTEES = {
    'AN': 'Anonymous',
    'AO': 'Account Operators',
    'AU': 'Authenticated Users',
    'BA': 'Administrators',
    'BG': 'Guests',
    'BO': 'Backup Operators',
    'BU': 'Users',
    'CA': 'Certificate Publishers',
    'CD': 'Certificate Services DCOM Access',
    'CG': 'Creator Group',
    'CO': 'Creator Owner',
    'DA': 'Domain Admins',
    'DC': 'Domain Computers',
    'DD': 'Domain Controllers',
    'DG': 'Domain Guests',
    'DU': 'Domain Users',
    'EA': 'Enterprise Admins',
    'ED': 'Enterprise Domain Controllers',
    'RO': 'Enterprise Read-Only Domain Controllers',
    'PA': 'Group Policy Admins',
    'IU': 'Interactive Users',
    'LA': 'Local Administrator',
    'LG': 'Local Guest',
    'LS': 'Local Service',
    'SY': 'Local System',
    'NU': 'Network',
    'LW': 'Low Integrity',
    'ME': 'Medium Integrity',
    'HI': 'High Integrity',
    'SI': 'System Integrity',
    'NO': 'Network Configuration Operators',
    'NS': 'Network Service',
    'PO': 'Printer Operators',
    'PS': 'Self',
    'PU': 'Power Users',
    'RS': 'RAS Servers',
    'RD': 'Remote Desktop Users',
    'RE': 'Replicator',
    'RC': 'Restricted Code',
    'RU': 'Pre-Win2k Compatibility Access',
    'SA': 'Schema Administrators',
    'SO': 'Server Operators',
    'SU': 'Service',
    'WD': 'Everyone',
    'WR': 'Write restricted Code',
}


ACCESS_MASK_HEX = dict([
    (0x10000000, 'GA'),
    (0x20000000, 'GX'),
    (0x40000000, 'GW'),
    (0x80000000, 'GR'),

    (0x02000000, 'MA'),
    (0x01000000, 'AS'),
    (0x00100000, 'SY'),
    (0x00010000, 'SD'),
    (0x00020000, 'RC'),
    (0x00040000, 'WD'),
    (0x00080000, 'WO'),

    (0x00000001, 'CC'),
    (0x00000002, 'DC'),
    (0x00000004, 'LC'),
    (0x00000008, 'SW'),
    (0x00000010, 'RP'),
    (0x00000020, 'WP'),
    (0x00000040, 'DT'),
    (0x00000080, 'LO'),
    (0x00000100, 'CR'),

    (0x000f01ff, 'FA'),
    (0x00020089, 'FR'),
    (0x00020116, 'FW'),
    (0x000200a0, 'FX'),

    (0x000f003f, 'KA'),
    (0x00020019, 'KR'),
    (0x00020006, 'KW'),
    (0x00020019, 'KE')
])


ACCESS_MASK_HEX_REVERSE = dict([
    ('GA', 0x10000000),
    ('GX', 0x20000000),
    ('GW', 0x40000000),
    ('GR', 0x80000000),

    ('MA', 0x02000000),
    ('AS', 0x01000000),
    ('SY', 0x00100000),
    ('SD', 0x00010000),
    ('RC', 0x00020000),
    ('WD', 0x00040000),
    ('WO', 0x00080000),

    ('CC', 0x00000001),
    ('DC', 0x00000002),
    ('LC', 0x00000004),
    ('SW', 0x00000008),
    ('RP', 0x00000010),
    ('WP', 0x00000020),
    ('DT', 0x00000040),
    ('LO', 0x00000080),
    ('CR', 0x00000100),

    ('FA', 0x000f01ff),
    ('FR', 0x00020089),
    ('FW', 0x00020116),
    ('FX', 0x000200a0),

    ('KA', 0x000f003f),
    ('KR', 0x00020019),
    ('KW', 0x00020006),
    ('KE', 0x00020019)
])


PERM_TYPE_MAPPING = {
    'ad':               dict(GENERIC_PERMISSIONS, **PERMISSIONS_AD),
    'file':             dict(GENERIC_PERMISSIONS, **PERMISSIONS_FILE),
    'directory':        dict(GENERIC_PERMISSIONS, **PERMISSIONS_DIRECTORY),
    'file_map':         dict(GENERIC_PERMISSIONS, **PERMISSIONS_FILE_MAP),
    'registry':         dict(GENERIC_PERMISSIONS, **PERMISSIONS_REGISTRY),
    'service':          dict(GENERIC_PERMISSIONS, **PERMISSIONS_SERVICE),
    'service_control':  dict(GENERIC_PERMISSIONS, **PERMISSIONS_SERVICE_CONTROL),
    'process':          dict(GENERIC_PERMISSIONS, **PERMISSIONS_PROCESS),
    'thread':           dict(GENERIC_PERMISSIONS, **PERMISSIONS_THREAD),
    'window_station':   dict(GENERIC_PERMISSIONS, **PERMISSIONS_WINDOW_STATION),
    'desktop':          dict(GENERIC_PERMISSIONS, **PERMISSIONS_DESKTOP),
    'pipe':             dict(GENERIC_PERMISSIONS, **PERMISSIONS_PIPE),
    'token':            dict(GENERIC_PERMISSIONS, **PERMISSIONS_TOKEN),
}


def get_permission_dict(permission_type: str) -> dict:
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
    ace_everyone = '(A;;GAGRGWGXRCSDWDWOSSCCDCLCSWRPWPDTLOCR;;;WD)'
    ace_anonymous = '(A;;GAGRGWGXRCSDWDWOSSCCDCLCSWRPWPDTLOCR;;;AN)'

    def __init__(self, ace_type: int, ace_flags: list[str], permissions: list[str], object_type: str,
                 inherited_object_type: str, trustee: str, numeric: int) -> None:
        '''
        The init function takes the six different ACE components and constructs an object out of them.

        Parameters:
            ace_type        integer that specifies the ACE type (see ACE_TYPES)
            ace_flags       ace_flags according to the sddl specifications
            permissions     permissions defined inside the ACE
            object_type     object_type according to the sddl specifications
            i_object_type   inherited_object_type according to the sddl specifications
            trustee         trustee the ACE applies to
            numeric         Integer ace value

        Returns:
            None
        '''
        self.ace_type = ace_type
        self.ace_flags = ace_flags
        self.permissions = permissions
        self.object_type = object_type
        self.inherited_object_type = inherited_object_type
        self.trustee = trustee
        self.numeric = numeric

    def __str__(self) -> str:
        '''
        Outputs a simple string represenation of the ACE. Only used for debugging purposes.

        Paramaters:
            None

        Returns:
            String representation of ACE
        '''
        result = f'ACE Type:\t {ACE_TYPES[self.ace_type]}\n'

        if self.trustee:
            result += f'Trustee:\t {self.trustee}\n'

        if self.permissions:
            result += 'Permissions:\n'
            for perm in self.permissions:
                result += f'\t\t+ {perm}\n'

        if self.ace_flags:
            result += 'ACE Flags:\n'
            for flag in self.ace_flags:
                result += f'\t\t+ {flag}\n'

        return result[:-1]

    def pretty_print(self, indent: str = ' ') -> None:
        '''
        Prints some formatted and colored output that represents the ACE. Probably not really
        ideal to be placed inside a library, but for now we can live with that.

        Parameters:
            indent          Spaces after the '[+]' prefix

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

        if self.permissions:

            print_blue(f'[+]{indent}Permissions:')
            for perm in self.permissions:
                print_blue('[+]', end='')
                print_yellow(f'{indent}\t\t+ {perm}')

    def clear_parentheses(ace_string: str) -> str:
        '''
        Removes the opening and closing parantheses from an ACE string (if present).

        Paramaters:
            ace_string      ACE string to operate on

        Returns:
            ACE string without parentheses
        '''
        if ace_string[0] == '(':
            ace_string = ace_string[1:]

        if ace_string[-1] == ')':
            ace_string = ace_string[:-1]

        return ace_string

    def get_ace_flags(ace_flag_string: str) -> list[str]:
        '''
        Parses the flag-portion of an ACE string and returns a list of the corresponding
        ACE flags.

        Paramaters:
            ace_flag_string String containing the ACE flags

        Returns:
            List containing the parsed ACE flags
        '''
        ace_flags = []

        for ctr in range(0, len(ace_flag_string), 2):

            try:
                ace_flag = ace_flag_string[ctr:ctr+2]
                ace_flag = ACE_FLAGS[ACE_FLAGS_SDDL[ace_flag]]
                ace_flags.append(ace_flag)

            except KeyError:
                raise WConvException(f"get_ace_flags(... - Unknown ACE flag '{ace_flag}'.")

        return ace_flags

    def get_ace_permissions(ace_permission_string: str, perm_type: str = 'file') -> list[str]:
        '''
        Takes the ACE portion containing the permission and returns a list of the corresponding parsed
        permissions.

        Paramaters:
            ace_permission_string   String containing the ACE permissions
            perm_type               Permission type (file, service, ...)

        Returns:
            List of corresponding permissions
        '''
        permissions = []
        perm_dict = get_permission_dict(perm_type)

        for ctr in range(0, len(ace_permission_string), 2):

            permission = ace_permission_string[ctr:ctr+2]

            try:

                if permission in GROUPED_PERMISSIONS:
                    permission = GROUPED_PERMISSIONS[permission]
                    permission = permission.split(",")
                    permissions += permission
                else:
                    permission = perm_dict[permission]
                    permissions.append(permission)

            except KeyError:
                raise WConvException(f"from_string(... - Unknown permission name '{permission}'.")

        return permissions

    def get_ace_numeric(ace_permission_string: str) -> int:
        '''
        Takes the ACE portion containing the permission and returns the corresponding integer value.

        Paramaters:
            ace_permission_string   String containing the ACE permissions

        Returns:
            Corresponding integer value
        '''
        ace_int = 0

        for ctr in range(0, len(ace_permission_string), 2):

            permission = ace_permission_string[ctr:ctr+2]

            try:
                ace_int += ACCESS_MASK_HEX_REVERSE[permission]

            except KeyError:
                raise WConvException(f"from_string(... - Unknown permission name '{permission}'.")

        return ace_int

    def from_string(ace_string: str, perm_type: str = 'file') -> Ace:
        '''
        Parses an ace from a string in SDDL representation (e.g. A;OICI;FA;;;BA).

        Parameters:
            ace_string      ACE string in sddl format
            perm_type       Object type the sddl applies to (file, service, ...)

        Returns:
            ace_object
        '''
        ace_string = Ace.clear_parentheses(ace_string)
        ace_split = ace_string.split(';')

        if len(ace_split) != 6:
            raise WConvException(f"from_string(... - Specified value '{ace_string}' is not a valid ACE string.")

        try:
            ace_type = ACE_SDDL[ace_split[0]]

        except KeyError:
            raise WConvException(f"from_string(... - Unknown ACE type '{ace_split[0]}'.")

        ace_flags = Ace.get_ace_flags(ace_split[1])
        permissions = Ace.get_ace_permissions(ace_split[2], perm_type)
        ace_int = Ace.get_ace_numeric(ace_split[2])

        object_type = ace_split[3]
        inherited_object_type = ace_split[4]

        if object_type:
            object_type = ObjectType(object_type)

        if inherited_object_type:
            inherited_object_type = ObjectType(inherited_object_type)

        trustee = ace_split[5]
        if trustee in TRUSTEES:
            trustee = TRUSTEES[trustee]

        return Ace(ace_type, ace_flags, permissions, object_type, inherited_object_type, trustee, ace_int)

    def from_int(integer: str | int, perm_type: str = 'file') -> Ace:
        '''
        Parses an ace from an integer value in string representation.

        Parameters:
            integer         Integer value as string (hex also allowed)
            perm_type       Object type the sddl applies to (file, service, ...)

        Returns:
            ace_object
        '''
        ace_int = get_int(integer)

        perm_dict = get_permission_dict(perm_type)
        permissions = []

        for key, value in ACCESS_MASK_HEX.items():

            if key & ace_int:

                try:
                    permission = perm_dict[value]
                    permissions.append(permission)

                except KeyError:
                    # Ignore matches on grouped permissions like FA, FR, FW...
                    pass

        return Ace(None, None, permissions, None, None, None, ace_int)

    def from_bytes(byte_data: bytes, perm_type: str = 'file') -> Ace:
        '''
        Parses an ACE from a bytes object.

        Parameters:
            byte_data       byte data of the ACE
            perm_type       Object type the sddl applies to (file, service, ...)

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

        perm_dict = get_permission_dict(perm_type)
        permissions = []

        for key, value in ACCESS_MASK_HEX.items():

            if key & ace_perms:

                try:
                    permission = perm_dict[value]
                    permissions.append(permission)

                except KeyError:
                    pass

        return Ace(ace_type, ace_flag_list, permissions, object_type, object_type_inherited, trustee, ace_perms)

    def toggle_permission(integer: str | int, permissions: list[str]) -> str:
        '''
        Takes an ace in integer format and toggles the specified permissions on it.

        Parameters:
            integer         Integer value as string (hex also allowed)
            permissions     List of permission to toggle (GA, GR, GW, GE, CC, ...)

        Returns:
            Resulting ace value as integer in hex format
        '''
        ace_int = get_int(integer)

        for permission in permissions:

            try:
                hex_value = ACCESS_MASK_HEX_REVERSE[permission]
                ace_int = ace_int ^ hex_value

            except KeyError:
                raise WConvException(f"toggle_permission(... - Unknown permission name '{permission}'")

        return "0x{:08x}".format(ace_int)
