#!/usr/bin/python3

from termcolor import cprint
from wconv import WConvException


ACE_TYPES = {
    "A": "ACCESS_ALLOWED",
    "D": "ACCESS_DENIED",
    "OA": "ACCESS_ALLOWED_OBJECT",
    "OD": "ACCESS_DENIED_OBJECT",
    "AU": "SYSTEM_AUDIT",
    "AL": "SYSTEM_ALARM",
    "OU": "SYSTEM_AUDIT_OBJECT",
    "OL": "SYSTEM_ALARM_OBJECT"
}

ACE_FLAGS = {
    "CI": "CONTAINER_INHERIT",
    "OI": "OBJECT_INHERIT",
    "NP": "NO_PROPAGATE_INHERIT",
    "IO": "INHERIT_ONLY",
    "ID": "INHERITED",
    "SA": "SUCCESSFUL_ACCESS",
    "FA": "FAILED_ACCESS"
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

GROUPED_PERMISSIONS = {
    "FA": "READ_CONTROL,DELETE,WRITE_DAC,WRITE_OWNER,SYNCHRONIZE,READ,WRITE,APPEND,READ_EXTENDED_ATTRIBUTES, \
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


def get_permission_dict(permission_type):
    '''
    The meaning of permission shortnames like 'CC' change depending on the resource
    they are assigned to. This function returns the corresponding dictionary for
    the requested permission type.

    Parameters:
        permission_type         (string)        Permission type (file, service, ...)

    Returns:
        permission_dict         (dict)          Dictionary containing permission map
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

    def __init__(self, ace_type, ace_flags, permissions, object_type, inherited_object_type, trustee, numeric):
        '''
        The init function takes the six different ACE components and constructs an object out of them.

        Parameters:
            ace_type        (string)            ace_type according to the sddl specifications
            ace_flags       (list[string])      ace_flags according to the sddl specifications
            permissions     (list[string])      permissions defined inside the ACE
            object_type     (string)            object_type according to the sddl specifications
            i_object_type   (string)            inherited_object_type according to the sddl specifications
            trustee         (string)            trustee the ACE applies to
            numeric         (int)               Integer ace value

        Returns:
            ace_object      (Ace)               New generated ACE object
        '''
        self.ace_type = ace_type
        self.ace_flags = ace_flags
        self.permissions = permissions
        self.object_type = object_type
        self.inherited_object_type = inherited_object_type
        self.trustee = trustee
        self.numeric = numeric

    def __str__(self):
        '''
        Outputs a simple string represenation of the ACE. Only used for debugging purposes.

        Paramaters:
            None

        Returns:
            None
        '''
        if self.ace_type:
            result = f'ACE Type:\t {self.ace_type}\n'

        if self.ace_trustee:
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

    def pretty_print(self, indent=' ', verbose=False):
        '''
        Prints some formatted and colored output that represents the ACE. Probably not really
        ideal to be placed inside a library, but for now we can live with that.

        Parameters:
            indent          (string)            Spaces after the '[+]' prefix
            verbose         (boolean)           Decides if ACE flags are printed

        Returns:
            None
        '''
        if self.ace_type:
            cprint(f'[+]{indent}ACE Type:\t', 'blue', end='')
            cprint(self.ace_type, 'yellow')

        if self.trustee:
            cprint(f'[+]{indent}Trustee:\t', 'blue', end='')
            cprint(self.trustee, 'yellow')

        if self.numeric:
            cprint(f'[+]{indent}Numeric:\t', 'blue', end='')
            cprint('0x{:08x}'.format(self.numeric), 'yellow')

        if verbose:
            if self.ace_flags:

                cprint(f'[+]{indent}ACE Flags:\t', 'blue')
                for flag in self.ace_flags:
                    cprint('[+]', 'blue', end='')
                    cprint(f'{indent}\t\t+ {flag}', 'yellow')

        if self.permissions:

            cprint(f'[+]{indent}Permissions:\t', 'blue')
            for perm in self.permissions:
                cprint('[+]', 'blue', end='')
                cprint(f'{indent}\t\t+ {perm}', 'yellow')

    def clear_parentheses(ace_string):
        '''
        Removes the opening and closing parantheses from an ACE string (if present).

        Paramaters:
            ace_string      (string)            ACE string to operate on

        Returns:
            ace_string      (string)            ACE string without parentheses
        '''
        if ace_string[0] == '(':
            ace_string = ace_string[1:]

        if ace_string[-1] == ')':
            ace_string = ace_string[:-1]

        return ace_string

    def get_ace_flags(ace_flag_string):
        '''
        Parses the flag-portion of an ACE string and returns a list of the corresponding
        ACE flags.

        Paramaters:
            ace_flag_string (string)            String containing the ACE flags

        Returns:
            ace_flags       (list[string])      List containing the parsed ACE flags
        '''
        ace_flags = []

        for ctr in range(0, len(ace_flag_string), 2):

            try:
                ace_flag = ace_flag_string[ctr:ctr+2]
                ace_flag = ACE_FLAGS[ace_flag]
                ace_flags.append(ace_flag)

            except KeyError:
                raise WConvException(f"get_ace_flags(... - Unknown ACE flag '{ace_flag}'.")

        return ace_flags

    def get_ace_permissions(ace_permission_string, perm_type='file'):
        '''
        Takes the ACE portion containing the permission and returns a list of the corresponding parsed
        permissions.

        Paramaters:
            ace_permission_string   (string)        String containing the ACE permissions
            perm_type               (string)        Permission type (file, service, ...)

        Returns:
            permissions             (list[string])  List of corresponding permissions
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

    def get_ace_numeric(ace_permission_string):
        '''
        Takes the ACE portion containing the permission and returns the corresponding integer value.

        Paramaters:
            ace_permission_string   (string)        String containing the ACE permissions

        Returns:
            ace_int                 (int)           Corresponding integer value
        '''
        ace_int = 0

        for ctr in range(0, len(ace_permission_string), 2):

            permission = ace_permission_string[ctr:ctr+2]

            try:
                ace_int += ACCESS_MASK_HEX_REVERSE[permission]

            except KeyError:
                raise WConvException(f"from_string(... - Unknown permission name '{permission}'.")

        return ace_int

    def from_string(ace_string, perm_type='file'):
        '''
        Parses an ace from a string in SDDL representation (e.g. A;OICI;FA;;;BA).

        Parameters:
            ace_string      (string)            ACE string in sddl format
            perm_type       (string)            Object type the sddl applies to (file, service, ...)

        Returns:
            ace_object      (Ace)
        '''
        ace_string = Ace.clear_parentheses(ace_string)

        ace_split = ace_string.split(';')
        if len(ace_split) != 6:
            raise WConvException(f"from_string(... - Specified value '{ace_string}' is not a valid ACE string.")

        try:
            ace_type = ACE_TYPES[ace_split[0]]
        except KeyError:
            raise WConvException(f"from_string(... - Unknown ACE type '{ace_split[0]}'.")

        ace_flags = Ace.get_ace_flags(ace_split[1])
        permissions = Ace.get_ace_permissions(ace_split[2], perm_type)
        ace_int = Ace.get_ace_numeric(ace_split[2])

        object_type = ace_split[3]
        inherited_object_type = ace_split[4]

        trustee = ace_split[5]
        if trustee in TRUSTEES:
            trustee = TRUSTEES[trustee]

        return Ace(ace_type, ace_flags, permissions, object_type, inherited_object_type, trustee, ace_int)

    def from_int(integer, perm_type='file'):
        '''
        Parses an ace from an integer value in string representation.

        Parameters:
            integer         (string)            Integer value as string (hex also allowed)
            perm_type       (string)            Object type the sddl applies to (file, service, ...)

        Returns:
            ace_object      (Ace)
        '''
        try:
            ace_int = int(integer, 0)
        except ValueError:
            raise WConvException(f"from_int(... - Specified value '{integer}' is not an integer.")

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

    def toggle_permission(integer, permissions):
        '''
        Takes an ace in integer format and toggles the specified permissions on it.

        Parameters:
            integer         (string)            Integer value as string (hex also allowed)
            permissions     (list[string])      List of permission to toggle (GA, GR, GW, GE, CC, ...)

        Returns:
            integer         (string)            Resulting ace value as integer in hex format
        '''
        try:
            ace_int = int(integer, 0)
        except ValueError:
            raise WConvException(f"from_int(... - Specified value '{integer}' is not an integer.")

        for permission in permissions:

            try:
                hex_value = ACCESS_MASK_HEX_REVERSE[permission]
                ace_int = ace_int ^ hex_value

            except KeyError:
                raise WConvException(f"toggle_permission(... - Unknown permission name '{permission}'")

        return "0x{:08x}".format(ace_int)
