#!/usr/bin/python3

from __future__ import annotations

import re
import wconv.ace

from wconv import WConvException
from wconv.acl import Acl
from wconv.sid import SecurityIdentifier
from wconv.helpers import print_yellow, print_blue


SDDL_HEADERS = {
    'O': 'Owner',
    'G': 'Group',
    'D': 'DACL',
    'S': 'SACL'
}


SDDL_ACE_TYPES = {
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


SDDL_ACE_FLAGS = {
    'OI': 0x01,
    'CI': 0x02,
    'NP': 0x04,
    'IO': 0x08,
    'ID': 0x10,
    'CR': 0x20,
    'SA': 0x40,
    'FA': 0x80,
}


SDDL_OTHER_FLAGS = {
    'P':  'PROTECTED',
    'AI': 'ACL_INHERITANCE',
    'AR': 'LEGACY_ACL_INHERITANCE'
}


ACCESS_MASK_HEX = {
    # generic access rights
    'GA': 0x10000000,
    'GX': 0x20000000,
    'GW': 0x40000000,
    'GR': 0x80000000,
    # standard access rights
    'SD': 0x00010000,
    'RC': 0x00020000,
    'WD': 0x00040000,
    'WO': 0x00080000,
    # directory service access rights
    'CC': 0x00000001,
    'DC': 0x00000002,
    'LC': 0x00000004,
    'SW': 0x00000008,
    'RP': 0x00000010,
    'WP': 0x00000020,
    'DT': 0x00000040,
    'LO': 0x00000080,
    'CR': 0x00000100,
    # file access rights
    'FA': 0x000f01ff,
    'FR': 0x00020089,
    'FW': 0x00020116,
    'FX': 0x000200a0,
    # registry access rights
    'KA': 0x000f003f,
    'KR': 0x00020019,
    'KW': 0x00020006,
    'KE': 0x00020019,
}


GROUPED_PERMISSIONS = {
    'FA': 'READ_CONTROL,DELETE,WRITE_DAC,WRITE_OWNER,SYNCHRONIZE,READ,WRITE,APPEND,READ_EXTENDED_ATTRIBUTES,WRITE_EXTENDED_ATTRIBUTES,EXECUTE,MEANINGLESS,READ_ATTRIBUTES,WRITE_ATTRIBUTES',
    'FR': 'READ_CONTROL,READ,READ_ATTRIBUTES,READ_EXTENDED_ATTRIBUES,SYNCHRONIZE',
    'FW': 'READ_CONTROL,WRITE,WRITE_ATTRIBUTES,WRITE_EXTENDED_ATTRIBUES,APPEND,SYNCHRONIZE',
    'FX': 'READ_CONTROL,READ_ATTRIBUTES,EXECUTE,SYNCHRONIZE',
    'KA': 'READ_CONTROL,DELETE,WRITE_DAC,WRITE_OWNER,QUERY,SET,CREATE_SUB_KEY,ENUM_SUB_KEYS,NOTIFY,CREATE_LINK',
    'KR': 'READ_CONTROL,QUERY,ENUM_SUB_KEYS,NOTIFY',
    'KW': 'READ_CONTROL,SET,CREATE_SUB_KEY',
    'KE': 'READ_CONTROL,QUERY,ENUM_SUB_KEYS,NOTIFY'
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


re_owner = re.compile('O:([^:()]+)(?=[DGS]:)')
re_group = re.compile('G:([^:()]+)(?=[DOS]:)')
re_acl_type = re.compile('([DS]:(P|AI|AR)*)')
re_ace_perm = re.compile(r'\((([^\);]*;){5}[^\)]*)\)')

sddl_str_everyone = '(A;;GAGRGWGXRCSDWDWOSSCCDCLCSWRPWPDTLOCR;;;WD)'
sddl_str_anonymous = '(A;;GAGRGWGXRCSDWDWOSSCCDCLCSWRPWPDTLOCR;;;AN)'


def get_owner(sddl_string: str) -> SecurityIdentifier:
    '''
    Returns the owner contained inside a SDDL string in form of a
    SecurityIdentifier.

    Paramaters:
        sddl_string         sddl string to obtian the owner from

    Returns:
        SecurityIdentifier for the owner
    '''
    match = re_owner.search(sddl_string)

    if match:

        owner = match.group(1)

        if owner in TRUSTEES:

            owner = TRUSTEES[owner]
            return SecurityIdentifier.from_well_known(owner)

        return SecurityIdentifier.from_formatted(owner)

    raise WConvException(f'Unable to obtain owner from sddl: {sddl_string}')


def get_group(sddl_string: str) -> SecurityIdentifier:
    '''
    Returns the group contained inside a SDDL string as SecurityIdentifier.

    Paramaters:
        sddl_string         SDDL string to obtain the group from

    Returns:
        SecurityIdentifier representing the group
    '''
    match = re_group.search(sddl_string)

    if match:

        group = match.group(1)

        if group in TRUSTEES:
            group = TRUSTEES[group]
            return SecurityIdentifier.from_well_known(group)

        return SecurityIdentifier.from_formatted(group)

    raise WConvException(f'Unable to obtain owner from sddl: {sddl_string}')


def get_type(sddl_string: str) -> str:
    '''
    Returns the type of the specified sddl_string. At the time of writing,
    only DACL and SACL are recognized.

    Paramaters:
        sddl_string         sddl_string to obtain the type from

    Returns:
        DACL or SACL
    '''
    match = re_sddl_acl_type.search(sddl_string)

    if match:

        sddl_type = match.group(1)
        
        if sddl_type.startswith('D'):
            return 'DACL'

        if sddl_type.startswith('S'):
            return 'SACL'
        
    return None


def get_acl(sddl_string: str, perm_type: str = 'file') -> Acl:
    '''
    Create an ACL object from the specified sddl string.

    Paramaters:
        sddl_string         sddl string to obtain the ACL from
        perm_type           Permission type for ACL generation

    Returns:
        ACL for the specified sddl string
    '''
    ace_strings = Sddl.re_ace.findall(ace_string)
    ace_strings = list(map(lambda x: x[0], ace_strings))
    
    return Acl.from_sddl(''.join(ace_strings))


def map_ace_flags(ace_flag_sddl: str) -> list[str]:
    '''
    Parses the flag-portion of an SDDL string and returns the ACE
    flags as strings.

    Paramaters:
        ace_flag_sddl       sddl representation of the ace flags

    Returns:
        ACE flags as list of strings
    '''
    ace_flags = []

    for ctr in range(0, len(ace_flag_sddl), 2):

        try:
            ace_flag = ace_flag_sddl[ctr:ctr+2]
            ace_flag = wconv.ace.ACE_FLAGS[SDDL_ACE_FLAGS[ace_flag]]
            ace_flags.append(ace_flag)

        except KeyError:
            raise WConvException(f"get_ace_flags(... - Unknown ACE flag '{ace_flag}'.")

    return ace_flags


def get_ace_permissions(sddl_permission_string: str, perm_type: str = 'file') -> list[str]:
    '''
    Takes the ACE portion of an sddl containing the permission and returns a list
    of the corresponding parsed permission strings.

    Paramaters:
        sddl_permission_string      String containing the sddl permissions
        perm_type                   Permission type (file, service, ...)

    Returns:
        List of corresponding permissions
    '''
    permissions = []
    perm_dict = wconv.ace.get_permission_dict(perm_type)

    for ctr in range(0, len(sddl_permission_string), 2):

        try:
            permission = sddl_permission_string[ctr:ctr+2]

            if permission in GROUPED_PERMISSIONS:
                permission = GROUPED_PERMISSIONS[permission]
                permission = permission.split(',')
                permissions += permission

            else:
                numeric = ACCESS_MASK_HEX[permission]
                permission = perm_dict[numeric]
                permissions.append(permission)

        except KeyError:
            raise WConvException(f'from_string(... - Unknown permission name: {permission}.')

    return permissions


def get_ace_numeric(sddl_permission_string: str) -> int:
    '''
    Takes the ACE portion of an sddl containing the permission and returns a numeric
    representation of the permissions

    Paramaters:
        sddl_permission_string      String containing the sddl permissions
        perm_type                   Permission type (file, service, ...)

    Returns:
        numeric permissions
    '''
    ace_int = 0

    for ctr in range(0, len(sddl_permission_string), 2):

        permission = sddl_permission_string[ctr:ctr+2]

        try:
            ace_int += ACCESS_MASK_HEX[permission]

        except KeyError:
            raise WConvException(f"from_string(... - Unknown permission name '{permission}'.")

    return ace_int


def add_everyone(sddl_string: str) -> str:
    '''
    Adds full permissions for everyone on the specified sddl_string.

    Parameters:
        sddl_string         SDDL string

    Returns:
        SDDL string with full permissions for everyone
    '''
    return sddl_string + Sddl.sddl_everyone


def add_anonymous(self, sddl_string: str) -> str:
    '''
    Adds full permissions for anonymous on the specified sddl_string.

    Parameters:
        sddl_string         SDDL string

    Returns:
        SDDL string with full permissions for anonymous
    '''
    return sddl_string + Sddl.sddl_anonymous

