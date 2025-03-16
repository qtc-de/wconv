#!/usr/bin/python3

from __future__ import annotations

import re

from wconv import WConvException
from wconv.ace import Ace, TRUSTEES
from wconv.helpers import print_yellow, print_blue


SDDL_HEADERS = {
    "O": "Owner",
    "G": "Group",
    "D": "DACL",
    "S": "SACL"
}

ACL_FLAGS = {
    "P": "PROTECTED",
    "AI": "ACL_INHERITANCE",
    "AR": "LEGACY_ACL_INHERITANCE"
}


class Sddl:
    '''
    The Sddl class represents a Windows Sddl for an particular object.
    E.g.: D:PAI(D;OICI;FA;;;BG)(A;OICI;FA;;;BA)(A;OICIIO;FA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BU)
    '''
    # regex definitions to parse required elements from sddl
    re_owner = re.compile('O:([^:()]+)(?=[DGS]:)')
    re_group = re.compile('G:([^:()]+)(?=[DOS]:)')
    re_acl_type = re.compile('([DS]:(P|AI|AR)*)')
    re_ace = re.compile(r'\((([^\);]*;){5}[^\)]*)\)')

    def __init__(self, owner: str, group: str, acl_type: str, acl_flags: list[str], ace_list: list[Ace]) -> None:
        '''
        The init function takes the different components of a Sddl and creates an object out of
        them. It should not be called directly. Instead, the helper functions 'from_... should
        be used.

        Parameters:
            owner           Owner of the corresponding object
            group           Group of the corresponding object
            acl_type        Only DACL is currently supported
            acl_flags       ACL flags according to the SDDL specification
            ace_list        List of Ace objects parsed from the sddl
        '''
        self.owner = owner
        self.group = group
        self.acl_type = acl_type
        self.acl_flags = acl_flags
        self.ace_list = ace_list

    def pretty_print(self, indent: str = ' ') -> None:
        '''
        Prints the Sddl and the contained Aces in a formatted and colored format. Not
        ideal for a library, however, currently we can live with it.

        Parameters:
            indent          Spaces after the '[+]' prefix

        Returns:
            None
        '''
        print_blue(f'[+]{indent}ACL Type:\t', end='')
        print_yellow(self.acl_type)

        print_blue(f'[+]{indent}Owner:\t', end='')
        print_yellow(self.owner)

        print_blue(f'[+]{indent}Group:\t', end='')
        print_yellow(self.group)

        print_blue(f'[+]{indent}ACL Flags:')

        for flag in self.acl_flags:
            print_blue('[+]', end='')
            print_yellow(f'{indent}\t\t+ {flag}')

        print_blue(f'[+]{indent}ACE List:')
        print_blue('[+] ==================================')

        for ace in self.ace_list:
            ace.pretty_print(indent=indent + ' '*4)
            print_blue('[+] ==================================')

    def get_owner(sddl_string: str) -> str:
        '''
        Returns the owner contained inside a SDDL string or None if no owner
        was specified.

        Paramaters:
            sddl_string         Portion containing the owner is sufficient

        Returns:
            Object owner or None
        '''
        match = Sddl.re_owner.search(sddl_string)

        if match:

            owner = match.group(1)
            if owner in TRUSTEES:
                owner = TRUSTEES[owner]

        else:
            owner = None

        return owner

    def get_group(sddl_string: str) -> str:
        '''
        Returns the group contained inside a SDDL string or None if no group
        was specified.

        Paramaters:
            sddl_string         Portion containing the group is sufficient

        Returns:
            Object group or None
        '''
        match = Sddl.re_group.search(sddl_string)

        if match:

            group = match.group(1)
            if group in TRUSTEES:
                group = TRUSTEES[group]

        else:
            group = None

        return group

    def get_acl_flags(acl_flags_string: str) -> str:
        '''
        Takes the SDDL portion behind the 'D:' (acl flags) and returns a list of the corresponding
        contained ACL flags.

        Paramaters:
            acl_flags_strings   Sring containing the ACL flags ('D:THISONE(')

        Returns:
            List of contained ACL flags
        '''
        acl_flags = []

        if 'P' in acl_flags_string:
            acl_flags.append(ACL_FLAGS['P'])

        if 'AI' in acl_flags_string:
            acl_flags.append(ACL_FLAGS['AI'])

        if 'AR' in acl_flags_string:
            acl_flags.append(ACL_FLAGS['AR'])

        return acl_flags

    def get_ace_list(ace_string: str, perm_type: str = 'file'):
        '''
        Takes the SDDL portion that contains the ACEs and returns a list of corresponding ACE objects.

        Paramaters:
            ace_string          SDDL portion that contains the ACEs
            perm_type           Permission type for ACE generation

        Returns:
            Corresponding list of ACE objects
        '''
        ace_strings = Sddl.re_ace.findall(ace_string)
        ace_strings = list(map(lambda x: x[0], ace_strings))

        ace_list = []
        for ace_string in ace_strings:

            ace = Ace.from_string(ace_string, perm_type=perm_type)
            ace_list.append(ace)

        return ace_list

    def from_string(sddl_string: str, perm_type: str = 'file') -> Sddl:
        '''
        Parses an SDDL string an creates the corresponding Sddl object out of it.

        Parameters:
            sddl_string         String that represents the sddl
            perm_type           Type of the corresponding object (file, service, ...)

        Returns:
            sddl_object
        '''
        # Split sddl header from ace strings
        try:
            header_index = sddl_string.index('(')
            sddl_header_string = sddl_string[:header_index]
            sddl_ace_string = sddl_string[header_index:]

        except ValueError:
            raise WConvException("parse_sddl(... - Input string is no valid SDDL.")

        # Extract the acl type and the corresponding acl flags
        match = Sddl.re_acl_type.search(sddl_header_string)

        if not match:
            raise WConvException("parse_sddl(... - Input string is no valid SDDL.")

        # Save acl type
        acl_type_split = match.group(0).split(':')

        if acl_type_split[0] == 'D':
            acl_type = 'DACL'

        else:
            raise WConvException("parse_sddl(... - Input string describes no DACL. Other formarts are not supported.")

        acl_flags = Sddl.get_acl_flags(acl_type_split[1])
        owner = Sddl.get_owner(sddl_header_string)
        group = Sddl.get_group(sddl_header_string)
        ace_list = Sddl.get_ace_list(sddl_ace_string, perm_type)

        return Sddl(owner, group, acl_type, acl_flags, ace_list)

    def add_everyone(sddl_string: str) -> str:
        '''
        Adds full permissions for everyone on the specified sddl_string.

        Parameters:
            sddl_string         SDDL string

        Returns:
            SDDL string with full permissions for everyone
        '''
        return sddl_string + Ace.ace_everyone

    def add_anonymous(sddl_string: str) -> str:
        '''
        Adds full permissions for anonymous on the specified sddl_string.

        Parameters:
            sddl_string         SDDL string

        Returns:
            SDDL string with full permissions for anonymous
        '''
        return sddl_string + Ace.ace_anonymous
