#!/usr/bin/python3

from __future__ import annotations

from wconv import WConvException
from wconv.helpers import print_yellow, print_blue, get_max


UAC_DICT = {
    0x00000001: 'SCRIPT',
    0x00000002: 'ACCOUNTDISABLE',
    0x00000008: 'HOMEDIR_REQUIRED',
    0x00000010: 'LOCKOUT',
    0x00000020: 'PASSWD_NOTREQD',
    0x00000040: 'PASSWD_CANT_CHANGE',
    0x00000080: 'ENCRYPTED_TEXT_PWD_ALLOWED',
    0x00000100: 'TEMP_DUPLICATE_ACCOUNT',
    0x00000200: 'NORMAL_ACCOUNT',
    0x00000800: 'INTERDOMAIN_TRUST_ACCOUNT',
    0x00001000: 'WORKSTATION_TRUST_ACCOUNT',
    0x00002000: 'SERVER_TRUST_ACCOUNT',
    0x00010000: 'DONT_EXPIRE_PASSWORD',
    0x00020000: 'MNS_LOGON_ACCOUNT',
    0x00040000: 'SMARTCARD_REQUIRED',
    0x00080000: 'TRUSTED_FOR_DELEGATION',
    0x00100000: 'NOT_DELEGATED',
    0x00200000: 'USE_DES_KEY_ONLY',
    0x00400000: 'DONT_REQ_PREAUTH',
    0x00800000: 'PASSWORD_EXPIRED',
    0x01000000: 'TRUSTED_TO_AUTH_FOR_DELEGATION',
    0x04000000: 'PARTIAL_SECRETS_ACCOUN',
}


def get_hex(uac: str) -> int:
    '''
    Obtain the hex value for a UAC by specifying it's
    string value.

    Parameters:
        uac         UAC in string representation

    Returns:
        uac as hex
    '''
    for hex_value, string_value in UAC_DICT.items():

        if string_value == uac:
            return hex_value
        

class UserAccountControl:
    '''
    Represents a UserAccountControl entry of Active Directory.
    '''

    def __init__(self, uac_value: int | str) -> None:
        '''
        Consrutcs a new UserAccountControl object from an UAC integer
        (optionally in string representation).

        Paramaters:
            uac_value       UAC integer value in string format

        Returns:
            UserAccountControl
        '''
        if isinstance(uac_value, int):
            uac_int = uac_value

        else:
            try:
                uac_int = int(uac_value, 0)

            except ValueError:
                raise WConvException(f"UserAccountControl.__init__(... - Specified UAC value '{uac_value}' is not an integer.")

        self.uac_value = uac_int

    def __str__(self) -> str:
        '''
        Converts a UserAccountControl object into a simple formatted string.
        Useful for debugging purposes.

        Paramaters:
            None

        Returns:
            UserAccountControl object in string representation
        '''
        result = f'UserAccountControl: {self.uac_value}\n'

        for flag in self.get_flags():
            result += f'    {flag}\n'

        return result[:-1]

    def pretty_print(self) -> None:
        '''
        Prints some formatted and colored information about the UserAccountControl object.

        Parameters:
            None

        Returns:
            None
        '''
        print_blue('[+] UserAccountControl:\t', end='')
        print_yellow('{} (0x{:08x})'.format(self.uac_value, self.uac_value))

        flags = self.get_flags()
        padding = get_max(flags)

        for flag in flags:
            print_blue('[+]\t', end='')
            print_yellow(f'+ {flag.ljust(padding)}', end='')
            print_blue(f' (0x{get_hex(flag):08x})')


    def toggle_flag(self, flags: list[str]) -> None:
        '''
        Toggles the specified UAC flag on the UserAccountControl object.

        Parameters:
            flags       List of flags to enable on the UAC object

        Returns:
            None
        '''
        for flag in flags:
            self.uac_value ^= get_hex(flag)

    def get_flags(self) -> list[str]:
        '''
        Takes an integer UserAccountControl value and returns a formatted string
        containing the corresponding flags.

        Paramaters:
            uac_value       UserAccountControl value

        Returns:
            List of UAC flags
        '''
        flags = []

        for key, value in UAC_DICT.items():

            if self.uac_value & key:
                flags.append(value)

        return flags
