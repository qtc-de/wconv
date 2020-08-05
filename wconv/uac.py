#!/usr/bin/python3

from termcolor import cprint
from wconv import WConvException

UAC_DICT = dict([
    (0x00000001, "SCRIPT"),
    (0x00000002, "ACCOUNTDISABLE"),
    (0x00000008, "HOMEDIR_REQUIRED"),
    (0x00000010, "LOCKOUT"),
    (0x00000020, "PASSWD_NOTREQD"),
    (0x00000040, "PASSWD_CANT_CHANGE"),
    (0x00000080, "ENCRYPTED_TEXT_PWD_ALLOWED"),
    (0x00000100, "TEMP_DUPLICATE_ACCOUNT"),
    (0x00000200, "NORMAL_ACCOUNT"),
    (0x00000800, "INTERDOMAIN_TRUST_ACCOUNT"),
    (0x00001000, "WORKSTATION_TRUST_ACCOUNT"),
    (0x00002000, "SERVER_TRUST_ACCOUNT"),
    (0x00010000, "DONT_EXPIRE_PASSWORD"),
    (0x00020000, "MNS_LOGON_ACCOUNT"),
    (0x00040000, "SMARTCARD_REQUIRED"),
    (0x00080000, "TRUSTED_FOR_DELEGATION"),
    (0x00100000, "NOT_DELEGATED"),
    (0x00200000, "USE_DES_KEY_ONLY"),
    (0x00400000, "DONT_REQ_PREAUTH"),
    (0x00800000, "PASSWORD_EXPIRED"),
    (0x01000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
    (0x04000000, "PARTIAL_SECRETS_ACCOUNT")
])

UAC_DICT_REVERSE = dict([
    ("SCRIPT",                          0x00000001),
    ("ACCOUNTDISABLE",                  0x00000002),
    ("HOMEDIR_REQUIRED",                0x00000008),
    ("LOCKOUT",                         0x00000010),
    ("PASSWD_NOTREQD",                  0x00000020),
    ("PASSWD_CANT_CHANGE",              0x00000040),
    ("ENCRYPTED_TEXT_PWD_ALLOWED",      0x00000080),
    ("TEMP_DUPLICATE_ACCOUNT",          0x00000100),
    ("NORMAL_ACCOUNT",                  0x00000200),
    ("INTERDOMAIN_TRUST_ACCOUNT",       0x00000800),
    ("WORKSTATION_TRUST_ACCOUNT",       0x00001000),
    ("SERVER_TRUST_ACCOUNT",            0x00002000),
    ("DONT_EXPIRE_PASSWORD",            0x00010000),
    ("MNS_LOGON_ACCOUNT",               0x00020000),
    ("SMARTCARD_REQUIRED",              0x00040000),
    ("TRUSTED_FOR_DELEGATION",          0x00080000),
    ("NOT_DELEGATED",                   0x00100000),
    ("USE_DES_KEY_ONLY",                0x00200000),
    ("DONT_REQ_PREAUTH",                0x00400000),
    ("PASSWORD_EXPIRED",                0x00800000),
    ("TRUSTED_TO_AUTH_FOR_DELEGATION",  0x01000000),
    ("PARTIAL_SECRETS_ACCOUNT",         0x04000000)
])


class UserAccountControl:
    '''
    Represents a UserAccountControl entry of Active Directory.
    '''

    def __init__(self, uac_value):
        '''
        Consrutcs a new UserAccountControl object from an UAC integer in string representation.

        Paramaters:
            uac_value           (string)            UAC integer value in string format

        Returns:
            UserAccountControl  (UserAccountControl)
        '''
        try:
            uac_int = int(uac_value, 0)
        except ValueError:
            raise WConvException(f"__init__(... - Specified UAC value '{uac_value}' is not an integer.")

        self.uac_value = uac_int
        self.flags = UserAccountControl.parse_flags(uac_int)

    def __str__(self):
        '''
        Converts a UserAccountControl object into a simple formatted string. Useful for debugging purposes.

        Paramaters:
            None

        Returns:
            result              (string)            UserAccountControl object in string representation
        '''
        result = f'UserAccountControl: {self.uac_value}\n'

        for flag in self.flags:
            result += f'    {flag}\n'

        return result[:-1]

    def pretty_print(self):
        '''
        Prints some formatted and colored information about the UserAccountControl object.

        Parameters:
            None

        Returns:
            None
        '''
        cprint('[+] UserAccountControl:\t', 'blue', end='')
        cprint('{} (0x{:08x})'.format(self.uac_value, self.uac_value), 'yellow')

        for flag in self.flags:
            cprint('[+]\t', 'blue', end='')
            cprint(f'+ {flag}', 'yellow')

    def toggle_flag(self, flags):
        '''
        Toggles the specified UAC flag on the UserAccountControl object.

        Parameters:
            flags           (list[str])         List of flags to enable on the UAC object

        Returns:
            None
        '''
        for flag in flags:

            try:
                numeric = UAC_DICT_REVERSE[flag]
                self.uac_value = self.uac_value ^ numeric
                self.flags = UserAccountControl.parse_flags(self.uac_value)

            except KeyError:
                raise WConvException(f"toggle_flag(... - Specified UAC flag '{flag}' does not exist.")

    def parse_flags(uac_value):
        '''
        Takes an integer UserAccountControl value and returns a formatted string
        containing the corresponding flags.

        Paramaters:
            uac_value       (int)               UserAccountControl value

        Returns:
            flags           (list[string])      List of UAC flags
        '''
        flags = []

        for key, value in UAC_DICT.items():
            if uac_value & key:
                flags.append(value)

        return flags
