#!/usr/bin/python3

import re
import base64
import binascii

from termcolor import cprint
from wconv import WConvException

WELL_KNOWN_SIDS = {
    "S-1-0-0": "NULL",
    "S-1-1-0": "EVERYONE",
    "S-1-2-0": "LOCAL",
    "S-1-2-1": "CONSOLE_LOGON",
    "S-1-3-0": "CREATOR_OWNER",
    "S-1-3-1": "CREATOR_GROUP",
    "S-1-3-2": "OWNER_SERVER",
    "S-1-3-3": "GROUP_SERVER",
    "S-1-3-4": "OWNER_RIGHTS",
    "S-1-5": "NT_AUTHORITY",
    "S-1-5-1": "DIALUP",
    "S-1-5-2": "NETWORK",
    "S-1-5-3": "BATCH",
    "S-1-5-4": "INTERACTIVE",
    "S-1-5-5-x-y": "LOGON_ID",
    "S-1-5-6": "SERVICE",
    "S-1-5-7": "ANONYMOUS",
    "S-1-5-8": "PROXY",
    "S-1-5-9": "ENTERPRISE_DOMAIN_CONTROLLERS",
    "S-1-5-10": "PRINCIPAL_SELF",
    "S-1-5-11": "AUTHENTICATED_USERS",
    "S-1-5-12": "RESTRICTED_CODE",
    "S-1-5-13": "TERMINAL_SERVER_USER",
    "S-1-5-14": "REMOTE_INTERACTIVE_LOGON",
    "S-1-5-15": "THIS_ORGANIZATION",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "LOCAL_SYSTEM",
    "S-1-5-19": "LOCAL_SERVICE",
    "S-1-5-20": "NETWORK_SERVICE",
    "S-1-5-21-[-0-9]+-498": "ENTERPRISE_READONLY_DOMAIN_CONTROLLERS",
    "S-1-5-21-0-0-0-496": "COMPOUNDED_AUTHENTICATION",
    "S-1-5-21-0-0-0-497": "CLAIMS_VALID",
    "S-1-5-21-[-0-9]+-500": "ADMINISTRATOR",
    "S-1-5-21-[-0-9]+-501": "GUEST",
    "S-1-5-21-[-0-9]+-502": "KRBTGT",
    "S-1-5-21-[-0-9]+-512": "DOMAIN_ADMINS",
    "S-1-5-21-[-0-9]+-513": "DOMAIN_USERS",
    "S-1-5-21-[-0-9]+-514": "DOMAIN_GUESTS",
    "S-1-5-21-[-0-9]+-515": "DOMAIN_COMPUTERS",
    "S-1-5-21-[-0-9]+-516": "DOMAIN_DOMAIN_CONTROLLERS",
    "S-1-5-21-[-0-9]+-517": "CERT_PUBLISHERS",
    "S-1-5-21-[-0-9]+-518": "SCHEMA_ADMINISTRATORS",
    "S-1-5-21-[-0-9]+-519": "ENTERPRISE_ADMINS",
    "S-1-5-21-[-0-9]+-520": "GROUP_POLICY_CREATOR_OWNERS",
    "S-1-5-21-[-0-9]+-521": "READONLY_DOMAIN_CONTROLLERS",
    "S-1-5-21-[-0-9]+-522": "CLONEABLE_CONTROLLERS",
    "S-1-5-21-[-0-9]+-525": "PROTECTED_USERS",
    "S-1-5-21-[-0-9]+-526": "KEY_ADMINS",
    "S-1-5-21-[-0-9]+-527": "ENTERPRISE_KEY_ADMINS",
    "S-1-5-21-[-0-9]+-553": "RAS_SERVERS",
    "S-1-5-21-[-0-9]+-571": "ALLOWED_RODC_PASSWORD_REPLICATION_GROUP",
    "S-1-5-21-[-0-9]+-572": "DENIED_RODC_PASSWORD_REPLICATION_GROUP",
    "S-1-5-32": "BUILTIN",
    "S-1-5-32-544": "BUILTIN_ADMINISTRATORS",
    "S-1-5-32-545": "BUILTIN_USERS",
    "S-1-5-32-546": "BUILTIN_GUESTS",
    "S-1-5-32-547": "POWER_USERS",
    "S-1-5-32-548": "ACCOUNT_OPERATORS",
    "S-1-5-32-549": "SERVER_OPERATORS",
    "S-1-5-32-550": "PRINTER_OPERATORS",
    "S-1-5-32-551": "BACKUP_OPERATORS",
    "S-1-5-32-552": "REPLICATOR",
    "S-1-5-32-554": "ALIAS_PREW2KCOMPACC",
    "S-1-5-32-555": "REMOTE_DESKTOP",
    "S-1-5-32-556": "NETWORK_CONFIGURATION_OPS",
    "S-1-5-32-557": "INCOMING_FOREST_TRUST_BUILDERS",
    "S-1-5-32-558": "PERFMON_USERS",
    "S-1-5-32-559": "PERFLOG_USERS",
    "S-1-5-32-560": "WINDOWS_AUTHORIZATION_ACCESS_GROUP",
    "S-1-5-32-561": "TERMINAL_SERVER_LICENSE_SERVERS",
    "S-1-5-32-562": "DISTRIBUTED_COM_USERS",
    "S-1-5-32-568": "IIS_IUSRS",
    "S-1-5-32-569": "CRYPTOGRAPHIC_OPERATORS",
    "S-1-5-32-573": "EVENT_LOG_READERS",
    "S-1-5-32-574": "CERTIFICATE_SERVICE_DCOM_ACCESS",
    "S-1-5-32-575": "RDS_REMOTE_ACCESS_SERVERS",
    "S-1-5-32-576": "RDS_ENDPOINT_SERVERS",
    "S-1-5-32-577": "RDS_MANAGEMENT_SERVERS",
    "S-1-5-32-578": "HYPER_V_ADMINS",
    "S-1-5-32-579": "ACCESS_CONTROL_ASSISTANCE_OPS",
    "S-1-5-32-580": "REMOTE_MANAGEMENT_USERS",
    "S-1-5-33": "WRITE_RESTRICTED_CODE",
    "S-1-5-64-10": "NTLM_AUTHENTICATION",
    "S-1-5-64-14": "SCHANNEL_AUTHENTICATION",
    "S-1-5-64-21": "DIGEST_AUTHENTICATION",
    "S-1-5-65-1": "THIS_ORGANIZATION_CERTIFICATE",
    "S-1-5-80": "NT_SERVICE",
    "S-1-5-84-0-0-0-0-0": "USER_MODE_DRIVERS",
    "S-1-5-113": "LOCAL_ACCOUNT",
    "S-1-5-114": "LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP",
    "S-1-5-1000": "OTHER_ORGANIZATION",
    "S-1-15-2-1": "ALL_APP_PACKAGES",
    "S-1-16-0": "ML_UNTRUSTED",
    "S-1-16-4096": "ML_LOW",
    "S-1-16-8192": "ML_MEDIUM",
    "S-1-16-8448": "ML_MEDIUM_PLUS",
    "S-1-16-12288": "ML_HIGH",
    "S-1-16-16384": "ML_SYSTEM",
    "S-1-16-20480": "ML_PROTECTED_PROCESS",
    "S-1-16-28672": "ML_SECURE_PROCESS",
    "S-1-18-1": "AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY",
    "S-1-18-2": "SERVICE_ASSERTED_IDENTITY",
    "S-1-18-3": "FRESH_PUBLIC_KEY_IDENTITY",
    "S-1-18-4": "KEY_TRUST_IDENTITY",
    "S-1-18-5": "KEY_PROPERTY_MFA",
    "S-1-18-6": "KEY_PROPERTY_ATTESTATION"
}


class SecurityIdentifier:
    '''
    Represents a Windows Security Identifier.
    '''

    def __init__(self, binary):
        '''
        Initializes a SecurityIdentifier object by using its raw (bytes) representation.

        Parameters:
            binary              (bytes)             Security identifier in bytes format

        Returns:
            SecurityIdentifier  (SecurityIdentifier)
        '''
        self.raw_sid = binary
        self.parsed_sid = SecurityIdentifier.parse_binary(binary)
        self.formatted_sid = SecurityIdentifier.format_sid(self.parsed_sid)
        self.well_known = SecurityIdentifier.get_well_known(self.formatted_sid)

    def __str__(self):
        '''
        Returns a simple representation of the SecurityIdentifier object. Useful for
        debugging purposes.

        Parameters:
            None

        Returns:
            None
        '''
        result = f'{self.formatted_sid}'

        if self.well_known:
            result += f' ({self.well_known})'

        return result

    def pretty_print(self):
        '''
        Prints a colored and formatted output of the SecurityIdentifier object.

        Parameters:
            None

        Returns:
            None
        '''
        cprint('[+] SID: ', 'blue', end='')
        cprint(self.formatted_sid, 'yellow', end='')

        if self.well_known:
            cprint(' (', 'blue', end='')
            cprint(self.well_known, 'yellow', end='')
            cprint(')', 'blue', end='')

        print()

    def parse_binary(binary):
        '''
        Parse the different components of a binary SID and return them as an array of integers.

        Parameters:
            binary          (bytes)             binary representation of a SID

        Returns:
            items           (list[int])         list of integer components of the SID
        '''
        revision = binary[0]
        if revision != 1:
            raise WConvException(f"parse_sid(... - Unknown SID version '{revision}'.")

        dash_count = binary[1]
        if dash_count * 4 + 8 != len(binary):
            raise WConvException("parse_sid(... - SID has an invalid length.")

        authority = int.from_bytes(binary[2:8], 'big')

        items = [revision, authority]
        for count in range(0, dash_count * 4, 4):
            item = binary[8 + count:8 + count + 4]
            item = int.from_bytes(item, 'little')
            items.append(item)

        return items

    def format_sid(sid_value):
        '''
        Takes a Security Identifier and converts it into a SID string.

        Parameters:
            sid_vaue        (bytes|list[int])   Security identifier either as raw bytes or as parsed list

        Returns:
            result          (string)            SID string
        '''
        if isinstance(sid_value, bytes):
            sid_value = SecurityIdentifier.parse_binary(sid_value)

        result = 'S-'
        for item in sid_value:
            result += str(item)
            result += '-'

        result = result[0:-1]
        return result

    def get_well_known(sid_string):
        '''
        Get the well known name for the specified SID string.

        Paramaters:
            sid_string      (string)            SID string to look for

        Returns:
            value           (string)            Well known name of the SID or None
        '''
        for key, value in WELL_KNOWN_SIDS.items():

            if re.match(f'^{key}$', sid_string):
                return value

        return None

    def to_b64(self):
        '''
        Converts an SecurityIdentifier object to base64.

        Parameters:
            None

        Returns:
            b64             (string)            Base64 encoded SID value
        '''
        b64 = base64.b64encode(self.raw_sid)
        return b64.decode('utf-8')

    def from_b64(b64_sid):
        '''
        Creates an SecurityIdentifier object from a base64 string.

        Paramaters:
            b64_sid         (string)            SID in base64 format

        Returns:
            object          (SecurityIdentifier)
        '''
        try:
            binary = base64.b64decode(b64_sid)
        except Exception as e:
            raise WConvException(f"from_b64(... - Specified base64 string is malformed: '{str(e)}'.")

        return SecurityIdentifier(binary)

    def from_hex(hex_sid):
        '''
        Creates an SecurityIdentifier object from a hex string.

        Paramaters:
            hex_sid         (string)            SID in hex format

        Returns:
            object          (SecurityIdentifier)
        '''
        try:
            binary = binascii.unhexlify(hex_sid)
        except binascii.Error as e:
            raise WConvException(f"from_hex(... - Specified hex string is malformed: '{str(e)}'.")

        return SecurityIdentifier(binary)

    def from_formatted(sid_string):
        '''
        Creates an SecurityIdentifier object from an SID string.

        Paramaters:
            sid_string      (string)            SID in string format

        Returns:
            object          (SecurityIdentifier)
        '''
        if sid_string[0:2] != 'S-':
            raise WConvException(f"from_formatted(... - Specified string '{sid_string}' is not a valid SID.")

        split = sid_string.split('-')
        split = split[1:]

        if split[0] != '1':
            raise WConvException(f"from_formatted(... - Unknown SID version '{split[0]}'.")

        revision = int(split[0])
        dash_count = len(split) - 2

        if dash_count < 0:
            raise WConvException(f"from_formatted(... - Specified string '{sid_string}' is not a valid SID.")

        binary = int.to_bytes(revision, 1, 'big')
        binary += int.to_bytes(dash_count, 1, 'big')

        try:
            binary += int.to_bytes(int(split[1]), 6, 'big')

            for count in range(2, len(split)):
                binary += int.to_bytes(int(split[count]), 4, 'little')

        except (ValueError, OverflowError) as e:
            raise WConvException(f"from_formatted(... - Specified string '{sid_string}' contains invalid value: {str(e)}.")

        return SecurityIdentifier(binary)
