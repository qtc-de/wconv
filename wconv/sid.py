#!/usr/bin/python3

from __future__ import annotations

import re
import base64
import binascii

from wconv import WConvException
from wconv.helpers import print_yellow, print_blue, print_magenta


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


KNOWN_SIDS = {}


class SecurityIdentifier:
    '''
    Represents a Windows Security Identifier.
    '''

    def __init__(self, binary: bytes, check_length: bool = True) -> None:
        '''
        Initializes a SecurityIdentifier object by using its raw (bytes) representation.

        Parameters:
            binary              Security identifier in bytes format
            check_length        Whether to check the length of the inpurt string

        Returns:
            SecurityIdentifier
        '''
        self.raw_sid = binary

        self.parsed_sid = SecurityIdentifier.parse_binary(binary, check_length)
        self.formatted_sid = SecurityIdentifier.format_sid(self.parsed_sid)

        self.name = SecurityIdentifier.get_well_known(self.formatted_sid) or KNOWN_SIDS.get(self.formatted_sid)

    def __str__(self) -> str:
        '''
        Returns the SecurityIdentifier in string format.

        Parameters:
            None

        Returns:
            String representation of the SID
        '''
        return self.formatted_sid

    def pretty_print(self, end: str = '\n') -> None:
        '''
        Prints a colored and formatted output of the SecurityIdentifier object.
        This includes the resolved human readable name, if present.

        Parameters:
            None

        Returns:
            None
        '''
        print_yellow(self.formatted_sid, end='')

        if self.name:
            print_magenta(f' ({self.name})', end='')

        print(end=end)

    def get_binary_length(self) -> int:
        '''
        Returns the binary length of the sid.

        Parameters:
            None

        Returns:
            Binary length of the SID as int
        '''
        dash_count = self.binary[1]
        return dash_count * 4 + 8

    def get_well_known(sid_string: str) -> str:
        '''
        Get the well known name for the specified SID string. Notice that the
        WELL_KNOWN_SIDS dictionary contains regex like expression. A simple
        dictionary lookup is therefore not sufficient.

        Paramaters:
            sid_string      SID string to look for

        Returns:
            Well known name of the SID or None
        '''
        for key, value in WELL_KNOWN_SIDS.items():

            if re.match(f'^{key}$', sid_string):
                return value

        return None

    def parse_binary(binary: bytes, check_length: bool) -> list[int]:
        '''
        Parse the different components of a binary SID and return them as an array of integers.

        Parameters:
            binary          binary representation of a SID
            check_length    whether to check the length of the input string

        Returns:
            list of integer components of the SID
        '''
        revision = binary[0]

        if revision != 1:
            raise WConvException(f"parse_sid(... - Unknown SID version '{revision}'.")

        dash_count = binary[1]

        if check_length and dash_count * 4 + 8 != len(binary):
            raise WConvException("parse_sid(... - SID has an invalid length.")

        authority = int.from_bytes(binary[2:8], 'big')

        items = [revision, authority]

        for count in range(0, dash_count * 4, 4):
            item = binary[8 + count:8 + count + 4]
            item = int.from_bytes(item, 'little')
            items.append(item)

        return items

    def format_sid(sid_value: bytes | list[int]) -> str:
        '''
        Takes a Security Identifier and converts it into a SID string.

        Parameters:
            sid_vaue        Security identifier either as raw bytes or as parsed list

        Returns:
            SID string
        '''
        if isinstance(sid_value, bytes):
            sid_value = SecurityIdentifier.parse_binary(sid_value)

        result = 'S-'

        for item in sid_value:
            result += str(item)
            result += '-'

        return result[0:-1]

    def to_b64(self) -> str:
        '''
        Converts an SecurityIdentifier object to base64.

        Parameters:
            None

        Returns:
            Base64 encoded SID value
        '''
        b64 = base64.b64encode(self.raw_sid)
        return b64.decode('utf-8')

    def from_b64(b64_sid: str) -> SecurityIdentifier:
        '''
        Creates an SecurityIdentifier object from a base64 string.

        Paramaters:
            b64_sid         SID in base64 format

        Returns:
            SecurityIdentifier
        '''
        try:
            binary = base64.b64decode(b64_sid)

        except Exception as e:
            raise WConvException(f"from_b64(... - Specified base64 string is malformed: '{str(e)}'.")

        return SecurityIdentifier(binary)

    def from_hex(hex_sid: str) -> SecurityIdentifier:
        '''
        Creates an SecurityIdentifier object from a hex string.

        Paramaters:
            hex_sid         SID in hex format

        Returns:
            SecurityIdentifier
        '''
        try:
            binary = binascii.unhexlify(hex_sid)

        except binascii.Error as e:
            raise WConvException(f"from_hex(... - Specified hex string is malformed: '{str(e)}'.")

        return SecurityIdentifier(binary)

    def from_formatted(sid_string: str) -> SecurityIdentifier:
        '''
        Creates an SecurityIdentifier object from an SID string.

        Paramaters:
            sid_string      SID in string format

        Returns:
            SecurityIdentifier
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
