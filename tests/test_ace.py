#!/usr/bin/python3

import pytest
import wconv.ace as a

from_string_format = 'ace_string, perm_type, ace_type, trustee, numeric, flags, perms'
from_string_tests = [
    ('(A;OICI;SDWD;;;BU)', 'file', 'ACCESS_ALLOWED', 'Users', 0x00050000,
        ['OBJECT_INHERIT', 'CONTAINER_INHERIT'], ['DELETE', 'WRITE_DAC']),

    ('(D;NPFA;GAWP;;;BA)', 'registry', 'ACCESS_DENIED', 'Administrators', 0x10000020,
        ['NO_PROPAGATE_INHERIT', 'FAILED_ACCESS'], ["GENERIC_ALL", "CREATE_LINK"]),

    ('(AU;SAID;CCDC;;;SY)', 'service', 'SYSTEM_AUDIT', 'Local System', 0x00000003,
        ['SUCCESSFUL_ACCESS', 'INHERITED'], ['QUERY_CONFIG', 'CHANGE_CONFIG']),

    ('(AL;IOSA;LCWP;;;BO)', 'token', 'SYSTEM_ALARM', 'Backup Operators', 0x00000024,
        ['INHERIT_ONLY', 'SUCCESSFUL_ACCESS'], ['IMPERSONATE', 'ADJUST_PRIVELEGES'])
]


@pytest.mark.parametrize(from_string_format, from_string_tests)
def test_ace_from_string(ace_string, perm_type, ace_type, trustee, numeric, flags, perms):
    ace = a.Ace.from_string(ace_string, perm_type)
    assert a.ACE_TYPES[ace.ace_type] == ace_type
    assert ace.trustee == trustee
    assert ace.numeric == numeric
    assert ace.ace_flags == flags
    assert ace.permissions == perms


from_int_format = 'ace_int, perm_type, perms'
from_int_tests = [
    ('0x00050000', 'file', ['DELETE', 'WRITE_DAC']),
    ('0x10000020', 'registry', ['GENERIC_ALL', 'CREATE_LINK']),
    ('0x00000003', 'service', ['QUERY_CONFIG', 'CHANGE_CONFIG']),
    ('0x00000024', 'token', ['IMPERSONATE', 'ADJUST_PRIVELEGES'])
]


@pytest.mark.parametrize(from_int_format, from_int_tests)
def test_ace_from_int(ace_int, perm_type, perms):
    ace = a.Ace.from_int(ace_int, perm_type)
    assert ace.numeric == int(ace_int, 16)
    assert ace.permissions == perms


toggle_format = 'initial, toggle_list, permissions, numeric'
toggle_tests = [
    ('0x00000000', ['GA', 'GR'], ['GENERIC_ALL', 'GENERIC_READ'], 0x90000000),
    ('0x90000000', ['GR'], ['GENERIC_ALL'], 0x10000000)
]


@pytest.mark.parametrize(toggle_format, toggle_tests)
def test_ace_toggle(initial, toggle_list, permissions, numeric):
    ace_value = a.Ace.toggle_permission(initial, toggle_list)
    ace = a.Ace.from_int(ace_value)
    assert ace.numeric == numeric
    assert ace.permissions == permissions
