#!/usr/bin/python3

import pytest
import wconv.uac as u

constructor_format = 'uac_value, flags'
constructor_tests = [
    ('532480', ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION']),
    ('66082', ['ACCOUNTDISABLE', 'PASSWD_NOTREQD', 'NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']),
    ('4096', ['WORKSTATION_TRUST_ACCOUNT']),
]


@pytest.mark.parametrize(constructor_format, constructor_tests)
def test_uac_constructor(uac_value, flags):
    uac = u.UserAccountControl(uac_value)
    assert uac.flags == flags


toggle_format = 'initial, toggle_list, flags, numeric'
toggle_tests = [
    ('0', ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION'],
        ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION'], 532480),

    ('66082', ['ACCOUNTDISABLE', 'PASSWD_NOTREQD'],
        ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD'], 66048),

    ('4096', ['SERVER_TRUST_ACCOUNT'],
        ['WORKSTATION_TRUST_ACCOUNT', 'SERVER_TRUST_ACCOUNT'], 12288),
]


@pytest.mark.parametrize(toggle_format, toggle_tests)
def test_uac_toggle(initial, toggle_list, flags, numeric):
    uac = u.UserAccountControl(initial)
    uac.toggle_flag(toggle_list)
    assert uac.flags == flags
    assert uac.uac_value == numeric
