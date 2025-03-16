#!/usr/bin/python3

import pytest
import wconv.sid as s

from_base64_format = 'base64, sid_value, trustee'
from_base64_tests = [
    ('AQIAAAAAAAUgAAAAIAIAAA==', 'S-1-5-32-544', 'BUILTIN_ADMINISTRATORS'),
    ('AQUAAAAAAAUVAAAAsexT/iL5hu1Kf3av9QEAAA==', 'S-1-5-21-4266912945-3985045794-2943778634-501', 'GUEST'),
    ('AQUAAAAAAAUVAAAAsexT/iL5hu1Kf3avFTcAAA==', 'S-1-5-21-4266912945-3985045794-2943778634-14101', None),
]


@pytest.mark.parametrize(from_base64_format, from_base64_tests)
def test_sid_from_base64(base64, sid_value, trustee):
    sid = s.SecurityIdentifier.from_b64(base64)
    assert sid.formatted_sid == sid_value
    assert sid.name == trustee


to_base64_format = 'sid_value, base64'
to_base64_tests = [
    ('S-1-5-32-544', 'AQIAAAAAAAUgAAAAIAIAAA=='),
    ('S-1-5-21-4266912945-3985045794-2943778634-501', 'AQUAAAAAAAUVAAAAsexT/iL5hu1Kf3av9QEAAA=='),
    ('S-1-5-21-4266912945-3985045794-2943778634-14101', 'AQUAAAAAAAUVAAAAsexT/iL5hu1Kf3avFTcAAA=='),
]


@pytest.mark.parametrize(to_base64_format, to_base64_tests)
def test_sid_to_base64(sid_value, base64):
    sid = s.SecurityIdentifier.from_formatted(sid_value)
    b64 = sid.to_b64()
    assert b64 == base64


from_hex_format = 'hex_string, sid_value, trustee'
from_hex_tests = [
    ('01020000000000052000000020020000', 'S-1-5-32-544', 'BUILTIN_ADMINISTRATORS'),
    ('010500000000000515000000b1ec53fe22f986ed4a7f76aff5010000', 'S-1-5-21-4266912945-3985045794-2943778634-501', 'GUEST'),
    ('010500000000000515000000b1ec53fe22f986ed4a7f76af15370000', 'S-1-5-21-4266912945-3985045794-2943778634-14101', None),
]


@pytest.mark.parametrize(from_hex_format, from_hex_tests)
def test_sid_from_hex(hex_string, sid_value, trustee):
    sid = s.SecurityIdentifier.from_hex(hex_string)
    assert sid.formatted_sid == sid_value
    assert sid.name == trustee
