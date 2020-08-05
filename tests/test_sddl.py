#!/usr/bin/python3

import pytest
import wconv.sddl as s

from_string_format = 'sddl_string, acl_type, acl_flags, owner, group, numeric_ace_1, numeric_ace_2'
from_string_tests = [
    ('O:BAG:SYD:PAI(D;CI;DCWP;;;BA)(A;OI;RPDT;;;CO)', 'DACL', ['PROTECTED', 'ACL_INHERITANCE'],
        'Administrators', 'Local System', 0x00000022, 0x00000050),

    ('O:BOD:AR(D;CI;GAGR;;;BU)(A;;CC;;;WD)', 'DACL', ['LEGACY_ACL_INHERITANCE'],
        'Backup Operators', None, 0x90000000, 0x00000001),

    ('G:DAD:P(D;CI;WP;;;ED)(D;;DC;;;AN)', 'DACL', ['PROTECTED'],
        None, 'Domain Admins', 0x00000020, 0x00000002),

    ('D:P(D;CI;WPGA;;;ED)(D;;DCGR;;;AN)', 'DACL', ['PROTECTED'],
        None, None, 0x10000020, 0x80000002),
]


@pytest.mark.parametrize(from_string_format, from_string_tests)
def test_sddl_from_string(sddl_string, acl_type, acl_flags, owner, group, numeric_ace_1, numeric_ace_2):
    sddl = s.Sddl.from_string(sddl_string)
    assert sddl.acl_type == 'DACL'
    assert sddl.acl_flags == acl_flags
    assert sddl.owner == owner
    assert sddl.group == group
    assert sddl.ace_list[0].numeric == numeric_ace_1
    assert sddl.ace_list[1].numeric == numeric_ace_2
