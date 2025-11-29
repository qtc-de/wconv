#!/usr/bin/python3

import pytest
import wconv.securitydescriptor as sd 

# Define the format for your test parameters
sd_to_sddl_format = 'hex_string, expected_sddl'

# Define a list of tests
sd_to_sddl_tests = [
    # Test 1: Simple DACL (O:SID G:SID D:(A;;...))
    (
        '0100049c2001000000000000000000001400000004000c010600000005003800300100000100000068c9100efb78d21190d400c04f79dc550105000000000005150000002a34293374a622e6185bf1ec0002000005003800300100000100000068c9100efb78d21190d400c04f79dc550105000000000005150000002a34293374a622e6185bf1ec0302000005003800300100000100000068c9100efb78d21190d400c04f79dc550105000000000005150000002a34293374a622e6185bf1ec0702000000002400ff000f000105000000000005150000002a34293374a622e6185bf1ec0002000000002400ff000f000105000000000005150000002a34293374a622e6185bf1ec07020000000014009400020001010000000000050b0000000105000000000005150000002a34293374a622e6185bf1ec07020000',
        'O:S-1-5-21-858338346-3861030516-3975240472-519D:(OA;;RPWPCR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DA)(OA;;RPWPCR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DC)(OA;;RPWPCR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;EA)(A;;SDRCWDWOCCDCLCSWRPWPDTLO;;;DA)(A;;SDRCWDWOCCDCLCSWRPWPDTLO;;;EA)(A;;RCLCRPLO;;;AU)'
    )
]

@pytest.mark.parametrize(sd_to_sddl_format, sd_to_sddl_tests)
def test_security_descriptor_to_sddl(hex_string, expected_sddl):
    """
    Tests the end-to-end conversion from a raw hex security descriptor 
    to its full SDDL string representation.
    """ 
    sd_object = sd.SecurityDescriptor.from_hex(hex_string)
    sddl_output = sd_object.to_sddl()
    assert sddl_output == expected_sddl
