#!/usr/bin/python3

import sys
import argparse

import wconv
import wconv.uac
import wconv.sid
import wconv.sddl
import wconv.objecttype
import wconv.securitydescriptor

from wconv.helpers import print_yellow, print_blue, file_to_dict


typelist = [
            'ad',
            'file',
            'directory',
            'file_map',
            'registry',
            'service',
            'service_control',
            'process',
            'thread',
            'window_station',
            'desktop',
            'pipe',
            'token'
           ]


parser = argparse.ArgumentParser(description=f'''wconv {wconv.version} - a command line utility to convert Windows specific
                                                formats into human readable form. Currently, wconv supports convertion
                                                of ACE, SDDL, SID, UAC and SecurityDescriptor values.''')
subparsers = parser.add_subparsers(dest='command')

parser.add_argument('--sid-mappings', metavar='path', type=argparse.FileType('r'), help='file containing SID mappings')
parser.add_argument('--type-mappings', metavar='path', type=argparse.FileType('r'), help='file containing object type mappings')

parser_ace = subparsers.add_parser('ace', help='convert integer ace')
parser_ace.add_argument('ace', nargs='?', metavar='int', help='integer ace value')
parser_ace.add_argument('--ace-flags', dest='flags', action='store_true', help='show available ACE flags')
parser_ace.add_argument('--ace-types', dest='types', action='store_true', help='show available ACE types')
parser_ace.add_argument('--ace-permissions', dest='permissions', action='store_true', help='show permission definitions for requested type')
parser_ace.add_argument('--from-string', dest='string', action='store_true', help='interpret ace value als ace-string (sddl format)')
parser_ace.add_argument('--type', metavar='type', choices=typelist, default='file', help='permission type (default: file)')
parser_ace.add_argument('--toggle', metavar='perm', action='append', default=[], help='toogles specified permission on the ace value')
parser_ace.add_argument('--trustees', action='store_true', help='display available trustees')

parser_sddl = subparsers.add_parser('sddl', help='convert sddl string into readable permissions')
parser_sddl.add_argument('sddl', nargs='?', metavar='str', help='sddl string')
parser_sddl.add_argument('--add-everyone', dest='everyone', action='store_true', help='add full permissions for everyone')
parser_sddl.add_argument('--add-anonymous', dest='anonymous', action='store_true', help='add full permissions for anonymous')
parser_sddl.add_argument('--type', metavar='type', choices=typelist, default='file', help='permission type (default: file)')

parser_sid = subparsers.add_parser('sid', help='convert Windows SecurityIdentifier formats')
parser_sid.add_argument('sid', nargs='?', metavar='b64', help='sid value (default format: base64)')
parser_sid.add_argument('--to-b64', dest='b64', action='store_true', help='converts formatted sid (S-1-*) to base64')
parser_sid.add_argument('--raw', action='store_true', help='specify sid as raw hex string (010500...)')
parser_sid.add_argument('--well-known', dest='known', action='store_true', help='display list of well known sids')

parser_uac = subparsers.add_parser('uac', help='convert integer UserAccountControl')
parser_uac.add_argument('uac', nargs='?', metavar='int', help='binary user account control value')
parser_uac.add_argument('--mapping', action='store_true', help='display UserAccountControl mappings (flags)')
parser_uac.add_argument('--toggle', metavar='flag', action='append', default=[], help='toogles specified flag on the UserAccountControl value')

parser_desc = subparsers.add_parser('desc', help='convert security descriptor')
parser_desc.add_argument('desc', metavar='b64', help='security descriptor in base64')
parser_desc.add_argument('--hex', action='store_true', help='specify the descriptor in hex format instead')
parser_desc.add_argument('--type', metavar='type', choices=typelist, default='ad', help='permission type (default: ad)')
parser_desc.add_argument('--sid', metavar='sid', help='filter for a specific sid')
parser_desc.add_argument('--adminsd', action='store_true', help='filter out inherited ACEs')


def main():
    '''
    Main method :)
    '''
    args = parser.parse_args()

    if args.sid_mappings:
        wconv.sid.KNOWN_SIDS |= file_to_dict(args.sid_mappings.name)

    if args.type_mappings:
         wconv.objecttype.ObjectType.add_types(file_to_dict(args.type_mappings.name))

    try:

        ##########################################################################
        #######                    ACE related Actions                      ######
        ##########################################################################
        if args.command == 'ace':

            if args.permissions:
                perm_dict = wconv.ace.get_permission_dict(args.type)

                for key, value in perm_dict.items():

                    hex_value = wconv.ace.ACCESS_MASK_HEX_REVERSE[key]
                    hex_value = '{:08x}'.format(hex_value)
                    print_blue(f'[+] {hex_value} - {key} - ', end='')
                    print_yellow(value)

                sys.exit(0)

            if args.trustees:

                for key, value in wconv.ace.TRUSTEES.items():
                    print_blue(f'[+] {key} - ', end='')
                    print_yellow(value)

                sys.exit(0)

            if args.flags:

                for key, value in wconv.ace.ACE_FLAGS.items():
                    print_blue(f'[+] {key} - ', end='')
                    print_yellow(value)

                sys.exit(0)

            if args.types:

                for key, value in wconv.ace.ACE_TYPES.items():
                    print_blue(f'[+] {key} - ', end='')
                    print_yellow(value)

                sys.exit(0)

            if args.ace is not None:

                if args.string:
                    ace = wconv.ace.Ace.from_string(args.ace, args.type)

                elif args.toggle:
                    ace_value = wconv.ace.Ace.toggle_permission(args.ace, args.toggle)
                    ace = wconv.ace.Ace.from_int(ace_value, args.type)

                else:
                    ace = wconv.ace.Ace.from_int(args.ace, args.type)

                ace.pretty_print()
                sys.exit(0)

            parser_ace.print_usage()

        ##########################################################################
        #######                    SDDL related Actions                     ######
        ##########################################################################
        elif args.command == 'sddl':

            if args.sddl:

                if args.everyone:
                    new_sddl = wconv.sddl.Sddl.add_everyone(args.sddl)
                    print_blue('[+] ', end='')
                    print_yellow(new_sddl)
                    sys.exit(0)

                if args.anonymous:
                    new_sddl = wconv.sddl.Sddl.add_anonymous(args.sddl)
                    print_blue('[+] ', end='')
                    print_yellow(new_sddl)
                    sys.exit(0)

                sddl = wconv.sddl.Sddl.from_string(args.sddl, args.type)
                sddl.pretty_print()
                sys.exit(0)

            parser_sddl.print_usage()

        ##########################################################################
        #######                     SID related Actions                     ######
        ##########################################################################
        elif args.command == 'sid':

            if args.known:

                for key, value in wconv.sid.WELL_KNOWN_SIDS.items():
                    key = key.ljust(25)
                    print_blue(f'[+] {key} - ', end='')
                    print_yellow(value)
                sys.exit(0)

            if args.sid:

                if args.raw:
                    sid = wconv.sid.SecurityIdentifier.from_hex(args.sid)

                elif args.b64:
                    sid = wconv.sid.SecurityIdentifier.from_formatted(args.sid)
                    b64 = sid.to_b64()
                    print_blue('[+] ', end='')
                    print_yellow(b64)
                    sys.exit(0)

                else:
                    sid = wconv.sid.SecurityIdentifier.from_b64(args.sid)

                sid.pretty_print()
                sys.exit(0)

            parser_sid.print_usage()

        ##########################################################################
        #######                     UAC related Actions                     ######
        ##########################################################################
        elif args.command == 'uac':

            if args.mapping:

                for key, value in wconv.uac.UAC_DICT.items():
                    key = '{:08x}'.format(key)
                    print_blue(f'[+] 0x{key} - ', end='')
                    print_yellow(value)
                sys.exit(0)

            if args.uac:

                uac = wconv.uac.UserAccountControl(args.uac)
                if args.toggle:
                    uac.toggle_flag(args.toggle)

                uac.pretty_print()
                sys.exit(0)

            parser_uac.print_usage()

        ##########################################################################
        #######                    DESC related Actions                     ######
        ##########################################################################
        elif args.command == 'desc':

            if args.hex:
                desc = wconv.securitydescriptor.SecurityDescriptor.from_hex(args.desc, args.type)

            else:
                desc = wconv.securitydescriptor.SecurityDescriptor.from_base64(args.desc, args.type)

            if args.sid:

                for ace in desc.filter_sid(args.sid):
                    ace.pretty_print()
                    print_blue('[+]')

            if args.adminsd:

                for ace in desc.filter_inherited():
                    ace.pretty_print()
                    print_blue('[+]')

            else:
                desc.pretty_print()

        ##########################################################################
        #######                     No Command Selected                     ######
        ##########################################################################
        else:
            parser.print_usage()

    except wconv.WConvException as e:
        print("[-] Error: " + str(e))
        sys.exit(1)
