#!/usr/bin/python3

import argparse

import wconv
import wconv.uac
import wconv.sid
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
parser_ace.add_argument('ace', nargs='?', metavar='int', help='integer ace value (dec or hex)')
parser_ace.add_argument('--hex', action='store_true', help='the specified value is a hex string')
parser_ace.add_argument('--sddl', action='store_true', help='the specified value is an sddl string')
parser_ace.add_argument('--flags', action='store_true', help='show available ACE flags')
parser_ace.add_argument('--types', action='store_true', help='show available ACE types')
parser_ace.add_argument('--permissions', action='store_true', help='show permission definitions for requested type')
parser_ace.add_argument('--type', metavar='type', choices=typelist, default='file', help='permission type (default: file)')
parser_ace.add_argument('--toggle', metavar='perm', action='append', default=[], help='toogles specified permission on the ace value')
parser_ace.add_argument('--trustees', action='store_true', help='display well known trustees')

parser_sid = subparsers.add_parser('sid', help='convert Windows SecurityIdentifier formats')
parser_sid.add_argument('sid', nargs='?', metavar='b64', help='sid value (default format: base64)')
parser_sid.add_argument('--formatted', action='store_true', help='input is aformatted sid (S-1-*)')
parser_sid.add_argument('--hex', action='store_true', help='input is SID as hex string (010500...)')
parser_sid.add_argument('--well-known', dest='known', action='store_true', help='display list of well known sids')

parser_uac = subparsers.add_parser('uac', help='convert integer UserAccountControl')
parser_uac.add_argument('uac', nargs='?', metavar='int', help='binary user account control value')
parser_uac.add_argument('--mapping', action='store_true', help='display UserAccountControl mappings (flags)')
parser_uac.add_argument('--toggle', metavar='flag', action='append', default=[], help='toogles specified flag on the UserAccountControl value')

parser_sd = subparsers.add_parser('sd', help='convert security descriptor')
parser_sd.add_argument('sd', metavar='b64', help='security descriptor in base64')
parser_sd.add_argument('--hex', action='store_true', help='specified descriptor is in hex format')
parser_sd.add_argument('--sddl', action='store_true', help='specified descriptor is in sddl format')
parser_sd.add_argument('--type', metavar='type', choices=typelist, default='ad', help='permission type (default: ad)')
parser_sd.add_argument('--sid', metavar='sid', help='filter for a specific sid')
parser_sd.add_argument('--adminsd', action='store_true', help='filter out inherited ACEs')
parser_sd.add_argument('--add-everyone', dest='everyone', action='store_true', help='add full permissions for everyone')
parser_sd.add_argument('--add-anonymous', dest='anonymous', action='store_true', help='add full permissions for anonymous')


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

                for hex_value, name in perm_dict.items():

                    sddl_name = '??'
                    for sddl, other_hex in wconv.sddl.ACCESS_MASK_HEX.items():
                        
                        if other_hex == hex_value:
                            sddl_name = sddl

                    hex_value = '{:08x}'.format(hex_value)
                    print_blue(f'[+] {hex_value} - {sddl_name} - ', end='')
                    print_yellow(name)

            elif args.trustees:

                for key, value in wconv.sddl.TRUSTEES.items():
                    print_blue(f'[+] {key} - ', end='')
                    print_yellow(value)

            elif args.flags:

                for key, value in wconv.ace.ACE_FLAGS.items():
                    print_blue(f'[+] {key} - ', end='')
                    print_yellow(value)

            elif args.types:

                for key, value in wconv.ace.ACE_TYPES.items():
                    print_blue(f'[+] {key} - ', end='')
                    print_yellow(value)

            elif args.ace is not None:

                if args.sddl:
                    ace = wconv.ace.Ace.from_sddl(args.ace, args.type)

                elif args.hex:
                    ace = wconv.ace.Ace.from_hex(args.ace, args.type)

                else:
                    ace = wconv.ace.Ace.from_int(args.ace, args.type)

                if args.toggle:
                    ace.toggle_permission(args.toggle, args.type)

                ace.pretty_print()

            else:
                parser_ace.print_usage()

        ##########################################################################
        #######                     SID related Actions                     ######
        ##########################################################################
        elif args.command == 'sid':

            if args.known:

                for key, value in wconv.sid.WELL_KNOWN_SIDS.items():
                    key = key.ljust(25)
                    print_blue(f'[+] {key} - ', end='')
                    print_yellow(value)

            elif args.sid:

                if args.hex:
                    sid = wconv.sid.SecurityIdentifier.from_hex(args.sid)

                elif args.formatted:
                    sid = wconv.sid.SecurityIdentifier.from_formatted(args.sid)

                else:
                    sid = wconv.sid.SecurityIdentifier.from_b64(args.sid)

                sid.pretty_print()

            else:
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

            elif args.uac:

                uac = wconv.uac.UserAccountControl(args.uac)

                if args.toggle:
                    uac.toggle_flag(args.toggle)

                uac.pretty_print()

            else:
                parser_uac.print_usage()

        ##########################################################################
        #######                    DESC related Actions                     ######
        ##########################################################################
        elif args.command == 'sd':

            if args.hex:
                desc = wconv.securitydescriptor.SecurityDescriptor.from_hex(args.sd, args.type)

            elif args.sddl:
                desc = wconv.securitydescriptor.SecurityDescriptor.from_sddl(args.sd, args.type)

            else:
                desc = wconv.securitydescriptor.SecurityDescriptor.from_base64(args.sd, args.type)

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
