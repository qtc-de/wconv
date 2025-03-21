### wconv

----

*wconv* is a simple command line utility that can be used to parse and convert
Windows related formats into human readable form. Additionally, it supports
simple modifications on Windows related formats.

![](https://github.com/qtc-de/wconv/workflows/master/badge.svg)
![](https://github.com/qtc-de/wconv/workflows/develop/badge.svg)
[![](https://img.shields.io/badge/version-2.0.0-blue)](https://github.com/qtc-de/wconv/releases)
[![](https://img.shields.io/badge/packaging-pypi-blue)](https://pypi.org/project/wconv/)
![](https://img.shields.io/badge/python-10%2b-blue)
[![](https://img.shields.io/badge/license-GPL%20v3.0-blue)](https://github.com/qtc-de/wconv/blob/master/LICENSE)
![example-gif](https://github.com/qtc-de/wconv/raw/master/images/example.gif)


### Table of Contents

----

- [Installation](#installation)
- [Supported Operations](#supported-operations)
  * [ACE Module](#ace-module) 
    + [From Integer](#from-integer)
    + [From String](#from-string)
    + [Toggle Permission](#toggle-permission)
    + [Display ACE Flags](#display-ace-flags)
    + [Display ACE Types](#display-ace-types)
    + [Display ACE Permissions](#display-ace-permissions)
    + [Trustees](#trustees)
  * [SDDL Module](#sddl-module)
    + [Parse SDDL](#parse-sddl)
    + [Add Everyone](#add-everyone)
    + [Add Anonymous](#add-anonymous)
  * [SID Module](#sid-module)
    + [From base64](#from-base64)
    + [To base64](#to-base64)
    + [From Raw](#from-raw)
    + [Well Known](#well-known)
  * [UAC Module](#uac-module)
    + [Parse UAC](#parse-uac)
    + [Toggle Flag](#toggle-flag)
    + [Display Mappings](#display-mappings)
  * [DESC Module](#desc-module)
    + [Parse SecurityDescriptor](#parse-securitydescriptor)
- [Library Information](#library-information)
- [Resources](#resources)


### Installation

----

*wconv* can be build and installed as a [pip package](https://pypi.org/project/wconv/).
The recommended way of installing *wconv* is using [pipx](https://github.com/pypa/pipx)

```console
$ pipx install wconv
```

You can also build *wconv* from source and install it directly by using
the following commands:

```console
$ git clone https://github.com/qtc-de/wconv
$ cd wconv
$ pipx install .
```

If you want to use *wconv* as a programming library, simply declare it as a dependency
of your project. To use the library for simple scripts, install via *pipx* as mentioned
above and use the venv specific interpreter for script execution. The interpreter can
be found using:

```console
$ pipx environment --value PIPX_HOME
/home/user/.local/pipx
$ /home/user/.local/pipx/venvs/wconv/bin/python3
Python 3.11.2 (main, Nov 30 2024, 21:22:50) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import wconv
```
 
Additionally, *wconv* ships a [bash-completion](./wconv/resources/bash_completion.d/wconv) script.
The completion script relies on the [completion-helpers](https://github.com/qtc-de/completion-helpers)
package. with *completion-helpers* already installed, the following command enables autocompletion
for *wconv*:

```console
$ cp wconv/resources/bash_completion.d/wconv ~/.bash_completion.d
```


### Supported Operations

----

*wconv* is written as a *Python* library, but also contains a small reference implementation that
uses the library functions to perform some useful operations. In the following some supported
operations are demonstrated.

```console
$ wconv --help
usage: wconv [-h] [--sid-mappings path] [--type-mappings path] {ace,sddl,sid,uac,desc} ...

wconv v2.0.0 - a command line utility to convert Windows specific formats into human readable form. Currently, wconv supports convertion of ACE, SDDL, SID, UAC and SecurityDescriptor
values.

positional arguments:
  {ace,sddl,sid,uac,desc}
    ace                 convert integer ace
    sddl                convert sddl string into readable permissions
    sid                 convert Windows SecurityIdentifier formats
    uac                 convert integer UserAccountControl
    desc                convert security descriptor

options:
  -h, --help            show this help message and exit
  --sid-mappings path   file containing SID mappings
  --type-mappings path  file containing object type mappings
```

Aside from the module specific options and flags, *wconv* supports two global options that can be used
to specify additional information that is accessible from all modules. Using the `--sid-mappings` option,
you can specify the path to a textfile that contains SID mappings in the following format:

```
<SID>: <NAME>
<SID>: <NAME>
...
```

The same can be used for *Object Types* using the `--type-mappings` option. Whenever *wconv* attempts
to print a *SID* or *Object Type*, it checks whether a mapping to a human readable name exists and
appends this data if present.


#### ACE Module

----

The *ACE module* supports operations to work with Windows *ACE* values. Its main purpose is to convert
*ACE* values from binary or SDDL format into human readable form.

```console
$ wconv ace --help
usage: wconv ace [-h] [--ace-flags] [--ace-types] [--ace-permissions] [--from-string] [--type type] [--toggle perm] [--trustees] [int]

positional arguments:
  int                integer ace value

options:
  -h, --help         show this help message and exit
  --ace-flags        show available ACE flags
  --ace-types        show available ACE types
  --ace-permissions  show permission definitions for requested type
  --from-string      interpret ace value als ace-string (sddl format)
  --type type        permission type (default: file)
  --toggle perm      toogles specified permission on the ace value
  --trustees         display available trustees
```

##### From Integer

Parses the given integer as an ACE. This is the default action and does not require an additional flag.
The ``--type`` parameter can again be used to change the displayed permission types.

```console
$ wconv ace 0x00050010
[+] Numeric:	0x00050010
[+] Permissions:	
[+] 		+ DELETE
[+] 		+ WRITE_DAC
[+] 		+ WRITE_EXTENDED_ATTRIBUTES
```

##### From String

Parse ACE from string in SDDL format.
The ``--type`` parameter can again be used to change the displayed permission types.

```console
$ wconv ace --from-string '(A;OICINPFA;RPSDWD;;;BU)'
[+] ACE Type:	ACCESS_ALLOWED
[+] Trustee:	Users
[+] Numeric:	0x00050010
[+] Permissions:	
[+] 		+ WRITE_EXTENDED_ATTRIBUTES
[+] 		+ DELETE
[+] 		+ WRITE_DAC
```

##### Toggle Permission

Toggle the specified permission on the ACE value:

```console
$ wconv ace 0x00050010 --toggle WP --toggle GA
[+] Numeric:	0x10050030
[+] Permissions:	
[+] 		+ GENERIC_ALL
[+] 		+ DELETE
[+] 		+ WRITE_DAC
[+] 		+ WRITE_EXTENDED_ATTRIBUTES
[+] 		+ EXECUTE
```

##### Display ACE Flags

Displays a list of all available ACE flags:

```console
$ wconv ace --ace-flags
[+] CI - CONTAINER_INHERIT
[+] OI - OBJECT_INHERIT
[+] NP - NO_PROPAGATE_INHERIT
[+] IO - INHERIT_ONLY
[+] ID - INHERITED
[+] SA - SUCCESSFUL_ACCESS
[+] FA - FAILED_ACCESS
```

##### Display ACE Types

Displays a list of all available ACE types:

```console
$ wconv ace --ace-types
[+] A - ACCESS_ALLOWED
[+] D - ACCESS_DENIED
[+] OA - ACCESS_ALLOWED_OBJECT
[+] OD - ACCESS_DENIED_OBJECT
[+] AU - SYSTEM_AUDIT
[+] AL - SYSTEM_ALARM
[+] OU - SYSTEM_AUDIT_OBJECT
[+] OL - SYSTEM_ALARM_OBJECT
```

##### Display ACE Permissions

Displays a list of all available ACE permissions:

```console
$ wconv ace --ace-permissions
[+] 10000000 - GA - GENERIC_ALL
[+] 20000000 - GX - GENERIC_EXECUTE
[+] 40000000 - GW - GENERIC_WRITE
[+] 80000000 - GR - GENERIC_READ
[+] 00010000 - SD - DELETE
[+] 00020000 - RC - READ_CONTROL
[+] 00040000 - WD - WRITE_DAC
[+] 00080000 - WO - WRITE_OWNER
[+] 00000001 - CC - READ
[+] 00000002 - DC - WRITE
[+] 00000004 - LC - APPEND
[+] 00000008 - SW - READ_EXTENDED_ATTRIBUTES
[+] 00000010 - RP - WRITE_EXTENDED_ATTRIBUTES
[+] 00000020 - WP - EXECUTE
[+] 00000040 - DT - MEANINGLESS
[+] 00000080 - LO - READ_ATTRIBUTES
[+] 00000100 - CR - WRITE_ATTRIBUTES
```

The default permission type is set to **file**, but can be changed using the ``--type`` parameter:

```console
$ wconv ace --ace-permissions --type service
[+] 10000000 - GA - GENERIC_ALL
[+] 20000000 - GX - GENERIC_EXECUTE
[+] 40000000 - GW - GENERIC_WRITE
[+] 80000000 - GR - GENERIC_READ
[+] 00010000 - SD - DELETE
[+] 00020000 - RC - READ_CONTROL
[+] 00040000 - WD - WRITE_DAC
[+] 00080000 - WO - WRITE_OWNER
[+] 00000001 - CC - QUERY_CONFIG
[+] 00000002 - DC - CHANGE_CONFIG
[+] 00000004 - LC - QUERY_STATISTIC
[+] 00000008 - SW - ENUM_DEPENDENCIES
[+] 00000010 - RP - START
[+] 00000020 - WP - STOP
[+] 00000040 - DT - PAUSE
[+] 00000080 - LO - INTERROGATE
[+] 00000100 - CR - USER_DEFINIED
```

##### Trustees

Display all available trustees:

```console
$ wconv ace --trustees 
[+] AN - Anonymous
[+] AO - Account Operators
[+] AU - Authenticated Users
[+] BA - Administrators
[+] BG - Guests
[+] BO - Backup Operators
[+] BU - Users
[+] CA - Certificate Publishers
[+] CD - Certificate Services DCOM Access
[+] CG - Creator Group
[+] CO - Creator Owner
[+] DA - Domain Admins
[+] DC - Domain Computers
[+] DD - Domain Controllers
[+] DG - Domain Guests
[+] DU - Domain Users
[+] EA - Enterprise Admins
[+] ED - Enterprise Domain Controllers
[+] RO - Enterprise Read-Only Domain Controllers
[+] PA - Group Policy Admins
[+] IU - Interactive Users
[+] LA - Local Administrator
[+] LG - Local Guest
[+] LS - Local Service
[+] SY - Local System
[+] NU - Network
[+] LW - Low Integrity
[+] ME - Medium Integrity
[+] HI - High Integrity
[+] SI - System Integrity
[+] NO - Network Configuration Operators
[+] NS - Network Service
[+] PO - Printer Operators
[+] PS - Self
[+] PU - Power Users
[+] RS - RAS Servers
[+] RD - Remote Desktop Users
[+] RE - Replicator
[+] RC - Restricted Code
[+] RU - Pre-Win2k Compatibility Access
[+] SA - Schema Administrators
[+] SO - Server Operators
[+] SU - Service
[+] WD - Everyone
[+] WR - Write restricted Code
```


#### SDDL Module

----

The *SDDL module* supports operations to convert *SDDL strings* into human readable form.

```console
$ wconv sddl --help
usage: wconv sddl [-h] [--add-everyone] [--add-anonymous] [--type type] [str]

positional arguments:
  str              sddl string

options:
  -h, --help       show this help message and exit
  --add-everyone   add full permissions for everyone
  --add-anonymous  add full permissions for anonymous
  --type type      permission type (default: file)
```

##### Parse SDDL

Parses the given SDDL string. This is the default action and does not require additional arguments.

```console
$ wconv sddl 'O:BAG:SYD:PAI(D;OICI;FA;;;BA)(A;OICIIO;RPDTSDWD;;;CO)'
[+] ACL Type:	DACL
[+] Owner:	Administrators
[+] Group:	Local System
[+] ACE List:
[+] ==================================
[+]     ACE Type:	ACCESS_DENIED
[+]     Trustee:	Administrators
[+]     Numeric:	0x000f01ff
[+]     Permissions:	
[+]     		+ READ_CONTROL
[+]     		+ DELETE
[+]     		+ WRITE_DAC
[+]     		+ WRITE_OWNER
[+]     		+ SYNCHRONIZE
[+]     		+ READ
[+]     		+ WRITE
[+]     		+ APPEND
[+]     		+ READ_EXTENDED_ATTRIBUTES
[+]     		+ WRITE_EXTENDED_ATTRIBUTES
[+]     		+ EXECUTE
[+]     		+ MEANINGLESS
[+]     		+ READ_ATTRIBUTES
[+]     		+ WRITE_ATTRIBUTES
[+] ==================================
[+]     ACE Type:	ACCESS_ALLOWED
[+]     Trustee:	Creator Owner
[+]     Numeric:	0x00050050
[+]     Permissions:	
[+]     		+ WRITE_EXTENDED_ATTRIBUTES
[+]     		+ MEANINGLESS
[+]     		+ DELETE
[+]     		+ WRITE_DAC
[+] ==================================
```

The default permission type is **file** and can be changed with the ``--type`` parameter:

```console
$ wconv sddl 'O:BAG:SYD:PAI(D;OICI;FA;;;BA)(A;OICIIO;RPDTSDWD;;;CO)' --type service
[+] ACL Type:	DACL
[+] Owner:	Administrators
[+] Group:	Local System
[+] ACE List:
[+] ==================================
[+]     ACE Type:	ACCESS_DENIED
[+]     Trustee:	Administrators
[+]     Numeric:	0x000f01ff
[+]     Permissions:	
[+]     		+ READ_CONTROL
[+]     		+ DELETE
[+]     		+ WRITE_DAC
[+]     		+ WRITE_OWNER
[+]     		+ SYNCHRONIZE
[+]     		+ READ
[+]     		+ WRITE
[+]     		+ APPEND
[+]     		+ READ_EXTENDED_ATTRIBUTES
[+]     		+ WRITE_EXTENDED_ATTRIBUTES
[+]     		+ EXECUTE
[+]     		+ MEANINGLESS
[+]     		+ READ_ATTRIBUTES
[+]     		+ WRITE_ATTRIBUTES
[+] ==================================
[+]     ACE Type:	ACCESS_ALLOWED
[+]     Trustee:	Creator Owner
[+]     Numeric:	0x00050050
[+]     Permissions:	
[+]     		+ START
[+]     		+ PAUSE
[+]     		+ DELETE
[+]     		+ WRITE_DAC
[+] ==================================
```

##### Add Everyone

Add full access for everyone to the specified SDDL:

```console
$ wconv sddl --add-everyone 'O:BAG:SYD:PAI(D;OICI;FA;;;BA)(A;OICIIO;RPDTSDWD;;;CO)' 
[+] O:BAG:SYD:PAI(D;OICI;FA;;;BA)(A;OICIIO;RPDTSDWD;;;CO)(A;;GAGRGWGXRCSDWDWOSSCCDCLCSWRPWPDTLOCR;;;WD)
```

##### Add Anonymous

Add full access for anonymous to the specified SDDL:

```console
$ wconv sddl --add-anonymous 'O:BAG:SYD:PAI(D;OICI;FA;;;BA)(A;OICIIO;RPDTSDWD;;;CO)' 
[+] O:BAG:SYD:PAI(D;OICI;FA;;;BA)(A;OICIIO;RPDTSDWD;;;CO)(A;;GAGRGWGXRCSDWDWOSSCCDCLCSWRPWPDTLOCR;;;AN)
```


#### SID Module

----

The *SID module* can be used to convert between different representations of Windows *SecurityIdentifiers*.
One use case is querying *Active Directory* via *LDAP*, where the *objectSID* attributes are stored as
base64 encoded binary blobs.

```console
$ wconv sid --help
usage: wconv sid [-h] [--to-b64] [--raw] [--well-known] [b64]

positional arguments:
  b64           sid value (default format: base64)

options:
  -h, --help    show this help message and exit
  --to-b64      converts formatted sid (S-1-*) to base64
  --raw         specify sid as raw hex string (010500...)
  --well-known  display list of well known sids
```

##### From Base64

Converts a SID from base64 format to its human readable form. This is the default action
and does not require any flags:

```console
$ wconv sid AQUAAAAAAAUVAAAAsexT/iL5hu1Kf3avAAIAAA==
[+] SID: S-1-5-21-4266912945-3985045794-2943778634-512 (DOMAIN_ADMINS)
```

##### To Base64

Converts a SID from its human readable form to base64:

```console
$ wconv sid --to-b64 S-1-5-21-4266912945-3985045794-2943778634-512
[+] AQUAAAAAAAUVAAAAsexT/iL5hu1Kf3avAAIAAA==
```

##### From Raw

Converts a SID from raw hex representation to its human readable format:

```console
$ echo -n "AQUAAAAAAAUVAAAAsexT/iL5hu1Kf3avAAIAAA==" | base64 -d | xxd -p
010500000000000515000000b1ec53fe22f986ed4a7f76af00020000
$ wconv sid --raw 010500000000000515000000b1ec53fe22f986ed4a7f76af00020000
[+] SID: S-1-5-21-4266912945-3985045794-2943778634-512 (DOMAIN_ADMINS)
```

##### Well Known

Display list of well known SIDs:

```console
$ wconv sid --well-known 
[+] S-1-0-0                   - NULL
[+] S-1-1-0                   - EVERYONE
[+] S-1-2-0                   - LOCAL
[+] S-1-2-1                   - CONSOLE_LOGON
[+] S-1-3-0                   - CREATOR_OWNER
[+] S-1-3-1                   - CREATOR_GROUP
[+] S-1-3-2                   - OWNER_SERVER
[+] S-1-3-3                   - GROUP_SERVER
[+] S-1-3-4                   - OWNER_RIGHTS
[+] S-1-5                     - NT_AUTHORITY
[...]
```


#### UAC Module

----

The *UAC module* can parse integer *UserAccountControl* values from *ActiveDirectory*
into a human readable format. You can also toggle specific *UAC Flags* and output
the corresponding integer representation again.

```console
$ wconv uac --help
usage: wconv uac [-h] [--mapping] [--toggle flag] [int]

positional arguments:
  int            binary user account control value

options:
  -h, --help     show this help message and exit
  --mapping      display UserAccountControl mappings (flags)
  --toggle flag  toogles specified flag on the UserAccountControl value
```

##### Parse UAC

Parses a *UserAccountControl* value in its different components. This is the default
action and does not require additional arguments:

```console
$ wconv uac 1114624
[+] UserAccountControl:	1114624 (0x00110200)
[+]	+ NORMAL_ACCOUNT
[+]	+ DONT_EXPIRE_PASSWORD
[+]	+ NOT_DELEGATED
```

##### Toggle Flag

Adds the specified flag(s) to the UAC value:

```console
$ wconv uac 1114624 --toggle DONT_REQ_PREAUTH --toggle TRUSTED_FOR_DELEGATION 
[+] UserAccountControl:	5833216 (0x00590200)
[+]	+ NORMAL_ACCOUNT
[+]	+ DONT_EXPIRE_PASSWORD
[+]	+ TRUSTED_FOR_DELEGATION
[+]	+ NOT_DELEGATED
[+]	+ DONT_REQ_PREAUTH
```

##### Display Mappings

Display the integer to flag mappings:

```console
$ wconv uac --mapping
[+] 0x00000001 - SCRIPT
[+] 0x00000002 - ACCOUNTDISABLE
[+] 0x00000008 - HOMEDIR_REQUIRED
[+] 0x00000010 - LOCKOUT
[+] 0x00000020 - PASSWD_NOTREQD
[+] 0x00000040 - PASSWD_CANT_CHANGE
[+] 0x00000080 - ENCRYPTED_TEXT_PWD_ALLOWED
[+] 0x00000100 - TEMP_DUPLICATE_ACCOUNT
[+] 0x00000200 - NORMAL_ACCOUNT
[+] 0x00000800 - INTERDOMAIN_TRUST_ACCOUNT
[+] 0x00001000 - WORKSTATION_TRUST_ACCOUNT
[+] 0x00002000 - SERVER_TRUST_ACCOUNT
[+] 0x00010000 - DONT_EXPIRE_PASSWORD
[+] 0x00020000 - MNS_LOGON_ACCOUNT
[+] 0x00040000 - SMARTCARD_REQUIRED
[+] 0x00080000 - TRUSTED_FOR_DELEGATION
[+] 0x00100000 - NOT_DELEGATED
[+] 0x00200000 - USE_DES_KEY_ONLY
[+] 0x00400000 - DONT_REQ_PREAUTH
[+] 0x00800000 - PASSWORD_EXPIRED
[+] 0x01000000 - TRUSTED_TO_AUTH_FOR_DELEGATION
[+] 0x04000000 - PARTIAL_SECRETS_ACCOUNT
```


### DESC Module

----

The *DESC module* supports operations to convert *SecurityDescriptors* into human readable form.

```console
$ wconv desc -h
usage: wconv desc [-h] [--hex] [--type type] [--sid sid] [--adminsd] b64

positional arguments:
  b64          security descriptor in base64

options:
  -h, --help   show this help message and exit
  --hex        specify the descriptor in hex format instead
  --type type  permission type (default: ad)
  --sid sid    filter for a specific sid
  --adminsd    filter out inherited ACEs
```

##### Parse SecurityDescriptor

Parses the given base64 formatted SecurityDescriptor. This is the default action and does not require
additional flags. When specifying the `--hex` flag, the SecurityDescriptor is expected in hex format
instead.

```console
$ wconv desc AQAEjKQgAADAIAAAAAAAA...
[+] Owner:	S-1-5-21-1004336348-1177238915-682003330-512 (DOMAIN_ADMINS)
[+] Group:	S-1-5-21-1004336348-1177238915-682003330-513 (DOMAIN_USERS)
[+] Ace Count:	154
[+] ACE list:
[+]
[+] Trustee:	S-1-5-21-1004336348-1177238915-682003330-519 (ENTERPRISE_ADMINS)
[+] Numeric:	0x000f01ff
[+] ACE Flags:
[+] 		+ CONTAINER_INHERIT
[+] 		+ INHERITED
[+] Permissions:
[+] 		+ DELETE
[+] 		+ READ_CONTROL
[+] 		+ WRITE_DACL
[+] 		+ WRITE_OWNER
[+] 		+ DS_CREATE_CHILD
[+] 		+ DS_DELETE_CHILD
[+] 		+ ACTRL_DS_LIST
[+] 		+ DS_SELF
[+] 		+ DS_READ_PROP
[+] 		+ DS_WRITE_PROP
[+] 		+ DS_DELETE_TREE
[+] 		+ DS_LIST_OBJECT
[+] 		+ DS_CONTROL_ACCESS
[+]
[+] Trustee:	S-1-5-32-554 (ALIAS_PREW2KCOMPACC)
[+] Numeric:	0x00000004
[+] ACE Flags:
[+] 		+ CONTAINER_INHERIT
[+] 		+ INHERITED
[+] Permissions:
[+] 		+ ACTRL_DS_LIST
[+]
[+] Trustee:	S-1-5-32-544 (BUILTIN_ADMINISTRATORS)
[+] Numeric:	0x000f01bd
[+] ACE Flags:
[+] 		+ CONTAINER_INHERIT
[+] 		+ INHERITED
[+] Permissions:
[+] 		+ DELETE
[+] 		+ READ_CONTROL
[+] 		+ WRITE_DACL
[+] 		+ WRITE_OWNER
[+] 		+ DS_CREATE_CHILD
[+] 		+ ACTRL_DS_LIST
[+] 		+ DS_SELF
[+] 		+ DS_READ_PROP
[+] 		+ DS_WRITE_PROP
[+] 		+ DS_LIST_OBJECT
[+] 		+ DS_CONTROL_ACCESS
...
```

##### AdminSDHolder Filtering

ACE inheritance is deactivated for Active Directory objects protected by AdminSDHolder.
To filter inherited permissions, you can use the `--adminsd` flag.

```console
$ wconv desc AQAEjKQgAADAIAAAAAAAA... --adminsd
[+] ACE Type:	ACCESS_ALLOWED_OBJECT
[+] Trustee:	S-1-5-32-560 (WINDOWS_AUTHORIZATION_ACCESS_GROUP)
[+] Numeric:	0x00000010
[+] Obj Type:	46a9b11d-60ae-405a-b7e8-ff8a58d456d2 (Token-Groups-Global-And-Universal)
[+] Permissions:
[+] 		+ DS_READ_PROP
[+]
[+] ACE Type:	ACCESS_ALLOWED_OBJECT
[+] Trustee:	S-1-5-32-561 (TERMINAL_SERVER_LICENSE_SERVERS)
[+] Numeric:	0x00000030
[+] Obj Type:	6db69a1c-9422-11d1-aebd-0000f80367c1 (Terminal-Server)
[+] Permissions:
[+] 		+ DS_READ_PROP
[+] 		+ DS_WRITE_PROP
[+]
[+] ACE Type:	ACCESS_ALLOWED_OBJECT
[+] Trustee:	S-1-5-32-561 (TERMINAL_SERVER_LICENSE_SERVERS)
[+] Numeric:	0x00000030
[+] Obj Type:	5805bc62-bdc9-4428-a5e2-856a0f4c185e (Terminal-Server-License-Server)
[+] Permissions:
[+] 		+ DS_READ_PROP
[+] 		+ DS_WRITE_PROP
```


### Library Information

----

Please notice that the *wconv* library is not really well thought out. A good term to describe it
is *quick and dirty*, as I required the functionality of *wconv* and decided to write the functions
in a reusable way. However, everything was written on the fly and many sections could be written
better and may contain bugs. Pull requests to improve the library are always welcome :)


### Resources

----

Here is a list of some resources that contain the required information about the different supported
Windows structures.

* [The Security Descriptor Definition Language of Love (Part 1)](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/the-security-descriptor-definition-language-of-love-part-1/ba-p/395202)
* [The Security Descriptor Definition Language of Love (Part 2)](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/the-security-descriptor-definition-language-of-love-part-2/ba-p/395258)
* [Understanding Windows File And Registry Permissions](https://docs.microsoft.com/en-us/archive/msdn-magazine/2008/november/access-control-understanding-windows-file-and-registry-permissions)
* [How do I convert a SID between binary and string forms](https://devblogs.microsoft.com/oldnewthing/20040315-00/?p=40253)
* [How to use the UserAccountControl flags](https://support.microsoft.com/en-us/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties)
* [Parsing-the-NtSecurityDescriptor](https://www.chadsikorra.com/blog/Parsing-the-NtSecurityDescriptor)
* [ldaptools](https://github.com/ldaptools/ldaptools)
* [sddl.py](https://github.com/tojo2k/pysddl/blob/master/sddl.py/sddl.py)
