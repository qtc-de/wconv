#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
from wconv import WConvException
from colorama import Fore, Style


def file_to_dict(path: str, delim: str = ':') -> dict:
    '''
    Takes a file system path, attempts to read and create
    a dictionary from it using the specified delimiter.

    Paramaters:
        path            file system path to read in
        delim           delimiter to use for dict creation

    Returns:
        dictionary created from file contents
    '''
    dic = dict()
    path = Path(path)

    if not path.is_file():
        return dic

    text = path.read_text()
    for line in text.split('\n'):

        try:
            key, value = line.split(delim, 1)
            dic[key.strip()] = value.strip()

        except:
            pass

    return dic


def get_int(integer: str | int) -> int:
    '''
    Helper function to convert a value into an integer, but
    do not throw an error if it already is an integer.

    Parameters:
        integer         value to convert

    Returns:
        integer value
    '''
    if isinstance(integer, int):
        return integer

    else:

        try:
            return int(integer, 0)

        except ValueError:
            raise WConvException(f"from_int(... - Specified value '{integer}' is not an integer.")


def print_blue(string: str, **kwargs) -> None:
    '''
    Wrapper around regular print which prints text
    in blue color.

    Parameters:
        string          the string to print
        **kwargs        same as for regular print

    Returns:
        None
    '''
    print(Fore.BLUE + str(string) + Style.RESET_ALL, **kwargs)


def print_yellow(string: str, **kwargs) -> None:
    '''
    Wrapper around regular print which prints text
    in yellow color.

    Parameters:
        string          the string to print
        **kwargs        same as for regular print

    Returns:
        None
    '''
    print(Fore.YELLOW + str(string) + Style.RESET_ALL, **kwargs)


def print_magenta(string: str, **kwargs) -> None:
    '''
    Wrapper around regular print which prints text
    in magenta color.

    Parameters:
        string          the string to print
        **kwargs        same as for regular print

    Returns:
        None
    '''
    print(Fore.MAGENTA + str(string) + Style.RESET_ALL, **kwargs)
