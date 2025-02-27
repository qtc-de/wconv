#!/usr/bin/env python3

from __future__ import annotations

from colorama import Fore, Style


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
    print(Fore.BLUE + string + Style.RESET_ALL, **kwargs)


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
    print(Fore.YELLOW + string + Style.RESET_ALL, **kwargs)
