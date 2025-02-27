#!/usr/bin/env python3

from colorama import Fore, Style


def print_blue(string, **kwargs):
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


def print_yellow(string, **kwargs):
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
