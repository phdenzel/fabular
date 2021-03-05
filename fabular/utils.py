#!/usr/bin/env python
"""
fabular - utils

@author: phdenzel
"""


def xterm256_color(i):
    """
    The i-th color from the xterm-256 color table
    """
    i = int(i) % 256
    xterm_clr = "\033[38;5;{:03d}m".format(i)
    return xterm_clr


ansi_map = {
    'reset': '\033[0m',
    'white': xterm256_color(251),
    'black': xterm256_color(240),
    'red': xterm256_color(196),
    'green': xterm256_color(36),
    'blue': xterm256_color(69),
    'yellow': xterm256_color(222),
    'orange': xterm256_color(215),
    'brown': xterm256_color(94),
    'viridian': xterm256_color(41),
    'turquoise': xterm256_color(43),
    'cyan': xterm256_color(51),
    'violet': xterm256_color(105),
    'purple': xterm256_color(63),
    'pink': xterm256_color(207),
    'magenta': xterm256_color(162),
    'silver': xterm256_color(117),
    'gold': xterm256_color(178)
}


def id_color(id_str):
    """
    Deterministically assign a color to an ID string (e.g. username)
    """
    signs = ("abcdefghijklmnopqrstuvwxyz"
             "0123456789~!@#$%^&*()"
             "_-+={}|[]:;'<>?,./")
    id_int = sum([signs.find(i) if i in signs else 0 for i in id_str.lower()])
    choices = list(ansi_map.keys())
    choices.remove('reset')
    color = choices[int(id_int % len(choices))]
    return color


def assign_color(id_str, color_list, limit=16):
    """
    Assign a unique color to an ID string relative to a list of colors
    """
    add = ''
    while id_color(id_str+add) in color_list:
        add += 'b'
        if len(add) > 16:
            break
    return id_color(id_str+add)


def mkdir_p(pathname):
    """
    Create a directory as if using 'mkdir -p' on the command line

    Args:
        pathname <str> - create all directories in given path

    Kwargs/Return:
        None
    """
    from os import makedirs, path
    from errno import EEXIST

    try:
        makedirs(pathname)
    except OSError as exc:  # Python > 2.5
        if exc.errno == EEXIST and path.isdir(pathname):
            pass
        else:
            raise


if __name__ == "__main__":

    from tests.prototype import SequentialTestLoader
    from tests.utils_test import UtilsModuleTest
    loader = SequentialTestLoader()
    loader.proto_load(UtilsModuleTest)
    loader.run_suites()
