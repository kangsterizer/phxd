#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""Configures phxd before its first launch
either interactively or using a command
TODO: This is unecessarily complex. Need to use a
better config file format instead
"""
from __future__ import absolute_import
from __future__ import print_function
__author__ = "Cat'Killer"
__version__ = "0.0.1"
__license__ = "WTFPL"
__maintainer__ = "Cat'Killer"
__email__ = "catkiller@catkiller.org"

import tempfile
import shutil
from config import *
from argparse import RawDescriptionHelpFormatter, Action, ArgumentParser
from support.text_db_setup import init_databases

try:
    user_in = raw_input
except NameError:
    # Python3
    user_in = input

C_FIELDS = {"DB_TYPE":{"default":DB_TYPE, "legal":["Text", "MySQL"]},
          "DB_USER":{"default":DB_USER}, "DB_PASS":{"default":DB_PASS},
          "DB_NAME":{"default":DB_NAME},
          "DB_FILE_BASEPATH":{"default": DB_FILE_BASEPATH},
          "ENABLE_FILE_LOG":{"default":ENABLE_FILE_LOG, "legal":bool},
          "SERVER_PORT":{"default":SERVER_PORT, "legal":int},
          "SERVER_NAME":{"default":SERVER_NAME},
          "IRC_SERVER_NAME":{"default":IRC_SERVER_NAME},
          "IDLE_TIME":{"default":IDLE_TIME, "legal":int},
          "BAN_TIME":{"default":BAN_TIME, "legal":int},
          "LOG_CHAT":{"default":LOG_CHAT, "legal":bool},
          "LOG_DIR":{"default":LOG_DIR},
          "FILE_ROOT":{"default":FILE_ROOT},
          "ENABLE_GIF_ICONS":{"default":ENABLE_GIF_ICONS}}

def convert_bool_str(user_str):
    """Converts the specified user string
    to a boolean, if possible."""
    user_str_nocase = user_str.lower()
    if user_str_nocase == "true":
        return True
    elif user_str_nocase == "false":
        return False
    else:
        raise ValueError("{} is neither true or false".format(user_str))

def rewrite_config_file(filepath, values_dict):
    """Rewrites the config.py file with the specified
    key/value attributes held in the specified value_dict
    """
    if not values_dict:
        return
    keys = list(values_dict.keys())
    with open(filepath, 'r') as config_file:
        config_str = config_file.read()
    with tempfile.NamedTemporaryFile(delete=False) as tmpconfig:
        for line in config_str.splitlines():
            newline = line
            try:
                key, _ = line.split("=")
                key = key.strip()
                new_value = values_dict[key]
                newline = "{}={}".format(key, new_value)
            except ValueError:
                # This is an invalid config line, probably contains
                # two equal characters within the same line. Skip it.
                pass
            except KeyError:
                # This key/value item doesn't need to be changed, skip it.
                pass
            tmpconfig.write("{}\n".format(newline).encode("ascii"))
    # Move the tmpfile in place
    shutil.move(tmpconfig.name, filepath)

def check_and_set_value(changed_dict, key, value):
    """Verifies that the specified user value for the specified key is legal.
    """
    checker = None
    try:
        checker = C_FIELDS[key]["legal"]
    except KeyError:
        # key isn't defined in C_FIELDS or has no checker.
        pass
    if value and checker == bool:
        changed_dict[key] = convert_bool_str(value)
    elif value and isinstance(checker, list):
        if value not in checker:
            raise ValueError("{} is not a legal value from [{}]".format(
                             value, "/".join(checker)))
        # This is a string value, quote it
        changed_dict[key] = '"{}"'.format(value)
    elif value and checker:
        changed_dict[key] = checker(value)
    elif value:
        # This is a string value, quote it
        changed_dict[key] = '"{}"'.format(value)

def config_interactive():
    """Prompts the user for values to add to the config file.
    """
    print("Choose a new value for each configuration attribute, and press enter"
          " or leave blank to leave the defaults in place.")
    print("If selecting 'DB_TYPE=Text' DB_USER, DB_PASS and DB_NAME don't apply.")
    changed_dict = {}
    for key, options in C_FIELDS.items():
        checker = None
        prompt_str = "{}={}".format(key, options["default"])
        try:
            checker = options["legal"]
            prompt_str += " [{}]".format("/".join(checker))
        except KeyError:
            # There is no restriction on this string
            pass
        except TypeError:
            # This requires checking the new value through a function
            checker = options["legal"]
            if checker == bool:
                prompt_str += " [True/False]"
            elif checker == int:
                prompt_str += " [integer values only]"
        prompt_str += "\t"
        value = user_in(prompt_str).strip()
        check_and_set_value(changed_dict, key, value)
    return changed_dict

class StoreConfigAttrs(Action):
    """Class used to parse and record new config attributes specified
    as key value pairs.
    """
    def __call__(self, parser, namespace, values, option_string):
        namespace.new_values = {}
        for new_value_pair in values:
            key, value = new_value_pair.split("=")
            # All config attribute names are uppercases
            check_and_set_value(namespace.new_values, key.upper(), value)

if __name__ == "__main__":
    desc = """Configures the phxd service before its first run.
              This program can be run interactively by specifying
              -i, or on the command line using no arguments to set
              up the relevant database files from the current config
              file contents, or by first modifying config attributes
              by specifying key=value as arguments to the program.
              """
    parser = ArgumentParser(description=desc,
                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument("-i", "--interactive", action="store_true",
                        help="Runs this program interactively")
    parser.add_argument("new_values", nargs="*", metavar="attr=value",
                        help="Config attributes to modify", action=StoreConfigAttrs)
    args = parser.parse_args()
    new_values = args.new_values
    if args.interactive:
        new_values = config_interactive()
    rewrite_config_file("config.py", new_values)
    init_databases()
