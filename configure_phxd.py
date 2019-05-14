#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""Configures phxd before its first launch
either interactively or using a command
TODO: This is unecessarily complex. Need to use a
better config file format instead
"""
__author__ = "Cat'Killer"
__version__ = "0.0.1"
__license__ = "WTFPL"
__maintainer__ = "Cat'Killer"
__email__ = "catkiller@catkiller.org"

import tempfile
import shutil
from config import *
from support.text_db_setup import init_databases

try:
    user_in = raw_input
except NameError:
    # Python3
    user_in = input

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
    keys = values_dict.keys()
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

def config_interactive():
    """Prompts the user for values to add to the config file.
    """
    c_dict = {"DB_TYPE":{"default":DB_TYPE, "legal":["Text", "MySQL"]},
              "DB_USER":{"default":DB_USER}, "DB_PASS":{"default":DB_PASS},
              "DB_NAME":{"default":DB_NAME},
              "DB_FILE_BASEPATH":{"default": DB_FILE_BASEPATH},
              "ENABLE_FILE_LOG":{"default":ENABLE_FILE_LOG, "legal":bool},
              "SERVER_PORT":{"default":SERVER_PORT, "legal":int},
              "SERVER_NAME":{"default":SERVER_NAME},
              "IRC_SERVER_NAME":{"default":IRC_SERVER_NAME},
              "IDLE_TIME":{"default":IDLE_TIME},
              "BAN_TIME":{"default":BAN_TIME},
              "LOG_CHAT":{"default":LOG_CHAT, "legal":bool},
              "LOG_DIR":{"default":LOG_DIR},
              "FILE_ROOT":{"default":FILE_ROOT},
              "ENABLE_GIF_ICONS":{"default":ENABLE_GIF_ICONS}}
    print("Choose a new value for each configuration attribute, and press enter"
          " or leave blank to leave the defaults in place.")
    print("If selecting 'DB_TYPE=Text' DB_USER, DB_PASS and DB_NAME don't apply.")
    changed_dict = {}
    for key, options in c_dict.items():
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
    return changed_dict

new_values = config_interactive()
rewrite_config_file("config.py", new_values)
init_databases()
