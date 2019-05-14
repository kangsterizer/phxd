#!/usr/bin/env python

import os
from config import *

def init_databases():
    try:
        os.makedirs(DB_FILE_NEWSDIR)
    except OSError:
        pass
    if not os.path.exists(DB_FILE_ACCOUNTS):
        with open(DB_FILE_ACCOUNTS, 'w') as fp:
            fp.write("admin\t1\t25e4ee4e9229397b6b17776bfceaf8e7\tAdministrator\t18443313597422501888\t\t0\t0\t0000-00-00 00:00:00\n")
            fp.write("guest\t2\td41d8cd98f00b204e9800998ecf8427e\tGuest Account\t27021597764222976\t\t0\t0\t0000-00-00 00:00:00")
    if not os.path.exists(DB_FILE_LOG):
        with open(DB_FILE_LOG, "w") as fp:
            pass
    if not os.path.exists(DB_FILE_BANLIST):
        with open(DB_FILE_BANLIST , "w") as fp:
            pass
