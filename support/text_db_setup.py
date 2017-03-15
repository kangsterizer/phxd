#!/usr/bin/env python

from config import *
from os import stat , mkdir

try:
	mkdir( DB_FILE_NEWSDIR )
except OSError:
	pass

try:
	stat( DB_FILE_ACCOUNTS )
except OSError:
	fp = file( DB_FILE_ACCOUNTS , "w" )
	fp.write( "admin\t1\t25e4ee4e9229397b6b17776bfceaf8e7\tAdministrator\t18443313597422501888\t\t0\t0\t0000-00-00 00:00:00\n" )
	fp.write( "guest\t2\td41d8cd98f00b204e9800998ecf8427e\tGuest Account\t27021597764222976\t\t0\t0\t0000-00-00 00:00:00" )
	fp.close()

try:
	stat( DB_FILE_LOG )
except:
	fp = file( DB_FILE_LOG , "w" )
	fp.close()

try:
	stat( DB_FILE_BANLIST )
except OSError:
	fp = file( DB_FILE_BANLIST , "w" )
	fp.close()
