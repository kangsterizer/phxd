import os
################################################################################
# database configuration
################################################################################

# DB_TYPE actually specifies the prefix of the class that will be used
# for all database operations (accounts, news, login, banlist, etc)
# i.e. MySQL would mean use the MySQLDatabase class in database/MySQLDatabase.py
# available database types:
#    * MySQL
#    * Text
DB_TYPE = "Text"

# used when DB_TYPE is MySQL
DB_HOST = "localhost"
DB_USER = "root"
DB_PASS = ""
DB_NAME = "phxd"

# used when DB_TYPE is Text
DB_FILE_BASEPATH = "textdb"
DB_FILE_NEWSDIR = os.path.join(DB_FILE_BASEPATH, "db_news")
DB_FILE_ACCOUNTS = os.path.join(DB_FILE_BASEPATH, "db_accounts.txt")
DB_FILE_LOG = os.path.join(DB_FILE_BASEPATH, "db_log.txt")
DB_FILE_BANLIST = os.path.join(DB_FILE_BASEPATH, "db_banlist.txt")

################################################################################
# logging configuration
################################################################################

ENABLE_FILE_LOG = True
LOG_FILE = os.path.join(DB_FILE_BASEPATH, "phxd.log")
LOG_MAX_SIZE_MBYTES = 10
MAX_LOG_FILES = 5

################################################################################
# server configuration
################################################################################

SERVER_PORT = 5500
SERVER_NAME = "phxd server"
SERVER_DESCRIPTION = "Yet another phxd server instance"
IDLE_TIME = 10 * 60
BAN_TIME = 15 * 60

################################################################################
# tracker client options
################################################################################

# TRACKER_LIST example:
#TRACKER_LIST=[("tracker.hostname.tld", 5499),
#              ("127.0.0.1", 5499)]
TRACKER_LIST=[]
TRACKER_REFRESH_PERIOD=60


################################################################################
# chat options
################################################################################

CHAT_FORMAT = "\r%13.13s:  %s"
EMOTE_FORMAT = "\r ### %s %s"
MAX_NICK_LEN = 32
MAX_CHAT_LEN = 4096
LOG_CHAT = True
LOG_DIR = "chatlogs"

################################################################################
# files options
################################################################################

FILE_ROOT = "files"
SHOW_DOTFILES = False

################################################################################
# transfer options
##########################################################

XFER_START_TIMEOUT = 30

################################################################################
# GIF icon options
################################################################################

ENABLE_GIF_ICONS = True
MAX_GIF_SIZE = 32768

################################################################################
# XML-RPC options
################################################################################

ENABLE_XMLRPC = False
XMLRPC_PORT = 5800

################################################################################
# IRC options
################################################################################

IRC_SERVER_NAME = "phxd"


################################################################################
# Server linking options
################################################################################

ENABLE_SERVER_LINKING = False
LINK_PORT = SERVER_PORT + 3
