from __future__ import absolute_import
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
# Minimum level of the messages written to stdout ("docker logs") and to
# LOG_FILE: DEBUG, INFO, WARNING, ERROR or CRITICAL. DEBUG includes hex
# dumps of every packet, so only use it for troubleshooting.
LOG_LEVEL = "INFO"

################################################################################
# server configuration
################################################################################

SERVER_PORT = 5500
SERVER_NAME = "phxd server"
SERVER_DESCRIPTION = "Yet another phxd server instance"
IDLE_TIME = 10 * 60
# Dead connection detection. Clients whose network drops without closing
# the connection would otherwise stay listed for 15+ minutes (or forever
# while idle). TCP keepalive probes a connection after TCP_KEEPALIVE_IDLE
# seconds of silence, every TCP_KEEPALIVE_INTERVAL seconds, and drops it
# after TCP_KEEPALIVE_COUNT unanswered probes; TCP_USER_TIMEOUT drops a
# connection whose sent data stays unacknowledged that many seconds.
# Set TCP_KEEPALIVE_IDLE or TCP_USER_TIMEOUT to 0 to disable them.
TCP_KEEPALIVE_IDLE = 60
TCP_KEEPALIVE_INTERVAL = 15
TCP_KEEPALIVE_COUNT = 4
TCP_USER_TIMEOUT = 90
BAN_TIME = 15 * 60

# Path (relative to the server working directory or absolute) to a plain-
# text file containing the connection agreement. The classic 1.9 client
# and most modern clients block Chat/Files/News until they receive this
# push from the server. If the file is missing or empty the server still
# pushes an empty agreement so the client unblocks.
SERVER_AGREEMENT_PATH = "support/agreement.txt"

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
# Seconds to wait after an IRC client connects for it to log in (server
# password, /msg NickServ IDENTIFY or /msg loginserv) before logging it in
# automatically as guest. Requires a "guest" account. 0 disables auto-guest.
IRC_GUEST_LOGIN_DELAY = 5
# IRC over TLS: port to accept TLS connections on (6697 is the standard
# IRC TLS port; 0 disables TLS), and the PEM certificate chain and private
# key to use, e.g. Let's Encrypt's fullchain.pem and privkey.pem. The files
# are reloaded automatically when they change (certificate renewals).
# Connections on this port are otherwise identical to SERVER_PORT ones.
IRC_TLS_PORT = 0
IRC_TLS_CERT = ""
IRC_TLS_KEY = ""


################################################################################
# Server linking options
################################################################################

ENABLE_SERVER_LINKING = False
LINK_PORT = SERVER_PORT + 3


################################################################################
# YAML overrides
################################################################################

# Any setting above can be overridden from a YAML file, read at startup:
# $PHXD_CONFIG if set, otherwise phxd.yaml next to this file. Settings are
# written in lower case, e.g.:
#
#   server_name: "My Hotline server"
#   tracker_list:
#     - tracker.preterhuman.net:5499
#   log_level: INFO
#
# In Docker, mount the file into the container (see README.md) so the
# configuration can change with a restart instead of an image rebuild.
from shared.HLConfig import loadOverrides as _loadOverrides
CONFIG_OVERRIDDEN = _loadOverrides( globals() , os.path.dirname( os.path.abspath( __file__ ) ) )
