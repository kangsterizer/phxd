from __future__ import absolute_import
from __future__ import print_function
from struct import *
from struct import pack
from config import *
import random
import re

def buildTrackerClientPacket(name, description, port, users):
    """Builds an info packet incorporating the specified name
    and description ASCII strings and user numbers integer.
    """
    return b'\x00\x01%s%s\x00\x00%s%s%s%s%s\x00' % (
            pack('>H', port), pack('>H', users), pack("I",
            random.randint(0, 4294967295)), pack('b', len(name)),
            name, pack('b', len(description)), description)

def ircCheckUserNick( user ):
    """ Check for nick conformance to IRC standards and rename a correct one """
    nickname = ""
    nickname = user.nick.replace(" ", "")
    nickname = re.search('^([0-9-A-z]*)', nickname).group(0)
    nickname = str(user.uid)+"_"+nickname
    return nickname

def HLCharConst( str ):
    """ Returns the numeric equivalent of a 4-character string (OSType in classic Mac OS).
    Used for file types, creator codes, and magic numbers. """
    if len( str ) != 4:
        return 0
    return 0 + ( ord( str[0] ) << 24 ) + ( ord( str[1] ) << 16 ) + ( ord( str[2] ) << 8 ) + ord( str[3] )

def HLEncode( s ):
    """ Encodes plaintext for the wire per Hotline 1.x spec: byte-wise
    XOR with 0xFF. Symmetric in theory, but inbound credentials may
    arrive XORed with 0x7F instead (see ``HLDecode``), so we keep
    outbound at the documented mask and only auto-detect on inbound.
    Accepts ``str`` or ``bytes`` and always returns ``bytes``. Strings
    are interpreted as mac-roman, matching the rest of the protocol. """
    if s is None:
        return None
    if isinstance( s , str ):
        s = s.encode( 'mac-roman' )
    return bytes( 255 - b for b in s )


def HLDecode( s ):
    """ Decodes XOR-encoded wire bytes for credentials, or returns the
    bytes unchanged if they look like plaintext.

    Three real on-wire encodings have shown up in testing:

      * ``XOR 0xFF`` — the documented Hotline 1.x mask. Used by the
        classic Hotline client for login credentials. Encoded printable
        ASCII always lands in ``[0x80, 0xFF]`` (bit 7 set on every byte).
      * ``XOR 0x7F`` — the variant used by the Mierau Swift client at
        github.com/mierau/hotline for login credentials. Encoded
        printable ASCII always lands in ``[0x00, 0x1F]`` (control
        bytes — bit 7 AND bit 6 clear on every byte).
      * Plain ASCII — used by the classic client for *non-credential*
        logins (notably ACCOUNT_READ / ACCOUNT_DELETE, where the login
        is just a key, not a secret). Lands in the printable range.

    Pick the mask by majority byte class. Very short inputs (≤2 bytes)
    are almost always sentinels (e.g. the single-byte 0x00 "password
    unchanged" marker that decodes to 0xFF) — for those we always use
    the documented XOR 0xFF, since real plaintext logins of that
    length aren't meaningful.

    Returns ``bytes`` (the same length as the input). Caller is
    responsible for decoding to ``str`` if a textual login is needed. """
    if s is None:
        return None
    if isinstance( s , str ):
        s = s.encode( 'mac-roman' )
    if not s:
        return b""
    if len( s ) <= 2:
        return bytes( 0xFF ^ b for b in s )
    high = sum( 1 for b in s if b >= 0x80 )
    ctrl = sum( 1 for b in s if b < 0x20 )
    if high > len( s ) // 2:
        return bytes( 0xFF ^ b for b in s )
    if ctrl > len( s ) // 2:
        return bytes( 0x7F ^ b for b in s )
    # Looks like printable ASCII already — leave it alone.
    return bytes( s )

def isPingType( type ):
    """ Returns True if the packet type can be considered a ping packet, i.e.
    the server should not consider it when determining idle behavior. """
    if type == HTLC_HDR_PING:
        return True
    elif type == HTLC_HDR_USER_LIST:
        return True
    elif type == HTLC_HDR_USER_INFO:
        return True
    elif type == HTLC_HDR_ICON_GET:
        return True
    else:
        return False

class HLObject:
    def __init__( self , type , data ):
        self.type = type
        self.data = data
    
    def __str__( self ):
        return "HLObject [type=%d,size=%d]" % ( self.type , len( self.data ) )
    
    def getObjects( self, type ):
        objs = []
        for obj in self.objs:
            if obj.type == type:
                objs.append( obj )
        return objs

    def flatten( self ):
        """ Returns a flattened, byte-swapped string for this hotline object. """
        #Significantly modified
        type_bytes = self.type.to_bytes(2, byteorder='big')
        len_bytes = len(self.data).to_bytes(2, byteorder='big')
        data_bytes = self.data
        
        if not isinstance(self.data, bytes):
            # make it bytes
            data_bytes = self.data.encode('mac-roman')
        return type_bytes + len_bytes + data_bytes


class HLPacket:
    def __init__( self , type = 0 , seq = 0 , flags = 0 , isIRC = 0 ):
        self.objs = []
        self.type = type
        # Per the Hotline protocol spec, the transaction ID "must be != 0"
        # (see reference/mobius/hotline/transaction.go:80 — "Unique
        # transaction ID (must be != 0)"). Replies copy the request's
        # ID so they always get a non-zero value, but server-pushed
        # transactions (TranShowAgreement, TranUserAccess, chat, etc.)
        # were going out with seq=0 because nothing was passed in.
        # The classic 1.9 client silently drops those, which is why the
        # "Loading Agreement" task never resolved and pushed chat
        # messages didn't appear. Auto-assign a random non-zero ID
        # whenever the caller didn't supply one.
        if seq == 0:
            seq = random.randint( 1 , 0xFFFFFFFF )
        self.seq = seq
        self.flags = flags
        self.isIRC = isIRC
        self.server = None
        self.irctrap = ""
        self.connID = 0
    
    def __str__( self ):
        s = "HLPacket [type=%x,seq=%d,flags=%d]" % ( self.type , self.seq , self.flags )
        for obj in self.objs:
            s += "\n  " + str( obj )
        return s
    
    def parse( self , data ):
        """ Tries to parse an entire packet from the data passed in. If successful,
        returns the number of bytes parsed, otherwise returns 0. """
        if self.isIRC:
            if len( data ) == 0:
                return 0
            # Twisted hands us ``bytes`` for IRC traffic too; the IRC parsing
            # code below works on ``str``, so decode once here.
            if isinstance( data , (bytes , bytearray) ):
                data = data.decode( 'mac-roman' )
            line = data.split( "\n" )[0]
            if line == "":
                line = data.split( "\r" )[0]
            cmd = line.split( " " )[0].upper()
            if cmd == "NICK":
                self.type = HTLC_HDR_USER_CHANGE
                if line.split( " " )[1].startswith( ":" ):
                    self.addString( DATA_NICK , line.split( " " )[1][1:])
                else:
                    self.addString( DATA_NICK , line.split( " " )[1] )
                self.addNumber( DATA_ICON , 500 )
                self.addNumber( DATA_COLOR , 1 )
            
            elif cmd == "PING":
                self.type = HTLC_HDR_PING
            
            elif cmd.startswith("LAGTIME"):
                return len( line )
            
            elif cmd == "PRIVMSG":
                # Chat
                if line.split( " " )[1].startswith("#"):
                    try:
                        if line.split( " ", 2)[2].startswith( ":" ):
                            reply = line.split( " " , 2 )[2][1:]
                        else:
                            reply = line.split( " " , 2 )[2]
                        chatid = line.split( " " )[1].replace( "#" , "" )
                        if chatid != "public":
                            chatid = int( chatid )
                        else:
                            chatid = 0
                        self.type = HTLC_HDR_CHAT
                        self.addString( DATA_STRING , reply )
                        self.addNumber( DATA_OPTION , 0 )
                        self.addNumber( DATA_CHATID , chatid )
                    except:
                        #TODO Handle condition or throw away ?
                        print("handle that")
                # Private Message
                else:
                    # Authentication "bot"
                    if line.split( " " , 2 )[1] == "loginserv":
                        self.type = HTLC_HDR_LOGIN
                        loginStr = line.split(" ", 3)[2]
                        if loginStr.startswith(":"):
                            # In IRC private messages not containing space separated text
                            # are not prefixed with a colon character ":". This is important
                            # for passwordless login to loginserv, i.e. Guest login.
                            loginStr = loginStr[1:]
                        self.addString( DATA_LOGIN , HLEncode( loginStr ) )
                        try:
                            self.addString( DATA_PASSWORD , HLEncode( line.split( " " , 4 )[3] ) )
                        except IndexError:
                            # No password provided, but HL can handle blank passwords, try that.
                            self.addString(DATA_PASSWORD, HLEncode(""))
                            print("no password provided..")
                    else:
                        try:
                            uid = int( line.split( " " , 2 )[1].split( "_" , 1 )[0] )
                            self.type = HTLC_HDR_MSG
                            self.addNumber( DATA_UID , uid )
                            self.addString( DATA_STRING , line.split( " " , 2 )[2][1:] )
                        except:
                            # Throw an error, needs HLException
                            print("handle that")
            elif cmd == "WHO":
                self.type = HTLC_HDR_USER_LIST
                
            elif cmd == "WHOIS":
                try:
                    uid = int( line.split( " " , 2 )[1].split( "_" , 1 )[0] ) 
                except:
                    return 0
                self.type = HTLC_HDR_USER_INFO
                self.addNumber( DATA_UID , uid )
                
            elif cmd == "KICK":
                try:
                    uid = int( line.split( " " , 2 )[2].split( "_" , 1 )[0] )
                except:
                    return len( line )
                self.type = HTLC_HDR_KICK
                self.addNumber( DATA_UID , uid )
                self.addNumber( DATA_BAN , 0 )

            elif cmd == "MODE":
                return len( line )

            elif cmd == "JOIN":
            #TODO if chat does not exists, send a HTLC_HDR_CHAT_CREATE
                try:
                    chatid = int( line.split( "#" )[1] )
                except:
                    return len( line )
                self.type = HTLC_HDR_CHAT_JOIN
                self.addNumber( DATA_CHATID , chatid )
                
                
            elif cmd == "PART":
                try:
                    chatid = int( line.split( "#" )[1] )
                except:
                     return len( line )
                self.type = HTLC_HDR_CHAT_LEAVE
                self.addNumber( DATA_CHATID , chatid )
            
            elif cmd == "INVITE":
                uid = int( line.split( " " , 2 )[1].split( "_" , 1 )[0] )
                chatid = int ( line.split( " " , 3 )[2].replace( "#" , "" ) )
                self.type = HTLC_HDR_CHAT_INVITE
                self.addNumber( DATA_CHATID , chatid )
                self.addNumber( DATA_UID , uid )
            
            elif cmd == "QUIT":
                self.server.removeConnection( self.connID )

            else:
                self.irctrap = cmd

            return len( line )
        # This is the Hotline code now.
        else:
            if len( data ) < 20:
                return 0
            ( self.type , self.seq , self.flags , size , check ) = unpack( "!5L", data[0:20] )
            if ( len( data ) - 20 ) < size:
                return 0
            if size >= 2:
                pos = 20
                count = unpack( "!H" , data[pos:pos+2] )[0]
                pos += 2
                while count > 0:
                    ( obj_type , obj_size ) = unpack( "!2H", data[pos:pos+4] )
                    pos += 4
                    obj = HLObject( obj_type , data[pos:pos+obj_size] )
                    self.addObject( obj )
                    pos += obj_size
                    count = count - 1
            return 20 + size
    
    def addObject( self , obj ):
        """ Adds a HLObject to the object list. """
        self.objs.append( obj )
    
    def addString( self , type , data ):
        """ Wraps a string in a HLObject and adds it. """
        obj = HLObject( type , data )
        self.addObject( obj )
    
    def addNumber( self , type , data ):
        """ Wraps a number in a HLObject, byte-swapping it based
        on its magnitude, and adds it. """
        num = int( data )
        packed = b""
        if num < ( 1 << 16 ):
            packed = pack( "!H" , num )
        elif num < ( 1 << 32 ):
            packed = pack( "!L" , num )
        elif num < ( 1 << 64 ):
            packed = pack( "!Q" , num )
        obj = HLObject( type , packed )
        self.addObject( obj )
    
    def addInt16( self , type , data ):
        """ Adds a 16-bit byte-swapped number as a HLObject. """
        num = int( data )
        obj = HLObject( type , pack( "!H" , num ) )
        self.addObject( obj )
    
    def addInt32( self , type , data ):
        """ Adds a 32-bit byte-swapped number as a HLObject. """
        num = int( data )
        obj = HLObject( type , pack( "!L" , num ) )
        self.addObject( obj )
    
    def addInt64( self , type , data ):
        """ Adds a 64-bit byte-swapped number as a HLObject. """
        num = int( data )
        obj = HLObject( type , pack( "!Q" , num ) )
        self.addObject( obj )
    
    def addBinary( self , type , data ):
        """ Functionally equivalent to addString. """
        self.addString( type , data )
    
    def getString( self , type , default = None ):
        """ Returns a ``str`` for the specified object type, or
        ``default`` when the specified type is not present. The on-the-wire
        form is decoded as mac-roman to match the rest of the protocol. """
        for obj in self.objs:
            if ( obj.type == type ) and ( len( obj.data ) > 0 ):
                if isinstance( obj.data , (bytes , bytearray) ):
                    return obj.data.decode( 'mac-roman' )
                return obj.data
        return default

    def getNumber( self , type , default = None ):
        """ Returns a byte-swapped number for the specified object type, or
        a default value when the specified type is not present. """
        for obj in self.objs:
            if obj.type == type:
                if len( obj.data ) == 2:
                    return unpack( "!H" , obj.data )[0]
                elif len( obj.data ) == 4:
                    return unpack( "!L" , obj.data )[0]
                elif len( obj.data ) == 8:
                    return unpack( "!Q" , obj.data )[0]
        return default

    def getBinary( self , type , default = None ):
        """ Returns ``bytes`` for the specified object type, or ``default``
        when the specified type is not present. Used for raw protocol
        payloads (XOR-encoded credentials, packed dir descriptors, GIFs). """
        for obj in self.objs:
            if ( obj.type == type ) and ( len( obj.data ) > 0 ):
                if isinstance( obj.data , str ):
                    return obj.data.encode( 'mac-roman' )
                return bytes( obj.data )
        return default
    
    def flatten( self , user ):
        """ Returns a flattened string of this packet and embedded objects. """
        data = ""
        if self.isIRC:
            if self.type == HTLS_HDR_PING:
                data = "PONG :"+IRC_SERVER_NAME+"\r\n"
            
            elif self.type == HTLS_HDR_CHAT:
                try:
                    chat = self.getString(DATA_STRING).split( ": " , 1 )[1].replace( "\r" , " " )
                except IndexError:
                    chat = self.getString(DATA_STRING).replace( "\r" , " " )
                try:
                    ( c , u ) = self.server.clients[self.getNumber( DATA_UID )]
                    # this should be hanlded already elsewhere but forgot :(
                    if user.uid == u.uid:
                        return data
                    mynick = ircCheckUserNick( u )
                    mynick = u.nick.replace( " " , "" )
                except KeyError:
                    mynick = "PHXD"
                chatid = self.getNumber( DATA_CHATID )
                if chatid == None:
                    channel = "public"
                else:
                    channel = str(chatid)
                data = ":"+mynick+" PRIVMSG #"+channel+" :"+chat[1:]+"\r\n"
                
            elif self.type == HTLS_HDR_MSG:
                chat = self.getString( DATA_STRING )
                try:
                    ( c , u ) = self.server.clients[self.getNumber( DATA_UID )]
                    mynick = ircCheckUserNick( u )
                    myip = u.ip
                except KeyError:
                    mynick = "PHXD"
                    myip = "127.0.0.1"
                data = ":"+mynick+"!~"+mynick+"@"+myip+" PRIVMSG "+user.nick+" :"+chat.replace( "\r" , " " )+"\r\n"
            
            elif self.type == HTLS_HDR_USER_LEAVE:
                ( c, u ) = self.server.clients[self.getNumber( DATA_UID )]
                mynick = ircCheckUserNick( u )	
                if u.isIRC:
                    proto = "IRC"
                else:
                    proto = "Hotline"
                data = ":"+mynick+"!~"+mynick+"@"+u.ip+" PART #public :Client disconnected from "+proto+"\r\n"

            elif self.type == HTLS_HDR_USER_CHANGE:
                ( c, u ) = self.server.clients[self.getNumber( DATA_UID )]
                mynick = ircCheckUserNick( u )
                oldnick = self.getString( DATA_IRC_OLD_NICK )
                if not u.valid: # Login ? If so, force join the public channel
                    data = ":"+mynick+"!~"+mynick+"@"+u.ip+" JOIN :#public\r\n"
                else:
                    if u.nick == oldnick:
                        data = "NOTICE *: *** "+oldnick+" changed status to "+str( u.status )+"\r\n"
                    else:
                        if user.uid == u.uid:
                            data = ":"+oldnick+"!~"+oldnick+"@"+u.ip+" NICK :"+user.nick+"\r\n"
                        else:
                            data = ":"+str( u.uid )+"_"+oldnick.replace( " " , "" )+" NICK "+ircCheckUserNick( u )+"\r\n"
                        
            elif self.type == HTLS_HDR_TASK:
                # check for HTLC_HDR_USER_LIST reply:
                if self.getBinary( DATA_USER ):
                    keys = list(self.server.clients.keys())
                    keys.sort()
                    for uid in keys:
                        ( c , u ) = self.server.clients[uid]
                        mynick = ircCheckUserNick( u )
                        if u.isLoggedIn():
                            data += ":"+IRC_SERVER_NAME+" 352 "+mynick+" #public "+mynick+" "+u.ip+" "+IRC_SERVER_NAME+" "+u.account.name.replace( " ", "_" )+"\r\n"
                    data += ":"+IRC_SERVER_NAME+" 315 "+user.nick+" #public :End of /WHO list.\r\n"
                
                # HTLC_HDR_USER_INFO then :)
                elif self.getString( DATA_NICK ):
                    uid = self.getNumber( DATA_UID )
                    ( c , u ) = self.server.clients[uid]
                    mynick = ircCheckUserNick( u )
                    info = self.getString( DATA_STRING )
                    
                    idle = info.split( "idle: " )[1].split( '\r' )[0]
                    if u.isIRC:
                        proto = "IRC"
                    else:
                        proto = "Hotline"
                    
                    data = ":"+IRC_SERVER_NAME+" 311 "+user.nick+" "+mynick+" ~"+mynick+" "+u.ip+" * :"+u.account.name.replace(" ", "_")+"\r\n"
                    data += ":"+IRC_SERVER_NAME+" 312 "+user.nick+" "+mynick+" "+IRC_SERVER_NAME+" :http//chatonly.org\r\n"
                    data += ":"+IRC_SERVER_NAME+" 320 "+user.nick+" "+mynick+" :Using protocol "+proto+"\r\n"
                    data += ":"+IRC_SERVER_NAME+" 317 "+user.nick+" "+mynick+" "+idle+" 0 :seconds idle, signon time\r\n"
                    data += ":"+IRC_SERVER_NAME+" 318 "+user.nick+" "+mynick+" :End of /WHOIS list.\r\n"

            elif self.type == HTLS_HDR_CHAT_INVITE:
                chatid = self.getNumber( DATA_CHATID)
                uid = self.getNumber( DATA_UID )
                ( c , u ) = self.server.clients[uid]
                mynick = ircCheckUserNick( u )
                data = ":PHXD PRIVMSG #public :"+mynick+" invites you to join private chat #"+str(chatid)+"\r\n"
            elif self.type == HTLS_HDR_CHAT_USER_LEAVE:
                chatid = self.getNumber( DATA_CHATID)
                uid = self.getNumber( DATA_UID )
                ( c , u ) = self.server.clients[uid]
                mynick = ircCheckUserNick( u )
                data = ":"+mynick+"!~"+mynick+"@"+u.ip+" PART #"+str( chatid )+" :Client left channel #"+str( chatid )+"\r\n"

            elif self.type == HTLS_HDR_CHAT_USER_CHANGE:
                # Basically this is a JOIN packet for a private chat
                chatid = self.getNumber( DATA_CHATID)
                uid = self.getNumber( DATA_UID )
                ( c , u ) = self.server.clients[uid]
                mynick = ircCheckUserNick( self.getString( DATA_NICK ) )
                data = ":"+mynick+"!~"+mynick+"@"+u.ip+" JOIN :#"+str(chatid)+"\r\n"

            elif self.type == HTLS_HDR_BROADCAST:
                data = "NOTICE * :*** BROADCAST: "+self.getString( DATA_STRING )+"\r\n"

            # Twisted's transport.write requires bytes in Python 3.
            return data.encode( 'mac-roman' ) if isinstance( data , str ) else data
        # Normal Hotline processing
        else:
            data = b""
            for obj in self.objs:
                data += obj.flatten()

            return pack( "!5L1H" , self.type , self.seq , self.flags , len( data ) + 2 , len( data ) + 2 , len( self.objs ) ) + data

# Client packet types

HTLC_HDR_NEWS_GET =		0x00000065
HTLC_HDR_NEWS_POST =		0x00000067
HTLC_HDR_CHAT = 		0x00000069
HTLC_HDR_LOGIN = 		0x0000006B
HTLC_HDR_MSG =			0x0000006C
HTLC_HDR_KICK =			0x0000006E
HTLC_HDR_CHAT_CREATE =		0x00000070
HTLC_HDR_CHAT_INVITE =		0x00000071
HTLC_HDR_CHAT_DECLINE =		0x00000072
HTLC_HDR_CHAT_JOIN =		0x00000073
HTLC_HDR_CHAT_LEAVE =		0x00000074
HTLC_HDR_CHAT_SUBJECT =		0x00000078
# Sent by the client after the user clicks "Agree" on the connection
# agreement modal. Carries the user's chosen nick/icon/status; we use
# it to finalise the join even though our existing handleLogin path
# has already broadcast the user-change notification.
HTLC_HDR_AGREED =		0x00000079
HTLC_HDR_FILE_LIST =		0x000000C8
HTLC_HDR_FILE_GET =		0x000000CA
HTLC_HDR_FILE_PUT =		0x000000CB
HTLC_HDR_FILE_DELETE =		0x000000CC
HTLC_HDR_FILE_MKDIR =		0x000000CD
HTLC_HDR_FILE_GETINFO =		0x000000CE
HTLC_HDR_FILE_SETINFO =		0x000000CF
HTLC_HDR_FILE_MOVE =		0x000000D0
HTLC_HDR_FILE_ALIAS =		0x000000D1
HTLC_HDR_USER_LIST =		0x0000012C
HTLC_HDR_USER_INFO =		0x0000012F
HTLC_HDR_USER_CHANGE =		0x00000130
HTLC_HDR_ACCOUNT_CREATE =	0x0000015E
HTLC_HDR_ACCOUNT_DELETE =	0x0000015F
HTLC_HDR_ACCOUNT_READ =		0x00000160
HTLC_HDR_ACCOUNT_MODIFY =	0x00000161
# tranListUsers (348) — sent by the client when "Administer Accounts"
# opens. The client expects a TASK reply containing one DATA_STRING
# (0x65) field per account on the server, where each DATA_STRING
# payload is itself a serialized sub-packet:
#   [2-byte field count]
#   [DATA_NICK   (0x66) tag/len/data]   — display name
#   [DATA_LOGIN  (0x69) tag/len/data]   — XOR-encoded login
#   [DATA_PRIVS  (0x6E) tag/len/data]   — 8-byte access bitmap
#   [DATA_PASSWORD (0x6A) tag/len/data] — present iff a password is set,
#                                          value "x" as a placeholder
# Cross-checked against Mobius (HandleListUsers in
# reference/mobius/internal/mobius/transaction_handlers.go:697 and
# Account.Read in reference/mobius/hotline/account.go:34).
HTLC_HDR_ACCOUNT_LIST =		0x0000015C
# tranUpdateUser (349) — the v1.5+ batch user editor sends this whenever
# the user clicks "Save" in the Administer Accounts window. It can carry
# a mix of create / modify / delete / rename operations, one per outer
# DATA_STRING field. Each DATA_STRING payload is a serialized sub-packet:
#   [2-byte sub-field count]
#   [DATA_STRING   (0x65) — original login, present only on RENAME]
#   [DATA_LOGIN    (0x69) — new/current login, always present]
#   [DATA_NICK     (0x66) — display name]
#   [DATA_PASSWORD (0x6A) — password, see semantics below]
#   [DATA_PRIVS    (0x6E) — 8-byte access bitmap]
# Operation type is inferred:
#   * sub-field count == 1                              → DELETE
#   * DATA_STRING present                               → RENAME (+ modify)
#   * account exists                                    → MODIFY
#   * account does not exist                            → CREATE
# Password semantics (mirrored from Mobius):
#   * DATA_PASSWORD missing entirely → clear password
#   * DATA_PASSWORD == single 0x00   → leave password unchanged
#   * DATA_PASSWORD == anything else → set new password
# Reply: empty TASK ack.
HTLC_HDR_ACCOUNT_UPDATE =	0x0000015D
HTLC_HDR_BROADCAST =		0x00000163
HTLC_HDR_PING =			0x000001F4

# Hotline 1.5+ extensions used by some clients (e.g. mierau/hotline Swift).
# Not all servers implement these; sending a success-with-no-data TASK ack
# is usually enough to keep the client happy and let it move on.
HTLC_HDR_DOWNLOAD_BANNER =	0x000000D4

# Threaded news (Hotline 1.5+ — distinct from the old flat news at 0x65).
# Currently stubbed to return empty results — see TODO.md for full impl.
HTLC_HDR_NEWS_CAT_LIST =	0x00000172
HTLC_HDR_NEWS_ART_LIST =	0x00000173
HTLC_HDR_NEWS_CAT_NEW =		0x00000174
HTLC_HDR_NEWS_FLDR_NEW =	0x00000175
HTLC_HDR_NEWS_CAT_DELETE =	0x00000178
HTLC_HDR_NEWS_ART_GET =		0x00000190
HTLC_HDR_NEWS_ART_POST =	0x0000019A
HTLC_HDR_NEWS_ART_DELETE =	0x0000019B

# Avaraline protocol additions

HTLC_HDR_ICON_LIST =		0x00000745
HTLC_HDR_ICON_SET =		0x00000746
HTLC_HDR_ICON_GET =		0x00000747

# Server packet types

HTLS_HDR_NEWS_POST =		0x00000066
HTLS_HDR_MSG =			0x00000068
HTLS_HDR_CHAT =			0x0000006A
# Server→client push: the connection agreement text. Hotline clients
# (classic 1.9, Mierau Swift) block most UI features — Chat, Files,
# news pane — until they receive this packet, even when the body is
# empty or the user has PRIV_NO_AGREEMENT set.
HTLS_HDR_SHOW_AGREEMENT =	0x0000006D
HTLS_HDR_CHAT_INVITE =		0x00000071
HTLS_HDR_CHAT_USER_CHANGE =	0x00000075
HTLS_HDR_CHAT_USER_LEAVE =	0x00000076
HTLS_HDR_CHAT_SUBJECT =		0x00000077
HTLS_HDR_USER_CHANGE =		0x0000012D
HTLS_HDR_USER_LEAVE =		0x0000012E
HTLS_HDR_SELFINFO =		0x00000162
HTLS_HDR_BROADCAST =		0x00000163
HTLS_HDR_PING = 		0x000001f4
HTLS_HDR_TASK =			0x00010000

# Avaraline protocol additions

HTLS_HDR_ICON_CHANGE =		0x00000748

HTLS_HDR_LINK_LOGIN =          0x00000800
HTLS_HDR_LINK_JOIN =           0x00000801
HTLS_HDR_LINK_LEAVE =          0x00000802
HTLS_HDR_LINK_PACKET =         0x00000803

# Common data (object) types

DATA_ERROR =		0x0064
DATA_STRING = 		0x0065
DATA_NICK = 		0x0066
DATA_UID =		0x0067
DATA_ICON =		0x0068
DATA_LOGIN = 		0x0069
DATA_PASSWORD = 	0x006A
DATA_XFERID =		0x006B
DATA_XFERSIZE =		0x006C
DATA_OPTION =		0x006D
DATA_PRIVS =		0x006E
DATA_STATUS =		0x0070
DATA_BAN =		0x0071
DATA_CHATID =		0x0072
DATA_SUBJECT =		0x0073
DATA_VERSION =		0x00A0
# Community banner ID — sent in the LOGIN TASK reply alongside DATA_VERSION /
# DATA_SERVERNAME. Mobius and other modern Hotline servers send a 2-byte
# placeholder ([0,0]) here even when no community banner is hosted; the
# classic 1.9 client appears to require the field to consider the LOGIN
# response complete and unblock the agreement-loading task.
DATA_BANNERID =		0x00A1
DATA_SERVERNAME =	0x00A2
DATA_FILE =		0x00C8
DATA_FILENAME =		0x00C9
DATA_DIR =		0x00CA
DATA_RESUME =		0x00CB
DATA_XFEROPTIONS =	0x00CC
DATA_FILETYPE =		0x00CD
DATA_FILECREATOR =	0x00CE
DATA_FILESIZE =		0x00CF
DATA_NEWFILE =		0x00D3
DATA_NEWDIR =		0x00D4
DATA_USER =		0x012C

# Avaraline protocol additions

DATA_GIFICON =		0x0300
DATA_GIFLIST =		0x0301
DATA_NEWSLIMIT =	0x0320
DATA_COLOR =		0x0500
DATA_PACKET =           0x0600

# IRC needed hackery
DATA_IRC_OLD_NICK = 	0x0400

# Hotline's idea of "bit 0" is ass backwards

PRIV_DELETE_FILES =	1 << 63
PRIV_UPLOAD_FILES =	1 << 62
PRIV_DOWNLOAD_FILES =	1 << 61
PRIV_RENAME_FILES =	1 << 60
PRIV_MOVE_FILES =	1 << 59
PRIV_CREATE_FOLDERS =	1 << 58
PRIV_DELETE_FOLDERS =	1 << 57
PRIV_RENAME_FOLDERS =	1 << 56
PRIV_MOVE_FOLDERS =	1 << 55
PRIV_READ_CHAT =	1 << 54
PRIV_SEND_CHAT =	1 << 53
PRIV_CREATE_CHATS =	1 << 52
PRIV_DELETE_CHATS =	1 << 51
PRIV_SHOW_USER =	1 << 50
PRIV_CREATE_USERS =	1 << 49
PRIV_DELETE_USERS =	1 << 48
PRIV_READ_USERS =	1 << 47
PRIV_MODIFY_USERS =	1 << 46
PRIV_CHANGE_PASSWORD =	1 << 45
PRIV_UNKNOWN =		1 << 44
PRIV_READ_NEWS =	1 << 43
PRIV_POST_NEWS =	1 << 42
PRIV_KICK_USERS =	1 << 41
PRIV_KICK_PROTECT =	1 << 40
PRIV_USER_INFO =	1 << 39
PRIV_UPLOAD_ANYWHERE =	1 << 38
PRIV_USE_ANY_NAME =	1 << 37
PRIV_NO_AGREEMENT =	1 << 36
PRIV_COMMENT_FILES =	1 << 35
PRIV_COMMENT_FOLDERS =	1 << 34
PRIV_VIEW_DROPBOXES =	1 << 33
PRIV_MAKE_ALIASES =	1 << 32
PRIV_BROADCAST =	1 << 31

PRIV_SEND_MESSAGES =	1 << 23

# Status bits

STATUS_AWAY =		1 << 0
STATUS_ADMIN =		1 << 1