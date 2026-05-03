from __future__ import absolute_import
from __future__ import print_function
from twisted.internet.protocol import Factory , Protocol
from twisted.internet import task
from twisted.internet import reactor
from shared.HLProtocol import *
from shared.HLTypes import *
from server.HLDatabase import getDatabase
from server.HLFileServer import *
from server.HLWebServices import *
from server.HLDatabaseLogger import *
from server.HLServerLinkage import *
from server.HLTracker import HLTrackerClient
import sys
#from twisted.logger import globalLogBeginner, textFileLogObserver
#globalLogBeginner.beginLoggingTo([textFileLogObserver(sys.stdout)])

from config import *
import time , logging
from logging.handlers import RotatingFileHandler

class HLConnection( Protocol ):
    """ Protocol subclass to handle parsing and dispatching of raw hotline data. """
    
    def __init__( self , factory , connID ):
        self.factory = factory
        self.connID = connID
    
    def connectionMade( self ):
        """ Called when a connection is accepted. """
        self.gotMagic = False
        self.isIRC = False
        self.packet = HLPacket()
        self.buffer = b''
        self.idleTimer = reactor.callLater( IDLE_TIME , self.idleCheck )
        try:
            peer = self.transport.getPeer()
            self.factory.log.info( "Client connected: %s:%s (connID=%d)" , peer.host , peer.port , self.connID )
        except Exception:
            pass

    def connectionLost( self , reason ):
        """ Called when the connection is lost. """
        if ( self.idleTimer != None ) and self.idleTimer.active():
            self.idleTimer.cancel()
        try:
            self.factory.log.info( "Client disconnected (connID=%d): %s" , self.connID , reason.getErrorMessage() if hasattr( reason , 'getErrorMessage' ) else reason )
        except Exception:
            pass
        self.factory.removeConnection( self.connID )

    def dataReceived( self , data ):
        """ Called when the socket receives data. """
        try:
            self.factory.log.debug(
                "dataReceived connID=%d gotMagic=%s isIRC=%s len=%d hex=%s" ,
                self.connID , self.gotMagic , self.isIRC , len( data ) ,
                data.hex() if isinstance( data , (bytes , bytearray) ) else '<not bytes>'
            )
        except Exception:
            pass
        self.buffer += data
        try:
            self.parseBuffer()
        except Exception:
            # Don't let an exception inside parseBuffer disappear into
            # Twisted — log it explicitly so it shows in docker logs.
            self.factory.log.exception( "Unhandled exception in parseBuffer (connID=%d)" , self.connID )
            self.transport.loseConnection()
    
    def parseBuffer( self ):
        """ Parses the current buffer until the buffer is empty or until no more packets can be parsed. """
        if self.gotMagic:
            done = False
            while not done:
                if self.isIRC:
                    # Buffer is ``bytes`` from Twisted's ``dataReceived``;
                    # strip CR with a bytes literal.
                    self.buffer = self.buffer.replace(b"\r", b"") #FIXME is it really necessary ? it is also done during packet parsing
                    self.packet.isIRC = self.isIRC
                    self.packet.connID = self.connID
                    self.packet.server = self.factory
                size = self.packet.parse( self.buffer )
                if size > 0:
                    if self.isIRC:
                        size = size + 1
                    self.buffer = self.buffer[size:]
                    self.handlePacket()
                    self.packet = HLPacket()
                else:
                    done = True
        else:
            if len( self.buffer ) >= 12:
                ( proto , subProto , vers , subVers ) = unpack( "!LLHH" , self.buffer[0:12] )
                if proto == HLCharConst( "TRTP" ):
                    self.buffer = self.buffer[12:]
                    self.gotMagic = True
                    self.transport.write( pack( "!2L" , HLCharConst( "TRTP" ) , 0 ) )
                    # If there is still data in the buffer, check for packets.
                    if len( self.buffer ) > 0:
                        self.parseBuffer()
                else:
                    # Not hotline, assume IRC. Multiple commands can be chained in IRC.
                    cmds = self.buffer.splitlines()
                    if cmds[0].startswith(b"CAP"):
                        # We received CAP LS, ignore it and read the rest of the buffer
                        # This is for compatibility with IRC v3.02 clients like irssi
                        cmds.pop(0)
                    # If there are no further commands, close the connection.
                    if not cmds:
                        self.transport.loseConnection()
                    # More commands still in the buffer, parse them.
                    value = ""
                    try:
                        # breaking and busted in here
                        print("got in my try block")
                        cmd, value = cmds[0].decode('mac-roman').split(" ", 1)
                    except ValueError:
                        # Value isn't defined, only parse cmd
                        print("got in this except?")
                        cmd = cmds[0].decode('mac-roman').split(" ", 1)[0]
                    # Check the first command, if NICK or USER, login, else return UNKNOWN COMMAND
                    if ( cmd == "NICK" ) or ( cmd == "USER" ):
                        nick = value or "Unnamed"
                        user = self.factory.getUser( self.connID )
                        user.nick = nick # Making sure we have the right nick.
                        # Twisted's transport.write requires bytes in Py3.
                        def _w( msg ):
                            self.transport.write( msg.encode( 'mac-roman' ) )
                        _w( "NOTICE * :*** Welcome to Hotline\r\n" )
                        _w( "NOTICE AUTH :*** You are NOT logged in\r\n" )
                        _w( "NOTICE AUTH :*** Please send '/msg loginserv login password' to proceed.\r\n" )
                        _w( "NOTICE AUTH :*** If you do not have an account, use '/msg loginserv guest' to proceed.\r\n" )
                        _w( ":"+IRC_SERVER_NAME+" 001 %s :Waiting for login input..\r\n" % nick )
                        _w( ":"+IRC_SERVER_NAME+" 375 %s :- MOTDs are for losers.\r\n" % user.nick )
                        _w( ":"+IRC_SERVER_NAME+" 372 %s :- :)\r\n" % user.nick )
                        _w( ":"+IRC_SERVER_NAME+" 376 %s :End of /MOTD command.\r\n" % user.nick )

                        self.isIRC = True
                        self.gotMagic = True
                        self.parseBuffer()
                    else:
                        self.transport.write(
                            ( ":"+IRC_SERVER_NAME+" 421 %s :Unknown command\r\n" % cmd ).encode( 'mac-roman' )
                        )
                        self.transport.loseConnection()
    
    def handlePacket( self ):
        """ Dispatch the packet to the factory (and its listeners) and check to see if we should update our away status. """
        try:
            user = self.factory.getUser( self.connID )
            if not user:
                self.transport.loseConnection()
                return
            if self.isIRC and self.packet.irctrap:
                # Unsupported command, return 421
                self.transport.write(
                    ( ":"+IRC_SERVER_NAME+" 421 %s %s :Unknown command\r\n" % (user.nick, self.packet.irctrap) ).encode( 'mac-roman' )
                )
            if user.isLoggedIn():
                # Make sure we're logged in before doing anything.
                self.factory.dispatchPacket( self.connID , self.packet )
                if ( not isPingType( self.packet.type ) ) and ( not user.away ):
                    # We got a non-ping packet, and we're not away.
                    user.lastPacketTime = time.time()
                    if ( self.idleTimer != None ) and self.idleTimer.active():
                        # If the idleTimer exists and hasn't fired yet, remain active.
                        self.idleTimer.reset( IDLE_TIME )
                    else:
                        # Otherwise, we just came back from being idle.
                        user.status &= ~STATUS_AWAY
                        self.factory.dispatchPacket( self.connID , HLPacket( HTLC_HDR_USER_CHANGE ) )
                        self.idleTimer = reactor.callLater( IDLE_TIME , self.idleCheck )
            elif ( self.packet.type == HTLC_HDR_LOGIN ):
                user.isIRC = self.packet.isIRC
                # If we're not logged in, only dispatch login packets.
                user.lastPacketTime = time.time()
                self.factory.dispatchPacket( self.connID , self.packet )
            elif ( self.packet.type == HTLC_HDR_PING ):
                if self.packet.isIRC:
                    self.factory.dispatchPacket( self.connID , self.packet )
            else:
                if ( self.packet.isIRC == 0 ) and ( self.packet.type != 0 ) and ( self.packet.type != 130 ):
                    print("got packet before login:")
                    print(self.packet)
        except HLException as ex:
            # Unhandled packets and task errors will be caught here.
            self.factory.log.warning(
                "HLException on connID=%d packet.type=0x%x fatal=%s: %s" ,
                self.connID , self.packet.type , ex.fatal , ex.msg
            )
            if self.isIRC:
                if self.packet.irctrap:
                    # Not sure this is still required since we already return a 421 "Unknown command" reply.
                    self.transport.write(
                        ( "NOTICE * :*** HL Error 0x%x [%s] %s\r\n" % ( self.packet.type, self.packet.irctrap, ex.msg ) ).encode( 'mac-roman' )
                    )
            else:
                packet = HLPacket( HTLS_HDR_TASK , self.packet.seq , 1 )
                packet.addString( DATA_ERROR , ex.msg )
                self.writePacket( packet )
            if ex.fatal:
                # The exception was fatal (i.e. failed login) so kill the connection.
                self.transport.loseConnection()
        except Exception:
            # Anything else is a bug — surface it instead of letting Twisted
            # eat it.
            self.factory.log.exception( "Unhandled error in handlePacket (connID=%d)" , self.connID )
            self.transport.loseConnection()
    
    def idleCheck( self ):
        """ Called a set amount of time after the last non-ping packet, mark us as idle and trick the handlers into sending the change. """
        user = self.factory.getUser( self.connID )
        if not user.away:
            # Only send the change if the user is not away and not idle.
            user.status |= STATUS_AWAY
            self.factory.dispatchPacket( self.connID , HLPacket(HTLC_HDR_USER_CHANGE ) )
        del self.idleTimer
        self.idleTimer = None
    
    def writePacket( self , packet ):
        """ Flattens and writes a packet out to the socket. """
        packet.server = self.factory
        self.transport.write( packet.flatten(  self.factory.getUser( self.connID ) ) )

class HLServer( Factory ):
    """ Factory subclass that handles all global server operations. Also owns database and fileserver objects. """
    
    def __init__( self ):
        self.port = SERVER_PORT
        self.lastUID = 0
        self.lastChatID = 0
        self.clients = {}
        self.chats = {}
        self.handlers = []
        self.tempBans = {}
        self.database = getDatabase( DB_TYPE )
        self.fileserver = HLFileServer( self )
        self.webserver = HLWebServices( self )
        self.startTime = time.time()
        self.log = logging.getLogger( "phxd" )
        self.linker = HLServerLinker( self )
        self._initLog()
        reactor.listenTCP( self.port , self )
        # Update all trackers periodically
        recurrentTask = task.LoopingCall(self.updateTrackers)
        recurrentTask.start(TRACKER_REFRESH_PERIOD)
        #recurrentTask.addErrback(updateTrackersFailed)
    
    def updateTrackers(self):
        """Updates the register trackers, if any, with the name
        and description of server and the current user count.
        """
        for hostname, port in TRACKER_LIST:
            reactor.listenUDP(0, HLTrackerClient(self, hostname, port))

    def updateTrackersFailed(self, reason):
        """Errback invoked when the task to update the trackers
        fails for whatever reason.
        """
        print("Failed to update tracker: reason")

    def _initLog( self ):
        import os, sys
        self.log.setLevel( logging.DEBUG )
        # Don't propagate to the root logger — we attach our own handlers.
        self.log.propagate = False

        fmt = logging.Formatter( '%(asctime)s\t%(levelname)s\t%(message)s' )

        # Always stream to stdout so ``docker logs`` shows server activity.
        # Without this, every log call goes to a file inside the container
        # (or, worse, nowhere at all when ENABLE_FILE_LOG is off).
        streamHandler = logging.StreamHandler( sys.stdout )
        streamHandler.setFormatter( fmt )
        streamHandler.setLevel( logging.DEBUG )
        self.log.addHandler( streamHandler )

        if ENABLE_FILE_LOG:
            # NOTE: the previous version had setFormatter/addHandler nested
            # inside the ``except IOError`` branch, so the rotating file
            # handler was created but never attached when the log dir
            # already existed. Also, ``logging.FileHandler`` doesn't take
            # ``maxBytes``/``backupCount`` — keep ``RotatingFileHandler``
            # for both branches.
            logSizeBytes = LOG_MAX_SIZE_MBYTES * 1024 * 1024
            log_dir = os.path.dirname( LOG_FILE )
            if log_dir and not os.path.isdir( log_dir ):
                try:
                    os.makedirs( log_dir )
                except OSError:
                    pass
            try:
                fileHandler = RotatingFileHandler(
                    LOG_FILE,
                    maxBytes=logSizeBytes,
                    backupCount=MAX_LOG_FILES,
                )
                fileHandler.setFormatter( fmt )
                fileHandler.setLevel( logging.DEBUG )
                self.log.addHandler( fileHandler )
            except (IOError, OSError) as e:
                self.log.warning( "Could not open log file %s: %s" , LOG_FILE , e )

            # Database event log (info+).
            try:
                dbHandler = HLDatabaseLogger( self.database )
                dbHandler.setLevel( logging.INFO )
                self.log.addHandler( dbHandler )
            except Exception as e:
                self.log.warning( "Could not attach database log handler: %s" , e )

        # Bridge Twisted's own logging system to Python logging so
        # connection/handshake errors and tracebacks from inside Twisted
        # callbacks (e.g. unhandled exceptions in ``dataReceived``) show
        # up in ``docker logs`` instead of being silently swallowed.
        try:
            from twisted.python import log as twisted_log
            twisted_logger = logging.getLogger( "twisted" )
            twisted_logger.setLevel( logging.DEBUG )
            twisted_logger.propagate = False
            twisted_logger.addHandler( streamHandler )

            def _bridge( eventDict ):
                if eventDict.get( "isError" ):
                    msg = twisted_log.textFromEventDict( eventDict ) or ""
                    twisted_logger.error( "%s" , msg )
                else:
                    msg = twisted_log.textFromEventDict( eventDict )
                    if msg:
                        twisted_logger.info( "%s" , msg )

            twisted_log.addObserver( _bridge )
        except Exception as e:
            self.log.warning( "Could not bridge Twisted log: %s" , e )
        
    def linkToServer( self, addr ):
        ( ip , port ) = addr.split( ':' )
        self.linker.link( ip, int(port) )

    def addRemoteUser( self, remoteUser, sendChange = True ):
        self.lastUID += 1
        user = HLUser( self.lastUID, "<linked ip>" )
        user.nick = remoteUser.nick
        user.icon = remoteUser.icon
        user.color = remoteUser.color
        user.status = remoteUser.status
        user.local = False
        user.account = HLAccount( "<linked account>" )
        user.account.name = "Linked Account"
        user.valid = True

        self.clients[self.lastUID] = ( None , user )

        if sendChange:
            change = HLPacket( HTLS_HDR_USER_CHANGE )
            change.addNumber( DATA_UID , user.uid )
            change.addString( DATA_NICK , user.nick )
            change.addNumber( DATA_ICON , user.icon )
            change.addNumber( DATA_STATUS , user.status )
            for ( conn , user ) in self.clients.values():
                if user.local:
                    conn.writePacket( change )
        return user.uid

    def removeRemoteUser( self, uid ):
               if uid in self.clients:
                       del( self.clients[uid] )
    
    def handleUserLogin( self, user ):
               user.valid = True
               self.linker.forwardUserConnect( user )

    
    def addTempBan( self , addr , reason = "no reason" ):
        """ Adds a temporary ban for addr that will expire in BAN_TIME seconds. """
        if addr not in self.tempBans:
            self.tempBans[addr] = reason
            reactor.callLater( BAN_TIME , self.removeTempBan , addr )
    
    def removeTempBan( self , addr ):
        """ Removes a temporary ban for addr, if it exists. """
        if addr in self.tempBans:
            del self.tempBans[addr]
    
    def checkForBan( self , addr ):
        """ Returns the reason given for a ban, if it exists. Otherwise returns None. """
        if addr in self.tempBans:
            return self.tempBans[addr]
        return self.database.checkBanlist( addr )
    
    def buildProtocol( self , addr ):
        """ Called when the factory accepts a connection and is asked to return a Protocol (in our case, a HLConnection). """
        self.lastUID += 1
        conn = HLConnection( self , self.lastUID )
        user = HLUser( self.lastUID , addr.host )
        self.clients[self.lastUID] = ( conn , user )
        for handler in self.handlers:
            handler.handleUserConnected( self , user )
        return conn
    
    def registerPacketHandler( self , handler ):
        """ Registers a HLPacketHandler. """
        if isinstance( handler , HLPacketHandler ):
            self.handlers.append( handler )
    
    def disconnectUser( self , uid ):
        """ Actively disconnect the specified user. """
        if uid in self.clients:
            ( conn , user ) = self.clients[uid]
            conn.transport.loseConnection()
    
    def removeConnection( self , connID ):
        """ Called from HLConnection when a connection dies. """
        if connID in self.clients:
            ( conn , user ) = self.clients[connID]
            if user.isLoggedIn():
                for handler in self.handlers:
                    handler.handleUserDisconnected( self , user )
                self.fileserver.cleanupTransfers( user.uid )
                self.linker.forwardUserDisconnect( user )
            del( self.clients[connID] )
    
    def getUser( self , uid ):
        """ Gets the HLUser object for the specified uid. """
        if uid in self.clients:
            ( conn , user ) = self.clients[uid]
            return user
        return None

    def getUserCount( self ):
        """ Returns the number of logged in HLUsers. """
        # NOTE: this method was previously nested inside ``getUser`` due to
        # over-indentation, which made it unreachable. ``HLTracker`` calls
        # it on every tracker update.
        return len( [user for _, user in self.clients.values() if user.isLoggedIn()] )

    def getOrderedUserlist( self ):
        """ Returns a list of HLUsers, ordered by uid. """
        keys = list(self.clients.keys())
        keys.sort()
        userlist = []
        for uid in keys:
            ( conn , user ) = self.clients[uid]
            if user.isLoggedIn():
                userlist.append( user )
        return userlist
    
    def createChat( self ):
        """ Creates and registers a new private chat, returns the ID of the newly created chat. """
        self.lastChatID += 1
        chat = HLChat( self.lastChatID )
        self.chats[self.lastChatID] = chat
        return chat
    
    def removeChat( self , id ):
        """ Remove the specified private chat. """
        if id in self.chats:
            del self.chats[id]
    
    def getChat( self , id ):
        """ Gets the HLChat object for the specified chat ID. """
        if id in self.chats:
            return self.chats[id]
        return None
    
    def sendPacket( self , uid , packet ):
        """ Sends the specified packet to the specified user. """
        if uid in self.clients:
            ( conn , user ) = self.clients[uid]
            packet.isIRC = conn.isIRC
            if user.local:
                conn.writePacket( packet )
            else:
                self.linker.forwardPacket( packet, user.uid )
    
    def broadcastPacket( self , packet , priv = 0 ):
        """ Sends the specified packet to all connected users. If priv is specified, only sends to users with that priv. """
        for ( conn , user ) in self.clients.values():
            packet.isIRC = conn.isIRC
            if not user.local:
                self.linker.forwardPacket( packet, user.uid )
            elif user.isLoggedIn():
                if priv > 0:
                    if user.hasPriv( priv ):
                        conn.writePacket( packet )
                else:
                    conn.writePacket( packet )

    def dispatchPacket( self , connID , packet ):
        """ Called from HLConnection to dispatch a packet to all registered packet handlers. """
        if connID in self.clients:
            handled = False
            ( conn , user ) = self.clients[connID]
            for handler in self.handlers:
                handled |= handler.handlePacket( self , user , packet )
            if handled == False:
                raise HLException("unknown packet type")

    #def returnClients( self ):
    #	""" For irc :p """
    #	return self.clients
    # DELETEME i think its dead code!!

    def logEvent( self , typeInt , msg , user = None ):
        """ Logs an event. If user is specified, the event will be logged with the users nickname, login, and IP address. """
        login = ""
        nickname = ""
        ip = ""
        if user != None:
            login = user.account.login
            nickname = user.nick
            ip = user.ip
        typeStr = str(typeInt)
        try:
            typeStr = LOG_TYPE_STR_MAP[typeInt]
        except KeyError:
            pass
        # format as <typeStr>\t<message>\t<login>\t<nickname>\t<ip>
        # this is the "message" for the FileLogger
        fmt = "%s\t%s\t%s\t%s\t%s"
        # NOTE: previously compared against the builtin ``type`` instead of
        # the ``typeInt`` parameter, which meant every event went through
        # the ``info`` branch.
        if typeInt == LOG_TYPE_ERROR:
            self.log.error( fmt, typeStr, msg, login, nickname, ip )
        elif typeInt == LOG_TYPE_DEBUG:
            self.log.debug( fmt, typeStr, msg, login, nickname, ip )
        else:
            self.log.info( fmt, typeStr, msg, login, nickname, ip )
    
    def updateAccounts( self , acct ):
        """ Updates the account information for all current users with login matching that of the specified HLAccount. """
        for ( conn , user ) in self.clients.values():
            if user.isLoggedIn() and ( user.account.login.upper() == acct.login.upper() ):
                user.account.copyFrom( acct )
                self.dispatchPacket( user.uid , HLPacket( HTLC_HDR_USER_CHANGE ) )
