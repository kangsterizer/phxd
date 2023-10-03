from __future__ import absolute_import
from twisted.internet.protocol import Factory , Protocol
from twisted.internet.interfaces import IProducer
from twisted.internet import reactor
from shared.HLProtocol import *
from server.HLDatabase import *
from shared.HLTypes import *
from shared.HLTransfer import *
from config import *
import os

class HLTransferConnection( Protocol ):
    #__implements__ = Protocol.__implements__ + ( IProducer , )
    
    def connectionMade( self ):
        self.info = None
        self.gotMagic = False
        self.buffer = ""
    
    def connectionLost( self , reason ):
        if self.info != None:
            self.info.finish()
            self.factory.removeTransfer( self.info.id )
    
    def dataReceived( self , data ):
        """ Called when the transfer connection receives data. Should only happen
        for uploads, and for the 16-byte magic header for all transfers. """
        if self.gotMagic:
            if ( self.info != None ) and ( self.info.type == XFER_TYPE_UPLOAD ):
                self.info.parseData( data )
                if self.info.isComplete():
                    # The upload is done, it's our job to close the connection.
                    self.transport.loseConnection()
            else:
                self.transport.loseConnection()
        else:
            # Make sure we buffer at this point in case we don't get the
            # HTXF magic all at once, or get more than just the magic.
            self.buffer += data
            if len( self.buffer ) >= 16:
                # We got the HTXF magic, parse it.
                ( proto , xfid , size , flags ) = unpack( "!4L" , self.buffer[0:16] )
                self.buffer = self.buffer[16:]
                self.gotMagic = True
                self.info = self.factory.findTransfer( xfid )
                if self.info == None:
                    # Invalid xfer ID, kill the connection.
                    self.transport.loseConnection()
                else:
                    if self.info.type == XFER_TYPE_UPLOAD:
                        if self.info.total == 0:
                            self.info.total = size
                    elif self.info.type == XFER_TYPE_DOWNLOAD:
                        self.transport.registerProducer( self , False )
                    # Cancel the xfer timeout and start it up.
                    self.factory.cancelTimeout( self.info.id )
                    self.info.start()
                if len( self.buffer ) > 0:
                    # Recurse for any remaining data with gotMagic = True.
                    self.dataReceived( self.buffer )
    
    def resumeProducing( self ):
        """ The transport asked us for more data. Should only happen for
        downloads after we've been registered as a producer. """
        chunk = self.info.getDataChunk()
        if len( chunk ) > 0:
            self.transport.write( chunk )
        else:
            self.transport.unregisterProducer()
    
    def pauseProducing( self ):
        pass
    
    def stopProducing( self ):
        pass

class HLFileServer (Factory):
    protocol = HLTransferConnection
    
    def __init__( self , server ):
        self.port = SERVER_PORT + 1
        self.server = server
        self.lastTransferID = 0
        self.transfers = {}
        self.timeouts = {}
        reactor.listenTCP( self.port , self )
    
    def addUpload( self , owner , path ):
        """ Adds an upload to the list of transfers. """
        self.lastTransferID += 1
        info = HLUpload( self.lastTransferID , path , owner )
        self.transfers[self.lastTransferID] = info
        self.timeouts[info.id] = reactor.callLater( XFER_START_TIMEOUT , self.timeoutTransfer , info.id )
        return info
    
    def addDownload( self , owner , path , offset ):
        """ Adds a download to the list of transfers. """
        self.lastTransferID += 1
        info = HLDownload( self.lastTransferID , path , owner , offset )
        self.transfers[self.lastTransferID] = info
        self.timeouts[info.id] = reactor.callLater( XFER_START_TIMEOUT , self.timeoutTransfer , info.id )
        return info
    
    def findTransfer( self , xfid ):
        """ Returns the HLTransfer (HLDownload or HLUpload) object for the specified transfer ID. """
        if xfid in self.transfers:
            return self.transfers[xfid]
        return None
    
    def findTransfersForUser( self , uid ):
        """ Returns a list of all transfers for the specified user ID. """
        xfers = []
        for info in self.transfers.values():
            if info.owner == uid:
                xfers.append( info )
        return xfers
    
    def cancelTimeout( self , id ):
        """ Cancels a pending timeout for the specified transfer. """
        if id in self.timeouts:
            self.timeouts[id].cancel()
            del self.timeouts[id]
    
    def timeoutTransfer( self , id ):
        """ Called after an initial timeout to remove the dead transfer from the list of transfers. """
        if id in self.transfers:
            del self.timeouts[id]
            del self.transfers[id]
    
    def removeTransfer( self , xfid ):
        """ Removes a transfer from the list of transfers. """
        if xfid in self.transfers:
            info = self.transfers[xfid]
            user = self.server.getUser( info.owner )
            if user != None:
                if info.isComplete():
                    type = ( "Download" , "Upload" )[info.type]
                    speed = "%d k/sec" % ( info.getTotalBPS() / 1024 )
                    msg = "%s of '%s' complete (%s)" % ( type , info.name , speed )
                    self.server.logEvent( LOG_TYPE_TRANSFER , msg , user )
                if info.type == XFER_TYPE_DOWNLOAD:
                    self.server.database.updateAccountStats( user.account.login , info.transferred , 0 )
                elif info.type == XFER_TYPE_UPLOAD:
                    self.server.database.updateAccountStats( user.account.login , 0 , info.transferred )
            del self.transfers[info.id]
    
    def cleanupTransfers( self , owner ):
        """ Removes any transfers owned by owner. Should be called when the user disconnects or is disconnected. """
        for xfer in self.transfers.values():
            if xfer.owner == owner:
                self.removeTransfer( xfer.id )
