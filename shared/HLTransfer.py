from __future__ import absolute_import
from shared.HLProtocol import *
import os , time

XFER_TYPE_DOWNLOAD = 0
XFER_TYPE_UPLOAD = 1

class HLTransfer:
	def __init__( self , id , path , owner , type ):
		self.id = id
		self.path = path
		self.name = os.path.basename( path )
		self.owner = owner
		self.type = type
		self.total = 0
		self.transferred = 0
		self.offset = 0
		self.startTime = 0.0
	
	def overallPercent( self ):
		return 0
	
	def getTotalBPS( self ):
		""" Returns the overall speed (in BPS) of this transfer. """
		elapsed = time.time() - self.startTime
		if elapsed > 0.0:
			return int( float( self.transferred ) / elapsed )
		return 0
	
	def isComplete( self ):
		""" Returns True if all data has been sent or received. """
		return self.transferred >= self.total
	
	def parseData( self , data ):
		""" Called when data is received from a transfer. """
		raise "Transfer does not implement parseData."
	
	def getDataChunk( self ):
		""" Called when writing data to a transfer. """
		raise "Transfer does not implement getDataChunk."
	
	def start( self ):
		""" Called when the connection is opened. """
		self.startTime = time.time()
	
	def finish( self ):
		""" Called when the connection is closed. """
		pass

class HLDownload( HLTransfer ):
	def __init__( self , id , path , owner , offset ):
		HLTransfer.__init__( self , id , path , owner , XFER_TYPE_DOWNLOAD )
		self.offset = offset
		self.dataSize = os.path.getsize( path ) - offset
		self.file = open( path , "r" )
		self.file.seek( offset )
		self.sentHeader = False
		self._buildHeaderData()
		self.total = len( self.header ) + self.dataSize
	
	def overallPercent( self ):
		done = self.offset + self.transferred
		total = os.path.getsize( self.path ) + len( self.header )
		if total > 0:
			return int( ( float( done ) / float( total ) ) * 100 )
		return 0
	
	def getDataChunk( self ):
		""" Returns the next chunk of data to be sent out. """
		if self.sentHeader:
			# We already sent the header, read from the file.
			data = self.file.read( 2 ** 14 )
			self.transferred += len( data )
			return data
		else:
			# Send the header, mark it as sent.
			self.sentHeader = True
			self.transferred += len( self.header )
			return self.header
	
	def finish( self ):
		""" Called when the download connection closes. """
		self.file.close()
	
	def _buildHeaderData( self ):
		""" Builds the header info for the file transfer, including the FILP header, INFO header and fork, and DATA header. """
		self.header = pack( "!LHLLLLH" , HLCharConst( "FILP" ) , 1 , 0 , 0 , 0 , 0 , 2 )
		self.header += pack( "!4L" , HLCharConst( "INFO" ) , 0 , 0 , 74 + len( self.name ) )
		self.header += pack( "!5L" , HLCharConst( "AMAC" ) , HLCharConst( "????" ) , HLCharConst( "????" ) , 0 , 0 )
		self.header += ( "\0" * 32 )
		self.header += pack( "!HHL" , 0 , 0 , 0 )
		self.header += pack( "!HHL" , 0 , 0 , 0 )
		self.header += pack( "!HH" , 0 , len( self.name ) )
		self.header += self.name
		self.header += pack( "!H" , 0 )
		self.header += pack( "!4L" , HLCharConst( "DATA" ) , 0 , 0 , self.dataSize )

STATE_FILP = 0
STATE_HEADER = 1
STATE_FORK = 2

class HLUpload( HLTransfer ):
	def __init__( self , id , path , owner ):
		HLTransfer.__init__( self , id , path , owner , 1 )
		self.file = open( path , "a" )
		self.initialSize = os.path.getsize( path )
		self.buffer = ""
		self.state = STATE_FILP
		self.forkCount = 0
		self.currentFork = 0
		self.forkSize = 0
		self.forkOffset = 0
	
	def overallPercent( self ):
		done = self.initialSize + self.transferred
		total = self.initialSize + self.total
		if total > 0:
			return int( ( float( done ) / float( total ) ) * 100 )
		return 0
	
	def parseData( self , data ):
		""" Called when data is received from the upload connection. writes any data received for the DATA fork out to the specified file. """
		self.buffer += data
		self.transferred += len( data )
		while True:
			if self.state == STATE_FILP:
				if len( self.buffer ) < 24:
					return False
				( proto , vers , _r1 , _r2 , _r3 , _r4 , self.forkCount ) = unpack( "!LHLLLLH" , self.buffer[0:24] )
				self.buffer = self.buffer[24:]
				self.state = STATE_HEADER
			elif self.state == STATE_HEADER:
				if len( self.buffer ) < 16:
					return False
				(self.currentFork , _r1 , _r2 , self.forkSize ) = unpack( "!4L" , self.buffer[0:16] )
				self.buffer = self.buffer[16:]
				self.forkOffset = 0
				self.state = STATE_FORK
			elif self.state == STATE_FORK:
				remaining = self.forkSize - self.forkOffset
				if len( self.buffer ) < remaining:
					# We don't have the rest of the fork yet.
					if self.currentFork == HLCharConst( "DATA" ):
						# Write to the file if this is the DATA fork.
						self.file.write( self.buffer )
					self.forkOffset += len( self.buffer )
					self.buffer = ""
					return False
				else:
					# We got the rest of the current fork.
					if self.currentFork == HLCharConst( "DATA" ):
						self.file.write( self.buffer[0:remaining] )
					self.buffer = self.buffer[remaining:]
					self.forkCount -= 1
					if self.forkCount <= 0:
						return True
					self.state = STATE_HEADER
	
	def finish( self ):
		""" Called when the upload connection closes. If the upload is complete, renames the file, stripping off the .hpf extension. """
		self.file.close()
		if self.isComplete() and self.path.endswith( ".hpf" ):
			newPath = self.path[:-4]
			os.rename( self.path , newPath )
			self.path = newPath
			self.name = os.path.basename( self.path )
