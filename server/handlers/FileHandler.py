from shared.HLProtocol import *
from shared.HLTypes import *
from config import *
from struct import pack
from statvfs import *
import os

def installHandler( server ):
	server.registerPacketHandler( FileHandler() )

def parseDir( dir ):
	parts = []
	if ( dir == None ) or ( len( dir ) < 5 ):
		return parts
	pos = 0
	count = unpack( "!H" , dir[pos:pos+2] )[0]
	pos += 3
	while ( pos < len( dir ) ) and ( count > 0 ):
		size = unpack( "!H" , dir[pos:pos+2] )[0]
		pos += 2
		parts.append( dir[pos:pos+size] )
		pos += size + 1
		count -= 1
	return parts

def buildPath( root , dir , file = None ):
	""" Build a path from a root directory, an array of directory parts, and a filename. Filter out any references to .. """
	pathArray = []
	pathArray.append( root )
	for part in dir:
		if ( len( part ) > 0 ) and ( part != ".." ):
			pathArray.append( part )
	if ( file != None ) and ( len( file ) > 0 ):
		pathArray.append( file )
	return os.sep.join( pathArray )

def getFileType( path ):
	if os.path.isdir( path ):
		return HLCharConst( "fldr" )
	elif path.endswith( ".hpf" ):
		return HLCharConst( "HTft" )
	else:
		return HLCharConst( "????" )

def getFileCreator( path ):
	if os.path.isdir( path ):
		return 0
	elif path.endswith( ".hpf" ):
		return HLCharConst( "HTLC" )
	else:
		return HLCharConst( "????" )

class FileHandler( HLPacketHandler ):
	def __init__( self ):
		HLPacketHandler.__init__( self )
		self.registerHandlerFunction( HTLC_HDR_FILE_LIST , self.handleFileList )
		self.registerHandlerFunction( HTLC_HDR_FILE_GET , self.handleFileDownload )
		self.registerHandlerFunction( HTLC_HDR_FILE_PUT , self.handleFileUpload )
		self.registerHandlerFunction( HTLC_HDR_FILE_DELETE , self.handleFileDelete )
		self.registerHandlerFunction( HTLC_HDR_FILE_MKDIR , self.handleFolderCreate )
		self.registerHandlerFunction( HTLC_HDR_FILE_MOVE , self.handleFileMove )
		self.registerHandlerFunction( HTLC_HDR_FILE_GETINFO , self.handleFileGetInfo )
		self.registerHandlerFunction( HTLC_HDR_FILE_SETINFO , self.handleFileSetInfo )
	
	def handleFileList( self , server , user , packet ):
		dir = parseDir( packet.getBinary( DATA_DIR ) )
		path = buildPath( user.account.fileRoot , dir )
		
		if not os.path.exists( path ):
			raise HLException , "The specified directory does not exist."
		if not os.path.isdir( path ):
			raise HLException , "The specified path is not a directory."
		if ( not user.hasPriv( PRIV_VIEW_DROPBOXES ) ) and ( path.upper().find( "DROP BOX" ) >= 0 ):
			raise HLException , "You are not allowed to view drop boxes."
		fn = path.split("/")[-1] # gets folder name kang
		#beware of non exact matches!! FIXME
		if (path.upper().find("DROP BOX") >= 0) and (fn.upper()[0:4] != "DROP") and (fn.upper().find(user.account.login.upper()) < 0):
			raise HLException, "Sorry, this is not your dropbox. You are not allowed to view it"
		
		reply = HLPacket( HTLS_HDR_TASK , packet.seq )
		files = os.listdir( path )
		for fname in files:
			if SHOW_DOTFILES or ( fname[0] != '.' ):
				# Only list files starting with . if SHOW_DOTFILES is True.
				fpath = os.path.join( path , fname )
				type = getFileType( fpath )
				creator = getFileCreator( fpath )
				if os.path.isdir( fpath ):
					size = len( os.listdir( fpath ) )
				else:
					size = os.path.getsize( fpath )
				data = pack( "!5L" , type , creator , size , size , len( fname ) ) + fname
				reply.addBinary( DATA_FILE , data )
		server.sendPacket( user.uid , reply )
	
	def handleFileDownload( self , server , user , packet ):
		dir = parseDir( packet.getBinary( DATA_DIR ) )
		name = packet.getString( DATA_FILENAME , "" )
		resume = HLResumeData( packet.getBinary( DATA_RESUME ) )
		options = packet.getNumber( DATA_XFEROPTIONS , 0 )
		
		path = buildPath( user.account.fileRoot , dir , name )
		if not user.hasPriv( PRIV_DOWNLOAD_FILES ):
			raise HLException , "You are not allowed to download files."
		if not os.path.exists( path ):
			raise HLException , "Specified file does not exist."
		
		offset = resume.forkOffset( HLCharConst( "DATA" ) )
		xfer = server.fileserver.addDownload( user.uid , path , offset )
		
		reply = HLPacket( HTLS_HDR_TASK , packet.seq )
		reply.addNumber( DATA_XFERSIZE , xfer.total )
		reply.addNumber( DATA_FILESIZE , xfer.dataSize )
		reply.addNumber( DATA_XFERID , xfer.id )
		server.sendPacket( user.uid , reply )
	
	def handleFileUpload( self , server , user , packet ):
		dir = parseDir( packet.getBinary( DATA_DIR ) )
		name = packet.getString( DATA_FILENAME , "" )
		size = packet.getNumber( DATA_XFERSIZE , 0 )
		options = packet.getNumber( DATA_XFEROPTIONS , 0 )
		
		if not user.hasPriv( PRIV_UPLOAD_FILES ):
			raise HLException , "You are not allowed to upload files."
		
		path = buildPath( user.account.fileRoot , dir , name )
		if os.path.exists( path ):
			# If this path exists, theres already a complete file.
			raise HLException , "File already exists."
		if ( not user.hasPriv( PRIV_UPLOAD_ANYWHERE ) ) and ( path.upper().find( "UPLOAD" ) < 0 ):
			raise HLException , "You must upload to an upload directory."
		
		# Make sure we have enough disk space to accept the file.
		upDir = buildPath( user.account.fileRoot , dir )
		info = os.statvfs( upDir )
		free = info[F_BAVAIL] * info[F_FRSIZE]
		if size > free:
			raise HLException , "Insufficient disk space."
		
		# All uploads in progress should have this extension.
		path += ".hpf"
		
		xfer = server.fileserver.addUpload( user.uid , path )
		if size > 0:
			xfer.total = size
		reply = HLPacket( HTLS_HDR_TASK , packet.seq )
		reply.addNumber( DATA_XFERID , xfer.id )
		if os.path.exists( path ):
			resume = HLResumeData()
			resume.setForkOffset( HLCharConst( "DATA" ) , os.path.getsize( path ) )
			reply.addBinary( DATA_RESUME , resume.flatten() )
		server.sendPacket( user.uid , reply )
	
	def handleFileDelete( self , server , user , packet ):
		dir = parseDir( packet.getBinary( DATA_DIR ) )
		name = packet.getString( DATA_FILENAME , "" )
		
		path = buildPath( user.account.fileRoot , dir , name )
		if not user.hasPriv( PRIV_DELETE_FILES ):
			raise HLException , "You are not allowed to delete files."
		if not os.path.exists( path ):
			raise HLException , "Specified file does not exist."
		
		if os.path.isdir( path ):
			# First, recursively delete everything inside the directory.
			for ( root , dirs , files ) in os.walk( path , topdown = False ):
				for name in files:
					os.unlink( os.path.join( root , name ) )
				for name in dirs:
					os.rmdir( os.path.join( root , name ) )
			# Then delete the directory itself.
			os.rmdir( path )
		else:
			os.unlink( path )
		
		server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
	
	def handleFolderCreate( self , server , user , packet ):
		dir = parseDir( packet.getBinary( DATA_DIR ) )
		name = packet.getString( DATA_FILENAME , "" )
		
		path = buildPath( user.account.fileRoot , dir , name )
		if not user.hasPriv( PRIV_CREATE_FOLDERS ):
			raise HLException , "You are not allowed to create folders."
		if os.path.exists( path ):
			raise HLException , "Specified directory/file already exists."
		
		os.mkdir( path , 0755 )
		server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
	
	def handleFileMove( self , server , user , packet ):
		oldDir = parseDir( packet.getBinary( DATA_DIR ) )
		newDir = parseDir( packet.getBinary( DATA_NEWDIR ) )
		name = packet.getString( DATA_FILENAME , "" )
		
		oldPath = buildPath( user.account.fileRoot , oldDir , name )
		newPath = buildPath( user.account.fileRoot , newDir , name )
		
		if not user.hasPriv( PRIV_MOVE_FILES ):
			raise HLException , "You are not allowed to move files."
		if not os.path.exists( oldPath ):
			raise HLException , "Invalid file or directory."
		if os.path.exists( newPath ):
			raise HLException , "The specified file already exists."
		
		os.rename( oldPath , newPath )
		server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
	
	def handleFileGetInfo( self , server , user , packet ):
		dir = parseDir( packet.getBinary( DATA_DIR ) )
		name = packet.getString( DATA_FILENAME , "" )
		
		path = buildPath( user.account.fileRoot , dir , name )
		if not os.path.exists( path ):
			raise HLException , "No such file or directory."
		
		info = HLPacket( HTLS_HDR_TASK , packet.seq )
		info.addString( DATA_FILENAME , name )
		info.addNumber( DATA_FILESIZE , os.path.getsize( path ) )
		info.addNumber( DATA_FILETYPE , getFileType( path ) )
		info.addNumber( DATA_FILECREATOR , getFileCreator( path ) )
		server.sendPacket( user.uid , info )
	
	def handleFileSetInfo( self , server , user , packet ):
		dir = parseDir( packet.getBinary( DATA_DIR ) )
		oldName = packet.getString( DATA_FILENAME , "" )
		newName = packet.getString( DATA_NEWFILE , oldName )
		
		if ( oldName != newName ) and ( not user.hasPriv( PRIV_RENAME_FILES ) ):
			raise HLException , "You cannot rename files."
		
		oldPath = buildPath( user.account.fileRoot , dir , oldName )
		newPath = buildPath( user.account.fileRoot , dir , newName )
		
		if not os.path.exists( oldPath ):
			raise HLException , "Invalid file or directory."
		if os.path.exists( newPath ):
			raise HLException , "The specified file already exists."
		
		os.rename( oldPath , newPath )
		server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )	
