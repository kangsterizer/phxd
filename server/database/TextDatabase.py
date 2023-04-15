from server.HLDatabase import HLDatabase
from shared.HLTypes import *
from config import *
from datetime import datetime
from os import mkdir , listdir , sep
import re

class TextDatabase (HLDatabase):
	""" Text-based implementation of HLDatabase. """
	
	def __init__( self ):
		self.newsDir = DB_FILE_NEWSDIR
		self.accountsFile = DB_FILE_ACCOUNTS
		self.logFile = DB_FILE_LOG
		self.banlistFile = DB_FILE_BANLIST
		self.regexNewsID = re.compile( "^([0-9]+)" )
		self.logTypes = {
			1: "General" ,
			2: "Login" ,
			3: "Users" ,
			4: "Accounts" ,
			5: "Files" ,
			6: "Transfers" ,
			7: "Trackers" ,
			99: "Errors" ,
		}
	
	def loadAccount( self , login ):
		""" Creates a new HLAccount object and loads information for the specified login into it. Returns None if unsuccessful. """
		acct = None
		try:
			fp = file( self.accountsFile , "r" )
		except IOError:
			return acct
		for l in fp.readlines():
			if l.split( "\t" )[0] == login:
				acct = HLAccount( login )
				try:
					( acct.id , acct.password , acct.name , acct.privs , acct.fileRoot ) = l.rstrip( "\n" ).split( "\t" )[1:6]
					( acct.id , acct.privs ) = ( int( acct.id ) , long( acct.privs ) )
					break
				except ValueError:
					return None
		fp.close()
		return acct
	
	def saveAccount( self , acct ):
		""" Saves the specified HLAccount object to the database. If the HLAccount has a non-zero ID, the information is updated, otherwise a new account is inserted. """
		try:
			fp = file( self.accountsFile , "r" )
			lines = fp.readlines()
			fp.close()
		except IOError:
			lines = []
		if acct.id > 0L:
			# Finds the account lines that corresponds to the provided ID and updates the account's info.
			found = False
			for l in range( len( lines ) ):
				try:
					if int( lines[l].split( "\t" )[1] ) == acct.id:
						found = True
						( bytesDown , bytesUp , lastLogin ) = lines[l].rstrip( "\n" ).split( "\t" )[6:9]
						lines[l] = "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % ( acct.login , acct.id , acct.password , acct.name , acct.privs , acct.fileRoot , bytesDown , bytesUp , lastLogin )
						break
				except IndexError:
					continue
				except ValueError:
					return False
			if not found:
				return False
			fp = file( self.accountsFile , "w" )
			fp.write( "".join( lines ) )
			fp.close()
		else:
			# First check to see if the login already exists.
			for l in lines:
				if l.split( "\t" )[0] == acct.login:
					return False
			# Find the largest UID then append to the account file.
			maxuid = 0
			for l in range( len( lines ) ):
				try:
					uid = lines[l].split( "\t" )[1]
				except IndexError:
					continue
				else:
					if uid > maxuid:
						maxuid = uid
			lines.append( "%s\t%s\t%s\t%s\t%s\t%s\t0\t0\t0000-00-00 00:00:00\n" % ( acct.login , int( maxuid ) + 1 , acct.password , acct.name , acct.privs , acct.fileRoot ) )
			fp = file( self.accountsFile , "w" )
			fp.write( "".join( lines ) )
			fp.close()
		return True
	
	def deleteAccount( self , login ):
		""" Deletes an account with the specified login. """
		try:
			fp = file( self.accountsFile , "r" )
		except IOError:
			return False
		( found , lines ) = ( False , fp.readlines() )
		fp.close()
		for l in range( len( lines ) ):
			if lines[l].split( "\t" )[0] == login:
				found = True
				del( lines[l] )
				break
		if not found:
			return False
		fp = file( self.accountsFile , "w" )
		fp.write( "".join( lines ) )
		fp.close()
		return True
	
	def updateAccountStats( self , login , downloaded , uploaded , setDate = False ):
		try:
			fp = file( self.accountsFile , "r" )
		except IOError:
			return False
		( found , lines ) = ( False , fp.readlines() )
		fp.close()
		for l in range( len( lines ) ):
			if lines[l].split( "\t" )[0] == login:
				found = True
				try:
					( acctLogin, acctID , acctPass , acctName , acctPrivs , acctFileRoot , acctBytesDown, acctBytesUp , acctLastLogin ) = lines[l].rstrip( "\n" ).split( "\t" )
				except ValueError:
					return False
				else:
					if ( downloaded > 0 ) or ( uploaded > 0 ):
						acctBytesDown = long( acctBytesDown ) + downloaded
						acctBytesUp = long( acctBytesUp ) + uploaded
					if setDate:
						acctLastLogin = datetime.now().strftime( "%Y-%m-%d %H:%M:%S" )
					lines[l] = "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % ( acctLogin , acctID , acctPass , acctName , acctPrivs , acctFileRoot , acctBytesDown , acctBytesUp , acctLastLogin )
					break
		if not found:
			return False
		fp = file( self.accountsFile , "w" )
		fp.write( "".join( lines ) )
		fp.close()
		return True
	
	def loadNewsPosts( self , limit = 0 ):
		posts = []
		files = listdir( self.newsDir )
		if limit > len( files ):
			limit = len( files )
		if limit == 0:
			files = listdir( self.newsDir )
		else:
			files = files[len( files ) - limit:len( files )]
		for f in files:
			post = HLNewsPost()
			fp = file( "%s%s%s" % ( self.newsDir , sep , f ) , "r" )
			( post.id , post.date , post.login , post.nick ) = fp.readline().rstrip( "\n" ).split( "\t" )
			post.post = "".join( fp.readlines() )
			fp.close()
			posts.append( post )
		return posts
	
	def saveNewsPost( self , post ):
		try:
			mkdir( self.newsDir )
		except OSError:
			pass
		try:
			maxid = int( self.regexNewsID.match( listdir( "%s%s" % ( self.newsDir , sep ) )[-1] ).group() )
		except:
			maxid = 0
		if post.id > 0L:
			maxid = post.id - 1
		else:
			fp = file( "%s%s%s.txt" % ( self.newsDir , sep , maxid + 1 ) , "w" )
			fp.write( "%s\t%s\t%s\t%s\n%s" % ( str( maxid + 1 ) , post.date , post.login , post.nick , post.post ) )
			fp.close()
		return True
	
	def checkBanlist( self , addr ):
		reason = None
		try:
			fp = file( self.banlistFile , "r" )
		except:
			return reason
		for l in fp.readlines():
			if l.split( "\t" )[0] == addr:
				try:
					reason = l.split( "\t" )[1]
				except IndexError:
					reason = "Reason not supplied."
				break
		return reason
	
	def logEvent( self , type , event , login = "" , nick = "" , ip = "" ):
            """
            This method is disabled, since we already have a pretty extensive
            logging facility using ENABLE_FILE_LOG. The difference is that file
            log runs at a DEBUG level while the DB log runs at INFO, but we have
            currentl no DEBUG messages available anyways, so it's redundant.
            """
            return
            fp = file( self.logFile , "a" )
            eventType = "???"
            try:
                eventType = self.logTypes[type]
            except NameError:
                pass
            fp.write( "\n%s\t%s\t%s\t%s\t%s\t%s" % ( eventType , login , nick , ip , event , datetime.now().strftime( "%Y-%m-%d %H:%M:%S" ) ) )
            fp.close()
