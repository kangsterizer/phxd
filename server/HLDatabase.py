from shared.HLTypes import *
import server.database

def getDatabase( type ):
    """ Returns a HLDatabase subclass based on the type string (used as a prefix). """
    cls = "%sDatabase" % type
    try:
        mod = __import__( "server.database.%s" % cls , None , None , "server.database" )
        db = eval( "mod.%s()" % cls )
        return db
    except ImportError:
        print "error importing server.database.%s" % cls
        return None

class HLDatabase:
    """ Base class for phxd database implementations. Should be overridden by classes in the database directory. """
    
    def __init__( self ):
        pass
    
    def loadAccount( self , login ):
        """ Creates a new HLAccount object and loads information for the specified login into it. Returns None if unsuccessful. """
        return None
    
    def saveAccount( self , acct ):
        """ Saves the specified HLAccount object to the database. If the HLAccount has a non-zero ID, the information is updated, otherwise a new account is inserted. """
        pass
    
    def deleteAccount( self , login ):
        """ Deletes an account with the specified login from the database. """
        return False
    
    def updateAccountStats( self , login , downloaded , uploaded , setDate = False ):
        """ Updates statistics for an account in the database. """
        pass
    
    def loadNewsPosts( self , limit = 0 ):
        """ Loads and returns a list of HLNewsPost objects from the database. If limit > 0, the returned list will contain no more than limit posts. """
        return []
    
    def saveNewsPost( self , post ):
        """ Saves a HLNewsPost object to the database. """
        pass
    
    def checkBanlist( self , addr ):
        """ Checks the banlist table, returns a reason, or None if no entry was found. """
        return None
    
    def logEvent( self , type , event , login = "" , nick = "" , ip = "" ):
        """ Logs an event to the database (see HLTypes for log types). """
        pass
