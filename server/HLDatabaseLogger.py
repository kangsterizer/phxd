from logging import Handler

class HLDatabaseLogger( Handler ):
    
    def __init__( self , db ):
        Handler.__init__( self )
        self.db = db
    
    def emit( self , record ):
        if record.args:
            ( type , msg , login , nick , ip ) = record.args
            self.db.logEvent( type , msg , login , nick , ip )
