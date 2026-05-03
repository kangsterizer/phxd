from __future__ import absolute_import
from logging import Handler

class HLDatabaseLogger( Handler ):
    """ Logging handler that forwards ``HLServer.logEvent`` records into
    the configured database. Only handles records whose ``args`` is the
    5-tuple shape produced by ``logEvent`` — generic ``log.info("...", x)``
    calls are skipped (they would have unpacked into a ValueError before,
    which then exploded out of every log call site). """

    def __init__( self , db ):
        Handler.__init__( self )
        self.db = db

    def emit( self , record ):
        # Only the structured 5-tuple format produced by ``logEvent`` makes
        # sense for the DB log; anything else is a free-form Python log
        # message and should be silently ignored here.
        args = record.args
        if not isinstance( args , tuple ) or len( args ) != 5:
            return
        try:
            ( type , msg , login , nick , ip ) = args
            self.db.logEvent( type , msg , login , nick , ip )
        except Exception:
            # Never let DB-logging failures break the application logger.
            self.handleError( record )
